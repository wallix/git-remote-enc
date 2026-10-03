//! An encrypted remote: connect, list, fetch, push. DESIGN.md §5, §6.

use std::io::{self, BufReader, Read, Write};
use std::path::PathBuf;
use std::str::FromStr;

use age::secrecy::ExposeSecret;
use anyhow::{Context, Result, anyhow, bail};
use ssh_key::PrivateKey;
use zeroize::Zeroizing;

use crate::backend::{self, Backend, PushOutcome};
use crate::config::Config;
use crate::crypto::{self, HashReader, HashWriter, Identity, Participant, TrustKey};
use crate::git::{self, Oid, Streaming, TreeEntry};
use crate::info;
use crate::manifest::{Manifest, Pack, join_envelope, split_envelope};
use crate::parts::{self, BlobChain, PartWriter};
use crate::progress::{self, Meter, MeterReader};
use crate::state::{State, Trust};

const MANIFEST_BLOB: &str = "manifest";
/// The manifest is read into memory before it can be authenticated, and the
/// host chooses its size. A pack line is ~140 bytes: this is ~450,000 pushes.
const MAX_MANIFEST_BYTES: u64 = 64 << 20;
const PUSH_ATTEMPTS: u32 = 3;

/// One `push` line from git: `[+]<src>:<dst>`; an empty `src` deletes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefSpec {
    pub force: bool,
    pub src: Option<String>,
    pub dst: String,
}

impl RefSpec {
    pub fn parse(spec: &str) -> Result<Self> {
        let (force, rest) = match spec.strip_prefix('+') {
            Some(r) => (true, r),
            None => (false, spec),
        };
        let (src, dst) = rest
            .split_once(':')
            .ok_or_else(|| anyhow!("malformed refspec `{spec}`"))?;
        if dst.is_empty() {
            bail!("malformed refspec `{spec}`: empty destination");
        }
        Ok(Self {
            force,
            src: (!src.is_empty()).then(|| src.to_owned()),
            dst: dst.to_owned(),
        })
    }
}

/// `(oid, refname)` as printed for `list`.
pub type RefList = Vec<(Oid, String)>;

/// How a participant list differs from another, by key (comments ignored).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ParticipantDiff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

impl ParticipantDiff {
    pub fn between(old: &[String], new: &[String]) -> Result<Self> {
        let keys = |texts: &[String]| -> Result<Vec<String>> {
            Ok(Participant::parse_all(texts)?
                .iter()
                .map(Participant::key)
                .collect())
        };
        let (old_keys, new_keys) = (keys(old)?, keys(new)?);
        let pick = |texts: &[String], keys: &[String], other: &[String]| {
            texts
                .iter()
                .zip(keys)
                .filter(|(_, k)| !other.contains(k))
                .map(|(t, _)| t.clone())
                .collect()
        };
        Ok(Self {
            added: pick(new, &new_keys, &old_keys),
            removed: pick(old, &old_keys, &new_keys),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

/// One manifest of the backend history.
pub enum HistoryEntry {
    Readable {
        commit: Oid,
        generation: u64,
        time: Option<u64>,
        /// The signer's participant line, or its fingerprint if the manifest
        /// does not list it.
        signer: String,
        /// `+`, `-` or `~` and the ref name, relative to the manifest before.
        refs: Vec<String>,
        participants: ParticipantDiff,
        admins: ParticipantDiff,
        /// The generation the changes are relative to: the previous readable
        /// manifest's, `None` for an empty remote.
        base: Option<u64>,
        /// Its packs replace earlier ones (`git-remote-enc repack`).
        repacked: bool,
        /// A participant's repack dropped the history before it.
        history_start: bool,
        /// Chained by `previous` digests to the accepted manifest, hence
        /// authentic. Otherwise anyone with write access to the host may
        /// have written it, and `signer` is a bare fingerprint.
        verified: bool,
        /// Whether the manifest `base` names is verified: when it is not,
        /// the changes are relative to what may be a forgery.
        base_verified: bool,
        /// `time` is earlier than the previous readable manifest's: a
        /// pusher's clock was wrong, or the time was set on purpose.
        time_regressed: bool,
    },
    /// The backend history skips from `expected` to `found`: generations
    /// are missing (or repeated), so the host rewrote it.
    Discontinuity { expected: u64, found: u64 },
    /// Not decryptable with the local identities (a manifest from before
    /// they were added, for instance) or malformed.
    Unreadable { commit: Oid, reason: String },
}

/// A readable manifest of the backend history, for checking its chain.
struct Link {
    /// Its index in the history entries.
    entry: usize,
    /// Its signer's fingerprint.
    fingerprint: String,
    /// SHA-256 of its text.
    digest: String,
    /// The digest its `previous` item names.
    previous: Option<String>,
}

/// Ref changes from `before` to `after`, as `+ name`, `- name`, `~ name`.
fn ref_changes(before: Option<&Manifest>, after: &Manifest) -> Vec<String> {
    let mut out = Vec::new();
    for (oid, name) in &after.refs {
        match before.and_then(|b| b.ref_oid(name)) {
            None => out.push(format!("+ {name}")),
            Some(old) if old != oid => out.push(format!("~ {name}")),
            Some(_) => {}
        }
    }
    for (_, name) in before.map_or(&[][..], |b| &b.refs) {
        if after.ref_oid(name).is_none() {
            out.push(format!("- {name}"));
        }
    }
    out
}

/// Who may read, push and administer a remote, and the pending changes the
/// configuration would apply.
pub struct Access {
    pub participants: Vec<String>,
    pub admins: Vec<String>,
    pub participants_diff: Option<ParticipantDiff>,
    pub admins_diff: Option<ParticipantDiff>,
}

pub struct Pins {
    pub repo: String,
    pub generation: u64,
    pub participants: Vec<String>,
}

pub enum PushStatus {
    Ok(String),
    Error(String, String),
}

pub struct Remote {
    /// How the user names this remote: its git remote name, else the URL.
    label: String,
    cfg: Config,
    backend: Backend,
    state: State,
    connected: bool,
    tip: Option<Oid>,
    tree: Vec<TreeEntry>,
    manifest: Option<Manifest>,
    /// SHA-256 of `manifest`'s text as signed: the next one's `previous`.
    manifest_digest: Option<String>,
    identities: Option<Vec<Identity>>,
    trust_keys: Option<Vec<TrustKey>>,
    /// The pack of a push attempt that lost the race, kept for the retry.
    staged: Option<Staged>,
    /// `pack_usage` before the current repack's first attempt.
    repack_before: Option<(usize, u64)>,
}

impl Remote {
    /// `name` is git's remote name (absent when it equals the URL); `url` is
    /// the helper URL with or without its `enc::` prefix.
    pub fn open(name: Option<&str>, url: &str) -> Result<Self> {
        let (url, branch) = crate::setup::split_url(url)?;
        let url = url.as_str();
        // Per repository, not per worktree: trust accepted in one worktree
        // must hold in all of them.
        let state = State::open(&git::common_dir()?, url, &branch)?;
        let backend = Backend {
            url: url.to_owned(),
            branch,
            tracking_ref: state.tracking_ref.clone(),
        };
        let name = name.filter(|n| *n != url && !n.starts_with("enc::"));
        if let Some(n) = name {
            refuse_plain_push_url(n)?;
        }
        Ok(Self {
            label: name.map_or_else(|| format!("enc::{url}"), str::to_owned),
            cfg: Config::load(name)?,
            backend,
            state,
            connected: false,
            tip: None,
            tree: vec![],
            manifest: None,
            manifest_digest: None,
            identities: None,
            trust_keys: None,
            staged: None,
            repack_before: None,
        })
    }

    pub fn url(&self) -> &str {
        &self.backend.url
    }

    pub fn identity_paths(&self) -> &[PathBuf] {
        &self.cfg.identity_paths
    }

    /// Whether contact installs, or reports on, the pre-push guard.
    pub fn set_install_hook(&mut self, on: bool) {
        self.cfg.install_hook = on;
    }

    /// What a new clone pins on first contact (DESIGN.md §6.1); `None` for
    /// a remote nobody pushed to yet.
    pub fn pins(&mut self) -> Result<Option<Pins>> {
        self.connect()?;
        Ok(self.manifest.as_ref().map(|m| Pins {
            repo: m.repo_id.clone(),
            generation: m.generation,
            participants: m.participants.clone(),
        }))
    }

    /// Why a push would be refused for Git LFS, if it would.
    pub fn lfs_refusal(&self) -> Result<Option<String>> {
        if self.cfg.allow_lfs {
            return Ok(None);
        }
        lfs_pre_push_hook()
    }

    fn identities(&mut self) -> Result<&[Identity]> {
        if self.identities.is_none() {
            if self.cfg.identity_paths.is_empty() {
                bail!(
                    "no identity: set enc.identity (or remote.<name>.enc-identity) to an SSH or age private key file"
                );
            }
            self.identities = Some(crypto::load_identities(&self.cfg.identity_paths)?);
        }
        Ok(self.identities.as_deref().unwrap_or(&[]))
    }

    /// Keys authenticating the local trust state: one per identity, or the
    /// signing key when that is the only key configured. The first one
    /// writes; any of them reads.
    fn trust_keys(&mut self) -> Result<Vec<TrustKey>> {
        if self.trust_keys.is_none() {
            let keys = if self.cfg.identity_paths.is_empty() && self.cfg.signing_key.is_some() {
                vec![TrustKey::from_ssh(&self.signing_key()?)?]
            } else {
                self.identities()?
                    .iter()
                    .map(Identity::trust_key)
                    .collect::<Result<_>>()?
            };
            self.trust_keys = Some(keys);
        }
        Ok(self.trust_keys.clone().unwrap_or_default())
    }

    fn save_trust(&mut self, t: &Trust) -> Result<()> {
        let keys = self.trust_keys()?;
        let key = keys
            .first()
            .ok_or_else(|| anyhow!("no private key to authenticate the local trust state with"))?;
        self.state.save_trust(t, key)
    }

    /// Drop the local state kept for this remote: accepted trust, indexed
    /// packs and the tracking ref. Returns the directory removed.
    pub fn forget(&mut self) -> Result<PathBuf> {
        self.state.forget()?;
        if git::rev_parse(&self.backend.tracking_ref)?.is_some() {
            git::delete_ref(&self.backend.tracking_ref)?;
        }
        Ok(self.state.dir().to_owned())
    }

    // ---- connect ----------------------------------------------------------

    pub fn connect(&mut self) -> Result<()> {
        if self.connected {
            return Ok(());
        }
        // The tracking ref is set once a manifest has been accepted; with it
        // present, missing trust state was lost, not never written.
        let previous_tip = git::rev_parse(&self.backend.tracking_ref)?;
        let known = previous_tip.is_some();
        if self.cfg.install_hook {
            crate::guard::ensure_hook()?;
        }
        // Ask for a key passphrase before a potentially long download.
        if !self.cfg.identity_paths.is_empty() {
            self.identities()?;
        }
        self.tip = self.backend.fetch_tip()?;
        // Every push appends to the backend history; a tip that does not
        // descend from the one seen before means the host rewrote it, and
        // the audit trail `log` reads from it is incomplete. The fetch is
        // forced, so the old tip is still in the object store to compare.
        let rewritten = match (&previous_tip, &self.tip.clone()) {
            (Some(old), Some(new)) if old != new && !git::is_ancestor(old, new)? => {
                // The tracking ref has already moved, so an error here must
                // not lose the report: `None` reports the host's rewrite, and
                // `load_manifest` reads the trust state again and fails.
                let accepted = self
                    .trust_keys()
                    .and_then(|k| self.state.trust(&k))
                    .ok()
                    .flatten()
                    .map(|t| t.generation);
                Some((old.clone(), new.clone(), accepted))
            }
            _ => None,
        };
        match self.tip.clone() {
            Some(tip) => {
                self.tree = Backend::tree_entries(&tip)?;
                match self.load_manifest(known) {
                    Ok(m) => {
                        if let Some((old, new, accepted)) = rewritten {
                            self.report_rewrite(&m, &old, &new, accepted);
                        }
                        self.manifest = Some(m);
                    }
                    Err(e) => {
                        // The tracking ref has moved to the new tip, so no
                        // later connect sees the rewrite: report it now,
                        // without a manifest to attribute it by.
                        if let Some((old, new, _)) = &rewritten {
                            self.warn_host_rewrite(old, new);
                        }
                        // A refused first contact leaves nothing that could
                        // later appear accepted.
                        if !known {
                            // Best effort: the refusal is the error to report.
                            let _ = git::delete_ref(&self.backend.tracking_ref);
                        }
                        return Err(e);
                    }
                }
            }
            None => {
                if known || self.state.has_trust() {
                    let keys = self.trust_keys()?;
                    let generation = self.state.trust(&keys)?.map_or(0, |t| t.generation);
                    bail!(
                        "branch {} no longer exists on {}, but this repository accepted its manifests up to \
                         generation {generation}: the host deleted it, or the URL is wrong. Refusing to treat it \
                         as a new remote. If every participant confirms it was deleted on purpose, \
                         `git-remote-enc forget {}` drops the local state (DESIGN.md §9)",
                        self.backend.branch,
                        self.backend.url,
                        self.label
                    );
                }
                self.tree = vec![];
                self.manifest = None;
                self.manifest_digest = None;
            }
        }
        self.connected = true;
        Ok(())
    }

    /// The backend history no longer descends from `old`. A participant's
    /// `repack --rewrite-history` since generation `accepted` says so in
    /// the signed manifest (`epoch`); anything else is the host's doing.
    fn report_rewrite(&self, m: &Manifest, old: &str, new: &str, accepted: Option<u64>) {
        match (m.epoch, accepted) {
            (Some(e), Some(a)) if e > a => info(&format!(
                "the history of branch {} on {} was repacked at generation {e} by a participant: \
                 `git-remote-enc log` shows it from there",
                self.backend.branch, self.backend.url
            )),
            _ => self.warn_host_rewrite(old, new),
        }
    }

    fn warn_host_rewrite(&self, old: &str, new: &str) {
        info(&format!(
            "warning: the history of branch {} on {} was rewritten (backend commit {old} is no \
             longer an ancestor of {new}): the host removed or replaced past manifests, so \
             `git-remote-enc log` cannot show them. Check with the other participants",
            self.backend.branch, self.backend.url
        ));
    }

    fn reconnect(&mut self) -> Result<()> {
        self.connected = false;
        self.connect()
    }

    /// `known`: a manifest from this remote was accepted before, so its
    /// trust state must exist.
    fn load_manifest(&mut self, known: bool) -> Result<Manifest> {
        let oid = Backend::blob_oid(&self.tree, MANIFEST_BLOB)
            .ok_or_else(|| {
                anyhow!(
                    "branch {} on {} exists but carries no manifest: not an encrypted remote (refusing to touch it)",
                    self.backend.branch,
                    self.backend.url
                )
            })?
            .to_owned();
        let blob = read_manifest_blob(&oid)?;
        let identities = self.identities()?;
        let envelope = crypto::decrypt_to_vec(identities, &blob)?;
        let (text, sig) =
            split_envelope(&envelope).ok_or_else(|| anyhow!("manifest is not signed"))?;

        // Who may have signed this: the previously accepted participant list,
        // or on first contact the configured one. Either way the signature is
        // checked before the manifest text is parsed. Only trust on first use
        // takes the signer list from the unauthenticated manifest itself.
        let keys = self.trust_keys()?;
        let own = self.state.trust(&keys)?;
        if own.is_none() && known {
            bail!(
                "the local trust state for {} ({}) is missing although manifests were accepted from it; \
                 refusing to start over from first contact. `git-remote-enc forget {}` drops what is left \
                 (DESIGN.md §9)",
                self.label,
                self.state.dir().display(),
                self.label
            );
        }
        let (allowed_texts, parsed) = match (&own, &self.cfg.participants) {
            (Some(t), _) => (t.participants.clone(), None),
            (None, Some(p)) => (p.clone(), None),
            (None, None) => {
                let m = Manifest::parse(text).context("parsing manifest")?;
                (m.participants.clone(), Some(m))
            }
        };
        let signer = verified_signer(&allowed_texts, text, sig)?;
        let m = match parsed {
            Some(m) => m,
            None => Manifest::parse(text).context("parsing manifest")?,
        };

        // Nothing accepted under this URL: the same repository may be known
        // under another spelling of it (scp-style vs ssh://, an insteadOf).
        // Its trust state then applies, signer and anti-rollback included.
        let trust = match own {
            Some(t) => Some(t),
            None => match self.state.trust_for_repo(&m.repo_id, &keys)? {
                Some((t, dir)) => {
                    verified_signer(&t.participants, text, sig)?;
                    info(&format!(
                        "{} is repository {} already known locally (state {}); continuing from generation {}",
                        self.backend.url,
                        m.repo_id,
                        dir.display(),
                        t.generation
                    ));
                    Some(t)
                }
                None => None,
            },
        };

        // Pinned out of band: the only rollback and substitution bound a
        // first contact has, since there is no local state yet.
        if let Some(r) = &self.cfg.repo
            && *r != m.repo_id
        {
            bail!(
                "{} serves repository {}, but enc-repo pins {r}: the host substituted another remote, \
                 or the URL is wrong. Refusing it",
                self.backend.url,
                m.repo_id
            );
        }
        if let Some(g) = self.cfg.min_generation
            && m.generation < g
        {
            bail!(
                "rollback detected: remote manifest is generation {} but enc-minGeneration requires at least {g}",
                m.generation
            );
        }
        self.check_generation_jump(&m, trust.as_ref())?;
        match &trust {
            Some(t) => {
                if t.repo_id != m.repo_id {
                    bail!(
                        "{} now serves a different repository (repo id {} → {}): it was recreated, or the host \
                         replaced it. Refusing it. Confirm with the participants out of band before \
                         `git-remote-enc forget {}`; the next first contact then needs a pinned participant list",
                        self.backend.url,
                        t.repo_id,
                        m.repo_id,
                        self.label
                    );
                }
                if m.generation < t.generation {
                    bail!(
                        "rollback detected: remote manifest is generation {} but generation {} was already accepted",
                        m.generation,
                        t.generation
                    );
                }
                // Two different manifests with one generation: the history
                // forked (the host served another view, or rewound the branch
                // under a pusher). Both are signed: refused unless the
                // participants settled on this one and turned that off.
                let forked_here = m.generation == t.generation
                    && t.digest
                        .as_ref()
                        .is_some_and(|d| *d != crypto::sha256_hex(text.as_bytes()));
                // The next generation names its predecessor: not the one
                // accepted here means the same fork, one generation later.
                let forked_before = Some(m.generation) == t.generation.checked_add(1)
                    && m.previous.is_some()
                    && t.digest.is_some()
                    && m.previous != t.digest;
                let fork = if forked_here {
                    Some(format!(
                        "{} now serves a different manifest for generation {} than the one accepted \
                         earlier",
                        self.backend.url, m.generation
                    ))
                } else if forked_before {
                    Some(format!(
                        "{} serves a generation {} that does not follow the generation {} accepted \
                         earlier",
                        self.backend.url, m.generation, t.generation
                    ))
                } else {
                    None
                };
                match fork {
                    Some(f) if self.cfg.refuse_forks => bail!(
                        "{f}: the remote's history forked (the host served another view, or rewound \
                         the branch under a pusher). Refusing it. Once the participants agree this \
                         view is the one to keep, `git -c enc.refuseForks=false fetch` accepts it"
                    ),
                    Some(f) => info(&format!(
                        "warning: {f}; the remote's history forked, check with the other participants"
                    )),
                    None => {}
                }
            }
            None if self.cfg.participants.is_some() => info(&format!(
                "first contact with {}: repository {} at generation {}, manifest signed by configured \
                 participant {signer}{}",
                self.backend.url,
                m.repo_id,
                m.generation,
                unpinned_hint(&self.cfg)
            )),
            None if self.cfg.trust_on_first_use => info(&format!(
                "first contact with {}: trusting repository {} at generation {}, manifest signed by \
                 {signer} (enc.trustOnFirstUse)",
                self.backend.url, m.repo_id, m.generation
            )),
            None => bail!(
                "first contact with {}: no participant list to check its signer against. The manifest is \
                 signed by {signer}; confirm that fingerprint with the remote's owner, then either pin the \
                 participants (git config --add remote.<name>.enc-participants \"<public key>\", or \
                 git -c enc.participants=\"<public key>\" clone …) or accept it unverified with \
                 enc.trustOnFirstUse=true",
                self.backend.url
            ),
        }
        // Only an admin of the accepted manifest may change who reads or
        // administers. A remote created before admins existed has none, so any
        // trusted signer may change these lists.
        if let Some(t) = &trust
            && !t.admins.is_empty()
            && !(same_keys(&t.participants, &m.participants)? && same_keys(&t.admins, &m.admins)?)
        {
            verified_signer(&t.admins, text, sig).map_err(|_| {
                anyhow!(
                    "manifest generation {} changes the participant or admin list but is not signed by an \
                     admin; refusing it",
                    m.generation
                )
            })?;
            // Once a remote has admins it keeps some: an empty list (or a
            // version 1 manifest, which has none) would hand the role to
            // every participant.
            if m.admins.is_empty() {
                bail!(
                    "manifest generation {} removes every admin; refusing it",
                    m.generation
                );
            }
        }
        // Validate the new lists now so a later push gets a clear error.
        Participant::parse_all(&m.participants).context("manifest participant list")?;
        check_admins(&m.participants, &m.admins).context("manifest admin list")?;
        self.save_trust(&trust_in(&m, text, self.tip.as_deref()))?;
        self.manifest_digest = Some(crypto::sha256_hex(text.as_bytes()));
        Ok(m)
    }

    /// Each push adds one commit to the backend branch's first-parent chain
    /// and one generation, so a generation cannot run ahead of those
    /// commits: without this bound a participant could push generation
    /// 2^64 - 1, after which nobody can push again and going back is refused
    /// as a rollback. Counted from the commit of the accepted manifest when
    /// the history still descends from it, else, on first contact or after
    /// a participant's rewrite (`epoch` above the accepted generation), from
    /// the root, or from the manifest's `epoch` where the history really
    /// starts there ([`rewrite_epoch`]). A new remote's first push may start
    /// on a staging chain (DESIGN.md §5.1), whose commits then count too: a
    /// slightly looser bound.
    fn check_generation_jump(&self, m: &Manifest, trust: Option<&Trust>) -> Result<()> {
        let Some(tip) = self.tip.as_deref() else {
            return Ok(());
        };
        let count = |range: &str| -> Result<u64> {
            git::run_line(["rev-list", "--count", "--first-parent", range])?
                .parse()
                .context("rev-list --count")
        };
        // Since a rewrite, the history starts at its epoch.
        let from_epoch = |epoch: u64| -> Result<(u64, u64)> {
            Ok((epoch, epoch.saturating_sub(1).saturating_add(count(tip)?)))
        };
        let (base, limit) = match trust {
            Some(t) => match &t.commit {
                Some(c) if git::has_object(c)? && git::is_ancestor(c, tip)? => (
                    t.generation,
                    t.generation.saturating_add(count(&format!("{c}..{tip}"))?),
                ),
                // A participant's rewrite (connect reports it as such).
                _ => match m.epoch {
                    Some(e) if e > t.generation && rewrite_epoch(tip)? == Some(e) => from_epoch(e)?,
                    // Older state, or the host's rewrite (reported by connect).
                    _ => return Ok(()),
                },
            },
            None => match m.epoch {
                Some(e) if rewrite_epoch(tip)? == Some(e) => from_epoch(e)?,
                _ => from_epoch(0)?,
            },
        };
        if m.generation > limit {
            bail!(
                "manifest generation {} is more than the backend history allows ({limit}, from generation \
                 {base} and one per commit since): a participant or the host wrote an invalid manifest. \
                 Refusing it",
                m.generation
            );
        }
        Ok(())
    }

    // ---- list -------------------------------------------------------------

    /// `(refs, HEAD target)` for the `list` command. `for_push` tolerates a
    /// remote that does not exist yet.
    pub fn list(&mut self, for_push: bool) -> Result<(RefList, Option<String>)> {
        // git runs the pre-push hook after `list for-push` and before
        // `push`: refusing here is the last point where nothing has left.
        if for_push
            && !self.cfg.allow_lfs
            && let Some(hook) = lfs_pre_push_hook()?
        {
            bail!(
                "Git LFS may run before this push ({hook}): it would upload every LFS-tracked \
                 file of the pushed commits, in clear, to the LFS server (lfs.url, usually the \
                 forge), outside the encrypted remote. Refusing to push. Commit the \
                 files the fix needs outside LFS, point lfs.url at nothing in this clone's config \
                 (it overrides .lfsconfig), then set remote.<name>.enc-allowLfs=true; or remove \
                 the hook"
            );
        }
        self.connect()?;
        match &self.manifest {
            Some(m) => {
                let head = m.head.clone().filter(|h| m.ref_oid(h).is_some());
                Ok((m.refs.clone(), head))
            }
            None if for_push => Ok((vec![], None)),
            None => bail!(
                "no encrypted remote at {} (branch {})",
                self.backend.url,
                self.backend.branch
            ),
        }
    }

    /// The decrypted manifest for display. Pack keys decrypt the whole
    /// history, so they are shown only when `with_keys` is set.
    pub fn manifest_text(&mut self, with_keys: bool) -> Result<Option<Zeroizing<String>>> {
        self.connect()?;
        Ok(self.manifest.as_ref().map(|m| {
            if with_keys {
                m.serialize()
            } else {
                Zeroizing::new(m.serialize_redacted())
            }
        }))
    }

    /// Every manifest in the backend history, newest first, as far as the
    /// local identities can decrypt them: the audit trail the anonymous
    /// backend commits do not give.
    pub fn history(&mut self) -> Result<Vec<HistoryEntry>> {
        self.connect()?;
        if self.tip.is_none() {
            bail!("no encrypted remote at {}", self.backend.url);
        }
        let commits: Vec<String> = pushes(&self.backend.tracking_ref)?
            .into_iter()
            .map(|(c, _)| c)
            .collect();
        let mut entries = Vec::new();
        let mut previous: Option<Manifest> = None;
        // Each push appends one commit and one generation: the commit at
        // index i carries generation i + 1 unless the host rewrote history.
        let mut expected: u64 = 1;
        let mut links: Vec<Option<Link>> = Vec::new();
        for commit in &commits {
            let commit = commit.as_str();
            let entry = match self.read_historical(commit) {
                Ok((m, signer, digest)) => {
                    // A participant's rewrite starts the history over.
                    let history_start = m.epoch == Some(m.generation);
                    if history_start {
                        expected = m.generation;
                    }
                    if m.generation != expected {
                        entries.push(HistoryEntry::Discontinuity {
                            expected,
                            found: m.generation,
                        });
                    }
                    expected = m.generation;
                    links.push(Some(Link {
                        entry: entries.len(),
                        fingerprint: signer.clone(),
                        digest,
                        previous: m.previous.clone(),
                    }));
                    let e = HistoryEntry::Readable {
                        commit: commit.to_owned(),
                        generation: m.generation,
                        time: m.time,
                        signer: m
                            .participants
                            .iter()
                            .find(|p| {
                                Participant::parse(p).is_ok_and(|p| p.fingerprint() == signer)
                            })
                            .cloned()
                            .unwrap_or(signer),
                        refs: ref_changes(previous.as_ref(), &m),
                        participants: ParticipantDiff::between(
                            previous.as_ref().map_or(&[][..], |p| &p.participants),
                            &m.participants,
                        )?,
                        admins: ParticipantDiff::between(
                            previous.as_ref().map_or(&[][..], |p| &p.admins),
                            &m.admins,
                        )?,
                        base: previous.as_ref().map(|p| p.generation),
                        repacked: history_start
                            || previous
                                .as_ref()
                                .is_some_and(|p| p.packs.iter().any(|old| !m.packs.contains(old))),
                        history_start,
                        verified: false,
                        base_verified: true,
                        time_regressed: matches!(
                            (previous.as_ref().and_then(|p| p.time), m.time),
                            (Some(before), Some(now)) if now < before
                        ),
                    };
                    previous = Some(m);
                    e
                }
                Err(e) => {
                    links.push(None);
                    HistoryEntry::Unreadable {
                        commit: commit.to_owned(),
                        reason: format!("{e:#}"),
                    }
                }
            };
            entries.push(entry);
            expected = expected.saturating_add(1);
        }

        // Signatures alone prove nothing here: the host can insert manifests
        // signed by its own key named after a participant. The accepted tip is
        // authentic, as is every manifest linked to it through the `previous`
        // chain, back to the first break.
        let mut want = self.manifest_digest.clone();
        for link in links.iter().rev() {
            let Some(link) = link else {
                break;
            };
            if want.as_ref() != Some(&link.digest) {
                break;
            }
            if let Some(HistoryEntry::Readable { verified, .. }) = entries.get_mut(link.entry) {
                *verified = true;
            }
            want = link.previous.clone();
        }
        // An unverified manifest's own participant list may be forged, so
        // it does not get to name its signer.
        let mut previous_verified = true;
        for link in links.iter().flatten() {
            if let Some(HistoryEntry::Readable {
                verified,
                signer,
                base_verified,
                ..
            }) = entries.get_mut(link.entry)
            {
                if !*verified {
                    signer.clone_from(&link.fingerprint);
                }
                *base_verified = previous_verified;
                previous_verified = *verified;
            }
        }
        entries.reverse();
        Ok(entries)
    }

    /// The manifest at backend `commit`, the fingerprint of its signer and
    /// the SHA-256 of its text.
    fn read_historical(&mut self, commit: &str) -> Result<(Manifest, String, String)> {
        let tree = Backend::tree_entries(commit)?;
        let oid = Backend::blob_oid(&tree, MANIFEST_BLOB)
            .ok_or_else(|| anyhow!("no manifest"))?
            .to_owned();
        let blob = read_manifest_blob(&oid)?;
        let envelope = crypto::decrypt_to_vec(self.identities()?, &blob)?;
        let (text, sig) =
            split_envelope(&envelope).ok_or_else(|| anyhow!("manifest is not signed"))?;
        let signer = crypto::signature_key(text.as_bytes(), sig)?;
        Ok((
            Manifest::parse(text)?,
            signer,
            crypto::sha256_hex(text.as_bytes()),
        ))
    }

    // ---- fetch ------------------------------------------------------------

    /// Index every pack not yet indexed locally, in manifest order.
    pub fn fetch(&mut self) -> Result<()> {
        self.connect()?;
        let Some(m) = self.manifest.clone() else {
            return Ok(());
        };
        let have = self.state.have()?;
        let todo: Vec<&Pack> = m.packs.iter().filter(|p| !have.contains(&p.id)).collect();
        for (i, pack) in todo.iter().enumerate() {
            let blobs = parts::find(&self.tree, &pack.id).ok_or_else(|| {
                anyhow!(
                    "pack {} listed in manifest is missing on the remote",
                    pack.id
                )
            })?;
            let label = format!("pack {}/{}", i.saturating_add(1), todo.len());
            self.index_pack(pack, blobs, &label)?;
            self.state.add_have(&pack.id)?;
        }
        Ok(())
    }

    /// Decrypt the pack held by `blobs` (its parts, in order) into the object
    /// store.
    fn index_pack(&self, pack: &Pack, blobs: Vec<Oid>, label: &str) -> Result<()> {
        let key = age::x25519::Identity::from_str(&pack.key)
            .map_err(|e| anyhow!("pack {}: bad key in manifest: {e}", pack.id))?;
        // Check the blob against its name before anything reaches the
        // object store: one extra read of a local object.
        let size = parts::total_size(&blobs)?;
        let (mut hashed, digest) = HashReader::new(MeterReader::new(
            BlobChain::new(blobs.clone()),
            Meter::new(format!("verifying {label}"), Some(size)),
        ));
        io::copy(&mut hashed, &mut io::sink())
            .with_context(|| format!("reading pack blob {}", pack.id))?;
        drop(hashed);
        let got = crypto::finalize_shared(&digest);
        if got != pack.id {
            bail!(
                "pack blob {} does not match its manifest name (got {got})",
                pack.id
            );
        }

        let mut plain = crypto::decrypt_stream(&key, BufReader::new(BlobChain::new(blobs)))?;
        let progress = progress::enabled();
        if progress {
            info(&format!("decrypting {label} ({})", progress::human(size)));
        }
        let mut args = vec!["index-pack", "--stdin", "--fix-thin"];
        if progress {
            args.push("-v");
        }
        args.extend(self.cfg.fsck.as_deref());
        let mut index = Streaming::writer_tee(args, progress)?;
        {
            let mut stdin = index.stdin()?;
            io::copy(&mut plain, &mut stdin)
                .with_context(|| format!("decrypting pack {}", pack.id))?;
        }
        index.finish()?;
        Ok(())
    }

    // ---- push -------------------------------------------------------------

    pub fn push(&mut self, specs: &[RefSpec]) -> Result<Vec<PushStatus>> {
        self.push_with(specs, Op::Push)
    }

    /// Replace every pack with one holding exactly what the refs reach, as a
    /// new generation; with `rewrite_history`, as a commit descending from
    /// none of the backend history, so the host can drop the old blobs.
    /// DESIGN.md §7.
    pub fn repack(&mut self, rewrite_history: bool) -> Result<Repacked> {
        self.connect()?;
        if self.manifest.is_none() {
            bail!("no encrypted remote at {}", self.backend.url);
        }
        self.repack_before = None;
        self.push_with(
            &[],
            Op::Repack {
                rewrite: rewrite_history,
            },
        )?;
        Ok(Repacked {
            before: self.repack_before.unwrap_or_default(),
            after: self.pack_usage()?,
        })
    }

    /// `(packs, bytes of pack blobs)` in the current backend tree.
    fn pack_usage(&self) -> Result<(usize, u64)> {
        let packs = self.manifest.as_ref().map_or(0, |m| m.packs.len());
        let mut bytes = 0u64;
        for (_, ty, oid, name) in &self.tree {
            if ty == "blob" && name != MANIFEST_BLOB {
                bytes = bytes.saturating_add(git::object_size(oid)?);
            }
        }
        Ok((packs, bytes))
    }

    /// The remote's participant and admin lists, and how the configured
    /// ones differ from them (`None` where the configuration sets none).
    pub fn access(&mut self) -> Result<Access> {
        self.connect()?;
        let m = self
            .manifest
            .as_ref()
            .ok_or_else(|| anyhow!("no encrypted remote at {}", self.backend.url))?;
        let diff = |current: &[String], configured: &Option<Vec<String>>| {
            configured
                .as_ref()
                .map(|c| ParticipantDiff::between(current, c))
                .transpose()
        };
        Ok(Access {
            participants_diff: diff(&m.participants, &self.cfg.participants)?,
            admins_diff: diff(&m.admins, &self.cfg.admins)?,
            participants: m.participants.clone(),
            admins: m.admins.clone(),
        })
    }

    /// Replace the remote's participant list with the configured one, as a
    /// push that changes no ref.
    pub fn apply_participants(&mut self) -> Result<()> {
        self.connect()?;
        if self.manifest.is_none() {
            bail!("no encrypted remote at {}", self.backend.url);
        }
        self.push_with(&[], Op::SetParticipants).map(drop)
    }

    fn push_with(&mut self, specs: &[RefSpec], op: Op) -> Result<Vec<PushStatus>> {
        let result = self.push_attempts(specs, op);
        if let Some(staged) = self.staged.take() {
            self.discard(staged);
        }
        result
    }

    fn push_attempts(&mut self, specs: &[RefSpec], op: Op) -> Result<Vec<PushStatus>> {
        self.connect()?;
        for attempt in 1..=PUSH_ATTEMPTS {
            if let Some(statuses) = self.try_push(specs, op)? {
                return Ok(statuses);
            }
            info(&format!(
                "remote changed while pushing, retrying ({attempt}/{PUSH_ATTEMPTS})"
            ));
            self.reconnect()?;
        }
        bail!("the remote kept changing under us; retry the push")
    }

    /// Delete a staged pack's upload branch from the host, if it has one.
    fn discard(&self, staged: Staged) {
        if let Some(branch) = &staged.upload_branch
            && let Err(e) = self.backend.delete_upload(branch)
        {
            info(&format!(
                "warning: could not delete the upload branch {branch}; delete it by hand: {e:#}"
            ));
        }
    }

    /// One attempt. `None` means the compare-and-swap lost; the caller
    /// reconnects and calls again. `Op::SetParticipants` replaces the list
    /// with the configured one; otherwise an existing remote keeps its own.
    fn try_push(&mut self, specs: &[RefSpec], op: Op) -> Result<Option<Vec<PushStatus>>> {
        let set_participants = op == Op::SetParticipants;
        let repack = match op {
            Op::Repack { rewrite } => Some(rewrite),
            _ => None,
        };
        let is_new = self.manifest.is_none();
        // What this attempt repacks.
        let usage = repack.map(|_| self.pack_usage()).transpose()?;
        let mut m = match &self.manifest {
            Some(m) => m.clone(),
            None => Manifest {
                repo_id: crypto::random_id()?,
                ..Manifest::default()
            },
        };

        // Participants: a new remote takes the configured list. An existing one
        // keeps its own unless explicitly changed, so a stale or partial local
        // list never rewrites it as a side effect.
        let participant_texts = match (&self.cfg.participants, is_new || set_participants) {
            (Some(p), true) => p.clone(),
            (None, true) if is_new => bail!(
                "creating an encrypted remote needs its participants: \
                 git config --add remote.<name>.enc-participants \"$(cat ~/.ssh/enc_key.pub)\" \
                 (a key not registered with any forge, which would identify you: DESIGN.md §6.4)"
            ),
            (None, true) if self.cfg.admins.is_some() => m.participants.clone(),
            (None, true) => bail!(
                "no participant list to apply: set remote.<name>.enc-participants (or enc.participants)"
            ),
            (Some(p), false) => {
                if !ParticipantDiff::between(&m.participants, p)?.is_empty() {
                    info(&format!(
                        "warning: the configured participants differ from {}'s; a push does not change them. \
                         `git-remote-enc participants {}` shows the difference, `--apply` applies it",
                        self.label, self.label
                    ));
                }
                m.participants.clone()
            }
            (None, false) => m.participants.clone(),
        };
        if set_participants && !is_new {
            let admins_unchanged = match &self.cfg.admins {
                Some(a) => same_keys(&m.admins, a)?,
                None => true,
            };
            if admins_unchanged && same_keys(&m.participants, &participant_texts)? {
                return Ok(Some(vec![]));
            }
        }
        let participants = Participant::parse_all(&participant_texts)?;
        if !participants.iter().any(Participant::can_sign) {
            bail!("at least one participant must be an SSH key (age recipients cannot sign)");
        }

        // Our signing key must be allowed to write: a participant of the
        // current manifest, or of the initial list when creating.
        let signer = self.signing_key()?;
        // Fail before anything is written if the accepted state cannot be
        // recorded afterwards.
        self.trust_keys()?;
        let previous = if is_new {
            None
        } else {
            Some(Participant::parse_all(&m.participants)?)
        };
        let allowed = previous.as_ref().unwrap_or(&participants);
        if !allowed.iter().any(|p| p.matches(&signer)) {
            bail!(
                "your signing key {} is not a participant of this remote",
                signer.fingerprint(ssh_key::HashAlg::Sha256)
            );
        }
        if !participants.iter().any(|p| p.matches(&signer)) {
            info(
                "warning: your own key is not in the new participant list; you will lose read access",
            );
        }

        // Admins: the configured list or the creator for a new remote; the
        // configured list, if any, for `participants --apply`; else unchanged.
        let admin_texts = if is_new {
            match &self.cfg.admins {
                Some(a) => a.clone(),
                None => participants
                    .iter()
                    .filter(|p| p.matches(&signer))
                    .map(|p| p.text().to_owned())
                    .collect(),
            }
        } else if set_participants {
            self.cfg.admins.clone().unwrap_or_else(|| m.admins.clone())
        } else {
            m.admins.clone()
        };
        check_admins(&participant_texts, &admin_texts)?;
        let changes_access = !is_new
            && !(same_keys(&m.participants, &participant_texts)?
                && same_keys(&m.admins, &admin_texts)?);
        if changes_access {
            if !m.admins.is_empty() {
                let admins = Participant::parse_all(&m.admins)?;
                if !admins.iter().any(|a| a.matches(&signer)) {
                    bail!(
                        "only an admin of {} may change its participant or admin list; its admins are {}",
                        self.label,
                        admins
                            .iter()
                            .map(Participant::fingerprint)
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                }
                if admin_texts.is_empty() {
                    bail!("refusing to remove every admin of {}", self.label);
                }
            } else if admin_texts.is_empty() {
                info(&format!(
                    "warning: {} has no admin, so any participant may change its participant list; \
                     set remote.<name>.enc-admins and apply it with `git-remote-enc participants --apply`",
                    self.label
                ));
            }
        }

        // Fast-forward checks (git does not do them reliably for helpers).
        let mut statuses = Vec::new();
        let mut accepted: Vec<(&RefSpec, Option<Oid>)> = Vec::new();
        for spec in specs {
            let Some(src) = &spec.src else {
                accepted.push((spec, None));
                continue;
            };
            let Some(new) = git::rev_parse(src)? else {
                statuses.push(PushStatus::Error(spec.dst.clone(), "unknown source".into()));
                continue;
            };
            if let Some(old) = m.ref_oid(&spec.dst)
                && !spec.force
                && old != new
            {
                if !git::has_object(old)? {
                    statuses.push(PushStatus::Error(spec.dst.clone(), "fetch first".into()));
                    continue;
                }
                if !git::is_ancestor(old, &new)? {
                    statuses.push(PushStatus::Error(
                        spec.dst.clone(),
                        "non-fast-forward".into(),
                    ));
                    continue;
                }
            }
            accepted.push((spec, Some(new)));
        }
        if accepted.is_empty() && !set_participants && repack.is_none() {
            return Ok(Some(statuses));
        }

        // A losing attempt's pack. Landed (the manifest lists it although
        // git reported a failure): its objects are ours, so no fetch
        // downloads it, and listing it again would make the manifest
        // unreadable; a landed repack is done. Otherwise it is reused below
        // for the same wants unless every pushed tip is already a ref
        // (someone pushed the same tips: it would be redundant) or a repack
        // has since dropped a pack it is thin against. A repack's pack is
        // not thin: the same refs are enough.
        let staged = match self.staged.take() {
            Some(s) if m.packs.iter().any(|p| p.id == s.id) => {
                let done = repack.is_some() && matches!(m.packs.as_slice(), [p] if p.id == s.id);
                let added = self.state.add_have(&s.id);
                self.discard(s);
                added?;
                if done {
                    return Ok(Some(statuses));
                }
                None
            }
            s => s,
        };
        // Keep the first attempt's usage: a retry may start from our own
        // repack after another push landed on top of it.
        if let Some(u) = usage {
            self.repack_before.get_or_insert(u);
        }
        // The new pack is built from local objects: every pack must be
        // indexed here first.
        if repack.is_some() {
            self.fetch()?;
        }

        let known: Vec<Oid> = m.refs.iter().map(|(oid, _)| oid.clone()).collect();
        let (wants, excludes) = if repack.is_some() {
            // Everything the refs reach, and nothing else.
            let have = git::have_objects(&known)?;
            if let Some(missing) = known.iter().find(|k| !have.contains(k)) {
                bail!("{missing}, named by a ref of {}, is not here", self.label);
            }
            (known.clone(), Vec::new())
        } else {
            // Everything reachable from a manifest ref is already on the
            // remote.
            let wants: Vec<Oid> = accepted.iter().filter_map(|(_, o)| o.clone()).collect();
            let excludes = git::have_objects(&known)?;
            (wants, excludes)
        };
        // LFS uploads a file's content from its own pre-push hook, which an
        // encrypted push refuses (`list`) or does not run: the other
        // participants would get the pointer and nothing to resolve it.
        if repack.is_none()
            && !self.cfg.allow_lfs
            && !wants.is_empty()
            && let Some(path) = git::lfs_pointers(&wants, &excludes)?.first()
        {
            bail!(
                "{path} is a Git LFS pointer: the file itself is in LFS storage, which an encrypted \
                 push does not carry, so the other participants would get the pointer only. Commit \
                 such files outside LFS (git lfs migrate export), or set \
                 remote.<name>.enc-allowLfs=true to push the pointers anyway"
            );
        }
        // A shallow clone's pack would reference parents it does not hold,
        // and every fetch of it would fail.
        if let Some(c) = git::shallow_boundaries(&wants, &excludes)?.first() {
            bail!(
                "this clone is shallow and the pushed history reaches its boundary at {c}, whose \
                 parents are not here: the other participants could not fetch the push. Fetch the \
                 full history first (git fetch --unshallow <the remote it was cloned from>), then \
                 push again"
            );
        }
        let mut sorted_wants = wants.clone();
        sorted_wants.sort_unstable();
        let reusable = |s: &Staged| {
            s.wants == sorted_wants
                && (repack.is_some()
                    || (wants.iter().any(|w| !known.contains(w))
                        && s.bases.iter().all(|b| m.packs.iter().any(|p| &p.id == b))))
        };
        let pack = match staged {
            Some(s) if reusable(&s) => Some(s),
            old => {
                if let Some(old) = old {
                    self.discard(old);
                }
                if wants.is_empty() {
                    None
                } else {
                    let bases = m.packs.iter().map(|p| p.id.clone()).collect();
                    let built = self.build_pack(&wants, &excludes, repack.is_none())?;
                    // The old packs are about to be dropped: the new one
                    // must hold every object the refs reach.
                    if repack.is_some()
                        && let Some(b) = &built
                    {
                        let reachable = git::count_objects(&wants)?;
                        if u64::from(b.count) != reachable {
                            bail!(
                                "the new pack holds {} objects but the refs reach {reachable}; \
                                 nothing was changed",
                                b.count
                            );
                        }
                    }
                    built
                        .map(|p| self.stage(p, sorted_wants, bases))
                        .transpose()?
                }
            }
        };
        // Held by `self` from here on, so whatever ends this attempt, its
        // upload branch is deleted (`push_with`) or reused (a lost race).
        self.staged = pack;
        let pack = self
            .staged
            .as_ref()
            .map(|p| (p.id.clone(), p.key.clone(), p.blobs.clone()));

        m.generation = m
            .generation
            .checked_add(1)
            .ok_or_else(|| anyhow!("generation overflow"))?;
        m.previous = self.manifest_digest.clone();
        m.time = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .context("the clock is before 1970")?
                .as_secs(),
        );
        for (spec, new) in &accepted {
            match new {
                Some(oid) => m.set_ref(&spec.dst, oid),
                None => m.delete_ref(&spec.dst),
            }
        }
        if m.head.is_none() {
            m.head = accepted
                .iter()
                .filter(|(_, o)| o.is_some())
                .map(|(s, _)| s.dst.clone())
                .find(|d| d.starts_with("refs/heads/"));
        }
        m.participants = participant_texts;
        m.admins = admin_texts;
        if repack.is_some() {
            m.packs.clear();
        }
        if repack == Some(true) {
            m.epoch = Some(m.generation);
        }
        if let Some((id, key, _)) = &pack {
            m.packs.push(Pack {
                id: id.clone(),
                key: String::clone(key),
            });
        }

        let text = m.serialize();
        let sig = crypto::sign(&signer, text.as_bytes())?;
        let envelope = join_envelope(&text, &sig);
        let manifest_blob = crypto::encrypt_to_participants(&participants, &envelope, Vec::new())?;
        let mut upserts = vec![(MANIFEST_BLOB.to_owned(), git::hash_object(&manifest_blob)?)];
        if let Some((_, _, blobs)) = &pack {
            upserts.extend(blobs.iter().cloned());
        }
        let upload = self.staged.as_ref().and_then(|s| s.upload_tip.clone());
        let commit = match repack {
            None => Backend::build_commit(self.tip.as_deref(), upload.as_deref(), &upserts)?,
            Some(false) => {
                Backend::build_replacing(self.tip.as_deref(), upload.as_deref(), &upserts)?
            }
            Some(true) => Backend::build_rewrite(upload.as_deref(), &upserts, m.generation)?,
        };

        match self.backend.push(&commit, self.tip.as_deref())? {
            PushOutcome::StaleLease => Ok(None),
            PushOutcome::Failed(stderr) => {
                // The lease is also enforced by the server; if the branch has
                // moved since we read it, this was a lost race, not a failure.
                if self.backend.fetch_tip()? != self.tip {
                    return Ok(None);
                }
                if repack == Some(true) {
                    bail!(
                        "pushing to {}: {stderr}\nRewriting the history replaces branch {} by a \
                         commit that does not descend from it: the host must allow a forced \
                         update of that branch (GitLab: Settings > Repository > Protected \
                         branches, \"Allowed to force push\")",
                        self.backend.url,
                        self.backend.branch
                    );
                }
                bail!("pushing to {}: {stderr}", self.backend.url)
            }
            PushOutcome::Done => {
                if let Some(p) = self.staged.take() {
                    let added = self.state.add_have(&p.id);
                    self.discard(p);
                    added?;
                }
                self.save_trust(&trust_in(&m, &text, Some(&commit)))?;
                self.manifest_digest = Some(crypto::sha256_hex(text.as_bytes()));
                self.tip = Some(commit.clone());
                self.tree = Backend::tree_entries(&commit)?;
                self.manifest = Some(m);
                for (spec, _) in &accepted {
                    statuses.push(PushStatus::Ok(spec.dst.clone()));
                }
                Ok(Some(statuses))
            }
        }
    }

    fn signing_key(&mut self) -> Result<PrivateKey> {
        if let Some(path) = self.cfg.signing_key.clone() {
            let ids = crypto::load_identities(std::slice::from_ref(&path))?;
            return ids
                .iter()
                .find_map(Identity::ssh_key)
                .cloned()
                .ok_or_else(|| anyhow!("{} is not an SSH private key", path.display()));
        }
        self.identities()?
            .iter()
            .find_map(Identity::ssh_key)
            .cloned()
            .ok_or_else(|| {
                anyhow!("no SSH private key to sign with; pushing needs an ssh-ed25519 identity")
            })
    }

    /// `pack-objects` over `wants` minus `excludes` (thin against them when
    /// `thin`), encrypted to a fresh key into temp files of at most
    /// `part_size` bytes. `None` when there is nothing to send.
    fn build_pack(&self, wants: &[Oid], excludes: &[Oid], thin: bool) -> Result<Option<BuiltPack>> {
        let mut revs = String::new();
        for w in wants {
            revs.push_str(w);
            revs.push('\n');
        }
        for e in excludes {
            revs.push('^');
            revs.push_str(e);
            revs.push('\n');
        }
        let progress = progress::enabled();
        let mut args = vec![
            "pack-objects",
            "--revs",
            "--stdout",
            if progress { "--all-progress" } else { "-q" },
            "--delta-base-offset",
        ];
        if thin {
            args.push("--thin");
        }
        let mut po = Streaming::reader_tee(args, Some(revs.as_bytes()), progress)?;
        let mut out = po.stdout()?;
        let mut header = [0u8; 12];
        out.read_exact(&mut header)
            .context("pack-objects produced no pack")?;
        let count = header
            .get(8..12)
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .map(u32::from_be_bytes)
            .ok_or_else(|| anyhow!("short pack header"))?;
        if count == 0 {
            po.finish()?;
            return Ok(None);
        }

        let key = age::x25519::Identity::generate();
        let writer = PartWriter::new(&self.state.temp_path("pack"), self.cfg.part_size);
        let mut enc = crypto::encrypt_stream(&key.to_public(), HashWriter::new(writer))?;
        enc.write_all(&header)?;
        io::copy(&mut out, &mut enc).context("encrypting pack")?;
        let (writer, id) = enc.finish()?.finish();
        let paths = writer.finish()?;
        let built = BuiltPack {
            paths,
            count,
            id,
            key: Zeroizing::new(key.to_string().expose_secret().to_owned()),
        };
        po.finish()?;
        Ok(Some(built))
    }

    /// Store a built pack's parts as blobs and, when they exceed one upload
    /// batch, push them ahead of the manifest on a branch of their own, a
    /// batch at a time: the final push then sends only the manifest.
    fn stage(&self, built: BuiltPack, wants: Vec<Oid>, bases: Vec<String>) -> Result<Staged> {
        let names: Vec<String> = if built.paths.len() == 1 {
            vec![format!("{}.age", built.id)]
        } else {
            (0..built.paths.len())
                .map(|n| parts::part_name(&built.id, n))
                .collect()
        };
        let sizes = built
            .paths
            .iter()
            .map(|p| Ok(std::fs::metadata(p)?.len()))
            .collect::<Result<Vec<u64>>>()?;
        let total = sizes.iter().fold(0u64, |a, s| a.saturating_add(*s));
        let mut meter = Meter::new("storing pack", Some(total));
        let mut blobs = Vec::new();
        for ((name, path), size) in names.into_iter().zip(&built.paths).zip(&sizes) {
            blobs.push((name, git::hash_object_file(path)?));
            // Best effort: the blob is in the object store now.
            let _ = std::fs::remove_file(path);
            meter.add(*size);
        }
        meter.finish();

        let mut staged = Staged {
            wants,
            bases,
            id: built.id.clone(),
            key: built.key.clone(),
            blobs,
            upload_branch: None,
            upload_tip: None,
        };
        let batch = self.cfg.upload_batch;
        if batch == 0 || total <= batch || staged.blobs.len() < 2 {
            return Ok(staged);
        }
        // Batches of whole parts, each at most `batch` bytes or one part.
        let mut batches: Vec<(Vec<(String, Oid)>, u64)> = Vec::new();
        for (blob, size) in staged.blobs.iter().zip(&sizes) {
            match batches.last_mut() {
                Some((b, len)) if len.saturating_add(*size) <= batch => {
                    b.push(blob.clone());
                    *len = len.saturating_add(*size);
                }
                _ => batches.push((vec![blob.clone()], *size)),
            }
        }
        let branch = self.backend.upload_branch()?;
        for (i, (batch, len)) in batches.iter().enumerate() {
            if progress::enabled() {
                info(&format!(
                    "uploading pack {}, batch {}/{} ({})",
                    progress::human(total),
                    i.saturating_add(1),
                    batches.len(),
                    progress::human(*len)
                ));
            }
            let pushed =
                Backend::build_upload(staged.upload_tip.as_deref(), batch).and_then(|commit| {
                    self.backend.push_upload(&commit, &branch)?;
                    Ok(commit)
                });
            match pushed {
                Ok(commit) => {
                    // On the host from here on, for `discard` to delete.
                    staged.upload_branch = Some(branch.clone());
                    staged.upload_tip = Some(commit);
                }
                Err(e) => {
                    self.discard(staged);
                    return Err(e);
                }
            }
        }
        Ok(staged)
    }
}

/// The backend commits on `rev`'s first-parent walk that carry a manifest,
/// oldest first, with their subjects. The first parents are the pushes; a
/// second parent is the chain of commits that staged a large push's parts.
/// On a new remote, or since a rewrite, that chain is the first push's only
/// parent (DESIGN.md §5.1), so its commits are on the walk and skipped.
fn pushes(rev: &str) -> Result<Vec<(String, String)>> {
    let out = git::run(["log", "--first-parent", "--reverse", "--format=%H %s", rev])?;
    let log = String::from_utf8(out).context("git log output is not UTF-8")?;
    let mut commits = Vec::new();
    for (c, subject) in log.lines().filter_map(|l| l.split_once(' ')) {
        // A staging commit carries no manifest; one that does is a push,
        // whatever its message says.
        if subject == backend::UPLOAD_MESSAGE.trim_end() && !has_manifest(c)? {
            continue;
        }
        commits.push((c.to_owned(), subject.to_owned()));
    }
    Ok(commits)
}

fn has_manifest(commit: &str) -> Result<bool> {
    Ok(Backend::blob_oid(&Backend::tree_entries(commit)?, MANIFEST_BLOB).is_some())
}

/// The epoch `tip`'s history starts at, if a participant's rewrite started
/// it: its oldest push says so in its subject ([`backend::EPOCH_SUBJECT`])
/// and every push is on the first-parent walk, so nothing older is
/// reachable. Without the last condition, a fast-forward could put a forged
/// start under a new first parent and the real history under a second one.
/// The subject is not signed: only a forced update of the branch, i.e. a
/// rewrite, or creating the branch (a new remote, or after deleting it) can
/// place it under the history, so the remote's creator can set any epoch.
/// DESIGN.md §6.2.
fn rewrite_epoch(tip: &str) -> Result<Option<u64>> {
    let pushes = pushes(tip)?;
    let Some(epoch) = pushes.first().and_then(|(_, s)| {
        s.strip_prefix(backend::EPOCH_SUBJECT)
            .and_then(|e| e.parse::<u64>().ok())
    }) else {
        return Ok(None);
    };
    let list = |first_parent: bool| -> Result<String> {
        let mut args = vec!["rev-list"];
        args.extend(first_parent.then_some("--first-parent"));
        args.push(tip);
        String::from_utf8(git::run(args)?).context("rev-list output is not UTF-8")
    };
    let walk = list(true)?;
    let walk: std::collections::HashSet<&str> = walk.lines().collect();
    for c in list(false)?.lines() {
        if !walk.contains(c) && has_manifest(c)? {
            return Ok(None);
        }
    }
    Ok(Some(epoch))
}

/// git picks the transport from the push URL, so a `pushurl` or a
/// `pushInsteadOf` rule that leads away from `enc::` sends pushes to that
/// remote in clear without ever running the helper. Its fetches still run
/// it, and so does the pre-push guard; both refuse such a remote.
fn refuse_plain_push_url(name: &str) -> Result<()> {
    let Some(url) = git::config(&format!("remote.{name}.url"))? else {
        return Ok(());
    };
    for push_url in push_urls(name, &url)? {
        if !push_url.starts_with("enc::") {
            bail!(
                "remote {name} is encrypted ({url}) but git would push to it in clear, to {push_url}, \
                 because of remote.{name}.pushurl or a url.<base>.pushInsteadOf / insteadOf rule. \
                 Refusing to use it until that configuration is removed"
            );
        }
    }
    Ok(())
}

/// The URLs `git push <name>` would push to, as git rewrites them.
fn push_urls(name: &str, url: &str) -> Result<Vec<String>> {
    let rules = |var: &str| -> Result<Vec<(String, String)>> {
        let suffix = format!(".{var}");
        Ok(git::config_regexp(&format!(r"^url\..*\.{var}$"))?
            .into_iter()
            .filter_map(|(key, prefix)| {
                key.strip_prefix("url.")
                    .and_then(|k| k.strip_suffix(&suffix))
                    .map(|base| (base.to_owned(), prefix))
            })
            .collect())
    };
    // The longest matching prefix wins, as in git.
    let rewrite = |url: &str, rules: &[(String, String)]| -> Option<String> {
        rules
            .iter()
            .filter(|(_, prefix)| url.starts_with(prefix.as_str()))
            .max_by_key(|(_, prefix)| prefix.len())
            .map(|(base, prefix)| format!("{base}{}", url.get(prefix.len()..).unwrap_or("")))
    };
    let instead_of = rules("insteadof")?;
    let explicit = git::config_all(&format!("remote.{name}.pushurl"))?;
    if !explicit.is_empty() {
        return Ok(explicit
            .iter()
            .map(|u| rewrite(u, &instead_of).unwrap_or_else(|| u.clone()))
            .collect());
    }
    let push_instead_of = rules("pushinsteadof")?;
    Ok(vec![
        rewrite(url, &push_instead_of)
            .or_else(|| rewrite(url, &instead_of))
            .unwrap_or_else(|| url.to_owned()),
    ])
}

/// Why Git LFS could upload files on this push, if it can: LFS has files
/// in its local storage, the only place it uploads from, and a pre-push hook
/// other than the guard runs. Hooks are shell, so what one runs cannot be
/// read off its text; any other hook counts.
fn lfs_pre_push_hook() -> Result<Option<String>> {
    let Some(storage) = lfs_storage_with_objects()? else {
        return Ok(None);
    };
    let path = git::hook_path("pre-push")?;
    match std::fs::read(&path) {
        Ok(bytes) if !crate::guard::is_guard_hook(&String::from_utf8_lossy(&bytes)) => {
            return Ok(Some(format!(
                "the pre-push hook {}, with LFS files in {storage}",
                path.display()
            )));
        }
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    }
    Ok(git::config_regexp(r"^hook\..*\.command$")?
        .into_iter()
        .find(|(_, command)| !command.trim_start().starts_with("git-remote-enc pre-push"))
        .map(|(key, _)| format!("{key}, with LFS files in {storage}")))
}

/// The LFS object directory, if it holds any file: `<common dir>/lfs`, or
/// `lfs.storage` (relative to the working tree, else to the common dir).
fn lfs_storage_with_objects() -> Result<Option<String>> {
    let common = git::common_dir()?;
    let mut dirs = vec![common.join("lfs")];
    if let Some(s) = git::config("lfs.storage")? {
        let p = PathBuf::from(&s);
        if p.is_absolute() {
            dirs.push(p);
        } else {
            if let Ok(top) = git::run_line(["rev-parse", "--show-toplevel"]) {
                dirs.push(PathBuf::from(top).join(&p));
            }
            dirs.push(common.join(&p));
        }
    }
    for d in dirs {
        if has_file(&d.join("objects"), 4)? {
            return Ok(Some(d.display().to_string()));
        }
    }
    Ok(None)
}

/// Is there a file under `dir`, at most `depth` levels down?
fn has_file(dir: &std::path::Path, depth: u32) -> Result<bool> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e).with_context(|| format!("listing {}", dir.display())),
    };
    for e in entries {
        let e = e?;
        let ty = e.file_type()?;
        if ty.is_file() {
            return Ok(true);
        }
        if ty.is_dir() && depth > 0 && has_file(&e.path(), depth.saturating_sub(1))? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// On a first contact pinned by participants only, how to pin the rest.
fn unpinned_hint(cfg: &Config) -> &'static str {
    if cfg.repo.is_some() && cfg.min_generation.is_some() {
        ""
    } else {
        "; confirm the repository and generation with an admin, or pin them (enc.repo, \
         enc.minGeneration): without them the host can serve an older manifest or another remote"
    }
}

fn read_manifest_blob(oid: &str) -> Result<Vec<u8>> {
    let size = git::object_size(oid)?;
    if size > MAX_MANIFEST_BYTES {
        bail!(
            "the remote's manifest is {size} bytes, over the {MAX_MANIFEST_BYTES}-byte limit; refusing to read it"
        );
    }
    git::cat_blob(oid)
}

/// Do two key lists name the same keys, comments and order aside?
fn same_keys(a: &[String], b: &[String]) -> Result<bool> {
    Ok(ParticipantDiff::between(a, b)?.is_empty())
}

/// Every admin must be a participant that can sign.
fn check_admins(participants: &[String], admins: &[String]) -> Result<()> {
    let participants = Participant::parse_all(participants)?;
    for a in Participant::parse_all(admins)? {
        if !a.can_sign() || !participants.iter().any(|p| p.key() == a.key()) {
            bail!(
                "admin {} is not an SSH participant; an admin leaving the participants must also \
                 leave the admin list (enc-admins)",
                a.fingerprint()
            );
        }
    }
    Ok(())
}

/// The fingerprint of the participant in `allowed` whose key signed `text`.
fn verified_signer(allowed: &[String], text: &str, sig: &str) -> Result<String> {
    let allowed = Participant::parse_all(allowed)?;
    crypto::verify(&allowed, text.as_bytes(), sig)?
        .and_then(|i| allowed.get(i))
        .map(Participant::fingerprint)
        .ok_or_else(|| anyhow!("manifest is not signed by a trusted participant; refusing it"))
}

/// The trust state recording `m`, whose signed text is `text`, as accepted.
fn trust_in(m: &Manifest, text: &str, commit: Option<&str>) -> Trust {
    Trust {
        generation: m.generation,
        repo_id: m.repo_id.clone(),
        participants: m.participants.clone(),
        admins: m.admins.clone(),
        digest: Some(crypto::sha256_hex(text.as_bytes())),
        commit: commit.map(str::to_owned),
    }
}

struct BuiltPack {
    /// Its parts, in order.
    paths: Vec<PathBuf>,
    /// Objects in the pack, from its header.
    count: u32,
    id: String,
    key: Zeroizing<String>,
}

impl Drop for BuiltPack {
    fn drop(&mut self) {
        // Best effort: stored or abandoned, the files are not needed.
        PartWriter::discard(&self.paths);
    }
}

/// What a push writes besides the refs it updates.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Push,
    /// The configured participant and admin lists.
    SetParticipants,
    /// One pack for everything the refs reach, replacing all others.
    Repack {
        rewrite: bool,
    },
}

/// Pack count and bytes of pack blobs before and after a repack.
pub struct Repacked {
    pub before: (usize, u64),
    pub after: (usize, u64),
}

/// A pack whose blobs are in the local object store and, for a large one,
/// already uploaded to `upload_branch`.
struct Staged {
    /// The new tips it was built for, sorted.
    wants: Vec<Oid>,
    /// The ids of the packs listed when it was built.
    bases: Vec<String>,
    id: String,
    key: Zeroizing<String>,
    /// Tree name and blob of each part.
    blobs: Vec<(String, Oid)>,
    upload_branch: Option<String>,
    /// The last commit pushed to `upload_branch`.
    upload_tip: Option<Oid>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refspec_parsing() {
        assert_eq!(
            RefSpec::parse("+refs/heads/a:refs/heads/b").unwrap(),
            RefSpec {
                force: true,
                src: Some("refs/heads/a".into()),
                dst: "refs/heads/b".into()
            }
        );
        assert_eq!(
            RefSpec::parse(":refs/heads/gone").unwrap(),
            RefSpec {
                force: false,
                src: None,
                dst: "refs/heads/gone".into()
            }
        );
        assert!(RefSpec::parse("nocolon").is_err());
        assert!(RefSpec::parse("a:").is_err());
    }

    #[test]
    fn refspec_parser_survives_corrupted_input() {
        for input in crate::mutate::variants(b"+refs/heads/a:refs/heads/b", 20_000) {
            if let Ok(s) = std::str::from_utf8(&input)
                && let Ok(r) = RefSpec::parse(s)
            {
                assert!(!r.dst.is_empty());
            }
        }
    }
}
