//! An encrypted remote: connect, list, fetch, push. DESIGN.md §5, §6.

use std::io::{self, BufReader, Read, Write};
use std::path::PathBuf;
use std::str::FromStr;

use age::secrecy::ExposeSecret;
use anyhow::{Context, Result, anyhow, bail};
use ssh_key::PrivateKey;

use crate::backend::{Backend, DEFAULT_BRANCH, PushOutcome};
use crate::config::Config;
use crate::crypto::{self, HashReader, HashWriter, Identity, Participant};
use crate::git::{self, Oid, Streaming, TreeEntry};
use crate::info;
use crate::manifest::{Manifest, Pack, join_envelope, split_envelope};
use crate::state::{State, Trust};

const MANIFEST_BLOB: &str = "manifest";
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

pub enum PushStatus {
    Ok(String),
    Error(String, String),
}

pub struct Remote {
    cfg: Config,
    backend: Backend,
    state: State,
    connected: bool,
    tip: Option<Oid>,
    tree: Vec<TreeEntry>,
    manifest: Option<Manifest>,
    identities: Option<Vec<Identity>>,
}

impl Remote {
    /// `name` is git's remote name (absent when it equals the URL); `url` is
    /// the helper URL with or without its `enc::` prefix.
    pub fn open(name: Option<&str>, url: &str) -> Result<Self> {
        let url = url.strip_prefix("enc::").unwrap_or(url);
        let (url, fragment) = match url.rsplit_once('#') {
            Some((u, f)) if !f.is_empty() => (u, Some(f)),
            _ => (url, None),
        };
        // git would parse a leading dash as an option (`--upload-pack=…`)
        // wherever the URL is not behind `--`.
        if url.is_empty() || url.starts_with('-') {
            bail!("refusing the backend URL `{url}`: it is empty or starts with `-`");
        }
        let branch = fragment.unwrap_or(DEFAULT_BRANCH);
        let branch = if branch.starts_with("refs/") {
            branch.to_owned()
        } else {
            format!("refs/heads/{branch}")
        };
        let state = State::open(&git::git_dir()?, url, &branch)?;
        let backend = Backend {
            url: url.to_owned(),
            branch,
            tracking_ref: state.tracking_ref.clone(),
        };
        let name = name.filter(|n| *n != url && !n.starts_with("enc::"));
        Ok(Self {
            cfg: Config::load(name)?,
            backend,
            state,
            connected: false,
            tip: None,
            tree: vec![],
            manifest: None,
            identities: None,
        })
    }

    pub fn url(&self) -> &str {
        &self.backend.url
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

    // ---- connect ----------------------------------------------------------

    pub fn connect(&mut self) -> Result<()> {
        if self.connected {
            return Ok(());
        }
        self.tip = self.backend.fetch_tip()?;
        match self.tip.clone() {
            Some(tip) => {
                self.tree = Backend::tree_entries(&tip)?;
                self.manifest = Some(self.load_manifest()?);
            }
            None => {
                if let Some(t) = self.state.trust()? {
                    bail!(
                        "branch {} no longer exists on {} but this repository has accepted its manifests up to generation {}; \
                         if the remote was intentionally deleted, remove the local state directory for it under .git/enc/",
                        self.backend.branch,
                        self.backend.url,
                        t.generation
                    );
                }
                self.tree = vec![];
                self.manifest = None;
            }
        }
        self.connected = true;
        Ok(())
    }

    fn reconnect(&mut self) -> Result<()> {
        self.connected = false;
        self.connect()
    }

    fn load_manifest(&mut self) -> Result<Manifest> {
        let oid = Backend::blob_oid(&self.tree, MANIFEST_BLOB)
            .ok_or_else(|| {
                anyhow!(
                    "branch {} on {} exists but carries no manifest: not an encrypted remote (refusing to touch it)",
                    self.backend.branch,
                    self.backend.url
                )
            })?
            .to_owned();
        let blob = git::cat_blob(&oid)?;
        let identities = self.identities()?;
        let envelope = crypto::decrypt_to_vec(identities, &blob)?;
        let (text, sig) =
            split_envelope(&envelope).ok_or_else(|| anyhow!("manifest is not signed"))?;
        let m = Manifest::parse(text).context("parsing manifest")?;

        // Who may have signed this: the previously accepted participant list,
        // or on first contact the configured one, or (TOFU) the manifest's own.
        let trust = self.state.trust()?;
        let allowed_texts = match (&trust, &self.cfg.participants) {
            (Some(t), _) => t.participants.clone(),
            (None, Some(p)) => p.clone(),
            (None, None) => m.participants.clone(),
        };
        let allowed = Participant::parse_all(&allowed_texts)?;
        let signer = crypto::verify(&allowed, text.as_bytes(), sig)?
            .and_then(|i| allowed.get(i))
            .ok_or_else(|| {
                anyhow!(
                    "manifest (generation {}) is not signed by a trusted participant; refusing it",
                    m.generation
                )
            })?;

        match &trust {
            Some(t) => {
                if t.repo_id != m.repo_id {
                    bail!(
                        "the remote was recreated (repo id {} → {}); if this is expected, remove the local state directory for it under .git/enc/",
                        t.repo_id,
                        m.repo_id
                    );
                }
                if m.generation < t.generation {
                    bail!(
                        "rollback detected: remote manifest is generation {} but generation {} was already accepted",
                        m.generation,
                        t.generation
                    );
                }
            }
            None => info(&format!(
                "first contact with {}: trusting manifest signed by {}",
                self.backend.url,
                signer.fingerprint()
            )),
        }
        // Validate the new list now so a later push gets a clear error.
        Participant::parse_all(&m.participants).context("manifest participant list")?;
        self.state.save_trust(&Trust {
            generation: m.generation,
            repo_id: m.repo_id.clone(),
            participants: m.participants.clone(),
        })?;
        Ok(m)
    }

    // ---- list -------------------------------------------------------------

    /// `(refs, HEAD target)` for the `list` command. `for_push` tolerates a
    /// remote that does not exist yet.
    pub fn list(&mut self, for_push: bool) -> Result<(RefList, Option<String>)> {
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
    pub fn manifest_text(&mut self, with_keys: bool) -> Result<Option<String>> {
        self.connect()?;
        Ok(self.manifest.as_ref().map(|m| {
            if with_keys {
                m.serialize()
            } else {
                m.serialize_redacted()
            }
        }))
    }

    // ---- fetch ------------------------------------------------------------

    /// Index every pack not yet indexed locally, in manifest order.
    pub fn fetch(&mut self) -> Result<()> {
        self.connect()?;
        let Some(m) = self.manifest.clone() else {
            return Ok(());
        };
        let have = self.state.have()?;
        for pack in &m.packs {
            if have.contains(&pack.id) {
                continue;
            }
            let blob = Backend::blob_oid(&self.tree, &pack.blob_name())
                .ok_or_else(|| {
                    anyhow!(
                        "pack {} listed in manifest is missing on the remote",
                        pack.id
                    )
                })?
                .to_owned();
            self.index_pack(pack, &blob)?;
            self.state.add_have(&pack.id)?;
        }
        Ok(())
    }

    fn index_pack(&self, pack: &Pack, blob_oid: &str) -> Result<()> {
        let key = age::x25519::Identity::from_str(&pack.key)
            .map_err(|e| anyhow!("pack {}: bad key in manifest: {e}", pack.id))?;
        let mut cat = Streaming::reader(["cat-file", "blob", blob_oid], None)?;
        let (hashed, digest) = HashReader::new(cat.stdout()?);
        let mut plain = crypto::decrypt_stream(&key, BufReader::new(hashed))?;
        let mut index = Streaming::writer(["index-pack", "--stdin", "--fix-thin"])?;
        {
            let mut stdin = index.stdin()?;
            io::copy(&mut plain, &mut stdin)
                .with_context(|| format!("decrypting pack {}", pack.id))?;
        }
        index.finish()?;
        cat.finish()?;
        let got = crypto::finalize_shared(&digest);
        if got != pack.id {
            bail!(
                "pack blob {} does not match its manifest name (got {got})",
                pack.id
            );
        }
        Ok(())
    }

    // ---- push -------------------------------------------------------------

    pub fn push(&mut self, specs: &[RefSpec]) -> Result<Vec<PushStatus>> {
        self.connect()?;
        for attempt in 1..=PUSH_ATTEMPTS {
            if let Some(statuses) = self.try_push(specs)? {
                return Ok(statuses);
            }
            info(&format!(
                "remote changed while pushing, retrying ({attempt}/{PUSH_ATTEMPTS})"
            ));
            self.reconnect()?;
        }
        bail!("the remote kept changing under us; retry the push")
    }

    /// One attempt. `None` means the compare-and-swap lost; the caller
    /// reconnects and calls again.
    fn try_push(&mut self, specs: &[RefSpec]) -> Result<Option<Vec<PushStatus>>> {
        let is_new = self.manifest.is_none();
        let mut m = match &self.manifest {
            Some(m) => m.clone(),
            None => Manifest {
                repo_id: crypto::random_id()?,
                ..Manifest::default()
            },
        };

        // Participants: config overrides; a new remote needs them.
        let participant_texts = match (&self.cfg.participants, is_new) {
            (Some(p), _) => p.clone(),
            (None, false) => m.participants.clone(),
            (None, true) => bail!(
                "creating an encrypted remote needs its participants: \
                 git config --add remote.<name>.enc-participants \"$(cat ~/.ssh/id_ed25519.pub)\""
            ),
        };
        let participants = Participant::parse_all(&participant_texts)?;
        if !participants.iter().any(Participant::can_sign) {
            bail!("at least one participant must be an SSH key (age recipients cannot sign)");
        }

        // Our signing key must be allowed to write: a participant of the
        // current manifest, or of the initial list when creating.
        let signer = self.signing_key()?;
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
        if accepted.is_empty() {
            return Ok(Some(statuses));
        }

        // Everything reachable from a manifest ref is already on the remote.
        let wants: Vec<Oid> = accepted.iter().filter_map(|(_, o)| o.clone()).collect();
        let known: Vec<Oid> = m.refs.iter().map(|(oid, _)| oid.clone()).collect();
        let excludes = git::have_objects(&known)?;
        let pack = self.build_pack(&wants, &excludes)?;

        m.generation = m
            .generation
            .checked_add(1)
            .ok_or_else(|| anyhow!("generation overflow"))?;
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
        if let Some(p) = &pack {
            m.packs.push(Pack {
                id: p.id.clone(),
                key: p.key.clone(),
            });
        }

        let text = m.serialize();
        let sig = crypto::sign(&signer, text.as_bytes())?;
        let envelope = join_envelope(&text, &sig);
        let manifest_blob = crypto::encrypt_to_participants(&participants, &envelope, Vec::new())?;
        let mut upserts = vec![(MANIFEST_BLOB.to_owned(), git::hash_object(&manifest_blob)?)];
        if let Some(p) = &pack {
            upserts.push((format!("{}.age", p.id), git::hash_object_file(&p.path)?));
            // Best effort: the blob is in the object store now.
            let _ = std::fs::remove_file(&p.path);
        }
        let commit = Backend::build_commit(self.tip.as_deref(), &upserts)?;

        match self.backend.push(&commit, self.tip.as_deref())? {
            PushOutcome::StaleLease => Ok(None),
            PushOutcome::Failed(stderr) => {
                // The lease is also enforced by the server; if the branch has
                // moved since we read it, this was a lost race, not a failure.
                if self.backend.fetch_tip()? != self.tip {
                    return Ok(None);
                }
                bail!("pushing to {}: {stderr}", self.backend.url)
            }
            PushOutcome::Done => {
                if let Some(p) = &pack {
                    self.state.add_have(&p.id)?;
                }
                self.state.save_trust(&Trust {
                    generation: m.generation,
                    repo_id: m.repo_id.clone(),
                    participants: m.participants.clone(),
                })?;
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
                anyhow!("no SSH private key to sign with; pushing needs an ssh-ed25519 or ssh-rsa identity")
            })
    }

    /// `pack-objects --thin` over `wants` minus `excludes`, encrypted to a
    /// fresh key into a temp file. `None` when there is nothing to send.
    fn build_pack(&self, wants: &[Oid], excludes: &[Oid]) -> Result<Option<BuiltPack>> {
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
        let mut po = Streaming::reader(
            [
                "pack-objects",
                "--revs",
                "--thin",
                "--stdout",
                "-q",
                "--delta-base-offset",
            ],
            Some(revs.as_bytes()),
        )?;
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
        let path = self.state.temp_path("pack");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("creating {}", path.display()))?;
        let mut enc = crypto::encrypt_stream(&key.to_public(), HashWriter::new(file))?;
        enc.write_all(&header)?;
        io::copy(&mut out, &mut enc).context("encrypting pack")?;
        let (file, id) = enc.finish()?.finish();
        file.sync_all()?;
        drop(file);
        po.finish()?;
        Ok(Some(BuiltPack {
            path,
            id,
            key: key.to_string().expose_secret().to_owned(),
        }))
    }
}

struct BuiltPack {
    path: PathBuf,
    id: String,
    key: String,
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
}
