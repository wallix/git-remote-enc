//! The git-hosted store: one branch whose chained commits carry a flat tree of
//! age blobs, mirrored in a bare partial clone the helper owns. DESIGN.md
//! §4.1, §5.1 steps 6–7, §5.4.

use std::collections::HashSet;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};

use crate::git::{self, Git, Oid, Streaming, TreeEntry};
use crate::progress;

pub const DEFAULT_BRANCH: &str = "enc";
/// The message of a commit staging pack parts (DESIGN.md §5.1); the
/// backend branch's own commits say `enc`, or [`EPOCH_SUBJECT`].
pub const UPLOAD_MESSAGE: &str = "enc upload\n";
/// Subject of a commit that starts a rewritten history, followed by its
/// manifest's `epoch` (DESIGN.md §6.2).
pub const EPOCH_SUBJECT: &str = "enc epoch ";
/// The tree name of the manifest blob.
pub const MANIFEST_BLOB: &str = "manifest";
/// Where the backend repository keeps the host's branch.
const TRACKING_REF: &str = "refs/enc/tip";
/// Blobs above this size are fetched by id when needed: pack blobs, except
/// small ones, and a manifest over it. Every generation's manifest is
/// normally under it, and comes with the branch.
const FILTER: &str = "blob:limit=1m";
/// The user's settings that decide how git reaches a host. The backend
/// repository does not read the user's repository config, so these are
/// passed on (system and global config apply as usual).
const TRANSPORT_CONFIG: &str = r"^(url\..*\.(insteadof|pushinsteadof)|core\.(sshcommand|askpass|gitproxy)|http\..*|credential\..*|ssh\..*|protocol\..*)$";

pub struct Backend {
    /// The git URL, exactly as handed to git.
    pub url: String,
    /// Full ref name on the host, e.g. `refs/heads/enc`.
    pub branch: String,
    git: Git,
}

pub enum PushOutcome {
    Done,
    /// Someone else moved the branch since we read it.
    StaleLease,
    /// Rejected for another reason; the caller decides whether the tip moved.
    Failed(String),
}

impl Backend {
    /// Open the backend at `dir`; [`Backend::create_if_missing`] creates it.
    pub fn open(dir: PathBuf, url: &str, branch: &str) -> Result<Self> {
        Ok(Self {
            url: url.to_owned(),
            branch: branch.to_owned(),
            git: Git::at(dir, backend_env()?),
        })
    }

    /// Create a missing backend partial clone in `tmp` on the same filesystem,
    /// then rename it into place atomically. If another helper creates it
    /// first, use that repository.
    pub fn create_if_missing(&self, tmp: &Path) -> Result<()> {
        let dir = self
            .git
            .dir()
            .ok_or_else(|| anyhow!("the backend repository has no directory"))?;
        if dir.exists() {
            return Ok(());
        }
        if tmp.exists() {
            std::fs::remove_dir_all(tmp).with_context(|| format!("removing {}", tmp.display()))?;
        }
        create(tmp, &self.url)?;
        if let Err(e) = std::fs::rename(tmp, dir) {
            if !dir.exists() {
                return Err(e).with_context(|| format!("creating {}", dir.display()));
            }
            // Best effort: a later run removes it once stale.
            let _ = std::fs::remove_dir_all(tmp);
        }
        Ok(())
    }

    /// The last backend commit fetched or pushed, if any.
    pub fn tip(&self) -> Result<Option<Oid>> {
        self.git.rev_parse(TRACKING_REF)
    }

    /// Forget the tracking ref: the next fetch is a first contact again.
    pub fn drop_tip(&self) -> Result<()> {
        if self.tip()?.is_some() {
            self.git.delete_ref(TRACKING_REF)?;
        }
        Ok(())
    }

    /// Fetch the backend branch into the tracking ref, pack blobs left on the
    /// host. `None` when the branch does not exist yet (a new remote); any
    /// other failure is an error.
    pub fn fetch_tip(&self) -> Result<Option<Oid>> {
        let refspec = format!("+{}:{TRACKING_REF}", self.branch);
        let progress = progress::enabled();
        let (ok, _, stderr) = self.git.run_status_tee(
            [
                "fetch",
                // `-q` would also silence the download's own meter; without
                // it, fetch's other output is kept off the terminal.
                if progress { "--progress" } else { "-q" },
                "--no-tags",
                "--no-write-fetch-head",
                "--no-recurse-submodules",
                "origin",
                &refspec,
            ],
            None,
            progress,
        )?;
        if !ok {
            if stderr.contains("couldn't find remote ref") {
                return Ok(None);
            }
            bail!(
                "fetching {} from {}: {}",
                self.branch,
                self.url,
                stderr.trim()
            );
        }
        self.tip()
    }

    /// Fetch whichever of `oids` the backend repository lacks.
    pub fn ensure_blobs(&self, oids: &[Oid]) -> Result<()> {
        let have: HashSet<Oid> = self.git.have_objects(oids)?.into_iter().collect();
        let missing: Vec<&str> = oids
            .iter()
            .filter(|o| !have.contains(*o))
            .map(String::as_str)
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        // On stdin: there can be more than a command line holds.
        let mut input = missing.join("\n");
        input.push('\n');
        let progress = progress::enabled();
        let (ok, _, stderr) = self.git.run_status_tee(
            [
                "fetch",
                // As in `fetch_tip`.
                if progress { "--progress" } else { "-q" },
                "--no-tags",
                "--no-write-fetch-head",
                "--no-recurse-submodules",
                "--stdin",
                "origin",
            ],
            Some(input.as_bytes()),
            progress,
        )?;
        if !ok {
            bail!(
                "fetching {} pack blob(s) from {}: {}\nFetching a blob by id needs \
                 protocol v2, or uploadpack.allowAnySHA1InWant on the host",
                missing.len(),
                self.url,
                stderr.trim()
            );
        }
        Ok(())
    }

    /// A present blob's content.
    pub fn cat_blob(&self, oid: &str) -> Result<Vec<u8>> {
        self.git.run(["cat-file", "blob", oid])
    }

    /// A present blob's content, as a stream.
    pub fn blob_reader(&self, oid: &str) -> Result<Streaming> {
        Streaming::reader_in(&self.git, ["cat-file", "blob", oid], None, false)
    }

    pub fn object_size(&self, oid: &str) -> Result<u64> {
        self.git.object_size(oid)
    }

    pub fn has_object(&self, oid: &str) -> Result<bool> {
        self.git.has_object(oid)
    }

    pub fn is_ancestor(&self, old: &str, new: &str) -> Result<bool> {
        Ok(self.git.has_object(old)? && self.git.is_ancestor(old, new)?)
    }

    /// The backend commits on `rev`'s first-parent walk that carry a
    /// manifest, oldest first, with their subjects. The first parents are
    /// the pushes; a second parent is the chain of commits that staged a
    /// large push's parts. On a new remote, or since a rewrite, that chain is
    /// the first push's only parent (DESIGN.md §5.1), so its commits are on
    /// the walk and skipped.
    pub fn pushes(&self, rev: &str) -> Result<Vec<(String, String)>> {
        let out = self
            .git
            .run(["log", "--first-parent", "--reverse", "--format=%H %s", rev])?;
        let log = String::from_utf8(out).context("git log output is not UTF-8")?;
        let mut commits = Vec::new();
        for (c, subject) in log.lines().filter_map(|l| l.split_once(' ')) {
            // A staging commit carries no manifest; one that does is a push,
            // whatever its message says.
            if subject == UPLOAD_MESSAGE.trim_end() && !self.has_manifest(c)? {
                continue;
            }
            commits.push((c.to_owned(), subject.to_owned()));
        }
        Ok(commits)
    }

    fn has_manifest(&self, commit: &str) -> Result<bool> {
        Ok(Self::blob_oid(&self.tree_entries(commit)?, MANIFEST_BLOB).is_some())
    }

    /// The epoch `tip`'s history starts at, if a participant's rewrite
    /// started it: its oldest push says so in its subject
    /// ([`EPOCH_SUBJECT`]) and every push is on the first-parent walk, so
    /// nothing older is reachable. Without the last condition, a
    /// fast-forward could put a forged start under a new first parent and
    /// the real history under a second one. The subject is not signed: only
    /// a forced update of the branch, i.e. a rewrite, or creating the branch
    /// (a new remote, or after deleting it) can place it under the history,
    /// so the remote's creator can set any epoch. DESIGN.md §6.2.
    pub fn rewrite_epoch(&self, tip: &str) -> Result<Option<u64>> {
        let pushes = self.pushes(tip)?;
        let Some(epoch) = pushes.first().and_then(|(_, s)| {
            s.strip_prefix(EPOCH_SUBJECT)
                .and_then(|e| e.parse::<u64>().ok())
        }) else {
            return Ok(None);
        };
        let list = |first_parent: bool| -> Result<String> {
            let mut args = vec!["rev-list"];
            args.extend(first_parent.then_some("--first-parent"));
            args.push(tip);
            String::from_utf8(self.git.run(args)?).context("rev-list output is not UTF-8")
        };
        let walk = list(true)?;
        let walk: HashSet<&str> = walk.lines().collect();
        for c in list(false)?.lines() {
            if !walk.contains(c) && self.has_manifest(c)? {
                return Ok(None);
            }
        }
        Ok(Some(epoch))
    }

    pub fn count_first_parents(&self, range: &str) -> Result<u64> {
        self.git
            .run_line(["rev-list", "--count", "--first-parent", range])?
            .parse()
            .context("rev-list --count")
    }

    /// Store `path`'s content as a blob, uncompressed: it is ciphertext.
    pub fn hash_object_file(&self, path: &Path) -> Result<Oid> {
        self.git.hash_object_file(path)
    }

    pub fn hash_object(&self, data: &[u8]) -> Result<Oid> {
        self.git.hash_object(data)
    }

    pub fn tree_entries(&self, commit: &str) -> Result<Vec<TreeEntry>> {
        self.git.ls_tree(commit)
    }

    pub fn blob_oid<'a>(entries: &'a [TreeEntry], name: &str) -> Option<&'a str> {
        entries
            .iter()
            .find(|(_, ty, _, n)| ty == "blob" && n == name)
            .map(|(_, _, oid, _)| oid.as_str())
    }

    /// Create a commit on `parent`, applying `upserts` (name → blob oid) to
    /// its tree. Add the staging tip `upload` as the next parent so git knows
    /// the host has those parts and does not send them again.
    pub fn build_commit(
        &self,
        parent: Option<&str>,
        upload: Option<&str>,
        upserts: &[(String, Oid)],
    ) -> Result<Oid> {
        self.commit(parent, parent, upload, upserts, "enc\n")
    }

    /// [`Backend::build_commit`] whose tree holds `entries` only: a
    /// repack, which drops the blobs it replaces.
    pub fn build_replacing(
        &self,
        parent: Option<&str>,
        upload: Option<&str>,
        entries: &[(String, Oid)],
    ) -> Result<Oid> {
        self.commit(None, parent, upload, entries, "enc\n")
    }

    /// [`Backend::build_replacing`] that descends from none of the
    /// history (only from the staging tip `upload`), at `epoch`.
    pub fn build_rewrite(
        &self,
        upload: Option<&str>,
        entries: &[(String, Oid)],
        epoch: u64,
    ) -> Result<Oid> {
        self.commit(
            None,
            None,
            upload,
            entries,
            &format!("{EPOCH_SUBJECT}{epoch}\n"),
        )
    }

    /// A commit staging parts: `upserts` added to `parent`'s tree.
    pub fn build_upload(&self, parent: Option<&str>, upserts: &[(String, Oid)]) -> Result<Oid> {
        self.commit(parent, parent, None, upserts, UPLOAD_MESSAGE)
    }

    /// A commit on `parent` (then `upload`) whose tree is `base`'s with
    /// `upserts` applied.
    fn commit(
        &self,
        base: Option<&str>,
        parent: Option<&str>,
        upload: Option<&str>,
        upserts: &[(String, Oid)],
        message: &str,
    ) -> Result<Oid> {
        let mut entries: Vec<TreeEntry> = match base {
            Some(p) => self
                .tree_entries(p)?
                .into_iter()
                .filter(|(_, ty, _, _)| ty == "blob")
                .collect(),
            None => vec![],
        };
        let names: HashSet<&str> = upserts.iter().map(|(n, _)| n.as_str()).collect();
        entries.retain(|(_, _, _, n)| !names.contains(n.as_str()));
        for (name, oid) in upserts {
            entries.push(("100644".into(), "blob".into(), oid.clone(), name.clone()));
        }
        let tree = self.git.mktree(&entries)?;
        let parents: Vec<&str> = parent.into_iter().chain(upload).collect();
        self.git.commit_tree(&tree, &parents, message)
    }

    /// Compare-and-swap push of `commit` onto the branch, expecting the
    /// branch to still be at `expected_old` (absent for a new remote).
    pub fn push(&self, commit: &str, expected_old: Option<&str>) -> Result<PushOutcome> {
        let lease = format!(
            "--force-with-lease={}:{}",
            self.branch,
            expected_old.unwrap_or("")
        );
        let refspec = format!("{commit}:{}", self.branch);
        let (ok, stderr) = self.git_push(&[&lease, "--", &self.url, &refspec])?;
        if ok {
            self.git.update_ref(TRACKING_REF, commit)?;
            return Ok(PushOutcome::Done);
        }
        // Client-side lease check; a lost race can also surface as a
        // server-side rejection, which the caller resolves by re-fetching.
        if stderr.contains("stale info") {
            return Ok(PushOutcome::StaleLease);
        }
        Ok(PushOutcome::Failed(stderr.trim().to_owned()))
    }

    /// A branch to stage a large push's parts on, next to the backend
    /// branch: `<branch>-upload-<random>`.
    pub fn upload_branch(&self) -> Result<String> {
        let id = crate::crypto::random_id()?;
        Ok(format!(
            "{}-upload-{}",
            self.branch,
            id.get(..16).unwrap_or(&id)
        ))
    }

    /// Push `commit` to the staging branch `branch`, unconditionally: no
    /// one else writes to it.
    pub fn push_upload(&self, commit: &str, branch: &str) -> Result<()> {
        let refspec = format!("+{commit}:{branch}");
        let (ok, stderr) = self.git_push(&["--", &self.url, &refspec])?;
        if !ok {
            bail!("uploading to {} on {}: {}", branch, self.url, stderr.trim());
        }
        Ok(())
    }

    /// Delete the staging branch `branch` from the host.
    pub fn delete_upload(&self, branch: &str) -> Result<()> {
        let refspec = format!(":{branch}");
        let (ok, stderr) = self.git_push(&["--", &self.url, &refspec])?;
        if !ok {
            bail!("deleting {} on {}: {}", branch, self.url, stderr.trim());
        }
        Ok(())
    }

    fn git_push(&self, args: &[&str]) -> Result<(bool, String)> {
        let progress = progress::enabled();
        let mut all = vec![
            "push",
            "-q",
            if progress {
                "--progress"
            } else {
                "--no-progress"
            },
            "--no-verify",
            "--no-recurse-submodules",
        ];
        all.extend_from_slice(args);
        let (ok, _, stderr) = self.git.run_status_tee(all, None, progress)?;
        Ok((ok, stderr))
    }
}

/// A bare repository at `dir` that fetches `url` as a partial clone:
/// commits, trees and manifests come with the branch, pack blobs on demand.
/// Its object format is the user repository's, which held the backend
/// branch before it, whatever `GIT_DEFAULT_HASH` or `init.defaultObjectFormat`
/// say.
fn create(dir: &Path, url: &str) -> Result<()> {
    let format = git::run_line(["rev-parse", "--show-object-format"])?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let git = Git::at(dir.to_owned(), vec![]);
    git.run([
        "init",
        "-q",
        "--bare",
        "--template=",
        &format!("--object-format={format}"),
    ])?;
    for (k, v) in [
        // `extensions.*` needs it.
        ("core.repositoryformatversion", "1"),
        ("remote.origin.url", url),
        ("remote.origin.promisor", "true"),
        ("remote.origin.partialclonefilter", FILTER),
        ("extensions.partialclone", "origin"),
        // Ciphertext: deflating it, or searching it for deltas, only costs
        // time (a lot of it for pack parts, which are under
        // core.bigFileThreshold). Set the loose and pack levels themselves:
        // a user's explicit one beats `core.compression`. A fetch of fewer
        // than `fetch.unpackLimit` objects (nearly every one here: a few
        // large blobs) is unpacked into loose objects.
        ("core.compression", "0"),
        ("core.looseCompression", "0"),
        ("pack.compression", "0"),
        ("pack.window", "0"),
        ("core.logAllRefUpdates", "false"),
    ] {
        git.run(["config", k, v])?;
    }
    Ok(())
}

/// The environment of every backend command: no lazy fetch of a missing
/// object (a stray read of a pack blob would download it silently), and the
/// user's transport settings as `GIT_CONFIG_*` variables, which other users
/// cannot read the way they can a command line.
fn backend_env() -> Result<Vec<(OsString, OsString)>> {
    let mut env: Vec<(OsString, OsString)> = vec![("GIT_NO_LAZY_FETCH".into(), "1".into())];
    let (ok, out, _) = git::run_status([
        "config",
        "--local",
        "--includes",
        "-z",
        "--get-regexp",
        TRANSPORT_CONFIG,
    ])?;
    if !ok {
        return Ok(env);
    }
    // Entries already passed this way by whoever ran git come first.
    let start: usize = std::env::var("GIT_CONFIG_COUNT")
        .ok()
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    env.extend(config_env(&out, start));
    Ok(env)
}

/// `git config -z --get-regexp` output as `GIT_CONFIG_*` variables, numbered
/// from `start`.
fn config_env(out: &[u8], start: usize) -> Vec<(OsString, OsString)> {
    let mut env = Vec::new();
    let mut n = start;
    for entry in out.split(|b| *b == 0).filter(|e| !e.is_empty()) {
        let mut fields = entry.splitn(2, |b| *b == b'\n');
        let key = fields.next().unwrap_or_default();
        // A key without a value (`[http] sslVerify`) is a true boolean; an
        // empty value would read as false.
        let value = fields.next().unwrap_or(b"true");
        env.push((
            format!("GIT_CONFIG_KEY_{n}").into(),
            OsString::from_vec(key.to_vec()),
        ));
        env.push((
            format!("GIT_CONFIG_VALUE_{n}").into(),
            OsString::from_vec(value.to_vec()),
        ));
        n = n.saturating_add(1);
    }
    if n > start {
        env.push(("GIT_CONFIG_COUNT".into(), n.to_string().into()));
    }
    env
}

/// The backend repository of the remote whose local state is in `state_dir`.
pub fn repo_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("backend.git")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_env_keeps_bytes_and_reads_a_bare_key_as_true() {
        let out = b"http.sslverify\0http.proxy\nhttp://p\xff\0http.x.extraheader\n\0";
        let env = config_env(out, 2);
        let os = |s: &[u8]| OsString::from_vec(s.to_vec());
        assert_eq!(
            env,
            vec![
                (os(b"GIT_CONFIG_KEY_2"), os(b"http.sslverify")),
                (os(b"GIT_CONFIG_VALUE_2"), os(b"true")),
                (os(b"GIT_CONFIG_KEY_3"), os(b"http.proxy")),
                (os(b"GIT_CONFIG_VALUE_3"), os(b"http://p\xff")),
                (os(b"GIT_CONFIG_KEY_4"), os(b"http.x.extraheader")),
                (os(b"GIT_CONFIG_VALUE_4"), os(b"")),
                (os(b"GIT_CONFIG_COUNT"), os(b"5")),
            ]
        );
        assert!(config_env(b"", 0).is_empty());
    }

    #[test]
    fn create_if_missing_replaces_a_leftover_and_is_atomic() {
        let root = std::env::temp_dir().join(format!("enc-backend-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("backend.git");
        let tmp = root.join("tmp").join("backend.git-1");
        // An interrupted creation: a half-made repository under `tmp`.
        std::fs::create_dir_all(tmp.join("objects")).unwrap();
        std::fs::write(tmp.join("HEAD"), "junk").unwrap();
        let b = Backend::open(dir.clone(), "/nowhere", "refs/heads/enc").unwrap();
        b.create_if_missing(&tmp).unwrap();
        assert!(!tmp.exists());
        assert_eq!(
            b.git.run_line(["config", "remote.origin.url"]).unwrap(),
            "/nowhere"
        );
        // Present: left alone.
        std::fs::create_dir_all(&tmp).unwrap();
        b.create_if_missing(&tmp).unwrap();
        assert!(tmp.exists());
        std::fs::remove_dir_all(&root).unwrap();
    }
}
