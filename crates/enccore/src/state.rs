//! Per-remote local state under `<common dir>/enc/<key>/`, shared by every
//! worktree. DESIGN.md §5.4, §6.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::crypto::{TrustKey, sha256_hex};

/// A temp file untouched for this long belongs to no running helper.
const STALE_TEMP: Duration = Duration::from_secs(24 * 60 * 60);

pub struct State {
    /// `<common>/enc`, holding one directory per remote.
    root: PathBuf,
    dir: PathBuf,
    /// Local ref tracking the backend branch; keeps transfers incremental.
    pub tracking_ref: String,
}

/// What the last accepted manifest said about who may sign the next one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Trust {
    pub generation: u64,
    pub repo_id: String,
    pub participants: Vec<String>,
    pub admins: Vec<String>,
    /// SHA-256 of the accepted manifest text; absent in state written by
    /// older versions.
    pub digest: Option<String>,
}

impl State {
    pub fn open(common_dir: &Path, url: &str, branch: &str) -> Result<Self> {
        let key = sha256_hex(format!("{url}\0{branch}").as_bytes());
        let key = key.get(..16).unwrap_or(&key).to_owned();
        let root = common_dir.join("enc");
        let dir = root.join(&key);
        fs::create_dir_all(dir.join("tmp"))
            .with_context(|| format!("creating {}", dir.display()))?;
        // Leftovers from an interrupted run. A helper running concurrently on
        // the same remote (a push racing a fetch) owns the recent ones.
        if let Ok(entries) = fs::read_dir(dir.join("tmp")) {
            for e in entries.flatten() {
                let stale = e
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .is_some_and(|age| age > STALE_TEMP);
                if stale {
                    // Best effort: a stale temp file is harmless.
                    let _ = fs::remove_file(e.path());
                }
            }
        }
        Ok(Self {
            root,
            dir,
            tracking_ref: format!("refs/enc/{key}"),
        })
    }

    pub fn temp_path(&self, name: &str) -> PathBuf {
        self.dir
            .join("tmp")
            .join(format!("{name}-{}", std::process::id()))
    }

    pub fn have(&self) -> Result<BTreeSet<String>> {
        match fs::read_to_string(self.dir.join("have")) {
            Ok(s) => Ok(s
                .lines()
                .map(str::to_owned)
                .filter(|l| !l.is_empty())
                .collect()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeSet::new()),
            Err(e) => Err(e).context("reading have list"),
        }
    }

    pub fn add_have(&self, pack_id: &str) -> Result<()> {
        let mut f = OpenOptions::new()
            .append(true)
            .create(true)
            .open(self.dir.join("have"))
            .context("opening have list")?;
        writeln!(f, "{pack_id}")?;
        Ok(())
    }

    /// The accepted trust state, authenticated with whichever of `keys` it
    /// names. A file that fails authentication is an error, never a first
    /// contact.
    pub fn trust(&self, keys: &[TrustKey]) -> Result<Option<Trust>> {
        read_trust(&self.dir.join("trust"), keys)
    }

    /// The most advanced trust state any other remote of this repository
    /// holds for repository id `repo_id`, with that remote's directory: the
    /// same encrypted remote reached through another URL spelling. State
    /// that does not authenticate with `keys` is skipped.
    pub fn trust_for_repo(
        &self,
        repo_id: &str,
        keys: &[TrustKey],
    ) -> Result<Option<(Trust, PathBuf)>> {
        let mut best: Option<(Trust, PathBuf)> = None;
        for e in fs::read_dir(&self.root).context("listing local enc state")? {
            let dir = e?.path();
            if dir == self.dir {
                continue;
            }
            let Ok(Some(t)) = read_trust(&dir.join("trust"), keys) else {
                continue;
            };
            if t.repo_id == repo_id
                && best
                    .as_ref()
                    .is_none_or(|(b, _)| t.generation > b.generation)
            {
                best = Some((t, dir));
            }
        }
        Ok(best)
    }

    /// Replace the trust state, authenticated with `key`.
    pub fn save_trust(&self, t: &Trust, key: &TrustKey) -> Result<()> {
        let mut text = format!("generation {}\nrepo {}\n", t.generation, t.repo_id);
        if let Some(d) = &t.digest {
            text.push_str(&format!("digest {d}\n"));
        }
        for p in &t.participants {
            text.push_str(&format!("participant {p}\n"));
        }
        for a in &t.admins {
            text.push_str(&format!("admin {a}\n"));
        }
        let tag = key.tag(text.as_bytes());
        text.push_str(&format!("{MAC_ITEM} {} {tag}\n", key.id));
        let tmp = self.temp_path("trust");
        fs::write(&tmp, text).context("writing trust file")?;
        fs::rename(&tmp, self.dir.join("trust")).context("replacing trust file")?;
        Ok(())
    }

    /// Delete everything kept for this remote. The caller removes the
    /// tracking ref.
    pub fn forget(&self) -> Result<()> {
        fs::remove_dir_all(&self.dir).with_context(|| format!("removing {}", self.dir.display()))
    }

    pub fn has_trust(&self) -> bool {
        self.dir.join("trust").exists()
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

/// Last line of a trust file: `mac <key id> <hex HMAC-SHA256 of the lines above>`.
const MAC_ITEM: &str = "mac";

fn read_trust(path: &Path, keys: &[TrustKey]) -> Result<Option<Trust>> {
    let text = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let body = match text.trim_end_matches('\n').rsplit_once('\n') {
        Some((body, last)) if last.starts_with("mac ") => {
            let (id, tag) = last
                .strip_prefix("mac ")
                .and_then(|r| r.split_once(' '))
                .with_context(|| format!("{}: malformed mac line", path.display()))?;
            let key = keys.iter().find(|k| k.id == id).with_context(|| {
                format!(
                    "{} is authenticated by the key {id}, which is not among your identities; \
                     configure that identity again (enc.identity)",
                    path.display()
                )
            })?;
            let body = format!("{body}\n");
            if !key.verify(body.as_bytes(), tag) {
                bail!(
                    "{} was modified outside git-remote-enc (its authentication tag does not match); \
                     the accepted trust state for this remote cannot be relied on",
                    path.display()
                );
            }
            body
        }
        // Written before the state was authenticated; the next accepted
        // manifest rewrites it with a tag.
        _ => text,
    };
    let mut t = Trust::default();
    for line in body.lines() {
        let (item, rest) = line.split_once(' ').unwrap_or((line, ""));
        match item {
            "generation" => t.generation = rest.trim().parse().context("trust: generation")?,
            "repo" => t.repo_id = rest.trim().to_owned(),
            "digest" => t.digest = Some(rest.trim().to_owned()),
            "participant" => t.participants.push(rest.trim().to_owned()),
            "admin" => t.admins.push(rest.trim().to_owned()),
            "" => {}
            other => bail!("{}: unknown item `{other}`", path.display()),
        }
    }
    Ok(Some(t))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    #[test]
    fn open_removes_only_stale_temp_files() {
        let root = std::env::temp_dir().join(format!("enc-state-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let s = State::open(&root, "url", "refs/heads/enc").unwrap();
        let fresh = s.temp_path("fresh");
        let old = s.temp_path("old");
        fs::write(&fresh, "x").unwrap();
        fs::write(&old, "x").unwrap();
        let two_days_ago = SystemTime::now() - Duration::from_secs(2 * 24 * 60 * 60);
        fs::File::options()
            .write(true)
            .open(&old)
            .unwrap()
            .set_modified(two_days_ago)
            .unwrap();

        State::open(&root, "url", "refs/heads/enc").unwrap();
        assert!(
            fresh.exists(),
            "a concurrent helper's temp file was removed"
        );
        assert!(!old.exists());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn trust_file_authentication() {
        let root = std::env::temp_dir().join(format!("enc-trust-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let s = State::open(&root, "url", "refs/heads/enc").unwrap();
        let ours = age::x25519::Identity::generate();
        let ours = crate::crypto::Identity::Age {
            path: "ours".into(),
            key: ours,
        }
        .trust_key()
        .unwrap();
        let theirs = crate::crypto::Identity::Age {
            path: "theirs".into(),
            key: age::x25519::Identity::generate(),
        }
        .trust_key()
        .unwrap();
        let t = Trust {
            generation: 7,
            repo_id: "r".into(),
            participants: vec!["age1x".into()],
            admins: vec![],
            digest: Some("d".into()),
        };

        s.save_trust(&t, &ours).unwrap();
        assert_eq!(
            s.trust(std::slice::from_ref(&ours)).unwrap(),
            Some(t.clone())
        );
        let err = s.trust(&[theirs]).unwrap_err().to_string();
        assert!(err.contains("not among your identities"), "{err}");

        // State written before authentication existed is still read.
        fs::write(
            s.dir().join("trust"),
            "generation 3\nrepo r\nparticipant age1x\n",
        )
        .unwrap();
        assert_eq!(s.trust(&[ours]).unwrap().map(|t| t.generation), Some(3));
        fs::remove_dir_all(&root).unwrap();
    }
}
