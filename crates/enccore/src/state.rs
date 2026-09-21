//! Per-remote local state under `$GIT_DIR/enc/<key>/`. DESIGN.md §5.4, §6.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::crypto::sha256_hex;

pub struct State {
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
}

impl State {
    pub fn open(git_dir: &Path, url: &str, branch: &str) -> Result<Self> {
        let key = sha256_hex(format!("{url}\0{branch}").as_bytes());
        let key = key.get(..16).unwrap_or(&key).to_owned();
        let dir = git_dir.join("enc").join(&key);
        fs::create_dir_all(dir.join("tmp"))
            .with_context(|| format!("creating {}", dir.display()))?;
        // Leftovers from an interrupted run.
        if let Ok(entries) = fs::read_dir(dir.join("tmp")) {
            for e in entries.flatten() {
                // Best effort: a stale temp file is harmless.
                let _ = fs::remove_file(e.path());
            }
        }
        Ok(Self {
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

    pub fn trust(&self) -> Result<Option<Trust>> {
        let text = match fs::read_to_string(self.dir.join("trust")) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).context("reading trust file"),
        };
        let mut t = Trust::default();
        for line in text.lines() {
            let (item, rest) = line.split_once(' ').unwrap_or((line, ""));
            match item {
                "generation" => t.generation = rest.trim().parse().context("trust: generation")?,
                "repo" => t.repo_id = rest.trim().to_owned(),
                "participant" => t.participants.push(rest.trim().to_owned()),
                "" => {}
                other => bail!("trust file: unknown item `{other}`"),
            }
        }
        Ok(Some(t))
    }

    pub fn save_trust(&self, t: &Trust) -> Result<()> {
        let mut text = format!("generation {}\nrepo {}\n", t.generation, t.repo_id);
        for p in &t.participants {
            text.push_str(&format!("participant {p}\n"));
        }
        let tmp = self.temp_path("trust");
        fs::write(&tmp, text).context("writing trust file")?;
        fs::rename(&tmp, self.dir.join("trust")).context("replacing trust file")?;
        Ok(())
    }
}
