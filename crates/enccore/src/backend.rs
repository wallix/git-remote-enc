//! The git-hosted store: one branch whose chained commits carry a flat tree of
//! age blobs. DESIGN.md §4.1, §5.1 steps 6–7.

use anyhow::{Result, bail};

use crate::git::{self, Oid, TreeEntry};

pub const DEFAULT_BRANCH: &str = "enc";

pub struct Backend {
    /// The git URL, exactly as handed to git.
    pub url: String,
    /// Full ref name on the host, e.g. `refs/heads/enc`.
    pub branch: String,
    /// Local tracking ref.
    pub tracking_ref: String,
}

pub enum PushOutcome {
    Done,
    /// Someone else moved the branch since we read it.
    StaleLease,
    /// Rejected for another reason; the caller decides whether the tip moved.
    Failed(String),
}

impl Backend {
    /// Fetch the backend branch into the tracking ref. `None` when the branch
    /// does not exist yet (a new remote); any other failure is an error.
    pub fn fetch_tip(&self) -> Result<Option<Oid>> {
        let refspec = format!("+{}:{}", self.branch, self.tracking_ref);
        let (ok, _, stderr) = git::run_status([
            "fetch",
            "-q",
            "--no-tags",
            "--no-write-fetch-head",
            "--no-recurse-submodules",
            "--",
            &self.url,
            &refspec,
        ])?;
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
        git::rev_parse(&self.tracking_ref)
    }

    pub fn tree_entries(commit: &str) -> Result<Vec<TreeEntry>> {
        git::ls_tree(commit)
    }

    pub fn blob_oid<'a>(entries: &'a [TreeEntry], name: &str) -> Option<&'a str> {
        entries
            .iter()
            .find(|(_, ty, _, n)| ty == "blob" && n == name)
            .map(|(_, _, oid, _)| oid.as_str())
    }

    /// A new commit on top of `parent` whose tree is the parent's tree with
    /// `upserts` (name → blob oid) applied.
    pub fn build_commit(parent: Option<&str>, upserts: &[(String, Oid)]) -> Result<Oid> {
        let mut entries: Vec<TreeEntry> = match parent {
            Some(p) => Self::tree_entries(p)?
                .into_iter()
                .filter(|(_, ty, _, _)| ty == "blob")
                .collect(),
            None => vec![],
        };
        for (name, oid) in upserts {
            entries.retain(|(_, _, _, n)| n != name);
            entries.push(("100644".into(), "blob".into(), oid.clone(), name.clone()));
        }
        let tree = git::mktree(&entries)?;
        git::commit_tree(&tree, parent, "enc\n")
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
        let (ok, _, stderr) = git::run_status([
            "push",
            "-q",
            "--no-verify",
            "--no-recurse-submodules",
            &lease,
            "--",
            &self.url,
            &refspec,
        ])?;
        if ok {
            git::update_ref(&self.tracking_ref, commit)?;
            return Ok(PushOutcome::Done);
        }
        // Client-side lease check; a lost race can also surface as a
        // server-side rejection, which the caller resolves by re-fetching.
        if stderr.contains("stale info") {
            return Ok(PushOutcome::StaleLease);
        }
        Ok(PushOutcome::Failed(stderr.trim().to_owned()))
    }
}
