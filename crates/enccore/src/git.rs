//! Thin wrappers around git plumbing. Every command inherits `GIT_DIR` from
//! the environment, exactly as git sets it for a remote helper, and runs in
//! the C locale.

use std::ffi::OsStr;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use anyhow::{Context, Result, anyhow, bail};

/// A hex object id as git prints it. Kept as a string: the helper never
/// interprets it beyond passing it back to git.
pub type Oid = String;

/// `(mode, type, oid, name)` as printed by `git ls-tree`.
pub type TreeEntry = (String, String, Oid, String);

fn command<I, S>(args: I) -> Command
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut c = Command::new("git");
    c.args(args);
    // Some failures are told apart by git's message (a missing remote ref,
    // a stale lease), which a translated locale would reword.
    c.env("LC_ALL", "C");
    c
}

fn describe<I, S>(args: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    args.into_iter()
        .map(|a| a.as_ref().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Run a git command and return its stdout. A non-zero exit is an error
/// carrying git's stderr.
pub fn run<I, S>(args: I) -> Result<Vec<u8>>
where
    I: IntoIterator<Item = S> + Clone,
    S: AsRef<OsStr>,
{
    let (ok, stdout, stderr) = run_status(args.clone())?;
    if !ok {
        bail!("`git {}` failed: {}", describe(args), stderr.trim());
    }
    Ok(stdout)
}

/// Run a git command, returning `(success, stdout, stderr)` without failing
/// on a non-zero exit.
pub fn run_status<I, S>(args: I) -> Result<(bool, Vec<u8>, String)>
where
    I: IntoIterator<Item = S> + Clone,
    S: AsRef<OsStr>,
{
    let out = command(args.clone())
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("spawning `git {}`", describe(args)))?;
    Ok((
        out.status.success(),
        out.stdout,
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

/// [`run`] for commands whose output is a single ASCII line.
pub fn run_line<I, S>(args: I) -> Result<String>
where
    I: IntoIterator<Item = S> + Clone,
    S: AsRef<OsStr>,
{
    ascii_line(&run(args)?)
}

/// Run with `input` on stdin and return stdout.
pub fn run_input<I, S>(args: I, input: &[u8]) -> Result<Vec<u8>>
where
    I: IntoIterator<Item = S> + Clone,
    S: AsRef<OsStr>,
{
    let desc = describe(args.clone());
    let mut child = command(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning `git {desc}`"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("no stdin for `git {desc}`"))?
        .write_all(input)?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!(
            "`git {desc}` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(out.stdout)
}

/// A spawned git command whose stdout (or stdin) is consumed as a stream by
/// the caller. [`Streaming::finish`] reaps it and surfaces a non-zero exit.
pub struct Streaming {
    child: Child,
    desc: String,
}

impl Streaming {
    /// Spawn with stdout piped; `input`, if any, is written to stdin first.
    pub fn reader<I, S>(args: I, input: Option<&[u8]>) -> Result<Self>
    where
        I: IntoIterator<Item = S> + Clone,
        S: AsRef<OsStr>,
    {
        let desc = describe(args.clone());
        let mut child = command(args)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("spawning `git {desc}`"))?;
        if let Some(input) = input {
            child
                .stdin
                .take()
                .ok_or_else(|| anyhow!("no stdin for `git {desc}`"))?
                .write_all(input)?;
        }
        Ok(Self { child, desc })
    }

    /// Spawn with stdin piped for the caller to write into.
    pub fn writer<I, S>(args: I) -> Result<Self>
    where
        I: IntoIterator<Item = S> + Clone,
        S: AsRef<OsStr>,
    {
        let desc = describe(args.clone());
        let child = command(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("spawning `git {desc}`"))?;
        Ok(Self { child, desc })
    }

    pub fn stdout(&mut self) -> Result<std::process::ChildStdout> {
        self.child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("no stdout for `git {}`", self.desc))
    }

    pub fn stdin(&mut self) -> Result<std::process::ChildStdin> {
        self.child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("no stdin for `git {}`", self.desc))
    }

    /// Wait for exit; returns whatever stdout was not taken by the caller.
    pub fn finish(mut self) -> Result<Vec<u8>> {
        let mut stdout = Vec::new();
        if let Some(mut o) = self.child.stdout.take() {
            o.read_to_end(&mut stdout)?;
        }
        let mut stderr = String::new();
        if let Some(mut e) = self.child.stderr.take() {
            e.read_to_string(&mut stderr)?;
        }
        let status = self.child.wait()?;
        if !status.success() {
            bail!("`git {}` failed: {}", self.desc, stderr.trim());
        }
        Ok(stdout)
    }
}

fn ascii_line(out: &[u8]) -> Result<String> {
    let line = out.split(|b| *b == b'\n').next().unwrap_or_default();
    let s = std::str::from_utf8(line).context("git printed non-UTF-8 where ASCII was expected")?;
    Ok(s.trim().to_owned())
}

// ---- higher-level helpers -------------------------------------------------

/// The repository's common directory: the main `.git` even from a linked
/// worktree, whose own `$GIT_DIR` is `.git/worktrees/<name>`.
pub fn common_dir() -> Result<PathBuf> {
    Ok(run_line(["rev-parse", "--path-format=absolute", "--git-common-dir"])?.into())
}

/// Where git looks for hook `name`, `core.hooksPath` included.
pub fn hook_path(name: &str) -> Result<PathBuf> {
    Ok(run_line([
        "rev-parse",
        "--path-format=absolute",
        "--git-path",
        &format!("hooks/{name}"),
    ])?
    .into())
}

pub fn config(key: &str) -> Result<Option<String>> {
    let (ok, out, _) = run_status(["config", "--get", key])?;
    if ok {
        Ok(Some(
            String::from_utf8(out)
                .with_context(|| format!("config {key} is not UTF-8"))?
                .trim_end()
                .to_owned(),
        ))
    } else {
        Ok(None)
    }
}

pub fn config_all(key: &str) -> Result<Vec<String>> {
    let (ok, out, _) = run_status(["config", "--get-all", key])?;
    if !ok {
        return Ok(vec![]);
    }
    Ok(String::from_utf8(out)
        .with_context(|| format!("config {key} is not UTF-8"))?
        .lines()
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect())
}

/// `(key, value)` for every config entry whose key matches `regexp`; keys
/// come back lowercased, as git prints them.
pub fn config_regexp(regexp: &str) -> Result<Vec<(String, String)>> {
    let (ok, out, _) = run_status(["config", "--get-regexp", regexp])?;
    if !ok {
        return Ok(vec![]);
    }
    Ok(String::from_utf8(out)
        .with_context(|| format!("config matching {regexp} is not UTF-8"))?
        .lines()
        .filter(|s| !s.is_empty())
        .map(|l| {
            let (k, v) = l.split_once(' ').unwrap_or((l, ""));
            (k.to_owned(), v.to_owned())
        })
        .collect())
}

pub fn set_config(key: &str, value: &str) -> Result<()> {
    run(["config", key, value])?;
    Ok(())
}

/// Resolve a revision to an object id, `None` if it does not exist locally.
pub fn rev_parse(rev: &str) -> Result<Option<Oid>> {
    let spec = format!("{rev}^{{object}}");
    let (ok, out, _) = run_status(["rev-parse", "-q", "--verify", &spec])?;
    if ok {
        Ok(Some(ascii_line(&out)?))
    } else {
        Ok(None)
    }
}

pub fn object_type(oid: &str) -> Result<String> {
    run_line(["cat-file", "-t", oid])
}

pub fn has_object(oid: &str) -> Result<bool> {
    Ok(run_status(["cat-file", "-e", oid])?.0)
}

/// Filter `oids` down to those present in the local object store.
pub fn have_objects(oids: &[Oid]) -> Result<Vec<Oid>> {
    if oids.is_empty() {
        return Ok(vec![]);
    }
    let mut input = oids.join("\n");
    input.push('\n');
    let out = run_input(["cat-file", "--batch-check"], input.as_bytes())?;
    let text = std::str::from_utf8(&out).context("cat-file output is not UTF-8")?;
    Ok(text
        .lines()
        .filter(|l| !l.ends_with(" missing"))
        .filter_map(|l| l.split(' ').next().map(str::to_owned))
        .collect())
}

pub fn is_ancestor(old: &str, new: &str) -> Result<bool> {
    Ok(run_status(["merge-base", "--is-ancestor", old, new])?.0)
}

pub fn update_ref(name: &str, oid: &str) -> Result<()> {
    run(["update-ref", name, oid])?;
    Ok(())
}

pub fn delete_ref(name: &str) -> Result<()> {
    run(["update-ref", "-d", name])?;
    Ok(())
}

pub fn hash_object_file(path: &Path) -> Result<Oid> {
    let mut c = command(["hash-object", "-w", "--no-filters"]);
    c.arg(path);
    let out = c.stdin(Stdio::null()).output()?;
    if !out.status.success() {
        bail!(
            "git hash-object failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    ascii_line(&out.stdout)
}

pub fn hash_object(data: &[u8]) -> Result<Oid> {
    ascii_line(&run_input(
        ["hash-object", "-w", "--stdin", "--no-filters"],
        data,
    )?)
}

pub fn object_size(oid: &str) -> Result<u64> {
    run_line(["cat-file", "-s", oid])?
        .parse()
        .with_context(|| format!("size of object {oid}"))
}

pub fn cat_blob(oid: &str) -> Result<Vec<u8>> {
    run(["cat-file", "blob", oid])
}

pub fn ls_tree(treeish: &str) -> Result<Vec<TreeEntry>> {
    let out = run(["ls-tree", "-z", treeish])?;
    let mut entries = Vec::new();
    for raw in out.split(|b| *b == 0).filter(|s| !s.is_empty()) {
        let entry = std::str::from_utf8(raw).context("non-UTF-8 name in backend tree")?;
        let (meta, name) = entry.split_once('\t').context("malformed ls-tree output")?;
        let mut it = meta.split(' ');
        let mode = it.next().context("ls-tree mode")?;
        let ty = it.next().context("ls-tree type")?;
        let oid = it.next().context("ls-tree oid")?;
        entries.push((mode.into(), ty.into(), oid.into(), name.into()));
    }
    Ok(entries)
}

pub fn mktree(entries: &[TreeEntry]) -> Result<Oid> {
    let mut input = Vec::new();
    for (mode, ty, oid, name) in entries {
        input.extend_from_slice(format!("{mode} {ty} {oid}\t{name}\0").as_bytes());
    }
    ascii_line(&run_input(["mktree", "-z"], &input)?)
}

/// A deterministic, anonymous commit: fixed author/committer/date so the
/// backend history leaks nothing about who pushed or when. Never signed,
/// whatever `commit.gpgSign` says: a signature would name the pusher.
pub fn commit_tree(tree: &str, parent: Option<&str>, message: &str) -> Result<Oid> {
    let mut args = vec!["commit-tree", "--no-gpg-sign", tree];
    if let Some(p) = parent {
        args.push("-p");
        args.push(p);
    }
    let mut c = command(&args);
    for (k, v) in [
        ("GIT_AUTHOR_NAME", "enc"),
        ("GIT_AUTHOR_EMAIL", "enc@localhost"),
        ("GIT_AUTHOR_DATE", "1000000000 +0000"),
        ("GIT_COMMITTER_NAME", "enc"),
        ("GIT_COMMITTER_EMAIL", "enc@localhost"),
        ("GIT_COMMITTER_DATE", "1000000000 +0000"),
    ] {
        c.env(k, v);
    }
    let mut child = c
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning git commit-tree")?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("no stdin for git commit-tree"))?
        .write_all(message.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!(
            "git commit-tree failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    ascii_line(&out.stdout)
}
