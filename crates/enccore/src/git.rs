//! Thin wrappers around git plumbing, in the C locale. A command runs in the
//! user's repository, inheriting `GIT_DIR` from the environment exactly as
//! git sets it for a remote helper ([`USER`] and the free functions), or in
//! another repository (a [`Git`] made by [`Git::at`]).

use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::JoinHandle;

use anyhow::{Context, Result, anyhow, bail};

/// A hex object id as git prints it. Kept as a string: the helper never
/// interprets it beyond passing it back to git.
pub type Oid = String;

/// `(mode, type, oid, name)` as printed by `git ls-tree`.
pub type TreeEntry = (String, String, Oid, String);

/// The repository commands run in.
pub struct Git {
    /// `None`: the user's repository, as the environment names it.
    dir: Option<PathBuf>,
    /// Extra environment for every command.
    env: Vec<(OsString, OsString)>,
}

/// The user's repository.
pub static USER: Git = Git {
    dir: None,
    env: Vec::new(),
};

/// Variables through which git names the repository to work on, or alters
/// how it reads it; a command in another repository must not inherit them.
/// `git rev-parse --local-env-vars` also lists `GIT_CONFIG_PARAMETERS` and
/// `GIT_CONFIG_COUNT` (with its `GIT_CONFIG_KEY_<n>`/`GIT_CONFIG_VALUE_<n>`):
/// those stay inherited on purpose, as they carry the user's `-c` settings,
/// transport options among them.
const REPO_ENV: [&str; 15] = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_IMPLICIT_WORK_TREE",
    "GIT_CONFIG",
    "GIT_GRAFT_FILE",
    "GIT_REPLACE_REF_BASE",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_COMMON_DIR",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_INDEX_FILE",
    "GIT_NAMESPACE",
    "GIT_SHALLOW_FILE",
    "GIT_QUARANTINE_PATH",
    "GIT_PREFIX",
];

// Show only environment variable names: values may contain credentials
// (for example, an `http.extraHeader`).
impl std::fmt::Debug for Git {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Git")
            .field("dir", &self.dir)
            .field("env", &self.env.iter().map(|(k, _)| k).collect::<Vec<_>>())
            .finish()
    }
}

impl Git {
    /// Commands in `dir`, which must be a bare repository, with `env` added
    /// to every command. `env` must not set a `REPO_ENV` variable, which
    /// would point the command back at another repository.
    pub fn at(dir: PathBuf, env: Vec<(OsString, OsString)>) -> Self {
        debug_assert!(
            !env.iter()
                .any(|(k, _)| REPO_ENV.iter().any(|v| k.as_os_str() == OsStr::new(v))),
            "Git::at: env sets a repository variable"
        );
        Self {
            dir: Some(dir),
            env,
        }
    }

    /// The repository's directory; `None` for the user's repository.
    pub fn dir(&self) -> Option<&Path> {
        self.dir.as_deref()
    }

    fn command<I, S>(&self, args: I) -> Command
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut c = Command::new("git");
        if let Some(dir) = &self.dir {
            for v in REPO_ENV {
                c.env_remove(v);
            }
            c.arg("--git-dir").arg(dir);
        }
        c.args(args);
        c.envs(self.env.iter().map(|(k, v)| (k, v)));
        // Distinguish failures (a missing remote ref, a stale lease) by git's
        // message, which a translated locale would reword.
        c.env("LC_ALL", "C");
        c
    }
}

fn command<I, S>(args: I) -> Command
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    USER.command(args)
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

impl Git {
    /// Run a git command and return its stdout. A non-zero exit is an error
    /// carrying git's stderr.
    pub fn run<I, S>(&self, args: I) -> Result<Vec<u8>>
    where
        I: IntoIterator<Item = S> + Clone,
        S: AsRef<OsStr>,
    {
        let (ok, stdout, stderr) = self.run_status(args.clone())?;
        if !ok {
            bail!("`git {}` failed: {}", describe(args), stderr.trim());
        }
        Ok(stdout)
    }

    /// Run a git command, returning `(success, stdout, stderr)` without failing
    /// on a non-zero exit.
    pub fn run_status<I, S>(&self, args: I) -> Result<(bool, Vec<u8>, String)>
    where
        I: IntoIterator<Item = S> + Clone,
        S: AsRef<OsStr>,
    {
        let out = self
            .command(args.clone())
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("spawning `git {}`", describe(args)))?;
        Ok((
            out.status.success(),
            out.stdout,
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ))
    }

    /// [`Self::run`] for commands whose output is a single ASCII line.
    pub fn run_line<I, S>(&self, args: I) -> Result<String>
    where
        I: IntoIterator<Item = S> + Clone,
        S: AsRef<OsStr>,
    {
        ascii_line(&self.run(args)?)
    }

    /// Run with `input` on stdin and return stdout.
    pub fn run_input<I, S>(&self, args: I, input: &[u8]) -> Result<Vec<u8>>
    where
        I: IntoIterator<Item = S> + Clone,
        S: AsRef<OsStr>,
    {
        let desc = describe(args.clone());
        let mut child = self
            .command(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("spawning `git {desc}`"))?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("no stdin for `git {desc}`"))?;
        // Write from another thread while reading output: commands that answer as
        // they read (`patch-id`, `cat-file --batch`) would otherwise block on a
        // full stdout pipe while this thread blocks on a full stdin pipe.
        let (written, out) = std::thread::scope(|s| {
            let writer = s.spawn(move || stdin.write_all(input));
            let out = child.wait_with_output();
            (writer.join(), out)
        });
        let out = out?;
        if out.status.success() {
            written.map_err(|_| anyhow!("writing to `git {desc}` panicked"))??;
        } else {
            bail!(
                "`git {desc}` failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(out.stdout)
    }

    /// [`Self::run_status`], with `input`, if any, on stdin, and git's stderr
    /// also shown as it arrives when `tee`: for `fetch`/`push --progress`.
    pub fn run_status_tee<I, S>(
        &self,
        args: I,
        input: Option<&[u8]>,
        tee: bool,
    ) -> Result<(bool, Vec<u8>, String)>
    where
        I: IntoIterator<Item = S> + Clone,
        S: AsRef<OsStr>,
    {
        let desc = describe(args.clone());
        let mut child = self
            .command(args)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("spawning `git {desc}`"))?;
        let stderr = drain_stderr(&mut child, tee);
        let stdin = child.stdin.take();
        let mut stdout = Vec::new();
        // Reaped and its stderr collected even when the read fails; the dropped
        // pipe ends git if it is still writing. Input is written from another
        // thread, as in `run_input`.
        let read = std::thread::scope(|s| {
            if let (Some(mut stdin), Some(input)) = (stdin, input) {
                // A write error is git exiting early, which its status reports.
                s.spawn(move || {
                    let _ = stdin.write_all(input);
                });
            }
            child
                .stdout
                .take()
                .map_or(Ok(0), |mut o| o.read_to_end(&mut stdout))
        });
        let status = child.wait();
        let stderr = join_stderr(stderr);
        read.with_context(|| format!("reading `git {desc}`"))?;
        let status = status.with_context(|| format!("waiting for `git {desc}`"))?;
        Ok((status.success(), stdout, stderr))
    }

    /// Resolve a revision to an object id, `None` if it does not exist locally.
    pub fn rev_parse(&self, rev: &str) -> Result<Option<Oid>> {
        let spec = format!("{rev}^{{object}}");
        let (ok, out, _) = self.run_status(["rev-parse", "-q", "--verify", &spec])?;
        if ok {
            Ok(Some(ascii_line(&out)?))
        } else {
            Ok(None)
        }
    }

    pub fn has_object(&self, oid: &str) -> Result<bool> {
        Ok(self.run_status(["cat-file", "-e", oid])?.0)
    }

    /// Filter `oids` down to those present in the local object store.
    pub fn have_objects(&self, oids: &[Oid]) -> Result<Vec<Oid>> {
        if oids.is_empty() {
            return Ok(vec![]);
        }
        let mut input = oids.join("\n");
        input.push('\n');
        let out = self.run_input(["cat-file", "--batch-check"], input.as_bytes())?;
        let text = std::str::from_utf8(&out).context("cat-file output is not UTF-8")?;
        Ok(text
            .lines()
            .filter(|l| !l.ends_with(" missing"))
            .filter_map(|l| l.split(' ').next().map(str::to_owned))
            .collect())
    }

    pub fn is_ancestor(&self, old: &str, new: &str) -> Result<bool> {
        Ok(self
            .run_status(["merge-base", "--is-ancestor", old, new])?
            .0)
    }

    pub fn update_ref(&self, name: &str, oid: &str) -> Result<()> {
        self.run(["update-ref", name, oid])?;
        Ok(())
    }

    pub fn delete_ref(&self, name: &str) -> Result<()> {
        self.run(["update-ref", "-d", name])?;
        Ok(())
    }

    /// Store a ciphertext file as an uncompressed blob; deflating it gains
    /// nothing. Set both loose and pack compression levels because files over
    /// `core.bigFileThreshold` go straight into a pack.
    pub fn hash_object_file(&self, path: &Path) -> Result<Oid> {
        let mut c = self.command([
            "-c",
            "core.looseCompression=0",
            "-c",
            "pack.compression=0",
            "hash-object",
            "-w",
            "--no-filters",
        ]);
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

    pub fn hash_object(&self, data: &[u8]) -> Result<Oid> {
        ascii_line(&self.run_input(["hash-object", "-w", "--stdin", "--no-filters"], data)?)
    }

    pub fn object_size(&self, oid: &str) -> Result<u64> {
        self.run_line(["cat-file", "-s", oid])?
            .parse()
            .with_context(|| format!("size of object {oid}"))
    }

    pub fn cat_blob(&self, oid: &str) -> Result<Vec<u8>> {
        self.run(["cat-file", "blob", oid])
    }

    pub fn ls_tree(&self, treeish: &str) -> Result<Vec<TreeEntry>> {
        let out = self.run(["ls-tree", "-z", treeish])?;
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

    /// Entries may name objects that are not here: in the backend
    /// repository, pack blobs stay on the host until needed.
    pub fn mktree(&self, entries: &[TreeEntry]) -> Result<Oid> {
        let mut input = Vec::new();
        for (mode, ty, oid, name) in entries {
            input.extend_from_slice(format!("{mode} {ty} {oid}\t{name}\0").as_bytes());
        }
        ascii_line(&self.run_input(["mktree", "-z", "--missing"], &input)?)
    }

    /// A deterministic, anonymous commit: fixed author/committer/date so the
    /// backend history leaks nothing about who pushed or when. Never signed,
    /// whatever `commit.gpgSign` says: a signature would name the pusher.
    pub fn commit_tree(&self, tree: &str, parents: &[&str], message: &str) -> Result<Oid> {
        let mut args = vec!["commit-tree", "--no-gpg-sign", tree];
        for p in parents {
            args.push("-p");
            args.push(p);
        }
        let mut c = self.command(&args);
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
}

// The user's repository: shorthands for the [`USER`] methods, whose docs
// apply. Functions with no `Git` method below run there too.

pub fn run<I, S>(args: I) -> Result<Vec<u8>>
where
    I: IntoIterator<Item = S> + Clone,
    S: AsRef<OsStr>,
{
    USER.run(args)
}

pub fn run_status<I, S>(args: I) -> Result<(bool, Vec<u8>, String)>
where
    I: IntoIterator<Item = S> + Clone,
    S: AsRef<OsStr>,
{
    USER.run_status(args)
}

pub fn run_line<I, S>(args: I) -> Result<String>
where
    I: IntoIterator<Item = S> + Clone,
    S: AsRef<OsStr>,
{
    USER.run_line(args)
}

pub fn run_input<I, S>(args: I, input: &[u8]) -> Result<Vec<u8>>
where
    I: IntoIterator<Item = S> + Clone,
    S: AsRef<OsStr>,
{
    USER.run_input(args, input)
}

pub fn rev_parse(rev: &str) -> Result<Option<Oid>> {
    USER.rev_parse(rev)
}

pub fn has_object(oid: &str) -> Result<bool> {
    USER.has_object(oid)
}

pub fn have_objects(oids: &[Oid]) -> Result<Vec<Oid>> {
    USER.have_objects(oids)
}

pub fn is_ancestor(old: &str, new: &str) -> Result<bool> {
    USER.is_ancestor(old, new)
}

pub fn update_ref(name: &str, oid: &str) -> Result<()> {
    USER.update_ref(name, oid)
}

pub fn delete_ref(name: &str) -> Result<()> {
    USER.delete_ref(name)
}

pub fn object_size(oid: &str) -> Result<u64> {
    USER.object_size(oid)
}

/// Collects a child's stderr on a thread, so a chatty command (progress
/// output) never blocks on a full pipe; `tee` also copies its progress lines
/// to ours as they arrive and leaves them out of the result. Errors are
/// reported by the caller, and other messages (a host's hints) are not for
/// the user.
fn drain_stderr(child: &mut Child, tee: bool) -> Option<JoinHandle<String>> {
    let mut err = child.stderr.take()?;
    Some(std::thread::spawn(move || {
        let mut kept = Vec::new();
        let mut pending = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = match err.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    // Keep the pipe open to EOF: closed, it would kill git
                    // with SIGPIPE before it writes its error.
                    let _ = std::io::copy(&mut err, &mut std::io::sink());
                    break;
                }
            };
            let chunk = buf.get(..n).unwrap_or_default();
            if !tee {
                kept.extend_from_slice(chunk);
                continue;
            }
            pending.extend_from_slice(chunk);
            let (lines, tail) = split_lines(&pending);
            let mut stderr = std::io::stderr().lock();
            for line in lines.into_iter().filter_map(|r| pending.get(r)) {
                if is_meter(line) {
                    // Best effort: this is progress output.
                    let _ = stderr.write_all(line);
                } else {
                    kept.extend_from_slice(line);
                }
            }
            let _ = stderr.flush();
            pending.drain(..tail);
        }
        kept.append(&mut pending);
        String::from_utf8_lossy(&kept).into_owned()
    }))
}

/// The complete lines of `out`, each with its `\r` or `\n`, and where the
/// incomplete tail starts.
fn split_lines(out: &[u8]) -> (Vec<Range<usize>>, usize) {
    let mut lines = Vec::new();
    let mut start = 0;
    for (i, b) in out.iter().enumerate() {
        if *b == b'\r' || *b == b'\n' {
            let end = i.saturating_add(1);
            lines.push(start..end);
            start = end;
        }
    }
    (lines, start)
}

/// Recognizes git's progress meters, including those relayed by the host.
/// The list is deliberately partial; unrecognized meters stay in the output.
fn is_meter(line: &[u8]) -> bool {
    const METERS: [&[u8]; 8] = [
        b"Enumerating objects",
        b"Counting objects",
        b"Compressing objects",
        b"Writing objects",
        b"Receiving objects",
        b"Resolving deltas",
        b"Unpacking objects",
        b"Indexing objects",
    ];
    let line = line.strip_prefix(b"remote: ").unwrap_or(line);
    METERS.iter().any(|m| line.starts_with(m))
}

fn join_stderr(handle: Option<JoinHandle<String>>) -> String {
    handle.and_then(|h| h.join().ok()).unwrap_or_default()
}

/// A spawned git command whose stdout (or stdin) is consumed as a stream by
/// the caller. [`Streaming::finish`] reaps it and surfaces a non-zero exit.
pub struct Streaming {
    child: Child,
    desc: String,
    stderr: Option<JoinHandle<String>>,
}

impl Streaming {
    /// Spawn with stdout piped; `input`, if any, is written to stdin first.
    pub fn reader<I, S>(args: I, input: Option<&[u8]>) -> Result<Self>
    where
        I: IntoIterator<Item = S> + Clone,
        S: AsRef<OsStr>,
    {
        Self::reader_tee(args, input, false)
    }

    /// [`Streaming::reader`], showing git's stderr as it arrives when `tee`.
    pub fn reader_tee<I, S>(args: I, input: Option<&[u8]>, tee: bool) -> Result<Self>
    where
        I: IntoIterator<Item = S> + Clone,
        S: AsRef<OsStr>,
    {
        Self::reader_in(&USER, args, input, tee)
    }

    /// [`Streaming::reader_tee`] in repository `git`.
    pub fn reader_in<I, S>(git: &Git, args: I, input: Option<&[u8]>, tee: bool) -> Result<Self>
    where
        I: IntoIterator<Item = S> + Clone,
        S: AsRef<OsStr>,
    {
        let desc = describe(args.clone());
        let mut child = git
            .command(args)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("spawning `git {desc}`"))?;
        let stderr = drain_stderr(&mut child, tee);
        if let Some(input) = input {
            child
                .stdin
                .take()
                .ok_or_else(|| anyhow!("no stdin for `git {desc}`"))?
                .write_all(input)?;
        }
        Ok(Self {
            child,
            desc,
            stderr,
        })
    }

    /// Spawn with stdin piped for the caller to write into.
    pub fn writer<I, S>(args: I) -> Result<Self>
    where
        I: IntoIterator<Item = S> + Clone,
        S: AsRef<OsStr>,
    {
        Self::writer_tee(args, false)
    }

    /// [`Streaming::writer`], showing git's stderr as it arrives when `tee`.
    pub fn writer_tee<I, S>(args: I, tee: bool) -> Result<Self>
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
        let stderr = drain_stderr(&mut child, tee);
        Ok(Self {
            child,
            desc,
            stderr,
        })
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
        let status = self.child.wait()?;
        let stderr = join_stderr(self.stderr.take());
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

pub fn object_type(oid: &str) -> Result<String> {
    run_line(["cat-file", "-t", oid])
}

/// `rev-list --stdin` input for `tips` minus `excludes`.
fn rev_list_input(tips: &[Oid], excludes: &[Oid]) -> String {
    let mut revs = String::new();
    for t in tips {
        revs.push_str(t);
        revs.push('\n');
    }
    for e in excludes {
        revs.push('^');
        revs.push_str(e);
        revs.push('\n');
    }
    revs
}

/// The commits of `tips` minus `excludes` that are shallow boundaries of
/// this clone: their parents are missing here, so a pack of that range
/// references commits it cannot carry.
pub fn shallow_boundaries(tips: &[Oid], excludes: &[Oid]) -> Result<Vec<Oid>> {
    let path = run_line([
        "rev-parse",
        "--path-format=absolute",
        "--git-path",
        "shallow",
    ])?;
    let shallow = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e).with_context(|| format!("reading {path}")),
    };
    let shallow: std::collections::HashSet<&str> = shallow.lines().collect();
    if shallow.is_empty() {
        return Ok(vec![]);
    }
    let listed = run_input(
        ["rev-list", "--stdin"],
        rev_list_input(tips, excludes).as_bytes(),
    )?;
    Ok(String::from_utf8(listed)
        .context("rev-list output is not UTF-8")?
        .lines()
        .filter(|c| shallow.contains(c))
        .map(str::to_owned)
        .collect())
}

/// The paths of the Git LFS pointers among the blobs reachable from `tips`
/// but not from `excludes`: files whose content is in LFS storage, not in
/// the objects.
pub fn lfs_pointers(tips: &[Oid], excludes: &[Oid]) -> Result<Vec<String>> {
    let revs = rev_list_input(tips, excludes);
    // The pointer format caps a pointer at 1024 bytes.
    let listed = run_input(
        [
            "rev-list",
            "--objects",
            "--filter=blob:limit=1024",
            "--stdin",
        ],
        revs.as_bytes(),
    )?;
    // `<oid> <path>` for trees and blobs; commits have no path.
    let named: Vec<(&[u8], &[u8])> = listed
        .split(|&b| b == b'\n')
        .filter_map(|l| {
            let at = l.iter().position(|&b| b == b' ')?;
            Some((l.get(..at)?, l.get(at.saturating_add(1)..)?))
        })
        .collect();
    if named.is_empty() {
        return Ok(vec![]);
    }
    let mut input = Vec::new();
    for (oid, _) in &named {
        input.extend_from_slice(oid);
        input.push(b'\n');
    }
    let types = run_input(["cat-file", "--batch-check=%(objecttype)"], &input)?;
    let blobs: Vec<&(&[u8], &[u8])> = named
        .iter()
        .zip(types.split(|&b| b == b'\n'))
        .filter(|(_, ty)| *ty == b"blob")
        .map(|(n, _)| n)
        .collect();
    if blobs.is_empty() {
        return Ok(vec![]);
    }
    let mut input = Vec::new();
    for (oid, _) in &blobs {
        input.extend_from_slice(oid);
        input.push(b'\n');
    }
    // `<oid> blob <size>\n<content>\n` per blob, in input order.
    let out = run_input(["cat-file", "--batch"], &input)?;
    let mut rest = out.as_slice();
    let mut pointers = Vec::new();
    for (_, path) in blobs {
        let header_end = rest
            .iter()
            .position(|&b| b == b'\n')
            .ok_or_else(|| anyhow!("short cat-file --batch output"))?;
        let size: usize = std::str::from_utf8(rest.get(..header_end).unwrap_or_default())
            .ok()
            .and_then(|h| h.rsplit(' ').next())
            .and_then(|n| n.parse().ok())
            .ok_or_else(|| anyhow!("malformed cat-file --batch header"))?;
        let start = header_end.saturating_add(1);
        let end = start.saturating_add(size);
        let content = rest
            .get(start..end)
            .ok_or_else(|| anyhow!("short cat-file --batch output"))?;
        if content.starts_with(b"version https://git-lfs.github.com/spec/")
            || content.starts_with(b"version https://hawser.github.com/spec/")
        {
            pointers.push(String::from_utf8_lossy(path).into_owned());
        }
        rest = rest.get(end.saturating_add(1)..).unwrap_or_default();
    }
    Ok(pointers)
}

/// How many objects `tips` reach.
pub fn count_objects(tips: &[Oid]) -> Result<u64> {
    let out = run_input(
        ["rev-list", "--objects", "--no-object-names", "--stdin"],
        rev_list_input(tips, &[]).as_bytes(),
    )?;
    Ok(out.iter().filter(|b| **b == b'\n').count() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_in_another_repository_drops_the_users_repository_env() {
        let git = Git::at("/x".into(), vec![("K".into(), "V".into())]);
        let c = git.command(["status"]);
        let args: Vec<_> = c.get_args().collect();
        assert_eq!(args[..2], [OsStr::new("--git-dir"), OsStr::new("/x")]);
        let envs: std::collections::HashMap<_, _> = c.get_envs().collect();
        for v in REPO_ENV {
            assert_eq!(envs.get(OsStr::new(v)), Some(&None), "{v}");
        }
        assert_eq!(envs.get(OsStr::new("K")), Some(&Some(OsStr::new("V"))));
        assert_eq!(envs.get(OsStr::new("LC_ALL")), Some(&Some(OsStr::new("C"))));

        let c = USER.command(["status"]);
        assert!(c.get_envs().all(|(_, v)| v.is_some()));
        assert_eq!(c.get_args().next(), Some(OsStr::new("status")));
    }

    #[test]
    fn run_input_survives_output_larger_than_a_pipe() {
        let mut log = String::new();
        for i in 0..3000 {
            log.push_str(&format!(
                "commit {i:040x}\ndiff --git a/f b/f\n--- a/f\n+++ b/f\n@@ -1 +1 @@\n-a{i}\n+b{i}\n"
            ));
        }
        let out = run_input(["patch-id", "--stable"], log.as_bytes()).unwrap();
        assert_eq!(out.iter().filter(|&&b| b == b'\n').count(), 3000);
    }

    #[test]
    fn split_lines_keeps_terminators_and_the_tail() {
        let out = b"Receiving objects:  50%\rReceiving objects: 100%, done.\nremote: Tot";
        let (lines, tail) = split_lines(out);
        assert_eq!(lines, [0..24, 24..55]);
        assert_eq!(&out[tail..], b"remote: Tot");
        assert_eq!(split_lines(b""), (vec![], 0));
        assert_eq!(split_lines(b"a\n\r"), (vec![0..2, 2..3], 3));
    }

    #[test]
    fn is_meter_matches_local_and_relayed_meters() {
        assert!(is_meter(b"Writing objects:  10% (1/10)\r"));
        assert!(is_meter(b"remote: Counting objects: 3, done.\n"));
        assert!(!is_meter(b"remote: Total 3 (delta 0), reused 0\n"));
        assert!(!is_meter(b"fatal: couldn't find remote ref enc\n"));
        assert!(!is_meter(b"remote: remote: Writing objects\n"));
    }
}
