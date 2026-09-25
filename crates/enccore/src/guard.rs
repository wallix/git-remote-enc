//! A pre-push guard: refuse to send what came from an encrypted remote to
//! any other remote. DESIGN.md §6.7.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};

use crate::git::{self, Oid};
use crate::info;

/// A pushed ref that would publish content of an encrypted remote.
pub struct Leak {
    pub local_ref: String,
    /// What it shares with the encrypted remote that the destination does
    /// not have: `commit <oid>`, `object <oid>`, `the change of <oid>` or
    /// `the lines added by <oid>`.
    pub what: String,
    /// The encrypted remote it comes from.
    pub source: String,
}

/// Check a pre-push hook's input: `remote` and `url` are its arguments,
/// `updates` its stdin (`<local ref> <local oid> <remote ref> <remote oid>`
/// per line).
pub fn check_pre_push(remote: &str, url: &str, updates: &str) -> Result<Vec<Leak>> {
    let remotes = encrypted_remotes()?;
    let configured = git::config(&format!("remote.{remote}.url"))?;
    let dest = configured.as_ref().map(|_| remote);
    // An encrypted remote whose push git rerouted to a plain URL
    // (`pushurl`, `pushInsteadOf`): the helper does not run, this does.
    let intended = configured.as_deref().unwrap_or(remote);
    if intended.starts_with("enc::") && !url.starts_with("enc::") {
        bail!(
            "{remote} is an encrypted remote ({intended}), but this push goes to {url} in clear: \
             remote.{remote}.pushurl or a url.<base>.pushInsteadOf / insteadOf rule reroutes it. \
             Refusing to push"
        );
    }
    // What the destination already has: its remote-tracking refs, and the
    // old values of the refs being pushed.
    let mut excludes = match dest {
        Some(d) => ref_oids(&format!("refs/remotes/{d}/"))?,
        None => vec![],
    };
    let mut pushed = Vec::new();
    for line in updates.lines() {
        let mut it = line.split(' ');
        let (Some(local_ref), Some(local), Some(_), Some(old)) =
            (it.next(), it.next(), it.next(), it.next())
        else {
            continue;
        };
        if !is_zero(old) && git::has_object(old)? {
            excludes.push(old.to_owned());
        }
        if !is_zero(local) {
            pushed.push((local_ref.to_owned(), local.to_owned()));
        }
    }

    // Per encrypted remote, the refs holding its content: its
    // remote-tracking refs, and the local branches building on it, which
    // hold commits not pushed there yet.
    let mut sources: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    let upstreams = git::config_regexp(r"^branch\..*\.remote$")?;
    for name in &remotes {
        // The destination itself, by name or by URL.
        if Some(name.as_str()) == dest
            || git::config(&format!("remote.{name}.url"))?.as_deref() == Some(url)
        {
            continue;
        }
        let refs = sources.entry(name).or_default();
        refs.extend(ref_names(&format!("refs/remotes/{name}/"))?);
        for (key, value) in &upstreams {
            if value == name
                && let Some(branch) = key
                    .strip_prefix("branch.")
                    .and_then(|k| k.strip_suffix(".remote"))
            {
                refs.push(format!("refs/heads/{branch}"));
            }
        }
    }

    // Content, not topology: a cherry-pick or a squash of the fix shares no
    // commit with the encrypted remote, but it shares its blobs (the fixed
    // file), or when applied to a different base its patch id, or the lines
    // one of its hunks adds when a conflict was resolved around them. Every
    // git failure is an error, so the push is refused rather than let
    // through.
    let trivial = trivial_objects()?;
    let mut leaks = Vec::new();
    for (name, refs) in &sources {
        if refs.is_empty() {
            continue;
        }
        let secret_objects: BTreeSet<Oid> = objects(refs, &excludes)?.into_iter().collect();
        if secret_objects.is_empty() {
            continue;
        }
        let secret = changes(refs, &excludes)?;
        for (local_ref, local) in &pushed {
            let tip = std::slice::from_ref(local);
            let what = match objects(tip, &excludes)?
                .into_iter()
                .find(|o| secret_objects.contains(o) && !trivial.contains(o))
            {
                Some(o) if git::object_type(&o)? == "commit" => Some(format!("commit {o}")),
                Some(o) => Some(format!("object {o}")),
                None => {
                    let pushed = changes(tip, &excludes)?;
                    pushed
                        .patches
                        .keys()
                        .find_map(|id| secret.patches.get(id))
                        .map(|c| format!("the change of {c}"))
                        .or_else(|| {
                            pushed
                                .hunks
                                .keys()
                                .find_map(|h| secret.hunks.get(h))
                                .map(|c| format!("the lines added by {c}"))
                        })
                }
            };
            if let Some(what) = what {
                leaks.push(Leak {
                    local_ref: local_ref.clone(),
                    what,
                    source: (*name).to_owned(),
                });
            }
        }
    }
    Ok(leaks)
}

/// Objects reachable from `tips` but not from `excludes`, commits first.
fn objects(tips: &[String], excludes: &[Oid]) -> Result<Vec<Oid>> {
    let out = git::run_input(
        ["rev-list", "--objects", "--no-object-names", "--stdin"],
        revs(tips, excludes).as_bytes(),
    )?;
    Ok(String::from_utf8(out)
        .context("rev-list output is not UTF-8")?
        .lines()
        .map(str::to_owned)
        .collect())
}

/// Fingerprints of the non-merge commits reachable from some tips but not
/// from others, each mapped to the commit it was taken from.
struct Changes {
    /// `git patch-id --stable` of the diff without context lines, so a
    /// change applied where its surroundings differ keeps its id.
    patches: BTreeMap<String, Oid>,
    /// Per hunk, the lines it adds (see [`hunk_prints`]): what survives a
    /// conflict resolved around the fix, or a squash with other changes.
    hunks: BTreeMap<String, Oid>,
}

fn changes(tips: &[String], excludes: &[Oid]) -> Result<Changes> {
    let log = git::run_input(
        [
            "log",
            "--no-merges",
            "-p",
            "-U0",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            "--format=commit %H",
            "--stdin",
        ],
        revs(tips, excludes).as_bytes(),
    )?;
    let out = git::run_input(["patch-id", "--stable"], &log)?;
    let patches = String::from_utf8(out)
        .context("patch-id output is not UTF-8")?
        .lines()
        .filter_map(|l| l.split_once(' '))
        .map(|(id, commit)| (id.to_owned(), commit.to_owned()))
        .collect();
    Ok(Changes {
        patches,
        hunks: hunk_prints(&log),
    })
}

/// Hunks adding less than this, whitespace aside, are too common (a closing
/// brace, an `else`) to tell a backport from unrelated work.
const MIN_HUNK_BYTES: usize = 24;

/// `SHA-256 → commit` of what each hunk of a `git log -p -U0
/// --format="commit %H"` output adds, whitespace and line breaks dropped
/// (reindenting or rewrapping the fix keeps it), for the hunks adding at
/// least [`MIN_HUNK_BYTES`].
fn hunk_prints(log: &[u8]) -> BTreeMap<String, Oid> {
    let mut prints = BTreeMap::new();
    let mut commit: Option<&str> = None;
    let mut in_hunk = false;
    let mut added: Vec<u8> = Vec::new();
    let mut flush = |added: &mut Vec<u8>, commit: Option<&str>| {
        if added.len() >= MIN_HUNK_BYTES
            && let Some(c) = commit
        {
            prints
                .entry(crate::crypto::sha256_hex(added))
                .or_insert_with(|| c.to_owned());
        }
        added.clear();
    };
    for line in log.split(|&b| b == b'\n') {
        if let Some(c) = line.strip_prefix(b"commit ") {
            flush(&mut added, commit);
            commit = std::str::from_utf8(c).ok();
            in_hunk = false;
        } else if line.starts_with(b"diff ") {
            flush(&mut added, commit);
            in_hunk = false;
        } else if line.starts_with(b"@@") {
            flush(&mut added, commit);
            in_hunk = true;
        } else if in_hunk && let Some(text) = line.strip_prefix(b"+") {
            added.extend(text.iter().filter(|b| !b.is_ascii_whitespace()));
        }
    }
    flush(&mut added, commit);
    prints
}

fn revs(tips: &[String], excludes: &[Oid]) -> String {
    let mut input = String::new();
    for t in tips {
        input.push_str(t);
        input.push('\n');
    }
    for e in excludes {
        input.push('^');
        input.push_str(e);
        input.push('\n');
    }
    input
}

/// The empty blob and tree: shared by unrelated histories, so no evidence.
fn trivial_objects() -> Result<BTreeSet<Oid>> {
    let mut set = BTreeSet::new();
    for ty in ["blob", "tree"] {
        // stdin is empty: git runs with it closed.
        set.insert(git::run_line(["hash-object", "-t", ty, "--stdin"])?);
    }
    Ok(set)
}

/// On every contact with an encrypted remote, check that the guard runs:
/// install it where no pre-push hook exists (again, if something removed
/// it), and report a pre-push hook that does not run it, one that is not
/// executable, or a shared `core.hooksPath` directory without one, which
/// are left alone. Another tool (`git lfs install --force`) may replace
/// the guard at any time, so a check on first contact only is not enough.
pub fn ensure_hook() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let path = git::hook_path("pre-push")?;
    let unguarded = "so nothing stops a push of this remote's commits to a plain remote";
    let silence = "enc.installHook=false silences this";
    match std::fs::read(&path) {
        Ok(text) if String::from_utf8_lossy(&text).contains("git-remote-enc pre-push") => {
            let mode = std::fs::metadata(&path)
                .with_context(|| format!("reading {}", path.display()))?
                .permissions()
                .mode();
            if mode & 0o111 == 0 {
                info(&format!(
                    "warning: {} is not executable, so git does not run it, {unguarded}; \
                     chmod +x it ({silence}; DESIGN.md §6.7)",
                    path.display()
                ));
            }
        }
        Ok(_) => info(&format!(
            "warning: {} exists and does not run the git-remote-enc guard, {unguarded}; make it \
             run `git-remote-enc pre-push \"$1\" \"$2\"` ({silence}; DESIGN.md §6.7)",
            path.display()
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if git::config("core.hooksPath")?.is_some() {
                info(&format!(
                    "warning: core.hooksPath is set and {} does not exist, {unguarded}; see \
                     `git-remote-enc install-hook` ({silence}; DESIGN.md §6.7)",
                    path.display()
                ));
            } else {
                let path = install_hook()?;
                info(&format!(
                    "installed the pre-push guard {} (enc.installHook=false turns this off)",
                    path.display()
                ));
            }
        }
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    }
    Ok(())
}

/// Write the pre-push hook that runs the guard. An existing hook is left
/// alone: it has to call the guard itself.
pub fn install_hook() -> Result<std::path::PathBuf> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let path = git::hook_path("pre-push")?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .open(&path)
        .with_context(|| {
            format!(
                "creating {}; if a hook is already there, make it run \
                 `git-remote-enc pre-push \"$1\" \"$2\"` with the same stdin",
                path.display()
            )
        })?;
    f.write_all(HOOK.as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// Is `text` the hook `install_hook` writes, and nothing else?
pub fn is_guard_hook(text: &str) -> bool {
    text.trim() == HOOK.trim()
}

const HOOK: &str = "#!/bin/sh\n\
# Refuse to push commits of an encrypted remote anywhere else\n\
# (git-remote-enc install-hook). `git push --no-verify` skips it.\n\
exec git-remote-enc pre-push \"$1\" \"$2\"\n";

/// Names of the configured remotes whose URL is an `enc::` one.
fn encrypted_remotes() -> Result<Vec<String>> {
    Ok(git::config_regexp(r"^remote\..*\.url$")?
        .into_iter()
        .filter(|(_, url)| url.starts_with("enc::"))
        .filter_map(|(key, _)| {
            key.strip_prefix("remote.")
                .and_then(|k| k.strip_suffix(".url"))
                .map(str::to_owned)
        })
        .collect())
}

fn for_each_ref(format: &str, prefix: &str) -> Result<Vec<String>> {
    let out = git::run(["for-each-ref", &format!("--format={format}"), prefix])?;
    Ok(String::from_utf8(out)
        .context("for-each-ref output is not UTF-8")?
        .lines()
        .map(str::to_owned)
        .collect())
}

fn ref_names(prefix: &str) -> Result<Vec<String>> {
    for_each_ref("%(refname)", prefix)
}

fn ref_oids(prefix: &str) -> Result<Vec<Oid>> {
    for_each_ref("%(objectname)", prefix)
}

fn is_zero(oid: &str) -> bool {
    oid.bytes().all(|b| b == b'0')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hunk_prints_ignore_context_whitespace_and_small_hunks() {
        let a = b"commit aaaa\ndiff --git a/x b/x\n@@ -3 +3 @@ ctx\n-\treturn n;\n+\treturn n < 0 || n > LIMIT ? -EINVAL : n;\n@@ -9,0 +10 @@\n+}\n";
        let b = b"commit bbbb\ndiff --git a/y b/y\n@@ -7 +7,2 @@ other\n-\treturn (long)n;\n+  return n < 0 || n > LIMIT ?\n+    -EINVAL : n;\n\n";
        let (pa, pb) = (hunk_prints(a), hunk_prints(b));
        assert_eq!(pa.len(), 1, "the one-brace hunk is too small");
        assert_eq!(pa.keys().collect::<Vec<_>>(), pb.keys().collect::<Vec<_>>());
        assert_eq!(pa.values().next().map(String::as_str), Some("aaaa"));
        // A line starting with `+` outside a hunk is a header, not content.
        assert!(hunk_prints(b"commit cccc\n+++ b/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n").is_empty());
    }
}
