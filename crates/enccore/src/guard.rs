//! A pre-push guard: refuse to send what came from an encrypted remote to
//! any other remote. DESIGN.md §6.7.

use anyhow::{Context, Result, bail};

use crate::git::{self, Oid};

/// A pushed ref that would publish commits of an encrypted remote.
pub struct Leak {
    pub local_ref: String,
    /// A commit it shares with the encrypted remote that the destination
    /// does not have.
    pub commit: Oid,
    /// The encrypted remote's ref it comes from.
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

    let mut sources = Vec::new();
    for name in &remotes {
        // The destination itself, by name or by URL.
        if Some(name.as_str()) == dest
            || git::config(&format!("remote.{name}.url"))?.as_deref() == Some(url)
        {
            continue;
        }
        sources.extend(ref_names(&format!("refs/remotes/{name}/"))?);
        // Local branches building on it hold commits not pushed there yet.
        for (key, value) in git::config_regexp(r"^branch\..*\.remote$")? {
            if value == *name
                && let Some(branch) = key
                    .strip_prefix("branch.")
                    .and_then(|k| k.strip_suffix(".remote"))
            {
                sources.push(format!("refs/heads/{branch}"));
            }
        }
    }

    let mut leaks = Vec::new();
    for (local_ref, local) in &pushed {
        'sources: for source in &sources {
            // Everything both reach is below their merge bases; if the
            // destination has every base, it has all of it.
            let (ok, out, _) = git::run_status(["merge-base", "--all", local, source])?;
            if !ok {
                continue;
            }
            let bases = String::from_utf8(out).context("merge-base output is not UTF-8")?;
            for base in bases.lines() {
                if !reachable_from(base, &excludes)? {
                    leaks.push(Leak {
                        local_ref: local_ref.clone(),
                        commit: base.to_owned(),
                        source: source.clone(),
                    });
                    break 'sources;
                }
            }
        }
    }
    Ok(leaks)
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

fn reachable_from(commit: &str, tips: &[Oid]) -> Result<bool> {
    let mut input = format!("{commit}\n");
    for t in tips {
        input.push('^');
        input.push_str(t);
        input.push('\n');
    }
    Ok(git::run_input(["rev-list", "-1", "--stdin"], input.as_bytes())?.is_empty())
}

fn is_zero(oid: &str) -> bool {
    oid.bytes().all(|b| b == b'0')
}
