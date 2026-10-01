//! `git-remote-enc`: the remote-helper protocol loop over `enccore`.
//!
//! Invoked by git as `git-remote-enc <remote> <url>` for `enc::` URLs.
//! stdout is the protocol channel; everything else goes to stderr.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]

use std::io::{self, BufRead, Write};

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use enccore::remote::{HistoryEntry, ParticipantDiff, PushStatus, RefSpec, Remote};

fn main() {
    if let Err(e) = run() {
        eprintln!("enc: error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [flag] if flag == "--version" || flag == "-V" => {
            println!("git-remote-enc {}", enccore::version::VERSION);
            Ok(())
        }
        [cmd, rest @ ..] if cmd == "manifest" && matches!(rest.len(), 1 | 2) => {
            let (with_keys, target) = match rest {
                [flag, target] if flag == "--show-keys" => (true, target),
                [target] => (false, target),
                _ => usage(),
            };
            let mut remote = open_by_name_or_url(target)?;
            match remote.manifest_text(with_keys)? {
                Some(text) => print!("{}", text.as_str()),
                None => bail!("no encrypted remote at {}", remote.url()),
            }
            Ok(())
        }
        [cmd, rest @ ..] if cmd == "participants" => {
            let o = Opts::parse(rest, &["--add", "--remove"], &["--apply", "--yes"])?;
            let [target] = o.positional.as_slice() else {
                usage()
            };
            let (add, remove) = (o.values("--add"), o.values("--remove"));
            if add.is_empty() && remove.is_empty() {
                return participants(&mut open_by_name_or_url(target)?, target, o.flag("--apply"));
            }
            edit_participants(target, &add, &remove, o.flag("--yes"))
        }
        [cmd, remote, url] if cmd == "pre-push" => pre_push(remote, url),
        [cmd, rest @ ..] if cmd == "install-hook" => {
            let o = Opts::parse(rest, &[], &["--chain"])?;
            if !o.positional.is_empty() {
                usage()
            }
            install_hook(o.flag("--chain"))
        }
        [cmd, rest @ ..] if cmd == "init" => {
            let o = Opts::parse(rest, &["--identity", "--participant"], &[])?;
            let [name, url] = o.positional.as_slice() else {
                usage()
            };
            init(name, url, o.value("--identity"), &o.values("--participant"))
        }
        [cmd, rest @ ..] if cmd == "join" => {
            let o = Opts::parse(
                rest,
                &["--identity", "--participant", "--repo", "--min-generation"],
                &[],
            )?;
            let [name, url] = o.positional.as_slice() else {
                usage()
            };
            join(name, url, &o)
        }
        [cmd, rest @ ..] if cmd == "invite" => {
            let o = Opts::parse(rest, &[], &["--yes"])?;
            let [target, keys @ ..] = o.positional.as_slice() else {
                usage()
            };
            invite(target, keys, o.flag("--yes"))
        }
        [cmd, target] if cmd == "doctor" => doctor(target),
        [cmd, target] if cmd == "log" => log(&mut open_by_name_or_url(target)?),
        [cmd, target] if cmd == "forget" => {
            let dir = open_by_name_or_url(target)?.forget()?;
            eprintln!(
                "enc: removed {}; the next contact with {target} is a first contact and needs a pinned participant list",
                dir.display()
            );
            Ok(())
        }
        [name, url] => helper(Remote::open(Some(name), url)?),
        [url] => helper(Remote::open(None, url)?),
        _ => usage(),
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: git-remote-enc <remote> <url>   (invoked by git for enc:: URLs)\n\
         \x20      git-remote-enc init <name> <git-url> [--identity <file>] [--participant <key|@file>]...\n\
         \x20      git-remote-enc invite <remote> [<their public key>...] [--yes]\n\
         \x20      git-remote-enc join <name> <git-url> --participant <key>... [--repo <id>] [--min-generation <n>] [--identity <file>]\n\
         \x20      git-remote-enc doctor <remote>\n\
         \x20      git-remote-enc manifest [--show-keys] <remote|url>\n\
         \x20      git-remote-enc participants [--apply] <remote|url>\n\
         \x20      git-remote-enc participants [--add <key>]... [--remove <key|fingerprint>]... [--yes] <remote>\n\
         \x20      git-remote-enc log <remote|url>\n\
         \x20      git-remote-enc forget <remote|url>\n\
         \x20      git-remote-enc install-hook [--chain]\n\
         \x20      git-remote-enc pre-push <remote> <url>   (as a pre-push hook)\n\
         \x20      git-remote-enc --version"
    );
    std::process::exit(2);
}

/// Print the remote's participants and admins and how the configured lists
/// differ; with `apply`, make the remote's lists the configured ones.
fn participants(remote: &mut Remote, target: &str, apply: bool) -> Result<()> {
    let access = remote.access()?;
    let pending = show_access(&mut io::stdout(), &access)?;
    if access.participants_diff.is_none() && access.admins_diff.is_none() {
        if apply {
            bail!(
                "nothing configured to apply for {target} (remote.<name>.enc-participants, enc-admins)"
            );
        }
    } else if !pending {
        println!("the configuration matches");
    } else if apply {
        remote.apply_participants()?;
        println!("applied (+ added, - removed)");
    } else {
        println!(
            "+/- lines are the configured changes; `git-remote-enc participants --apply {target}` applies them"
        );
    }
    Ok(())
}

/// Print the lists with configured changes as `+`/`-` lines; true if any
/// differ.
fn show_access(out: &mut dyn Write, access: &enccore::remote::Access) -> Result<bool> {
    let mut show = |title: &str, list: &[String], diff: &Option<ParticipantDiff>| {
        writeln!(out, "{title}:")?;
        for p in list {
            writeln!(out, "  {p}")?;
        }
        for p in diff.iter().flat_map(|d| &d.added) {
            writeln!(out, "+ {p}")?;
        }
        for p in diff.iter().flat_map(|d| &d.removed) {
            writeln!(out, "- {p}")?;
        }
        io::Result::Ok(())
    };
    show(
        "participants",
        &access.participants,
        &access.participants_diff,
    )?;
    show("admins", &access.admins, &access.admins_diff)?;
    Ok([&access.participants_diff, &access.admins_diff]
        .iter()
        .any(|d| d.as_ref().is_some_and(|d| !d.is_empty())))
}

/// Print the backend history as an audit trail, newest first.
fn log(remote: &mut Remote) -> Result<()> {
    for entry in remote.history()? {
        match entry {
            HistoryEntry::Readable {
                commit,
                generation,
                time,
                signer,
                refs,
                participants,
                admins,
                base,
                verified,
                base_verified,
                time_regressed,
            } => {
                let time = time.map_or_else(|| "time unknown".to_owned(), |t| format!("time {t}"));
                println!("generation {generation} ({time}, backend commit {commit})");
                println!("  signed by {signer}");
                if time_regressed {
                    println!(
                        "  time earlier than the generation before: pushers set their own time"
                    );
                }
                if !verified {
                    println!(
                        "  not verified: not chained to the accepted manifest, so anyone with write \
                         access to the host may have written it"
                    );
                }
                // Changes relative to anything but the previous generation
                // would credit this signer with earlier signers' changes.
                match base {
                    Some(b) if !base_verified => {
                        println!("  changes relative to generation {b}, which is not verified");
                    }
                    Some(b) if Some(b) != generation.checked_sub(1) => {
                        println!("  changes relative to generation {b}");
                    }
                    None if generation != 1 => println!("  changes relative to an empty remote"),
                    _ => {}
                }
                for r in refs {
                    println!("  ref {r}");
                }
                for (sign, list) in [("+", &participants.added), ("-", &participants.removed)] {
                    for p in list {
                        println!("  participant {sign} {p}");
                    }
                }
                for (sign, list) in [("+", &admins.added), ("-", &admins.removed)] {
                    for a in list {
                        println!("  admin {sign} {a}");
                    }
                }
            }
            HistoryEntry::Unreadable { commit, reason } => {
                println!("backend commit {commit}: not readable ({reason})");
            }
            HistoryEntry::Discontinuity { expected, found } if found > expected => {
                let last = found.saturating_sub(1);
                println!(
                    "warning: generations {expected} to {last} are missing from the backend history: the host rewrote it"
                );
            }
            HistoryEntry::Discontinuity { expected, found } => println!(
                "warning: generation {found} where {expected} was expected: the backend history was rewritten"
            ),
        }
    }
    Ok(())
}

/// The pre-push hook: refuse a push that would publish commits of an
/// encrypted remote on another one.
fn pre_push(remote: &str, url: &str) -> Result<()> {
    let mut updates = String::new();
    io::Read::read_to_string(&mut io::stdin(), &mut updates)?;
    let leaks = enccore::guard::check_pre_push(remote, url, &updates)?;
    if leaks.is_empty() {
        return Ok(());
    }
    for l in &leaks {
        eprintln!(
            "enc: {} contains {} from encrypted remote {}, which {remote} does not have",
            l.local_ref, l.what, l.source
        );
    }
    bail!(
        "refusing to push to {remote}: it would publish commits of an encrypted remote. If that is \
         the disclosure, push with --no-verify"
    )
}

/// Options after a subcommand: `valued` take the next argument (and may
/// repeat), `flags` stand alone, anything else not starting with `--` is
/// positional.
struct Opts {
    positional: Vec<String>,
    values: Vec<(String, String)>,
    flags: Vec<String>,
}

impl Opts {
    fn parse(args: &[String], valued: &[&str], flags: &[&str]) -> Result<Self> {
        let mut o = Opts {
            positional: vec![],
            values: vec![],
            flags: vec![],
        };
        let mut it = args.iter();
        while let Some(a) = it.next() {
            if valued.contains(&a.as_str()) {
                let v = it.next().ok_or_else(|| anyhow!("{a} needs a value"))?;
                o.values.push((a.clone(), v.clone()));
            } else if flags.contains(&a.as_str()) {
                o.flags.push(a.clone());
            } else if a.starts_with("--") {
                usage()
            } else {
                o.positional.push(a.clone());
            }
        }
        Ok(o)
    }

    fn values(&self, name: &str) -> Vec<String> {
        self.values
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
            .collect()
    }

    fn value(&self, name: &str) -> Option<String> {
        self.values(name).pop()
    }

    fn flag(&self, name: &str) -> bool {
        self.flags.iter().any(|f| f == name)
    }
}

/// Ask on the terminal; without one, require `--yes`.
fn confirm(question: &str) -> Result<bool> {
    use std::io::Read as _;
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("no terminal to confirm on; pass --yes")?;
    write!(tty, "enc: {question} [y/N] ")?;
    let mut answer = Vec::new();
    let mut byte = [0u8];
    while tty.read(&mut byte)? == 1 && byte[0] != b'\n' {
        answer.push(byte[0]);
    }
    Ok(matches!(
        String::from_utf8_lossy(&answer).trim(),
        "y" | "Y" | "yes"
    ))
}

/// `'…'` for a POSIX shell.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

fn install_hook(chain: bool) -> Result<()> {
    use enccore::guard::{HookState, chain_hook, hook_state, install_hook};
    let (state, path) = hook_state()?;
    match state {
        HookState::Guard | HookState::NotExecutable => {
            eprintln!("enc: {} already runs the guard", path.display());
            return Ok(());
        }
        HookState::Other if chain => {
            let path = chain_hook()?;
            eprintln!(
                "enc: {} now runs the guard first (the original is pre-push.enc-orig beside it)",
                path.display()
            );
            return Ok(());
        }
        _ => {}
    }
    let path = install_hook()?;
    eprintln!(
        "enc: installed {}: pushing commits of an encrypted remote anywhere else is refused",
        path.display()
    );
    Ok(())
}

/// The guard for `init` and `join`: installed, or put in front of the
/// existing hook.
fn setup_hook() -> Result<()> {
    use enccore::guard::{HookState, hook_state};
    match hook_state()? {
        (HookState::Missing | HookState::Other, _) => install_hook(true),
        (HookState::MissingHooksPath, path) => {
            eprintln!(
                "enc: warning: core.hooksPath is set and {} does not exist; `git-remote-enc install-hook` installs the guard there, for every repository using it",
                path.display()
            );
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Add remote `name` at `url` with its identity, creating the key file if
/// needed; returns the identity's public key.
fn add_remote(name: &str, url: &str, identity: Option<String>) -> Result<(PathBuf, String)> {
    use enccore::{git, setup};
    if git::config(&format!("remote.{name}.url"))?.is_some() {
        bail!("remote {name} already exists");
    }
    let identity = match identity {
        Some(p) => PathBuf::from(p),
        None => setup::default_identity(name)?,
    };
    if setup::ensure_identity(&identity)? {
        eprintln!("enc: created the identity {}", identity.display());
    }
    let public = setup::public_key(&identity)?;
    git::run(["remote", "add", name, &format!("enc::{url}")])?;
    git::set_config(
        &format!("remote.{name}.enc-identity"),
        &identity.to_string_lossy(),
    )?;
    Ok((identity, public))
}

fn warn_if_shallow() -> Result<()> {
    if enccore::setup::is_shallow()? {
        eprintln!(
            "enc: warning: this clone is shallow; a push reaching its boundary is refused until `git fetch --unshallow <the remote it was cloned from>`"
        );
    }
    Ok(())
}

/// Create a remote: check the host, set up the identity, the participant
/// list and the guard. Nothing is pushed.
fn init(name: &str, url: &str, identity: Option<String>, others: &[String]) -> Result<()> {
    use enccore::{crypto::Participant, setup};
    let url = url.strip_prefix("enc::").unwrap_or(url);
    Participant::parse_all(others)?;
    if setup::probe(url)? {
        bail!(
            "{url} already holds an encrypted remote; ask one of its participants for `git-remote-enc invite`"
        );
    }
    let (_, public) = add_remote(name, url, identity)?;
    let list = setup::edit_list(std::slice::from_ref(&public), others, &[])?;
    setup::set_participants(name, &list)?;
    setup_hook()?;
    warn_if_shallow()?;
    eprintln!(
        "enc: remote {name} is ready: `git push {name} <branch>` creates it, then `git-remote-enc invite {name} '<their public key>'` lets someone in\nenc: your public key: {public}"
    );
    Ok(())
}

/// Join a remote: the pinned participants and generation from `invite`,
/// an identity, the guard, then a fetch.
fn join(name: &str, url: &str, o: &Opts) -> Result<()> {
    use enccore::{crypto::Participant, git, setup};
    let url = url.strip_prefix("enc::").unwrap_or(url);
    let pinned = o.values("--participant");
    if pinned.is_empty() {
        bail!(
            "join needs --participant with the keys of who pushes there, from `git-remote-enc invite` on their side"
        );
    }
    Participant::parse_all(&pinned)?;
    if !setup::probe(url)? {
        bail!("{url} holds no encrypted remote yet; `git-remote-enc init` creates one");
    }
    let (_, public) = add_remote(name, url, o.value("--identity"))?;
    setup::set_participants(name, &pinned)?;
    if let Some(repo) = o.value("--repo") {
        git::set_config(&format!("remote.{name}.enc-repo"), &repo)?;
    }
    if let Some(g) = o.value("--min-generation") {
        g.parse::<u64>()
            .with_context(|| format!("--min-generation `{g}` is not a number"))?;
        git::set_config(&format!("remote.{name}.enc-minGeneration"), &g)?;
    }
    setup_hook()?;
    warn_if_shallow()?;
    let status = std::process::Command::new("git")
        .args(["fetch", name])
        .status()
        .context("running git fetch")?;
    if !status.success() {
        bail!(
            "fetching {name} failed. If you are not a participant yet, send your public key to one: \
             they run `git-remote-enc invite {name} {}`, then `git fetch {name}` again",
            sh_quote(&public)
        );
    }
    eprintln!("enc: joined {name}");
    Ok(())
}

/// Let others in (when keys are given), then print the `join` command
/// that pins this remote for them.
fn invite(target: &str, keys: &[String], yes: bool) -> Result<()> {
    if !keys.is_empty() {
        edit_participants(target, keys, &[], yes)?;
    }
    let mut remote = open_by_name_or_url(target)?;
    let pins = remote
        .pins()?
        .ok_or_else(|| anyhow!("nobody pushed to {target} yet: push first"))?;
    let mut line = format!(
        "git-remote-enc join {} {} --repo {} --min-generation {}",
        sh_quote(target),
        sh_quote(remote.url()),
        pins.repo,
        pins.generation
    );
    for p in &pins.participants {
        line.push_str(&format!(" --participant {}", sh_quote(p)));
    }
    eprintln!(
        "enc: send them this, to run in their clone; it is not secret, but send it over a channel the host does not control:"
    );
    println!("{line}");
    Ok(())
}

/// Add or remove participants in the configuration, show the change and
/// push it.
fn edit_participants(target: &str, add: &[String], remove: &[String], yes: bool) -> Result<()> {
    use enccore::{git, setup};
    if git::config(&format!("remote.{target}.url"))?.is_none() {
        bail!("{target} is not a configured remote");
    }
    let key = format!("remote.{target}.enc-participants");
    let mut current = git::config_all(&key)?;
    if current.is_empty() {
        current = open_by_name_or_url(target)?.access()?.participants;
    }
    let list = setup::edit_list(&current, add, remove)?;
    let before = git::config_all(&key)?;
    setup::set_participants(target, &list)?;
    let mut remote = open_by_name_or_url(target)?;
    if !show_access(&mut io::stderr(), &remote.access()?)? {
        eprintln!("enc: {target} already has this participant list");
        return Ok(());
    }
    if !yes
        && !confirm(&format!(
            "push this participant list to {target} (+ added, - removed)?"
        ))?
    {
        // Restore what was configured before.
        let _ = git::run_status(["config", "--unset-all", &key])?;
        for v in &before {
            git::run(["config", "--add", &key, v])?;
        }
        bail!("not applied");
    }
    remote.apply_participants()?;
    eprintln!("enc: applied");
    Ok(())
}

/// One check of `doctor`.
fn report(ok: &mut bool, check: &str, result: Result<String, String>) {
    match result {
        Ok(detail) => println!("ok    {check}{detail}"),
        Err(problem) => {
            *ok = false;
            println!("FAIL  {check}: {problem}");
        }
    }
}

/// Everything a push or fetch could trip on. Changes nothing a fetch would
/// not: the guard is left alone.
fn doctor(target: &str) -> Result<()> {
    use enccore::guard::{HookState, hook_state};
    use enccore::{crypto::Participant, git, setup};
    let mut ok = true;
    let url = match git::config(&format!("remote.{target}.url"))? {
        Some(u) if u.starts_with("enc::") => u,
        Some(u) => bail!("{target} is not an encrypted remote ({u})"),
        None => bail!("{target} is not a configured remote"),
    };
    let reach = setup::probe(&url).map_err(|e| format!("{e:#}"));
    let exists = *reach.as_ref().unwrap_or(&false);
    report(
        &mut ok,
        "host",
        reach.map(|e| {
            if e {
                String::new()
            } else {
                " (empty: the first push creates the remote)".to_owned()
            }
        }),
    );

    let mut remote = Remote::open(Some(target), &url)?;
    remote.set_install_hook(false);
    let mut keys = Vec::new();
    if remote.identity_paths().is_empty() {
        report(
            &mut ok,
            "identity",
            Err(format!(
                "none; `git config remote.{target}.enc-identity <key file>`"
            )),
        );
    }
    for path in remote.identity_paths().to_vec() {
        use std::os::unix::fs::PermissionsExt;
        let check = format!("identity {}", path.display());
        let result = match std::fs::metadata(&path) {
            Err(e) => Err(format!("{e}")),
            Ok(m) if m.permissions().mode() & 0o077 != 0 => Err(format!(
                "readable by others; `chmod 600 {}`",
                path.display()
            )),
            Ok(_) => setup::public_key(&path)
                .map(|k| {
                    keys.push(k);
                    String::new()
                })
                .map_err(|e| format!("{e:#}")),
        };
        report(&mut ok, &check, result);
    }

    let (state, hook) = hook_state()?;
    report(
        &mut ok,
        "pre-push guard",
        match state {
            HookState::Guard => Ok(String::new()),
            HookState::NotExecutable => Err(format!("`chmod +x {}`", hook.display())),
            HookState::Other => Err(format!(
                "{} does not run it; `git-remote-enc install-hook --chain`",
                hook.display()
            )),
            HookState::Missing | HookState::MissingHooksPath => Err(format!(
                "{} does not exist; `git-remote-enc install-hook`",
                hook.display()
            )),
        },
    );
    report(
        &mut ok,
        "full history",
        if setup::is_shallow()? {
            Err(
                "the clone is shallow; `git fetch --unshallow <the remote it was cloned from>`"
                    .to_owned(),
            )
        } else {
            Ok(String::new())
        },
    );
    report(
        &mut ok,
        "Git LFS",
        match remote.lfs_refusal()? {
            Some(why) => Err(format!("a push is refused: {why} (README, Git LFS)")),
            None => Ok(String::new()),
        },
    );

    if exists {
        match remote.access() {
            Err(e) => report(&mut ok, "manifest", Err(format!("{e:#}"))),
            Ok(access) => {
                report(&mut ok, "manifest", Ok(String::new()));
                let listed = Participant::parse_all(&access.participants)?;
                let mine = keys.iter().any(|k| {
                    Participant::parse(k).is_ok_and(|k| listed.iter().any(|p| p.key() == k.key()))
                });
                report(
                    &mut ok,
                    "participant",
                    if mine {
                        Ok(String::new())
                    } else {
                        Err("none of your identities is listed, so you cannot push".to_owned())
                    },
                );
                let pending = [&access.participants_diff, &access.admins_diff]
                    .iter()
                    .any(|d| d.as_ref().is_some_and(|d| !d.is_empty()));
                report(
                    &mut ok,
                    "participant list",
                    if pending {
                        Err(format!(
                            "the configured list differs; `git-remote-enc participants {target}` shows how"
                        ))
                    } else {
                        Ok(String::new())
                    },
                );
            }
        }
    } else if let Err(e) = remote.pins() {
        // Local state left from a remote the host no longer has.
        report(&mut ok, "local state", Err(format!("{e:#}")));
    }
    if !ok {
        std::process::exit(1);
    }
    Ok(())
}

/// A configured remote name resolves to its URL and its config.
fn open_by_name_or_url(target: &str) -> Result<Remote> {
    let (name, url) = match enccore::git::config(&format!("remote.{target}.url"))? {
        Some(url) => (Some(target), url),
        None => (None, target.to_owned()),
    };
    Remote::open(name, &url)
}

fn helper(mut remote: Remote) -> Result<()> {
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    let mut out = io::stdout().lock();

    while let Some(line) = lines.next() {
        let line = line?;
        match line.as_str() {
            "capabilities" => {
                out.write_all(b"fetch\npush\n\n")?;
            }
            "list" | "list for-push" => {
                let (refs, head) = remote.list(line == "list for-push")?;
                for (oid, name) in refs {
                    writeln!(out, "{oid} {name}")?;
                }
                if let Some(h) = head {
                    writeln!(out, "@{h} HEAD")?;
                }
                out.write_all(b"\n")?;
            }
            l if l.starts_with("fetch ") => {
                // The batch's individual wants are irrelevant: every pack not
                // yet indexed is fetched.
                drain_batch(&mut lines)?;
                remote.fetch()?;
                out.write_all(b"\n")?;
            }
            l if l.starts_with("push ") => {
                let mut specs = vec![RefSpec::parse(l.trim_start_matches("push "))?];
                for l in drain_batch(&mut lines)? {
                    specs.push(RefSpec::parse(l.trim_start_matches("push "))?);
                }
                for status in remote.push(&specs)? {
                    match status {
                        PushStatus::Ok(dst) => writeln!(out, "ok {dst}")?,
                        PushStatus::Error(dst, msg) => writeln!(out, "error {dst} {msg}")?,
                    }
                }
                out.write_all(b"\n")?;
            }
            "" => {}
            other => bail!("unsupported command from git: `{other}`"),
        }
        out.flush()?;
    }
    Ok(())
}

/// Collect the rest of a `fetch`/`push` batch, up to the blank line.
fn drain_batch(lines: &mut impl Iterator<Item = io::Result<String>>) -> Result<Vec<String>> {
    let mut batch = Vec::new();
    for line in lines {
        let line = line?;
        if line.is_empty() {
            break;
        }
        batch.push(line);
    }
    Ok(batch)
}
