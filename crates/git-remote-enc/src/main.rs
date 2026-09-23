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

use anyhow::{Result, bail};
use enccore::remote::{PushStatus, RefSpec, Remote};

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
                Some(text) => print!("{text}"),
                None => bail!("no encrypted remote at {}", remote.url()),
            }
            Ok(())
        }
        [name, url] => helper(Remote::open(Some(name), url)?),
        [url] => helper(Remote::open(None, url)?),
        _ => usage(),
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: git-remote-enc <remote> <url>   (invoked by git for enc:: URLs)\n       git-remote-enc manifest [--show-keys] <remote|url>\n       git-remote-enc --version"
    );
    std::process::exit(2);
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
