//! Shared by `init`, `join`, `invite` and `doctor`: identity files, the backend
//! URL check, and the configured participant list. DESIGN.md §8.1.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result, anyhow, bail};
use ssh_key::PrivateKey;

use crate::backend::DEFAULT_BRANCH;
use crate::crypto::Participant;
use crate::git;

/// `~/.ssh/enc_<remote>`: a key for this remote only, as README advises.
pub fn default_identity(remote: &str) -> Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set"))?;
    Ok(Path::new(&home).join(".ssh").join(format!("enc_{remote}")))
}

/// Create an ed25519 key at `path` with `ssh-keygen`, which asks for its
/// passphrase on the terminal. Returns false when the file already exists.
pub fn ensure_identity(path: &Path) -> Result<bool> {
    if path.exists() {
        return Ok(false);
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let comment = format!("{} git-remote-enc", whoami());
    let status = std::process::Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-C", &comment, "-f"])
        .arg(path)
        .status()
        .context("running ssh-keygen to create the identity")?;
    if !status.success() {
        bail!("ssh-keygen failed to create {}", path.display());
    }
    Ok(true)
}

fn whoami() -> String {
    let user = std::env::var("USER").unwrap_or_else(|_| "user".to_owned());
    match std::fs::read_to_string("/etc/hostname") {
        Ok(h) if !h.trim().is_empty() => format!("{user}@{}", h.trim()),
        _ => user,
    }
}

/// The participant line for an identity file: its OpenSSH public key with
/// the comment (readable without the passphrase), or the age recipient.
pub fn public_key(path: &Path) -> Result<String> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading identity {}", path.display()))?;
    if text.contains("BEGIN OPENSSH PRIVATE KEY") {
        let key = PrivateKey::from_openssh(&text)
            .with_context(|| format!("parsing SSH key {}", path.display()))?;
        return key
            .public_key()
            .to_openssh()
            .context("encoding the public key");
    }
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .ok_or_else(|| anyhow!("{}: no identity found", path.display()))?;
    let id = age::x25519::Identity::from_str(line)
        .map_err(|e| anyhow!("{}: not an SSH or age identity: {e}", path.display()))?;
    Ok(id.to_public().to_string())
}

/// `<url>[#<branch>]` without `enc::`: the git URL and the full ref name of
/// the backend branch.
pub fn split_url(url: &str) -> Result<(String, String)> {
    let url = url.strip_prefix("enc::").unwrap_or(url);
    let (url, fragment) = match url.rsplit_once('#') {
        Some((u, f)) if !f.is_empty() => (u, Some(f)),
        _ => (url, None),
    };
    // git would parse a leading dash as an option (`--upload-pack=…`)
    // wherever the URL is not behind `--`.
    if url.is_empty() || url.starts_with('-') {
        bail!("refusing the backend URL `{url}`: it is empty or starts with `-`");
    }
    let branch = fragment.unwrap_or(DEFAULT_BRANCH);
    let branch = if branch.starts_with("refs/") {
        branch.to_owned()
    } else {
        format!("refs/heads/{branch}")
    };
    Ok((url.to_owned(), branch))
}

/// Check host reachability and backend branch presence. On failure, return an
/// error with git's message.
pub fn probe(url: &str) -> Result<bool> {
    let (url, branch) = split_url(url)?;
    let (ok, out, err) = git::run_status(["ls-remote", "--", &url, &branch])?;
    if !ok {
        let hint = scp_without_user(&url)
            .map(|h| format!(" ({h})"))
            .unwrap_or_default();
        bail!("cannot reach {url}{hint}: {}", err.trim());
    }
    Ok(!out.is_empty())
}

/// An scp-like URL with no user logs in as the local user, which forges
/// reject after trying every key the agent offers.
pub fn scp_without_user(url: &str) -> Option<String> {
    if url.contains("://") {
        return None;
    }
    let (host, path) = url.split_once(':')?;
    if host.is_empty() || host.contains(['/', '@']) {
        return None;
    }
    Some(format!(
        "no user in the URL, so ssh logs in as yours; forges expect git@{host}:{path}"
    ))
}

/// Replace `remote.<name>.enc-participants` with `list` after checking every
/// key. Lists read from an `@<file>` must be edited in that file.
pub fn set_participants(remote: &str, list: &[String]) -> Result<()> {
    let key = format!("remote.{remote}.enc-participants");
    if git::config_all(&key)?.iter().any(|v| v.starts_with('@')) {
        bail!("{key} reads a key file (`@…`): edit that file instead");
    }
    Participant::parse_all(list)?;
    let _ = git::run_status(["config", "--unset-all", &key])?;
    for p in list {
        git::run(["config", "--add", &key, p])?;
    }
    Ok(())
}

/// `list` with `add` appended and `remove` (keys or `SHA256:` fingerprints)
/// dropped; the comment is not part of a key.
pub fn edit_list(list: &[String], add: &[String], remove: &[String]) -> Result<Vec<String>> {
    let parsed = Participant::parse_all(list)?;
    let names = |r: &str, p: &Participant| {
        r == p.fingerprint() || Participant::parse(r).is_ok_and(|r| r.key() == p.key())
    };
    if let Some(r) = remove.iter().find(|r| !parsed.iter().any(|p| names(r, p))) {
        bail!("{r} is not a participant");
    }
    let mut out: Vec<String> = list
        .iter()
        .zip(&parsed)
        .filter(|(_, p)| !remove.iter().any(|r| names(r, p)))
        .map(|(text, _)| text.clone())
        .collect();
    for a in add {
        let new = Participant::parse(a)?;
        if !Participant::parse_all(&out)?
            .iter()
            .any(|p| p.key() == new.key())
        {
            out.push(a.trim().to_owned());
        }
    }
    Ok(out)
}

pub fn is_shallow() -> Result<bool> {
    Ok(git::run_line(["rev-parse", "--is-shallow-repository"])? == "true")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scp_urls_without_a_user_are_spotted() {
        assert!(scp_without_user("gitlab.example.com:team/vault.git").is_some());
        assert!(scp_without_user("git@gitlab.example.com:team/vault.git").is_none());
        assert!(scp_without_user("ssh://gitlab.example.com/team/vault.git").is_none());
        assert!(scp_without_user("/srv/vault.git").is_none());
        assert!(scp_without_user("./a:b").is_none());
    }

    #[test]
    fn urls_split_into_url_and_branch() {
        let (u, b) = split_url("enc::git@h:r.git#vault").unwrap();
        assert_eq!(
            (u.as_str(), b.as_str()),
            ("git@h:r.git", "refs/heads/vault")
        );
        let (_, b) = split_url("git@h:r.git").unwrap();
        assert_eq!(b, "refs/heads/enc");
        assert!(split_url("enc::--upload-pack=x").is_err());
    }
}
