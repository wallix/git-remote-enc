//! The git-config surface. DESIGN.md §8.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::git;

#[derive(Debug, Default)]
pub struct Config {
    pub identity_paths: Vec<PathBuf>,
    pub signing_key: Option<PathBuf>,
    /// `None` when unset; `Some` replaces the manifest's list on push.
    pub participants: Option<Vec<String>>,
    /// Accept whoever signed the manifest on first contact when no
    /// participant list is configured. Off unless set.
    pub trust_on_first_use: bool,
}

impl Config {
    pub fn load(remote_name: Option<&str>) -> Result<Self> {
        let all = |key: &str| -> Result<Vec<String>> {
            if let Some(name) = remote_name {
                let v = git::config_all(&format!("remote.{name}.enc-{key}"))?;
                if !v.is_empty() {
                    return Ok(v);
                }
            }
            git::config_all(&format!("enc.{key}"))
        };
        let one = |key: &str| -> Result<Option<String>> { Ok(all(key)?.into_iter().last()) };

        let mut identity_paths: Vec<PathBuf> =
            all("identity")?.iter().map(|s| expand_home(s)).collect();
        if identity_paths.is_empty() {
            identity_paths = default_identities()?;
        }
        let signing_key = one("signingkey")?.map(|s| expand_home(&s));
        let trust_on_first_use = match one("trustOnFirstUse")? {
            Some(v) => parse_bool(&v)
                .with_context(|| format!("enc trustOnFirstUse: `{v}` is not a boolean"))?,
            None => false,
        };

        let raw = all("participants")?;
        let participants = if raw.is_empty() {
            None
        } else {
            let mut list = Vec::new();
            for item in raw {
                if let Some(file) = item.strip_prefix('@') {
                    let path = expand_home(file);
                    let text = std::fs::read_to_string(&path)
                        .with_context(|| format!("reading participants file {}", path.display()))?;
                    list.extend(
                        text.lines()
                            .map(str::trim)
                            .filter(|l| !l.is_empty() && !l.starts_with('#'))
                            .map(str::to_owned),
                    );
                } else {
                    list.push(item.trim().to_owned());
                }
            }
            Some(list)
        };

        Ok(Self {
            identity_paths,
            signing_key,
            participants,
            trust_on_first_use,
        })
    }
}

/// `user.signingkey` when git itself signs with SSH, else `~/.ssh/id_ed25519`.
fn default_identities() -> Result<Vec<PathBuf>> {
    if git::config("gpg.format")?.as_deref() == Some("ssh")
        && let Some(key) = git::config("user.signingkey")?
        && !key.starts_with("key::")
    {
        let p = expand_home(&key);
        if p.is_file() {
            return Ok(vec![p]);
        }
    }
    let p = expand_home("~/.ssh/id_ed25519");
    if p.is_file() {
        return Ok(vec![p]);
    }
    Ok(vec![])
}

/// git's boolean spellings.
fn parse_bool(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Some(true),
        "false" | "no" | "off" | "0" | "" => Some(false),
        _ => None,
    }
}

fn expand_home(s: &str) -> PathBuf {
    if let Some(rest) = s.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return Path::new(&home).join(rest);
    }
    PathBuf::from(s)
}
