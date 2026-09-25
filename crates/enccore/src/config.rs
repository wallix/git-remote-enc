//! The git-config surface. DESIGN.md §8.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::git;

#[derive(Debug, Default)]
pub struct Config {
    pub identity_paths: Vec<PathBuf>,
    pub signing_key: Option<PathBuf>,
    /// `None` when unset. Creates a remote, pins its signer on first
    /// contact, and replaces its list on `participants --apply`.
    pub participants: Option<Vec<String>>,
    /// `None` when unset; like `participants`, for the admin list. Defaults
    /// to the creator when a remote is created.
    pub admins: Option<Vec<String>>,
    /// Accept whoever signed the manifest on first contact when no
    /// participant list is configured. Off unless set.
    pub trust_on_first_use: bool,
    /// The repository id the remote must serve, learned out of band.
    pub repo: Option<String>,
    /// The lowest manifest generation to accept, learned out of band: bounds
    /// a rollback on first contact, before there is local state to do it.
    pub min_generation: Option<u64>,
    /// Install the pre-push guard where no pre-push hook exists, and report
    /// one that does not run it, on every contact.
    pub install_hook: bool,
    /// Push even though Git LFS would upload files in clear alongside.
    pub allow_lfs: bool,
    /// Refuse a manifest that forks from the accepted one, rather than
    /// warn and accept it. On unless set to false.
    pub refuse_forks: bool,
    /// `index-pack` fsck option for received packs (`--fsck-objects[=…]`),
    /// `None` when disabled.
    pub fsck: Option<String>,
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

        let install_hook = match one("installHook")? {
            Some(v) => parse_bool(&v)
                .with_context(|| format!("enc installHook: `{v}` is not a boolean"))?,
            None => true,
        };
        let allow_lfs = match one("allowLfs")? {
            Some(v) => {
                parse_bool(&v).with_context(|| format!("enc allowLfs: `{v}` is not a boolean"))?
            }
            None => false,
        };
        let refuse_forks = match one("refuseForks")? {
            Some(v) => parse_bool(&v)
                .with_context(|| format!("enc refuseForks: `{v}` is not a boolean"))?,
            None => true,
        };
        let repo = one("repo")?.map(|r| r.trim().to_owned());
        let min_generation = one("minGeneration")?
            .map(|v| {
                v.trim()
                    .parse()
                    .with_context(|| format!("enc minGeneration: `{v}` is not a number"))
            })
            .transpose()?;
        let fsck = fsck_option()?;
        let participants = key_list(all("participants")?)?;
        let admins = key_list(all("admins")?)?;

        Ok(Self {
            identity_paths,
            signing_key,
            participants,
            admins,
            trust_on_first_use,
            repo,
            min_generation,
            install_hook,
            allow_lfs,
            refuse_forks,
            fsck,
        })
    }
}

/// Packs from an encrypted remote bypass the checks git applies on fetch,
/// so the helper runs them itself: on unless `fetch.fsckObjects` (else
/// `transfer.fsckObjects`) is explicitly false, with git's `fetch.fsck.*`
/// severities and skip list.
fn fsck_option() -> Result<Option<String>> {
    for key in ["fetch.fsckObjects", "transfer.fsckObjects"] {
        if let Some(v) = git::config(key)? {
            if !parse_bool(&v).with_context(|| format!("{key}: `{v}` is not a boolean"))? {
                return Ok(None);
            }
            break;
        }
    }
    let mut msgs = Vec::new();
    for (key, value) in git::config_regexp(r"^fetch\.fsck\.")? {
        let id = key.strip_prefix("fetch.fsck.").unwrap_or(&key);
        if id.contains([',', '=']) || value.contains(',') {
            bail!("{key}: `{value}` cannot be passed on to git index-pack");
        }
        msgs.push(format!("{id}={value}"));
    }
    Ok(Some(if msgs.is_empty() {
        "--fsck-objects".to_owned()
    } else {
        format!("--fsck-objects={}", msgs.join(","))
    }))
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

/// Public keys, one per value or `@<file>` (authorized_keys-style: one per
/// line, `#` comments); `None` when there are no values.
fn key_list(raw: Vec<String>) -> Result<Option<Vec<String>>> {
    if raw.is_empty() {
        return Ok(None);
    }
    let mut list = Vec::new();
    for item in raw {
        if let Some(file) = item.strip_prefix('@') {
            let path = expand_home(file);
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("reading key list {}", path.display()))?;
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
    Ok(Some(list))
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
