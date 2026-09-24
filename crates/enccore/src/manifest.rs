//! The manifest: the one piece of plaintext state describing an encrypted
//! remote. Grammar in DESIGN.md §4.2; the signed/encrypted envelope in §4.3.

use std::fmt;

use zeroize::{Zeroize, Zeroizing};

/// The version written. Version 1 (no `admin` item) is still read.
pub const FORMAT_VERSION: u32 = 2;
const OLDEST_VERSION: u32 = 1;
const HEADER: &str = "enc-manifest";
/// Stands in for a pack key in a displayed manifest.
pub const REDACTED_KEY: &str = "<redacted>";

/// A pack blob and the age identity that decrypts it.
#[derive(Clone, PartialEq, Eq)]
pub struct Pack {
    /// Hex SHA-256 of the ciphertext; the blob is stored as `<id>.age`.
    pub id: String,
    /// `AGE-SECRET-KEY-1…`
    pub key: String,
}

impl Pack {
    pub fn blob_name(&self) -> String {
        format!("{}.age", self.id)
    }
}

/// The key stays out of debug output, and so out of logs and panics.
impl fmt::Debug for Pack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pack")
            .field("id", &self.id)
            .field("key", &REDACTED_KEY)
            .finish()
    }
}

impl Drop for Pack {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Manifest {
    pub generation: u64,
    /// When the pusher wrote it, in Unix seconds by the pusher's clock. For
    /// the audit trail (`git-remote-enc log`); never used to decide trust.
    pub time: Option<u64>,
    /// Hex SHA-256 of the previous generation's manifest text: chains the
    /// history, so the accepted tip authenticates every manifest before it.
    /// New in version 2; absent on a remote's first manifest.
    pub previous: Option<String>,
    pub repo_id: String,
    pub head: Option<String>,
    /// Public keys as written by the user (`ssh-ed25519 AAAA… comment`,
    /// `age1…`). Parsed lazily by `crypto::Participant`.
    pub participants: Vec<String>,
    /// The participants who may change `participants` and `admins`. Empty in
    /// a remote created before version 2: any signer may then change them.
    pub admins: Vec<String>,
    /// `(oid, refname)` in manifest order.
    pub refs: Vec<(String, String)>,
    /// In append order; a pack may be thin relative to earlier ones.
    pub packs: Vec<Pack>,
    /// Unknown items, preserved verbatim for forward compatibility.
    pub extensions: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    NotAManifest,
    UnsupportedVersion(u32),
    Malformed(usize, String),
    Duplicate(usize, String),
    Missing(&'static str),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAManifest => write!(f, "not an enc manifest"),
            Self::UnsupportedVersion(v) => {
                write!(f, "manifest format {v} is not supported by this binary")
            }
            Self::Malformed(line, item) => write!(f, "malformed manifest line {line}: {item}"),
            Self::Duplicate(line, item) => write!(f, "manifest line {line} repeats `{item}`"),
            Self::Missing(what) => write!(f, "manifest lacks a `{what}` item"),
        }
    }
}

impl std::error::Error for ParseError {}

impl Manifest {
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        let mut lines = text.lines().enumerate();
        let (_, first) = lines.next().ok_or(ParseError::NotAManifest)?;
        let version = first
            .strip_prefix(HEADER)
            .and_then(|r| r.strip_prefix(' '))
            .and_then(|v| v.trim().parse::<u32>().ok())
            .ok_or(ParseError::NotAManifest)?;
        if !(OLDEST_VERSION..=FORMAT_VERSION).contains(&version) {
            return Err(ParseError::UnsupportedVersion(version));
        }

        let mut m = Manifest::default();
        let mut have_generation = false;
        let mut seen: Vec<&str> = Vec::new();
        for (idx, line) in lines {
            let lineno = idx.saturating_add(1);
            let line = line.trim_end();
            if line.is_empty() {
                continue;
            }
            let malformed = || ParseError::Malformed(lineno, line.to_owned());
            let (item, rest) = line.split_once(' ').unwrap_or((line, ""));
            // Items that say one thing about the remote say it once.
            if matches!(item, "generation" | "time" | "previous" | "repo" | "head") {
                if seen.contains(&item) {
                    return Err(ParseError::Duplicate(lineno, item.to_owned()));
                }
                seen.push(item);
            }
            match item {
                "generation" => {
                    m.generation = rest.trim().parse().map_err(|_| malformed())?;
                    have_generation = true;
                }
                "time" => m.time = Some(rest.trim().parse().map_err(|_| malformed())?),
                "previous" => {
                    let d = rest.trim();
                    if d.len() != 64 || !is_hex(d) {
                        return Err(malformed());
                    }
                    m.previous = Some(d.to_owned());
                }
                "repo" => m.repo_id = nonempty(rest).ok_or_else(malformed)?.to_owned(),
                "head" => {
                    let head = nonempty(rest).ok_or_else(malformed)?;
                    if !is_ref_name(head) {
                        return Err(malformed());
                    }
                    m.head = Some(head.to_owned());
                }
                "participant" => m
                    .participants
                    .push(nonempty(rest).ok_or_else(malformed)?.to_owned()),
                "admin" => m
                    .admins
                    .push(nonempty(rest).ok_or_else(malformed)?.to_owned()),
                "ref" => {
                    let (oid, name) = rest.split_once(' ').ok_or_else(malformed)?;
                    if !is_hex(oid) || !is_ref_name(name) {
                        return Err(malformed());
                    }
                    if m.ref_oid(name).is_some() {
                        return Err(ParseError::Duplicate(lineno, format!("ref {name}")));
                    }
                    m.refs.push((oid.to_owned(), name.to_owned()));
                }
                "pack" => {
                    let (id, key) = rest.split_once(' ').ok_or_else(malformed)?;
                    if id.len() != 64 || !is_hex(id) || key.is_empty() || key.contains(' ') {
                        return Err(malformed());
                    }
                    if m.packs.iter().any(|p| p.id == id) {
                        return Err(ParseError::Duplicate(lineno, format!("pack {id}")));
                    }
                    m.packs.push(Pack {
                        id: id.to_owned(),
                        key: key.to_owned(),
                    });
                }
                _ => m.extensions.push(line.to_owned()),
            }
        }
        if !have_generation {
            return Err(ParseError::Missing("generation"));
        }
        if m.repo_id.is_empty() {
            return Err(ParseError::Missing("repo"));
        }
        Ok(m)
    }

    /// The manifest text, pack keys included: wiped when dropped.
    pub fn serialize(&self) -> Zeroizing<String> {
        Zeroizing::new(self.render(true))
    }

    /// [`Manifest::serialize`] with every pack key replaced by
    /// [`REDACTED_KEY`], for display.
    pub fn serialize_redacted(&self) -> String {
        self.render(false)
    }

    fn render(&self, with_keys: bool) -> String {
        let mut out = format!(
            "{HEADER} {FORMAT_VERSION}\ngeneration {}\nrepo {}\n",
            self.generation, self.repo_id
        );
        if let Some(t) = self.time {
            out.push_str(&format!("time {t}\n"));
        }
        if let Some(p) = &self.previous {
            out.push_str(&format!("previous {p}\n"));
        }
        if let Some(h) = &self.head {
            out.push_str(&format!("head {h}\n"));
        }
        for p in &self.participants {
            out.push_str(&format!("participant {p}\n"));
        }
        for a in &self.admins {
            out.push_str(&format!("admin {a}\n"));
        }
        for (oid, name) in &self.refs {
            out.push_str(&format!("ref {oid} {name}\n"));
        }
        for p in &self.packs {
            let key = if with_keys { &p.key } else { REDACTED_KEY };
            out.push_str(&format!("pack {} {key}\n", p.id));
        }
        for e in &self.extensions {
            out.push_str(e);
            out.push('\n');
        }
        out
    }

    pub fn ref_oid(&self, name: &str) -> Option<&str> {
        self.refs
            .iter()
            .find(|(_, n)| n == name)
            .map(|(oid, _)| oid.as_str())
    }

    pub fn set_ref(&mut self, name: &str, oid: &str) {
        match self.refs.iter_mut().find(|(_, n)| n == name) {
            Some(entry) => entry.0 = oid.to_owned(),
            None => self.refs.push((oid.to_owned(), name.to_owned())),
        }
    }

    pub fn delete_ref(&mut self, name: &str) {
        self.refs.retain(|(_, n)| n != name);
        if self.head.as_deref() == Some(name) {
            self.head = None;
        }
    }
}

fn nonempty(s: &str) -> Option<&str> {
    let s = s.trim();
    if s.is_empty() { None } else { Some(s) }
}

/// A full ref name git would accept (`git check-ref-format`), as the
/// helper hands them back to git: `refs/…`, no empty or dot-led component,
/// no `..`, `@{`, `.lock` suffix, control or special characters.
fn is_ref_name(name: &str) -> bool {
    name.starts_with("refs/")
        && !name.contains("..")
        && !name.contains("@{")
        && !name.ends_with('/')
        && !name.ends_with('.')
        && name
            .split('/')
            .all(|c| !c.is_empty() && !c.starts_with('.') && !c.ends_with(".lock"))
        && !name
            .chars()
            .any(|c| c.is_control() || matches!(c, ' ' | '~' | '^' | ':' | '?' | '*' | '[' | '\\'))
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

// ---- envelope -------------------------------------------------------------

const SIG_BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";

/// Split a decrypted envelope into `(manifest text, signature PEM)`.
pub fn split_envelope(envelope: &[u8]) -> Option<(&str, &str)> {
    let text = std::str::from_utf8(envelope).ok()?;
    let at = text.find(SIG_BEGIN)?;
    let (body, sig) = text.split_at(at);
    Some((body, sig))
}

pub fn join_envelope(manifest: &str, signature_pem: &str) -> Zeroizing<Vec<u8>> {
    let mut v = Zeroizing::new(Vec::with_capacity(
        manifest
            .len()
            .saturating_add(signature_pem.len())
            .saturating_add(1),
    ));
    v.extend_from_slice(manifest.as_bytes());
    if !manifest.ends_with('\n') {
        v.push(b'\n');
    }
    v.extend_from_slice(signature_pem.as_bytes());
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "enc-manifest 2\ngeneration 3\nrepo abcdef0123\ntime 1790000000\nprevious 1111111111111111111111111111111111111111111111111111111111111111\nhead refs/heads/main\nparticipant ssh-ed25519 AAAAC3 alice\nparticipant age1qqq\nadmin ssh-ed25519 AAAAC3 alice\nref 0123456789abcdef0123456789abcdef01234567 refs/heads/main\npack 0000000000000000000000000000000000000000000000000000000000000000 AGE-SECRET-KEY-1X\nextn future stuff\n";

    #[test]
    fn roundtrip() {
        let m = Manifest::parse(SAMPLE).unwrap();
        assert_eq!(m.generation, 3);
        assert_eq!(m.repo_id, "abcdef0123");
        assert_eq!(m.time, Some(1_790_000_000));
        assert_eq!(m.previous.as_deref(), Some(&*"1".repeat(64)));
        assert_eq!(m.head.as_deref(), Some("refs/heads/main"));
        assert_eq!(m.participants.len(), 2);
        assert_eq!(m.participants[0], "ssh-ed25519 AAAAC3 alice");
        assert_eq!(m.admins, vec!["ssh-ed25519 AAAAC3 alice"]);
        assert_eq!(m.refs.len(), 1);
        assert_eq!(m.packs.len(), 1);
        assert_eq!(m.extensions, vec!["extn future stuff"]);
        assert_eq!(*m.serialize(), SAMPLE);
        let shown = m.serialize_redacted();
        assert!(!shown.contains("AGE-SECRET-KEY"), "{shown}");
        assert_eq!(shown, SAMPLE.replace("AGE-SECRET-KEY-1X", REDACTED_KEY));
        let debug = format!("{m:?}");
        assert!(!debug.contains("AGE-SECRET-KEY"), "{debug}");
    }

    #[test]
    fn rejects_garbage_and_future_versions() {
        assert_eq!(Manifest::parse("hello"), Err(ParseError::NotAManifest));
        assert_eq!(
            Manifest::parse("enc-manifest 3\ngeneration 1\nrepo x\n"),
            Err(ParseError::UnsupportedVersion(3))
        );
        assert_eq!(
            Manifest::parse("enc-manifest 0\ngeneration 1\nrepo x\n"),
            Err(ParseError::UnsupportedVersion(0))
        );
        // Version 1 is read, and written back as the current version.
        let v1 = Manifest::parse("enc-manifest 1\ngeneration 1\nrepo x\n").unwrap();
        assert!(v1.admins.is_empty());
        assert!(v1.serialize().starts_with("enc-manifest 2\n"));
        assert_eq!(
            Manifest::parse("enc-manifest 1\nrepo x\n"),
            Err(ParseError::Missing("generation"))
        );
        assert!(matches!(
            Manifest::parse("enc-manifest 1\ngeneration 1\nrepo x\nref nothex refs/heads/x\n"),
            Err(ParseError::Malformed(4, _))
        ));
        // Said twice, or a ref name git would refuse.
        let oid = "0123456789abcdef0123456789abcdef01234567";
        for (text, want) in [
            ("generation 1\ngeneration 2\nrepo x\n", "generation"),
            ("generation 1\nrepo x\nrepo y\n", "repo"),
            (
                &*format!("generation 1\nrepo x\nref {oid} refs/heads/a\nref {oid} refs/heads/a\n"),
                "ref refs/heads/a",
            ),
        ] {
            assert!(
                matches!(
                    Manifest::parse(&format!("enc-manifest 2\n{text}")),
                    Err(ParseError::Duplicate(_, ref item)) if item == want
                ),
                "{text}"
            );
        }
        for name in [
            "main",
            "refs/heads/a..b",
            "refs/heads/.hidden",
            "refs/heads/x.lock",
            "refs/heads/a@{1}",
            "refs/heads/a:b",
            "refs//x",
            "refs/heads/x/",
        ] {
            let text = format!("enc-manifest 2\ngeneration 1\nrepo x\nref {oid} {name}\n");
            assert!(
                matches!(Manifest::parse(&text), Err(ParseError::Malformed(4, _))),
                "{name}"
            );
            let text = format!("enc-manifest 2\ngeneration 1\nrepo x\nhead {name}\n");
            assert!(Manifest::parse(&text).is_err(), "head {name}");
        }
    }

    #[test]
    fn ref_updates() {
        let mut m = Manifest::parse(SAMPLE).unwrap();
        m.set_ref("refs/heads/main", "ffff");
        m.set_ref("refs/heads/dev", "eeee");
        assert_eq!(m.ref_oid("refs/heads/main"), Some("ffff"));
        assert_eq!(m.refs.len(), 2);
        m.delete_ref("refs/heads/main");
        assert_eq!(m.ref_oid("refs/heads/main"), None);
        assert_eq!(m.head, None);
    }

    #[test]
    fn parser_survives_corrupted_input() {
        for input in crate::mutate::variants(SAMPLE.as_bytes(), 20_000) {
            let Ok(text) = std::str::from_utf8(&input) else {
                assert!(split_envelope(&input).is_none());
                continue;
            };
            // Whatever parses must serialize to something that parses back
            // to the same manifest.
            if let Ok(m) = Manifest::parse(text) {
                assert_eq!(Manifest::parse(&m.serialize()), Ok(m.clone()), "{text:?}");
                let _ = m.serialize_redacted();
            }
            let _ = split_envelope(&input);
        }
    }

    #[test]
    fn envelope() {
        let env = join_envelope(
            "enc-manifest 1\n",
            "-----BEGIN SSH SIGNATURE-----\nxx\n-----END SSH SIGNATURE-----\n",
        );
        let (body, sig) = split_envelope(&env).unwrap();
        assert_eq!(body, "enc-manifest 1\n");
        assert!(sig.starts_with(SIG_BEGIN));
        assert!(split_envelope(b"no signature here").is_none());
    }
}
