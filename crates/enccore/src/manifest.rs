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
#[derive(Clone, Debug, PartialEq, Eq)]
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
        for (idx, line) in lines {
            let lineno = idx.saturating_add(1);
            let line = line.trim_end();
            if line.is_empty() {
                continue;
            }
            let malformed = || ParseError::Malformed(lineno, line.to_owned());
            let (item, rest) = line.split_once(' ').unwrap_or((line, ""));
            match item {
                "generation" => {
                    m.generation = rest.trim().parse().map_err(|_| malformed())?;
                    have_generation = true;
                }
                "time" => m.time = Some(rest.trim().parse().map_err(|_| malformed())?),
                "repo" => m.repo_id = nonempty(rest).ok_or_else(malformed)?.to_owned(),
                "head" => m.head = Some(nonempty(rest).ok_or_else(malformed)?.to_owned()),
                "participant" => m
                    .participants
                    .push(nonempty(rest).ok_or_else(malformed)?.to_owned()),
                "admin" => m
                    .admins
                    .push(nonempty(rest).ok_or_else(malformed)?.to_owned()),
                "ref" => {
                    let (oid, name) = rest.split_once(' ').ok_or_else(malformed)?;
                    if !is_hex(oid) || name.is_empty() || name.contains(' ') {
                        return Err(malformed());
                    }
                    m.refs.push((oid.to_owned(), name.to_owned()));
                }
                "pack" => {
                    let (id, key) = rest.split_once(' ').ok_or_else(malformed)?;
                    if id.len() != 64 || !is_hex(id) || key.is_empty() || key.contains(' ') {
                        return Err(malformed());
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

    const SAMPLE: &str = "enc-manifest 2\ngeneration 3\nrepo abcdef0123\ntime 1790000000\nhead refs/heads/main\nparticipant ssh-ed25519 AAAAC3 alice\nparticipant age1qqq\nadmin ssh-ed25519 AAAAC3 alice\nref 0123456789abcdef0123456789abcdef01234567 refs/heads/main\npack 0000000000000000000000000000000000000000000000000000000000000000 AGE-SECRET-KEY-1X\nextn future stuff\n";

    #[test]
    fn roundtrip() {
        let m = Manifest::parse(SAMPLE).unwrap();
        assert_eq!(m.generation, 3);
        assert_eq!(m.repo_id, "abcdef0123");
        assert_eq!(m.time, Some(1_790_000_000));
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
