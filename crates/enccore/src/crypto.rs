//! Identities (what we hold), participants (who may read and sign), age
//! encryption streams and SSH signatures. DESIGN.md §4.3, §4.4, §6.

use std::cell::RefCell;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::str::FromStr;

use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha256};
use ssh_key::{HashAlg, LineEnding, PrivateKey, PublicKey, SshSig};

/// SSH signature namespace; distinct from git's own `git` namespace so a
/// manifest signature can never be replayed as a commit signature.
pub const SIG_NAMESPACE: &str = "git-remote-enc";

/// Environment variable read instead of prompting for a key passphrase.
pub const PASSPHRASE_ENV: &str = "GIT_ENC_PASSPHRASE";

// ---- identities -----------------------------------------------------------

/// A private key we can decrypt with (and, for SSH keys, sign with).
// A process holds a handful of these; boxing the SSH variant buys nothing.
#[allow(clippy::large_enum_variant)]
pub enum Identity {
    Ssh {
        path: PathBuf,
        key: PrivateKey,
        age: age::ssh::Identity,
    },
    Age {
        path: PathBuf,
        key: age::x25519::Identity,
    },
}

impl Identity {
    pub fn path(&self) -> &Path {
        match self {
            Identity::Ssh { path, .. } | Identity::Age { path, .. } => path,
        }
    }

    fn as_age(&self) -> &dyn age::Identity {
        match self {
            Identity::Ssh { age, .. } => age,
            Identity::Age { key, .. } => key,
        }
    }

    pub fn ssh_key(&self) -> Option<&PrivateKey> {
        match self {
            Identity::Ssh { key, .. } => Some(key),
            Identity::Age { .. } => None,
        }
    }
}

/// Load every identity in `paths`. Each file is either an OpenSSH private
/// key (`ssh-ed25519` or `ssh-rsa`; passphrase-protected keys are decrypted
/// with `GIT_ENC_PASSPHRASE` or a tty prompt) or an age identity file.
pub fn load_identities(paths: &[PathBuf]) -> Result<Vec<Identity>> {
    let mut out = Vec::new();
    for path in paths {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading identity {}", path.display()))?;
        if text.contains("BEGIN OPENSSH PRIVATE KEY") {
            out.push(load_ssh_identity(path, &text)?);
        } else {
            out.extend(load_age_identities(path, &text)?);
        }
    }
    Ok(out)
}

fn load_ssh_identity(path: &Path, pem: &str) -> Result<Identity> {
    let mut key = PrivateKey::from_openssh(pem)
        .with_context(|| format!("parsing SSH key {}", path.display()))?;
    if key.is_encrypted() {
        let passphrase = match std::env::var(PASSPHRASE_ENV) {
            Ok(p) => p,
            Err(_) => {
                rpassword::prompt_password(format!("enc: passphrase for {}: ", path.display()))
                    .context("reading passphrase from the terminal")?
            }
        };
        key = key
            .decrypt(passphrase.as_bytes())
            .with_context(|| format!("decrypting SSH key {}", path.display()))?;
    }
    match key.algorithm() {
        ssh_key::Algorithm::Ed25519 | ssh_key::Algorithm::Rsa { .. } => {}
        other => bail!(
            "{}: {other} keys cannot be used for encryption; use an ssh-ed25519 or ssh-rsa key",
            path.display()
        ),
    }
    // age parses the key itself; hand it the decrypted key re-serialised.
    let plain = key
        .to_openssh(LineEnding::LF)
        .context("re-encoding SSH key")?;
    let age = age::ssh::Identity::from_buffer(
        BufReader::new(plain.as_bytes()),
        Some(path.display().to_string()),
    )
    .with_context(|| format!("age does not accept SSH key {}", path.display()))?;
    if let age::ssh::Identity::Unsupported(_) = age {
        bail!("{}: unsupported SSH key type for age", path.display());
    }
    Ok(Identity::Ssh {
        path: path.to_owned(),
        key,
        age,
    })
}

fn load_age_identities(path: &Path, text: &str) -> Result<Vec<Identity>> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let key = age::x25519::Identity::from_str(line)
            .map_err(|e| anyhow!("{}: not an age identity: {e}", path.display()))?;
        out.push(Identity::Age {
            path: path.to_owned(),
            key,
        });
    }
    if out.is_empty() {
        bail!("{}: no identity found", path.display());
    }
    Ok(out)
}

// ---- participants ---------------------------------------------------------

/// A public key from the manifest's participant list.
#[allow(clippy::large_enum_variant)]
pub enum Participant {
    /// May read and, since it can sign, push.
    Ssh {
        text: String,
        public: PublicKey,
        recipient: age::ssh::Recipient,
    },
    /// Read-only.
    Age {
        text: String,
        recipient: age::x25519::Recipient,
    },
}

impl Participant {
    pub fn parse(text: &str) -> Result<Self> {
        let text = text.trim();
        if text.starts_with("age1") {
            let recipient = age::x25519::Recipient::from_str(text)
                .map_err(|e| anyhow!("invalid age recipient `{text}`: {e}"))?;
            return Ok(Participant::Age {
                text: text.to_owned(),
                recipient,
            });
        }
        let public = PublicKey::from_openssh(text)
            .with_context(|| format!("invalid participant key `{text}`"))?;
        // age's parser wants exactly `<type> <base64>`; drop any comment.
        let bare = text
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        let recipient = age::ssh::Recipient::from_str(&bare).map_err(|e| {
            anyhow!("participant `{text}` cannot be an age recipient: {e:?} (only ssh-ed25519 and ssh-rsa are supported)")
        })?;
        Ok(Participant::Ssh {
            text: text.to_owned(),
            public,
            recipient,
        })
    }

    pub fn parse_all(texts: &[String]) -> Result<Vec<Self>> {
        texts.iter().map(|t| Self::parse(t)).collect()
    }

    pub fn text(&self) -> &str {
        match self {
            Participant::Ssh { text, .. } | Participant::Age { text, .. } => text,
        }
    }

    fn recipient(&self) -> &dyn age::Recipient {
        match self {
            Participant::Ssh { recipient, .. } => recipient,
            Participant::Age { recipient, .. } => recipient,
        }
    }

    pub fn can_sign(&self) -> bool {
        matches!(self, Participant::Ssh { .. })
    }

    /// `SHA256:…` fingerprint for SSH keys, the recipient string otherwise.
    pub fn fingerprint(&self) -> String {
        match self {
            Participant::Ssh { public, .. } => public.fingerprint(HashAlg::Sha256).to_string(),
            Participant::Age { text, .. } => text.clone(),
        }
    }

    /// Does this participant hold `key`?
    pub fn matches(&self, key: &PrivateKey) -> bool {
        match self {
            Participant::Ssh { public, .. } => public.key_data() == key.public_key().key_data(),
            Participant::Age { .. } => false,
        }
    }
}

// ---- age streams ----------------------------------------------------------

/// Encrypt `input` to `participants`, writing the age file to `output`.
pub fn encrypt_to_participants<W: Write>(
    participants: &[Participant],
    input: &[u8],
    output: W,
) -> Result<W> {
    let encryptor = age::Encryptor::with_recipients(participants.iter().map(|p| p.recipient()))
        .map_err(|e| anyhow!("age: {e}"))?;
    let mut w = encryptor.wrap_output(output)?;
    w.write_all(input)?;
    Ok(w.finish()?)
}

/// An age writer encrypting to a single recipient; used for packs.
pub fn encrypt_stream<W: Write>(
    recipient: &age::x25519::Recipient,
    output: W,
) -> Result<age::stream::StreamWriter<W>> {
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(recipient as &dyn age::Recipient))
            .map_err(|e| anyhow!("age: {e}"))?;
    Ok(encryptor.wrap_output(output)?)
}

/// Decrypt an age file with any of `identities`.
pub fn decrypt_with_identities<R: BufRead>(
    identities: &[Identity],
    input: R,
) -> Result<age::stream::StreamReader<R>> {
    let decryptor = age::Decryptor::new_buffered(input).map_err(|e| anyhow!("age: {e}"))?;
    decryptor
        .decrypt(identities.iter().map(|i| i.as_age()))
        .map_err(|e| match e {
            age::DecryptError::NoMatchingKeys => anyhow!(
                "none of your identities can decrypt this remote (tried: {}); you are not a participant",
                identities
                    .iter()
                    .map(|i| i.path().display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            other => anyhow!("age: {other}"),
        })
}

/// Decrypt an age file with one pack key.
pub fn decrypt_stream<R: BufRead>(
    key: &age::x25519::Identity,
    input: R,
) -> Result<age::stream::StreamReader<R>> {
    let decryptor = age::Decryptor::new_buffered(input).map_err(|e| anyhow!("age: {e}"))?;
    decryptor
        .decrypt(std::iter::once(key as &dyn age::Identity))
        .map_err(|e| anyhow!("pack does not decrypt with its manifest key: {e}"))
}

pub fn decrypt_to_vec(identities: &[Identity], input: &[u8]) -> Result<Vec<u8>> {
    let mut r = decrypt_with_identities(identities, input)?;
    let mut out = Vec::new();
    r.read_to_end(&mut out)?;
    Ok(out)
}

// ---- signatures -----------------------------------------------------------

pub fn sign(key: &PrivateKey, data: &[u8]) -> Result<String> {
    let sig = key
        .sign(SIG_NAMESPACE, HashAlg::Sha512, data)
        .context("signing manifest")?;
    sig.to_pem(LineEnding::LF).context("encoding signature")
}

/// Return the index of the participant whose key produced `sig_pem` over
/// `data`, if any.
pub fn verify(participants: &[Participant], data: &[u8], sig_pem: &str) -> Result<Option<usize>> {
    let sig = SshSig::from_pem(sig_pem).context("parsing manifest signature")?;
    if sig.namespace() != SIG_NAMESPACE {
        bail!("manifest signature has namespace `{}`", sig.namespace());
    }
    for (i, p) in participants.iter().enumerate() {
        if let Participant::Ssh { public, .. } = p
            && public.key_data() == sig.public_key()
            && public.verify(SIG_NAMESPACE, data, &sig).is_ok()
        {
            return Ok(Some(i));
        }
    }
    Ok(None)
}

// ---- hashing adapters -----------------------------------------------------

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// 16 random bytes as hex, for the repo id.
pub fn random_id() -> Result<String> {
    let mut buf = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .context("reading /dev/urandom")?;
    Ok(hex(&buf))
}

/// A `Write` that hashes everything passing through.
pub struct HashWriter<W: Write> {
    inner: W,
    hasher: Sha256,
}

impl<W: Write> HashWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
        }
    }

    pub fn finish(self) -> (W, String) {
        let digest = self.hasher.finalize();
        (self.inner, hex(&digest))
    }
}

impl<W: Write> Write for HashWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(buf.get(..n).unwrap_or(buf));
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// A `Read` that hashes everything passing through. The digest is shared so
/// it can be read after the reader has been moved into a decryptor.
pub struct HashReader<R: Read> {
    inner: R,
    hasher: Rc<RefCell<Sha256>>,
}

impl<R: Read> HashReader<R> {
    pub fn new(inner: R) -> (Self, Rc<RefCell<Sha256>>) {
        let hasher = Rc::new(RefCell::new(Sha256::new()));
        (
            Self {
                inner,
                hasher: Rc::clone(&hasher),
            },
            hasher,
        )
    }
}

impl<R: Read> Read for HashReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if let Some(chunk) = buf.get(..n) {
            self.hasher.borrow_mut().update(chunk);
        }
        Ok(n)
    }
}

pub fn finalize_shared(hasher: &Rc<RefCell<Sha256>>) -> String {
    let h = std::mem::take(&mut *hasher.borrow_mut());
    hex(&h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (PrivateKey, Participant) {
        let key = PrivateKey::random(&mut ssh_key::rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
        let text = key.public_key().to_openssh().unwrap();
        (key, Participant::parse(&text).unwrap())
    }

    #[test]
    fn sign_verify_roundtrip() {
        let (k1, p1) = keypair();
        let (_k2, p2) = keypair();
        let sig = sign(&k1, b"hello").unwrap();
        assert_eq!(verify(&[p2, p1], b"hello", &sig).unwrap(), Some(1));
        let (_, p3) = keypair();
        assert_eq!(verify(&[p3], b"hello", &sig).unwrap(), None);
        let (_k1, p1) = keypair();
        assert_eq!(verify(&[p1], b"hellp", &sig).unwrap(), None);
    }

    #[test]
    fn participant_parsing() {
        let (_, p) = keypair();
        assert!(p.can_sign());
        assert!(p.fingerprint().starts_with("SHA256:"));
        let id = age::x25519::Identity::generate();
        let p = Participant::parse(&id.to_public().to_string()).unwrap();
        assert!(!p.can_sign());
        assert!(Participant::parse("garbage").is_err());
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let (key, participant) = keypair();
        let pem = key.to_openssh(LineEnding::LF).unwrap();
        let dir = std::env::temp_dir().join(format!("enc-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("id");
        std::fs::write(&path, pem.as_bytes()).unwrap();
        let ids = load_identities(&[path]).unwrap();
        let ct = encrypt_to_participants(&[participant], b"secret", Vec::new()).unwrap();
        assert_eq!(decrypt_to_vec(&ids, &ct).unwrap(), b"secret");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn hashing_adapters() {
        let mut w = HashWriter::new(Vec::new());
        w.write_all(b"abc").unwrap();
        let (_, h) = w.finish();
        assert_eq!(h, sha256_hex(b"abc"));
        let (mut r, shared) = HashReader::new(&b"abc"[..]);
        let mut v = Vec::new();
        r.read_to_end(&mut v).unwrap();
        assert_eq!(finalize_shared(&shared), h);
    }
}
