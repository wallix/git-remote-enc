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
use zeroize::{Zeroize, Zeroizing};

/// SSH signature namespace; distinct from git's own `git` namespace so a
/// manifest signature can never be replayed as a commit signature.
pub const SIG_NAMESPACE: &str = "git-remote-enc";

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

    /// The key authenticating local trust state, derived from this identity.
    pub fn trust_key(&self) -> Result<TrustKey> {
        match self {
            Identity::Ssh { key, .. } => TrustKey::from_ssh(key),
            Identity::Age { key, .. } => {
                use age::secrecy::ExposeSecret;
                TrustKey::derive(
                    key.to_public().to_string(),
                    key.to_string().expose_secret().as_bytes(),
                )
            }
        }
    }
}

// ---- local state authentication -------------------------------------------

/// A MAC key for the local trust state, derived from one of the user's
/// private keys, so the state cannot be rewritten without that key.
#[derive(Clone)]
pub struct TrustKey {
    /// The public half's fingerprint (`SHA256:…`) or age recipient, recorded
    /// next to the tag so a reader knows which identity to use.
    pub id: String,
    key: [u8; 32],
}

impl Drop for TrustKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl TrustKey {
    const DOMAIN: &'static [u8] = b"git-remote-enc local trust state v1";

    fn derive(id: String, secret: &[u8]) -> Result<Self> {
        Ok(Self {
            id,
            key: hmac_sha256(secret, Self::DOMAIN)?,
        })
    }

    pub fn from_ssh(key: &PrivateKey) -> Result<Self> {
        let pair = key
            .key_data()
            .ed25519()
            .ok_or_else(|| anyhow!("only ssh-ed25519 keys are supported"))?;
        Self::derive(
            key.public_key().fingerprint(HashAlg::Sha256).to_string(),
            pair.private.as_ref(),
        )
    }

    /// Hex HMAC-SHA256 tag over `data`.
    pub fn tag(&self, data: &[u8]) -> Result<String> {
        Ok(hex(&hmac_sha256(&self.key, data)?))
    }

    /// Constant-time check of a hex `tag` over `data`.
    pub fn verify(&self, data: &[u8], tag: &str) -> bool {
        let Ok(want) = self.tag(data) else {
            return false;
        };
        want.len() == tag.len()
            && want
                .bytes()
                .zip(tag.bytes())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32]> {
    use hmac::Mac;
    let mut mac =
        hmac::Hmac::<Sha256>::new_from_slice(key).map_err(|e| anyhow!("HMAC key: {e}"))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

/// Load every identity in `paths`. Each file is either an OpenSSH private
/// key (`ssh-ed25519`; passphrase-protected keys are decrypted
/// with a prompt on the tty) or an age identity file.
pub fn load_identities(paths: &[PathBuf]) -> Result<Vec<Identity>> {
    let mut out = Vec::new();
    for path in paths {
        // As ssh does: a key others can read is not private any more.
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .with_context(|| format!("reading identity {}", path.display()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            bail!(
                "identity {} is accessible by others (mode {:o}); `chmod 600` it",
                path.display(),
                mode & 0o777
            );
        }
        // An unencrypted key file is the private key itself.
        let text = Zeroizing::new(
            std::fs::read_to_string(path)
                .with_context(|| format!("reading identity {}", path.display()))?,
        );
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
        // Only from the terminal: an environment variable would leak into
        // child processes, /proc/<pid>/environ and CI logs.
        let passphrase = Zeroizing::new(
            rpassword::prompt_password(format!("enc: passphrase for {}: ", path.display()))
                .context("reading passphrase from the terminal")?,
        );
        key = key
            .decrypt(passphrase.as_bytes())
            .with_context(|| format!("decrypting SSH key {}", path.display()))?;
    }
    if key.algorithm() != ssh_key::Algorithm::Ed25519 {
        bail!(
            "{}: {} keys are not supported; use an ssh-ed25519 key",
            path.display(),
            key.algorithm()
        );
    }
    // age parses the key itself; hand it the decrypted key re-serialised
    // (wiped on drop; age's own parsing copy is not).
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
        // ssh-rsa is refused: the `rsa` crate age uses for it has an
        // unfixed timing side channel (RUSTSEC-2023-0071).
        if public.algorithm() != ssh_key::Algorithm::Ed25519 {
            bail!(
                "participant `{text}`: {} keys are not supported; use an ssh-ed25519 or age1… key",
                public.algorithm()
            );
        }
        // age's parser wants exactly `<type> <base64>`; drop any comment.
        let bare = text
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        let recipient = age::ssh::Recipient::from_str(&bare)
            .map_err(|e| anyhow!("participant `{text}` cannot be an age recipient: {e:?}"))?;
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

    /// The key alone, without the comment: what identifies a participant.
    pub fn key(&self) -> String {
        match self {
            Participant::Ssh { text, .. } => text
                .split_whitespace()
                .take(2)
                .collect::<Vec<_>>()
                .join(" "),
            Participant::Age { text, .. } => text.clone(),
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

/// The plaintext is wiped when dropped: here it is always a manifest.
pub fn decrypt_to_vec(identities: &[Identity], input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut r = decrypt_with_identities(identities, input)?;
    let mut out = Zeroizing::new(Vec::new());
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

/// The fingerprint of the key that made `sig_pem` over `data`, if the
/// signature verifies; whether that key was allowed to sign is not checked.
pub fn signature_key(data: &[u8], sig_pem: &str) -> Result<String> {
    let sig = SshSig::from_pem(sig_pem).context("parsing manifest signature")?;
    let key = PublicKey::new(sig.public_key().clone(), "");
    key.verify(SIG_NAMESPACE, data, &sig)
        .context("manifest signature does not verify")?;
    Ok(key.fingerprint(HashAlg::Sha256).to_string())
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
        let rsa = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDMedYM//B0/qDeXYaDBhekHB6LuonqH4bymUIoew/eq0NKMmJfSGBQFJV7oYTg/iIDILdtFdk09BNUZJT/Dfu6qRSwmUHJwU+ARneNuvEjoNkVdpDhCTyLEhSuvaHE/GuQs83x6srPYdTxvaW6mIrfB5H5cIVdKbzq1DQ0XeB8KQ== rsa";
        let err = Participant::parse(rsa).err().unwrap().to_string();
        assert!(err.contains("not supported"), "{err}");
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let (key, participant) = keypair();
        let pem = key.to_openssh(LineEnding::LF).unwrap();
        let dir = std::env::temp_dir().join(format!("enc-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("id");
        std::fs::write(&path, pem.as_bytes()).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = load_identities(std::slice::from_ref(&path))
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("accessible by others"), "{err}");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let ids = load_identities(&[path]).unwrap();
        let ct = encrypt_to_participants(&[participant], b"secret", Vec::new()).unwrap();
        assert_eq!(*decrypt_to_vec(&ids, &ct).unwrap(), b"secret");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn key_and_signature_parsers_survive_corrupted_input() {
        let (key, p) = keypair();
        let text = p.text().to_owned();
        for input in crate::mutate::variants(text.as_bytes(), 5_000) {
            if let Ok(s) = std::str::from_utf8(&input) {
                let _ = Participant::parse(s);
            }
        }
        let sig = sign(&key, b"manifest").unwrap();
        let signers = [p];
        for input in crate::mutate::variants(sig.as_bytes(), 5_000) {
            if let Ok(s) = std::str::from_utf8(&input) {
                // A corrupted signature that still verifies must be the same
                // key's signature over the same data: ssh-key tolerates some
                // encoding slack (a wrong inner length prefix on the embedded
                // key), which changes nothing that is signed.
                if let Ok(Some(_)) = verify(&signers, b"manifest", s) {
                    let (got, want) = (
                        SshSig::from_pem(s).unwrap(),
                        SshSig::from_pem(&sig).unwrap(),
                    );
                    assert_eq!(got.public_key(), want.public_key(), "{s}");
                    assert_eq!(got.signature_bytes(), want.signature_bytes(), "{s}");
                    assert_eq!(got.namespace(), want.namespace(), "{s}");
                }
                let _ = signature_key(b"manifest", s);
            }
        }
    }

    #[test]
    fn hmac_matches_rfc4231() {
        // Test cases 1 and 6 (a key longer than the block size).
        assert_eq!(
            hex(&hmac_sha256(&[0x0b; 20], b"Hi There").unwrap()),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex(&hmac_sha256(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )
            .unwrap()),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
        let (key, _) = keypair();
        let k = TrustKey::from_ssh(&key).unwrap();
        let tag = k.tag(b"state").unwrap();
        assert!(k.verify(b"state", &tag));
        assert!(!k.verify(b"statf", &tag));
        assert!(!k.verify(b"state", &tag[1..]));
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
