//! Black-box tests: the real binary driven through git against a local bare
//! repository standing in for the hosting service. DESIGN.md §10.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ssh_key::{Algorithm, LineEnding, PrivateKey};

struct Sandbox {
    root: PathBuf,
    home: PathBuf,
    path: String,
}

impl Sandbox {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "git-remote-enc-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&root);
        let home = root.join("home");
        fs::create_dir_all(&home).unwrap();
        fs::write(
            home.join(".gitconfig"),
            "[user]\n\tname = t\n\temail = t@example.com\n[init]\n\tdefaultBranch = main\n[advice]\n\tdetachedHead = false\n",
        )
        .unwrap();
        let bin = Path::new(env!("CARGO_BIN_EXE_git-remote-enc"))
            .parent()
            .unwrap()
            .to_owned();
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        Self { root, home, path }
    }

    fn cmd(&self, dir: &Path, program: &str) -> Command {
        let mut c = Command::new(program);
        c.current_dir(dir)
            .env_clear()
            .env("PATH", &self.path)
            .env("HOME", &self.home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("LC_ALL", "C");
        c
    }

    fn git(&self, dir: &Path, args: &[&str]) -> Output {
        self.cmd(dir, "git").args(args).output().unwrap()
    }

    fn git_ok(&self, dir: &Path, args: &[&str]) -> String {
        let out = self.git(dir, args);
        assert!(
            out.status.success(),
            "git {args:?} in {} failed:\n{}\n{}",
            dir.display(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    fn git_fails(&self, dir: &Path, args: &[&str]) -> String {
        let out = self.git(dir, args);
        assert!(
            !out.status.success(),
            "git {args:?} in {} unexpectedly succeeded:\n{}",
            dir.display(),
            String::from_utf8_lossy(&out.stdout)
        );
        String::from_utf8_lossy(&out.stderr).into_owned()
    }

    fn dir(&self, name: &str) -> PathBuf {
        let d = self.root.join(name);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn host(&self) -> PathBuf {
        let d = self.dir("host.git");
        self.git_ok(&d, &["init", "-q", "--bare"]);
        // Keep received packs on disk so their sizes can be inspected.
        self.git_ok(&d, &["config", "transfer.unpackLimit", "1"]);
        d
    }

    fn url(&self, host: &Path, branch: Option<&str>) -> String {
        match branch {
            Some(b) => format!("enc::{}#{b}", host.display()),
            None => format!("enc::{}", host.display()),
        }
    }

    /// A fresh ed25519 key pair; returns (private key path, public key line).
    fn keypair(&self, name: &str) -> (PathBuf, String) {
        let key = PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519).unwrap();
        let dir = self.dir("keys");
        let path = dir.join(name);
        fs::write(&path, key.to_openssh(LineEnding::LF).unwrap().as_bytes()).unwrap();
        let public = format!("{} {name}", key.public_key().to_openssh().unwrap());
        (path, public)
    }

    fn repo(&self, name: &str) -> PathBuf {
        let d = self.dir(name);
        self.git_ok(&d, &["init", "-q"]);
        d
    }

    fn commit_random(&self, repo: &Path, file: &str, bytes: usize) {
        let mut data = vec![0u8; bytes];
        fs::File::open("/dev/urandom")
            .unwrap()
            .read_exact_into(&mut data);
        fs::write(repo.join(file), data).unwrap();
        self.git_ok(repo, &["add", file]);
        self.git_ok(repo, &["commit", "-qm", file]);
    }

    fn commit_text(&self, repo: &Path, file: &str, text: &str) {
        fs::write(repo.join(file), text).unwrap();
        self.git_ok(repo, &["add", file]);
        self.git_ok(repo, &["commit", "-qm", file]);
    }

    fn add_remote(&self, repo: &Path, url: &str, identity: &Path, participants: &[&str]) {
        self.git_ok(repo, &["remote", "add", "enc", url]);
        self.git_ok(
            repo,
            &[
                "config",
                "remote.enc.enc-identity",
                identity.to_str().unwrap(),
            ],
        );
        for p in participants {
            self.git_ok(repo, &["config", "--add", "remote.enc.enc-participants", p]);
        }
    }

    fn clone(&self, name: &str, url: &str, identity: &Path) -> PathBuf {
        let d = self.root.join(name);
        let id = identity.to_str().unwrap();
        self.git_ok(
            &self.root,
            &[
                "-c",
                &format!("enc.identity={id}"),
                "clone",
                "-q",
                url,
                name,
            ],
        );
        self.git_ok(&d, &["config", "remote.origin.enc-identity", id]);
        d
    }

    fn host_pack_sizes(&self, host: &Path) -> Vec<u64> {
        let mut v: Vec<u64> = fs::read_dir(host.join("objects/pack"))
            .unwrap()
            .flatten()
            .filter(|e| e.path().extension().is_some_and(|x| x == "pack"))
            .map(|e| e.metadata().unwrap().len())
            .collect();
        v.sort_unstable();
        v
    }
}

trait ReadExactInto {
    fn read_exact_into(self, buf: &mut [u8]);
}

impl ReadExactInto for fs::File {
    fn read_exact_into(mut self, buf: &mut [u8]) {
        std::io::Read::read_exact(&mut self, buf).unwrap();
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        if std::env::var_os("ENC_TEST_KEEP").is_none() {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

// ---------------------------------------------------------------------------

#[test]
fn push_clone_fetch_roundtrip() {
    let sb = Sandbox::new("roundtrip");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let (bob, bob_pub) = sb.keypair("bob");

    let a = sb.repo("alice");
    sb.commit_text(&a, "README", "hello\n");
    sb.commit_random(&a, "blob.bin", 100_000);
    sb.add_remote(&a, &url, &alice, &[&alice_pub, &bob_pub]);
    let out = sb.git(&a, &["push", "enc", "main"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The host sees only the backend branch with opaque blobs.
    let refs = sb.git_ok(&host, &["for-each-ref", "--format=%(refname)"]);
    assert_eq!(refs.trim(), "refs/heads/enc");
    let tree = sb.git_ok(&host, &["ls-tree", "--name-only", "refs/heads/enc"]);
    let names: Vec<&str> = tree.lines().collect();
    assert_eq!(names.len(), 2);
    assert!(names.contains(&"manifest"));
    assert!(names.iter().any(|n| n.ends_with(".age") && n.len() == 68));
    let grep = sb.git(&host, &["grep", "-q", "hello", "refs/heads/enc"]);
    assert!(!grep.status.success(), "plaintext leaked to the host");

    // Bob clones with his own key and sees the same history.
    let b = sb.clone("bob", &url, &bob);
    assert_eq!(fs::read_to_string(b.join("README")).unwrap(), "hello\n");
    assert_eq!(
        sb.git_ok(&a, &["rev-parse", "HEAD"]),
        sb.git_ok(&b, &["rev-parse", "HEAD"])
    );
    assert_eq!(
        fs::read(a.join("blob.bin")).unwrap(),
        fs::read(b.join("blob.bin")).unwrap()
    );

    // Alice pushes more; Bob pulls it incrementally.
    sb.commit_text(&a, "second", "2\n");
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    sb.git_ok(&b, &["pull", "-q", "origin", "main"]);
    assert_eq!(
        sb.git_ok(&a, &["rev-parse", "HEAD"]),
        sb.git_ok(&b, &["rev-parse", "HEAD"])
    );

    // Bob pushes back (he is a participant); Alice fetches.
    sb.commit_text(&b, "third", "3\n");
    sb.git_ok(&b, &["push", "-q", "origin", "main"]);
    sb.git_ok(&a, &["fetch", "-q", "enc"]);
    assert_eq!(
        sb.git_ok(&b, &["rev-parse", "HEAD"]),
        sb.git_ok(&a, &["rev-parse", "enc/main"])
    );

    // Tags and ref deletion.
    sb.git_ok(&a, &["tag", "v1", "HEAD~1"]);
    sb.git_ok(&a, &["push", "-q", "enc", "v1"]);
    sb.git_ok(&a, &["push", "-q", "enc", "HEAD:refs/heads/tmp"]);
    let ls = sb.git_ok(&b, &["ls-remote", "origin"]);
    assert!(ls.contains("refs/tags/v1"));
    assert!(ls.contains("refs/heads/tmp"));
    sb.git_ok(&a, &["push", "-q", "enc", "--delete", "tmp"]);
    let ls = sb.git_ok(&b, &["ls-remote", "origin"]);
    assert!(!ls.contains("refs/heads/tmp"));

    // The inspection subcommand, by remote name, shows the participants.
    let out = sb
        .cmd(&a, "git-remote-enc")
        .args(["manifest", "enc"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let m = String::from_utf8(out.stdout).unwrap();
    assert!(m.starts_with("enc-manifest 1\n"), "{m}");
    assert!(m.contains("participant ssh-ed25519"));
    // Three pushes carried objects; the tag, branch and deletion pushes
    // only moved refs and stored no pack.
    assert_eq!(m.matches("\npack ").count(), 3, "{m}");
}

#[test]
fn transfers_are_incremental() {
    let sb = Sandbox::new("incremental");
    let host = sb.host();
    let url = sb.url(&host, Some("store"));
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);

    let chunk = 200_000;
    for i in 0..4 {
        sb.commit_random(&a, &format!("f{i}"), chunk);
        sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    }
    let sizes = sb.host_pack_sizes(&host);
    assert_eq!(sizes.len(), 4, "{sizes:?}");
    // Every push transferred about one chunk, never the accumulated history.
    for s in &sizes {
        assert!(*s < (chunk as u64) * 3 / 2, "pack too large: {sizes:?}");
    }
    assert_eq!(
        sb.git_ok(&host, &["for-each-ref", "--format=%(refname)"])
            .trim(),
        "refs/heads/store"
    );
    // The backend history is a chain, not a series of roots.
    let parents = sb.git_ok(&host, &["rev-list", "--count", "refs/heads/store"]);
    assert_eq!(parents.trim(), "4");

    // A fetch after one more push is also bounded by the new objects.
    let b = sb.clone("bob", &url, &alice);
    sb.git_ok(&b, &["config", "transfer.unpackLimit", "1"]);
    let before: Vec<u64> = sb.host_pack_sizes(&b.join(".git"));
    sb.commit_random(&a, "f9", chunk);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    sb.git_ok(&b, &["fetch", "-q", "origin"]);
    let after = sb.host_pack_sizes(&b.join(".git"));
    let new: Vec<u64> = after
        .iter()
        .filter(|s| !before.contains(s))
        .copied()
        .collect();
    // Two new packs: the fetched backend commit and the decrypted pack.
    assert!(!new.is_empty(), "{before:?} -> {after:?}");
    for s in &new {
        assert!(*s < (chunk as u64) * 3 / 2, "fetched too much: {new:?}");
    }
}

#[test]
fn non_fast_forward_is_rejected() {
    let sb = Sandbox::new("nonff");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.commit_text(&a, "a", "1\n");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);

    let b = sb.clone("bob", &url, &alice);

    // Alice moves main; Bob diverges without fetching.
    sb.commit_text(&a, "a2", "2\n");
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    sb.commit_text(&b, "b2", "2\n");
    let err = sb.git_fails(&b, &["push", "origin", "main"]);
    assert!(
        err.contains("fetch first") || err.contains("rejected"),
        "{err}"
    );

    // After fetching it is a plain non-fast-forward.
    sb.git_ok(&b, &["fetch", "-q", "origin"]);
    let err = sb.git_fails(&b, &["push", "origin", "main"]);
    assert!(
        err.contains("non-fast-forward") || err.contains("rejected"),
        "{err}"
    );

    // Alice's tip is intact on the remote.
    assert_eq!(
        sb.git_ok(&b, &["ls-remote", "origin", "refs/heads/main"])
            .split_whitespace()
            .next()
            .unwrap(),
        sb.git_ok(&a, &["rev-parse", "HEAD"]).trim()
    );

    // --force wins, and Alice sees Bob's history.
    sb.git_ok(&b, &["push", "-q", "--force", "origin", "main"]);
    sb.git_ok(&a, &["fetch", "-q", "enc"]);
    assert_eq!(
        sb.git_ok(&a, &["rev-parse", "enc/main"]),
        sb.git_ok(&b, &["rev-parse", "HEAD"])
    );
}

#[test]
fn concurrent_pushes_lose_nothing() {
    let sb = Sandbox::new("concurrent");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.commit_text(&a, "base", "0\n");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    let b = sb.clone("bob", &url, &alice);

    for round in 0..3 {
        sb.git_ok(&a, &["checkout", "-q", "-B", &format!("a{round}"), "main"]);
        sb.commit_random(&a, &format!("a{round}.bin"), 50_000);
        sb.git_ok(&b, &["checkout", "-q", "-B", &format!("b{round}"), "main"]);
        sb.commit_random(&b, &format!("b{round}.bin"), 50_000);

        let mut pa = sb
            .cmd(&a, "git")
            .args(["push", "-q", "enc", &format!("a{round}")])
            .spawn()
            .unwrap();
        let mut pb = sb
            .cmd(&b, "git")
            .args(["push", "-q", "origin", &format!("b{round}")])
            .spawn()
            .unwrap();
        assert!(pa.wait().unwrap().success());
        assert!(pb.wait().unwrap().success());
    }

    let c = sb.clone("carol", &url, &alice);
    let refs = sb.git_ok(
        &c,
        &[
            "for-each-ref",
            "--format=%(refname:short)",
            "refs/remotes/origin",
        ],
    );
    for round in 0..3 {
        for who in ["a", "b"] {
            let branch = format!("origin/{who}{round}");
            assert!(refs.contains(&branch), "missing {branch} in {refs}");
            // Its objects are all present (no pack was lost).
            sb.git_ok(&c, &["rev-list", "--objects", "--missing=error", &branch]);
        }
    }
}

#[test]
fn access_control() {
    let sb = Sandbox::new("access");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let (_bob, bob_pub) = sb.keypair("bob");
    let (carol, _carol_pub) = sb.keypair("carol");

    // A read-only age participant.
    let reader = age::x25519::Identity::generate();
    let reader_pub = reader.to_public().to_string();
    let reader_path = sb.dir("keys").join("reader.age");
    {
        use age::secrecy::ExposeSecret;
        let mut f = fs::File::create(&reader_path).unwrap();
        writeln!(f, "{}", reader.to_string().expose_secret()).unwrap();
    }

    let a = sb.repo("alice");
    sb.commit_text(&a, "secret", "s\n");
    sb.add_remote(&a, &url, &alice, &[&alice_pub, &bob_pub, &reader_pub]);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);

    // Carol is not a participant: cannot read.
    let err = String::from_utf8_lossy(
        &sb.git(
            &sb.root,
            &[
                "-c",
                &format!("enc.identity={}", carol.display()),
                "clone",
                "-q",
                &url,
                "carol",
            ],
        )
        .stderr,
    )
    .into_owned();
    assert!(err.contains("not a participant"), "{err}");

    // The age reader can clone but not push.
    let r = sb.clone("reader", &url, &reader_path);
    assert_eq!(fs::read_to_string(r.join("secret")).unwrap(), "s\n");
    sb.commit_text(&r, "evil", "x\n");
    let err = sb.git_fails(&r, &["push", "origin", "main"]);
    assert!(err.contains("no SSH private key to sign with"), "{err}");

    // Carol gets added by Alice; now she can clone.
    sb.git_ok(
        &a,
        &[
            "config",
            "--add",
            "remote.enc.enc-participants",
            &_carol_pub,
        ],
    );
    sb.commit_text(&a, "more", "m\n");
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    let c = sb.clone("carol", &url, &carol);
    assert_eq!(fs::read_to_string(c.join("more")).unwrap(), "m\n");

    // A signer not in the participant list cannot push even if they can
    // read: Alice removes herself... then is rejected on the next push.
    sb.git_ok(
        &a,
        &["config", "--unset-all", "remote.enc.enc-participants"],
    );
    for p in [&bob_pub, &_carol_pub] {
        sb.git_ok(&a, &["config", "--add", "remote.enc.enc-participants", p]);
    }
    sb.commit_text(&a, "bye", "b\n");
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    sb.commit_text(&a, "again", "a\n");
    let err = sb.git_fails(&a, &["push", "enc", "main"]);
    assert!(err.contains("not a participant"), "{err}");
}

#[test]
fn rollback_and_recreation_are_refused() {
    let sb = Sandbox::new("rollback");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.commit_text(&a, "one", "1\n");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    let gen1 = sb.git_ok(&host, &["rev-parse", "refs/heads/enc"]);
    sb.commit_text(&a, "two", "2\n");
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);

    let b = sb.clone("bob", &url, &alice);
    assert!(b.join("two").exists());

    // The host rewinds the backend branch: Bob refuses to go back.
    sb.git_ok(&host, &["update-ref", "refs/heads/enc", gen1.trim()]);
    let err = sb.git_fails(&b, &["fetch", "origin"]);
    assert!(err.contains("rollback detected"), "{err}");

    // A different encrypted remote transplanted onto the branch by someone
    // with host access (Mallory) is refused as well: wrong repo id / signer.
    let (mallory, mallory_pub) = sb.keypair("mallory");
    let host2 = sb.dir("host2.git");
    sb.git_ok(&host2, &["init", "-q", "--bare"]);
    let m = sb.repo("mallory");
    sb.commit_text(&m, "trap", "t\n");
    sb.add_remote(
        &m,
        &sb.url(&host2, None),
        &mallory,
        &[&mallory_pub, &alice_pub],
    );
    sb.git_ok(&m, &["push", "-q", "enc", "main"]);
    sb.git_ok(
        &host,
        &[
            "fetch",
            "-q",
            host2.to_str().unwrap(),
            "+refs/heads/enc:refs/heads/enc",
        ],
    );
    let err = sb.git_fails(&b, &["fetch", "origin"]);
    assert!(
        err.contains("recreated") || err.contains("not signed by a trusted participant"),
        "{err}"
    );
}
