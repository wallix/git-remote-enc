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
        // No automatic gc or maintenance: the incremental-transfer test counts
        // the packs each repository received, which a repack would merge.
        fs::write(
            home.join(".gitconfig"),
            "[user]\n\tname = t\n\temail = t@example.com\n[init]\n\tdefaultBranch = main\n[advice]\n\tdetachedHead = false\n\
             [gc]\n\tauto = 0\n[receive]\n\tautogc = false\n[maintenance]\n\tauto = false\n",
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

    /// Clone accepting the manifest's signer on first contact; see
    /// `first_contact_needs_a_known_signer` for the pinned alternatives.
    fn clone(&self, name: &str, url: &str, identity: &Path) -> PathBuf {
        let d = self.root.join(name);
        let id = identity.to_str().unwrap();
        self.git_ok(
            &self.root,
            &[
                "-c",
                &format!("enc.identity={id}"),
                "-c",
                "enc.trustOnFirstUse=true",
                "clone",
                "-q",
                url,
                name,
            ],
        );
        self.git_ok(&d, &["config", "remote.origin.enc-identity", id]);
        d
    }

    /// Replace the host's manifest with `edit` of the current one, signed
    /// with `key` and encrypted to `recipients`, as a participant running
    /// some other client could.
    fn forge_manifest(
        &self,
        host: &Path,
        key: &Path,
        recipients: &[&str],
        edit: impl Fn(&str) -> String,
    ) {
        use std::io::Read;
        let run = |args: &[&str], stdin: Option<&Path>| {
            let mut c = self.cmd(host, "git");
            c.args(args);
            if let Some(f) = stdin {
                c.stdin(fs::File::open(f).unwrap());
            }
            let out = c.output().unwrap();
            assert!(
                out.status.success(),
                "{args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            out.stdout
        };
        let blob = run(&["cat-file", "blob", "refs/heads/enc:manifest"], None);
        let pem = fs::read_to_string(key).unwrap();
        let id = age::ssh::Identity::from_buffer(pem.as_bytes(), None).unwrap();
        let mut plain = String::new();
        age::Decryptor::new(&blob[..])
            .unwrap()
            .decrypt(std::iter::once(&id as &dyn age::Identity))
            .unwrap()
            .read_to_string(&mut plain)
            .unwrap();
        let (text, _) = plain.split_at(plain.find("-----BEGIN SSH SIGNATURE-----").unwrap());
        let text = edit(text);
        let sig = PrivateKey::from_openssh(&pem)
            .unwrap()
            .sign("git-remote-enc", ssh_key::HashAlg::Sha512, text.as_bytes())
            .unwrap()
            .to_pem(LineEnding::LF)
            .unwrap();
        let recipients: Vec<age::ssh::Recipient> = recipients
            .iter()
            .map(|r| {
                let bare = r.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
                bare.parse().unwrap()
            })
            .collect();
        let enc =
            age::Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))
                .unwrap();
        let mut out = Vec::new();
        let mut w = enc.wrap_output(&mut out).unwrap();
        w.write_all(format!("{text}{sig}").as_bytes()).unwrap();
        w.finish().unwrap();

        let tmp = self.dir("forge");
        fs::write(tmp.join("manifest"), &out).unwrap();
        let oid = String::from_utf8(run(
            &["hash-object", "-w", tmp.join("manifest").to_str().unwrap()],
            None,
        ))
        .unwrap();
        let tree = String::from_utf8(run(&["ls-tree", "refs/heads/enc"], None)).unwrap();
        let tree: String = tree
            .lines()
            .map(|l| {
                if l.ends_with("\tmanifest") {
                    format!("100644 blob {}\tmanifest\n", oid.trim())
                } else {
                    format!("{l}\n")
                }
            })
            .collect();
        fs::write(tmp.join("tree"), tree).unwrap();
        let tree = String::from_utf8(run(&["mktree"], Some(&tmp.join("tree")))).unwrap();
        let commit = String::from_utf8(run(
            &[
                "commit-tree",
                tree.trim(),
                "-p",
                "refs/heads/enc",
                "-m",
                "enc",
            ],
            None,
        ))
        .unwrap();
        run(&["update-ref", "refs/heads/enc", commit.trim()], None);
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

    // The inspection subcommand, by remote name, shows the participants
    // but not the pack keys unless asked.
    let manifest = |args: &[&str]| {
        let out = sb.cmd(&a, "git-remote-enc").args(args).output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    };
    let m = manifest(&["manifest", "enc"]);
    assert!(m.starts_with("enc-manifest 2\n"), "{m}");
    assert!(m.contains("participant ssh-ed25519"));
    // Three pushes carried objects; the tag, branch and deletion pushes
    // only moved refs and stored no pack.
    assert_eq!(m.matches("\npack ").count(), 3, "{m}");
    assert!(!m.contains("AGE-SECRET-KEY-"), "{m}");
    let m = manifest(&["manifest", "--show-keys", "enc"]);
    assert_eq!(m.matches(" AGE-SECRET-KEY-").count(), 3, "{m}");

    // The audit trail: who signed each generation and what it changed.
    let log = manifest(&["log", "enc"]);
    assert!(log.starts_with("generation 6 ("), "{log}");
    assert!(log.contains("  ref - refs/heads/tmp\n"), "{log}");
    assert!(log.contains("  ref + refs/tags/v1\n"), "{log}");
    assert!(log.contains(&format!("  signed by {bob_pub}\n")), "{log}");
    assert!(
        log.contains(&format!("  participant + {bob_pub}\n")),
        "{log}"
    );
    assert!(log.contains(&format!("  admin + {alice_pub}\n")), "{log}");
    assert_eq!(log.matches("\ngeneration ").count() + 1, 6, "{log}");
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
    let (carol, carol_pub) = sb.keypair("carol");

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

    // Carol gets added by Alice, explicitly; now she can clone. A plain
    // push with the longer configured list does not add her.
    let enc = |dir: &Path, args: &[&str]| {
        let out = sb.cmd(dir, "git-remote-enc").args(args).output().unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success(), "{text}");
        text
    };
    sb.git_ok(
        &a,
        &["config", "--add", "remote.enc.enc-participants", &carol_pub],
    );
    sb.commit_text(&a, "more", "m\n");
    let out = sb.git(&a, &["push", "enc", "main"]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert!(err.contains("a push does not change them"), "{err}");
    let shown = enc(&a, &["participants", "enc"]);
    assert!(shown.contains(&format!("+ {carol_pub}")), "{shown}");
    enc(&a, &["participants", "--apply", "enc"]);
    let c = sb.clone("carol", &url, &carol);
    assert_eq!(fs::read_to_string(c.join("more")).unwrap(), "m\n");

    // Carol's own config names only Alice (a stale list): her pushes keep
    // Bob and the reader in, and the next push by Alice still reaches Bob.
    sb.git_ok(
        &c,
        &["config", "remote.origin.enc-participants", &alice_pub],
    );
    sb.commit_text(&c, "typo", "t\n");
    sb.git_ok(&c, &["push", "-q", "origin", "main"]);
    let m = enc(&a, &["manifest", "enc"]);
    for p in [&alice_pub, &bob_pub, &reader_pub, &carol_pub] {
        assert!(m.contains(&format!("participant {p}\n")), "{p} lost: {m}");
    }

    // A signer not in the participant list cannot push even if they can
    // read: Alice removes herself... then is rejected on the next push.
    sb.git_ok(
        &a,
        &["config", "--unset-all", "remote.enc.enc-participants"],
    );
    for p in [&bob_pub, &carol_pub] {
        sb.git_ok(&a, &["config", "--add", "remote.enc.enc-participants", p]);
    }
    sb.git_ok(&a, &["pull", "-q", "enc", "main"]);
    // Not while she is the only admin: someone must keep that role.
    let out = sb
        .cmd(&a, "git-remote-enc")
        .args(["participants", "--apply", "enc"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("must also leave the admin list"), "{err}");
    sb.git_ok(&a, &["config", "remote.enc.enc-admins", &bob_pub]);
    let shown = enc(&a, &["participants", "--apply", "enc"]);
    assert!(shown.contains(&format!("- {alice_pub}")), "{shown}");
    assert!(shown.contains(&format!("- {reader_pub}")), "{shown}");
    sb.commit_text(&a, "again", "a\n");
    let err = sb.git_fails(&a, &["push", "enc", "main"]);
    assert!(err.contains("not a participant"), "{err}");
}

#[test]
fn only_admins_change_the_participant_list() {
    let sb = Sandbox::new("admins");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let (bob, bob_pub) = sb.keypair("bob");
    let (_, carol_pub) = sb.keypair("carol");
    let enc = |dir: &Path, args: &[&str]| {
        let out = sb.cmd(dir, "git-remote-enc").args(args).output().unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.success(), text)
    };

    // The creator is the admin by default.
    let a = sb.repo("alice");
    sb.commit_text(&a, "one", "1\n");
    sb.add_remote(&a, &url, &alice, &[&alice_pub, &bob_pub]);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    let (ok, m) = enc(&a, &["manifest", "enc"]);
    assert!(ok && m.starts_with("enc-manifest 2\n"), "{m}");
    assert!(m.contains(&format!("admin {alice_pub}\n")), "{m}");

    // Bob pushes, but may not add Carol.
    let b = sb.clone("bob", &url, &bob);
    sb.commit_text(&b, "two", "2\n");
    sb.git_ok(&b, &["push", "-q", "origin", "main"]);
    sb.git_ok(
        &b,
        &[
            "config",
            "--add",
            "remote.origin.enc-participants",
            &alice_pub,
        ],
    );
    sb.git_ok(
        &b,
        &[
            "config",
            "--add",
            "remote.origin.enc-participants",
            &bob_pub,
        ],
    );
    sb.git_ok(
        &b,
        &[
            "config",
            "--add",
            "remote.origin.enc-participants",
            &carol_pub,
        ],
    );
    let (ok, out) = enc(&b, &["participants", "--apply", "origin"]);
    assert!(!ok && out.contains("only an admin"), "{out}");

    // A client that skips that check does not get past the readers either.
    sb.forge_manifest(&host, &bob, &[&alice_pub, &bob_pub, &carol_pub], |text| {
        let generation: u64 = text
            .lines()
            .find_map(|l| l.strip_prefix("generation "))
            .unwrap()
            .parse()
            .unwrap();
        text.replace(
            &format!("generation {generation}\n"),
            &format!("generation {}\n", generation + 1),
        )
        .replace(
            &format!("participant {bob_pub}\n"),
            &format!("participant {bob_pub}\nparticipant {carol_pub}\n"),
        )
    });
    let err = sb.git_fails(&a, &["fetch", "enc"]);
    assert!(err.contains("not signed by an admin"), "{err}");
    sb.git_ok(&host, &["update-ref", "refs/heads/enc", "refs/heads/enc~1"]);

    // Nor can an admin drop the role for everyone, e.g. by writing the
    // pre-admin format.
    sb.forge_manifest(&host, &alice, &[&alice_pub, &bob_pub], |text| {
        let generation: u64 = text
            .lines()
            .find_map(|l| l.strip_prefix("generation "))
            .unwrap()
            .parse()
            .unwrap();
        text.replace("enc-manifest 2\n", "enc-manifest 1\n")
            .replace(&format!("admin {alice_pub}\n"), "")
            .replace(
                &format!("generation {generation}\n"),
                &format!("generation {}\n", generation + 1),
            )
    });
    let err = sb.git_fails(&a, &["fetch", "enc"]);
    assert!(err.contains("removes every admin"), "{err}");
    sb.git_ok(&host, &["update-ref", "refs/heads/enc", "refs/heads/enc~1"]);

    // Alice, the admin, adds Carol and makes Bob an admin; then Bob may
    // change the list himself.
    sb.git_ok(
        &a,
        &["config", "--add", "remote.enc.enc-participants", &carol_pub],
    );
    for p in [&alice_pub, &bob_pub] {
        sb.git_ok(&a, &["config", "--add", "remote.enc.enc-admins", p]);
    }
    let (ok, out) = enc(&a, &["participants", "--apply", "enc"]);
    assert!(ok, "{out}");
    assert!(
        out.contains(&format!("+ {carol_pub}")) && out.contains(&format!("+ {bob_pub}")),
        "{out}"
    );
    sb.git_ok(
        &b,
        &["config", "--unset-all", "remote.origin.enc-participants"],
    );
    for p in [&alice_pub, &bob_pub] {
        sb.git_ok(
            &b,
            &["config", "--add", "remote.origin.enc-participants", p],
        );
    }
    let (ok, out) = enc(&b, &["participants", "--apply", "origin"]);
    assert!(ok && out.contains(&format!("- {carol_pub}")), "{out}");
}

#[test]
fn first_contact_needs_a_known_signer() {
    let sb = Sandbox::new("firstcontact");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let (_, mallory_pub) = sb.keypair("mallory");
    let a = sb.repo("alice");
    sb.commit_text(&a, "one", "1\n");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);

    let id = format!("enc.identity={}", alice.display());
    let clone = |name: &str, extra: &str| {
        sb.git(
            &sb.root,
            &["-c", &id, "-c", extra, "clone", "-q", &url, name],
        )
    };
    // No list and no opt-in: refused, naming the fingerprint to check.
    let out = clone("unpinned", "enc.unrelated=1");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(
        err.contains("no participant list") && err.contains("SHA256:"),
        "{err}"
    );
    // A pinned list that does not name the signer: refused.
    let out = clone("wrongpin", &format!("enc.participants={mallory_pub}"));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(err.contains("not signed by a trusted participant"), "{err}");
    // A pinned list naming the signer: accepted.
    let out = clone("pinned", &format!("enc.participants={alice_pub}"));
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Another spelling of the same URL keeps the accepted state instead of
    // starting over: the rollback check still applies to it.
    let gen1 = sb.git_ok(&host, &["rev-parse", "refs/heads/enc"]);
    sb.commit_text(&a, "two", "2\n");
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    sb.git_ok(&host, &["update-ref", "refs/heads/enc", gen1.trim()]);
    let respelled = format!("enc::file://{}", host.display());
    sb.git_ok(&a, &["remote", "add", "again", &respelled]);
    sb.git_ok(
        &a,
        &[
            "config",
            "remote.again.enc-identity",
            alice.to_str().unwrap(),
        ],
    );
    let err = sb.git_fails(&a, &["fetch", "again"]);
    assert!(err.contains("already known locally"), "{err}");
    assert!(err.contains("rollback detected"), "{err}");
}

#[test]
fn local_trust_state_is_authenticated() {
    let sb = Sandbox::new("truststate");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.commit_text(&a, "one", "1\n");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    let b = sb.clone("bob", &url, &alice);

    let state: Vec<PathBuf> = fs::read_dir(b.join(".git/enc"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(state.len(), 1, "{state:?}");
    let trust = state[0].join("trust");
    let original = fs::read_to_string(&trust).unwrap();
    assert!(original.lines().last().unwrap().starts_with("mac SHA256:"));

    // Rewritten by hand: refused, not re-trusted.
    fs::write(&trust, original.replace("generation 1", "generation 0")).unwrap();
    let err = sb.git_fails(&b, &["fetch", "origin"]);
    assert!(err.contains("modified outside git-remote-enc"), "{err}");

    // The same rewrite with the tag line cut off: refused too, not read as
    // unauthenticated state from an older version.
    let untagged: String = original
        .replace("generation 1", "generation 0")
        .lines()
        .filter(|l| !l.starts_with("mac "))
        .map(|l| format!("{l}\n"))
        .collect();
    fs::write(&trust, untagged).unwrap();
    let err = sb.git_fails(&b, &["fetch", "origin"]);
    assert!(err.contains("no authentication tag"), "{err}");

    // Deleted: refused as well, instead of falling back to first contact.
    fs::remove_file(&trust).unwrap();
    let err = sb.git_fails(&b, &["fetch", "origin"]);
    assert!(err.contains("trust state for origin"), "{err}");
    assert!(err.contains("git-remote-enc forget origin"), "{err}");

    // `forget` resets it; the next contact is a first contact again.
    let out = sb
        .cmd(&b, "git-remote-enc")
        .args(["forget", "origin"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!state[0].exists());
    let err = sb.git_fails(&b, &["fetch", "origin"]);
    assert!(err.contains("no participant list"), "{err}");
    sb.git_ok(
        &b,
        &[
            "-c",
            &format!("enc.participants={alice_pub}"),
            "fetch",
            "origin",
        ],
    );

    // The host deletes the branch: not mistaken for a new remote.
    sb.git_ok(&host, &["update-ref", "-d", "refs/heads/enc"]);
    let err = sb.git_fails(&b, &["fetch", "origin"]);
    assert!(err.contains("no longer exists"), "{err}");
    let err = sb.git_fails(&a, &["push", "enc", "main"]);
    assert!(err.contains("no longer exists"), "{err}");
}

#[test]
fn forked_generation_is_reported() {
    let sb = Sandbox::new("fork");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.commit_text(&a, "one", "1\n");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    let gen1 = sb.git_ok(&host, &["rev-parse", "refs/heads/enc"]);
    // A second clone of Alice's, still at generation 1.
    let a2 = sb.clone("alice2", &url, &alice);

    sb.commit_text(&a, "two", "2\n");
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    let b = sb.clone("bob", &url, &alice);

    // The host rewinds; the stale clone pushes its own generation 2.
    sb.git_ok(&host, &["update-ref", "refs/heads/enc", gen1.trim()]);
    sb.commit_text(&a2, "other", "2'\n");
    sb.git_ok(&a2, &["push", "-q", "origin", "main"]);

    let out = sb.git(&b, &["fetch", "origin"]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert!(err.contains("different manifest for generation 2"), "{err}");
}

#[test]
fn worktrees_share_the_trust_state() {
    let sb = Sandbox::new("worktree");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.commit_text(&a, "one", "1\n");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);

    let wt = sb.root.join("alice-wt");
    sb.git_ok(&a, &["worktree", "add", "-q", wt.to_str().unwrap()]);
    let out = sb.git(&wt, &["fetch", "enc"]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert!(!err.contains("first contact"), "{err}");
}

#[test]
fn option_like_urls_are_refused() {
    let sb = Sandbox::new("optionurl");
    let (alice, _) = sb.keypair("alice");
    let a = sb.repo("alice");
    let witness = sb.root.join("pwned");
    for url in [
        format!("enc::--upload-pack=touch {}", witness.display()),
        format!("enc::-u touch {}", witness.display()),
    ] {
        let id = format!("enc.identity={}", alice.display());
        let err = sb.git_fails(&a, &["-c", &id, "fetch", &url, "main"]);
        assert!(err.contains("starts with `-`"), "{err}");
        let err = sb.git_fails(&a, &["-c", &id, "push", &url, "main"]);
        assert!(err.contains("starts with `-`"), "{err}");
    }
    assert!(!witness.exists(), "the URL was run as a git option");
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

#[test]
fn rewritten_backend_history_is_reported() {
    let sb = Sandbox::new("rewrite");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    for n in ["one", "two", "three"] {
        sb.commit_text(&a, n, "x\n");
        sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    }
    let b = sb.clone("bob", &url, &alice);

    // The host squashes the three generations into one parentless commit
    // carrying the same tree: the manifest itself is still the latest.
    let tree = sb.git_ok(&host, &["rev-parse", "refs/heads/enc^{tree}"]);
    let root = sb.git_ok(&host, &["commit-tree", tree.trim(), "-m", "enc"]);
    sb.git_ok(&host, &["update-ref", "refs/heads/enc", root.trim()]);

    let out = sb.git(&b, &["fetch", "origin"]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert!(err.contains("was rewritten"), "{err}");

    let out = sb
        .cmd(&b, "git-remote-enc")
        .args(["log", "origin"])
        .output()
        .unwrap();
    let log = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{log}");
    assert!(log.starts_with("generation 3 ("), "{log}");
    assert!(
        log.contains("  changes relative to an empty remote\n"),
        "{log}"
    );
    assert!(
        log.contains("generations 1 to 2 are missing from the backend history"),
        "{log}"
    );

    // Only the first fetch after the rewrite warns; `log` keeps saying so.
    let out = sb.git(&b, &["fetch", "origin"]);
    assert!(!String::from_utf8_lossy(&out.stderr).contains("was rewritten"));
}

#[test]
fn received_objects_are_fscked() {
    let sb = Sandbox::new("fsck");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.commit_text(&a, "one", "1\n");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    let b = sb.clone("bob", &url, &alice);

    // A tree with a `.git` entry, which a checkout would write into the
    // repository's own control directory.
    let mktree = |input: String| {
        let tmp = sb.dir("fsck-input").join("tree");
        fs::write(&tmp, input).unwrap();
        let out = sb
            .cmd(&a, "git")
            .arg("mktree")
            .stdin(fs::File::open(&tmp).unwrap())
            .output()
            .unwrap();
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    };
    let blob = sb.git_ok(&a, &["hash-object", "-w", "one"]);
    let inner = mktree(format!("100644 blob {}\tconfig\n", blob.trim()));
    let evil = mktree(format!("040000 tree {inner}\t.git\n"));
    let commit = sb.git_ok(&a, &["commit-tree", &evil, "-m", "attack"]);
    sb.git_ok(
        &a,
        &[
            "push",
            "-q",
            "enc",
            &format!("{}:refs/heads/attack", commit.trim()),
        ],
    );

    let err = sb.git_fails(&b, &["fetch", "origin"]);
    assert!(err.contains("hasDotgit"), "{err}");
    assert!(sb.git(&b, &["cat-file", "-e", &evil]).status.code() != Some(0));

    // git's own fetch.fsck.* severities apply.
    sb.git_ok(
        &b,
        &["-c", "fetch.fsck.hasDotgit=ignore", "fetch", "-q", "origin"],
    );
    sb.git_ok(&b, &["cat-file", "-e", &evil]);
}
