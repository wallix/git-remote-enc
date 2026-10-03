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

    /// `git-remote-enc <args>` in `dir`: (success, stdout, stderr).
    fn enc(&self, dir: &Path, args: &[&str]) -> (bool, String, String) {
        let out = self.cmd(dir, "git-remote-enc").args(args).output().unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn enc_ok(&self, dir: &Path, args: &[&str]) -> String {
        let (ok, out, err) = self.enc(dir, args);
        assert!(ok, "git-remote-enc {args:?} failed:\n{out}\n{err}");
        out
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
        // As GitLab and GitHub: clients fetch pack blobs on demand.
        self.git_ok(&d, &["config", "uploadpack.allowFilter", "true"]);
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
        let mut perms = fs::metadata(&path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o600);
        fs::set_permissions(&path, perms).unwrap();
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

    /// Install `body` as the host's hook `name`, a shell script run in the
    /// host repository.
    fn host_hook(&self, host: &Path, name: &str, body: &str) {
        let hook = host.join("hooks").join(name);
        fs::create_dir_all(hook.parent().unwrap()).unwrap();
        fs::write(&hook, format!("#!/bin/sh\n{body}")).unwrap();
        let mut perms = fs::metadata(&hook).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        fs::set_permissions(&hook, perms).unwrap();
    }

    /// The pack ids listed in `remote`'s manifest, as seen from `repo`.
    fn pack_ids(&self, repo: &Path, remote: &str) -> Vec<String> {
        let m = self.enc_ok(repo, &["manifest", remote]);
        m.lines()
            .filter_map(|l| l.strip_prefix("pack "))
            .map(|l| l.split_whitespace().next().unwrap().to_owned())
            .collect()
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
    assert!(m.starts_with("enc-manifest 4\n"), "{m}");
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
        let mut perms = f.metadata().unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o600);
        f.set_permissions(perms).unwrap();
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

    // Alice explicitly adds Carol so she can clone. A plain push with the
    // longer configured list does not add her.
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
    assert!(ok && m.starts_with("enc-manifest 4\n"), "{m}");
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
        text.replace("enc-manifest 4\n", "enc-manifest 1\n")
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

    // Another spelling of the same URL keeps the accepted state: the rollback
    // check still applies.
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
fn a_refused_identity_fails_before_the_backend_fetch() {
    let sb = Sandbox::new("refusedid");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let (bob, bob_pub) = sb.keypair("bob");
    let a = sb.repo("alice");
    sb.commit_text(&a, "one", "1\n");
    sb.add_remote(&a, &url, &alice, &[&alice_pub, &bob_pub]);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    let b = sb.clone("bob", &url, &bob);
    let backend = backend_repo(&b);
    let tracking = || {
        sb.git_ok(
            &b,
            &[
                "--git-dir",
                backend.to_str().unwrap(),
                "for-each-ref",
                "refs/enc/",
            ],
        )
    };
    let before = tracking();
    assert!(!before.is_empty());

    sb.commit_text(&a, "two", "2\n");
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    let mut perms = fs::metadata(&bob).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o644);
    fs::set_permissions(&bob, perms).unwrap();
    let err = sb.git_fails(&b, &["fetch", "origin"]);
    assert!(err.contains("accessible by others"), "{err}");
    // The new backend tip was not fetched.
    assert_eq!(tracking(), before);
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
        .filter(|p| p.is_dir())
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
    let marker = state[0].with_extension("known");
    assert!(!state[0].exists() && !marker.exists());
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

    // The whole state directory lost, backend repository included: still
    // refused, the contact is recorded outside it.
    assert!(marker.exists());
    fs::remove_dir_all(&state[0]).unwrap();
    let err = sb.git_fails(&b, &["fetch", "origin"]);
    assert!(err.contains("trust state for origin"), "{err}");

    // The host deletes the branch: not mistaken for a new remote.
    sb.git_ok(&host, &["update-ref", "-d", "refs/heads/enc"]);
    let err = sb.git_fails(&b, &["fetch", "origin"]);
    assert!(err.contains("no longer exists"), "{err}");
    let err = sb.git_fails(&a, &["push", "enc", "main"]);
    assert!(err.contains("no longer exists"), "{err}");
}

#[test]
fn forked_history_is_refused() {
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
    let c = sb.clone("carol", &url, &alice);

    // The host rewinds; the stale clone pushes its own generation 2.
    sb.git_ok(&host, &["update-ref", "refs/heads/enc", gen1.trim()]);
    sb.commit_text(&a2, "other", "2'\n");
    sb.git_ok(&a2, &["push", "-q", "origin", "main"]);
    let err = sb.git_fails(&c, &["fetch", "origin"]);
    assert!(err.contains("different manifest for generation 2"), "{err}");
    assert!(err.contains("Refusing it"), "{err}");

    // One generation later, the fork shows in the chain.
    sb.commit_text(&a2, "three", "3'\n");
    sb.git_ok(&a2, &["push", "-q", "origin", "main"]);
    let err = sb.git_fails(&b, &["fetch", "origin"]);
    assert!(err.contains("does not follow the generation 2"), "{err}");

    // The participants keep this view: accepted once on request, then as
    // the new baseline.
    let out = sb.git(&b, &["-c", "enc.refuseForks=false", "fetch", "origin"]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert!(err.contains("warning:") && err.contains("forked"), "{err}");
    sb.git_ok(&b, &["fetch", "origin"]);
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

#[test]
fn first_contact_can_pin_repository_and_generation() {
    let sb = Sandbox::new("pinrepo");
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

    // What an admin hands out with their key.
    let out = sb
        .cmd(&a, "git-remote-enc")
        .args(["manifest", "enc"])
        .output()
        .unwrap();
    let manifest = String::from_utf8(out.stdout).unwrap();
    let repo = manifest
        .lines()
        .find_map(|l| l.strip_prefix("repo "))
        .unwrap()
        .to_owned();

    let clone = |name: &str, pins: &[String]| {
        let mut args = vec![
            "-c".to_owned(),
            format!("enc.identity={}", alice.display()),
            "-c".to_owned(),
            format!("enc.participants={alice_pub}"),
        ];
        for p in pins {
            args.extend(["-c".to_owned(), p.clone()]);
        }
        args.extend(["clone", "-q", &url, name].map(str::to_owned));
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        sb.git(&sb.root, &args)
    };
    let pins = |repo: &str, generation: u64| {
        [
            format!("enc.repo={repo}"),
            format!("enc.minGeneration={generation}"),
        ]
    };

    // The host serves the older, validly signed generation to a new clone.
    sb.git_ok(&host, &["update-ref", "refs/heads/enc", gen1.trim()]);
    let out = clone("participants-only", &[]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert!(
        err.contains(&format!("repository {repo} at generation 1"))
            && err.contains("enc.minGeneration"),
        "{err}"
    );
    let out = clone("floor", &pins(&repo, 2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(
        err.contains("enc-minGeneration requires at least 2"),
        "{err}"
    );

    // Another remote the same admin signed, substituted by the host.
    let out = clone("other-repo", &pins("0123456789abcdef0123456789abcdef", 1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(err.contains("enc-repo pins"), "{err}");

    let out = clone("pinned", &pins(&repo, 1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert!(!err.contains("enc.minGeneration"), "{err}");
}

#[test]
fn git_lfs_pre_push_hook_blocks_the_push() {
    let sb = Sandbox::new("lfs");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.commit_text(&a, "one", "1\n");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    let hook = a.join(".git/hooks/pre-push");
    let witness = sb.root.join("hook-ran");
    let write_hook = |body: &str| {
        fs::write(
            &hook,
            format!("#!/bin/sh\n{body}\ntouch '{}'\n", witness.display()),
        )
        .unwrap();
        let mut perms = fs::metadata(&hook).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        fs::set_permissions(&hook, perms).unwrap();
    };
    let host_is_empty = || {
        sb.git(&host, &["rev-parse", "-q", "--verify", "refs/heads/enc"])
            .stdout
            .is_empty()
    };

    // A hook but nothing for LFS to upload: the push goes through.
    write_hook(": git lfs pre-push");
    let other = sb.repo("other");
    sb.commit_text(&other, "x", "x\n");
    sb.add_remote(&other, &sb.url(&host, Some("other")), &alice, &[&alice_pub]);
    fs::create_dir_all(other.join(".git/hooks")).unwrap();
    fs::copy(&hook, other.join(".git/hooks/pre-push")).unwrap();
    sb.git_ok(&other, &["push", "-q", "enc", "main"]);
    assert!(witness.exists());
    fs::remove_file(&witness).unwrap();

    // Files in LFS storage, and any pre-push hook, however it spells the
    // LFS call: refused before the hook runs.
    let objects = a.join(".git/lfs/objects/2f/65");
    fs::create_dir_all(&objects).unwrap();
    fs::write(objects.join("2f655113"), "binary").unwrap();
    for body in [
        "git lfs pre-push \"$@\"",
        "git  lfs pre-push \"$@\"",
        "git \"lfs\" pre-push \"$@\"",
        "L=lfs; git $L pre-push \"$@\"",
        ". ./.husky/pre-push",
    ] {
        write_hook(&format!(": {body}"));
        let err = sb.git_fails(&a, &["push", "enc", "main"]);
        assert!(
            err.contains("Git LFS may run before this push"),
            "{body}: {err}"
        );
        assert!(!witness.exists(), "the hook ran before the refusal");
        assert!(host_is_empty(), "the refused push reached the host");
    }

    // A config-defined hook counts too (harmless where git runs those).
    fs::remove_file(&hook).unwrap();
    sb.git_ok(&a, &["config", "hook.lfs.command", "true"]);
    let err = sb.git_fails(&a, &["push", "enc", "main"]);
    assert!(err.contains("hook.lfs.command"), "{err}");

    // Opting in, once LFS is neutralized, lets it through.
    sb.git_ok(&a, &["config", "remote.enc.enc-allowLfs", "true"]);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
}

#[test]
fn git_lfs_pointers_are_not_pushed_alone() {
    let sb = Sandbox::new("lfs-pointer");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.commit_text(&a, "one", "1\n");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);

    // What `git add` stores for an LFS-tracked file: its pointer.
    sb.commit_text(
        &a,
        "big.bin",
        "version https://git-lfs.github.com/spec/v1\n\
         oid sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393\n\
         size 12345\n",
    );
    let err = sb.git_fails(&a, &["push", "enc", "main"]);
    assert!(err.contains("big.bin is a Git LFS pointer"), "{err}");

    sb.git_ok(&a, &["config", "remote.enc.enc-allowLfs", "true"]);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
}

#[test]
fn shallow_history_is_not_pushed() {
    let sb = Sandbox::new("shallow");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let public = sb.dir("public.git");
    sb.git_ok(&public, &["init", "-q", "--bare"]);
    let seed = sb.repo("seed");
    sb.commit_text(&seed, "one", "1\n");
    sb.commit_text(&seed, "two", "2\n");
    sb.git_ok(&seed, &["push", "-q", public.to_str().unwrap(), "main"]);
    let public_url = format!("file://{}", public.display());

    // The pack would name the first commit as a parent without holding it.
    sb.git_ok(&sb.root, &["clone", "-q", "--depth=1", &public_url, "dev"]);
    let dev = sb.root.join("dev");
    sb.add_remote(&dev, &url, &alice, &[&alice_pub]);
    let err = sb.git_fails(&dev, &["push", "enc", "main"]);
    assert!(err.contains("this clone is shallow"), "{err}");
    sb.git_ok(&dev, &["fetch", "-q", "--unshallow", "origin"]);
    sb.git_ok(&dev, &["push", "-q", "enc", "main"]);

    // A boundary the remote already holds is fine: only new commits are packed.
    sb.git_ok(&sb.root, &["clone", "-q", "--depth=1", &public_url, "dev2"]);
    let dev2 = sb.root.join("dev2");
    sb.add_remote(&dev2, &url, &alice, &[&alice_pub]);
    sb.commit_text(&dev2, "three", "3\n");
    sb.git_ok(
        &dev2,
        &[
            "-c",
            "enc.trustOnFirstUse=true",
            "push",
            "-q",
            "enc",
            "main",
        ],
    );
    let c = sb.clone("bob", &url, &alice);
    assert_eq!(sb.git_ok(&c, &["rev-list", "--count", "main"]).trim(), "3");
}

#[test]
fn pre_push_guard_keeps_encrypted_commits_off_other_remotes() {
    let sb = Sandbox::new("guard");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");

    // The public product repository, and a developer clone of it that also
    // works on an embargoed fix.
    let public = sb.dir("public.git");
    sb.git_ok(&public, &["init", "-q", "--bare"]);
    let seed = sb.repo("seed");
    let lines: Vec<String> = (1..=20).map(|i| format!("line {i}\n")).collect();
    sb.commit_text(&seed, "product", &lines.concat());
    sb.git_ok(&seed, &["push", "-q", public.to_str().unwrap(), "main"]);
    sb.git_ok(&sb.root, &["clone", "-q", public.to_str().unwrap(), "dev"]);
    let dev = sb.root.join("dev");
    sb.add_remote(&dev, &url, &alice, &[&alice_pub]);
    let out = sb
        .cmd(&dev, "git-remote-enc")
        .arg("install-hook")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    sb.git_ok(&dev, &["checkout", "-q", "-b", "fix-main"]);
    sb.commit_text(&dev, "fix", "f\n");
    let mut patched = lines.clone();
    patched[1] = "line 2, patched\n".into();
    sb.commit_text(&dev, "product", &patched.concat());
    sb.git_ok(&dev, &["push", "-q", "-u", "enc", "fix-main"]);
    let fix = sb.git_ok(&dev, &["rev-parse", "fix-main"]);

    // One command away from publishing the fix before the date: refused.
    let err = sb.git_fails(&dev, &["push", "origin", "fix-main"]);
    assert!(
        err.contains("would publish commits of an encrypted remote"),
        "{err}"
    );
    assert!(err.contains(fix.trim()), "{err}");
    let err = sb.git_fails(&dev, &["push", "origin", "fix-main:main"]);
    assert!(err.contains("refusing to push to origin"), "{err}");
    assert!(
        sb.git(
            &public,
            &["rev-parse", "-q", "--verify", "refs/heads/fix-main"]
        )
        .stdout
        .is_empty()
    );

    // A local commit on top of the fix, not pushed anywhere yet, counts too.
    sb.commit_text(&dev, "fix2", "f2\n");
    sb.git_fails(&dev, &["push", "origin", "HEAD:refs/heads/other"]);

    // A backport shares no commit with the fix, only its content: a
    // cherry-pick or a squash carries the fixed files...
    sb.git_ok(&dev, &["checkout", "-q", "-b", "maint", "origin/main"]);
    sb.git_ok(&dev, &["cherry-pick", "-x", "fix-main~2"]);
    let err = sb.git_fails(&dev, &["push", "origin", "maint"]);
    assert!(err.contains("contains object"), "{err}");
    sb.git_ok(&dev, &["reset", "-q", "--hard", "origin/main"]);
    sb.git_ok(&dev, &["merge", "-q", "--squash", "fix-main"]);
    sb.git_ok(&dev, &["commit", "-qm", "squashed"]);
    let err = sb.git_fails(&dev, &["push", "origin", "maint"]);
    assert!(err.contains("contains object"), "{err}");
    // ...and on a base that diverged, the same change under another blob.
    sb.git_ok(&dev, &["reset", "-q", "--hard", "origin/main"]);
    let mut diverged = lines.clone();
    diverged[19] = "line 20, maint only\n".into();
    sb.commit_text(&dev, "product", &diverged.concat());
    sb.git_ok(&dev, &["cherry-pick", "fix-main~1"]);
    let err = sb.git_fails(&dev, &["push", "origin", "maint"]);
    assert!(err.contains("contains the change of"), "{err}");
    sb.git_ok(&dev, &["reset", "-q", "--hard", "origin/main"]);

    // Ordinary public work passes, and so does the disclosure, deliberately.
    sb.git_ok(&dev, &["checkout", "-q", "main"]);
    sb.commit_text(&dev, "feature", "x\n");
    sb.git_ok(&dev, &["push", "-q", "origin", "main"]);
    sb.git_ok(&dev, &["push", "-q", "--no-verify", "origin", "fix-main"]);
    // Once public, the fix no longer trips the guard.
    sb.git_ok(&dev, &["fetch", "-q", "origin"]);
    sb.git_ok(&dev, &["push", "-q", "origin", "fix-main:refs/heads/copy"]);

    // Installing again is a no-op; another hook is not overwritten.
    sb.enc_ok(&dev, &["install-hook"]);
    fs::write(dev.join(".git/hooks/pre-push"), "#!/bin/sh\n").unwrap();
    let (ok, _, err) = sb.enc(&dev, &["install-hook"]);
    assert!(!ok && err.contains("install-hook --chain"), "{err}");
}

#[test]
fn backports_onto_diverged_code_are_refused() {
    let sb = Sandbox::new("backport");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let public = sb.dir("public.git");
    sb.git_ok(&public, &["init", "-q", "--bare"]);
    let seed = sb.repo("seed");
    let code = "int f(int n)\n{\n\treturn n;\n}\n";
    sb.commit_text(&seed, "a.c", code);
    sb.git_ok(&seed, &["push", "-q", public.to_str().unwrap(), "main"]);
    sb.git_ok(&sb.root, &["clone", "-q", public.to_str().unwrap(), "dev"]);
    let dev = sb.root.join("dev");
    sb.add_remote(&dev, &url, &alice, &[&alice_pub]);
    let fixed_line = "\treturn n < 0 || n > LIMIT ? -EINVAL : n;\n";
    sb.git_ok(&dev, &["checkout", "-q", "-b", "fix"]);
    sb.commit_text(&dev, "a.c", &code.replace("\treturn n;\n", fixed_line));
    sb.git_ok(&dev, &["push", "-q", "-u", "enc", "fix"]);

    // A line added within the fix's diff context: the cherry-pick applies
    // cleanly, and only the context of its diff differs.
    sb.git_ok(&dev, &["checkout", "-q", "-b", "maint-3", "origin/main"]);
    sb.commit_text(&dev, "a.c", &format!("/* header v1 */\n{code}"));
    sb.git_ok(&dev, &["cherry-pick", "fix"]);
    let err = sb.git_fails(&dev, &["push", "origin", "maint-3"]);
    assert!(err.contains("contains the change of"), "{err}");

    // The fixed line itself diverged: a conflict, resolved by hand.
    sb.git_ok(&dev, &["checkout", "-q", "-b", "maint-2", "origin/main"]);
    let maint = "long f(long n)\n{\n\treturn (long)n;\n}\n";
    sb.commit_text(&dev, "a.c", maint);
    assert!(!sb.git(&dev, &["cherry-pick", "fix"]).status.success());
    fs::write(
        dev.join("a.c"),
        maint.replace("\treturn (long)n;\n", fixed_line),
    )
    .unwrap();
    sb.git_ok(&dev, &["add", "a.c"]);
    sb.git_ok(
        &dev,
        &["-c", "core.editor=true", "cherry-pick", "--continue"],
    );
    let err = sb.git_fails(&dev, &["push", "origin", "maint-2"]);
    assert!(err.contains("contains the lines added by"), "{err}");

    // The maintenance branch's own work still goes out.
    sb.git_ok(&dev, &["reset", "-q", "--hard", "HEAD~1"]);
    sb.git_ok(&dev, &["push", "-q", "origin", "maint-2"]);
}

#[test]
fn the_guard_is_checked_on_every_contact() {
    let sb = Sandbox::new("reguard");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.commit_text(&a, "one", "1\n");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    let hook = a.join(".git/hooks/pre-push");
    let fetch_stderr = || {
        let out = sb.git(&a, &["fetch", "enc"]);
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stderr).into_owned()
    };
    assert!(!fetch_stderr().contains("warning"));

    // Replaced by another tool (`git lfs install --force` does this).
    fs::write(&hook, "#!/bin/sh\ngit lfs pre-push \"$@\"\n").unwrap();
    let err = fetch_stderr();
    assert!(
        err.contains("does not run the git-remote-enc guard"),
        "{err}"
    );

    // Removed: installed again.
    fs::remove_file(&hook).unwrap();
    let err = fetch_stderr();
    assert!(err.contains("installed the pre-push guard"), "{err}");
    assert!(
        fs::read_to_string(&hook)
            .unwrap()
            .contains("git-remote-enc pre-push")
    );

    // Present but not executable, so git skips it.
    let mut perms = fs::metadata(&hook).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o644);
    fs::set_permissions(&hook, perms).unwrap();
    let err = fetch_stderr();
    assert!(err.contains("is not executable"), "{err}");

    // A shared hooks directory without it.
    fs::remove_file(&hook).unwrap();
    let shared = sb.dir("shared-hooks");
    sb.git_ok(&a, &["config", "core.hooksPath", shared.to_str().unwrap()]);
    let err = fetch_stderr();
    assert!(err.contains("core.hooksPath is set"), "{err}");
    assert!(!shared.join("pre-push").exists());
}

#[test]
fn plain_push_urls_of_encrypted_remotes_are_refused() {
    let sb = Sandbox::new("pushurl");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.commit_text(&a, "one", "1\n");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    // The guard was installed on first contact, as in every clone.
    let hook = fs::read_to_string(a.join(".git/hooks/pre-push")).unwrap();
    assert!(hook.contains("git-remote-enc pre-push"), "{hook}");
    let opted_out = sb.root.join("opted-out");
    sb.git_ok(
        &sb.root,
        &[
            "-c",
            &format!("enc.identity={}", alice.display()),
            "-c",
            &format!("enc.participants={alice_pub}"),
            "-c",
            "enc.installHook=false",
            "clone",
            "-q",
            &url,
            opted_out.to_str().unwrap(),
        ],
    );
    assert!(!opted_out.join(".git/hooks/pre-push").exists());
    let b = sb.clone("bob", &url, &alice);
    assert!(b.join(".git/hooks/pre-push").exists());
    let plain = sb.dir("plain.git");
    sb.git_ok(&plain, &["init", "-q", "--bare"]);
    let plain_has_main = || {
        !sb.git(&plain, &["rev-parse", "-q", "--verify", "refs/heads/main"])
            .stdout
            .is_empty()
    };
    sb.commit_text(&a, "fix", "f\n");

    // A push URL that is not enc:: never runs the helper on push.
    sb.git_ok(
        &a,
        &[
            "remote",
            "set-url",
            "--push",
            "enc",
            plain.to_str().unwrap(),
        ],
    );
    let err = sb.git_fails(&a, &["fetch", "enc"]);
    assert!(err.contains("would push to it in clear"), "{err}");
    let err = sb.git_fails(&a, &["push", "enc", "main"]);
    assert!(err.contains("reroutes it"), "{err}");
    assert!(!plain_has_main());

    // Same with a pushInsteadOf rule, typically in the global config.
    sb.git_ok(&a, &["config", "--unset", "remote.enc.pushurl"]);
    sb.git_ok(&a, &["fetch", "-q", "enc"]);
    sb.git_ok(
        &a,
        &[
            "config",
            "--global",
            &format!("url.{}.pushInsteadOf", plain.display()),
            &url,
        ],
    );
    let err = sb.git_fails(&a, &["fetch", "enc"]);
    assert!(err.contains("would push to it in clear"), "{err}");
    let err = sb.git_fails(&a, &["push", "enc", "main"]);
    assert!(err.contains("reroutes it"), "{err}");
    assert!(!plain_has_main());
}

#[test]
fn log_verifies_history_against_the_accepted_manifest() {
    let sb = Sandbox::new("logchain");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    for n in ["one", "two"] {
        sb.commit_text(&a, n, &format!("{n}\n"));
        sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    }
    let b = sb.clone("bob", &url, &alice);

    // The host forges a first generation with a key of its own, named after
    // Alice and encrypted to her, and slides the real tip on top of it.
    let (mallory, mallory_pub) = sb.keypair("mallory");
    let impostor = format!(
        "{} alice",
        mallory_pub
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ")
    );
    let host2 = sb.dir("host2.git");
    sb.git_ok(&host2, &["init", "-q", "--bare"]);
    let m = sb.repo("mallory");
    sb.commit_text(&m, "one", "forged\n");
    sb.add_remote(
        &m,
        &sb.url(&host2, None),
        &mallory,
        &[&impostor, &alice_pub],
    );
    sb.git_ok(&m, &["push", "-q", "enc", "main"]);
    sb.git_ok(
        &host,
        &[
            "fetch",
            "-q",
            host2.to_str().unwrap(),
            "refs/heads/enc:refs/forged",
        ],
    );
    let forged_tree = sb.git_ok(&host, &["rev-parse", "refs/forged^{tree}"]);
    let forged = sb.git_ok(&host, &["commit-tree", forged_tree.trim(), "-m", "enc"]);
    let tip_tree = sb.git_ok(&host, &["rev-parse", "refs/heads/enc^{tree}"]);
    let tip = sb.git_ok(
        &host,
        &[
            "commit-tree",
            tip_tree.trim(),
            "-p",
            forged.trim(),
            "-m",
            "enc",
        ],
    );
    sb.git_ok(&host, &["update-ref", "refs/heads/enc", tip.trim()]);

    sb.git_ok(&b, &["fetch", "-q", "origin"]);
    let out = sb
        .cmd(&b, "git-remote-enc")
        .args(["log", "origin"])
        .output()
        .unwrap();
    let log = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{log}");
    let (newest, oldest) = log.split_once("\ngeneration 1 ").unwrap();
    assert!(newest.contains(&format!("signed by {alice_pub}")), "{log}");
    assert!(!newest.contains("  not verified:"), "{log}");
    assert!(
        newest.contains("changes relative to generation 1, which is not verified"),
        "{log}"
    );
    assert!(oldest.contains("  not verified:"), "{log}");
    assert!(
        oldest.contains("  signed by SHA256:"),
        "the forgery named its signer: {log}"
    );
}

#[test]
fn a_generation_jump_past_the_history_is_refused() {
    let sb = Sandbox::new("genjump");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.commit_text(&a, "one", "1\n");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    let b = sb.clone("bob", &url, &alice);
    let good = sb.git_ok(&host, &["rev-parse", "refs/heads/enc"]);

    // A participant signs a manifest at the maximum generation: once accepted,
    // no push could follow it.
    sb.forge_manifest(&host, &alice, &[&alice_pub], |text| {
        text.replace("generation 1\n", &format!("generation {}\n", u64::MAX))
    });
    let err = sb.git_fails(&b, &["fetch", "origin"]);
    assert!(
        err.contains("more than the backend history allows"),
        "{err}"
    );
    let out = sb.git(
        &sb.root,
        &[
            "-c",
            &format!("enc.identity={}", alice.display()),
            "-c",
            &format!("enc.participants={alice_pub}"),
            "clone",
            "-q",
            &url,
            "fresh",
        ],
    );
    assert!(!out.status.success());

    // Never accepted, so restoring the branch is not a rollback.
    sb.git_ok(&host, &["update-ref", "refs/heads/enc", good.trim()]);
    sb.git_ok(&b, &["fetch", "-q", "origin"]);
    sb.commit_text(&a, "two", "2\n");
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
}

#[test]
fn a_forged_epoch_does_not_lift_the_first_contact_bound() {
    let sb = Sandbox::new("forged-epoch");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.commit_text(&a, "one", "1\n");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    let b = sb.clone("bob", &url, &alice);
    let good = sb.git_ok(&host, &["rev-parse", "refs/heads/enc"]);
    let good = good.trim();
    let first_contact = |name: &str| {
        let out = sb.git(
            &sb.root,
            &[
                "-c",
                &format!("enc.identity={}", alice.display()),
                "-c",
                &format!("enc.participants={alice_pub}"),
                "clone",
                "-q",
                &url,
                name,
            ],
        );
        assert!(!out.status.success(), "{name} accepted the forged epoch");
        let err = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(
            err.contains("more than the backend history allows"),
            "{err}"
        );
    };

    // A participant pushes an ordinary commit whose manifest claims the
    // history restarted at the maximum generation.
    let max = u64::MAX;
    sb.forge_manifest(&host, &alice, &[&alice_pub], |text| {
        text.replace(
            "generation 1\n",
            &format!("generation {max}\nepoch {max}\n"),
        )
    });
    let err = sb.git_fails(&b, &["fetch", "origin"]);
    assert!(
        err.contains("more than the backend history allows"),
        "{err}"
    );
    first_contact("fresh");

    // Or puts a forged start under it as its first parent, keeping a fast
    // forward with the real history as the second.
    let forged = sb.git_ok(&host, &["rev-parse", "refs/heads/enc^{tree}"]);
    let root = sb.git_ok(
        &host,
        &[
            "commit-tree",
            forged.trim(),
            "-m",
            &format!("enc epoch {max}"),
        ],
    );
    let tip = sb.git_ok(
        &host,
        &[
            "commit-tree",
            forged.trim(),
            "-p",
            root.trim(),
            "-p",
            good,
            "-m",
            "enc",
        ],
    );
    sb.git_ok(&host, &["update-ref", "refs/heads/enc", tip.trim()]);
    let err = sb.git_fails(&b, &["fetch", "origin"]);
    assert!(
        err.contains("more than the backend history allows"),
        "{err}"
    );
    first_contact("fresh2");
}

#[test]
fn a_rewrite_bounds_a_known_clients_generation_by_its_epoch() {
    let sb = Sandbox::new("rewrite-bound");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.commit_text(&a, "one", "1\n");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    let b = sb.clone("bob", &url, &alice);
    let good = sb.git_ok(&host, &["rev-parse", "refs/heads/enc"]);
    let good = good.trim();
    // A participant's rewrite: a single root commit starting at `epoch`, so
    // the generation may be `epoch` at most.
    let rewrite = |generation: u64| {
        sb.git_ok(&host, &["update-ref", "refs/heads/enc", good]);
        sb.forge_manifest(&host, &alice, &[&alice_pub], |text| {
            text.replace(
                "generation 1\n",
                &format!("generation {generation}\nepoch 5\n"),
            )
        });
        let tree = sb.git_ok(&host, &["rev-parse", "refs/heads/enc^{tree}"]);
        let root = sb.git_ok(&host, &["commit-tree", tree.trim(), "-m", "enc epoch 5"]);
        sb.git_ok(&host, &["update-ref", "refs/heads/enc", root.trim()]);
    };

    rewrite(6);
    let err = sb.git_fails(&b, &["fetch", "origin"]);
    assert!(
        err.contains("more than the backend history allows"),
        "{err}"
    );
    rewrite(5);
    sb.git_ok(&b, &["fetch", "-q", "origin"]);
}

#[test]
fn an_oversized_manifest_is_not_read() {
    let sb = Sandbox::new("bigmanifest");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.commit_text(&a, "one", "1\n");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);

    // The host swaps in a manifest blob larger than any real one.
    let big = sb.dir("big").join("manifest");
    fs::File::create(&big)
        .unwrap()
        .set_len((64 << 20) + 1)
        .unwrap();
    let oid = sb.git_ok(&host, &["hash-object", "-w", big.to_str().unwrap()]);
    let tree = sb.dir("big").join("tree");
    fs::write(&tree, format!("100644 blob {}\tmanifest\n", oid.trim())).unwrap();
    let out = sb
        .cmd(&host, "git")
        .arg("mktree")
        .stdin(fs::File::open(&tree).unwrap())
        .output()
        .unwrap();
    let tree = String::from_utf8(out.stdout).unwrap();
    let commit = sb.git_ok(
        &host,
        &[
            "commit-tree",
            tree.trim(),
            "-p",
            "refs/heads/enc",
            "-m",
            "enc",
        ],
    );
    sb.git_ok(&host, &["update-ref", "refs/heads/enc", commit.trim()]);

    let err = sb.git_fails(&a, &["fetch", "enc"]);
    assert!(err.contains("over the 67108864-byte limit"), "{err}");
}

#[test]
fn backend_commits_are_anonymous_even_with_commit_signing_on() {
    let sb = Sandbox::new("anon");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.commit_text(&a, "one", "1\n");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    for (k, v) in [
        ("gpg.format", "ssh"),
        ("user.signingkey", alice.to_str().unwrap()),
        ("commit.gpgSign", "true"),
    ] {
        sb.git_ok(&a, &["config", k, v]);
    }
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    let commit = sb.git_ok(&host, &["cat-file", "commit", "refs/heads/enc"]);
    assert!(!commit.contains("gpgsig"), "{commit}");
    assert!(
        commit.contains("author enc <enc@localhost> 1000000000 +0000"),
        "{commit}"
    );
}

#[test]
fn log_flags_a_time_going_backwards() {
    let sb = Sandbox::new("logtime");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.commit_text(&a, "one", "1\n");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    // A participant backdates the next generation.
    sb.forge_manifest(&host, &alice, &[&alice_pub], |text| {
        let text = text.replace("generation 1\n", "generation 2\n");
        let time = text.lines().find(|l| l.starts_with("time ")).unwrap();
        text.replace(time, "time 1000")
    });
    let out = sb
        .cmd(&a, "git-remote-enc")
        .args(["log", "enc"])
        .output()
        .unwrap();
    let log = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(log.starts_with("generation 2 (time 1000,"), "{log}");
    assert!(
        log.contains("  time earlier than the generation before"),
        "{log}"
    );
}

#[test]
fn init_invite_and_join_set_a_remote_up() {
    let sb = Sandbox::new("setup");
    let host = sb.host();
    let host_url = host.to_str().unwrap();
    let (alice, _) = sb.keypair("alice");
    let (bob, bob_pub) = sb.keypair("bob");
    let (carol, _) = sb.keypair("carol");

    let a = sb.repo("alice");
    sb.commit_text(&a, "one", "1\n");
    sb.enc_ok(
        &a,
        &[
            "init",
            "enc",
            host_url,
            "--identity",
            alice.to_str().unwrap(),
        ],
    );
    let (ok, _, err) = sb.enc(&a, &["init", "enc", host_url]);
    assert!(!ok && err.contains("remote enc already exists"), "{err}");
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    let (ok, _, err) = sb.enc(&a, &["init", "again", host_url]);
    assert!(
        !ok && err.contains("already holds an encrypted remote"),
        "{err}"
    );

    // The printed command pins the participants, repository and generation.
    let line = sb.enc_ok(&a, &["invite", "enc", &bob_pub, "--yes"]);
    assert!(line.starts_with("git-remote-enc join 'enc' "), "{line}");
    assert!(
        line.contains("--repo ") && line.contains("--min-generation 2"),
        "{line}"
    );
    let b = sb.repo("bob");
    let join = format!("{} --identity {}", line.trim(), bob.display());
    let out = sb.cmd(&b, "sh").args(["-c", &join]).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        sb.git_ok(&b, &["rev-parse", "refs/remotes/enc/main"]),
        sb.git_ok(&a, &["rev-parse", "main"])
    );
    sb.git_ok(&b, &["checkout", "-q", "-b", "main", "enc/main"]);
    sb.commit_text(&b, "two", "2\n");
    sb.git_ok(&b, &["push", "-q", "enc", "main"]);

    // Someone not invited is told what to send.
    let c = sb.repo("carol");
    let join = format!("{} --identity {}", line.trim(), carol.display());
    let out = sb.cmd(&c, "sh").args(["-c", &join]).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success() && err.contains("If you are not a participant yet"),
        "{err}"
    );

    // Removed by fingerprint, bob reads no more.
    let fp = ssh_key::PublicKey::from_openssh(&bob_pub)
        .unwrap()
        .fingerprint(ssh_key::HashAlg::Sha256)
        .to_string();
    sb.git_ok(&a, &["pull", "-q", "enc", "main"]);
    sb.enc_ok(&a, &["participants", "--remove", &fp, "--yes", "enc"]);
    let out = sb.enc_ok(&a, &["participants", "enc"]);
    assert!(
        !out.contains("bob") && out.contains("the configuration matches"),
        "{out}"
    );
    sb.commit_text(&a, "three", "3\n");
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    sb.git_fails(&b, &["fetch", "enc"]);
}

#[test]
fn install_hook_chain_runs_the_guard_before_an_existing_hook() {
    let sb = Sandbox::new("chain");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let public = sb.dir("public.git");
    sb.git_ok(&public, &["init", "-q", "--bare"]);
    let a = sb.repo("alice");
    sb.commit_text(&a, "one", "1\n");
    sb.git_ok(&a, &["push", "-q", public.to_str().unwrap(), "main"]);
    sb.git_ok(&a, &["remote", "add", "public", public.to_str().unwrap()]);
    sb.git_ok(&a, &["fetch", "-q", "public"]);

    let hook = a.join(".git/hooks/pre-push");
    fs::write(&hook, "#!/usr/bin/env python3\n").unwrap();
    let (ok, _, err) = sb.enc(&a, &["install-hook", "--chain"]);
    assert!(!ok && err.contains("is not a shell script"), "{err}");

    // An existing hook that records its stdin.
    fs::write(
        &hook,
        "#!/bin/sh\ncat > \"$(git rev-parse --git-dir)/seen\"\n",
    )
    .unwrap();
    let mut perms = fs::metadata(&hook).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    fs::set_permissions(&hook, perms).unwrap();
    sb.enc_ok(&a, &["install-hook", "--chain"]);
    assert!(a.join(".git/hooks/pre-push.enc-orig").is_file());
    sb.enc_ok(&a, &["install-hook", "--chain"]);
    assert_eq!(
        fs::read_to_string(&hook)
            .unwrap()
            .matches("git-remote-enc pre-push")
            .count(),
        1
    );

    sb.commit_text(&a, "two", "2\n");
    sb.git_ok(&a, &["push", "-q", "public", "main"]);
    let seen = fs::read_to_string(a.join(".git/seen")).unwrap();
    assert!(
        seen.starts_with("refs/heads/main ") && seen.ends_with('\n'),
        "{seen:?}"
    );

    // The guard itself runs first.
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    sb.commit_text(&a, "secret", "s\n");
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    let err = sb.git_fails(&a, &["push", "public", "main"]);
    assert!(err.contains("refusing to push to public"), "{err}");
}

#[test]
fn doctor_reports_what_would_get_in_the_way() {
    let sb = Sandbox::new("doctor");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.commit_text(&a, "one", "1\n");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    let out = sb.enc_ok(&a, &["doctor", "enc"]);
    assert!(
        out.contains("ok    manifest") && out.contains("ok    participant"),
        "{out}"
    );

    fs::write(a.join(".git/hooks/pre-push"), "#!/bin/sh\n").unwrap();
    let (ok, out, _) = sb.enc(&a, &["doctor", "enc"]);
    assert!(!ok && out.contains("FAIL  pre-push guard"), "{out}");
    // doctor changes nothing.
    assert_eq!(
        fs::read_to_string(a.join(".git/hooks/pre-push")).unwrap(),
        "#!/bin/sh\n"
    );

    // State left from a remote the host deleted.
    sb.git_ok(&host, &["update-ref", "-d", "refs/heads/enc"]);
    let (ok, out, _) = sb.enc(&a, &["doctor", "enc"]);
    assert!(
        !ok && out.contains("FAIL  local state") && out.contains("forget"),
        "{out}"
    );
}

#[test]
fn large_packs_are_split_and_uploaded_in_batches() {
    let sb = Sandbox::new("split");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    sb.git_ok(&a, &["config", "enc.partSize", "64k"]);
    sb.git_ok(&a, &["config", "enc.uploadBatch", "200k"]);
    sb.commit_random(&a, "big", 600_000);
    let out = sb
        .cmd(&a, "git")
        .args(["push", "--progress", "enc", "main"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert!(err.contains("batch 1/"), "{err}");

    // Parts of at most 64 KiB, in their own pushes, and no staging branch
    // left behind.
    let tree = sb.git_ok(&host, &["ls-tree", "-l", "refs/heads/enc"]);
    let parts: Vec<u64> = tree
        .lines()
        .filter(|l| l.contains(".age."))
        .map(|l| l.split_whitespace().nth(3).unwrap().parse().unwrap())
        .collect();
    assert!(parts.len() >= 10, "{tree}");
    assert!(parts.iter().all(|s| *s <= 64 << 10), "{tree}");
    assert!(!tree.contains(".age\t"), "{tree}");
    assert_eq!(
        sb.git_ok(&host, &["for-each-ref", "--format=%(refname)"])
            .trim(),
        "refs/heads/enc"
    );
    // 10 parts of 64 KiB, 3 per 200 KiB batch: 4 staging commits, then the
    // push that merges them.
    assert_eq!(
        sb.git_ok(&host, &["rev-list", "--count", "refs/heads/enc"])
            .trim(),
        "5"
    );
    // Each batch in its own push, and the parts sent once: the last push
    // carries the manifest only.
    let packs = sb.host_pack_sizes(&host);
    assert_eq!(packs.len(), 5, "{packs:?}");
    assert!(
        packs.iter().filter(|s| **s < 10_000).count() == 1,
        "{packs:?}"
    );
    assert!(packs.iter().all(|s| *s < 250_000), "{packs:?}");
    assert!(packs.iter().sum::<u64>() < 700_000, "{packs:?}");

    // A small push afterwards stores one blob.
    sb.commit_text(&a, "small", "x\n");
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    let tree = sb.git_ok(&host, &["ls-tree", "refs/heads/enc"]);
    assert_eq!(
        tree.lines().filter(|l| l.ends_with(".age")).count(),
        1,
        "{tree}"
    );

    let id = alice.to_str().unwrap();
    let out = sb
        .cmd(&sb.root, "git")
        .args([
            "-c",
            &format!("enc.identity={id}"),
            "-c",
            "enc.trustOnFirstUse=true",
            "clone",
            "--progress",
            &url,
            "bob",
        ])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert!(err.contains("decrypting pack 1/2"), "{err}");
    let b = sb.root.join("bob");
    assert_eq!(
        fs::read(b.join("big")).unwrap(),
        fs::read(a.join("big")).unwrap()
    );

    // The staging commits are not generations.
    sb.git_ok(&b, &["config", "remote.origin.enc-identity", id]);
    let log = sb.enc_ok(&b, &["log", "origin"]);
    assert_eq!(log.matches("generation ").count(), 2, "{log}");
    assert!(
        !log.contains("not readable") && !log.contains("warning"),
        "{log}"
    );
}

#[test]
fn a_missing_or_altered_part_fails_the_fetch() {
    let sb = Sandbox::new("bad-part");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    sb.git_ok(&a, &["config", "enc.partSize", "64k"]);
    sb.commit_random(&a, "big", 300_000);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);

    let tree = sb.git_ok(&host, &["ls-tree", "refs/heads/enc"]);
    let first = tree.lines().find(|l| l.ends_with(".age.0000")).unwrap();
    let second = tree.lines().find(|l| l.ends_with(".age.0001")).unwrap();
    let second_oid = second.split_whitespace().nth(2).unwrap();
    let rewrite = |edit: &dyn Fn(&str) -> Option<String>| {
        let lines: String = tree.lines().filter_map(edit).map(|l| l + "\n").collect();
        let dir = sb.dir("forge");
        fs::write(dir.join("tree"), lines).unwrap();
        let mut c = sb.cmd(&host, "git");
        c.args(["mktree"])
            .stdin(fs::File::open(dir.join("tree")).unwrap());
        let t = String::from_utf8(c.output().unwrap().stdout).unwrap();
        let commit = sb.git_ok(&host, &["commit-tree", t.trim(), "-m", "enc"]);
        sb.git_ok(&host, &["update-ref", "refs/heads/enc", commit.trim()]);
    };

    // Part 0 replaced by part 1: same count, wrong content.
    rewrite(&|l: &str| {
        Some(if l == first {
            l.replace(first.split_whitespace().nth(2).unwrap(), second_oid)
        } else {
            l.to_owned()
        })
    });
    let id = alice.to_str().unwrap();
    let clone = |name: &str| {
        sb.git_fails(
            &sb.root,
            &[
                "-c",
                &format!("enc.identity={id}"),
                "-c",
                "enc.trustOnFirstUse=true",
                "clone",
                "-q",
                &url,
                name,
            ],
        )
    };
    let err = clone("bob");
    assert!(err.contains("does not match its manifest name"), "{err}");

    // Part 1 gone: the rest is a truncated pack.
    rewrite(&|l: &str| (l != second).then(|| l.to_owned()));
    let err = clone("carol");
    assert!(err.contains("does not match its manifest name"), "{err}");
}

#[test]
fn concurrent_batched_pushes_lose_nothing() {
    let sb = Sandbox::new("concurrent-batched");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.commit_text(&a, "base", "0\n");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    let b = sb.clone("bob", &url, &alice);
    for r in [&a, &b] {
        sb.git_ok(r, &["config", "enc.partSize", "16k"]);
        sb.git_ok(r, &["config", "enc.uploadBatch", "40k"]);
    }

    for round in 0..3 {
        sb.git_ok(&a, &["checkout", "-q", "-B", &format!("a{round}"), "main"]);
        sb.commit_random(&a, &format!("a{round}.bin"), 100_000);
        sb.git_ok(&b, &["checkout", "-q", "-B", &format!("b{round}"), "main"]);
        sb.commit_random(&b, &format!("b{round}.bin"), 100_000);
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
    assert_eq!(
        sb.git_ok(&host, &["for-each-ref", "--format=%(refname)"])
            .trim(),
        "refs/heads/enc",
        "staging branches left behind"
    );

    let c = sb.clone("carol", &url, &alice);
    for round in 0..3 {
        for who in ["a", "b"] {
            let branch = format!("origin/{who}{round}");
            sb.git_ok(&c, &["rev-list", "--objects", "--missing=error", &branch]);
        }
    }
}

/// A host hook script fragment: run the rest of the line without the hook's
/// repository environment, as an unrelated git command would.
const NO_HOOK_ENV: &str = "env -u GIT_DIR -u GIT_QUARANTINE_PATH -u GIT_OBJECT_DIRECTORY \
                           -u GIT_ALTERNATE_OBJECT_DIRECTORIES -u GIT_PROTOCOL";

#[test]
fn a_push_reported_failed_after_it_landed_lists_its_pack_once() {
    let sb = Sandbox::new("landed");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.commit_text(&a, "base", "0\n");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    sb.git_ok(&a, &["config", "enc.partSize", "16k"]);
    sb.git_ok(&a, &["config", "enc.uploadBatch", "40k"]);

    // The next update of the backend branch lands, then is reported as
    // declined: the host keeps the received objects and moves the branch
    // itself before refusing.
    let mark = sb.root.join("landed");
    sb.host_hook(
        &host,
        "pre-receive",
        &format!(
            "while read old new ref; do\n\
             if [ \"$ref\" = refs/heads/enc ] && [ ! -e '{mark}' ]; then\n\
             touch '{mark}'\n\
             cp -R \"$GIT_QUARANTINE_PATH\"/. objects/ || exit 2\n\
             {NO_HOOK_ENV} git update-ref \"$ref\" \"$new\" \"$old\" || exit 2\n\
             echo 'declined after landing' >&2\n\
             exit 1\n\
             fi\n\
             done\n",
            mark = mark.display()
        ),
    );
    sb.commit_random(&a, "big", 100_000);
    let out = sb
        .cmd(&a, "git")
        .args(["push", "enc", "main"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert!(mark.exists() && err.contains("retrying"), "{err}");

    // The retry neither lists the pack again nor builds another one.
    let ids = sb.pack_ids(&a, "enc");
    assert_eq!(ids.len(), 2, "{ids:?}");
    assert_ne!(ids[0], ids[1]);
    assert_eq!(
        sb.git_ok(&host, &["for-each-ref", "--format=%(refname)"])
            .trim(),
        "refs/heads/enc"
    );
    // Both are recorded as indexed: no fetch downloads them again.
    let have: String = fs::read_dir(a.join(".git/enc"))
        .unwrap()
        .flatten()
        .filter_map(|e| fs::read_to_string(e.path().join("have")).ok())
        .collect();
    assert!(ids.iter().all(|id| have.contains(id.as_str())), "{have}");
    let b = sb.clone("bob", &url, &alice);
    assert_eq!(
        fs::read(b.join("big")).unwrap(),
        fs::read(a.join("big")).unwrap()
    );
}

#[test]
fn a_lost_race_reuses_the_staged_pack() {
    let sb = Sandbox::new("lost-race");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.commit_text(&a, "base", "0\n");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    let b = sb.clone("bob", &url, &alice);
    sb.git_ok(&b, &["checkout", "-q", "-b", "bob"]);
    sb.commit_text(&b, "bob", "b\n");
    sb.git_ok(&a, &["config", "enc.partSize", "16k"]);
    sb.git_ok(&a, &["config", "enc.uploadBatch", "40k"]);

    // Alice's first update of the backend branch lets Bob push first, so
    // the update fails; every update is logged with the pack blobs it adds.
    let log = sb.root.join("updates");
    let mark = sb.root.join("raced");
    sb.host_hook(
        &host,
        "pre-receive",
        &format!(
            "while read old new ref; do\n\
             case \"$ref\" in\n\
             refs/heads/enc)\n\
             echo \"enc $(git diff-tree --name-only \"$old\" \"$new\" | grep '\\.age' | tr '\\n' ' ')\" >>'{log}'\n\
             if [ ! -e '{mark}' ]; then\n\
             touch '{mark}'\n\
             (cd '{bob}' && {NO_HOOK_ENV} git push -q origin bob) </dev/null >&2 || exit 2\n\
             fi;;\n\
             *) echo \"other $ref $new\" >>'{log}';;\n\
             esac\n\
             done\n",
            log = log.display(),
            mark = mark.display(),
            bob = b.display()
        ),
    );
    sb.commit_random(&a, "big", 100_000);
    let out = sb
        .cmd(&a, "git")
        .args(["push", "enc", "main"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert!(err.contains("retrying"), "{err}");

    // Alice's two attempts added the same pack, uploaded once, on one
    // staging branch, which is deleted at the end.
    let updates = fs::read_to_string(&log).unwrap();
    let enc: Vec<&str> = updates.lines().filter(|l| l.starts_with("enc ")).collect();
    assert_eq!(enc.len(), 3, "{updates}");
    assert!(enc[0].contains(".age.0000"), "{updates}");
    assert_eq!(enc[0], enc[2], "{updates}");
    assert_ne!(enc[0], enc[1], "{updates}");
    let staging: Vec<(&str, &str)> = updates
        .lines()
        .filter_map(|l| l.strip_prefix("other "))
        .map(|l| l.split_once(' ').unwrap())
        .collect();
    assert!(
        staging
            .iter()
            .all(|(r, _)| *r == staging[0].0 && r.starts_with("refs/heads/enc-upload-")),
        "{updates}"
    );
    let deleted = |new: &str| new.bytes().all(|c| c == b'0');
    let (deletions, uploads): (Vec<&(&str, &str)>, Vec<_>) =
        staging.iter().partition(|(_, n)| deleted(n));
    assert_eq!(deletions.len(), 1, "{updates}");
    assert!(deleted(staging.last().unwrap().1), "{updates}");
    let count = |extra: &[&str]| -> usize {
        let mut args = vec!["rev-list", "--count"];
        args.extend_from_slice(extra);
        args.push("refs/heads/enc");
        sb.git_ok(&host, &args).trim().parse().unwrap()
    };
    assert_eq!(
        uploads.len(),
        count(&[]) - count(&["--first-parent"]),
        "{updates}"
    );
    assert_eq!(
        sb.git_ok(&host, &["for-each-ref", "--format=%(refname)"])
            .trim(),
        "refs/heads/enc"
    );

    let ids = sb.pack_ids(&a, "enc");
    assert_eq!(ids.len(), 3, "{ids:?}");
    let c = sb.clone("carol", &url, &alice);
    sb.git_ok(&c, &["rev-parse", "--verify", "origin/bob"]);
    assert_eq!(
        fs::read(c.join("big")).unwrap(),
        fs::read(a.join("big")).unwrap()
    );
}

#[test]
fn a_failed_staging_push_removes_the_staging_branch() {
    let sb = Sandbox::new("staging-fails");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.commit_text(&a, "base", "0\n");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    sb.git_ok(&a, &["config", "enc.partSize", "16k"]);
    sb.git_ok(&a, &["config", "enc.uploadBatch", "40k"]);

    // Refuse the second batch; allow and log branch deletion.
    let counter = sb.root.join("uploads");
    let deletions = sb.root.join("deletions");
    sb.host_hook(
        &host,
        "pre-receive",
        &format!(
            "while read old new ref; do\n\
             case \"$ref\" in refs/heads/enc-upload-*)\n\
             case \"$new\" in *[!0]*) ;; *) echo x >>'{deletions}'; continue;; esac\n\
             echo x >>'{counter}'\n\
             if [ \"$(wc -l <'{counter}')\" -ge 2 ]; then echo 'batch refused' >&2; exit 1; fi;;\n\
             esac\n\
             done\n",
            counter = counter.display(),
            deletions = deletions.display()
        ),
    );
    sb.commit_random(&a, "big", 100_000);
    let err = sb.git_fails(&a, &["push", "enc", "main"]);
    assert!(err.contains("batch refused"), "{err}");
    assert_eq!(
        sb.git_ok(&host, &["for-each-ref", "--format=%(refname)"])
            .trim(),
        "refs/heads/enc"
    );
    assert_eq!(sb.pack_ids(&a, "enc").len(), 1);

    // The first batch refused: there is no branch to delete.
    let err = sb.git_fails(&a, &["push", "enc", "main"]);
    assert!(err.contains("batch refused"), "{err}");
    assert!(!err.contains("upload branch"), "{err}");
    assert_eq!(fs::read_to_string(&deletions).unwrap().lines().count(), 1);

    fs::remove_file(host.join("hooks/pre-receive")).unwrap();
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    assert_eq!(sb.pack_ids(&a, "enc").len(), 2);
}

#[test]
fn progress_follows_git() {
    let sb = Sandbox::new("progress");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    sb.commit_random(&a, "f", 100_000);
    let push = |args: &[&str]| {
        let out = sb.cmd(&a, "git").args(args).output().unwrap();
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stderr).into_owned()
    };
    // Completed meters, as git closes them.
    let done = |err: &str, meter: &str| {
        err.split(['\r', '\n'])
            .filter(|l| l.starts_with(meter) && l.ends_with(", done."))
            .count()
    };
    let err = push(&["push", "--progress", "enc", "main"]);
    // pack-objects, then the backend push.
    assert_eq!(done(&err, "Writing objects: 100%"), 2, "{err}");
    // A new remote's missing branch is expected, not reported.
    assert!(!err.contains("fatal:"), "{err}");

    let id = alice.to_str().unwrap();
    let clone = |name: &str, flag: &str| {
        let out = sb
            .cmd(&sb.root, "git")
            .args([
                "-c",
                &format!("enc.identity={id}"),
                "-c",
                "enc.trustOnFirstUse=true",
                "-c",
                "enc.installHook=false",
                // The backend fetch indexes rather than unpacks, so its
                // meter shows however short the download.
                "-c",
                "fetch.unpackLimit=1",
                "clone",
                flag,
                &url,
                name,
            ])
            .output()
            .unwrap();
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stderr).into_owned()
    };
    let err = clone("bob", "--progress");
    assert!(err.contains("enc: decrypting pack 1/1"), "{err}");
    // The backend fetch, then index-pack.
    assert_eq!(done(&err, "Receiving objects: 100%"), 2, "{err}");
    let err = clone("carol", "-q");
    assert!(
        !err.contains("decrypting") && !err.contains("objects"),
        "{err}"
    );
}

#[test]
fn repack_merges_the_packs_in_place() {
    let sb = Sandbox::new("repack");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    for i in 0..3 {
        sb.commit_random(&a, &format!("f{i}"), 20_000);
        sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    }
    // A branch pushed then deleted: its objects are reachable from no ref.
    sb.git_ok(&a, &["checkout", "-q", "-b", "tmp"]);
    sb.commit_random(&a, "gone", 20_000);
    let gone = sb.git_ok(&a, &["rev-parse", "HEAD"]);
    sb.git_ok(&a, &["push", "-q", "enc", "tmp"]);
    sb.git_ok(&a, &["push", "-q", "enc", ":tmp"]);
    sb.git_ok(&a, &["checkout", "-q", "main"]);
    // An annotated tag on an older commit: the snapshot holds it, peeled.
    sb.git_ok(&a, &["tag", "-a", "-m", "v1", "v1", "main~2"]);
    sb.git_ok(&a, &["push", "-q", "enc", "v1"]);
    let b = sb.clone("bob", &url, &alice);
    let commits = |host: &Path| -> u32 {
        sb.git_ok(host, &["rev-list", "--count", "refs/heads/enc"])
            .trim()
            .parse()
            .unwrap()
    };
    let before = commits(&host);

    let (ok, _, err) = sb.enc(&a, &["repack", "enc"]);
    assert!(ok, "{err}");
    // A snapshot of the tips, and the history behind them.
    assert!(err.contains("5 packs") && err.contains("into 2"), "{err}");
    let tree = sb.git_ok(&host, &["ls-tree", "refs/heads/enc"]);
    assert_eq!(tree.lines().count(), 3, "{tree}");
    assert_eq!(commits(&host), before + 1);
    let m = sb.enc_ok(&a, &["manifest", "enc"]);
    let tip = sb.git_ok(&a, &["rev-parse", "main"]);
    let snapshot = m.lines().find(|l| l.starts_with("snapshot ")).unwrap();
    let first_pack = m.lines().find(|l| l.starts_with("pack ")).unwrap();
    assert_eq!(
        snapshot.split(' ').nth(1),
        first_pack.split(' ').nth(1),
        "{m}"
    );
    let tagged = sb.git_ok(&a, &["rev-parse", "v1^{commit}"]);
    let mut want = vec![tip.trim(), tagged.trim()];
    want.sort_unstable();
    let second_pack = m.lines().filter(|l| l.starts_with("pack ")).nth(1).unwrap();
    assert_eq!(
        snapshot.split(' ').nth(2),
        second_pack.split(' ').nth(1),
        "{m}"
    );
    assert_eq!(snapshot.split(' ').skip(3).collect::<Vec<_>>(), want, "{m}");

    // Existing clones carry on, in both directions.
    sb.commit_text(&b, "b", "b\n");
    sb.git_ok(&b, &["push", "-q", "origin", "main"]);
    // Later pushes, and participant changes, carry the snapshot forward.
    let snapshot_now = || {
        let m = sb.enc_ok(&a, &["manifest", "enc"]);
        m.lines()
            .find(|l| l.starts_with("snapshot "))
            .map(str::to_owned)
    };
    assert_eq!(snapshot_now().as_deref(), Some(snapshot));
    let (_, dave_pub) = sb.keypair("dave");
    sb.git_ok(
        &a,
        &["config", "--add", "remote.enc.enc-participants", &dave_pub],
    );
    sb.enc_ok(&a, &["participants", "--apply", "enc"]);
    assert_eq!(snapshot_now().as_deref(), Some(snapshot));
    let out = sb.git(&a, &["pull", "-q", "enc", "main"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!String::from_utf8_lossy(&out.stderr).contains("warning"));

    let c = sb.clone("carol", &url, &alice);
    assert_eq!(
        fs::read(c.join("f0")).unwrap(),
        fs::read(a.join("f0")).unwrap()
    );
    assert_eq!(fs::read_to_string(c.join("b")).unwrap(), "b\n");
    assert_eq!(
        sb.git_ok(&c, &["rev-parse", "v1^{commit}"]),
        sb.git_ok(&a, &["rev-parse", "v1^{commit}"])
    );
    assert!(
        !sb.git(&c, &["cat-file", "-e", gone.trim()])
            .status
            .success()
    );
    let log = sb.enc_ok(&c, &["log", "origin"]);
    assert!(
        log.contains("repacked: its packs replace all earlier ones"),
        "{log}"
    );
    assert!(!log.contains("warning"), "{log}");
}

#[test]
fn repack_of_a_single_commit_has_no_history_pack() {
    let sb = Sandbox::new("repack-single");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    sb.commit_text(&a, "f", "f\n");
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    sb.git_ok(&a, &["push", "-q", "enc", "main:other"]);

    let (ok, _, err) = sb.enc(&a, &["repack", "enc"]);
    assert!(ok, "{err}");
    assert!(err.contains("into 1"), "{err}");
    let m = sb.enc_ok(&a, &["manifest", "enc"]);
    let tip = sb.git_ok(&a, &["rev-parse", "main"]);
    let pack = m.lines().find(|l| l.starts_with("pack ")).unwrap();
    assert_eq!(
        m.lines().filter(|l| l.starts_with("pack ")).count(),
        1,
        "{m}"
    );
    assert_eq!(
        m.lines().find(|l| l.starts_with("snapshot ")),
        Some(&*format!(
            "snapshot {} - {}",
            pack.split(' ').nth(1).unwrap(),
            tip.trim()
        )),
        "{m}"
    );
    let c = sb.clone("carol", &url, &alice);
    assert_eq!(fs::read_to_string(c.join("f")).unwrap(), "f\n");
}

#[test]
fn repack_uploads_its_packs_in_shared_batches() {
    let sb = Sandbox::new("repack-batched");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    // One file rewritten: the snapshot holds its last version, the history
    // the two before.
    for _ in 0..3 {
        sb.commit_random(&a, "f", 40_000);
        sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    }
    // Two whole parts per batch: the snapshot's last part shares one with
    // the history's first.
    sb.git_ok(&a, &["config", "enc.partSize", "16k"]);
    sb.git_ok(&a, &["config", "enc.uploadBatch", "36k"]);

    let (ok, _, err) = sb.enc(&a, &["repack", "enc"]);
    assert!(ok, "{err}");
    let m = sb.enc_ok(&a, &["manifest", "enc"]);
    let packs: Vec<&str> = m
        .lines()
        .filter_map(|l| l.strip_prefix("pack "))
        .map(|l| l.split(' ').next().unwrap())
        .collect();
    assert_eq!(packs.len(), 2, "{m}");
    let snapshot = m.lines().find(|l| l.starts_with("snapshot ")).unwrap();
    assert_eq!(
        snapshot.split(' ').take(3).collect::<Vec<_>>(),
        ["snapshot", packs[0], packs[1]],
        "{m}"
    );
    assert_eq!(
        sb.git_ok(&host, &["for-each-ref", "--format=%(refname)"])
            .trim(),
        "refs/heads/enc"
    );
    // A staging commit carries parts of both packs.
    let commits = sb.git_ok(&host, &["rev-list", "refs/heads/enc"]);
    let spans = commits.lines().any(|c| {
        let added = sb.git_ok(
            &host,
            &[
                "diff-tree",
                "-r",
                "--root",
                "--no-commit-id",
                "--name-only",
                "--diff-filter=A",
                c,
            ],
        );
        packs
            .iter()
            .all(|p| added.lines().any(|n| n.starts_with(&format!("{p}.age."))))
    });
    assert!(spans, "{commits}");

    let c = sb.clone("carol", &url, &alice);
    assert_eq!(
        fs::read(c.join("f")).unwrap(),
        fs::read(a.join("f")).unwrap()
    );
    assert_eq!(sb.git_ok(&c, &["rev-list", "--count", "main"]).trim(), "3");
}

#[test]
fn repack_can_rewrite_the_backend_history() {
    let sb = Sandbox::new("repack-rewrite");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    for i in 0..3 {
        sb.commit_random(&a, &format!("f{i}"), 20_000);
        sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    }
    let b = sb.clone("bob", &url, &alice);
    let old_blobs: Vec<String> = sb
        .git_ok(&host, &["ls-tree", "refs/heads/enc"])
        .lines()
        .filter(|l| l.ends_with(".age"))
        .map(|l| l.split_whitespace().nth(2).unwrap().to_owned())
        .collect();
    assert_eq!(old_blobs.len(), 3);

    let (ok, _, err) = sb.enc(&a, &["repack", "--rewrite-history", "enc"]);
    assert!(ok, "{err}");
    assert_eq!(
        sb.git_ok(&host, &["rev-list", "--count", "refs/heads/enc"])
            .trim(),
        "1"
    );

    // A participant's rewrite is announced, not reported as the host's.
    let out = sb.git(&b, &["pull", "-q", "origin", "main"]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert!(err.contains("was repacked at generation 4"), "{err}");
    assert!(!err.contains("warning"), "{err}");
    sb.commit_text(&b, "b", "b\n");
    sb.git_ok(&b, &["push", "-q", "origin", "main"]);
    sb.git_ok(&a, &["pull", "-q", "enc", "main"]);
    assert_eq!(fs::read_to_string(a.join("b")).unwrap(), "b\n");

    // A first contact accepts generation 5 on a history of two commits.
    let c = sb.clone("carol", &url, &alice);
    assert_eq!(
        fs::read(c.join("f2")).unwrap(),
        fs::read(a.join("f2")).unwrap()
    );
    let log = sb.enc_ok(&c, &["log", "origin"]);
    assert_eq!(log.matches("generation ").count(), 2, "{log}");
    assert!(log.contains("dropping the history before it"), "{log}");
    assert!(
        !log.contains("warning") && !log.contains("missing"),
        "{log}"
    );

    // Once the host prunes, the old blobs are gone.
    sb.git_ok(&host, &["reflog", "expire", "--expire=now", "--all"]);
    sb.git_ok(&host, &["gc", "-q", "--prune=now"]);
    for blob in &old_blobs {
        assert!(!sb.git(&host, &["cat-file", "-e", blob]).status.success());
    }
}

/// Install a pre-receive hook on `host` that logs every update of the
/// backend branch with the pack blobs it changes, and runs `racer` in
/// `dir` before the first one is applied, so that one loses a race.
fn race_first_update(sb: &Sandbox, host: &Path, dir: &Path, racer: &str) -> PathBuf {
    let log = sb.root.join("updates");
    let mark = sb.root.join("raced");
    sb.host_hook(
        host,
        "pre-receive",
        &format!(
            "while read old new ref; do\n\
             case \"$ref\" in\n\
             refs/heads/enc)\n\
             echo \"enc $(git diff-tree --name-only \"$old\" \"$new\" | grep '\\.age' | tr '\\n' ' ')\" >>'{log}'\n\
             if [ ! -e '{mark}' ]; then\n\
             touch '{mark}'\n\
             (cd '{dir}' && {NO_HOOK_ENV} {racer}) </dev/null >&2 || exit 2\n\
             fi;;\n\
             esac\n\
             done\n",
            log = log.display(),
            mark = mark.display(),
            dir = dir.display()
        ),
    );
    log
}

/// The backend branch updates `race_first_update` logged.
fn enc_updates(log: &Path) -> Vec<String> {
    fs::read_to_string(log)
        .unwrap()
        .lines()
        .filter(|l| l.starts_with("enc "))
        .map(str::to_owned)
        .collect()
}

#[test]
fn a_push_that_lost_a_race_to_a_repack_rebuilds_its_pack() {
    let sb = Sandbox::new("lost-race-repack");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.commit_text(&a, "base", "0\n");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    sb.git_ok(&a, &["checkout", "-q", "-b", "tmp"]);
    sb.commit_random(&a, "gone", 20_000);
    sb.git_ok(&a, &["push", "-q", "enc", "tmp"]);
    let b = sb.clone("bob", &url, &alice);

    // Alice's first attempt leaves out what tmp reaches; Bob deletes tmp
    // and repacks, so no pack holds it any more.
    sb.git_ok(&a, &["checkout", "-q", "-b", "feat"]);
    sb.commit_random(&a, "feat", 20_000);
    let log = race_first_update(
        &sb,
        &host,
        &b,
        "sh -c 'git push -q origin :tmp && git-remote-enc repack origin'",
    );
    let out = sb
        .cmd(&a, "git")
        .args(["push", "enc", "feat"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert!(err.contains("retrying"), "{err}");

    // Alice's attempts, Bob's deletion and repack.
    let enc = enc_updates(&log);
    assert_eq!(enc.len(), 4, "{enc:?}");
    assert_ne!(enc[0], enc[3], "{enc:?}");
    let ids = sb.pack_ids(&a, "enc");
    assert_eq!(ids.len(), 2, "{ids:?}");
    assert!(
        ids.iter().all(|id| !enc[0].contains(id.as_str())),
        "{enc:?}"
    );
    let c = sb.clone("carol", &url, &alice);
    sb.git_ok(&c, &["checkout", "-q", "feat"]);
    for f in ["feat", "gone"] {
        assert_eq!(fs::read(c.join(f)).unwrap(), fs::read(a.join(f)).unwrap());
    }
}

#[test]
fn a_repack_that_lost_a_race_reuses_its_pack_for_the_same_refs() {
    let sb = Sandbox::new("repack-lost-race");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let (_, carol_pub) = sb.keypair("carol");
    let a = sb.repo("alice");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    for i in 0..2 {
        sb.commit_random(&a, &format!("f{i}"), 20_000);
        sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    }
    let b = sb.clone("bob", &url, &alice);

    // Bob changes the participants, not the refs.
    let log = race_first_update(
        &sb,
        &host,
        &b,
        &format!("git-remote-enc participants --add '{carol_pub}' --yes origin"),
    );
    let (ok, _, err) = sb.enc(&a, &["repack", "enc"]);
    assert!(ok, "{err}");
    assert!(err.contains("retrying"), "{err}");

    let enc = enc_updates(&log);
    assert_eq!(enc.len(), 3, "{enc:?}");
    assert_eq!(enc[0], enc[2], "{enc:?}");
    // The snapshot and history packs of the first attempt.
    let ids = sb.pack_ids(&a, "enc");
    assert_eq!(ids.len(), 2, "{ids:?}");
    for id in &ids {
        assert!(enc[0].contains(&format!("{id}.age")), "{enc:?}");
    }
    assert!(
        sb.enc_ok(&a, &["manifest", "enc"]).contains(&carol_pub),
        "the racer's participant change is kept"
    );
    let c = sb.clone("carol", &url, &alice);
    assert_eq!(
        fs::read(c.join("f1")).unwrap(),
        fs::read(a.join("f1")).unwrap()
    );
}

#[test]
fn a_repack_reported_failed_after_it_landed_is_done() {
    let sb = Sandbox::new("repack-landed");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    for i in 0..2 {
        sb.commit_random(&a, &format!("f{i}"), 20_000);
        sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    }
    let commits = || -> u32 {
        sb.git_ok(&host, &["rev-list", "--count", "refs/heads/enc"])
            .trim()
            .parse()
            .unwrap()
    };
    let before = commits();

    // The repack lands, then is reported as declined.
    let mark = sb.root.join("landed");
    sb.host_hook(
        &host,
        "pre-receive",
        &format!(
            "while read old new ref; do\n\
             if [ \"$ref\" = refs/heads/enc ] && [ ! -e '{mark}' ]; then\n\
             touch '{mark}'\n\
             cp -R \"$GIT_QUARANTINE_PATH\"/. objects/ || exit 2\n\
             {NO_HOOK_ENV} git update-ref \"$ref\" \"$new\" \"$old\" || exit 2\n\
             echo 'declined after landing' >&2\n\
             exit 1\n\
             fi\n\
             done\n",
            mark = mark.display()
        ),
    );
    let (ok, _, err) = sb.enc(&a, &["repack", "enc"]);
    assert!(ok, "{err}");
    assert!(mark.exists() && err.contains("retrying"), "{err}");
    assert!(err.contains("into 2"), "{err}");
    // Not repacked a second time.
    assert_eq!(commits(), before + 1);
    assert_eq!(sb.pack_ids(&a, "enc").len(), 2);
    let c = sb.clone("carol", &url, &alice);
    assert_eq!(
        fs::read(c.join("f1")).unwrap(),
        fs::read(a.join("f1")).unwrap()
    );
}

#[test]
fn a_host_refusing_the_rewrite_leaves_the_remote_unchanged() {
    let sb = Sandbox::new("repack-rewrite-refused");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    for i in 0..2 {
        sb.commit_random(&a, &format!("f{i}"), 20_000);
        sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    }
    sb.git_ok(&host, &["config", "receive.denyNonFastForwards", "true"]);
    let tip = sb.git_ok(&host, &["rev-parse", "refs/heads/enc"]);

    let (ok, _, err) = sb.enc(&a, &["repack", "--rewrite-history", "enc"]);
    assert!(!ok, "{err}");
    assert!(err.contains("Allowed to force push"), "{err}");
    assert_eq!(sb.git_ok(&host, &["rev-parse", "refs/heads/enc"]), tip);
    assert_eq!(
        sb.git_ok(&host, &["for-each-ref", "--format=%(refname)"])
            .trim(),
        "refs/heads/enc"
    );
    assert_eq!(sb.pack_ids(&a, "enc").len(), 2);
}

/// The helper's backend repository of the only encrypted remote of `repo`.
fn backend_repo(repo: &Path) -> PathBuf {
    let dirs: Vec<PathBuf> = fs::read_dir(repo.join(".git/enc"))
        .unwrap()
        .flatten()
        .map(|e| e.path().join("backend.git"))
        .filter(|p| p.exists())
        .collect();
    assert_eq!(dirs.len(), 1, "{dirs:?}");
    dirs.into_iter().next().unwrap()
}

/// Bytes of the files under `d`.
fn dir_size(d: &Path) -> u64 {
    fs::read_dir(d)
        .map(|it| {
            it.flatten()
                .map(|e| match e.metadata() {
                    Ok(m) if m.is_dir() => dir_size(&e.path()),
                    Ok(m) => m.len(),
                    Err(_) => 0,
                })
                .sum()
        })
        .unwrap_or(0)
}

/// Check that `repo`'s backend keeps the tip's commit, tree and manifest
/// and passes repack, gc and fsck with lazy fetching disabled.
fn assert_backend_sound(sb: &Sandbox, repo: &Path) {
    let backend = backend_repo(repo);
    let git = |args: &[&str]| {
        let out = sb
            .cmd(repo, "git")
            .env("GIT_NO_LAZY_FETCH", "1")
            .arg("--git-dir")
            .arg(&backend)
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}: git {args:?}: {}",
            backend.display(),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    };
    let tip = git(&["rev-parse", "refs/enc/tip"]);
    let tip = tip.trim();
    for o in [tip, &format!("{tip}^{{tree}}"), &format!("{tip}:manifest")] {
        git(&["cat-file", "-e", o]);
    }
    git(&["repack", "-d", "-q"]);
    git(&["fsck", "--connectivity-only"]);
    git(&["fsck", "--no-progress"]);
    git(&["gc", "--auto", "-q"]);
    assert!(!backend.join("gc.log").exists(), "{}", backend.display());
    git(&[
        "-c",
        "repack.writeBitmaps=false",
        "repack",
        "-a",
        "-d",
        "-q",
    ]);
    // With bitmaps, which need a pack closed over its non-promisor objects:
    // every landed push is sealed.
    git(&["gc", "-q"]);
}

#[test]
fn the_backend_stays_out_of_the_user_repository() {
    let sb = Sandbox::new("backend-repo");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    sb.commit_random(&a, "big", 2_000_000);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    let pack_blob = sb
        .git_ok(&host, &["ls-tree", "refs/heads/enc"])
        .lines()
        .find(|l| l.ends_with(".age"))
        .unwrap()
        .split_whitespace()
        .nth(2)
        .unwrap()
        .to_owned();

    let b = sb.clone("bob", &url, &alice);
    // Neither the user's repository nor, once the pack is pushed or indexed,
    // the backend repository keeps the ciphertext.
    for r in [&a, &b] {
        assert_eq!(sb.git_ok(r, &["for-each-ref", "refs/enc"]), "");
        assert!(!sb.git(r, &["cat-file", "-e", &pack_blob]).status.success());
        let backend = backend_repo(r);
        assert!(
            dir_size(&backend) < 500_000,
            "{}: {}",
            backend.display(),
            dir_size(&backend)
        );
        assert_backend_sound(&sb, r);
    }
    // And the next push and fetch do without it.
    sb.commit_text(&b, "g", "y\n");
    sb.git_ok(&b, &["push", "-q", "origin", "main"]);
    sb.git_ok(&a, &["pull", "-q", "enc", "main"]);
    assert_eq!(fs::read_to_string(a.join("g")).unwrap(), "y\n");
    assert_backend_sound(&sb, &b);
    assert_backend_sound(&sb, &a);
    // A push that stores no blob is sealed too.
    sb.git_ok(&a, &["push", "-q", "enc", "main:tmp"]);
    sb.git_ok(&a, &["push", "-q", "enc", "--delete", "tmp"]);
    assert_backend_sound(&sb, &a);
    // Several pushes, then a repack, each fetched by the other.
    for i in 0..3 {
        sb.commit_text(&a, "h", &format!("{i}\n"));
        sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    }
    sb.enc_ok(&a, &["repack", "enc"]);
    sb.git_ok(&b, &["pull", "-q", "origin", "main"]);
    assert_eq!(fs::read_to_string(b.join("h")).unwrap(), "2\n");
    for r in [&a, &b] {
        assert_backend_sound(&sb, r);
    }
    assert_eq!(
        fs::read(b.join("big")).unwrap(),
        fs::read(a.join("big")).unwrap()
    );

    // Listing reads the manifest only: the pack blob stays on the host.
    let c = sb.repo("carol");
    sb.git_ok(
        &c,
        &[
            "-c",
            &format!("enc.identity={}", alice.to_str().unwrap()),
            "-c",
            "enc.trustOnFirstUse=true",
            "ls-remote",
            &url,
        ],
    );
    let backend = backend_repo(&c);
    let present = sb
        .cmd(&c, "git")
        .env("GIT_NO_LAZY_FETCH", "1")
        .args([
            "--git-dir",
            backend.to_str().unwrap(),
            "cat-file",
            "-e",
            &pack_blob,
        ])
        .output()
        .unwrap();
    assert!(!present.status.success(), "the pack blob was downloaded");
}

#[test]
fn a_pushed_part_over_the_big_file_threshold_is_dropped_too() {
    let sb = Sandbox::new("backend-bigfile");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    sb.commit_random(&a, "big", 2_000_000);
    // `hash-object` writes the part into a pack of its own, not loose.
    let out = sb
        .cmd(&a, "git")
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "core.bigFileThreshold")
        .env("GIT_CONFIG_VALUE_0", "100k")
        .args(["push", "-q", "enc", "main"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let backend = backend_repo(&a);
    assert!(
        dir_size(&backend) < 500_000,
        "{}: {}",
        backend.display(),
        dir_size(&backend)
    );
    assert_backend_sound(&sb, &a);
    let b = sb.clone("bob", &url, &alice);
    assert_eq!(
        fs::read(b.join("big")).unwrap(),
        fs::read(a.join("big")).unwrap()
    );
}

#[test]
fn transport_settings_of_the_repository_apply_to_the_backend() {
    let sb = Sandbox::new("insteadof");
    let host = sb.host();
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    // Only this repository's config knows where `vault:` is.
    sb.git_ok(
        &a,
        &[
            "config",
            &format!("url.{}.insteadOf", host.display()),
            "vault:",
        ],
    );
    sb.add_remote(&a, "enc::vault:", &alice, &[&alice_pub]);
    sb.commit_text(&a, "f", "x\n");
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    sb.commit_text(&a, "g", "y\n");
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    assert_eq!(
        sb.git_ok(&host, &["rev-list", "--count", "refs/heads/enc"])
            .trim(),
        "2"
    );
}

#[test]
fn a_clone_from_before_the_backend_repository_carries_on() {
    let sb = Sandbox::new("legacy");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    sb.commit_text(&a, "f", "x\n");
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    let b = sb.clone("bob", &url, &alice);

    // As v0.1.0 left it: the backend branch tracked by a ref of the user's
    // repository, objects included, and no backend repository.
    let backend = backend_repo(&b);
    let key = backend
        .parent()
        .unwrap()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let legacy = format!("refs/enc/{key}");
    sb.git_ok(
        &b,
        &[
            "fetch",
            "-q",
            backend.to_str().unwrap(),
            &format!("refs/enc/tip:{legacy}"),
        ],
    );
    fs::remove_dir_all(&backend).unwrap();

    sb.commit_text(&a, "g", "y\n");
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    let out = sb.git(&b, &["pull", "-q", "origin", "main"]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    // Still the remote it trusted: no first contact, no rewrite warning.
    assert!(
        !err.contains("first contact") && !err.contains("warning"),
        "{err}"
    );
    assert_eq!(fs::read_to_string(b.join("g")).unwrap(), "y\n");
    assert_eq!(sb.git_ok(&b, &["for-each-ref", "refs/enc"]), "");
    backend_repo(&b);
}

#[test]
fn hosts_without_partial_clone_support_still_work() {
    let sb = Sandbox::new("no-filter");
    let host = sb.host();
    sb.git_ok(&host, &["config", "uploadpack.allowFilter", "false"]);
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    sb.commit_random(&a, "big", 2_000_000);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    let b = sb.clone("bob", &url, &alice);
    assert_eq!(
        fs::read(b.join("big")).unwrap(),
        fs::read(a.join("big")).unwrap()
    );
    sb.commit_text(&b, "g", "y\n");
    sb.git_ok(&b, &["push", "-q", "origin", "main"]);
    sb.git_ok(&a, &["pull", "-q", "enc", "main"]);
}

#[test]
fn the_backend_repository_has_the_object_format_of_the_user_repository() {
    let sb = Sandbox::new("object-format");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    // A SHA-1 repository and host, under a SHA-256 default.
    let push = |file: &str| {
        sb.commit_text(&a, file, "x\n");
        let out = sb
            .cmd(&a, "git")
            .env("GIT_DEFAULT_HASH", "sha256")
            .args(["push", "-q", "enc", "main"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    push("f");
    push("g");
    let backend = backend_repo(&a);
    assert_eq!(
        sb.git_ok(
            &a,
            &[
                "--git-dir",
                backend.to_str().unwrap(),
                "rev-parse",
                "--show-object-format",
            ],
        )
        .trim(),
        "sha1"
    );
    let b = sb.clone("bob", &url, &alice);
    assert_eq!(fs::read_to_string(b.join("g")).unwrap(), "x\n");
}

#[test]
fn a_backend_without_the_pack_blobs_pushes_and_repacks() {
    let sb = Sandbox::new("no-pack-blobs");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    sb.commit_random(&a, "big", 2_000_000);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    let pack_blob = sb
        .git_ok(&host, &["ls-tree", "refs/heads/enc"])
        .lines()
        .find(|l| l.ends_with(".age"))
        .unwrap()
        .split_whitespace()
        .nth(2)
        .unwrap()
        .to_owned();
    let b = sb.clone("bob", &url, &alice);
    // As a clone from before the backend repository: packs indexed, their
    // blobs on the host only.
    fs::remove_dir_all(backend_repo(&b)).unwrap();

    sb.commit_text(&b, "g", "y\n");
    sb.git_ok(&b, &["push", "-q", "origin", "main"]);
    let (ok, _, err) = sb.enc(&b, &["repack", "origin"]);
    assert!(ok, "{err}");
    assert!(err.contains("2 packs") && err.contains("into 2"), "{err}");
    let present = sb
        .cmd(&b, "git")
        .env("GIT_NO_LAZY_FETCH", "1")
        .args([
            "--git-dir",
            backend_repo(&b).to_str().unwrap(),
            "cat-file",
            "-e",
            &pack_blob,
        ])
        .output()
        .unwrap();
    assert!(!present.status.success(), "the pack blob was downloaded");

    sb.git_ok(&a, &["pull", "-q", "enc", "main"]);
    assert_eq!(fs::read_to_string(a.join("g")).unwrap(), "y\n");
    let c = sb.clone("carol", &url, &alice);
    assert_eq!(
        fs::read(c.join("big")).unwrap(),
        fs::read(a.join("big")).unwrap()
    );
}

/// Alice's repository with `n` pushes, each rewriting `data`, repacked.
fn repacked_history(sb: &Sandbox, n: usize) -> (PathBuf, String, PathBuf) {
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    // Over the backend's 1 MiB filter once repacked: the history pack stays
    // on the host until needed.
    for _ in 0..n {
        sb.commit_random(&a, "data", 400_000);
        sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    }
    sb.enc_ok(&a, &["repack", "enc"]);
    (a, url, alice)
}

fn shallow_clone(sb: &Sandbox, name: &str, url: &str, identity: &Path) -> (PathBuf, String) {
    let id = identity.to_str().unwrap();
    let out = sb
        .cmd(&sb.root, "git")
        .args([
            "-c",
            &format!("enc.identity={id}"),
            "-c",
            "enc.trustOnFirstUse=true",
            "clone",
            "-q",
            "--depth",
            "1",
            url,
            name,
        ])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(out.status.success(), "{err}");
    let d = sb.root.join(name);
    sb.git_ok(&d, &["config", "remote.origin.enc-identity", id]);
    (d, err)
}

#[test]
fn a_shallow_clone_does_without_the_history() {
    let sb = Sandbox::new("shallow");
    let (a, url, alice) = repacked_history(&sb, 4);
    // Pushed after the repack: part of a shallow clone.
    sb.commit_random(&a, "data", 50_000);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    let old = sb.git_ok(&a, &["rev-parse", "main~3:data"]);

    let (c, _) = shallow_clone(&sb, "carol", &url, &alice);
    assert_eq!(
        sb.git_ok(&c, &["rev-parse", "--is-shallow-repository"])
            .trim(),
        "true"
    );
    assert_eq!(sb.git_ok(&c, &["rev-list", "--count", "HEAD"]).trim(), "2");
    assert_eq!(
        fs::read(c.join("data")).unwrap(),
        fs::read(a.join("data")).unwrap()
    );
    assert!(!sb.git(&c, &["cat-file", "-e", old.trim()]).status.success());
    sb.git_ok(&c, &["fsck", "--connectivity-only"]);

    // A plain fetch keeps it shallow; pushing from it works.
    sb.commit_random(&a, "data", 50_000);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    sb.git_ok(&c, &["pull", "-q", "origin", "main"]);
    assert_eq!(
        sb.git_ok(&c, &["rev-parse", "--is-shallow-repository"])
            .trim(),
        "true"
    );
    assert!(!sb.git(&c, &["cat-file", "-e", old.trim()]).status.success());
    sb.commit_text(&c, "c", "c\n");
    sb.git_ok(&c, &["push", "-q", "origin", "main"]);
    sb.git_ok(&a, &["pull", "-q", "enc", "main"]);
    assert_eq!(fs::read_to_string(a.join("c")).unwrap(), "c\n");

    // The history pack never left the host.
    let m = sb.enc_ok(&a, &["manifest", "enc"]);
    let history = m
        .lines()
        .find(|l| l.starts_with("snapshot "))
        .and_then(|l| l.split(' ').nth(2))
        .unwrap()
        .to_owned();
    let tree = sb.git_ok(&a.join("../host.git"), &["ls-tree", "refs/heads/enc"]);
    let blob = tree
        .lines()
        .find(|l| l.ends_with(&format!("{history}.age")))
        .and_then(|l| l.split_whitespace().nth(2))
        .unwrap()
        .to_owned();
    let in_backend = |r: &Path| {
        sb.cmd(r, "git")
            .env("GIT_NO_LAZY_FETCH", "1")
            .args([
                "--git-dir",
                backend_repo(r).to_str().unwrap(),
                "cat-file",
                "-e",
                &blob,
            ])
            .output()
            .unwrap()
            .status
            .success()
    };
    assert!(!in_backend(&c));

    // Fetched, indexed, and dropped again.
    sb.git_ok(&c, &["fetch", "-q", "--unshallow", "origin"]);
    assert!(!in_backend(&c));
    assert_eq!(
        sb.git_ok(&c, &["rev-parse", "--is-shallow-repository"])
            .trim(),
        "false"
    );
    sb.git_ok(&c, &["cat-file", "-e", old.trim()]);
    assert_eq!(
        sb.git_ok(&c, &["rev-list", "--count", "HEAD"]),
        sb.git_ok(&a, &["rev-list", "--count", "HEAD"])
    );
    sb.git_ok(&c, &["fsck", "--connectivity-only"]);
}

#[test]
fn a_shallow_clone_fetches_the_history_a_ref_builds_on() {
    let sb = Sandbox::new("shallow-old-base");
    let (a, url, alice) = repacked_history(&sb, 4);
    // A branch off a commit only the history pack holds.
    sb.git_ok(&a, &["checkout", "-q", "-b", "old", "main~2"]);
    sb.commit_text(&a, "o", "o\n");
    sb.git_ok(&a, &["push", "-q", "enc", "old"]);

    let (c, err) = shallow_clone(&sb, "carol", &url, &alice);
    assert!(err.contains("older than the snapshot"), "{err}");
    assert_eq!(
        sb.git_ok(&c, &["rev-parse", "--is-shallow-repository"])
            .trim(),
        "false"
    );
    sb.git_ok(&c, &["fsck", "--connectivity-only"]);
    sb.git_ok(&c, &["fetch", "-q", "origin", "old"]);
    assert_eq!(
        sb.git_ok(&c, &["rev-parse", "FETCH_HEAD"]),
        sb.git_ok(&a, &["rev-parse", "old"])
    );
}

#[test]
fn a_remote_never_repacked_clones_in_full_with_a_depth() {
    let sb = Sandbox::new("shallow-none");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    for i in 0..3 {
        sb.commit_text(&a, "f", &format!("{i}\n"));
        sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    }
    let (c, err) = shallow_clone(&sb, "carol", &url, &alice);
    assert!(err.contains("no snapshot"), "{err}");
    assert_eq!(sb.git_ok(&c, &["rev-list", "--count", "HEAD"]).trim(), "3");
}

fn is_shallow(sb: &Sandbox, repo: &Path) -> bool {
    sb.git_ok(repo, &["rev-parse", "--is-shallow-repository"])
        .trim()
        == "true"
}

fn shallow_file(repo: &Path) -> String {
    fs::read_to_string(repo.join(".git/shallow")).unwrap_or_default()
}

#[test]
fn a_shallow_clone_keeps_its_boundary_when_the_history_is_dropped() {
    let sb = Sandbox::new("shallow-orphan");
    let (a, url, alice) = repacked_history(&sb, 3);
    let (c, _) = shallow_clone(&sb, "carol", &url, &alice);
    let tip = sb.git_ok(&c, &["rev-parse", "HEAD"]).trim().to_owned();
    assert!(shallow_file(&c).contains(&tip));

    // An orphan replaces main and a repack drops the old history: the
    // snapshot has no history pack that could complete the boundary.
    sb.git_ok(&a, &["checkout", "-q", "--orphan", "fresh"]);
    sb.commit_text(&a, "f", "f\n");
    sb.git_ok(&a, &["push", "-q", "--force", "enc", "fresh:main"]);
    sb.enc_ok(&a, &["repack", "enc"]);
    let m = sb.enc_ok(&a, &["manifest", "enc"]);
    let snapshot = m.lines().find(|l| l.starts_with("snapshot ")).unwrap();
    assert_eq!(snapshot.split(' ').nth(2), Some("-"), "{snapshot}");

    sb.git_ok(&c, &["fetch", "-q", "origin"]);
    assert!(shallow_file(&c).contains(&tip));
    sb.git_ok(&c, &["fsck", "--no-progress"]);
    sb.git_ok(&c, &["log", "--oneline", "main"]);
    sb.git_ok(&c, &["fetch", "-q", "--unshallow", "origin"]);
    assert!(shallow_file(&c).contains(&tip));
    sb.git_ok(&c, &["log", "--oneline", "main"]);
}

#[test]
fn a_push_reaching_a_dropped_snapshot_is_refused() {
    let sb = Sandbox::new("shallow-dropped");
    let (a, url, alice) = repacked_history(&sb, 3);
    sb.git_ok(&a, &["checkout", "-q", "-b", "tmp", "main~2"]);
    sb.commit_text(&a, "s", "s1\n");
    sb.commit_text(&a, "s", "s2\n");
    sb.git_ok(&a, &["push", "-q", "enc", "tmp"]);
    sb.enc_ok(&a, &["repack", "enc"]);
    let s2 = sb.git_ok(&a, &["rev-parse", "tmp"]).trim().to_owned();

    let (c, _) = shallow_clone(&sb, "carol", &url, &alice);
    sb.git_ok(
        &c,
        &["fetch", "-q", "origin", "tmp:refs/remotes/origin/tmp"],
    );
    assert!(shallow_file(&c).contains(&s2));

    // s1 leaves the remote: s2's parent is nowhere a participant can get it.
    sb.git_ok(&a, &["push", "-q", "enc", ":tmp"]);
    sb.enc_ok(&a, &["repack", "enc"]);

    let (ok, out, _) = sb.enc(&c, &["doctor", "origin"]);
    assert!(
        !ok && out.contains(&format!(
            "FAIL  shallow boundary: the clone is shallow at {s2},"
        )),
        "{out}"
    );
    sb.git_ok(&c, &["checkout", "-q", "-b", "t2", "origin/tmp"]);
    sb.commit_text(&c, "t2", "t2\n");
    let err = sb.git_fails(&c, &["push", "origin", "t2"]);
    assert!(
        err.contains(&format!("reaches its boundary at {s2}"))
            && err.contains("git fetch --unshallow"),
        "{err}"
    );
    let (d, _) = shallow_clone(&sb, "dave", &url, &alice);
    sb.git_ok(&d, &["fetch", "-q", "--unshallow", "origin"]);
    sb.git_ok(&d, &["fsck", "--connectivity-only"]);
}

#[test]
fn a_shallow_clone_fetches_the_history_a_pack_deltas_against() {
    let sb = Sandbox::new("shallow-delta");
    let (a, url, alice) = repacked_history(&sb, 4);
    // A blob only the history pack holds is the delta base of this push.
    sb.git_ok(&a, &["checkout", "-q", "-b", "side", "main~2"]);
    let mut data = fs::read(a.join("data")).unwrap();
    data[1000] ^= 0xff;
    fs::write(a.join("data"), data).unwrap();
    sb.git_ok(&a, &["commit", "-qam", "side"]);
    sb.git_ok(&a, &["push", "-q", "enc", "side"]);

    let (c, err) = shallow_clone(&sb, "carol", &url, &alice);
    assert!(
        err.contains("builds on history older than the snapshot") && !err.contains("a ref builds"),
        "{err}"
    );
    assert!(!is_shallow(&sb, &c));
    sb.git_ok(&c, &["fetch", "-q", "origin", "side"]);
    assert_eq!(
        sb.git_ok(&c, &["rev-parse", "FETCH_HEAD"]),
        sb.git_ok(&a, &["rev-parse", "side"])
    );
    sb.git_ok(&c, &["fsck", "--connectivity-only"]);
}

#[test]
fn a_shallow_clone_survives_a_deleted_branch_and_a_gc() {
    let sb = Sandbox::new("shallow-gc");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    for _ in 0..4 {
        sb.commit_random(&a, "data", 400_000);
        sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    }
    // A snapshot commit that no ref reaches once tmp is deleted.
    sb.git_ok(&a, &["push", "-q", "enc", "main~2:refs/heads/tmp"]);
    sb.enc_ok(&a, &["repack", "enc"]);
    let tmp = sb.git_ok(&a, &["rev-parse", "main~2"]).trim().to_owned();

    // Cloned while tmp exists: tmp is part of the boundary.
    let (before, _) = shallow_clone(&sb, "before", &url, &alice);
    sb.git_ok(
        &before,
        &["fetch", "-q", "origin", "tmp:refs/remotes/origin/tmp"],
    );
    assert!(shallow_file(&before).contains(&tmp));
    let (pusher, _) = shallow_clone(&sb, "pusher", &url, &alice);
    sb.git_ok(
        &pusher,
        &["fetch", "-q", "origin", "tmp:refs/remotes/origin/tmp"],
    );

    sb.git_ok(&a, &["push", "-q", "enc", ":tmp"]);

    // Cloned after: no ref reaches tmp, which is no boundary.
    let (after, _) = shallow_clone(&sb, "after", &url, &alice);
    assert!(!shallow_file(&after).contains(&tmp));
    assert!(is_shallow(&sb, &after));

    sb.git_ok(&before, &["update-ref", "-d", "refs/remotes/origin/tmp"]);
    for c in [&before, &after] {
        sb.git_ok(c, &["gc", "-q", "--prune=now"]);
    }
    assert!(!sb.git(&before, &["cat-file", "-e", &tmp]).status.success());
    sb.commit_random(&a, "data", 50_000);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    for c in [&before, &after] {
        sb.git_ok(c, &["pull", "-q", "origin", "main"]);
        assert!(is_shallow(&sb, c));
        assert!(!shallow_file(c).contains(&tmp));
        sb.git_ok(c, &["fsck", "--connectivity-only"]);
    }

    // A push reaching the boundary this remote set is not refused: the
    // remote holds its parents.
    sb.git_ok(&pusher, &["checkout", "-q", "-b", "t2", "origin/tmp"]);
    sb.commit_text(&pusher, "t2", "t2\n");
    sb.git_ok(&pusher, &["push", "-q", "origin", "t2"]);
    sb.git_ok(&a, &["fetch", "-q", "enc", "t2"]);
    sb.git_ok(&a, &["fsck", "--connectivity-only"]);
}

#[test]
fn deepen_fetches_the_whole_history() {
    let sb = Sandbox::new("shallow-deepen");
    let (a, url, alice) = repacked_history(&sb, 3);
    let (c, _) = shallow_clone(&sb, "carol", &url, &alice);
    assert!(is_shallow(&sb, &c));
    sb.git_ok(&c, &["fetch", "-q", "--deepen", "1", "origin"]);
    assert!(!is_shallow(&sb, &c));
    assert_eq!(
        sb.git_ok(&c, &["rev-list", "--count", "HEAD"]),
        sb.git_ok(&a, &["rev-list", "--count", "HEAD"])
    );
}

#[test]
fn unshallow_keeps_another_remotes_boundary() {
    let sb = Sandbox::new("shallow-foreign");
    let (_, url, alice) = repacked_history(&sb, 3);
    let (c, _) = shallow_clone(&sb, "carol", &url, &alice);
    let out = sb.enc_ok(&c, &["doctor", "origin"]);
    assert!(out.contains("ok    shallow boundary"), "{out}");

    let public = sb.dir("public.git");
    sb.git_ok(&public, &["init", "-q", "--bare"]);
    let seed = sb.repo("seed");
    sb.commit_text(&seed, "one", "1\n");
    sb.commit_text(&seed, "two", "2\n");
    sb.git_ok(&seed, &["push", "-q", public.to_str().unwrap(), "main"]);
    let public_url = format!("file://{}", public.display());
    sb.git_ok(
        &c,
        &[
            "fetch",
            "-q",
            "--depth=1",
            &public_url,
            "main:refs/heads/pub",
        ],
    );
    let pub_tip = sb.git_ok(&c, &["rev-parse", "pub"]).trim().to_owned();
    assert!(shallow_file(&c).contains(&pub_tip));

    sb.git_ok(&c, &["fetch", "-q", "--unshallow", "origin"]);
    assert_eq!(shallow_file(&c), format!("{pub_tip}\n"));
    sb.git_ok(&c, &["fsck", "--connectivity-only"]);

    let (ok, out, _) = sb.enc(&c, &["doctor", "origin"]);
    assert!(
        !ok && out.contains(&format!(
            "FAIL  shallow boundary: the clone is shallow at {pub_tip},"
        )),
        "{out}"
    );
    // That boundary still blocks a push.
    sb.git_ok(&c, &["checkout", "-q", "pub"]);
    let err = sb.git_fails(&c, &["push", "origin", "pub"]);
    assert!(err.contains("this clone is shallow"), "{err}");
}

#[test]
fn a_shallow_clone_repacks() {
    let sb = Sandbox::new("shallow-repack");
    let (a, url, alice) = repacked_history(&sb, 3);
    let (c, _) = shallow_clone(&sb, "carol", &url, &alice);
    sb.enc_ok(&c, &["repack", "origin"]);
    assert!(!is_shallow(&sb, &c));
    sb.git_ok(&a, &["pull", "-q", "enc", "main"]);
    let (d, _) = shallow_clone(&sb, "dave", &url, &alice);
    assert!(is_shallow(&sb, &d));
    sb.git_ok(&d, &["fetch", "-q", "--unshallow", "origin"]);
    assert_eq!(
        sb.git_ok(&d, &["rev-list", "--count", "HEAD"]),
        sb.git_ok(&a, &["rev-list", "--count", "HEAD"])
    );
}

#[test]
fn a_shallow_clone_keeps_its_boundary_across_repacks() {
    let sb = Sandbox::new("shallow-second-repack");
    let (a, url, alice) = repacked_history(&sb, 3);
    let (c, _) = shallow_clone(&sb, "carol", &url, &alice);
    let first = shallow_file(&c);
    assert!(!first.is_empty());

    sb.commit_random(&a, "data", 50_000);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    sb.enc_ok(&a, &["repack", "enc"]);
    sb.commit_random(&a, "data", 50_000);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);

    sb.git_ok(&c, &["pull", "-q", "origin", "main"]);
    assert_eq!(shallow_file(&c), first);
    assert_eq!(
        fs::read(c.join("data")).unwrap(),
        fs::read(a.join("data")).unwrap()
    );
    sb.git_ok(&c, &["fsck", "--connectivity-only"]);

    sb.git_ok(&c, &["fetch", "-q", "--unshallow", "origin"]);
    assert!(!is_shallow(&sb, &c));
    assert_eq!(
        sb.git_ok(&c, &["rev-list", "--count", "HEAD"]),
        sb.git_ok(&a, &["rev-list", "--count", "HEAD"])
    );
    sb.git_ok(&c, &["fsck", "--connectivity-only"]);
}

/// Run a git command, require success, and return its stderr.
fn git_err(sb: &Sandbox, repo: &Path, args: &[&str]) -> String {
    let out = sb.git(repo, args);
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(out.status.success(), "git {args:?} failed:\n{err}");
    err
}

#[test]
fn a_plain_fetch_after_a_repack_keeps_a_shallow_clone_connected() {
    let sb = Sandbox::new("shallow-reconnect");
    let (a, url, alice) = repacked_history(&sb, 3);
    let (c, _) = shallow_clone(&sb, "carol", &url, &alice);
    let tip = sb.git_ok(&c, &["rev-parse", "HEAD"]).trim().to_owned();

    // Neither commit reaches carol before the repack: the new snapshot's
    // commit would be a boundary cut off from her history.
    for _ in 0..2 {
        sb.commit_random(&a, "data", 50_000);
        sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    }
    sb.enc_ok(&a, &["repack", "enc"]);

    let err = git_err(&sb, &c, &["fetch", "origin"]);
    assert!(err.contains("does not connect"), "{err}");
    assert!(!err.contains("forced update"), "{err}");
    sb.git_ok(&c, &["merge-base", "--is-ancestor", &tip, "origin/main"]);
    sb.git_ok(&c, &["pull", "-q", "origin", "main"]);
    assert_eq!(
        sb.git_ok(&c, &["rev-parse", "HEAD"]),
        sb.git_ok(&a, &["rev-parse", "HEAD"])
    );
    assert!(!is_shallow(&sb, &c));
    sb.git_ok(&c, &["fsck", "--connectivity-only"]);
}

#[test]
fn a_depth_on_a_shallow_clone_says_it_does_not_deepen() {
    let sb = Sandbox::new("shallow-redepth");
    let (a, url, alice) = repacked_history(&sb, 3);
    let (c, _) = shallow_clone(&sb, "carol", &url, &alice);
    sb.commit_random(&a, "data", 50_000);
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    let err = git_err(&sb, &c, &["fetch", "--depth=3", "origin"]);
    assert!(err.contains("--depth does not deepen"), "{err}");
    assert!(is_shallow(&sb, &c));
}

#[test]
fn unshallow_reports_a_boundary_the_remote_no_longer_completes() {
    let sb = Sandbox::new("shallow-stuck");
    let (a, url, alice) = repacked_history(&sb, 3);
    let (c, _) = shallow_clone(&sb, "carol", &url, &alice);
    let tip = sb.git_ok(&c, &["rev-parse", "HEAD"]).trim().to_owned();

    // main drops tip and its parent; the next repack's history pack does
    // not hold that parent.
    sb.git_ok(&a, &["reset", "-q", "--hard", "HEAD~2"]);
    sb.commit_text(&a, "x", "x\n");
    sb.git_ok(&a, &["push", "-q", "--force", "enc", "main"]);
    sb.commit_text(&a, "y", "y\n");
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    sb.enc_ok(&a, &["repack", "enc"]);

    let err = git_err(&sb, &c, &["fetch", "--unshallow", "origin"]);
    assert!(
        err.contains(&format!("origin no longer holds the parents of {tip}")),
        "{err}"
    );
    assert_eq!(shallow_file(&c), format!("{tip}\n"));
    let (ok, out, _) = sb.enc(&c, &["doctor", "origin"]);
    assert!(
        !ok && out.contains(&format!(
            "the clone is shallow at {tip}, whose parents origin no longer holds"
        )) && !out.contains("--unshallow"),
        "{out}"
    );

    // A later repack: the plain fetch does not add a boundary cut off from
    // the history fetched.
    for f in ["z", "w"] {
        sb.commit_text(&a, f, "z\n");
        sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    }
    sb.enc_ok(&a, &["repack", "enc"]);
    sb.git_ok(&c, &["fetch", "-q", "origin"]);
    assert_eq!(shallow_file(&c), format!("{tip}\n"));
    assert_eq!(
        sb.git_ok(&c, &["rev-list", "--count", "origin/main"]),
        sb.git_ok(&a, &["rev-list", "--count", "main"])
    );
    sb.git_ok(&c, &["fsck", "--connectivity-only"]);

    // As the hint says: no ref reaching it, then a gc, drops it.
    sb.git_ok(&c, &["reset", "-q", "--hard", "origin/main"]);
    sb.git_ok(
        &c,
        &["reflog", "expire", "--expire-unreachable=now", "--all"],
    );
    sb.git_ok(&c, &["gc", "-q", "--prune=now"]);
    assert!(!is_shallow(&sb, &c));
    sb.git_ok(&c, &["fsck", "--connectivity-only"]);
}

#[test]
fn doctor_does_not_call_a_boundary_with_its_parents_here_stuck() {
    let sb = Sandbox::new("shallow-not-stuck");
    let (a, url, alice) = repacked_history(&sb, 3);
    let (c, _) = shallow_clone(&sb, "carol", &url, &alice);
    let tip = sb.git_ok(&c, &["rev-parse", "HEAD"]).trim().to_owned();
    // tip is no longer the snapshot's.
    sb.commit_text(&a, "x", "x\n");
    sb.git_ok(&a, &["push", "-q", "enc", "main"]);
    sb.enc_ok(&a, &["repack", "enc"]);
    sb.git_ok(&c, &["fetch", "-q", "--unshallow", "origin"]);
    assert!(!is_shallow(&sb, &c));

    // Recorded as a boundary again, parents and every pack here.
    fs::write(c.join(".git/shallow"), format!("{tip}\n")).unwrap();
    let state = backend_repo(&c).parent().unwrap().to_owned();
    fs::write(state.join("shallow"), format!("{tip}\n")).unwrap();
    let (_, out, _) = sb.enc(&c, &["doctor", "origin"]);
    assert!(!out.contains("no longer holds"), "{out}");
}

#[test]
fn shallow_since_and_exclude_are_refused() {
    let sb = Sandbox::new("shallow-since");
    let (_, url, alice) = repacked_history(&sb, 2);
    let id = alice.to_str().unwrap();
    for opt in ["--shallow-since=2000-01-01", "--shallow-exclude=main"] {
        let out = sb
            .cmd(&sb.root, "git")
            .args([
                "-c",
                &format!("enc.identity={id}"),
                "-c",
                "enc.trustOnFirstUse=true",
                "clone",
                "-q",
                opt,
                &url,
                "carol",
            ])
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        let flag = opt.split('=').next().unwrap();
        assert!(
            !out.status.success() && err.contains(&format!("{flag} is not supported")),
            "{err}"
        );
        assert!(!sb.root.join("carol").exists());
    }
    let (c, _) = shallow_clone(&sb, "carol", &url, &alice);
    let err = sb.git_fails(&c, &["fetch", "--shallow-since=2000-01-01", "origin"]);
    assert!(err.contains("--shallow-since is not supported"), "{err}");
}

#[test]
fn a_manifest_over_the_filter_is_fetched_once_and_kept() {
    let sb = Sandbox::new("big-manifest");
    let host = sb.host();
    let url = sb.url(&host, None);
    let (alice, alice_pub) = sb.keypair("alice");
    let a = sb.repo("alice");
    sb.add_remote(&a, &url, &alice, &[&alice_pub]);
    sb.commit_text(&a, "f", "0\n");
    // Enough long ref names for a manifest over 1 MiB.
    let head = sb.git_ok(&a, &["rev-parse", "HEAD"]).trim().to_owned();
    let pad = "x".repeat(200);
    let mut input = String::new();
    for i in 0..5000 {
        input.push_str(&format!("create refs/heads/b{i:05}-{pad} {head}\n"));
    }
    let mut child = sb
        .cmd(&a, "git")
        .args(["update-ref", "--stdin"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success());
    sb.git_ok(&a, &["push", "-q", "enc", "refs/heads/*"]);

    let b = sb.clone("bob", &url, &alice);
    let backend = backend_repo(&b);
    let out = sb
        .cmd(&b, "git")
        .env("GIT_NO_LAZY_FETCH", "1")
        .arg("--git-dir")
        .arg(&backend)
        .args(["cat-file", "-s", "refs/enc/tip:manifest"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let size: u64 = String::from_utf8(out.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(size > 1 << 20, "{size}");
    let packs = || {
        let mut v: Vec<_> = fs::read_dir(backend.join("objects/pack"))
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        v.sort();
        v
    };
    let before = packs();
    // Nothing new: the manifest is present, and not fetched again.
    let trace = sb.root.join("trace");
    let out = sb
        .cmd(&b, "git")
        .env("GIT_TRACE", &trace)
        .args(["fetch", "-q", "origin"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let trace = fs::read_to_string(&trace).unwrap();
    let fetches: Vec<&str> = trace
        .lines()
        .filter(|l| l.contains("built-in: git fetch"))
        .collect();
    assert!(
        fetches.len() > 1 && !fetches.iter().any(|l| l.contains("--stdin")),
        "{fetches:#?}"
    );
    assert_eq!(packs(), before);
    assert_backend_sound(&sb, &b);
}
