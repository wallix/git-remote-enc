# git-remote-enc

**An end-to-end encrypted git remote that lives inside an ordinary git
repository — GitLab, GitHub, or any bare repo over ssh.**

```bash
git-remote-enc init secret git@gitlab.example.com:team/vault.git   # key, remote, guard
git push secret main
git-remote-enc invite secret "ssh-ed25519 AAAA… alice"            # prints alice's join command
```

Alice runs the printed `git-remote-enc join …` in her clone. Before that, she
sends her public key; `join` creates her key and prints it if she has none.

Use a key that is not registered with any forge: the host can match the
ciphertext's recipient stanzas against the public keys forges publish
(`https://<forge>/<user>.keys`) and learn who participates
([DESIGN.md §6.4](DESIGN.md#64-what-the-host-learns)). The default identity,
`~/.ssh/id_ed25519`, is usually such a registered key.

The host stores one branch of opaque blobs. Only the participants listed in the
signed manifest can read refs, history or the participant list. Pushes and
fetches are incremental, concurrent pushes are safe, and a non-fast-forward push
is rejected exactly as on a plain remote.

Participants are identified by the `ssh-ed25519` keys they already use, or by
age public keys for read-only access (`ssh-rsa` is not supported). Encryption is
[age](https://age-encryption.org) (X25519, ChaCha20-Poly1305); authentication is
SSH signatures.

See [`DESIGN.md`](DESIGN.md) for the format, the protocol and the trust model,
and for why this exists instead of git-remote-gcrypt.

## Installation

From a release (`linux-x86_64`, `linux-aarch64`, `macos-x86_64`,
`macos-aarch64`), verified before it is unpacked:

```bash
v=v0.1.0 p=linux-x86_64
gh release download "$v" --repo wallix/git-remote-enc -p "git-remote-enc-$p.*"
sha256sum -c "git-remote-enc-$p.sha256"
gh attestation verify "git-remote-enc-$p.tar.gz" --repo wallix/git-remote-enc
tar -xzf "git-remote-enc-$p.tar.gz" git-remote-enc && install -m 755 git-remote-enc ~/.local/bin/
```

From source: `cargo install --git https://github.com/wallix/git-remote-enc git-remote-enc`.

The binary must be on `PATH` as `git-remote-enc`; git invokes it for every
`enc::` URL. It needs `git` (2.45 or later; an older one may download
encrypted data the helper did not ask for), and `ssh-keygen` for `init` and
`join` to create a key. Windows is not supported.

Every release archive carries Sigstore-signed SLSA build provenance and a
CycloneDX SBOM (`git-remote-enc-<platform>.cdx.json`), both attested by the
release workflow. Offline, verify against the bundle published with the
release:

```bash
gh attestation verify git-remote-enc-linux-x86_64.tar.gz --repo wallix/git-remote-enc \
  --bundle git-remote-enc.provenance.sigstore.jsonl
```

Linux binaries are reproducible: `./build.sh --verify` (Docker or vk) builds a
static-musl binary inside a Nix-pinned image, rebuilds it from a clean copy and
checks they are byte-identical. Its `dist/git-remote-enc.sha256`, published as
`git-remote-enc-linux-<arch>.build-info.txt`, records the commit and every
pinned input, so a release can be re-derived and compared years later.

## Configuration

| key | meaning |
|---|---|
| `remote.<name>.enc-identity` / `enc.identity` (repeatable) | private key files: OpenSSH (`~/.ssh/id_ed25519`) or age identity files. Default: `user.signingkey` if `gpg.format = ssh`, else `~/.ssh/id_ed25519` |
| `remote.<name>.enc-signingkey` / `enc.signingkey` | SSH private key used to sign pushes. Default: the first SSH identity |
| `remote.<name>.enc-participants` / `enc.participants` (repeatable) | one public key per value, or `@<file>` in `authorized_keys` format. Required to create a remote; on first contact with an existing one, its signer must be listed; on an existing remote a push never changes the list: `git-remote-enc participants --apply <remote>` does, after showing the difference |
| `remote.<name>.enc-admins` / `enc.admins` (repeatable) | the participants allowed to change the participant and admin lists, same syntax. Default for a new remote: its creator; applied to an existing one by `git-remote-enc participants --apply` |
| `remote.<name>.enc-trustOnFirstUse` / `enc.trustOnFirstUse` | `true` accepts whoever signed an unknown remote when no participant list is set. Default `false` |
| `remote.<name>.enc-repo` / `enc.repo` | the repository id the remote must serve (the manifest's `repo` line) |
| `remote.<name>.enc-minGeneration` / `enc.minGeneration` | the lowest manifest generation to accept |
| `remote.<name>.enc-installHook` / `enc.installHook` | `false` skips installing, and checking for, the pre-push guard. Default `true` |
| `remote.<name>.enc-allowLfs` / `enc.allowLfs` | `true` pushes even though Git LFS could upload files on pre-push, or the push carries LFS pointers. Default `false` (see below) |
| `remote.<name>.enc-partSize` / `enc.partSize` | encrypted packs larger than this are stored as parts of this size. Default `1g`, at least `16k`; `0` stores them whole. A host with a smaller per-file limit (GitHub: 100 MB) needs e.g. `48m`, at a CPU cost to the host (DESIGN.md §4.4) |
| `remote.<name>.enc-uploadBatch` / `enc.uploadBatch` | a push larger than this uploads its parts in several pushes of at most this size, under push-size limits. Default `1g`; `0` pushes at once (DESIGN.md §5.1) |
| `remote.<name>.enc-refuseForks` / `enc.refuseForks` | `false` accepts, with a warning, a manifest that forks from the one accepted before, once the participants agree to keep that view. Default `true` |

URL: `enc::<git url>[#<branch>]`; the backend branch defaults to `enc`.

Git LFS files are not encrypted: LFS uploads them from its pre-push hook to its
own server (`lfs.url`, normally the forge), and the helper sees only their
pointers. A push is therefore refused while LFS holds files in the clone's LFS
storage and a pre-push hook other than the guard is installed, and so is a push
carrying LFS pointers, which would reach the other participants without their
files. Commit the files a fix needs outside LFS, set `lfs.url` in the clone's
own config to an unreachable URL (it takes precedence over `.lfsconfig`), then
set `enc-allowLfs`.

## Setting up

`git-remote-enc init <name> <git-url>` checks the host is reachable and
empty (an scp-style URL without `git@` is flagged: ssh would log in as you),
creates `~/.ssh/enc_<name>` with `ssh-keygen` unless `--identity` names a
key, adds the remote with you as its participant (plus every
`--participant <key|@file>`), and installs the pre-push guard or puts it in
front of an existing hook. The first push creates the remote.

`git-remote-enc invite <remote> [<key>…]` adds the keys (showing the change,
asking first unless `--yes`) and prints the command for them:
`git-remote-enc join <name> <git-url> --repo … --min-generation …
--participant …`, which pins the remote they get (see below) and sets up
their identity and guard, then fetches. It is not secret, but it must reach
them over a channel the host does not control.

`git-remote-enc doctor <remote>` checks for push or fetch problems: the host and
its credentials, identity files, the guard, Git LFS, the manifest, whether you
are a participant, a pending participant change, and a shallow boundary the
remote cannot complete. It
exits 1 on a problem and installs nothing.

## Joining by hand

Cloning an existing remote needs the public key of someone who pushes to it,
obtained from them out of band, so a host cannot substitute a remote of its
own:

```bash
git -c enc.participants="ssh-ed25519 AAAA… alice" clone enc::git@gitlab.example.com:team/vault.git
```

Without it the clone is refused and the error prints the signer's fingerprint
to confirm; `-c enc.trustOnFirstUse=true` accepts it unverified.

A pinned key alone still lets the host serve an older manifest that key
signed (one from before a participant was removed, say) or another remote the
same person signed. An established clone refuses both; a new one needs the
repository id and current generation too, from the `repo` and `generation`
lines of `git-remote-enc manifest <remote>`:

```bash
git -c enc.participants="ssh-ed25519 AAAA… alice" -c enc.repo=3f9c6e4d… -c enc.minGeneration=42 \
  clone enc::git@gitlab.example.com:team/vault.git
```

Inspect the decrypted manifest of a remote from inside a repository:

```bash
git-remote-enc manifest secret              # a remote name, or an enc:: URL
git-remote-enc manifest --show-keys secret  # also print the pack keys
```

Pack keys are replaced by `<redacted>` unless `--show-keys` is given: together
they decrypt the whole history, so keep them out of terminals, logs and bug
reports.

Change who can read and push:

```bash
git-remote-enc participants --add "ssh-ed25519 AAAA… bob" secret   # shows the change, asks, pushes it
git-remote-enc participants --remove SHA256:… secret                # a key or its fingerprint
```

or edit `remote.<name>.enc-participants`, then:

```bash
git-remote-enc participants secret          # the remote's list and the pending change
git-remote-enc participants --apply secret  # push the configured list
```

A plain `git push` never changes the list, and only an admin (`enc-admins`;
by default whoever created the remote) can apply a change.

`git-remote-enc log <remote>` prints the audit trail: for every generation of
the manifest, who signed it, when (Unix time, by the pusher's clock) and which
refs, participants and admins it changed. The host can drop past
generations by rewriting the backend branch; `log` flags the missing ones, and
a fetch warns once when it sees the rewrite.

Every clone of, fetch from, or push to an encrypted remote installs a pre-push
hook, if none exists, that refuses to push its content to any other remote,
including cherry-picked backports, so an accidental `git push origin` does not
publish an embargoed fix. Push with `--no-verify` to publish intentionally. It
is not installed over an existing pre-push hook or into a `core.hooksPath`
directory (both are reported each time), nor with `enc.installHook=false`;
`git-remote-enc install-hook` installs it by hand, and `install-hook --chain`
puts it at the top of an existing shell hook (kept as `pre-push.enc-orig`),
which then gets git's ref list on stdin as before.

`git-remote-enc repack <remote>` replaces every encrypted pack by two holding
what the refs reach (a snapshot of the ref tips, and the history behind them),
as an ordinary push; every other participant's next fetch
then downloads the whole repository again. The old blobs stay in the backend
branch's history; `repack --rewrite-history` replaces that history by a new
commit that does not descend from it (the host must allow a forced update of
the branch), after which the host reclaims the space when it prunes
unreachable objects (GitLab: Settings > General > Advanced > Housekeeping).
The other participants' clones carry on, and are told a participant repacked
the remote.

After a repack, `git clone --depth 1 enc::…` downloads the snapshot and what
was pushed since, not the history pack; `git fetch --unshallow` fetches it,
and so does a fetch that needs it, a plain fetch after another repack among
them. Depths are honoured at the granularity of
packs: any depth gets everything since the last repack. `--shallow-since` and
`--shallow-exclude` are refused.

`git-remote-enc forget <remote>` drops the local trust state of a remote, which
the helper otherwise refuses to discard when the remote was recreated,
deleted, or its local state was lost. Do it only after the participants confirm
the change out of band: the next contact is a first contact.

## License

Apache-2.0.
