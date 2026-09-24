# git-remote-enc

**An end-to-end encrypted git remote that lives inside an ordinary git
repository — GitLab, GitHub, or any bare repo over ssh.**

```bash
ssh-keygen -t ed25519 -f ~/.ssh/enc_vault      # a key for this remote only
git remote add secret enc::git@gitlab.example.com:team/vault.git
git config remote.secret.enc-identity ~/.ssh/enc_vault
git config --add remote.secret.enc-participants "$(cat ~/.ssh/enc_vault.pub)"
git config --add remote.secret.enc-participants "ssh-ed25519 AAAA… alice"
git push secret main
```

Use a key that is not registered with any forge: the host can match the
ciphertext's recipient stanzas against the public keys forges publish
(`https://<forge>/<user>.keys`) and learn who participates
([DESIGN.md §6.4](DESIGN.md#64-what-the-host-learns)). The default identity,
`~/.ssh/id_ed25519`, is usually such a registered key.

The host stores one branch of opaque blobs. Only the participants listed in the
signed manifest can read refs, history or the participant list itself. Pushes
and fetches are incremental, concurrent pushes are safe, and a non-fast-forward
push is rejected exactly as on a plain remote.

Participants are identified by the `ssh-ed25519` keys they already use, or by
age public keys for read-only access (`ssh-rsa` is not supported). Encryption is
[age](https://age-encryption.org) (X25519, ChaCha20-Poly1305); authentication is
SSH signatures.

See [`DESIGN.md`](DESIGN.md) for the format, the protocol and the trust model,
and for why this exists instead of git-remote-gcrypt.

## Installation

```bash
cargo install --path crates/git-remote-enc
```

Release binaries are built reproducibly: `./build.sh --verify` (Docker or vk)
builds a static-musl binary inside a Nix-pinned image, rebuilds it from a clean
copy and checks the two are byte-identical. `dist/git-remote-enc.sha256` records
the commit and every pinned input so a release can be re-derived and compared
years later.

Every release archive carries Sigstore-signed SLSA build provenance and a
CycloneDX SBOM (`git-remote-enc-<platform>.cdx.json`), both attested by the
release workflow. Verify an archive before installing it:

```bash
gh attestation verify git-remote-enc-linux-x86_64.tar.gz --repo wallix/git-remote-enc
# offline, with the bundle published next to the archives:
gh attestation verify git-remote-enc-linux-x86_64.tar.gz --repo wallix/git-remote-enc \
  --bundle git-remote-enc.provenance.sigstore.jsonl
```

The binary must be on `PATH` as `git-remote-enc`; git invokes it for every
`enc::` URL.

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
| `remote.<name>.enc-installHook` / `enc.installHook` | `false` skips installing the pre-push guard on first contact. Default `true` |
| `remote.<name>.enc-allowLfs` / `enc.allowLfs` | `true` pushes even though Git LFS could upload files on pre-push. Default `false` (see below) |

URL: `enc::<git url>[#<branch>]`; the backend branch defaults to `enc`.

Git LFS files are not encrypted: LFS uploads them from its pre-push hook to
its own server (`lfs.url`, normally the forge), and the helper only ever sees
their pointers. A push is therefore refused while LFS holds files in the
clone's LFS storage and a pre-push hook other than the guard is installed. Commit the files a fix needs outside LFS, set `lfs.url` in the clone's
own config to an unreachable URL (it takes precedence over `.lfsconfig`),
then set `enc-allowLfs`.

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

Change who can read and push by editing `remote.<name>.enc-participants`, then:

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

The first clone of, or push to, an encrypted remote installs a pre-push hook
that refuses to push its content to any other remote, backports by
cherry-pick included, so an embargoed fix is not published by a slip of `git
push origin`. Push with `--no-verify` when publishing it is the intent. It is
not installed over an existing pre-push hook or into a `core.hooksPath`
directory (both are reported), nor with `enc.installHook=false`;
`git-remote-enc install-hook` installs it by hand.

`git-remote-enc forget <remote>` drops the local trust state of a remote, which
the helper otherwise refuses to discard when the remote was recreated,
deleted, or its local state was lost. Do it only after the participants confirm
the change out of band: the next contact is a first contact.

## License

Apache-2.0.
