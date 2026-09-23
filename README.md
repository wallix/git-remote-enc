# git-remote-enc

**An end-to-end encrypted git remote that lives inside an ordinary git
repository — GitLab, GitHub, or any bare repo over ssh.**

```bash
git remote add secret enc::git@gitlab.example.com:team/vault.git
git config --add remote.secret.enc-participants "$(cat ~/.ssh/id_ed25519.pub)"
git config --add remote.secret.enc-participants "ssh-ed25519 AAAA… alice"
git push secret main
```

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
| `remote.<name>.enc-participants` / `enc.participants` (repeatable) | one public key per value, or `@<file>` in `authorized_keys` format. Required to create a remote; on first contact with an existing one, its signer must be listed; if set on an existing remote, the next push replaces the list |
| `remote.<name>.enc-trustOnFirstUse` / `enc.trustOnFirstUse` | `true` accepts whoever signed an unknown remote when no participant list is set. Default `false` |

URL: `enc::<git url>[#<branch>]`; the backend branch defaults to `enc`.

Cloning an existing remote needs the public key of someone who pushes to it,
obtained from them out of band, so a host cannot substitute a remote of its
own:

```bash
git -c enc.participants="ssh-ed25519 AAAA… alice" clone enc::git@gitlab.example.com:team/vault.git
```

Without it the clone is refused and the error prints the signer's fingerprint
to confirm; `-c enc.trustOnFirstUse=true` accepts it unverified.

Inspect the decrypted manifest of a remote from inside a repository:

```bash
git-remote-enc manifest secret              # a remote name, or an enc:: URL
git-remote-enc manifest --show-keys secret  # also print the pack keys
```

Pack keys are replaced by `<redacted>` unless `--show-keys` is given: together
they decrypt the whole history, so keep them out of terminals, logs and bug
reports.

`git-remote-enc forget <remote>` drops the local trust state of a remote, which
the helper otherwise refuses to discard when the remote was recreated,
deleted, or its local state was lost. Do it only after the participants confirm
the change out of band: the next contact is a first contact.

## License

Apache-2.0.
