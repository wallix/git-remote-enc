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

Participants are identified by the SSH keys they already use (`ssh-ed25519`,
`ssh-rsa`), or by age public keys for read-only access. Encryption is
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

The binary must be on `PATH` as `git-remote-enc`; git invokes it for every
`enc::` URL.

## Configuration

| key | meaning |
|---|---|
| `remote.<name>.enc-identity` / `enc.identity` (repeatable) | private key files: OpenSSH (`~/.ssh/id_ed25519`) or age identity files. Default: `user.signingkey` if `gpg.format = ssh`, else `~/.ssh/id_ed25519` |
| `remote.<name>.enc-signingkey` / `enc.signingkey` | SSH private key used to sign pushes. Default: the first SSH identity |
| `remote.<name>.enc-participants` / `enc.participants` (repeatable) | one public key per value, or `@<file>` in `authorized_keys` format. Required to create a remote; if set on an existing remote, the next push replaces the list |

URL: `enc::<git url>[#<branch>]`; the backend branch defaults to `enc`.

Inspect the decrypted manifest of a remote from inside a repository:

```bash
git-remote-enc manifest secret        # a remote name, or an enc:: URL
```

## License

Apache-2.0.
