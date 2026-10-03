# Changelog

## Unreleased

- Faster clone, fetch and push of large repositories: encrypted data is no
  longer compressed or delta-searched locally.
- Progress for the slow steps (backend download and upload, packing,
  verifying and indexing packs), following git's `--progress`/`-q`.
- The key passphrase is asked for before the download from the remote, not
  after it. Even against a remote nobody has pushed to yet, the identities
  must now be readable, including the default one (`~/.ssh/id_ed25519`, or
  `user.signingkey` with `gpg.format = ssh`) when it exists.
- A push that loses a race to another one reuses its encrypted pack on retry
  instead of rebuilding and re-uploading it.

## v0.1.0 - 2026-10-02

First release.

- `enc::<git-url>[#<branch>]` remotes store an end-to-end encrypted
  repository on one branch of any git host (GitLab, GitHub, a bare repo over
  ssh). The host sees opaque age blobs; refs, history and the participant
  list are readable only by the participants.
- Pushes and fetches are incremental, concurrent pushes are safe
  (compare-and-swap on the backend branch), and a non-fast-forward push is
  rejected as on a plain remote.
- Participants are `ssh-ed25519` keys, or `age1…` keys for read-only access.
  Every manifest is SSH-signed and names the hash of the one before it.
  Admins (by default the creator) are the only ones who may change the
  participant list, and only with `git-remote-enc participants --apply` or
  `--add`/`--remove`: a push never changes it.
- First contact with a remote is refused unless the signer is pinned
  (`enc.participants`, or `enc.trustOnFirstUse`); `enc.repo` and
  `enc.minGeneration` also pin the repository and a lower bound on its
  generation. An established clone refuses a rollback, a fork, a recreated
  or deleted remote, a tampered local trust state, and a manifest over
  64 MiB; `git-remote-enc forget` drops the trust state when the
  participants confirm a remote was recreated.
- `git-remote-enc log` prints the audit trail: who pushed each generation,
  when, and what it changed, flagging generations the host removed and any
  not chained to the accepted manifest.
- A pre-push guard, installed on every contact where no pre-push hook exists,
  refuses to push the content of an encrypted remote to any other remote,
  backports by cherry-pick or squash included; `install-hook --chain` puts it
  in front of an existing shell hook.
- Refused pushes: through a `pushurl` or `pushInsteadOf` rule that would send
  them in clear, while Git LFS could upload files alongside or the commits
  carry LFS pointers (`enc.allowLfs` overrides), and from a shallow clone
  whose history reaches its boundary.
- Fetched objects are fsck-checked by default (`fetch.fsck.*` applies).
  Identity files readable by others are refused, passphrases are read from
  the terminal only, local state is owner-only, and `manifest` prints pack
  keys only with `--show-keys`.
- Setup commands: `init` creates a remote after checking the host, `invite`
  adds participants and prints the `join` command that pins the remote for
  them, `join` sets their clone up and fetches, and `doctor` reports what a
  push or fetch would trip on.
- Release builds are static, reproducible binaries for Linux (x86_64,
  aarch64) and macOS (x86_64, aarch64), with Sigstore build provenance and a
  CycloneDX SBOM per archive.
