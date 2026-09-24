# Changelog

## Unreleased

- An encrypted remote whose pushes git would send in clear, because of a
  `pushurl` or a `pushInsteadOf` rule, is refused: the pre-push guard stops
  the push, and fetches from it fail until the configuration is fixed.

- `git-remote-enc install-hook` installs a pre-push hook that refuses to push
  content of an encrypted remote to any other remote, such as the public
  repository before the disclosure date, including a backport made by
  cherry-pick or squash; `--no-verify` bypasses it.

- A push is refused while Git LFS runs on pre-push: LFS would upload the
  files it tracks, unencrypted, to its own server. `enc.allowLfs=true`
  overrides it once LFS is neutralized in the clone.

- `enc.repo` and `enc.minGeneration` pin the repository id and the lowest
  generation a first contact accepts, so a new clone cannot be served an
  older manifest or another remote with the same signer. The first-contact
  message prints both values.

- Objects fetched from an encrypted remote are checked like
  `fetch.fsckObjects` does, and by default: a hostile object such as a tree
  entry named `.git` is refused. `fetch.fsck.*` settings apply, and
  `fetch.fsckObjects=false` turns the check off.

- `git-remote-enc log` flags generations missing from the remote's history,
  and a fetch warns when the host rewrote that history, instead of silently
  crediting the next signer with earlier changes.

- `git-remote-enc log <remote>` prints who pushed each generation of a remote,
  when, and what it changed. Pushes record their time inside the encrypted
  manifest for it.
- On-remote format 2 (breaking): remotes gain admins, the only participants
  who may change the participant list. A new remote's admin is its creator
  unless `enc.admins` says otherwise. The first push with this version
  upgrades an existing remote to format 2, which older versions cannot read,
  so every participant must upgrade; `git-remote-enc participants --apply`
  with `enc.admins` set appoints its admins.
- Breaking: a push no longer replaces the remote's participant list with the
  configured one, so a stale local list cannot drop someone by accident.
  `git-remote-enc participants <remote>` shows the difference and `--apply`
  applies it; a push warns when they differ.
- The local trust state is authenticated with a key derived from your identity;
  a modified or missing trust file is refused instead of silently restarting
  from first contact. `git-remote-enc forget <remote>` replaces the advice to
  delete `.git/enc/` by hand when a remote was recreated or deleted. Trust
  files written by 0.1.0 carry no authentication and are refused: run
  `git-remote-enc forget <remote>` once per remote after upgrading.
- Breaking: first contact with an existing remote (a clone, or a new URL) is
  refused unless `enc.participants` names its signer, or
  `enc.trustOnFirstUse` is set to accept it unverified. The same remote reached
  through another spelling of its URL keeps the trust already accepted.
- A fetch warns when the remote serves a different manifest for the generation
  it already accepted, i.e. the remote's history forked.
- Linked worktrees share the repository's trust state for a remote instead of
  starting from first contact.
- Breaking: `ssh-rsa` keys are no longer accepted as participants or
  identities (the RSA implementation has an unfixed timing side channel,
  RUSTSEC-2023-0071). A remote whose participant list names an `ssh-rsa` key
  must have it replaced by an `ssh-ed25519` or `age1…` key.
- The undocumented `GIT_ENC_PASSPHRASE` environment variable is no longer
  read: a passphrase-protected key is unlocked only from the terminal.
- Security: `git-remote-enc manifest` no longer prints the pack keys, which
  decrypt the whole history; `--show-keys` prints them.
- Security: an `enc::` URL starting with `-` could make git run an arbitrary
  command (`enc::--upload-pack=…`). Such URLs are now refused, and the backend
  URL can no longer be read as a git option.

## v0.1.0 - 2026-09-21

- Initial implementation: `enc::<git-url>[#<branch>]` remotes store an
  end-to-end encrypted repository on any git host. Pushes are incremental and
  atomic (compare-and-swap on the backend branch), non-fast-forward pushes are
  rejected like on a plain remote, and access is controlled by a signed
  participant list of SSH (`ssh-ed25519`, `ssh-rsa`) or age public keys.
