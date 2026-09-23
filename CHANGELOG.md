# Changelog

## Unreleased

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
