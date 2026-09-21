# Changelog

## Unreleased

## v0.1.0 - 2026-09-21

- Initial implementation: `enc::<git-url>[#<branch>]` remotes store an
  end-to-end encrypted repository on any git host. Pushes are incremental and
  atomic (compare-and-swap on the backend branch), non-fast-forward pushes are
  rejected like on a plain remote, and access is controlled by a signed
  participant list of SSH (`ssh-ed25519`, `ssh-rsa`) or age public keys.
