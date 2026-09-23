# AGENTS.md

This file provides guidance to AI coding assistants (Claude Code, Copilot, etc.)
when working with code in this repository.

## Sourced Assertions

Verify load-bearing factual claims — code, tooling, third-party behaviour —
against the code, the repo docs, or a web search before stating them. Flag
anything unverified, or a deduction.

Badge in chat output only (never in commit messages, code comments, or committed
files), inline right after the claim, with a `path:line` cite for code/doc:

- `✅ code` / `✅ doc` `path:line` — verified in the code / repo docs
- `✅ web` URL — verified online (bare URL, outside the code span; pin to a
  commit SHA, not a branch)
- `💭 deduction` — inferred from verified facts
- `⚠️ unverified` — unverifiable, or from training data

Skip badges on restatements, tool output, and descriptions of your own next
step.

## Project Overview

git-remote-enc — a git remote helper (`enc::<git-url>`) that stores an
end-to-end encrypted repository inside an ordinary git repository on any host
(GitLab, GitHub, a bare repo over ssh). Only the participants listed in the
signed manifest can read the refs and history; the host sees opaque blobs.

It is a from-scratch reimplementation of the idea behind git-remote-gcrypt
without its two structural tradeoffs: pushes are incremental (the backend
history is a chain, so git's own negotiation transfers only new packs) and
atomic (compare-and-swap with `--force-with-lease`), and non-fast-forward
pushes are rejected exactly like on a plain remote. Crypto is age (X25519,
ChaCha20-Poly1305) plus SSH signatures; participants are identified by the SSH
keys they already use. [`DESIGN.md`](DESIGN.md) is the authoritative design
document: read it before touching the on-remote format or the push protocol.

## Architecture

A Cargo workspace (`Cargo.toml`, edition 2024) with two crates:

- **`crates/enccore/`** — the library and where nearly all the logic lives:
  `git.rs` (plumbing wrappers over `std::process::Command`), `manifest.rs`
  (the signed, encrypted manifest: refs, packs and their keys, participants,
  generation counter), `crypto.rs` (identities, recipients, age
  encrypt/decrypt streams, SSH sign/verify), `backend.rs` (the git-hosted
  store: tracking ref, tree/commit construction, fetch, lease push), `state.rs`
  (per-remote local state under `<git common dir>/enc/`: indexed packs and the
  trusted participant set), `remote.rs` (connect, list, fetch, push), `config.rs`
  (git-config surface).
- **`crates/git-remote-enc/`** — the binary: the remote-helper protocol loop
  (`capabilities`, `list`, `fetch`, `push`) plus the `manifest` inspection
  subcommand. Its `tests/` are the black-box suite.

## Development Environment

`rust-toolchain.toml` pins the host channel, clippy and rustfmt.
`.devcontainer/nix/flake.nix` pins the same channel inline for the build image,
where Nix installs it instead of rustup. `./update.sh` keeps both pins in sync;
they must not drift. Releases use the container's native musl target. A plain
host `cargo` is enough for the edit loop.

```bash
cargo build -p git-remote-enc                        # debug binary
cargo test --workspace --locked                      # full suite (CI parity)
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all                                      # check: --all -- --check
```

The repo also has a [`Taskfile.yml`](Taskfile.yml) (`task build|test|lint|fmt`)
for task-rs users.

The build image's whole package set is one Nix closure, pinned by
`.devcontainer/nix/flake.lock`. On a host that has Nix, the same toolchain is
available interactively without Docker:

```bash
nix develop ./.devcontainer/nix      # the build image's toolchain, as a shell
nix build ./.devcontainer/nix#buildEnv
```

### Build / container scripts

`build.sh`, `lint.sh`, `fmt.sh`, `audit.sh` and `sbom.sh` run inside the pinned
devcontainer image (one stage, `enc-build`). They use `vk` when available and
fall back to Docker; `--docker` forces Docker. `package.sh`,
`release-notes.sh`, `update.sh` and `tests/release-e2e.sh` run on the host;
`update.sh` additionally needs `rustup`, `curl` and `docker` with the `buildx`
plugin — it resolves the base-image version and digest over the network and
refreshes the flake lock inside a container, so the host needs no Nix.

```bash
./build.sh [--docker]     # reproducible static-musl binary -> dist/git-remote-enc (+ .sha256 manifest)
           [--target=x86_64|aarch64]   # assert the host's arch; the build is native
           [--package]    # + the release archive and sidecar for this platform
           [--verify]     # rebuild from a pristine copy and assert identical bytes
./package.sh --platform <name> --binary <path>   # deterministic release archive
./release-notes.sh v<X.Y.Z>   # that tag's CHANGELOG section, for the release notes
./lint.sh  [--docker]     # cargo clippy --workspace --all-targets --locked -- -D warnings
./fmt.sh   [--docker]     # cargo fmt (--check to verify)
./audit.sh [--docker]     # cargo-audit against the committed Cargo.lock
./sbom.sh  [--docker]     # CycloneDX SBOM per released platform -> dist/git-remote-enc-<platform>.cdx.json
./update.sh               # bump the pinned toolchain + re-pin the base image and flake lock
RELEASE_TAG=v<X.Y.Z> tests/release-e2e.sh   # the release gate, against dist/
```

`build.sh` compiles Linux releases natively for the host architecture.
`package.sh` packs every platform on Linux so archive bytes use one archiver.
macOS binaries are built with rustup on the pinned runner image and are
reproducible only on that image; Windows is not built (the helper relies on
`/dev/urandom` and `/dev/tty`).

`build.sh` output is a stripped static-pie ELF that links no system C
libraries. Rebuilding from the same commit must reproduce the same bytes — keep
the pinning (toolchain, base image digest, flake lock, `SOURCE_DATE_EPOCH`,
path remapping) intact when touching build inputs. This is load-bearing for a
crypto tool: a user must be able to rebuild a release years later and compare
the hash.

The black-box tests need `git` on `PATH`; they create their own throwaway
SSH keys with `ssh-key`, never touching `~/.ssh`. Put the debug binary on
`PATH` (`export PATH=$PWD/target/debug:$PATH`) to try it against a real
GitLab repository.

### Fast edit/check/test loop

```bash
cargo check -p enccore
cargo test -p enccore --lib manifest::
cargo test -p git-remote-enc --test e2e
```

Run the full `cargo test --workspace --locked` before calling a change done.

### Cutting a release

`release` is the integration branch, and the tag is a *result* of a green
pipeline rather than its trigger. Push the candidate there and `release.yml`
gates it, then fast-forwards `main` to it, pushes `v<X.Y.Z>` and publishes the
GitHub release. A failed candidate is corrected and force-pushed to `release`
(`git push --force-with-lease origin HEAD:release`); no tag existed for it, so
no tag is ever moved. `release` is the disposable branch that absorbs those
rewrites, which is what keeps tags and `main` append-only.

Because `publish` fast-forwards `main` from whatever `release` holds, `release`
is a write path into `main` and must be protected at least as strictly as it —
otherwise the review `main` expects is bypassed. `main` in turn has to let the
workflow's `GITHUB_TOKEN` fast-forward it: a "require a pull request" rule there
rejects that push outright.

1. Insert a `## v<X.Y.Z> - <YYYY-MM-DD>` heading in `CHANGELOG.md` below
   `## Unreleased`, moving the unreleased entries under it and leaving
   `## Unreleased` empty for the next cycle.
2. Set `version` under `[workspace.package]` in the root `Cargo.toml` to the
   same version — every crate inherits it.
3. Refresh `Cargo.lock` (`cargo check --workspace`) and commit it with the bump:
   CI builds `--locked`, so a lock still naming the old version fails the gate.
4. Commit as `git-remote-enc: release <X.Y.Z>` on top of an up-to-date `main`,
   then `git push origin HEAD:release`.

The tag is lightweight, so it carries no tagger metadata of its own and
`git describe` names the commit directly. The tag, the workspace version and the
newest CHANGELOG heading must agree: `prepare` derives the tag from
`Cargo.toml`, `release-notes.sh` takes the body from the matching
`## v<X.Y.Z>` section, and `version_matches_changelog` (in `cargo test`) ties
the workspace version to that heading.

The pipeline is `prepare` (version, unreleased tag, dated CHANGELOG section,
candidate contains `main`) → `quality` (fmt, clippy, `cargo test --workspace
--locked`, audit) and `build` (Linux x86_64/aarch64 in the devcontainer, rebuilt
from a clean copy and required to reproduce byte-for-byte; macOS x86_64/aarch64
native) → `e2e` ([`tests/release-e2e.sh`](tests/release-e2e.sh), which unpacks
the very archives that will be published and drives the shipped binary through
git), with `sbom` (`sbom.sh`) alongside → `publish`, which attests
Sigstore-signed build provenance for every archive and build manifest and an
SBOM per archive before any write. Nothing is written to `main` or to a tag
until all of them are green, so running the checks locally first is a
convenience, not a
safeguard.

`publish` can repeat each step: fast-forward `main`, push the tag, create the
release. After a partial failure, re-run the failed job from the Actions UI;
do not tag by hand.

## Code Quality Config

- **Rust:** rustfmt + clippy, pinned via `rust-toolchain.toml`; edition 2024
  comes from `[workspace.package]`. `[workspace.lints.clippy]` denies
  `unwrap_used`, `expect_used`, `panic`, `indexing_slicing` and
  `arithmetic_side_effects` for every member. Tests relax them locally, not
  globally.
- **Dependencies:** versions are centralized in `[workspace.dependencies]`;
  every entry beyond `anyhow` carries a comment justifying why the crate earns
  its place.
- **Shell:** Bash, `set -euo pipefail`, `cd "$(dirname "$0")"`.
- **Other files:** `.editorconfig` and `.prettierrc.yml` — conventions, not
  gates.
- **Dependency audit:** `cargo audit --deny warnings` in CI. An ignore goes in
  `.cargo/audit.toml` with the rationale and residual risk written out.
- **Dependency policy:** `cargo deny --locked check licenses bans sources` in
  CI against [`deny.toml`](deny.toml): permissive licences only, crates.io
  only, no wildcard versions. A new licence is a reviewed addition there.

## CI

`.github/workflows/`: `ci.yml` (push to `main` + PRs) and `release.yml` (push
to `release`) both call the reusable `quality.yml`, which runs fmt, clippy,
`cargo test --workspace --locked`, `cargo audit --deny warnings` and
`cargo deny` — one matrix entry each, all five inside the pinned `enc-build`
image, so CI uses exactly the toolchain the release build uses. Generated code **must** pass
those checks. Commit dependency changes with their `Cargo.lock` updates.
`build.sh` and `lint.sh` also pass `--locked`, so local runs reject a stale
lockfile too.

Both also call `build.yml` — gated on `quality` in CI, in parallel with it on a
release, where the build matrix is the long pole. CI runs its Linux jobs;
releases run the full matrix with reproducibility verification, then gate on
`tests/release-e2e.sh` before publishing with `release-notes.sh`.

## Commit Messages

See [`.agents/commit-message-guidelines.md`](.agents/commit-message-guidelines.md).
In short: one concern per commit, independently buildable; single-line
imperative summary (no trailing period) with an optional `scope:` prefix
(`enccore/manifest:`, `git-remote-enc:`, `ci:`, `devcontainer:`, `doc:`,
`tests:`); a wrapped
body only when the diff does not speak for itself. A user-visible change
updates `CHANGELOG.md` in the same commit. A change to the on-remote format
bumps the manifest version and says so in the body.

## Coding Conventions

See [`.agents/coding-guidelines.md`](.agents/coding-guidelines.md) for general
conventions and per-language guidelines (Rust, Shell).
