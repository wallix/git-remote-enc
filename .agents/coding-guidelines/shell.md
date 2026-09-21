# Shell Coding Guidelines

Applies to: `*.sh` (the build, package, release-notes, lint, format, audit and
update scripts at the repo root, and `tests/release-e2e.sh`).

See [`../coding-guidelines.md`](../coding-guidelines.md) for general conventions
and formatting requirements that apply to all code.

## Conventions

- Bash with `set -euo pipefail` and `cd "$(dirname "$0")"` at the top, so the
  script is location-independent and fails loudly.
- Preserve current flag semantics. New flags get a clear `--long-name` and a
  usage line; reject unknown args with `exit 2`.
- Make destructive or expensive operations safe: verbose output, idempotent
  re-runs, and preconditions checked up front rather than half way through.
  Clean temporary directories on every exit path with `trap ... EXIT`.
- Keep the two container backends symmetric: scripts that build or check inside
  the devcontainer prefer a `vk` on `PATH` and fall back to Docker, with
  `--docker` forcing Docker. Both paths must pass identical flags so they
  produce identical results.
- Keep builds reproducible: pin inputs (toolchain channel, base image tag
  **and** digest, the Nix flake lock that fixes every package in the image) and
  neutralize timestamps and host paths (`SOURCE_DATE_EPOCH`,
  `--remap-path-prefix`). Do not float a version that was previously pinned.
  `build.sh` writes `dist/git-remote-enc.sha256` — a rebuild from the same
  commit must match it, and `--verify` checks exactly that.
- Do not introduce `curl` to external domains without rationale. Verify
  downloads against a pinned checksum.
- Never embed credentials in scripts, and do not echo secrets.
- Prefer the dedicated tools the repo already uses (`sed -nE`, `awk`,
  `sha256sum`, `cargo`) over reinventing parsing; keep one script focused on one
  job.
