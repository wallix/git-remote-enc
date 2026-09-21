# Coding Guidelines

## General Coding Conventions

- Small, surgical diffs. Preserve existing style in untouched code.
- Extend patterns already present rather than inventing new ones.
- Validate assumptions by inspecting files before large changes.
- Do not mass-format unrelated files.
- Favor the standard library over external dependencies. Each new dep adds
  supply-chain surface, version churn, and reader burden. Pull one in only when
  stdlib genuinely lacks the capability, the algorithm is correctness-critical
  and risky to reimplement, or the dep is already transitive. "Slightly more
  ergonomic" is not a reason. Prefer writing the glue.
- The on-remote format is a compatibility contract: the manifest grammar, the
  age ciphertext layout, the SSH signature namespace and the backend tree
  layout are all documented in [`DESIGN.md`](../DESIGN.md). Changing any of
  them bumps the manifest format version and is a breaking change, not a
  refactor.
- Release builds must stay reproducible and free-standing: one static-musl
  binary with a pure-Rust dependency tree, byte-identical on a rebuild from the
  same commit years later. Do not introduce a dep that links a system C
  library, or build-time non-determinism (timestamps, host paths,
  network-dependent inputs) — see `build.sh`, `.devcontainer/`, and CI for the
  pinning that must be preserved.

## Formatting Requirements

Generated code **must** pass CI's checks (`.github/workflows/quality.yml`: fmt,
clippy, `cargo test --workspace --locked`, `cargo audit --deny warnings`).
`--locked` rejects a stale `Cargo.lock` instead of updating it. Commit
dependency changes with their lockfile updates.

| Language | Formatter / Linter | Check command | Fix command |
|----------|--------------------|---------------|-------------|
| Rust | rustfmt + clippy (CI-enforced) | `cargo fmt --all -- --check` && `cargo clippy --workspace --all-targets --locked -- -D warnings` | `cargo fmt --all` |
| Shell (*.sh) | — | `bash -n <file>` | — |
| YAML / JSON / Markdown | `.prettierrc.yml` + `.editorconfig` (advisory) | — | — |

## Area-Specific Conventions

- [Rust (every crate in the workspace)](coding-guidelines/rust.md)
- [Shell (`*.sh`)](coding-guidelines/shell.md)
