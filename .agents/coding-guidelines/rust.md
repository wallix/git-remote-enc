# Rust Coding Guidelines

Applies to: every Rust crate in the workspace (`enccore`, `git-remote-enc`).

See [`../coding-guidelines.md`](../coding-guidelines.md) for general conventions
and formatting requirements that apply to all code.

## Conventions

- Single responsibility per module; avoid cyclic dependencies. Logic belongs in
  `enccore`; the `git-remote-enc` crate stays a thin protocol loop and CLI over
  it.
- When you change a function's signature or return type, update every call site.
  Use repo-wide search first; a successful build does not prove all callers are
  covered.
- Validate external inputs early; no panics/unwraps on untrusted data. Anything
  read from the backend repository (manifest bytes, tree entries, pack blobs)
  and anything git prints is untrusted. Use inline interpolation in format
  macros: `write!(f, "Error: {key}")` not `write!(f, "Error: {}", key)`.
- **Panics are a bug, and the lints enforce it:** the workspace denies
  `unwrap_used`, `expect_used`, `panic`, `indexing_slicing` and
  `arithmetic_side_effects`. Use `?`, `.get()`, `checked_*`, `TryFrom`, and
  surface real errors. Relax a lint at the narrowest scope that works: the
  crate-root `#![cfg_attr(test, allow(...))]` so unit tests may panic while
  library code may not, plus a file-level `#![allow(...)]` at the top of each
  integration-test file.
- **Propagate errors:** do not discard `Result` with `.ok()`,
  `.unwrap_or_default()`, or `let _ =` without a comment explaining why the
  failure is safe to ignore.
- **Never write plaintext where git can see it.** Only ciphertext (age files)
  goes into the backend tree; refs, pack contents and the participant list are
  inside the manifest. The remote helper's stdout is git's protocol channel:
  diagnostics, prompts and progress go to stderr or `/dev/tty`, never stdout.
- **Stream, don't buffer, pack data.** Packs can be gigabytes: pack-objects →
  encrypt → hash → temp file, and blob → decrypt → index-pack, are pipelines
  of `Read`/`Write` adapters. The manifest is small and may be held in memory.
- **Stay in bytes at Unix boundaries:** `Path`/`PathBuf` for filesystem paths,
  `OsString`/`OsStr` for env vars, `&[u8]`/`Vec<u8>` for stream contents and
  command output. Parse git output as bytes and convert only the fields that
  are known to be ASCII (oids, ref names) with an explicit error on failure.
- **Determinism on the backend:** backend commits use a fixed author, email and
  date; the tree is sorted by git itself. Nothing time- or host-dependent goes
  into the ciphertext container except what age puts there.
- **TOCTOU on paths:** create temporary files with `create_new(true)` in the
  per-remote state directory under `$GIT_DIR`, never in a shared `/tmp`.
- Co-locate fast unit tests in the module they cover (manifest parsing,
  refspec parsing, trust rules). Black-box tests in
  `crates/git-remote-enc/tests/` drive the real binary through `git push` /
  `git fetch` / `git clone` against a local bare repository acting as the host.
- Measure before optimizing; document benchmark context when micro-optimizing.

## Dependencies — favor the standard library

- Dependency versions are centralized in the workspace `Cargo.toml`
  (`[workspace.dependencies]`), and **every entry beyond `anyhow` carries a
  comment saying why it earns its place**. Members reference them with
  `<dep>.workspace = true`.
- `std::collections` over `hashbrown`/`indexmap`; `std::sync` over
  `parking_lot`; `std::process::Command` for git plumbing (no libgit2, no gix:
  pack generation and indexing are delegated to `git pack-objects` and
  `git index-pack`, which is also what keeps thin-pack semantics identical to
  git's own).
- Crypto is `age` (format + primitives) and `ssh-key` (key files, signatures).
  Do not hand-roll an AEAD construction; if a primitive is needed that age does
  not expose, use the `chacha20poly1305` / `x25519-dalek` crates already in
  the tree behind it.
- `anyhow` only at the application boundary and in `enccore`'s I/O-heavy
  orchestration where a chain of git/crypto/IO failures is reported straight to
  the user; pure parsing code returns typed errors.
- New dependencies enlarge the `cargo-audit` surface and must stay statically
  linkable under musl with no system C libraries.
