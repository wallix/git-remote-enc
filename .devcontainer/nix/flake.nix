{
  # .devcontainer/Dockerfile installs this toolchain as `buildEnv`. Keeping it under
  # .devcontainer/nix puts it in the Docker/vk build context for `COPY nix /src/nix`.
  #
  # Static-musl releases of git-remote-enc need:
  #   - Rust with the host arch's musl target, clippy and rustfmt. ./update.sh keeps the
  #     inline channel in sync with rust-toolchain.toml; see rustToolchain below.
  #   - host gcc as the linker driver for build scripts and proc-macros. The dependency
  #     tree is pure Rust, so no musl cross C compiler is involved: the musl target links
  #     with rustc's self-contained crt objects and its bundled `rust-lld`.
  #   - GNU coreutils, bash, sed, grep, find and diff for the scripts and the black-box
  #     tests; git for the tests and the helper itself; ca-certificates and cargo-audit for
  #     audit.sh.
  #
  # Linux releases are native on x86_64-linux and aarch64-linux; the system determines
  # the musl target.
  #
  # Everything is pinned by flake.lock (nixpkgs and rust-overlay by git rev), so the inputs
  # are rebuildable-from-source years later. cache.nixos.org serves the nixpkgs half; the
  # compiler itself is a hash-pinned fetch of the official static.rust-lang.org tarball,
  # which is kept for every release. Nix runs only INSIDE the build image (a `RUN nix
  # build` at image-build time) — no Nix on any host.
  #
  # On a host with Nix:  nix develop ./.devcontainer/nix    (the same toolchain, interactively)
  #                      nix build ./.devcontainer/nix#buildEnv

  inputs = {
    # flake.lock pins the commit; this is the branch `nix flake update` follows. It is
    # nixos-unstable rather than a release branch because rust-overlay tracks it, and a
    # release build wants the newest stable Rust the day it ships — the lock is what makes
    # that reproducible, so the branch only decides what the next ./update.sh picks up.
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      # genAttrs covers both systems without adding a flake-utils input to pin.
      systems = [ "x86_64-linux" "aarch64-linux" ];
      eachSystem = nixpkgs.lib.genAttrs systems;

      envFor = system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };

          # x86_64-unknown-linux-musl / aarch64-unknown-linux-musl — nixpkgs' config string
          # for these two triples is also their rustc target name.
          muslTarget = {
            x86_64-linux = "x86_64-unknown-linux-musl";
            aarch64-linux = "aarch64-unknown-linux-musl";
          }.${system};

          # Exact toolchain: channel 1.98.1 — the same channel, minimal profile and
          # clippy/rustfmt components ../../rust-toolchain.toml pins, kept in sync by
          # ./update.sh, plus the musl target the release build needs (that file
          # deliberately pins no target). Reading it directly (rust-overlay's
          # fromRustupToolchainFile) would require the flake at the repo ROOT — a flake
          # cannot read `..` outside its own dir in pure eval — so with the flake under
          # .devcontainer/nix/ the channel is inline.
          rustToolchain = pkgs.rust-bin.stable."1.98.1".minimal.override {
            extensions = [ "clippy" "rustfmt" ];
            targets = [ muslTarget ];
          };

          buildTools = with pkgs; [
            rustToolchain
            # Build scripts and proc-macros target the glibc host and link with `cc`.
            stdenv.cc
            git
            cacert
            cargo-audit # audit.sh (RUSTSEC scan)
            # The scripts and the black-box tests use GNU tools; bash also provides
            # `sh` for build.sh's `sh -c "$BUILD_CMD"`.
            coreutils
            bash
            gnugrep
            gnused
            findutils
            diffutils
          ];

          # Merge the toolchain under one PATH prefix. buildEnv defaults to all of
          # "/"; link only /bin, /etc for cacert's ca-bundle.crt (SSL_CERT_FILE), and
          # /lib + /libexec for gcc's runtime and compiler executables. The image
          # does not read docs or headers, so omit /share and /include.
          binEnv = pkgs.buildEnv {
            name = "enc-build-env";
            paths = buildTools;
            pathsToLink = [ "/bin" "/etc" "/lib" "/libexec" ];
          };
        in
        { inherit pkgs muslTarget buildTools binEnv; };
    in
    {
      # `nix develop ./.devcontainer/nix` provides the build toolchain interactively.
      devShells = eachSystem (system:
        let env = envFor system; in
        {
          default = env.pkgs.mkShell {
            packages = env.buildTools;
            SOURCE_DATE_EPOCH = "0";
            shellHook = ''
              echo "git-remote-enc nix devShell — $(rustc --version), musl target: ${env.muslTarget}"
            '';
          };
        });

      # One closure with a merged /bin. .devcontainer/Dockerfile runs
      # `nix build .#buildEnv --out-link /opt/toolchain` inside nixos/nix and adds it
      # to PATH. /opt/toolchain keeps store hashes out of the Dockerfile.
      # Nix itself neither builds nor pushes an image.
      packages = eachSystem (system:
        let env = envFor system; in
        {
          buildEnv = env.binEnv;
          default = env.binEnv;
        });
    };
}
