#!/usr/bin/env bash
# sbom.sh — write a CycloneDX 1.5 SBOM of the git-remote-enc binary for every released
# platform to dist/git-remote-enc-<platform>.cdx.json, from the committed Cargo.lock.
# Build-time dependencies (build scripts, proc-macros) are left out: they are not in
# the binary. release.yml publishes these files next to the archives and attests them.
#
# Like build.sh/audit.sh, prefer vk on PATH (microVM), otherwise Docker; --docker
# forces Docker. Both use cargo-cyclonedx from the devcontainer's Nix closure.
set -euo pipefail
cd "$(dirname "$0")"

FORCE_DOCKER=""
for arg in "$@"; do
  case "$arg" in
    --docker) FORCE_DOCKER=1 ;;
    *) echo "sbom.sh: unknown argument: $arg (--docker)" >&2; exit 2 ;;
  esac
done

OUT=dist
BIN=git-remote-enc
# <platform>=<rust target>, as package.sh names the archives. Keep in sync with it.
PLATFORMS="linux-x86_64=x86_64-unknown-linux-musl linux-aarch64=aarch64-unknown-linux-musl"
PLATFORMS="$PLATFORMS macos-x86_64=x86_64-apple-darwin macos-aarch64=aarch64-apple-darwin"

# cargo-cyclonedx writes next to the crate's Cargo.toml; move each file to dist/.
SBOM_CMD="set -eu
for p in $PLATFORMS; do
  platform=\${p%%=*} target=\${p#*=}
  cargo cyclonedx -q --manifest-path crates/$BIN/Cargo.toml --format json \
    --spec-version 1.5 --no-build-deps --target \"\$target\" --target-in-filename \
    --override-filename $BIN
  rm -f crates/enccore/${BIN}_\"\$target\".cdx.json
  mv crates/$BIN/${BIN}_\"\$target\".cdx.json $OUT/$BIN-\"\$platform\".cdx.json
done"

mkdir -p "$OUT"
if [ -z "$FORCE_DOCKER" ] && command -v vk >/dev/null 2>&1; then
  # --net: cargo resolves the dependency metadata from crates.io.
  echo "sbom.sh: generating with vk from PATH ($(command -v vk)); pass --docker to force Docker" >&2
  vk run \
    --file .devcontainer/Dockerfile --context .devcontainer --target enc-build \
    --workdir "$PWD" --net \
    -- sh -c "$SBOM_CMD"
else
  docker build --target enc-build -t enc-build -f .devcontainer/Dockerfile .devcontainer
  docker run --rm \
    --user "$(id -u):$(id -g)" -e HOME=/tmp \
    -v "$PWD":/work -w /work \
    enc-build \
    sh -c "$SBOM_CMD"
fi
ls -1 "$OUT"/"$BIN"-*.cdx.json
