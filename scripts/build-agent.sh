#!/usr/bin/env bash
# Cross-compile the DranzoRMM agent. Used by CI and for local packaging tests.
#
#   scripts/build-agent.sh                      # all six targets (+ macOS universal when lipo exists)
#   scripts/build-agent.sh linux/arm64          # one target
#   scripts/build-agent.sh darwin/universal     # both darwin targets + lipo (macOS only)
#
# Output: $OUT_DIR (default: dist/agent)/dranzo-agent-<os>-<arch>[.exe]
#
# Environment:
#   DRANZO_VERSION             version stamped into the binary (default 0.0.0-dev)
#   OUT_DIR                    output directory
#   DRANZO_EMBED_COMMAND_KEYS  optional "kid:base64pub[,kid2:base64pub]" command-signing PUBLIC keys
#   DRANZO_EMBED_CA_PEM_B64    optional base64 of the PEM bundle of the pinned CA certificate(s)
# The two DRANZO_EMBED_* values are public trust anchors of ONE server deployment
# (GET /api/v1/agent/install-info returns them). Without them the binary has no
# built-in trust anchors and `dranzo-agent install` needs --ca-file/--trust-file.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${OUT_DIR:-$root/dist/agent}"
version="${DRANZO_VERSION:-0.0.0-dev}"
pkg="github.com/dranzo/dranzormm/agent/internal/buildinfo"

all_targets=(windows/amd64 windows/arm64 darwin/amd64 darwin/arm64 linux/amd64 linux/arm64)

# -s -w: strip symbol/debug tables (smaller binary; panics still show file:line).
ldflags="-s -w -X ${pkg}.Version=${version}"
if [ -n "${DRANZO_EMBED_COMMAND_KEYS:-}" ]; then
  ldflags="$ldflags -X ${pkg}.EmbeddedCommandKeys=${DRANZO_EMBED_COMMAND_KEYS}"
fi
if [ -n "${DRANZO_EMBED_CA_PEM_B64:-}" ]; then
  ldflags="$ldflags -X ${pkg}.EmbeddedCAPEMBase64=${DRANZO_EMBED_CA_PEM_B64}"
fi

mkdir -p "$out"
out="$(cd "$out" && pwd)"

build_one() {
  local goos="${1%/*}" goarch="${1#*/}" ext=""
  [ "$goos" = windows ] && ext=".exe"
  local dest="$out/dranzo-agent-${goos}-${goarch}${ext}"
  echo "building $goos/$goarch -> $dest"
  # CGO_ENABLED=0: static binary, no libc dependency, reproducible cross-compilation.
  # -trimpath: no local filesystem paths in the binary.
  ( cd "$root/agent" && \
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags "$ldflags" -o "$dest" ./cmd/dranzo-agent )
}

universal() {
  command -v lipo >/dev/null || { echo "error: lipo not found (macOS only)" >&2; exit 1; }
  local dest="$out/dranzo-agent-darwin-universal"
  lipo -create -output "$dest" "$out/dranzo-agent-darwin-amd64" "$out/dranzo-agent-darwin-arm64"
  lipo -info "$dest"
}

targets=("$@")
[ ${#targets[@]} -gt 0 ] || targets=("${all_targets[@]}")

want_universal=no
for t in "${targets[@]}"; do
  case "$t" in
    darwin/universal)
      build_one darwin/amd64
      build_one darwin/arm64
      want_universal=yes
      ;;
    windows/amd64|windows/arm64|darwin/amd64|darwin/arm64|linux/amd64|linux/arm64)
      build_one "$t"
      ;;
    *)
      echo "error: unsupported target '$t' (expected one of: ${all_targets[*]} darwin/universal)" >&2
      exit 2
      ;;
  esac
done

if [ "$want_universal" = yes ]; then
  universal
elif [ $# -eq 0 ] && command -v lipo >/dev/null; then
  universal
fi

echo "done: $out"
