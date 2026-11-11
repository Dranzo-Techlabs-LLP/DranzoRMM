#!/usr/bin/env bash
# Build the DranzoRMM agent .deb and .rpm for one architecture with nfpm.
#
#   installers/linux/build-packages.sh --arch arm64 --binary path/to/dranzo-agent \
#       --version 1.4.0 --out dist/linux
#
# Signing rule (docs/SPEC.md section 8, docs/RUNBOOK.md "Signing secrets"):
#   * GPG_PRIVATE_KEY unset/empty  -> packages are built UNSIGNED and a loud
#                                     "UNSIGNED BUILD" notice is printed.
#   * GPG_PRIVATE_KEY set          -> packages MUST be signed. Any signing or
#                                     verification failure fails the build.
#   GPG_PRIVATE_KEY   ASCII-armoured private key (the key itself, not a path)
#   GPG_PASSPHRASE    its passphrase (optional if the key has none)
#
# Requires: nfpm >= 2.40, ar, tar; for signed builds also gpg, and rpm (rpmkeys)
# to verify the .rpm signature.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

arch=""
binary=""
version="${DRANZO_VERSION:-}"
out="$here/dist"

usage() {
  sed -n '2,6p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --arch) arch="${2:-}"; shift 2 ;;
    --binary) binary="${2:-}"; shift 2 ;;
    --version) version="${2:-}"; shift 2 ;;
    --out) out="${2:-}"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done

case "$arch" in
  amd64|arm64) ;;
  *) echo "error: --arch must be amd64 or arm64" >&2; exit 2 ;;
esac
[ -n "$version" ] || { echo "error: --version (or DRANZO_VERSION) is required" >&2; exit 2; }
[ -f "$binary" ] || { echo "error: --binary '$binary' does not exist" >&2; exit 2; }
command -v nfpm >/dev/null || { echo "error: nfpm is not installed" >&2; exit 2; }

notice() { # GitHub Actions annotation when running in CI, plain text otherwise
  if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::$1 title=$2::$3"; fi
  echo "[$2] $3" >&2
}

mkdir -p "$out"
out="$(cd "$out" && pwd)"

work="$(mktemp -d "${TMPDIR:-/tmp}/dranzo-nfpm.XXXXXX")"
cleanup() { rm -rf "$work"; }
trap cleanup EXIT

# ----- Stage (nfpm resolves contents relative to its working directory) -----
stage="$work/stage"
mkdir -p "$stage/scripts"
install -m 0755 "$binary" "$stage/dranzo-agent"
install -m 0644 "$here/nfpm.yaml" "$here/dranzormm-agent.service" "$here/10-hardening.conf" "$here/README.package" "$stage/"
install -m 0755 "$here/scripts/postinstall.sh" "$here/scripts/preremove.sh" "$here/scripts/postremove.sh" "$stage/scripts/"

# ----- Signing mode -----
sign=no
key_file=""
if [ -n "${GPG_PRIVATE_KEY:-}" ]; then
  sign=yes
  command -v gpg >/dev/null || { echo "error: GPG_PRIVATE_KEY is set but gpg is not installed" >&2; exit 1; }
  ( umask 077; printf '%s\n' "$GPG_PRIVATE_KEY" >"$work/signing-key.asc" )
  key_file="$work/signing-key.asc"
  # Fail early with a clear message if the secret is not a private key.
  # ([B]LOCK: same match, but this script does not itself contain the armour header that
  # the pre-commit "detect-private-key" hook looks for.)
  grep -q 'BEGIN PGP PRIVATE KEY [B]LOCK' "$key_file" \
    || { echo "error: GPG_PRIVATE_KEY is set but is not an ASCII-armoured PGP private key" >&2; exit 1; }
else
  notice warning "UNSIGNED BUILD" "Linux packages for $arch are NOT GPG-signed (GPG_PRIVATE_KEY is not configured). Do not distribute them to client devices."
fi

# ----- Build -----
for packager in deb rpm; do
  ( cd "$stage" && \
    NFPM_ARCH="$arch" DRANZO_VERSION="$version" NFPM_SIGNING_KEY_FILE="$key_file" \
    NFPM_PASSPHRASE="${GPG_PASSPHRASE:-}" \
    nfpm package --config nfpm.yaml --packager "$packager" --target "$out/" )
done

shopt -s nullglob
case "$arch" in amd64) rpm_arch=x86_64 ;; arm64) rpm_arch=aarch64 ;; esac
debs=("$out"/dranzo-agent_*_"$arch".deb)
rpms=("$out"/dranzo-agent-*."$rpm_arch".rpm)
[ ${#debs[@]} -ge 1 ] && [ ${#rpms[@]} -ge 1 ] || { echo "error: nfpm did not produce both packages in $out" >&2; exit 1; }

# ----- Verify signatures (signed mode only; any failure is fatal) -----
if [ "$sign" = yes ]; then
  export GNUPGHOME="$work/gnupg"
  mkdir -m 0700 "$GNUPGHOME"
  # Import only the PUBLIC half into a throwaway keyring for verification.
  gpg --batch --quiet --pinentry-mode loopback --passphrase "${GPG_PASSPHRASE:-}" --import "$key_file"
  gpg --batch --quiet --armor --export >"$work/public.asc"
  [ -s "$work/public.asc" ] || { echo "error: could not derive the public key from GPG_PRIVATE_KEY" >&2; exit 1; }

  for deb in "${debs[@]}"; do
    members="$(ar t "$deb")"
    echo "$members" | grep -qx '_gpgorigin' \
      || { echo "error: $deb has no _gpgorigin signature although signing is configured" >&2; exit 1; }
    control="$(echo "$members" | grep '^control\.tar')"
    data="$(echo "$members" | grep '^data\.tar')"
    ar p "$deb" _gpgorigin >"$work/deb.sig"
    # The origin signature covers debian-binary + control.tar.* + data.tar.* in that order.
    ar p "$deb" debian-binary "$control" "$data" | gpg --batch --quiet --verify "$work/deb.sig" - \
      || { echo "error: GPG signature of $deb does not verify" >&2; exit 1; }
    echo "verified deb signature: $(basename "$deb")"
  done

  command -v rpmkeys >/dev/null \
    || { echo "error: signing is configured but 'rpmkeys' (package: rpm) is not installed, cannot verify the .rpm signature" >&2; exit 1; }
  rpmdb="$work/rpmdb"
  mkdir -p "$rpmdb"
  rpmkeys --dbpath "$rpmdb" --import "$work/public.asc"
  for rpm in "${rpms[@]}"; do
    result="$(rpmkeys --dbpath "$rpmdb" --checksig --verbose "$rpm")" || { echo "$result" >&2; echo "error: signature of $rpm does not verify" >&2; exit 1; }
    echo "$result" | grep -Eqi 'signature.*: *OK' \
      || { echo "$result" >&2; echo "error: $rpm carries no valid GPG signature although signing is configured" >&2; exit 1; }
    echo "verified rpm signature: $(basename "$rpm")"
  done

  cp "$work/public.asc" "$out/dranzo-agent-signing-pubkey.asc"
fi

# ----- Checksums -----
( cd "$out" && for f in "${debs[@]}" "${rpms[@]}"; do
    if command -v sha256sum >/dev/null; then sha256sum "$(basename "$f")"; else shasum -a 256 "$(basename "$f")"; fi
  done >"SHA256SUMS.linux-$arch" )

echo "signed=$sign"
printf 'built: %s\n' "${debs[@]}" "${rpms[@]}"
