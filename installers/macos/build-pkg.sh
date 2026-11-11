#!/usr/bin/env bash
# Build the DranzoRMM agent macOS installer package (DranzoAgent.pkg).
#
#   installers/macos/build-pkg.sh --binary dist/agent/dranzo-agent-darwin-universal \
#       --version 1.4.0 --out dist/macos
#
# Steps: (codesign binary) -> pkgbuild component -> productbuild distribution
#        -> (productsign -> notarytool -> stapler). macOS only.
#
# Signing rule (docs/SPEC.md section 8, docs/RUNBOOK.md "Signing secrets"):
#   * none of the APPLE_* variables below set  -> UNSIGNED package + loud
#     "UNSIGNED BUILD" notice. Gatekeeper will block it on other Macs.
#   * all of them set                          -> the binary is signed (Developer ID
#     Application, hardened runtime, secure timestamp), the package is signed
#     (Developer ID Installer), notarised and stapled. ANY failure fails the build.
#   * some but not all set                     -> the build fails ("partially configured").
#
#   APPLE_SIGN_APP_IDENTITY         "Developer ID Application: NAME (TEAMID)" or its SHA-1
#   APPLE_SIGN_INSTALLER_IDENTITY   "Developer ID Installer: NAME (TEAMID)" or its SHA-1
#   APPLE_SIGN_KEYCHAIN             optional: keychain that holds both identities
#   Notarisation, either an App Store Connect API key ...
#     APPLE_NOTARY_KEY_PATH         path to AuthKey_XXXX.p8
#     APPLE_NOTARY_KEY_ID           key ID
#     APPLE_NOTARY_ISSUER_ID        issuer UUID
#   ... or a stored profile (local use: `xcrun notarytool store-credentials`):
#     APPLE_NOTARY_KEYCHAIN_PROFILE profile name
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

binary=""
version="${DRANZO_VERSION:-}"
out="$here/dist"
PKG_ID="com.dranzormm.agent.pkg"
BIN_ID="com.dranzormm.agent"
PKG_NAME="DranzoAgent.pkg"   # name printed by the dashboard's install instructions

while [ $# -gt 0 ]; do
  case "$1" in
    --binary) binary="${2:-}"; shift 2 ;;
    --version) version="${2:-}"; shift 2 ;;
    --out) out="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,8p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ "$(uname -s)" = Darwin ] || { echo "error: build-pkg.sh must run on macOS (pkgbuild/productbuild/codesign)" >&2; exit 2; }
[ -f "$binary" ] || { echo "error: --binary '$binary' does not exist" >&2; exit 2; }
[ -n "$version" ] || { echo "error: --version (or DRANZO_VERSION) is required" >&2; exit 2; }
# pkg versions are dotted numbers; drop any semver pre-release / build suffix.
pkg_version="${version%%[-+]*}"
[[ "$pkg_version" =~ ^[0-9]+(\.[0-9]+){1,3}$ ]] || { echo "error: version '$version' has no numeric X.Y.Z prefix" >&2; exit 2; }

notice() { # GitHub Actions annotation when running in CI, plain text otherwise
  if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::$1 title=$2::$3"; fi
  echo "[$2] $3" >&2
}

# ----- Signing mode -----
app_id="${APPLE_SIGN_APP_IDENTITY:-}"
inst_id="${APPLE_SIGN_INSTALLER_IDENTITY:-}"
keychain="${APPLE_SIGN_KEYCHAIN:-}"
notary_profile="${APPLE_NOTARY_KEYCHAIN_PROFILE:-}"
notary_key="${APPLE_NOTARY_KEY_PATH:-}"
notary_key_id="${APPLE_NOTARY_KEY_ID:-}"
notary_issuer="${APPLE_NOTARY_ISSUER_ID:-}"

any_set="${app_id}${inst_id}${keychain}${notary_profile}${notary_key}${notary_key_id}${notary_issuer}"
sign=no
if [ -n "$any_set" ]; then
  sign=yes
  missing=()
  [ -n "$app_id" ] || missing+=(APPLE_SIGN_APP_IDENTITY)
  [ -n "$inst_id" ] || missing+=(APPLE_SIGN_INSTALLER_IDENTITY)
  if [ -z "$notary_profile" ]; then
    [ -n "$notary_key" ] || missing+=(APPLE_NOTARY_KEY_PATH)
    [ -n "$notary_key_id" ] || missing+=(APPLE_NOTARY_KEY_ID)
    [ -n "$notary_issuer" ] || missing+=(APPLE_NOTARY_ISSUER_ID)
  fi
  if [ ${#missing[@]} -gt 0 ]; then
    echo "error: macOS signing is partially configured; missing: ${missing[*]}" >&2
    echo "error: refusing to produce an unsigned package while signing settings are present" >&2
    exit 1
  fi
  if [ -n "$notary_key" ] && [ ! -f "$notary_key" ]; then
    echo "error: APPLE_NOTARY_KEY_PATH '$notary_key' does not exist" >&2
    exit 1
  fi
else
  notice warning "UNSIGNED BUILD" "macOS package is NOT code-signed and NOT notarised (no APPLE_* signing settings). Gatekeeper will block it; do not distribute it to client devices."
fi

mkdir -p "$out"
out="$(cd "$out" && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/dranzo-pkg.XXXXXX")"
cleanup() { rm -rf "$work"; }
trap cleanup EXIT

# ----- Facts from the binary -----
archs="$(lipo -archs "$binary")"
host_archs="$(echo "$archs" | tr ' ' ',' )"
# Lowest macOS the binary can run on, from LC_BUILD_VERSION (highest across slices).
min_macos="$(otool -l "$binary" | awk '/LC_BUILD_VERSION/{f=1} f && /minos/{print $2; f=0}' | sort -t. -k1,1n -k2,2n | tail -1)"
[ -n "$min_macos" ] || { echo "error: could not read the minimum macOS version from $binary" >&2; exit 1; }
min_major="${min_macos%%.*}"
echo "binary: archs=[$archs] minimum macOS=$min_macos version=$version (pkg $pkg_version)"

# ----- Payload -----
root="$work/root"
mkdir -p "$root/usr/local/bin" "$root/Library/DranzoRMM"
install -m 0755 "$binary" "$root/usr/local/bin/dranzo-agent"
install -m 0755 "$here/uninstall.sh" "$root/Library/DranzoRMM/uninstall.sh"
install -m 0644 "$here/resources/README.txt" "$root/Library/DranzoRMM/README.txt"
plutil -lint "$here/com.dranzormm.agent.plist" >/dev/null
install -m 0644 "$here/com.dranzormm.agent.plist" "$root/Library/DranzoRMM/com.dranzormm.agent.plist"
# No resource forks / Finder metadata in the payload.
xattr -cr "$root" 2>/dev/null || true
find "$root" -name '.DS_Store' -delete

scripts="$work/scripts"
mkdir -p "$scripts"
sed "s/__MIN_MACOS_MAJOR__/${min_major}/" "$here/scripts/preinstall" >"$scripts/preinstall"
install -m 0755 "$here/scripts/postinstall" "$scripts/postinstall"
chmod 0755 "$scripts/preinstall"

# ----- Sign the binary (before it goes into the package) -----
if [ "$sign" = yes ]; then
  # (the ${arr[@]+...} form below keeps `set -u` happy on macOS's bash 3.2 when the array is empty)
  kc_args=()
  if [ -n "$keychain" ]; then kc_args=(--keychain "$keychain"); fi
  # --options runtime = hardened runtime (required for notarisation);
  # --timestamp = Apple secure timestamp (required for notarisation).
  # No entitlements: the agent needs none (no JIT, no library injection).
  codesign --force --timestamp --options runtime --identifier "$BIN_ID" \
    ${kc_args[@]+"${kc_args[@]}"} --sign "$app_id" "$root/usr/local/bin/dranzo-agent"
  codesign --verify --strict --verbose=2 "$root/usr/local/bin/dranzo-agent"
  codesign --display --verbose=2 "$root/usr/local/bin/dranzo-agent" 2>&1 | grep -q 'flags=.*runtime' \
    || { echo "error: hardened runtime flag missing on the signed binary" >&2; exit 1; }
fi

# ----- Component package -----
pkgbuild \
  --root "$root" \
  --identifier "$PKG_ID" \
  --version "$pkg_version" \
  --install-location / \
  --scripts "$scripts" \
  --ownership recommended \
  "$work/agent-component.pkg"

# pkgbuild archives extended attributes as AppleDouble "._*" entries. When the
# build is started from an application macOS tracks with com.apple.provenance
# (many third-party terminals and IDEs), every staged file carries that
# attribute, `xattr -c` cannot remove it, and the payload would install junk
# such as /usr/local/bin/._dranzo-agent. GitHub runners and Terminal.app do not
# trigger this. If it happens, rebuild Payload and Bom without those entries.
strip_appledouble() {
  local pkg="$1" exp="$work/expanded" count
  rm -rf "$exp"
  pkgutil --expand "$pkg" "$exp"
  (
    cd "$exp"
    mkdir .payload
    ( cd .payload
      gunzip -dc ../Payload | cpio -i --quiet
      find . -name '._*' -delete
      # -R 0:0 = root:wheel, the same ownership `--ownership recommended` produced.
      find . | COPYFILE_DISABLE=1 cpio -o --quiet --format odc -R 0:0 | gzip -c >../Payload.new )
    # lsbom output is the input format of `mkbom -i`.
    lsbom Bom | grep -v '/\._[^/]*' >.filelist
    mkbom -i .filelist Bom.new
    count="$(wc -l <.filelist | tr -d ' ')"
    mv Payload.new Payload
    mv Bom.new Bom
    rm -rf .payload .filelist
    find Scripts -name '._*' -delete 2>/dev/null || true
    sed -i '' -E "s/numberOfFiles=\"[0-9]+\"/numberOfFiles=\"${count}\"/" PackageInfo
  )
  rm -f "$pkg"
  pkgutil --flatten "$exp" "$pkg"
  rm -rf "$exp"
}
if pkgutil --payload-files "$work/agent-component.pkg" | grep -q '/\._'; then
  echo "note: stripping AppleDouble entries that pkgbuild generated from extended attributes"
  strip_appledouble "$work/agent-component.pkg"
fi

# ----- Distribution (product) package -----
sed -e "s/__VERSION__/${pkg_version}/g" \
    -e "s/__MIN_MACOS__/${min_macos}/g" \
    -e "s/__HOST_ARCHS__/${host_archs}/g" \
    "$here/distribution.xml.in" >"$work/distribution.xml"

unsigned_pkg="$work/unsigned-$PKG_NAME"
productbuild \
  --distribution "$work/distribution.xml" \
  --package-path "$work" \
  --resources "$here/resources" \
  "$unsigned_pkg"

final="$out/$PKG_NAME"
rm -f "$final"

if [ "$sign" = yes ]; then
  ps_args=()
  if [ -n "$keychain" ]; then ps_args=(--keychain "$keychain"); fi
  productsign --timestamp ${ps_args[@]+"${ps_args[@]}"} --sign "$inst_id" "$unsigned_pkg" "$final"
  pkgutil --check-signature "$final"

  # ----- Notarise and staple -----
  if [ -n "$notary_profile" ]; then
    notary_auth=(--keychain-profile "$notary_profile")
  else
    notary_auth=(--key "$notary_key" --key-id "$notary_key_id" --issuer "$notary_issuer")
  fi
  # notarytool exits 0 for a completed submission even when Apple rejects it,
  # so the status is checked explicitly.
  xcrun notarytool submit "$final" "${notary_auth[@]}" --wait --timeout 30m \
    --output-format json >"$work/notary.json" || { cat "$work/notary.json" >&2 || true; echo "error: notarytool submit failed" >&2; exit 1; }
  status="$(plutil -extract status raw -o - "$work/notary.json" 2>/dev/null || true)"
  sub_id="$(plutil -extract id raw -o - "$work/notary.json" 2>/dev/null || true)"
  if [ "$status" != "Accepted" ]; then
    echo "error: notarisation status is '${status:-unknown}' (submission ${sub_id:-?})" >&2
    [ -n "$sub_id" ] && xcrun notarytool log "$sub_id" "${notary_auth[@]}" >&2 || true
    exit 1
  fi
  xcrun stapler staple "$final"
  xcrun stapler validate "$final"
  # Gatekeeper's own verdict on the finished package.
  spctl --assess --type install --verbose=2 "$final"
  echo "signed=yes notarised=yes"
else
  cp "$unsigned_pkg" "$final"
  echo "signed=no notarised=no"
fi

# Guard against AppleDouble files ever reaching the payload again.
if pkgutil --payload-files "$final" | grep -q '/\._'; then
  echo "error: package payload contains AppleDouble (._*) files" >&2
  exit 1
fi

( cd "$out" && shasum -a 256 "$PKG_NAME" >"SHA256SUMS.macos" )
echo "built: $final"
