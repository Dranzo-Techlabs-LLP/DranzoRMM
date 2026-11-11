#!/usr/bin/env bash
# CI helper (macOS runner): turn the Apple signing SECRETS into the settings
# build-pkg.sh expects, using a throwaway keychain.
#
#   installers/macos/ci-import-signing.sh setup     # before build-pkg.sh
#   installers/macos/ci-import-signing.sh cleanup   # always() afterwards
#
# Secrets (GitHub environment "release-signing"; see docs/RUNBOOK.md):
#   APPLE_DEVELOPER_ID_APPLICATION_P12_BASE64   base64 of the Developer ID Application .p12
#   APPLE_DEVELOPER_ID_INSTALLER_P12_BASE64     base64 of the Developer ID Installer .p12
#   APPLE_P12_PASSWORD                          password of both .p12 files
#   APPLE_NOTARY_KEY_P8_BASE64                  base64 of the App Store Connect API key (AuthKey_XXXX.p8)
#   APPLE_NOTARY_KEY_ID                         its key ID
#   APPLE_NOTARY_ISSUER_ID                      its issuer UUID
#
# Rule: no secret set -> nothing is exported and build-pkg.sh produces an
# UNSIGNED package with a notice. Some but not all set -> hard failure.
# All set -> identities are exported; build-pkg.sh then MUST sign and notarise.
set -euo pipefail

tmp="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
keychain="$tmp/dranzo-signing.keychain-db"
notary_key="$tmp/dranzo-notary-AuthKey.p8"

cleanup() {
  security delete-keychain "$keychain" >/dev/null 2>&1 || true
  rm -f "$notary_key" "$tmp/dranzo-app.p12" "$tmp/dranzo-installer.p12"
}

setup() {
  local names=(APPLE_DEVELOPER_ID_APPLICATION_P12_BASE64 APPLE_DEVELOPER_ID_INSTALLER_P12_BASE64 \
               APPLE_P12_PASSWORD APPLE_NOTARY_KEY_P8_BASE64 APPLE_NOTARY_KEY_ID APPLE_NOTARY_ISSUER_ID)
  local present=0 missing=() n
  for n in "${names[@]}"; do
    if [ -n "${!n:-}" ]; then present=$((present + 1)); else missing+=("$n"); fi
  done
  if [ "$present" -eq 0 ]; then
    echo "No Apple signing secrets configured: the package will be UNSIGNED."
    return 0
  fi
  if [ ${#missing[@]} -gt 0 ]; then
    echo "::error title=macOS signing misconfigured::Some Apple signing secrets are set but these are missing: ${missing[*]}"
    exit 1
  fi

  umask 077
  local kc_pass
  kc_pass="$(openssl rand -hex 24)"
  cleanup
  security create-keychain -p "$kc_pass" "$keychain"
  security set-keychain-settings -lut 3600 "$keychain"
  security unlock-keychain -p "$kc_pass" "$keychain"

  printf '%s' "$APPLE_DEVELOPER_ID_APPLICATION_P12_BASE64" | base64 --decode >"$tmp/dranzo-app.p12"
  printf '%s' "$APPLE_DEVELOPER_ID_INSTALLER_P12_BASE64" | base64 --decode >"$tmp/dranzo-installer.p12"
  security import "$tmp/dranzo-app.p12" -k "$keychain" -P "$APPLE_P12_PASSWORD" -T /usr/bin/codesign
  security import "$tmp/dranzo-installer.p12" -k "$keychain" -P "$APPLE_P12_PASSWORD" -T /usr/bin/productsign
  rm -f "$tmp/dranzo-app.p12" "$tmp/dranzo-installer.p12"
  # Let codesign/productsign use the keys without a UI prompt.
  security set-key-partition-list -S apple-tool:,apple: -s -k "$kc_pass" "$keychain" >/dev/null
  # Put the keychain on the search list (keeping the existing ones).
  # shellcheck disable=SC2046
  security list-keychains -d user -s "$keychain" $(security list-keychains -d user | tr -d '"')

  local app_id inst_id
  app_id="$(security find-identity -v -p codesigning "$keychain" | awk '/Developer ID Application/{print $2; exit}')"
  inst_id="$(security find-identity -v "$keychain" | awk '/Developer ID Installer/{print $2; exit}')"
  [ -n "$app_id" ] || { echo "::error::no 'Developer ID Application' identity in the imported certificate"; exit 1; }
  [ -n "$inst_id" ] || { echo "::error::no 'Developer ID Installer' identity in the imported certificate"; exit 1; }

  printf '%s' "$APPLE_NOTARY_KEY_P8_BASE64" | base64 --decode >"$notary_key"

  {
    echo "APPLE_SIGN_APP_IDENTITY=$app_id"
    echo "APPLE_SIGN_INSTALLER_IDENTITY=$inst_id"
    echo "APPLE_SIGN_KEYCHAIN=$keychain"
    echo "APPLE_NOTARY_KEY_PATH=$notary_key"
    echo "APPLE_NOTARY_KEY_ID=$APPLE_NOTARY_KEY_ID"
    echo "APPLE_NOTARY_ISSUER_ID=$APPLE_NOTARY_ISSUER_ID"
  } >>"${GITHUB_ENV:?GITHUB_ENV is not set (this helper is for GitHub Actions)}"
  echo "Apple signing identities imported; the package MUST be signed and notarised."
}

case "${1:-}" in
  setup) setup ;;
  cleanup) cleanup ;;
  *) echo "usage: $0 setup|cleanup" >&2; exit 2 ;;
esac
