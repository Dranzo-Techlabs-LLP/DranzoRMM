#!/usr/bin/env bash
# Builds the DranzoRMM Windows verification kit (run on macOS or Linux).
#
# For windows/amd64 and windows/arm64 it cross-compiles the agent
# (dranzo-agent.exe, version 0.1.0-wintest) and EVERY agent test package
# ("go test -c", one <pkg>.test.exe per package, with the package's testdata/
# next to it), adds the PowerShell runner, a README and a manifest with
# SHA-256 sums, and zips it:
#
#   dist/windows-kit/DranzoWindowsKit-amd64.zip
#   dist/windows-kit/DranzoWindowsKit-arm64.zip
#
# No secrets, keys or trust anchors are embedded (the agent is built without
# compiled-in anchors; live enrollment passes --ca-file/--trust-file).
#
# Usage: scripts/windows-kit/build-kit.sh [amd64] [arm64]
set -euo pipefail

KIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$KIT_DIR/../.." && pwd)"
AGENT="$REPO/agent"
OUT="$REPO/dist/windows-kit"
VERSION="0.1.0-wintest"
MODULE="github.com/dranzo/dranzormm/agent"
ARCHES=("$@")
[ ${#ARCHES[@]} -eq 0 ] && ARCHES=(amd64 arm64)

command -v go >/dev/null || { echo "go is required" >&2; exit 1; }
command -v zip >/dev/null || { echo "zip is required" >&2; exit 1; }

sha256() {
	if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# The commit is read from .git without running git (the kit must build from
# a plain checkout or an exported tree too).
git_commit() {
	local gd="$REPO/.git" head ref
	[ -f "$gd/HEAD" ] || { echo "unknown"; return; }
	head="$(cat "$gd/HEAD")"
	case "$head" in
	ref:*)
		ref="${head#ref: }"
		if [ -f "$gd/$ref" ]; then cat "$gd/$ref"
		elif [ -f "$gd/packed-refs" ] && grep -q " $ref\$" "$gd/packed-refs"; then grep " $ref\$" "$gd/packed-refs" | cut -d' ' -f1
		else echo "unknown"; fi ;;
	*) echo "$head" ;;
	esac
}

json_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

COMMIT="$(git_commit)"
BUILT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
GOVERSION="$(go env GOVERSION)"
mkdir -p "$OUT"

cd "$AGENT"
# Packages that have tests (internal and external test files), for Windows.
PKGS=()
while IFS= read -r p; do [ -n "$p" ] && PKGS+=("$p"); done < <(
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go list -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}' ./...)
echo "test packages: ${#PKGS[@]}"

for arch in "${ARCHES[@]}"; do
	name="DranzoWindowsKit-$arch"
	stage="$OUT/stage-$arch"
	root="$stage/$name"
	rm -rf "$stage" "$OUT/$name.zip"
	mkdir -p "$root/bin" "$root/tests"
	echo "== windows/$arch"

	GOOS=windows GOARCH="$arch" CGO_ENABLED=0 go build -trimpath \
		-ldflags "-X $MODULE/internal/buildinfo.Version=$VERSION" \
		-o "$root/bin/dranzo-agent.exe" ./cmd/dranzo-agent

	entries=""
	for pkg in "${PKGS[@]}"; do
		rel="${pkg#"$MODULE"/}"
		base="$(basename "$rel")"
		dest="$root/tests/$rel"
		mkdir -p "$dest"
		echo "   test $rel"
		# -s -w drops the symbol table and DWARF only; panics and t.Log keep
		# their file:line (from the Go runtime's own tables).
		GOOS=windows GOARCH="$arch" CGO_ENABLED=0 go test -c -trimpath \
			-ldflags "-s -w -X $MODULE/internal/buildinfo.Version=$VERSION" \
			-o "$dest/$base.test.exe" "./$rel"
		if [ -d "$AGENT/$rel/testdata" ]; then
			cp -R "$AGENT/$rel/testdata" "$dest/testdata"
		fi
		sum="$(sha256 "$dest/$base.test.exe")"
		size="$(wc -c <"$dest/$base.test.exe" | tr -d ' ')"
		entries="$entries    {\"package\": \"$(json_escape "$rel")\", \"path\": \"tests/$(json_escape "$rel")/$base.test.exe\", \"sha256\": \"$sum\", \"bytes\": $size, \"testdata\": $([ -d "$dest/testdata" ] && echo true || echo false)},
"
	done
	entries="${entries%,
}"

	cp "$KIT_DIR/Run-DranzoWindowsTests.ps1" "$root/"
	# README.txt: the owner's instructions with Windows line endings.
	sed 's/$/\r/' "$KIT_DIR/README.md" >"$root/README.txt"

	agent_sum="$(sha256 "$root/bin/dranzo-agent.exe")"
	cat >"$root/manifest.json" <<EOF
{
  "kit": "$name",
  "agentVersion": "$VERSION",
  "goos": "windows",
  "goarch": "$arch",
  "gitCommit": "$(json_escape "$COMMIT")",
  "buildTime": "$BUILT",
  "goVersion": "$(json_escape "$GOVERSION")",
  "agent": {"path": "bin/dranzo-agent.exe", "sha256": "$agent_sum"},
  "runner": {"path": "Run-DranzoWindowsTests.ps1", "sha256": "$(sha256 "$root/Run-DranzoWindowsTests.ps1")"},
  "tests": [
$entries
  ]
}
EOF
	# The kit must never carry key material.
	if find "$root" -type f \( -name '*.key' -o -name '*.pfx' -o -name '*.p12' -o -name 'bootstrap.json' -o -name 'token*.txt' \) | grep -q .; then
		echo "refusing to package key or token files:" >&2
		find "$root" -type f \( -name '*.key' -o -name '*.pfx' -o -name '*.p12' -o -name 'bootstrap.json' -o -name 'token*.txt' \) >&2
		exit 1
	fi
	(cd "$stage" && zip -qr -X "$OUT/$name.zip" "$name")
	rm -rf "$stage"
	ls -l "$OUT/$name.zip" | awk '{print "   " $5 " bytes  " $NF}'
done
