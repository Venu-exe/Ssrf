#!/usr/bin/env bash
# Installer for ssrf_oob.sh -- copies the script and wordlist into a
# bin/share layout under a prefix (default: ~/.local) and checks deps.
set -euo pipefail

PREFIX="${PREFIX:-$HOME/.local}"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BIN_DIR="$PREFIX/bin"
SHARE_DIR="$PREFIX/share/ssrf-oob"

mkdir -p "$BIN_DIR" "$SHARE_DIR/wordlists"
cp "$SRC_DIR/ssrf_oob.sh" "$BIN_DIR/ssrf_oob.sh"
chmod +x "$BIN_DIR/ssrf_oob.sh"
cp "$SRC_DIR/wordlists/params.txt" "$SHARE_DIR/wordlists/params.txt"

# Point the installed copy at the installed wordlist via a tiny wrapper
# only if the wordlist is not next to the script (script prefers the
# wordlist next to itself, then falls back to built-ins).
if [ ! -f "$BIN_DIR/wordlists/params.txt" ]; then
    mkdir -p "$BIN_DIR/wordlists"
    cp "$SRC_DIR/wordlists/params.txt" "$BIN_DIR/wordlists/params.txt"
fi

echo "Installed:"
echo "  $BIN_DIR/ssrf_oob.sh"
echo "  $BIN_DIR/wordlists/params.txt"
echo ""
echo "Make sure $BIN_DIR is on your PATH, e.g.:"
echo "  export PATH=\"$BIN_DIR:\$PATH\""
echo ""

missing=0
for dep in bash curl; do
    command -v "$dep" >/dev/null || { echo "MISSING: $dep"; missing=1; }
done
if ! command -v interactsh-client >/dev/null; then
    echo "MISSING: interactsh-client (install with: go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest)"
    echo "         or just run ssrf_oob.sh with -y once (requires Go)."
    missing=1
fi
command -v jq >/dev/null || echo "optional: jq not found (script falls back to grep parsing)"
command -v go >/dev/null || echo "optional: go not found (needed only for -y auto-install)"
[ "$missing" -eq 0 ] && echo "All required dependencies present."
