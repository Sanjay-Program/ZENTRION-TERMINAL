#!/usr/bin/env sh
# Produce a distributable archive. Usage: scripts/package.sh
set -eu

sha256_file() {
	file="$1"
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$file" | cut -d' ' -f1
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$file" | cut -d' ' -f1
	elif command -v openssl >/dev/null 2>&1; then
		openssl dgst -sha256 "$file" | awk '{print $2}'
	else
		echo "no SHA-256 tool available" >&2
		exit 1
	fi
}

cargo build --workspace --release
OS="$(uname -s | tr 'A-Z' 'a-z')"
case "$OS" in
	mingw*|msys*|cygwin*) OS="windows" ;;
	darwin*) OS="macos" ;;
	linux*) OS="linux" ;;
esac
ARCH="$(uname -m)"
case "$ARCH" in
		x86_64|amd64) ARCH="x64" ;;
		aarch64|arm64) ARCH="arm64" ;;
esac
NAME="zentrion-${OS}-${ARCH}"
OUT="dist/${NAME}"
rm -rf "$OUT"
mkdir -p "$OUT/bin"
if [ -f target/release/z.exe ]; then
	cp target/release/z.exe "$OUT/bin/"
	BIN_NAME="bin/z.exe"
else
	cp target/release/z "$OUT/bin/"
	BIN_NAME="bin/z"
fi
cp README.md "$OUT/" 2>/dev/null || true
cp SECURITY.md "$OUT/" 2>/dev/null || true
cp CHANGELOG.md "$OUT/" 2>/dev/null || true
cp FAQ.md "$OUT/" 2>/dev/null || true
cp -R docs "$OUT/"
mkdir -p dist
tar -czf "dist/${NAME}.tar.gz" -C dist "$NAME"
SHA256="$(sha256_file "dist/${NAME}.tar.gz")"
printf '%s  %s\n' "$SHA256" "${NAME}.tar.gz" > "dist/${NAME}.tar.gz.sha256"
cat > "dist/${NAME}.json" <<EOF
{
	"name": "${NAME}",
	"os": "${OS}",
	"arch": "${ARCH}",
	"binary": "${BIN_NAME}",
	"archive": "${NAME}.tar.gz"
}
EOF
echo "Wrote dist/${NAME}.tar.gz"
echo "Wrote dist/${NAME}.tar.gz.sha256"
echo "Wrote dist/${NAME}.json"
