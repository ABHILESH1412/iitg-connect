#!/bin/sh
# Linux and macOS installer: builds iitg-connect and installs iitg-connect / iitg-stop /
# iitg-update / iitg-status into ~/.local/bin (override with BIN_DIR=...).
set -eu
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
cd "$(dirname "$0")"

if ! command -v cargo >/dev/null 2>&1; then
    echo "Rust is not installed. Install it from https://rustup.rs and run this again." >&2
    exit 1
fi

cargo build --release
mkdir -p "$BIN_DIR"
# Remove first so a running copy keeps its old file instead of being overwritten in place.
rm -f "$BIN_DIR/iitg-connect"
cp target/release/iitg-connect "$BIN_DIR/iitg-connect"
chmod 755 "$BIN_DIR/iitg-connect"
for cmd in iitg-stop iitg-update iitg-status; do
    ln -sf iitg-connect "$BIN_DIR/$cmd"
done

echo "Installed to $BIN_DIR: iitg-connect, iitg-stop, iitg-update, iitg-status"
case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *)
        echo "Add $BIN_DIR to your PATH, then open a new terminal:"
        echo "  echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.$(basename "${SHELL:-sh}")rc"
        ;;
esac
