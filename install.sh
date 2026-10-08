#!/bin/sh
# Builds iitg-connect and installs iitg-connect / iitg-stop / iitg-update / iitg-status
# into ~/.local/bin (override with BIN_DIR=...).
set -eu
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
cd "$(dirname "$0")"

cargo build --release
mkdir -p "$BIN_DIR"
install -m 755 target/release/iitg-connect "$BIN_DIR/iitg-connect"
for cmd in iitg-stop iitg-update iitg-status; do
    ln -sf iitg-connect "$BIN_DIR/$cmd"
done

echo "Installed to $BIN_DIR: iitg-connect, iitg-stop, iitg-update, iitg-status"
case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) echo "Note: $BIN_DIR is not in your PATH; add it to ~/.zshrc." ;;
esac
