#!/usr/bin/env bash
# Build a statically linked secilc from the SELinux 3.11 source trees.
#
# libsepol 3.11 bundles CIL and generates its lexer with flex, so flex must be present
# (Manjaro: pacman -S flex). The resulting binary links libsepol statically and carries no
# runtime libsepol dependency, which is the point: it cannot drift against the system libsepol.
#
# Usage: build-secilc.sh <libsepol-src-dir> <secilc-src-dir> [output-path]
#   <libsepol-src-dir>  extracted libsepol-3.11 source tree
#   <secilc-src-dir>    extracted secilc-3.11 source tree
#   [output-path]       destination for the binary (default: ./secilc)

set -euo pipefail

LIBSEPOL_SRC="${1:?libsepol source dir required}"
SECILC_SRC="${2:?secilc source dir required}"
OUT="${3:-./secilc}"

command -v flex >/dev/null || { echo "flex not found (Manjaro: pacman -S flex)" >&2; exit 1; }
command -v gcc  >/dev/null || { echo "gcc not found" >&2; exit 1; }

# Static libsepol archive (generates cil_lexer.c via flex as a side effect).
make -C "$LIBSEPOL_SRC/src" libsepol.a

# Link secilc fully static against the archive.
gcc -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -O2 \
    -I"$LIBSEPOL_SRC/include" -static \
    -o "$OUT" "$SECILC_SRC/secilc.c" "$LIBSEPOL_SRC/src/libsepol.a"

strip "$OUT" || true
echo "built: $OUT"
file "$OUT"
sha256sum "$OUT"
