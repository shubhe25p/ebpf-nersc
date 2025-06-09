#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <name>"
  exit 1
fi

NAME=$1

echo "→ Building BPF program (${NAME}.bpf.c)…"
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 \
  -c "${NAME}.bpf.c" -o "${NAME}.temp.bpf.o"

echo "→ Generating relocatable BPF object (${NAME}.bpf.o)…"
bpftool gen object "${NAME}.bpf.o" "${NAME}.temp.bpf.o"

echo "→ Generating skeleton header (${NAME}.skel.h)…"
bpftool gen skeleton "${NAME}.bpf.o" > "${NAME}.skel.h"

echo "→ Compiling user-space program (${NAME}.user.c)…"
clang -g -Wall -c "${NAME}.user.c" -o "${NAME}.o"

echo "→ Linking final binary (${NAME})…"
clang -g -Wall "${NAME}.o" \
  -L"$HOME/libbpf/src" -lbpf -lelf -lz \
  -o "${NAME}"

echo "→ Cleaning up…"
rm -f "${NAME}.o" "${NAME}.bpf.o" "${NAME}.temp.bpf.o"

echo "✅ Done. Run with: sudo ./${NAME}"