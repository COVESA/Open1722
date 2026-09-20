#!/bin/sh
#
# Copyright (c) 2026, COVESA
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#    # Redistributions of source code must retain the above copyright notice,
#      this list of conditions and the following disclaimer.
#    # Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in the
#      documentation and/or other materials provided with the distribution.
#    # Neither the name of COVESA nor the names of its contributors may be
#      used to endorse or promote products derived from this software without
#      specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# SPDX-License-Identifier: BSD-3-Clause
#
# Verifies that version-typed accessors fold to direct bit manipulation:
#
# 1. The performance path is the header path: a consumer probe compiled at -O2
#    must produce call-free code for both the typed and the agnostic accessor.
# 2. The exported copies in libopen1722.so are FFI wrappers. C semantic
#    interposition prevents the compiler from fully folding them, so the check
#    only asserts that they never fall back to the version-agnostic dispatcher,
#    the generic engine or the version readers.
#
# Usage: ./bench/check-folding.sh [build-dir]

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
build_dir=${1:-"$root_dir/build-folding"}

if ! command -v objdump >/dev/null 2>&1; then
    echo "check-folding: objdump not found" >&2
    exit 2
fi

echo "Configuring $build_dir (Release)..."
cmake -S "$root_dir" -B "$build_dir" -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build "$build_dir" --target open1722 -j"$(nproc)" >/dev/null

lib="$build_dir/src/libopen1722.so"
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

objdump -d --no-show-raw-insn "$lib" >"$tmp_dir/disasm.txt"

failures=0

function_body() {
    symbol=$1
    file=$2
    awk -v s="$symbol" '
        $0 ~ ("^[0-9a-f]+ <" s ">:") { found = 1; print; next }
        $0 == (s ":") { found = 1; print; next }
        found && /^[0-9a-f]+ </ { exit }
        found && /^\.cfi_endproc/ { print; exit }
        found { print }
    ' "$file"
}

# Forbidden in an exported version-typed accessor: the generic engine, the
# version-agnostic dispatcher of any format, and the version readers.
FORBIDDEN='Avtp_GetField(@plt|\.part|>)|Avtp_SetField(@plt|\.part|>)|Avtp_[A-Za-z]+_GetField(@plt|\.part|>)|Avtp_[A-Za-z]+_SetField(@plt|\.part|>)|GetVersion(@plt|\.part|>)'

check_exported_typed() {
    symbol=$1
    body=$(function_body "$symbol" "$tmp_dir/disasm.txt")
    if [ -z "$body" ]; then
        echo "FAIL  $symbol: symbol not found in $lib"
        failures=$((failures + 1))
        return
    fi
    if printf '%s\n' "$body" | grep -qE "$FORBIDDEN"; then
        echo "FAIL  $symbol: falls back to dispatch/engine/version read"
        printf '%s\n' "$body" | grep -E "$FORBIDDEN" | sed 's/^/      /'
        failures=$((failures + 1))
    else
        echo "ok    $symbol"
    fi
}

echo
echo "Exported version-typed accessors (expect no dispatch/engine fallback):"
check_exported_typed Avtp_Tscf_GetSequenceNum_V1
check_exported_typed Avtp_Tscf_SetSequenceNum_V1
check_exported_typed Avtp_CommonStreamHeader_GetStreamId_V1
check_exported_typed Avtp_Rvf_GetActivePixels_V1

echo
echo "Consumer probe compiled at -O2 (expect call-free code):"
cat >"$tmp_dir/probe.c" <<'EOF'
#include "avtp/acf/Tscf.h"

uint32_t probe_typed(const Avtp_TscfV1_t *pdu)
{
    return Avtp_Tscf_GetSequenceNum_V1(pdu);
}

uint32_t probe_agnostic(const Avtp_Tscf_t *pdu)
{
    return Avtp_Tscf_GetSequenceNum(pdu);
}
EOF
cc -std=c99 -O2 -I"$root_dir/include" -S -o"$tmp_dir/probe.s" "$tmp_dir/probe.c"
for probe in probe_typed probe_agnostic; do
    body=$(function_body "$probe" "$tmp_dir/probe.s")
    if [ -z "$body" ]; then
        echo "FAIL  $probe: not found in generated assembly"
        failures=$((failures + 1))
    elif printf '%s\n' "$body" | grep -qE '[[:space:]]call'; then
        echo "FAIL  $probe: contains a call"
        printf '%s\n' "$body" | grep -E '[[:space:]]call' | sed 's/^/      /'
        failures=$((failures + 1))
    else
        echo "ok    $probe"
    fi
done

echo
if [ "$failures" -ne 0 ]; then
    echo "$failures folding check(s) failed"
    exit 1
fi
echo "All folding checks passed"
