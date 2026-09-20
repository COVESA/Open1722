# Accessor benchmarks and folding check

This directory contains tooling that validates the performance claim behind the
version-typed accessors (`_V0`/`_V1`): they should compile to direct bit
manipulation, close to a hand-written raw access, while the version-agnostic
accessors pay one version read and branch on top.

## Folding check

```sh
./bench/check-folding.sh [build-dir]
```

Builds `libopen1722.so` in Release mode (default build dir `build-folding`) and
checks two things:

1. **Consumer path (the performance claim).** A small probe including the
   headers is compiled at `-O2`; the generated assembly for a version-typed and
   a version-agnostic accessor must contain no `call` instructions. This is the
   path that embedded and normal C consumers use.
2. **Exported FFI wrappers.** The exported copies in `libopen1722.so` are
   regular functions and C semantic interposition prevents the compiler from
   fully folding them, so the check only asserts that representative typed
   accessors (`Avtp_Tscf_GetSequenceNum_V1`, `Avtp_Tscf_SetSequenceNum_V1`,
   `Avtp_CommonStreamHeader_GetStreamId_V1`, `Avtp_Rvf_GetActivePixels_V1`)
   never fall back to the version-agnostic dispatcher, the generic engine or the
   version readers.

The script exits non-zero on failure.

This check is deliberately not wired into CI: it inspects generated code and is
compiler/optimizer sensitive. Run it after changes to the field-access engine or
the accessor patterns.

## Micro-benchmark

```sh
cmake -S . -B build-bench -DCMAKE_BUILD_TYPE=Release
cmake --build build-bench --target bench-field-access -j"$(nproc)"
./build-bench/bench/bench-field-access
```

`bench-field-access` measures typed vs. agnostic vs. raw access for:

- TSCF v1 and v0 `sequence_num` (32 bit and 8 bit), get and set
- TSCF v1 `stream_id` (64 bit, two quadlets)
- RVF v1 `active_pixels` (format-specific field)

Each measurement runs 20 million iterations with a compiler barrier per
iteration so the loops cannot be optimized away or hoisted. Build with
`-DCMAKE_BUILD_TYPE=Release`; the library is not instrumented for coverage in
any build (see `unit/CMakeLists.txt`), so no special build flags are needed.

Example output shape:

```
TSCF version 1, get sequence_num (32 bit):
  typed    Avtp_Tscf_GetSequenceNum_V1     0.3 ns/op
  agnostic Avtp_Tscf_GetSequenceNum        1.2 ns/op
  raw      be32(header + 12)               0.3 ns/op
```

Absolute numbers depend on the machine and compiler; the typed column should be
within a few percent of the raw column, and the agnostic column is expected to
be a few cycles slower.
