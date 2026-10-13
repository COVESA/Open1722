# Alignment and Performance

This document explains the alignment contract of the Open1722 accessors, why
the library works on frames at any byte offset without a performance penalty on
the usual targets, and how to recover an aligned fast path on
strict-alignment targets.

The short version:

- IEEE 1722 defines only the *wire* ordering of fields, never the memory
  alignment of a frame. Buffers may be byte-aligned, and in practice often are
  not quadlet-aligned.
- The field-access engine and the custom format parsers therefore load and
  store quadlets with `memcpy`, which is safe at any alignment and does not
  violate the strict-aliasing rules.
- Compilers lower a fixed-size `memcpy` to a single load or store wherever the
  target permits unaligned accesses, and to a safe byte-wise sequence only
  where it does not. The inline engine still folds to direct bit manipulation.
- If your target is strict and you can guarantee alignment, tell the compiler
  (`__builtin_assume_aligned` or an aligned buffer type) instead of casting
  `uint8_t *` to a wider pointer type.

## What the specification says

IEEE 1722-2025, 3.5.1 ("Bit, octet, doublet, and quadlet ordering") defines the
serialization layout:

- "All Audio Video Transport Protocol Data Units (AVTPDUs) consist of an
  integral number of octets" - frames are byte-granular, not word-granular.
- Bits within an octet are numbered 0 to 7, octets are numbered from 1, and for
  multi-octet values the lower octet number holds the most-significant value
  (network byte order).
- "A quadlet is a series of four octets" - a quadlet is a grouping in the
  serialized frame, not a requirement that anything in memory be 4-byte
  aligned.

The quadlet padding that ACF messages use (their length fields count quadlets)
is likewise a property of the wire format, not of the receive buffer.

Unaligned frames are the normal case when frames arrive from the network. In a
raw Ethernet frame the AVTPDU starts after the 14-byte MAC header, or after 18
bytes with a VLAN tag. With UDP encapsulation it starts after 42 bytes (IPv4)
or 62 bytes (IPv6). Every one of those offsets is congruent to 2 modulo 4, so
a conforming implementation cannot assume even a 4-byte aligned AVTPDU in a
receive buffer.

## The library contract

All accessors accept a PDU at any alignment. The engine
(`Avtp_GetField`/`Avtp_SetField` in
[`Utils.h`](../include/avtp/Utils.h)) reads and writes each quadlet with a
fixed-size `memcpy` into a local `uint32_t`, so it neither faults on
strict-alignment targets nor relies on type-punning a `uint8_t` buffer through
a wider lvalue. The custom VSS parser uses the same pattern through
`vss_load_be16/32/64` and `vss_store_be16/32/64` in
[`Vss.c`](../src/avtp/acf/custom/Vss.c).

A frame taken straight from a receive buffer can be used as-is:

```c
uint8_t frame[1522];
recv(fd, frame, sizeof(frame), 0);

/* May be 2-byte aligned only; no copy required. */
const Avtp_Can_t *pdu = (const Avtp_Can_t *)(frame + 14);
uint32_t id = Avtp_Can_GetCanIdentifier(pdu);
```

## Why this is not slower

`memcpy` with a constant size is not a function call. GCC and Clang treat it as
a builtin and choose the best instruction sequence for the target. On a
little-endian x86-64 build (`-O2`), this:

```c
uint32_t v;
memcpy(&v, p, sizeof(v));
v = Avtp_BeToCpu32(v);
```

and a direct cast-and-dereference compile to identical assembly:

```asm
movl    (%rdi), %eax
bswap   %eax
```

The same holds on AArch64 and ARMv7+: a fixed-size `memcpy` from an
unknown-alignment pointer becomes a single `ldr`, because those targets allow
unaligned accesses. On strict-align targets (Cortex-M0, ARMv5, some MIPS,
SPARC, RISC-V cores without misaligned support) the compiler instead emits a
byte-wise sequence that is guaranteed not to fault. A raw `uint32_t *` cast
would have faulted there.

The engine's constant-folding property is unaffected: the accessors and the
engine are inline (`OPEN1722_INLINE`), so with a compile-time descriptor table
and field index the `memcpy` is folded together with the shifts and masks.
[`check-folding.sh`](../bench/check-folding.sh) asserts that a consumer probe
produces call-free code, and
[`bench-field-access.c`](../bench/bench-field-access.c) compares typed
accessors against raw bit access. Run them with:

```sh
cmake -S . -B build-bench -DCMAKE_BUILD_TYPE=Release
cmake --build build-bench --target bench-field-access -j"$(nproc)"
./build-bench/bench/bench-field-access
./bench/check-folding.sh
```

## Recovering an aligned fast path on strict targets

On a strict-alignment target, if you know that a buffer is 4-byte aligned, you
can let the compiler prove it and collapse the `memcpy` back to a single
aligned load. This only matters when the target would otherwise emit the
byte-wise sequence; on targets with hardware unaligned access the result is
already a single access.

The cleanest way is to give the buffer an alignment-carrying type, so the
compiler can see the alignment itself:

```c
_Alignas(4) uint8_t frame[1522]; /* C11 */
/* or */
alignas(4) uint8_t frame[1522];  /* C++11 */
```

If the pointer comes from opaque code, promise the alignment with the
GCC/Clang builtin at the call site:

```c
const Avtp_Can_t *pdu = (const Avtp_Can_t *)__builtin_assume_aligned(frame, 4);
uint32_t id = Avtp_Can_GetCanIdentifier(pdu);
```

Because the engine is inline, the alignment information reaches the `memcpy`
inside `Avtp_GetField`, and the compiler emits the aligned access. The promise
must hold; if the pointer is not actually 4-byte aligned the behavior is
undefined. C++20 standardizes the same hint as `std::assume_aligned`
(`<memory>`); the C builtin is available on GCC and Clang, the compilers this
project supports.

Do **not** use a pointer cast to get the fast path:

```c
/* Wrong: faults on strict-alignment targets and is strict-aliasing UB. */
uint32_t value = *(const uint32_t *)frame;
```

The libraries and the unit tests build with `-Wcast-align=strict` (GCC) /
`-Wcast-align` (Clang), both with `-Werror=cast-align`, so casts that increase
the required alignment are build errors. Use the memcpy-based helpers from
[`Byteorder.h`](../include/avtp/Byteorder.h),
[`Utils.h`](../include/avtp/Utils.h) or `Vss.c` instead.

## Regression guards

- [`unit/test-align.c`](../unit/test-align.c) builds and parses the same frame
  at byte offsets 0 through 3 and requires byte-identical results for the
  generic field engine, the typed accessors and the custom VSS format.
- CI runs the full unit test suite under
  `-fsanitize=undefined,alignment -fno-sanitize-recover=all`, which turns a
  misaligned access into a hard failure on every target, x86 included.

## See also

- [`api-design.md`](api-design.md) - API shape, including
  [The PDU struct in memory](api-design.md#the-pdu-struct-in-memory) and
  [The field-access engine](api-design.md#the-field-access-engine).
- [`inline.md`](inline.md) - how the inline accessors are also exported as
  shared library symbols.
- [`bench/README.md`](../bench/README.md) - the benchmark and folding checks.
