# Inline Functions and Shared Library Exports

## Overview

Open1722 uses `static inline` functions in public headers for field accessors, validation and message-building helpers (getters/setters, `Init`, `IsValid`, `CreateAcfMessage`) to allow the compiler to optimize them on embedded and bare-metal targets. However, `static inline` functions are not exported as symbols in the shared library (`libopen1722.so`), making them inaccessible to FFI users (Python ctypes, Rust FFI, etc.).

To support both use cases simultaneously, Open1722 uses a configurable inline macro and dedicated **export translation units** that force external definitions of every inline function in the shared library.

## How it works

### The `OPEN1722_INLINE` macro

The header `include/avtp/Inline.h` defines:

```c
#ifndef OPEN1722_INLINE
#define OPEN1722_INLINE static inline
#endif
```

All inline functions in the public headers use `OPEN1722_INLINE` instead of `static inline`. By default (when consumers just include the headers), `OPEN1722_INLINE` resolves to `static inline` — same behaviour as before, same performance characteristics.

### Export translation units

The shared library build includes a single file `src/avtp/export/InlineExports.c` that overrides the macro and re-includes all inline headers:

```c
// Phase 1: include shared deps in static-inline mode
#include "avtp/Inline.h"
#include "avtp/Defines.h"
#include "avtp/Byteorder.h"
// ...

// Phase 2: override and include all target headers
#undef OPEN1722_INLINE
#define OPEN1722_INLINE
#include "avtp/Udp.h"
#include "avtp/acf/Ntscf.h"
// ... all remaining format headers
```

When `OPEN1722_INLINE` is empty, each function definition in the target headers becomes a regular external function definition, emitted as an exported symbol in `libopen1722.so`.

Phase 1 ensures that all shared dependencies (Byteorder, Utils, AcfCommon, etc.) are processed in the default static-inline mode, so they have internal linkage and do not cause duplicate-symbol errors.

## Usage

### Embedded / header-only use (default)

Include the headers and call functions as usual. The compiler gets `static inline` versions.

```c
#include "avtp/acf/Ntscf.h"

void parse(uint8_t *frame) {
    Avtp_Ntscf_t *pdu = (Avtp_Ntscf_t *)frame;
    uint16_t len = Avtp_Ntscf_GetNtscfDataLength(pdu);
    // ...
}
```

### Shared library / FFI use

Link against `libopen1722.so`. All API functions — including the previously inline ones — are exported as regular symbols.

```python
# Python ctypes
import ctypes
lib = ctypes.CDLL("libopen1722.so")
lib.Avtp_Ntscf_GetNtscfDataLength.restype = ctypes.c_uint16
lib.Avtp_Ntscf_GetNtscfDataLength.argtypes = [ctypes.c_void_p]
```

```rust
// Rust FFI
extern "C" {
    fn Avtp_Ntscf_GetNtscfDataLength(pdu: *const Avtp_Ntscf_t) -> u16;
}
```

### Mixed use (headers + shared library)

You can include the headers AND link against the library in the same program. The header's `static inline` versions have internal linkage and take precedence in your translation units — the exported library symbols are simply ignored by the linker for those functions.

## How to force non-inline in user code

If you want to always call the shared library symbols (for example, to allow LD_PRELOAD overriding), define `OPEN1722_INLINE` to empty before including any Open1722 headers:

```c
#define OPEN1722_INLINE
#include "avtp/acf/Ntscf.h"
#include "avtp/acf/Tscf.h"
```

This makes the function declarations plain `extern` declarations — no function bodies, just prototypes. You must link against `libopen1722.so` to resolve them.

## Architecture

```
include/avtp/Inline.h                     ← defines OPEN1722_INLINE macro
include/avtp/acf/{Ntscf,Tscf,Can,...}.h   ← uses OPEN1722_INLINE
src/avtp/export/
└── InlineExports.c                       ← single export unit (all formats)
```

When a new header with inline functions is added, simply add its `#include` to `InlineExports.c` in phase 2.

## Frequently Asked Questions

### Does this affect embedded / Zephyr / bare-metal builds?

No. The export `.c` files are only added to the Linux/QNX shared library target. When building for Zephyr (static library), the export files are not compiled. Embedded users always get `static inline` — no overhead, no extra symbols.

### Does this increase code size?

The shared library gains one external copy of each function (shared across all processes via the dynamic linker). Embedded/static builds are unchanged.

### Why not just remove `static inline` from the headers?

Because on small microcontrollers, the compiler can fold getter/setter chains into single bit-field instructions when the function bodies are visible at the call site. Making them regular extern functions would add call overhead for every field access.
