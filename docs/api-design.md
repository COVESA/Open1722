# Open1722 API Design

This document describes the design and conventions of the Open1722 API. It
explains *how* and *why* the API is shaped the way it is, so that a reader can
use it fluently and a contributor can extend it consistently.

It focuses on the **AVTP Control Formats (ACF)** - CAN, LIN, FlexRay, VSS and
the other fieldbus formats - because that is where most of Open1722's own API
surface lives and where the conventions matter most. The ACF format modules all
follow one shared template. `ACF CAN` (`include/avtp/acf/Can.h`) is the
reference implementation of that template; when in doubt, follow it.

The document is split along two audiences:

- [Part 1 - Using Open1722](#part-1--using-open1722) covers everything an
  application developer needs to build and parse PDUs with the existing
  formats.
- [Part 2 - Extending Open1722](#part-2--extending-open1722) covers the
  internals and conventions needed to add or modify a format module.

Companion documents:

- [`inline.md`](inline.md) - how inline accessors are also exported as shared
  library symbols.
- [`CONTRIBUTING.md`](../CONTRIBUTING.md) - licence, commit and style rules.

---

## Design principles

Four principles shape every part of the API, and are worth knowing before
reading either half of this document.

### Names mirror the IEEE 1722 specification

Function, type and field names are taken directly from the IEEE 1722
specification. The guiding idea is: **if you have read and understood the spec,
you can use Open1722 directly** - the mapping from a spec field to the
corresponding API call is mechanical. 

For example, the ACF CAN header contains the fields `pad`, `mtv`, `rtr`, `eff`,
`brs`, `fdf`, `esi`, `can_bus_id`, `message_timestamp` and `can_identifier`.
Those exact names reappear in the API:

```c
Avtp_Can_GetPad(pdu);
Avtp_Can_IsMtv(pdu);
Avtp_Can_GetCanIdentifier(pdu);
Avtp_Can_SetMessageTimestamp(pdu, value);
```

There is no "rename for taste" step. If the spec calls a field `eff`, the
function is `Avtp_Can_IsEff`, not `Avtp_Can_GetExtendedFrameFormat`.

### Plumbing, not porcelain

Open1722 deliberately provides a *plumbing* API, not a *porcelain* one. It gives
you the raw primitives to build and parse PDUs; it does **not** attempt to hide
the wire format, nor to abstract all ACF variants behind one unified high-level
interface.

There *is* a small layer of convenience functions (see
[Convenience functions](#convenience-functions)) - for example a helper that
sets the payload length *and* computes the padding bytes and the
quadlet-encoded length field in one call. But those conveniences are thin and
predictable; they never hide the underlying format.

If you are looking for an API that abstracts away every version of NTSCF/TSCF
and every ACF format behind a single unified interface, Open1722 is not that.
We like to think it is a very good *basis* for building one.

### Performance first

The accessors are designed to be as cheap as possible. For simple formats the
getters/setters **assume the frame is already correctly formatted** and perform
no validation. There is no guarding against malformed input in the hot path;
that freedom is what lets you write truly high-performance code, e.g. forwarding
high-rate CAN traffic on a small microcontroller.

Where validation is wanted, each format offers an `IsValid()` function you can
call *once* to check a frame before accessing it (see
[Accessor semantics & the safety contract](#accessor-semantics--the-safety-contract)).

### Consistency across formats

Every format follows the same shape: same struct layout, same field-descriptor
mechanism, same naming scheme, same function families. Once you know one format
module, you know them all. The remainder of this document describes that shared
shape from both sides.

---

# Part 1 - Using Open1722

This part is for application developers who consume the library: reading,
writing and validating PDUs with the already-existing formats. It assumes you
know *what* fields a format has (from the spec); it explains how to reach them.

## Naming conventions

### Functions

Every API function follows one pattern:

```
Avtp_<Format>_<Verb><Field>
```

| Part | Meaning | Examples |
|------|---------|----------|
| `Avtp_` | Common prefix for everything. | - |
| `<Format>` | The PDU format. | `Can`, `CanBrief`, `Lin`, `Vss`, `CommonHeader`, `Udp`, `Tscf`, `Ntscf` |
| `<Verb>` | What the function does (see below). | `Get`, `Is`, `Set`, `Init`, `IsValid` |
| `<Field>` | The spec field name, verbatim. | `AcfMsgType`, `Pad`, `Mtv`, `CanBusId`, `MessageTimestamp` |

Verbs:

- **`Get<Field>`** - read a field, returning a value.
- **`Set<Field>`** - write a field, taking a value.
- **`Is<Flag>`** - read a single-bit flag, returning a `bool`.
- **`Init`** - zero-initialise the PDU header and set its message type.
- **`IsValid`** - validate a frame (see
  [Accessor semantics & the safety contract](#accessor-semantics--the-safety-contract)).
- **`Create…`** - build a complete message in one call (see
  [Convenience functions](#convenience-functions)).

A `Get`ter takes the PDU as a `const` pointer and returns a value; an `Is`
getter returns a `bool` for single-bit flags; a `Set`ter takes a non-`const`
pointer and a value and returns `void`:

```c
OPEN1722_INLINE uint8_t Avtp_Can_GetCanBusId(const Avtp_Can_t *const pdu);
OPEN1722_INLINE void    Avtp_Can_SetCanBusId(Avtp_Can_t *pdu, uint8_t value);
OPEN1722_INLINE bool    Avtp_Can_IsMtv(const Avtp_Can_t *const pdu);
OPEN1722_INLINE void    Avtp_Can_SetMtv(Avtp_Can_t *pdu, bool mtv);
```

### Return types

Getters return the natural C type for the field width - `uint8_t`,
`uint16_t`, `uint32_t` or `uint64_t`:

```c
OPEN1722_INLINE uint8_t  Avtp_Can_GetPad(const Avtp_Can_t *const pdu);
OPEN1722_INLINE uint16_t Avtp_AcfCommon_GetAcfMsgLengthInBytes(const Avtp_AcfCommon_t *const pdu);
OPEN1722_INLINE uint64_t Avtp_Can_GetMessageTimestamp(const Avtp_Can_t *const pdu);
```

Single-bit flag fields are booleans and return `bool` (via `Is<Flag>`):

```c
OPEN1722_INLINE bool Avtp_Can_IsMtv(const Avtp_Can_t *const pdu);
```

Fields that represent an enumeration of named values (most notably the ACF
message type) return the corresponding typed enum rather than a bare integer:

```c
Avtp_AcfMsgType_t Avtp_AcfCommon_GetAcfMsgType(const Avtp_AcfCommon_t *const pdu);
```

## The PDU struct in memory

Every format is described by a struct with a fixed-size `header` followed by a
zero-length flexible array member for the payload:

```c
#define AVTP_CAN_HEADER_LEN (4 * AVTP_QUADLET_SIZE)

typedef struct {
    uint8_t header[AVTP_CAN_HEADER_LEN];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_Can_t;
```

The struct is deliberately `packed` so that it can be overlaid directly on a
network buffer. The flexible `payload[0]` means the payload lives in the memory
immediately following the header: after casting a buffer to `Avtp_Can_t *`, you
read and write payload bytes through `pdu->payload` and the header fields
through the accessors.

When several PDU structs are combined into one frame, the outer struct must
also be `packed` so the compiler inserts no padding between them:

```c
typedef struct __attribute__((packed)) {
    Avtp_Tscf_t tscf;
    Avtp_Can_t  can;
    uint8_t     canPayload[8];
} My1722Pdu_t;
```

## Accessor semantics & the safety contract

Accessors are intentionally *unsafe against malformed input*. A getter assumes
the PDU it points at is a well-formed frame and reads the described bits without
checking. This keeps the hot path free of validation branches.

Validation is available explicitly, and the contract between the two is:

> **If `Avtp_<Format>_IsValid(pdu, bufferSize)` returns true, then every
> getter on that format is safe to call and will never overread the buffer.**

`IsValid` checks at minimum:

1. that the ACF length field, converted to octets, does not exceed `bufferSize`,
   and
2. any format-specific invariants (for CAN: the payload-length limit implied by
   classic CAN vs. CAN-FD, and that the declared padding is consistent with the
   length field).

Typical usage: validate once, then access freely:

```c
if (Avtp_Can_IsValid(pdu, buffer_size)) {
    uint32_t id = Avtp_Can_GetCanIdentifier(pdu);
    uint8_t  n  = Avtp_Can_GetPayloadLength(pdu);
    /* ... */
}
```

> **General rule, with exceptions.** This assume-valid model is the norm. Where
> it does not hold - because a format's validity check would be expensive or
> complex - the accessors perform their own bounds checking instead. See
> [Exceptions to the rules](#exceptions-to-the-rules).

## Convenience functions

Beyond the raw field accessors, each format offers a small set of *convenience*
functions for the most common operations. These are still plumbing - they do
predictable, spec-level work - but they spare you the tedious multi-step dance.

The canonical set (CAN as reference):

- **`GetPayload` / `SetPayload`** - access or copy the raw payload bytes.
- **`SetPayloadLength`** -  if you did read the IEEE-1722 specification you will have noticed it uses quadlets and 32 bit word aligned structures in some places and byte lengths elsewhere. Sometimes the same thing is measured in different ways. This helper got you covered:
  given a payload length it computes the padding required to reach a whole
  number of quadlets, zeroes the pad bytes (to avoid leaking information),
  writes the `pad` field, and sets the quadlet-encoded `acf_msg_length` field:

  ```c
  OPEN1722_INLINE void Avtp_Can_SetPayloadLength(Avtp_Can_t *can_pdu, uint16_t payload_length)
  {
      uint16_t msgLenBytes = AVTP_CAN_HEADER_LEN + payload_length;
      uint8_t  pad = (uint8_t)(4 - (msgLenBytes % 4)) % 4;
      if (pad > 0)
          memset(can_pdu->payload + payload_length, 0, pad);
      uint16_t msgLenQuadlets = (uint16_t)((msgLenBytes + pad) / 4);
      Avtp_Can_SetPad(can_pdu, pad);
      Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)can_pdu, msgLenQuadlets);
  }
  ```

- **`GetPayloadLength`** - the inverse: recover the true payload length by
  subtracting the header length and the declared padding from the quadlet-encoded
  length. It assumes the PDU has already been validated with `IsValid`.
- **`CreateAcfMessage`** - one-shot message construction: initialise the header
  (zero it and set the message type via `Init`), copy the payload, set the CAN
  identifier (and the extended-frame flag if the ID needs it), set the CAN-FD
  flag if requested, and finalise the length/pad fields. Set any additional
  header fields (e.g. `mtv`, `message_timestamp`, `rtr`, `brs`, `esi`) *after*
  calling it.

The raw quadlet-encoded `acf_msg_length` field can still be written directly
via `Avtp_AcfCommon_SetAcfMsgLength` when you need it;
`SetPayloadLength` is the friendlier path that keeps the padding consistent for
you.

## Inline accessors & the shared library

Accessors, `Init`, `IsValid` and the convenience helpers (payload access,
`SetPayloadLength`, `CreateAcfMessage`, …) are all declared `OPEN1722_INLINE`
rather than `static inline`. By default this resolves to `static inline`, so
embedded and bare-metal consumers get fully-inlined code with no call
overhead.

For shared-library/FFI users (e.g. Python `ctypes`, Rust FFI), the same
functions are also exported as regular symbols in `libopen1722.so`, so they can
be called across an FFI boundary. The mechanism, and how to force non-inline
use in your own code, is documented in [`inline.md`](inline.md).

---

# Part 2 - Extending Open1722

This part is for contributors who add or modify format modules. It describes
the internal template each format follows, the shared machinery it relies on,
and the checklist for adding a new format consistently.

## Naming: types, enums and macros

When writing a format module, the following naming patterns apply (see
[Anatomy of a format module](#anatomy-of-a-format-module) for how they are
used):

| Kind | Pattern | Example |
|------|---------|---------|
| PDU struct | `Avtp_<Format>_t` | `Avtp_Can_t` |
| Field enum | `Avtp_<Format>Fields_t` | `Avtp_CanFields_t` |
| Field descriptor table | `Avtp_<Format>FieldDesc` | `Avtp_CanFieldDesc` |
| Field enum values | `AVTP_<FORMAT>_FIELD_<NAME>` | `AVTP_CAN_FIELD_CAN_IDENTIFIER` |
| Enum terminator | `AVTP_<FORMAT>_FIELD_MAX` | `AVTP_CAN_FIELD_MAX` |
| Header length | `AVTP_<FORMAT>_HEADER_LEN` | `AVTP_CAN_HEADER_LEN` |
| ACF message type | `AVTP_ACF_TYPE_<NAME>` | `AVTP_ACF_TYPE_CAN` |

Field enum values are always declared with the terminator `..._FIELD_MAX` as the
last entry. This value is never a real field; it exists to give the field-count
used for bounds checking in the access engine (see
[The field-access engine](#the-field-access-engine)).

## Anatomy of a format module

A format module is a single self-contained header (`include/avtp/acf/<Format>.h`).
It contains the data description (struct, field enum, descriptor table), the
inline accessors, `IsValid()`, `Init` and the higher-level convenience
functions. No separate source file is needed; the standard ACF formats are
header-only.

Using `Can.h` as the reference, a module contains these pieces in order:

### The PDU struct

```c
#define AVTP_CAN_HEADER_LEN (4 * AVTP_QUADLET_SIZE)

typedef struct {
    uint8_t header[AVTP_CAN_HEADER_LEN];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_Can_t;
```

See [The PDU struct in memory](#the-pdu-struct-in-memory) for the user-facing
view of how this struct is overlaid on a buffer.

### The field enum

Every field of the header - including the two ACF *common* fields - is listed in
one enum:

```c
typedef enum {
    /* ACF common header fields */
    AVTP_CAN_FIELD_ACF_MSG_TYPE = 0,
    AVTP_CAN_FIELD_ACF_MSG_LENGTH,

    /* ACF CAN header fields */
    AVTP_CAN_FIELD_PAD,
    AVTP_CAN_FIELD_MTV,
    AVTP_CAN_FIELD_RTR,
    AVTP_CAN_FIELD_EFF,
    AVTP_CAN_FIELD_BRS,
    AVTP_CAN_FIELD_FDF,
    AVTP_CAN_FIELD_ESI,
    AVTP_CAN_FIELD_RSV1,
    AVTP_CAN_FIELD_CAN_BUS_ID,
    AVTP_CAN_FIELD_MESSAGE_TIMESTAMP,
    AVTP_CAN_FIELD_RSV2,
    AVTP_CAN_FIELD_CAN_IDENTIFIER,

    /* Count number of fields for bound checks */
    AVTP_CAN_FIELD_MAX
} Avtp_CanFields_t;
```

The common fields (`ACF_MSG_TYPE`, `ACF_MSG_LENGTH`) are always present and
always first. They are shared by all ACF formats and defined in
[`AcfCommon.h`](../include/avtp/acf/AcfCommon.h).

### The field descriptor table

A `static const` table maps each field enum value to its position in the header:

```c
static const Avtp_FieldDescriptor_t Avtp_CanFieldDesc[AVTP_CAN_FIELD_MAX] = {
    [AVTP_CAN_FIELD_ACF_MSG_TYPE]      = {.quadlet = 0, .offset = 0,  .bits = 7},
    [AVTP_CAN_FIELD_ACF_MSG_LENGTH]    = {.quadlet = 0, .offset = 7,  .bits = 9},
    [AVTP_CAN_FIELD_PAD]               = {.quadlet = 0, .offset = 16, .bits = 2},
    [AVTP_CAN_FIELD_MTV]               = {.quadlet = 0, .offset = 18, .bits = 1},
    [AVTP_CAN_FIELD_RTR]               = {.quadlet = 0, .offset = 19, .bits = 1},
    [AVTP_CAN_FIELD_EFF]               = {.quadlet = 0, .offset = 20, .bits = 1},
    [AVTP_CAN_FIELD_BRS]               = {.quadlet = 0, .offset = 21, .bits = 1},
    [AVTP_CAN_FIELD_FDF]               = {.quadlet = 0, .offset = 22, .bits = 1},
    [AVTP_CAN_FIELD_ESI]               = {.quadlet = 0, .offset = 23, .bits = 1},
    [AVTP_CAN_FIELD_RSV1]              = {.quadlet = 0, .offset = 24, .bits = 3},
    [AVTP_CAN_FIELD_CAN_BUS_ID]        = {.quadlet = 0, .offset = 27, .bits = 5},
    [AVTP_CAN_FIELD_MESSAGE_TIMESTAMP] = {.quadlet = 1, .offset = 0,  .bits = 64},
    [AVTP_CAN_FIELD_RSV2]              = {.quadlet = 3, .offset = 0,  .bits = 3},
    [AVTP_CAN_FIELD_CAN_IDENTIFIER]    = {.quadlet = 3, .offset = 3,  .bits = 29},
};
```

Each entry gives the *quadlet* (0-based word index), the *offset* (bit position
within that quadlet, counted from the most-significant bit) and the *bits*
(field width). This table is the single source of truth for where every field
lives; the accessors below never hard-code bit positions.

### Reserved fields

Reserved bits (`rsv`, `reserved`, `r` in the spec) are declared in the field
enum and the descriptor table like any other field. The table must describe
**every bit of the header exactly once - no holes and no overlaps** - so it
stays the single source of truth for the whole layout. This also makes it easy
to spot a forgotten or mis-sized reserved field during review.

The naming mirrors the spec, and the case matters:

| Spec calls it | Enum value | Notes |
|---------------|------------|-------|
| `rsv`         | `RSV`      | numbered `RSV1`, `RSV2`, … when several occur |
| `reserved`    | `RESERVED` | numbered `RESERVED1`, `RESERVED2`, … when several occur |
| `r`           | `R`        | e.g. GISF's 1-bit `r` that follows its 16-bit `RESERVED` |

Reserved fields deliberately get **no** `Get`/`Set`/`Is` accessors. A compliant
Talker keeps them zero (`Init` memsets the header, so they start zero) and a
Listener must ignore their value, so there is no legitimate per-field use case.
Code that needs to touch them anyway (test vectors, fuzzing, prototype formats)
can reach them through the generic engine:

```c
uint64_t rsv = Avtp_GetField(Avtp_CanFieldDesc, AVTP_CAN_FIELD_MAX,
                             (uint8_t *)pdu, AVTP_CAN_FIELD_RSV1);
```

### The GET/SET macros

Two macros wrap the generic field-access engine, binding it to this format's
descriptor table:

```c
#define GET_CAN_FIELD(field)                                                    \
    (Avtp_GetField(Avtp_CanFieldDesc, AVTP_CAN_FIELD_MAX, (uint8_t *)pdu, field))
#define SET_CAN_FIELD(field, value)                                             \
    (Avtp_SetField(Avtp_CanFieldDesc, AVTP_CAN_FIELD_MAX, (uint8_t *)pdu, field, value))
```

The parameter name `pdu` is assumed by the macro, so it must appear in the
enclosing function scope (the accessors below use exactly that name).

### Accessors

One getter and one setter per field, implemented as thin inline wrappers around
the macros:

```c
OPEN1722_INLINE uint8_t Avtp_Can_GetCanBusId(const Avtp_Can_t *const pdu)
{
    return (uint8_t)GET_CAN_FIELD(AVTP_CAN_FIELD_CAN_BUS_ID);
}

OPEN1722_INLINE void Avtp_Can_SetCanBusId(Avtp_Can_t *pdu, uint8_t value)
{
    SET_CAN_FIELD(AVTP_CAN_FIELD_CAN_BUS_ID, value);
}
```

For single-bit flag fields, `Is<Flag>` reads the flag as a `bool` and
`Set<Flag>(pdu, bool)` writes it:

```c
OPEN1722_INLINE bool Avtp_Can_IsMtv(const Avtp_Can_t *const pdu)
{
    return (bool)GET_CAN_FIELD(AVTP_CAN_FIELD_MTV);
}

OPEN1722_INLINE void Avtp_Can_SetMtv(Avtp_Can_t *pdu, bool mtv)
{
    SET_CAN_FIELD(AVTP_CAN_FIELD_MTV, mtv);
}
```

### Init

An `Init` function zeroes the header and stamps the message type, so a freshly
created PDU is at least a structurally correct header:

```c
OPEN1722_INLINE void Avtp_Can_Init(Avtp_Can_t *pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_Can_t));
        Avtp_AcfCommon_SetAcfMsgType((Avtp_AcfCommon_t *)pdu, AVTP_ACF_TYPE_CAN);
    }
}
```

### IsValid

A format provides an `IsValid` function as an inline accessor in its header. It
checks (1) that the length field is contained within the actual buffer, and (2)
any format-specific invariants. See
[Accessor semantics & the safety contract](#accessor-semantics--the-safety-contract).

```c
bool Avtp_Can_IsValid(const Avtp_Can_t *const pdu, size_t bufferSize);
```

### Convenience functions

Finally, a handful of inline helpers for common tasks - building a full
message, reading/writing the payload, and computing the length/padding fields.
See [Convenience functions](#convenience-functions).

```c
void Avtp_Can_CreateAcfMessage(Avtp_Can_t *can_pdu, uint32_t frame_id,
                               uint8_t *payload, uint16_t payload_length,
                               Avtp_CanVariant_t can_variant);
```

## ACF layering & the common header

ACF formats share a *common header* whose two fields - `acf_msg_type` and
`acf_msg_length` - occupy the first quadlet of every ACF message. These are
described once in [`AcfCommon.h`](../include/avtp/acf/AcfCommon.h):

- `Avtp_AcfCommon_t` - the common-header PDU struct.
- `Avtp_AcfMsgType_t` - the enumeration of all ACF message types
  (`AVTP_ACF_TYPE_CAN`, `AVTP_ACF_TYPE_LIN`, …).
- `Avtp_AcfCommon_GetAcfMsgType`, `Avtp_AcfCommon_SetAcfMsgType`,
  `Avtp_AcfCommon_Get/SetAcfMsgLength`,
  `Avtp_AcfCommon_GetAcfMsgLengthInBytes` - accessors for the two shared
  fields (the message type accessors are typed against
  `Avtp_AcfMsgType_t`).

Each concrete format defines its *own* field enum and descriptor table that
*include* the two common fields, so the format's struct can be overlaid on the
common header and its format-specific accessors stay self-contained.

The two common fields are accessed through the generic `AcfCommon` accessors,
never through per-format functions. Since every ACF format struct starts with
the common header (one quadlet), casting the format PDU pointer to
`Avtp_AcfCommon_t *` is always safe:

- The `acf_msg_type` field has exactly one correct value per format, so there
  is **no per-format `Get/SetAcfMsgType`**. `Init` stamps the message type with
  `Avtp_AcfCommon_SetAcfMsgType((Avtp_AcfCommon_t *)pdu, AVTP_ACF_TYPE_<NAME>)`,
  and `IsValid` checks it with `Avtp_AcfCommon_GetAcfMsgType((const
  Avtp_AcfCommon_t *)pdu)`.
- The `acf_msg_length` field is likewise accessed only through
  `Avtp_AcfCommon_GetAcfMsgLength`, `SetAcfMsgLength` and
  `Avtp_AcfCommon_GetAcfMsgLengthInBytes` - there are **no per-format
  `Get/SetAcfMsgLength` or `GetAcfMsgLengthInBytes`** either. The per-format
  convenience functions that deal in payload bytes (`SetPayloadLength`, and
  `GetPayloadLength` where the format encodes enough information to recover
  it) are where the raw quadlet-encoded length field is read or written.

## The field-access engine

All getters and setters ultimately funnel through two generic functions in
[`Utils.h`](../include/avtp/Utils.h):

```c
uint64_t Avtp_GetField(const Avtp_FieldDescriptor_t *fieldDescriptors,
                       uint8_t numFields, const uint8_t *const pdu, uint8_t field);
void     Avtp_SetField(const Avtp_FieldDescriptor_t *fieldDescriptors,
                       uint8_t numFields, uint8_t *pdu, uint8_t field, uint64_t value);
```

They look up `field` in `fieldDescriptors` and extract/insert the described bit
range, performing all necessary host/network byte-order conversion via the
helpers in [`Byteorder.h`](../include/avtp/Byteorder.h). `numFields` (the
`..._FIELD_MAX` terminator) is used only for a bounds check on the `field`
index.

The descriptor type is defined in [`Defines.h`](../include/avtp/Defines.h):

```c
typedef struct Avtp_FieldDescriptor {
    uint8_t quadlet; /* quadlet containing the first bit of the field */
    uint8_t offset;  /* bit offset within that quadlet, from the MSB */
    uint8_t bits;    /* field width in bits (max 64) */
} Avtp_FieldDescriptor_t;
```

A field wider than 64 bits cannot be described by a single descriptor; split it
into two or more fields and combine them in the accessor.

Because all accessors share this engine, byte-order correctness is centralised:
a format author never writes manual shifts or endianness handling in accessor
code.

## Inline accessors & symbol export

Accessors, `Init`, `IsValid` and the convenience helpers are declared
`OPEN1722_INLINE` rather than `static inline`:

```c
/* include/avtp/Inline.h */
#ifndef OPEN1722_INLINE
#define OPEN1722_INLINE static inline
#endif
```

By default `OPEN1722_INLINE` resolves to `static inline`, so embedded and
bare-metal consumers get fully-inlined accessors with no call overhead. For
shared-library/FFI users, a dedicated export translation unit
(`src/avtp/export/InlineExports.c`) re-includes the headers with the macro
emptied, forcing an external symbol for every inline function in
`libopen1722.so`.

The full mechanism, and how to force non-inline use in your own code, is
documented in [`inline.md`](inline.md). For the purposes of this document the
rule is simply: **performance-critical functions in public headers use
`OPEN1722_INLINE`, never a bare `static inline`.**

## Exceptions to the rules

The rules above are the norm, not an iron law. The main exception is the custom
**VSS** format (`include/avtp/acf/custom/Vss.h`), which does not live in the
IEEE 1722 standard and which carries variable-length, length-prefixed data.

For VSS:

- A cheap `IsValid` is not practical - verifying a VSS frame would require
  walking variable-length paths and payloads. So VSS accessors instead perform
  their own bounds checking, clamping reads against the *declared* message
  length so a malformed frame cannot cause an overread.
- Because of that complexity, VSS accessors are implemented in the `.c` file
  (non-inline) rather than as inline header functions.

Custom formats under `include/avtp/acf/custom/` are therefore allowed to deviate
from the inline, assume-valid pattern when their structure makes it
unreasonable. Standard formats follow the template of
[Anatomy of a format module](#anatomy-of-a-format-module).

## Adding a new format - checklist

When implementing a new format module (e.g. a new ACF message type), follow
this order and the template in
[Anatomy of a format module](#anatomy-of-a-format-module):

1. **Header file** `include/avtp/acf/<Format>.h`, BSD-3-Clause header, `#pragma once`,
   `extern "C"` guards.
2. Define `AVTP_<FORMAT>_HEADER_LEN` and the packed PDU struct
   `Avtp_<Format>_t` with `header[]` + `payload[0]`.
3. Define the field enum `Avtp_<Format>Fields_t`, starting with the two common
   fields (`ACF_MSG_TYPE`, `ACF_MSG_LENGTH`) and ending with `..._FIELD_MAX`.
4. Add the `static const` field descriptor table `Avtp_<Format>FieldDesc`,
   covering every header bit exactly once - reserved fields included, no holes
   and no overlaps (see [Reserved fields](#reserved-fields)).
5. Add the `GET_/SET_<FORMAT>_FIELD` macros.
6. Add one `Get`/`Set` accessor per field (using `OPEN1722_INLINE`); single-bit
   flags use `Is<Flag>` (returns `bool`) and `Set<Flag>(bool)`. Reserved fields
   get no accessors (see [Reserved fields](#reserved-fields)).
7. Add `Avtp_<Format>_Init` (zero + set the ACF message type).
8. Add the convenience functions (`Get/SetPayload`, `SetPayloadLength`,
   `GetPayloadLength`, and `Create…` if a full-message builder makes sense).
9. Add `Avtp_<Format>_IsValid` inline in the header, checking buffer
   containment and format invariants.
10. If the format is standard ACF, add its `AVTP_ACF_TYPE_<NAME>` to
    [`AcfCommon.h`](../include/avtp/acf/AcfCommon.h).
11. Register any new inline header in `src/avtp/export/InlineExports.c`
    (phase 2) so the accessors are exported to the shared library - see
    [`inline.md`](inline.md).
12. Add unit tests under `unit/` and register the test target in the build.

A concrete reference for every step is `Can.h`.
