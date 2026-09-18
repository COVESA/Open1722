/*
 * Copyright (c) 2024, COVESA
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of COVESA nor the names of its contributors may be
 *      used to endorse or promote products derived from this software without
 *      specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @file
 * This file contains the fields descriptions of the IEEE 1722 TSCF PDUs and
 * functions to invoke corresponding parser and deparser.
 *
 * TSCF uses the AVTPDU common stream header (4.7.4), so all common fields are
 * accessed through Avtp_CommonStreamHeader_*. The fields in this module are
 * described in version 0 coordinates; the GET/SET macros add the common stream
 * header's format offset to reach the version 1 positions.
 */

#pragma once
#include "avtp/Inline.h"

#ifdef LINUX_KERNEL1722
#include <linux/string.h>
#else
#include <string.h>
#include <stdbool.h>
#endif

#include "avtp/Defines.h"
#include "avtp/Utils.h"
#include "avtp/CommonHeader.h"
#include "avtp/CommonStreamHeader.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AVTP_TSCF_HEADER_LEN_V0 AVTPDU_CSH_LEN_V0 /* 24 */
#define AVTP_TSCF_HEADER_LEN_V1 AVTPDU_CSH_LEN_V1 /* 40 */
/* Kept for compatibility: the version 0 header length. */
#define AVTP_TSCF_HEADER_LEN AVTP_TSCF_HEADER_LEN_V0

/* TSCF supports both versions of the common stream header (Table 7). */
#define AVTP_TSCF_SUPPORTED_VERSIONS ((1u << AVTP_VERSION_0) | (1u << AVTP_VERSION_1))

#define GET_TSCF_FIELD(field)                                                                      \
    (Avtp_GetField(Avtp_TscfFieldDesc, AVTP_TSCF_FIELD_MAX,                                        \
                   (const uint8_t *)pdu + Avtp_CommonStreamHeader_GetFormatOffset(                 \
                                              (const Avtp_CommonStreamHeader_t *)pdu),             \
                   field))
#define SET_TSCF_FIELD(field, value)                                                               \
    (Avtp_SetField(Avtp_TscfFieldDesc, AVTP_TSCF_FIELD_MAX,                                        \
                   (uint8_t *)pdu + Avtp_CommonStreamHeader_GetFormatOffset(                       \
                                        (const Avtp_CommonStreamHeader_t *)pdu),                   \
                   field, value))

typedef struct {
    uint8_t header[AVTP_TSCF_HEADER_LEN_V0];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_Tscf_t;

typedef struct {
    uint8_t header[AVTP_TSCF_HEADER_LEN_V1];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_TscfV1_t;

typedef enum {

    /* TSCF-specific fields (format_specific_data_2 and _3) */
    AVTP_TSCF_FIELD_RESERVED2,
    AVTP_TSCF_FIELD_RESERVED3,

    /* Count number of fields for bound checks */
    AVTP_TSCF_FIELD_MAX
} Avtp_TscfFields_t;

/**
 * This table maps all TSCF-specific header fields to a descriptor. It is
 * written in version 0 coordinates; the accessors add the common stream
 * header's format offset for version 1.
 */
static const Avtp_FieldDescriptor_t Avtp_TscfFieldDesc[AVTP_TSCF_FIELD_MAX] = {
    [AVTP_TSCF_FIELD_RESERVED2] = {.quadlet = 4, .offset = 0, .bits = 32},
    [AVTP_TSCF_FIELD_RESERVED3] = {.quadlet = 5, .offset = 16, .bits = 16},
};

/**
 * Return the value of the TSCF SV field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @returns Value of the TSCF SV field.
 */
OPEN1722_INLINE bool Avtp_Tscf_IsSv(const Avtp_Tscf_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsSv((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Return the value of the TSCF MR field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @returns Value of the TSCF MR field.
 */
OPEN1722_INLINE bool Avtp_Tscf_IsMr(const Avtp_Tscf_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsMr((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Return the value of the TSCF TV field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @returns Value of the TSCF TV field.
 */
OPEN1722_INLINE bool Avtp_Tscf_IsTv(const Avtp_Tscf_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsTv((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Return the value of the TSCF TU field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @returns Value of the TSCF TU field.
 */
OPEN1722_INLINE bool Avtp_Tscf_IsTu(const Avtp_Tscf_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsTu((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Return the value of the TSCF Sequence Number field as specified in the IEEE 1722
 * Specification. The field is 8 bits in version 0 and 32 bits in version 1.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @returns Value of the TSCF Sequence Number field.
 */
OPEN1722_INLINE uint32_t Avtp_Tscf_GetSequenceNum(const Avtp_Tscf_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetSequenceNum((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Return the value of the TSCF sequence_num_lsb field. In version 0 this is the
 * 8-bit sequence_num field; in version 1 it is the copy of the eight least
 * significant bits of the 32-bit sequence_num field, stored in
 * format_specific_data_0 (TSCF-4).
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @returns Value of the TSCF sequence_num_lsb field.
 */
OPEN1722_INLINE uint8_t Avtp_Tscf_GetSequenceNumLsb(const Avtp_Tscf_t *const pdu)
{
    if (Avtp_CommonStreamHeader_GetVersion((const Avtp_CommonStreamHeader_t *)pdu) ==
        AVTP_VERSION_1) {
        return Avtp_CommonStreamHeader_GetFormatSpecificData0(
            (const Avtp_CommonStreamHeader_t *)pdu);
    }
    return (uint8_t)Avtp_CommonStreamHeader_GetSequenceNum((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Return the value of the TSCF Stream ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @returns Value of the TSCF Stream ID field.
 */
OPEN1722_INLINE uint64_t Avtp_Tscf_GetStreamId(const Avtp_Tscf_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetStreamId((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Return the value of the TSCF AVTP Timestamp field as specified in the IEEE 1722
 * Specification. The field is 32 bits in version 0 and 64 bits in version 1.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @returns Value of the TSCF AVTP Timestamp field.
 */
OPEN1722_INLINE uint64_t Avtp_Tscf_GetAvtpTimestamp(const Avtp_Tscf_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetAvtpTimestamp((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Return the value of the TSCF ptp_grandmaster_identity field. The field only
 * exists in version 1; version 0 returns 0.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @returns Value of the TSCF ptp_grandmaster_identity field.
 */
OPEN1722_INLINE uint64_t Avtp_Tscf_GetPtpGrandmasterIdentity(const Avtp_Tscf_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetPtpGrandmasterIdentity(
        (const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Return the value of the TSCF Stream Data Length field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @returns Value of the TSCF Stream Data Length field.
 */
OPEN1722_INLINE uint16_t Avtp_Tscf_GetStreamDataLength(const Avtp_Tscf_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetStreamDataLength((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Set the SV bit in an ACF Tscf frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @param sv Value to set the TSCF PDU SV field to.
 */
OPEN1722_INLINE void Avtp_Tscf_SetSv(Avtp_Tscf_t *pdu, bool sv)
{
    Avtp_CommonStreamHeader_SetSv((Avtp_CommonStreamHeader_t *)pdu, sv);
}

/**
 * Set the MR bit in an ACF Tscf frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @param mr Value to set the TSCF PDU MR field to.
 */
OPEN1722_INLINE void Avtp_Tscf_SetMr(Avtp_Tscf_t *pdu, bool mr)
{
    Avtp_CommonStreamHeader_SetMr((Avtp_CommonStreamHeader_t *)pdu, mr);
}

/**
 * Set the TV bit in an ACF Tscf frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @param tv Value to set the TSCF PDU TV field to.
 */
OPEN1722_INLINE void Avtp_Tscf_SetTv(Avtp_Tscf_t *pdu, bool tv)
{
    Avtp_CommonStreamHeader_SetTv((Avtp_CommonStreamHeader_t *)pdu, tv);
}

/**
 * Set the TU bit in an ACF Tscf frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @param tu Value to set the TSCF PDU TU field to.
 */
OPEN1722_INLINE void Avtp_Tscf_SetTu(Avtp_Tscf_t *pdu, bool tu)
{
    Avtp_CommonStreamHeader_SetTu((Avtp_CommonStreamHeader_t *)pdu, tu);
}

/**
 * Set the value of the TSCF Sequence Number field as specified in the IEEE 1722
 * Specification. In version 1 the eight least significant bits are also written
 * to the sequence_num_lsb copy in format_specific_data_0 (TSCF-4).
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @param value Value to set the TSCF PDU Sequence Number field to.
 */
OPEN1722_INLINE void Avtp_Tscf_SetSequenceNum(Avtp_Tscf_t *pdu, uint32_t value)
{
    Avtp_CommonStreamHeader_SetSequenceNum((Avtp_CommonStreamHeader_t *)pdu, value);
    if (Avtp_CommonStreamHeader_GetVersion((const Avtp_CommonStreamHeader_t *)pdu) ==
        AVTP_VERSION_1) {
        Avtp_CommonStreamHeader_SetFormatSpecificData0((Avtp_CommonStreamHeader_t *)pdu,
                                                       (uint8_t)(value & 0xFFU));
    }
}

/**
 * Set the value of the TSCF Stream ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @param value Value to set the TSCF PDU Stream ID field to.
 */
OPEN1722_INLINE void Avtp_Tscf_SetStreamId(Avtp_Tscf_t *pdu, uint64_t value)
{
    Avtp_CommonStreamHeader_SetStreamId((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Set the value of the TSCF AVTP Timestamp field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @param value Value to set the TSCF PDU AVTP Timestamp field to.
 */
OPEN1722_INLINE void Avtp_Tscf_SetAvtpTimestamp(Avtp_Tscf_t *pdu, uint64_t value)
{
    Avtp_CommonStreamHeader_SetAvtpTimestamp((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Set the value of the TSCF ptp_grandmaster_identity field. The field only
 * exists in version 1; on version 0 this is a no-op.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @param value Value to set the TSCF PDU ptp_grandmaster_identity field to.
 */
OPEN1722_INLINE void Avtp_Tscf_SetPtpGrandmasterIdentity(Avtp_Tscf_t *pdu, uint64_t value)
{
    Avtp_CommonStreamHeader_SetPtpGrandmasterIdentity((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Set the value of the TSCF Stream Data Length field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @param value Value to set the TSCF PDU Stream Data Length field to.
 */
OPEN1722_INLINE void Avtp_Tscf_SetStreamDataLength(Avtp_Tscf_t *pdu, uint16_t value)
{
    Avtp_CommonStreamHeader_SetStreamDataLength((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Returns a pointer to the payload of a TSCF frame. The payload starts after
 * the version-dependent common stream header.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @return Pointer to the TSCF frame payload.
 */
OPEN1722_INLINE const uint8_t *Avtp_Tscf_GetPayload(const Avtp_Tscf_t *const pdu)
{
    return (const uint8_t *)pdu +
           Avtp_CommonStreamHeader_GetHeaderLen((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Sets the TSCF payload.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @param payload Pointer to the payload byte array.
 * @param payload_length Length of the payload.
 */
OPEN1722_INLINE void Avtp_Tscf_SetPayload(Avtp_Tscf_t *pdu, uint8_t *payload,
                                          uint16_t payload_length)
{
    memcpy((uint8_t *)pdu +
               Avtp_CommonStreamHeader_GetHeaderLen((const Avtp_CommonStreamHeader_t *)pdu),
           payload, payload_length);
}

/**
 * Checks if the ACF Tscf frame is valid by checking:
 *     1) that the subtype is TSCF and the version is supported,
 *     2) that the version-dependent header fits into the buffer,
 *     3) that the declared stream_data_length fits into the buffer.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Tscf PDU.
 * @param bufferSize Size of the buffer containing the ACF Tscf frame.
 * @return true if the ACF Tscf frame is valid, false otherwise.
 */
OPEN1722_INLINE bool Avtp_Tscf_IsValid(const Avtp_Tscf_t *const pdu, size_t bufferSize)
{
    if (pdu == NULL) {
        return false;
    }

    if (Avtp_CommonHeader_GetSubtype((const Avtp_CommonHeader_t *)pdu) != AVTP_SUBTYPE_TSCF) {
        return false;
    }

    uint8_t version = Avtp_CommonStreamHeader_GetVersion((const Avtp_CommonStreamHeader_t *)pdu);
    if (!Avtp_Version_IsSupported(AVTP_TSCF_SUPPORTED_VERSIONS, version)) {
        return false;
    }

    size_t headerLen = Avtp_CommonStreamHeader_GetHeaderLen((const Avtp_CommonStreamHeader_t *)pdu);
    if (bufferSize < headerLen) {
        return false;
    }

    // Avtp_Tscf_GetStreamDataLength returns the stream data length in octets.
    if ((size_t)Avtp_Tscf_GetStreamDataLength(pdu) > bufferSize - headerLen) {
        return false;
    }

    return true;
}

/**
 * Initializes a version 0 TSCF PDU as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of a 1722 PDU. This is typically an AVTP-
 * or an ACF header.
 */
OPEN1722_INLINE void Avtp_Tscf_Init(Avtp_Tscf_t *pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_Tscf_t));
        Avtp_CommonHeader_SetSubtype((Avtp_CommonHeader_t *)pdu, AVTP_SUBTYPE_TSCF);
        Avtp_Tscf_SetSv(pdu, true);
    }
}

/**
 * Initializes a version 1 TSCF PDU. The caller must provide a buffer of at
 * least AVTP_TSCF_HEADER_LEN_V1 octets.
 *
 * @param pdu Pointer to the first bit of a 1722 PDU. This is typically an AVTP-
 * or an ACF header.
 */
OPEN1722_INLINE void Avtp_Tscf_InitV1(Avtp_TscfV1_t *pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_TscfV1_t));
        Avtp_CommonHeader_SetSubtype((Avtp_CommonHeader_t *)pdu, AVTP_SUBTYPE_TSCF);
        Avtp_CommonHeader_SetVersion((Avtp_CommonHeader_t *)pdu, AVTP_VERSION_1);
        Avtp_Tscf_SetSv((Avtp_Tscf_t *)pdu, true);
    }
}

/**
 * Returns the value of an AVTP TSCF field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AVTP TSCF PDU.
 * @param field Specifies the position of the data field to be read
 * @returns This function returns the value of the field.
 */
OPEN1722_INLINE uint64_t Avtp_Tscf_GetField(const Avtp_Tscf_t *const pdu, Avtp_TscfFields_t field)
{
    return (uint64_t)GET_TSCF_FIELD(field);
}

/**
 * Sets the value of an AVTP TSCF field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AVTP TSCF PDU.
 * @param field Specifies the position of the data field to be read
 * @param value The value to set.
 */
OPEN1722_INLINE void Avtp_Tscf_SetField(Avtp_Tscf_t *pdu, Avtp_TscfFields_t field, uint64_t value)
{
    SET_TSCF_FIELD(field, value);
}

#ifdef __cplusplus
}
#endif
