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
 * This file contains the fields descriptions of the IEEE 1722 NTSCF PDUs and
 * functions to invoke corresponding parser and deparser.
 *
 * NTSCF uses the AVTPDU alternative header (4.7.6) and declares a complete
 * descriptor table per version in absolute coordinates: the alternative header
 * fields reuse the positions from AlternativeHeader.h, the trailing 12-bit
 * reserved field and the NTSCF-specific fields are added by this module. A
 * consistency test keeps the alternative header entries aligned with the
 * alternative header module.
 */

#pragma once
#include "avtp/Inline.h"

#ifdef LINUX_KERNEL1722
#include <linux/string.h>
#else
#include <string.h>
#include <stdbool.h>
#endif

#include "avtp/Utils.h"
#include "avtp/Defines.h"
#include "avtp/CommonHeader.h"
#include "avtp/AlternativeHeader.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AVTP_NTSCF_HEADER_LEN_V0 (3 * AVTP_QUADLET_SIZE) /* 12 */
#define AVTP_NTSCF_HEADER_LEN_V1 (7 * AVTP_QUADLET_SIZE) /* 28 */
/* Kept for compatibility: the version 0 header length. */
#define AVTP_NTSCF_HEADER_LEN AVTP_NTSCF_HEADER_LEN_V0

/* NTSCF supports both versions of the alternative header (Table 7). */
#define AVTP_NTSCF_SUPPORTED_VERSIONS ((1u << AVTP_VERSION_0) | (1u << AVTP_VERSION_1))

typedef struct {
    uint8_t header[AVTP_NTSCF_HEADER_LEN_V0];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_Ntscf_t;

typedef struct {
    uint8_t header[AVTP_NTSCF_HEADER_LEN_V1];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_NtscfV1_t;

typedef enum {

    /* Common AVTP alternative header fields */
    AVTP_NTSCF_FIELD_RESERVED1 = 0,
    AVTP_NTSCF_FIELD_SEQUENCE_NUM,
    AVTP_NTSCF_FIELD_PTP_GRANDMASTER_IDENTITY,

    /* NTSCF header fields */
    AVTP_NTSCF_FIELD_SV,
    AVTP_NTSCF_FIELD_RESERVED,
    AVTP_NTSCF_FIELD_R,
    AVTP_NTSCF_FIELD_NTSCF_DATA_LENGTH,
    AVTP_NTSCF_FIELD_SEQUENCE_NUM_LSB,
    AVTP_NTSCF_FIELD_STREAM_ID,

    /* Count number of fields for bound checks */
    AVTP_NTSCF_FIELD_MAX
} Avtp_NtscfFields_t;

/**
 * This table maps all IEEE 1722 NTSCF header fields to a descriptor for version
 * 0. It is complete and in absolute coordinates; the alternative header fields
 * are absent in version 0.
 */
static const Avtp_FieldDescriptor_t Avtp_NtscfFieldDescV0[AVTP_NTSCF_FIELD_MAX] = {
    [AVTP_NTSCF_FIELD_RESERVED1] = {.quadlet = 0, .offset = 0, .bits = 0},
    [AVTP_NTSCF_FIELD_SEQUENCE_NUM] = {.quadlet = 0, .offset = 0, .bits = 0},
    [AVTP_NTSCF_FIELD_PTP_GRANDMASTER_IDENTITY] = {.quadlet = 0, .offset = 0, .bits = 0},
    [AVTP_NTSCF_FIELD_SV] = {.quadlet = 0, .offset = 8, .bits = 1},
    [AVTP_NTSCF_FIELD_RESERVED] = {.quadlet = 0, .offset = 0, .bits = 0},
    [AVTP_NTSCF_FIELD_R] = {.quadlet = 0, .offset = 12, .bits = 1},
    [AVTP_NTSCF_FIELD_NTSCF_DATA_LENGTH] = {.quadlet = 0, .offset = 13, .bits = 11},
    [AVTP_NTSCF_FIELD_SEQUENCE_NUM_LSB] = {.quadlet = 0, .offset = 24, .bits = 8},
    [AVTP_NTSCF_FIELD_STREAM_ID] = {.quadlet = 1, .offset = 0, .bits = 64},
};

/**
 * This table maps all IEEE 1722 NTSCF header fields to a descriptor for version
 * 1. It is complete and in absolute coordinates; the alternative header fields
 * use the same positions as Avtp_AhFieldDescV1.
 */
static const Avtp_FieldDescriptor_t Avtp_NtscfFieldDescV1[AVTP_NTSCF_FIELD_MAX] = {
    [AVTP_NTSCF_FIELD_RESERVED1] = {.quadlet = 0, .offset = 12, .bits = 20},
    [AVTP_NTSCF_FIELD_SEQUENCE_NUM] = {.quadlet = 1, .offset = 0, .bits = 32},
    [AVTP_NTSCF_FIELD_PTP_GRANDMASTER_IDENTITY] = {.quadlet = 2, .offset = 0, .bits = 64},
    [AVTP_NTSCF_FIELD_SV] = {.quadlet = 0, .offset = 8, .bits = 1},
    [AVTP_NTSCF_FIELD_RESERVED] = {.quadlet = 4, .offset = 0, .bits = 12},
    [AVTP_NTSCF_FIELD_R] = {.quadlet = 4, .offset = 12, .bits = 1},
    [AVTP_NTSCF_FIELD_NTSCF_DATA_LENGTH] = {.quadlet = 4, .offset = 13, .bits = 11},
    [AVTP_NTSCF_FIELD_SEQUENCE_NUM_LSB] = {.quadlet = 4, .offset = 24, .bits = 8},
    [AVTP_NTSCF_FIELD_STREAM_ID] = {.quadlet = 5, .offset = 0, .bits = 64},
};

/**
 * Returns the value of an AVTP NTSCF field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AVTP NTSCF PDU.
 * @param field Specifies the position of the data field to be read
 * @returns This function returns the value of the field.
 */
OPEN1722_INLINE uint64_t Avtp_Ntscf_GetField(const Avtp_Ntscf_t *const pdu,
                                             Avtp_NtscfFields_t field)
{
    const Avtp_FieldDescriptor_t *desc =
        Avtp_AlternativeHeader_GetVersion((const Avtp_AlternativeHeader_t *)pdu) == AVTP_VERSION_1
            ? Avtp_NtscfFieldDescV1
            : Avtp_NtscfFieldDescV0;
    return Avtp_GetField(desc, AVTP_NTSCF_FIELD_MAX, (const uint8_t *)pdu, (uint8_t)field);
}

/**
 * Sets the value of an AVTP NTSCF field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AVTP NTSCF PDU.
 * @param field Specifies the position of the data field to be written
 * @param value The value to set.
 */
OPEN1722_INLINE void Avtp_Ntscf_SetField(Avtp_Ntscf_t *pdu, Avtp_NtscfFields_t field,
                                         uint64_t value)
{
    const Avtp_FieldDescriptor_t *desc =
        Avtp_AlternativeHeader_GetVersion((const Avtp_AlternativeHeader_t *)pdu) == AVTP_VERSION_1
            ? Avtp_NtscfFieldDescV1
            : Avtp_NtscfFieldDescV0;
    Avtp_SetField(desc, AVTP_NTSCF_FIELD_MAX, (uint8_t *)pdu, (uint8_t)field, value);
}

/**
 * Returns the length of the NTSCF header in octets (12 or 28).
 */
OPEN1722_INLINE uint8_t Avtp_Ntscf_GetHeaderLen(const Avtp_Ntscf_t *const pdu)
{
    return Avtp_AlternativeHeader_GetVersion((const Avtp_AlternativeHeader_t *)pdu) ==
                   AVTP_VERSION_1
               ? (uint8_t)AVTP_NTSCF_HEADER_LEN_V1
               : (uint8_t)AVTP_NTSCF_HEADER_LEN_V0;
}

/**
 * Return the value of the NTSCF SV field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF NTSCF PDU.
 * @returns Value of the NTSCF SV field.
 */
OPEN1722_INLINE bool Avtp_Ntscf_IsSv(const Avtp_Ntscf_t *const pdu)
{
    return (bool)Avtp_Ntscf_GetField(pdu, AVTP_NTSCF_FIELD_SV);
}

/**
 * Return the value of the NTSCF Ntscf Data Length field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF NTSCF PDU.
 * @returns Value of the NTSCF Ntscf Data Length field.
 */
OPEN1722_INLINE uint16_t Avtp_Ntscf_GetNtscfDataLength(const Avtp_Ntscf_t *const pdu)
{
    return (uint16_t)Avtp_Ntscf_GetField(pdu, AVTP_NTSCF_FIELD_NTSCF_DATA_LENGTH);
}

/**
 * Return the effective NTSCF Sequence Number field as specified in the IEEE 1722
 * Specification. The field is the 8-bit sequence_num_lsb in version 0 and the
 * 32-bit sequence_num in version 1.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF NTSCF PDU.
 * @returns Value of the NTSCF Sequence Number field.
 */
OPEN1722_INLINE uint32_t Avtp_Ntscf_GetSequenceNum(const Avtp_Ntscf_t *const pdu)
{
    if (Avtp_AlternativeHeader_GetVersion((const Avtp_AlternativeHeader_t *)pdu) ==
        AVTP_VERSION_1) {
        return (uint32_t)Avtp_Ntscf_GetField(pdu, AVTP_NTSCF_FIELD_SEQUENCE_NUM);
    }
    return (uint8_t)Avtp_Ntscf_GetField(pdu, AVTP_NTSCF_FIELD_SEQUENCE_NUM_LSB);
}

/**
 * Return the value of the NTSCF sequence_num_lsb field. In version 1 it
 * contains a copy of the eight least significant bits of the sequence_num
 * field in the alternative header (NTSCF-6).
 *
 * @param pdu Pointer to the first bit of an 1722 ACF NTSCF PDU.
 * @returns Value of the NTSCF sequence_num_lsb field.
 */
OPEN1722_INLINE uint8_t Avtp_Ntscf_GetSequenceNumLsb(const Avtp_Ntscf_t *const pdu)
{
    return (uint8_t)Avtp_Ntscf_GetField(pdu, AVTP_NTSCF_FIELD_SEQUENCE_NUM_LSB);
}

/**
 * Return the value of the NTSCF ptp_grandmaster_identity field. The field only
 * exists in version 1; version 0 returns 0.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF NTSCF PDU.
 * @returns Value of the NTSCF ptp_grandmaster_identity field.
 */
OPEN1722_INLINE uint64_t Avtp_Ntscf_GetPtpGrandmasterIdentity(const Avtp_Ntscf_t *const pdu)
{
    return Avtp_Ntscf_GetField(pdu, AVTP_NTSCF_FIELD_PTP_GRANDMASTER_IDENTITY);
}

/**
 * Return the value of the NTSCF Stream ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF NTSCF PDU.
 * @returns Value of the NTSCF Stream ID field.
 */
OPEN1722_INLINE uint64_t Avtp_Ntscf_GetStreamId(const Avtp_Ntscf_t *const pdu)
{
    return Avtp_Ntscf_GetField(pdu, AVTP_NTSCF_FIELD_STREAM_ID);
}

/**
 * Set the SV bit in an ACF Ntscf frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF NTSCF PDU.
 * @param sv Value to set the NTSCF PDU SV field to.
 */
OPEN1722_INLINE void Avtp_Ntscf_SetSv(Avtp_Ntscf_t *pdu, bool sv)
{
    Avtp_Ntscf_SetField(pdu, AVTP_NTSCF_FIELD_SV, sv);
}

/**
 * Set the value of the NTSCF Ntscf Data Length field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF NTSCF PDU.
 * @param value Value to set the NTSCF PDU Ntscf Data Length field to.
 */
OPEN1722_INLINE void Avtp_Ntscf_SetNtscfDataLength(Avtp_Ntscf_t *pdu, uint16_t value)
{
    Avtp_Ntscf_SetField(pdu, AVTP_NTSCF_FIELD_NTSCF_DATA_LENGTH, value);
}

/**
 * Set the effective NTSCF Sequence Number field as specified in the IEEE 1722
 * Specification. In version 1 the eight least significant bits are also written
 * to the sequence_num_lsb copy (NTSCF-6); in version 0 they are the sequence
 * number itself.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF NTSCF PDU.
 * @param value Value to set the NTSCF PDU Sequence Number field to.
 */
OPEN1722_INLINE void Avtp_Ntscf_SetSequenceNum(Avtp_Ntscf_t *pdu, uint32_t value)
{
    /* No-op on version 0: the field only exists in the alternative header v1. */
    Avtp_Ntscf_SetField(pdu, AVTP_NTSCF_FIELD_SEQUENCE_NUM, value);
    Avtp_Ntscf_SetField(pdu, AVTP_NTSCF_FIELD_SEQUENCE_NUM_LSB, (uint8_t)(value & 0xFFU));
}

/**
 * Set the value of the NTSCF ptp_grandmaster_identity field. The field only
 * exists in version 1; on version 0 this is a no-op.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF NTSCF PDU.
 * @param value Value to set the NTSCF PDU ptp_grandmaster_identity field to.
 */
OPEN1722_INLINE void Avtp_Ntscf_SetPtpGrandmasterIdentity(Avtp_Ntscf_t *pdu, uint64_t value)
{
    Avtp_Ntscf_SetField(pdu, AVTP_NTSCF_FIELD_PTP_GRANDMASTER_IDENTITY, value);
}

/**
 * Set the value of the NTSCF Stream ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF NTSCF PDU.
 * @param value Value to set the NTSCF PDU Stream ID field to.
 */
OPEN1722_INLINE void Avtp_Ntscf_SetStreamId(Avtp_Ntscf_t *pdu, uint64_t value)
{
    Avtp_Ntscf_SetField(pdu, AVTP_NTSCF_FIELD_STREAM_ID, value);
}

/**
 * Returns pointer to the payload of an NTSCF frame. The payload starts after
 * the version-dependent NTSCF header.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF NTSCF PDU.
 * @return Pointer to the NTSCF frame payload.
 */
OPEN1722_INLINE const uint8_t *Avtp_Ntscf_GetPayload(const Avtp_Ntscf_t *const pdu)
{
    return (const uint8_t *)pdu + Avtp_Ntscf_GetHeaderLen(pdu);
}

/**
 * Sets the NTSCF payload.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF NTSCF PDU.
 * @param payload Pointer to the payload byte array.
 * @param payload_length Length of the payload.
 */
OPEN1722_INLINE void Avtp_Ntscf_SetPayload(Avtp_Ntscf_t *pdu, uint8_t *payload,
                                           uint16_t payload_length)
{
    memcpy((uint8_t *)pdu + Avtp_Ntscf_GetHeaderLen(pdu), payload, payload_length);
}

/**
 * Checks if the ACF Ntscf frame is valid by checking:
 *     1) that the subtype is NTSCF and the version is supported,
 *     2) that the version-dependent header fits into the buffer,
 *     3) that the declared ntscf_data_length fits into the buffer.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF NTSCF PDU.
 * @param bufferSize Size of the buffer containing the ACF NTSCF frame.
 * @return true if the ACF NTSCF frame is valid, false otherwise.
 */
OPEN1722_INLINE bool Avtp_Ntscf_IsValid(const Avtp_Ntscf_t *const pdu, size_t bufferSize)
{
    if (pdu == NULL) {
        return false;
    }

    if (Avtp_CommonHeader_GetSubtype((const Avtp_CommonHeader_t *)pdu) != AVTP_SUBTYPE_NTSCF) {
        return false;
    }

    uint8_t version = Avtp_AlternativeHeader_GetVersion((const Avtp_AlternativeHeader_t *)pdu);
    if (!Avtp_Version_IsSupported(AVTP_NTSCF_SUPPORTED_VERSIONS, version)) {
        return false;
    }

    size_t headerLen = Avtp_Ntscf_GetHeaderLen(pdu);
    if (bufferSize < headerLen) {
        return false;
    }

    // Avtp_Ntscf_GetNtscfDataLength returns the payload length in octets.
    if ((size_t)Avtp_Ntscf_GetNtscfDataLength(pdu) > bufferSize - headerLen) {
        return false;
    }

    return true;
}

/**
 * Initializes a version 0 NTSCF PDU as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of a 1722 PDU. This is typically an AVTP-
 * or an ACF header.
 */
OPEN1722_INLINE void Avtp_Ntscf_Init(Avtp_Ntscf_t *pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_Ntscf_t));
        Avtp_CommonHeader_SetSubtype((Avtp_CommonHeader_t *)pdu, AVTP_SUBTYPE_NTSCF);
        Avtp_Ntscf_SetSv(pdu, true);
    }
}

/**
 * Initializes a version 1 NTSCF PDU. The caller must provide a buffer of at
 * least AVTP_NTSCF_HEADER_LEN_V1 octets.
 *
 * @param pdu Pointer to the first bit of a 1722 PDU. This is typically an AVTP-
 * or an ACF header.
 */
OPEN1722_INLINE void Avtp_Ntscf_InitV1(Avtp_NtscfV1_t *pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_NtscfV1_t));
        Avtp_CommonHeader_SetSubtype((Avtp_CommonHeader_t *)pdu, AVTP_SUBTYPE_NTSCF);
        Avtp_CommonHeader_SetVersion((Avtp_CommonHeader_t *)pdu, AVTP_VERSION_1);
        Avtp_Ntscf_SetSv((Avtp_Ntscf_t *)pdu, true);
    }
}

#ifdef __cplusplus
}
#endif
