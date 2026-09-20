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
 * TSCF uses the AVTPDU common stream header (4.7.4) and declares a complete
 * descriptor table per version in absolute coordinates: the common fields
 * reuse the positions from CommonStreamHeader.h and the format-specific data
 * slots (format_specific_data_2 and _3) are overridden as reserved. A
 * consistency test keeps the common entries aligned with the common stream
 * header module.
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

typedef struct {
    uint8_t header[AVTP_TSCF_HEADER_LEN_V0];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_Tscf_t;

typedef struct {
    uint8_t header[AVTP_TSCF_HEADER_LEN_V1];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_TscfV1_t;

typedef enum {

    /* Common AVTP stream header fields */
    AVTP_TSCF_FIELD_SV = 0,
    AVTP_TSCF_FIELD_MR,
    AVTP_TSCF_FIELD_FSD,
    AVTP_TSCF_FIELD_TV,
    AVTP_TSCF_FIELD_SEQUENCE_NUM,
    AVTP_TSCF_FIELD_FSD0,
    AVTP_TSCF_FIELD_FSD1,
    AVTP_TSCF_FIELD_TU,
    AVTP_TSCF_FIELD_STREAM_ID,
    AVTP_TSCF_FIELD_AVTP_TIMESTAMP,
    AVTP_TSCF_FIELD_PTP_GRANDMASTER_IDENTITY,
    AVTP_TSCF_FIELD_STREAM_DATA_LENGTH,

    /* TSCF-specific fields (format_specific_data_2 and _3) */
    AVTP_TSCF_FIELD_RESERVED2,
    AVTP_TSCF_FIELD_RESERVED3,

    /* Count number of fields for bound checks */
    AVTP_TSCF_FIELD_MAX
} Avtp_TscfFields_t;

/**
 * This table maps all IEEE 1722 TSCF header fields to a descriptor for version
 * 0. It is complete and in absolute coordinates; the common stream header
 * fields use the same positions as Avtp_CshFieldDescV0.
 */
static const Avtp_FieldDescriptor_t Avtp_TscfFieldDescV0[AVTP_TSCF_FIELD_MAX] = {
    [AVTP_TSCF_FIELD_SV] = {.quadlet = 0, .offset = 8, .bits = 1},
    [AVTP_TSCF_FIELD_MR] = {.quadlet = 0, .offset = 12, .bits = 1},
    [AVTP_TSCF_FIELD_FSD] = {.quadlet = 0, .offset = 13, .bits = 2},
    [AVTP_TSCF_FIELD_TV] = {.quadlet = 0, .offset = 15, .bits = 1},
    [AVTP_TSCF_FIELD_SEQUENCE_NUM] = {.quadlet = 0, .offset = 16, .bits = 8},
    [AVTP_TSCF_FIELD_FSD0] = {.quadlet = 0, .offset = 0, .bits = 0},
    [AVTP_TSCF_FIELD_FSD1] = {.quadlet = 0, .offset = 24, .bits = 7},
    [AVTP_TSCF_FIELD_TU] = {.quadlet = 0, .offset = 31, .bits = 1},
    [AVTP_TSCF_FIELD_STREAM_ID] = {.quadlet = 1, .offset = 0, .bits = 64},
    [AVTP_TSCF_FIELD_AVTP_TIMESTAMP] = {.quadlet = 3, .offset = 0, .bits = 32},
    [AVTP_TSCF_FIELD_PTP_GRANDMASTER_IDENTITY] = {.quadlet = 0, .offset = 0, .bits = 0},
    [AVTP_TSCF_FIELD_STREAM_DATA_LENGTH] = {.quadlet = 5, .offset = 0, .bits = 16},
    [AVTP_TSCF_FIELD_RESERVED2] = {.quadlet = 4, .offset = 0, .bits = 32},
    [AVTP_TSCF_FIELD_RESERVED3] = {.quadlet = 5, .offset = 16, .bits = 16},
};

/**
 * This table maps all IEEE 1722 TSCF header fields to a descriptor for version
 * 1. It is complete and in absolute coordinates; the common stream header
 * fields use the same positions as Avtp_CshFieldDescV1.
 */
static const Avtp_FieldDescriptor_t Avtp_TscfFieldDescV1[AVTP_TSCF_FIELD_MAX] = {
    [AVTP_TSCF_FIELD_SV] = {.quadlet = 0, .offset = 8, .bits = 1},
    [AVTP_TSCF_FIELD_MR] = {.quadlet = 0, .offset = 12, .bits = 1},
    [AVTP_TSCF_FIELD_FSD] = {.quadlet = 0, .offset = 13, .bits = 2},
    [AVTP_TSCF_FIELD_TV] = {.quadlet = 0, .offset = 15, .bits = 1},
    [AVTP_TSCF_FIELD_SEQUENCE_NUM] = {.quadlet = 3, .offset = 0, .bits = 32},
    [AVTP_TSCF_FIELD_FSD0] = {.quadlet = 0, .offset = 16, .bits = 8},
    [AVTP_TSCF_FIELD_FSD1] = {.quadlet = 0, .offset = 24, .bits = 7},
    [AVTP_TSCF_FIELD_TU] = {.quadlet = 0, .offset = 31, .bits = 1},
    [AVTP_TSCF_FIELD_STREAM_ID] = {.quadlet = 1, .offset = 0, .bits = 64},
    [AVTP_TSCF_FIELD_AVTP_TIMESTAMP] = {.quadlet = 4, .offset = 0, .bits = 64},
    [AVTP_TSCF_FIELD_PTP_GRANDMASTER_IDENTITY] = {.quadlet = 6, .offset = 0, .bits = 64},
    [AVTP_TSCF_FIELD_STREAM_DATA_LENGTH] = {.quadlet = 9, .offset = 0, .bits = 16},
    [AVTP_TSCF_FIELD_RESERVED2] = {.quadlet = 8, .offset = 0, .bits = 32},
    [AVTP_TSCF_FIELD_RESERVED3] = {.quadlet = 9, .offset = 16, .bits = 16},
};

/**
 * Returns the value of an AVTP TSCF field as laid out by version 0. No version
 * dispatch is performed.
 *
 * @param pdu Pointer to the first bit of an 1722 AVTP TSCF PDU.
 * @param field Specifies the position of the data field to be read
 * @returns This function returns the value of the field.
 * @see Avtp_Tscf_GetField
 */
OPEN1722_INLINE uint64_t Avtp_Tscf_GetField_V0(const Avtp_Tscf_t *const pdu,
                                               Avtp_TscfFields_t field)
{
    return Avtp_GetField(Avtp_TscfFieldDescV0, AVTP_TSCF_FIELD_MAX, (const uint8_t *)pdu,
                         (uint8_t)field);
}

/**
 * Returns the value of an AVTP TSCF field as laid out by version 1. No version
 * dispatch is performed.
 *
 * @param pdu Pointer to the first bit of an 1722 AVTP TSCF PDU.
 * @param field Specifies the position of the data field to be read
 * @returns This function returns the value of the field.
 * @see Avtp_Tscf_GetField
 */
OPEN1722_INLINE uint64_t Avtp_Tscf_GetField_V1(const Avtp_TscfV1_t *const pdu,
                                               Avtp_TscfFields_t field)
{
    return Avtp_GetField(Avtp_TscfFieldDescV1, AVTP_TSCF_FIELD_MAX, (const uint8_t *)pdu,
                         (uint8_t)field);
}

/**
 * Returns the value of an AVTP TSCF field, dispatching on the version field of
 * the PDU.
 *
 * @param pdu Pointer to the first bit of an 1722 AVTP TSCF PDU.
 * @param field Specifies the position of the data field to be read
 * @returns This function returns the value of the field.
 */
OPEN1722_INLINE uint64_t Avtp_Tscf_GetField(const Avtp_Tscf_t *const pdu, Avtp_TscfFields_t field)
{
    return Avtp_CommonStreamHeader_GetVersion((const Avtp_CommonStreamHeader_t *)pdu) ==
                   AVTP_VERSION_1
               ? Avtp_Tscf_GetField_V1((const Avtp_TscfV1_t *)pdu, field)
               : Avtp_Tscf_GetField_V0(pdu, field);
}

/**
 * Sets the value of an AVTP TSCF field as laid out by version 0. No version
 * dispatch is performed.
 *
 * @param pdu Pointer to the first bit of an 1722 AVTP TSCF PDU.
 * @param field Specifies the position of the data field to be written
 * @param value The value to set.
 * @see Avtp_Tscf_SetField
 */
OPEN1722_INLINE void Avtp_Tscf_SetField_V0(Avtp_Tscf_t *pdu, Avtp_TscfFields_t field,
                                           uint64_t value)
{
    Avtp_SetField(Avtp_TscfFieldDescV0, AVTP_TSCF_FIELD_MAX, (uint8_t *)pdu, (uint8_t)field, value);
}

/**
 * Sets the value of an AVTP TSCF field as laid out by version 1. No version
 * dispatch is performed.
 *
 * @param pdu Pointer to the first bit of an 1722 AVTP TSCF PDU.
 * @param field Specifies the position of the data field to be written
 * @param value The value to set.
 * @see Avtp_Tscf_SetField
 */
OPEN1722_INLINE void Avtp_Tscf_SetField_V1(Avtp_TscfV1_t *pdu, Avtp_TscfFields_t field,
                                           uint64_t value)
{
    Avtp_SetField(Avtp_TscfFieldDescV1, AVTP_TSCF_FIELD_MAX, (uint8_t *)pdu, (uint8_t)field, value);
}

/**
 * Sets the value of an AVTP TSCF field, dispatching on the version field of the
 * PDU.
 *
 * @param pdu Pointer to the first bit of an 1722 AVTP TSCF PDU.
 * @param field Specifies the position of the data field to be written
 * @param value The value to set.
 */
OPEN1722_INLINE void Avtp_Tscf_SetField(Avtp_Tscf_t *pdu, Avtp_TscfFields_t field, uint64_t value)
{
    if (Avtp_CommonStreamHeader_GetVersion((const Avtp_CommonStreamHeader_t *)pdu) ==
        AVTP_VERSION_1) {
        Avtp_Tscf_SetField_V1((Avtp_TscfV1_t *)pdu, field, value);
    } else {
        Avtp_Tscf_SetField_V0(pdu, field, value);
    }
}

/**
 * Returns the length of the version 0 TSCF header in octets (24). The PDU
 * pointer is not read; it keeps the signature aligned with the
 * version-dispatched accessors.
 */
OPEN1722_INLINE uint8_t Avtp_Tscf_GetHeaderLen_V0(const Avtp_Tscf_t *const pdu)
{
    (void)pdu;
    return (uint8_t)AVTP_TSCF_HEADER_LEN_V0;
}

/**
 * Returns the length of the version 1 TSCF header in octets (40). The PDU
 * pointer is not read; it keeps the signature aligned with the
 * version-dispatched accessors.
 */
OPEN1722_INLINE uint8_t Avtp_Tscf_GetHeaderLen_V1(const Avtp_TscfV1_t *const pdu)
{
    (void)pdu;
    return (uint8_t)AVTP_TSCF_HEADER_LEN_V1;
}

/**
 * Returns the length of the TSCF header in octets (24 or 40), dispatching on
 * the version field of the PDU.
 */
OPEN1722_INLINE uint8_t Avtp_Tscf_GetHeaderLen(const Avtp_Tscf_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetVersion((const Avtp_CommonStreamHeader_t *)pdu) ==
                   AVTP_VERSION_1
               ? Avtp_Tscf_GetHeaderLen_V1((const Avtp_TscfV1_t *)pdu)
               : Avtp_Tscf_GetHeaderLen_V0(pdu);
}

/**
 * Return the value of the TSCF SV field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @returns Value of the TSCF SV field.
 */
OPEN1722_INLINE bool Avtp_Tscf_IsSv(const Avtp_Tscf_t *const pdu)
{
    return (bool)Avtp_Tscf_GetField(pdu, AVTP_TSCF_FIELD_SV);
}

/**
 * Return the value of the TSCF MR field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @returns Value of the TSCF MR field.
 */
OPEN1722_INLINE bool Avtp_Tscf_IsMr(const Avtp_Tscf_t *const pdu)
{
    return (bool)Avtp_Tscf_GetField(pdu, AVTP_TSCF_FIELD_MR);
}

/**
 * Return the value of the TSCF TV field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @returns Value of the TSCF TV field.
 */
OPEN1722_INLINE bool Avtp_Tscf_IsTv(const Avtp_Tscf_t *const pdu)
{
    return (bool)Avtp_Tscf_GetField(pdu, AVTP_TSCF_FIELD_TV);
}

/**
 * Return the value of the TSCF TU field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @returns Value of the TSCF TU field.
 */
OPEN1722_INLINE bool Avtp_Tscf_IsTu(const Avtp_Tscf_t *const pdu)
{
    return (bool)Avtp_Tscf_GetField(pdu, AVTP_TSCF_FIELD_TU);
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
    return (uint32_t)Avtp_Tscf_GetField(pdu, AVTP_TSCF_FIELD_SEQUENCE_NUM);
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
    return Avtp_CommonStreamHeader_GetVersion((const Avtp_CommonStreamHeader_t *)pdu) ==
                   AVTP_VERSION_1
               ? (uint8_t)Avtp_Tscf_GetField_V1((const Avtp_TscfV1_t *)pdu, AVTP_TSCF_FIELD_FSD0)
               : (uint8_t)Avtp_Tscf_GetField_V0(pdu, AVTP_TSCF_FIELD_SEQUENCE_NUM);
}

/**
 * Return the value of the TSCF Stream ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @returns Value of the TSCF Stream ID field.
 */
OPEN1722_INLINE uint64_t Avtp_Tscf_GetStreamId(const Avtp_Tscf_t *const pdu)
{
    return Avtp_Tscf_GetField(pdu, AVTP_TSCF_FIELD_STREAM_ID);
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
    return Avtp_Tscf_GetField(pdu, AVTP_TSCF_FIELD_AVTP_TIMESTAMP);
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
    return Avtp_Tscf_GetField(pdu, AVTP_TSCF_FIELD_PTP_GRANDMASTER_IDENTITY);
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
    return (uint16_t)Avtp_Tscf_GetField(pdu, AVTP_TSCF_FIELD_STREAM_DATA_LENGTH);
}

/**
 * Set the SV bit in an ACF Tscf frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @param sv Value to set the TSCF PDU SV field to.
 */
OPEN1722_INLINE void Avtp_Tscf_SetSv(Avtp_Tscf_t *pdu, bool sv)
{
    Avtp_Tscf_SetField(pdu, AVTP_TSCF_FIELD_SV, sv);
}

/**
 * Set the MR bit in an ACF Tscf frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @param mr Value to set the TSCF PDU MR field to.
 */
OPEN1722_INLINE void Avtp_Tscf_SetMr(Avtp_Tscf_t *pdu, bool mr)
{
    Avtp_Tscf_SetField(pdu, AVTP_TSCF_FIELD_MR, mr);
}

/**
 * Set the TV bit in an ACF Tscf frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @param tv Value to set the TSCF PDU TV field to.
 */
OPEN1722_INLINE void Avtp_Tscf_SetTv(Avtp_Tscf_t *pdu, bool tv)
{
    Avtp_Tscf_SetField(pdu, AVTP_TSCF_FIELD_TV, tv);
}

/**
 * Set the TU bit in an ACF Tscf frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @param tu Value to set the TSCF PDU TU field to.
 */
OPEN1722_INLINE void Avtp_Tscf_SetTu(Avtp_Tscf_t *pdu, bool tu)
{
    Avtp_Tscf_SetField(pdu, AVTP_TSCF_FIELD_TU, tu);
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
    if (Avtp_CommonStreamHeader_GetVersion((const Avtp_CommonStreamHeader_t *)pdu) ==
        AVTP_VERSION_1) {
        Avtp_Tscf_SetField_V1((Avtp_TscfV1_t *)pdu, AVTP_TSCF_FIELD_SEQUENCE_NUM, value);
        Avtp_Tscf_SetField_V1((Avtp_TscfV1_t *)pdu, AVTP_TSCF_FIELD_FSD0, (uint8_t)(value & 0xFFU));
    } else {
        Avtp_Tscf_SetField_V0(pdu, AVTP_TSCF_FIELD_SEQUENCE_NUM, value);
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
    Avtp_Tscf_SetField(pdu, AVTP_TSCF_FIELD_STREAM_ID, value);
}

/**
 * Set the value of the TSCF AVTP Timestamp field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @param value Value to set the TSCF PDU AVTP Timestamp field to.
 */
OPEN1722_INLINE void Avtp_Tscf_SetAvtpTimestamp(Avtp_Tscf_t *pdu, uint64_t value)
{
    Avtp_Tscf_SetField(pdu, AVTP_TSCF_FIELD_AVTP_TIMESTAMP, value);
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
    Avtp_Tscf_SetField(pdu, AVTP_TSCF_FIELD_PTP_GRANDMASTER_IDENTITY, value);
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
    Avtp_Tscf_SetField(pdu, AVTP_TSCF_FIELD_STREAM_DATA_LENGTH, value);
}

/**
 * Returns a pointer to the payload of a version 0 TSCF frame.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @return Pointer to the TSCF frame payload.
 * @see Avtp_Tscf_GetPayload
 */
OPEN1722_INLINE const uint8_t *Avtp_Tscf_GetPayload_V0(const Avtp_Tscf_t *const pdu)
{
    return (const uint8_t *)pdu + AVTP_TSCF_HEADER_LEN_V0;
}

/**
 * Returns a pointer to the payload of a version 1 TSCF frame.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @return Pointer to the TSCF frame payload.
 * @see Avtp_Tscf_GetPayload
 */
OPEN1722_INLINE const uint8_t *Avtp_Tscf_GetPayload_V1(const Avtp_TscfV1_t *const pdu)
{
    return (const uint8_t *)pdu + AVTP_TSCF_HEADER_LEN_V1;
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
    return Avtp_CommonStreamHeader_GetVersion((const Avtp_CommonStreamHeader_t *)pdu) ==
                   AVTP_VERSION_1
               ? Avtp_Tscf_GetPayload_V1((const Avtp_TscfV1_t *)pdu)
               : Avtp_Tscf_GetPayload_V0(pdu);
}

/**
 * Sets the payload of a version 0 TSCF frame.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @param payload Pointer to the payload byte array.
 * @param payload_length Length of the payload.
 * @see Avtp_Tscf_SetPayload
 */
OPEN1722_INLINE void Avtp_Tscf_SetPayload_V0(Avtp_Tscf_t *pdu, uint8_t *payload,
                                             uint16_t payload_length)
{
    memcpy((uint8_t *)pdu + AVTP_TSCF_HEADER_LEN_V0, payload, payload_length);
}

/**
 * Sets the payload of a version 1 TSCF frame.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @param payload Pointer to the payload byte array.
 * @param payload_length Length of the payload.
 * @see Avtp_Tscf_SetPayload
 */
OPEN1722_INLINE void Avtp_Tscf_SetPayload_V1(Avtp_TscfV1_t *pdu, uint8_t *payload,
                                             uint16_t payload_length)
{
    memcpy((uint8_t *)pdu + AVTP_TSCF_HEADER_LEN_V1, payload, payload_length);
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
    if (Avtp_CommonStreamHeader_GetVersion((const Avtp_CommonStreamHeader_t *)pdu) ==
        AVTP_VERSION_1) {
        Avtp_Tscf_SetPayload_V1((Avtp_TscfV1_t *)pdu, payload, payload_length);
    } else {
        Avtp_Tscf_SetPayload_V0(pdu, payload, payload_length);
    }
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

/*
 * Version-typed named accessors. These select the field layout for one
 * explicit version and never read the version field; the version-dispatched
 * accessors above delegate to them. Common stream header fields delegate to
 * the shared Avtp_CommonStreamHeader_* variants. See each version-dispatched
 * accessor for the full field documentation.
 */

/**
 * Version 0 variant of Avtp_Tscf_IsSv().
 * @see Avtp_Tscf_IsSv
 */
OPEN1722_INLINE bool Avtp_Tscf_IsSv_V0(const Avtp_Tscf_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsSv_V0((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Tscf_IsSv().
 * @see Avtp_Tscf_IsSv
 */
OPEN1722_INLINE bool Avtp_Tscf_IsSv_V1(const Avtp_TscfV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsSv_V1((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Tscf_IsMr().
 * @see Avtp_Tscf_IsMr
 */
OPEN1722_INLINE bool Avtp_Tscf_IsMr_V0(const Avtp_Tscf_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsMr_V0((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Tscf_IsMr().
 * @see Avtp_Tscf_IsMr
 */
OPEN1722_INLINE bool Avtp_Tscf_IsMr_V1(const Avtp_TscfV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsMr_V1((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Tscf_IsTv().
 * @see Avtp_Tscf_IsTv
 */
OPEN1722_INLINE bool Avtp_Tscf_IsTv_V0(const Avtp_Tscf_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsTv_V0((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Tscf_IsTv().
 * @see Avtp_Tscf_IsTv
 */
OPEN1722_INLINE bool Avtp_Tscf_IsTv_V1(const Avtp_TscfV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsTv_V1((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Tscf_IsTu().
 * @see Avtp_Tscf_IsTu
 */
OPEN1722_INLINE bool Avtp_Tscf_IsTu_V0(const Avtp_Tscf_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsTu_V0((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Tscf_IsTu().
 * @see Avtp_Tscf_IsTu
 */
OPEN1722_INLINE bool Avtp_Tscf_IsTu_V1(const Avtp_TscfV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsTu_V1((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Tscf_GetSequenceNum().
 * @see Avtp_Tscf_GetSequenceNum
 */
OPEN1722_INLINE uint32_t Avtp_Tscf_GetSequenceNum_V0(const Avtp_Tscf_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetSequenceNum_V0((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Tscf_GetSequenceNum().
 * @see Avtp_Tscf_GetSequenceNum
 */
OPEN1722_INLINE uint32_t Avtp_Tscf_GetSequenceNum_V1(const Avtp_TscfV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetSequenceNum_V1((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Tscf_GetSequenceNumLsb(). In version 0 this is the
 * 8-bit sequence_num field.
 * @see Avtp_Tscf_GetSequenceNumLsb
 */
OPEN1722_INLINE uint8_t Avtp_Tscf_GetSequenceNumLsb_V0(const Avtp_Tscf_t *const pdu)
{
    return (uint8_t)Avtp_Tscf_GetField_V0(pdu, AVTP_TSCF_FIELD_SEQUENCE_NUM);
}

/**
 * Version 1 variant of Avtp_Tscf_GetSequenceNumLsb(). In version 1 this is the
 * copy of the eight least significant bits of sequence_num stored in
 * format_specific_data_0 (TSCF-4).
 * @see Avtp_Tscf_GetSequenceNumLsb
 */
OPEN1722_INLINE uint8_t Avtp_Tscf_GetSequenceNumLsb_V1(const Avtp_TscfV1_t *const pdu)
{
    return (uint8_t)Avtp_Tscf_GetField_V1(pdu, AVTP_TSCF_FIELD_FSD0);
}

/**
 * Version 0 variant of Avtp_Tscf_GetStreamId().
 * @see Avtp_Tscf_GetStreamId
 */
OPEN1722_INLINE uint64_t Avtp_Tscf_GetStreamId_V0(const Avtp_Tscf_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetStreamId_V0((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Tscf_GetStreamId().
 * @see Avtp_Tscf_GetStreamId
 */
OPEN1722_INLINE uint64_t Avtp_Tscf_GetStreamId_V1(const Avtp_TscfV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetStreamId_V1((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Tscf_GetAvtpTimestamp().
 * @see Avtp_Tscf_GetAvtpTimestamp
 */
OPEN1722_INLINE uint64_t Avtp_Tscf_GetAvtpTimestamp_V0(const Avtp_Tscf_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetAvtpTimestamp_V0((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Tscf_GetAvtpTimestamp().
 * @see Avtp_Tscf_GetAvtpTimestamp
 */
OPEN1722_INLINE uint64_t Avtp_Tscf_GetAvtpTimestamp_V1(const Avtp_TscfV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetAvtpTimestamp_V1((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Tscf_GetPtpGrandmasterIdentity(). The field is
 * absent from version 0, so this always returns 0.
 * @see Avtp_Tscf_GetPtpGrandmasterIdentity
 */
OPEN1722_INLINE uint64_t Avtp_Tscf_GetPtpGrandmasterIdentity_V0(const Avtp_Tscf_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetPtpGrandmasterIdentity_V0(
        (const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Tscf_GetPtpGrandmasterIdentity().
 * @see Avtp_Tscf_GetPtpGrandmasterIdentity
 */
OPEN1722_INLINE uint64_t Avtp_Tscf_GetPtpGrandmasterIdentity_V1(const Avtp_TscfV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetPtpGrandmasterIdentity_V1(
        (const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Tscf_GetStreamDataLength().
 * @see Avtp_Tscf_GetStreamDataLength
 */
OPEN1722_INLINE uint16_t Avtp_Tscf_GetStreamDataLength_V0(const Avtp_Tscf_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetStreamDataLength_V0((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Tscf_GetStreamDataLength().
 * @see Avtp_Tscf_GetStreamDataLength
 */
OPEN1722_INLINE uint16_t Avtp_Tscf_GetStreamDataLength_V1(const Avtp_TscfV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetStreamDataLength_V1((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Tscf_SetSv().
 * @see Avtp_Tscf_SetSv
 */
OPEN1722_INLINE void Avtp_Tscf_SetSv_V0(Avtp_Tscf_t *pdu, bool sv)
{
    Avtp_CommonStreamHeader_SetSv_V0((Avtp_CommonStreamHeader_t *)pdu, sv);
}

/**
 * Version 1 variant of Avtp_Tscf_SetSv().
 * @see Avtp_Tscf_SetSv
 */
OPEN1722_INLINE void Avtp_Tscf_SetSv_V1(Avtp_TscfV1_t *pdu, bool sv)
{
    Avtp_CommonStreamHeader_SetSv_V1((Avtp_CommonStreamHeader_t *)pdu, sv);
}

/**
 * Version 0 variant of Avtp_Tscf_SetMr().
 * @see Avtp_Tscf_SetMr
 */
OPEN1722_INLINE void Avtp_Tscf_SetMr_V0(Avtp_Tscf_t *pdu, bool mr)
{
    Avtp_CommonStreamHeader_SetMr_V0((Avtp_CommonStreamHeader_t *)pdu, mr);
}

/**
 * Version 1 variant of Avtp_Tscf_SetMr().
 * @see Avtp_Tscf_SetMr
 */
OPEN1722_INLINE void Avtp_Tscf_SetMr_V1(Avtp_TscfV1_t *pdu, bool mr)
{
    Avtp_CommonStreamHeader_SetMr_V1((Avtp_CommonStreamHeader_t *)pdu, mr);
}

/**
 * Version 0 variant of Avtp_Tscf_SetTv().
 * @see Avtp_Tscf_SetTv
 */
OPEN1722_INLINE void Avtp_Tscf_SetTv_V0(Avtp_Tscf_t *pdu, bool tv)
{
    Avtp_CommonStreamHeader_SetTv_V0((Avtp_CommonStreamHeader_t *)pdu, tv);
}

/**
 * Version 1 variant of Avtp_Tscf_SetTv().
 * @see Avtp_Tscf_SetTv
 */
OPEN1722_INLINE void Avtp_Tscf_SetTv_V1(Avtp_TscfV1_t *pdu, bool tv)
{
    Avtp_CommonStreamHeader_SetTv_V1((Avtp_CommonStreamHeader_t *)pdu, tv);
}

/**
 * Version 0 variant of Avtp_Tscf_SetTu().
 * @see Avtp_Tscf_SetTu
 */
OPEN1722_INLINE void Avtp_Tscf_SetTu_V0(Avtp_Tscf_t *pdu, bool tu)
{
    Avtp_CommonStreamHeader_SetTu_V0((Avtp_CommonStreamHeader_t *)pdu, tu);
}

/**
 * Version 1 variant of Avtp_Tscf_SetTu().
 * @see Avtp_Tscf_SetTu
 */
OPEN1722_INLINE void Avtp_Tscf_SetTu_V1(Avtp_TscfV1_t *pdu, bool tu)
{
    Avtp_CommonStreamHeader_SetTu_V1((Avtp_CommonStreamHeader_t *)pdu, tu);
}

/**
 * Version 0 variant of Avtp_Tscf_SetSequenceNum(). Values are truncated to the
 * 8-bit version 0 sequence_num field.
 * @see Avtp_Tscf_SetSequenceNum
 */
OPEN1722_INLINE void Avtp_Tscf_SetSequenceNum_V0(Avtp_Tscf_t *pdu, uint32_t value)
{
    Avtp_Tscf_SetField_V0(pdu, AVTP_TSCF_FIELD_SEQUENCE_NUM, value);
}

/**
 * Version 1 variant of Avtp_Tscf_SetSequenceNum(). The eight least significant
 * bits are also written to the sequence_num_lsb copy in format_specific_data_0
 * (TSCF-4).
 * @see Avtp_Tscf_SetSequenceNum
 */
OPEN1722_INLINE void Avtp_Tscf_SetSequenceNum_V1(Avtp_TscfV1_t *pdu, uint32_t value)
{
    Avtp_Tscf_SetField_V1(pdu, AVTP_TSCF_FIELD_SEQUENCE_NUM, value);
    Avtp_Tscf_SetField_V1(pdu, AVTP_TSCF_FIELD_FSD0, (uint8_t)(value & 0xFFU));
}

/**
 * Version 0 variant of Avtp_Tscf_SetStreamId().
 * @see Avtp_Tscf_SetStreamId
 */
OPEN1722_INLINE void Avtp_Tscf_SetStreamId_V0(Avtp_Tscf_t *pdu, uint64_t value)
{
    Avtp_CommonStreamHeader_SetStreamId_V0((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 1 variant of Avtp_Tscf_SetStreamId().
 * @see Avtp_Tscf_SetStreamId
 */
OPEN1722_INLINE void Avtp_Tscf_SetStreamId_V1(Avtp_TscfV1_t *pdu, uint64_t value)
{
    Avtp_CommonStreamHeader_SetStreamId_V1((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 0 variant of Avtp_Tscf_SetAvtpTimestamp().
 * @see Avtp_Tscf_SetAvtpTimestamp
 */
OPEN1722_INLINE void Avtp_Tscf_SetAvtpTimestamp_V0(Avtp_Tscf_t *pdu, uint64_t value)
{
    Avtp_CommonStreamHeader_SetAvtpTimestamp_V0((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 1 variant of Avtp_Tscf_SetAvtpTimestamp().
 * @see Avtp_Tscf_SetAvtpTimestamp
 */
OPEN1722_INLINE void Avtp_Tscf_SetAvtpTimestamp_V1(Avtp_TscfV1_t *pdu, uint64_t value)
{
    Avtp_CommonStreamHeader_SetAvtpTimestamp_V1((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 0 variant of Avtp_Tscf_SetPtpGrandmasterIdentity(). The field is
 * absent from version 0, so this is a no-op.
 * @see Avtp_Tscf_SetPtpGrandmasterIdentity
 */
OPEN1722_INLINE void Avtp_Tscf_SetPtpGrandmasterIdentity_V0(Avtp_Tscf_t *pdu, uint64_t value)
{
    Avtp_CommonStreamHeader_SetPtpGrandmasterIdentity_V0((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 1 variant of Avtp_Tscf_SetPtpGrandmasterIdentity().
 * @see Avtp_Tscf_SetPtpGrandmasterIdentity
 */
OPEN1722_INLINE void Avtp_Tscf_SetPtpGrandmasterIdentity_V1(Avtp_TscfV1_t *pdu, uint64_t value)
{
    Avtp_CommonStreamHeader_SetPtpGrandmasterIdentity_V1((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 0 variant of Avtp_Tscf_SetStreamDataLength().
 * @see Avtp_Tscf_SetStreamDataLength
 */
OPEN1722_INLINE void Avtp_Tscf_SetStreamDataLength_V0(Avtp_Tscf_t *pdu, uint16_t value)
{
    Avtp_CommonStreamHeader_SetStreamDataLength_V0((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 1 variant of Avtp_Tscf_SetStreamDataLength().
 * @see Avtp_Tscf_SetStreamDataLength
 */
OPEN1722_INLINE void Avtp_Tscf_SetStreamDataLength_V1(Avtp_TscfV1_t *pdu, uint16_t value)
{
    Avtp_CommonStreamHeader_SetStreamDataLength_V1((Avtp_CommonStreamHeader_t *)pdu, value);
}

#ifdef __cplusplus
}
#endif
