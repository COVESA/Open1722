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
 * This file contains the fields descriptions of the IEEE 1722 CRF PDUs and
 * functions to invoke corresponding parser and deparser.
 *
 * CRF uses the AVTPDU alternative header (4.7.6) and declares a complete
 * descriptor table per version in absolute coordinates: the alternative header
 * fields reuse the positions from AlternativeHeader.h, the trailing 12-bit
 * reserved field and the CRF-specific fields are added by this module. A
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

#define AVTP_CRF_HEADER_LEN_V0 (5 * AVTP_QUADLET_SIZE) /* 20 */
#define AVTP_CRF_HEADER_LEN_V1 (9 * AVTP_QUADLET_SIZE) /* 36 */
/* Kept for compatibility: the version 0 header length. */
#define AVTP_CRF_HEADER_LEN AVTP_CRF_HEADER_LEN_V0

/* CRF supports both versions of the alternative header (Table 7). */
#define AVTP_CRF_SUPPORTED_VERSIONS ((1u << AVTP_VERSION_0) | (1u << AVTP_VERSION_1))

typedef struct {
    uint8_t header[AVTP_CRF_HEADER_LEN_V0];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_Crf_t;

typedef struct {
    uint8_t header[AVTP_CRF_HEADER_LEN_V1];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_CrfV1_t;

/**
 * CRF 'type' field values (IEEE 1722-2025, Table 31). Values 0x05-0xFF are
 * reserved.
 */
typedef enum {
    AVTP_CRF_TYPE_USER = 0x00,
    AVTP_CRF_TYPE_AUDIO_SAMPLE = 0x01,
    AVTP_CRF_TYPE_VIDEO_FRAME = 0x02,
    AVTP_CRF_TYPE_VIDEO_LINE = 0x03,
    AVTP_CRF_TYPE_MACHINE_CYCLE = 0x04,
} Avtp_CrfType_t;

/**
 * CRF 'pull' field values (IEEE 1722-2025, Table 32). Values 0x06-0x07 are
 * reserved.
 */
typedef enum {
    AVTP_CRF_PULL_MULT_BY_1 = 0x00,
    AVTP_CRF_PULL_MULT_BY_1_OVER_1_001 = 0x01,
    AVTP_CRF_PULL_MULT_BY_1_001 = 0x02,
    AVTP_CRF_PULL_MULT_BY_24_OVER_25 = 0x03,
    AVTP_CRF_PULL_MULT_BY_25_OVER_24 = 0x04,
    AVTP_CRF_PULL_MULT_BY_1_OVER_8 = 0x05,
} Avtp_CrfPull_t;

typedef enum {

    /* Common AVTP alternative header fields */
    AVTP_CRF_FIELD_RESERVED1 = 0,
    AVTP_CRF_FIELD_SEQUENCE_NUM,
    AVTP_CRF_FIELD_PTP_GRANDMASTER_IDENTITY,

    /* CRF header fields */
    AVTP_CRF_FIELD_SV,
    AVTP_CRF_FIELD_RESERVED,
    AVTP_CRF_FIELD_MR,
    AVTP_CRF_FIELD_R,
    AVTP_CRF_FIELD_FS,
    AVTP_CRF_FIELD_TU,
    AVTP_CRF_FIELD_SEQUENCE_NUM_LSB,
    AVTP_CRF_FIELD_TYPE,
    AVTP_CRF_FIELD_STREAM_ID,
    AVTP_CRF_FIELD_PULL,
    AVTP_CRF_FIELD_BASE_FREQUENCY,
    AVTP_CRF_FIELD_CRF_DATA_LENGTH,
    AVTP_CRF_FIELD_TIMESTAMP_INTERVAL,

    /* Count number of fields for bound checks */
    AVTP_CRF_FIELD_MAX
} Avtp_CrfFields_t;

/**
 * This table maps all IEEE 1722 CRF header fields to a descriptor for version
 * 0. It is complete and in absolute coordinates; the alternative header fields
 * are absent in version 0.
 */
static const Avtp_FieldDescriptor_t Avtp_CrfFieldDescV0[AVTP_CRF_FIELD_MAX] = {
    [AVTP_CRF_FIELD_RESERVED1] = {.quadlet = 0, .offset = 0, .bits = 0},
    [AVTP_CRF_FIELD_SEQUENCE_NUM] = {.quadlet = 0, .offset = 0, .bits = 0},
    [AVTP_CRF_FIELD_PTP_GRANDMASTER_IDENTITY] = {.quadlet = 0, .offset = 0, .bits = 0},
    [AVTP_CRF_FIELD_SV] = {.quadlet = 0, .offset = 8, .bits = 1},
    [AVTP_CRF_FIELD_RESERVED] = {.quadlet = 0, .offset = 0, .bits = 0},
    [AVTP_CRF_FIELD_MR] = {.quadlet = 0, .offset = 12, .bits = 1},
    [AVTP_CRF_FIELD_R] = {.quadlet = 0, .offset = 13, .bits = 1},
    [AVTP_CRF_FIELD_FS] = {.quadlet = 0, .offset = 14, .bits = 1},
    [AVTP_CRF_FIELD_TU] = {.quadlet = 0, .offset = 15, .bits = 1},
    [AVTP_CRF_FIELD_SEQUENCE_NUM_LSB] = {.quadlet = 0, .offset = 16, .bits = 8},
    [AVTP_CRF_FIELD_TYPE] = {.quadlet = 0, .offset = 24, .bits = 8},
    [AVTP_CRF_FIELD_STREAM_ID] = {.quadlet = 1, .offset = 0, .bits = 64},
    [AVTP_CRF_FIELD_PULL] = {.quadlet = 3, .offset = 0, .bits = 3},
    [AVTP_CRF_FIELD_BASE_FREQUENCY] = {.quadlet = 3, .offset = 3, .bits = 29},
    [AVTP_CRF_FIELD_CRF_DATA_LENGTH] = {.quadlet = 4, .offset = 0, .bits = 16},
    [AVTP_CRF_FIELD_TIMESTAMP_INTERVAL] = {.quadlet = 4, .offset = 16, .bits = 16},
};

/**
 * This table maps all IEEE 1722 CRF header fields to a descriptor for version
 * 1. It is complete and in absolute coordinates; the alternative header fields
 * use the same positions as Avtp_AhFieldDescV1.
 */
static const Avtp_FieldDescriptor_t Avtp_CrfFieldDescV1[AVTP_CRF_FIELD_MAX] = {
    [AVTP_CRF_FIELD_RESERVED1] = {.quadlet = 0, .offset = 12, .bits = 20},
    [AVTP_CRF_FIELD_SEQUENCE_NUM] = {.quadlet = 1, .offset = 0, .bits = 32},
    [AVTP_CRF_FIELD_PTP_GRANDMASTER_IDENTITY] = {.quadlet = 2, .offset = 0, .bits = 64},
    [AVTP_CRF_FIELD_SV] = {.quadlet = 0, .offset = 8, .bits = 1},
    [AVTP_CRF_FIELD_RESERVED] = {.quadlet = 4, .offset = 0, .bits = 12},
    [AVTP_CRF_FIELD_MR] = {.quadlet = 4, .offset = 12, .bits = 1},
    [AVTP_CRF_FIELD_R] = {.quadlet = 4, .offset = 13, .bits = 1},
    [AVTP_CRF_FIELD_FS] = {.quadlet = 4, .offset = 14, .bits = 1},
    [AVTP_CRF_FIELD_TU] = {.quadlet = 4, .offset = 15, .bits = 1},
    [AVTP_CRF_FIELD_SEQUENCE_NUM_LSB] = {.quadlet = 4, .offset = 16, .bits = 8},
    [AVTP_CRF_FIELD_TYPE] = {.quadlet = 4, .offset = 24, .bits = 8},
    [AVTP_CRF_FIELD_STREAM_ID] = {.quadlet = 5, .offset = 0, .bits = 64},
    [AVTP_CRF_FIELD_PULL] = {.quadlet = 7, .offset = 0, .bits = 3},
    [AVTP_CRF_FIELD_BASE_FREQUENCY] = {.quadlet = 7, .offset = 3, .bits = 29},
    [AVTP_CRF_FIELD_CRF_DATA_LENGTH] = {.quadlet = 8, .offset = 0, .bits = 16},
    [AVTP_CRF_FIELD_TIMESTAMP_INTERVAL] = {.quadlet = 8, .offset = 16, .bits = 16},
};

/**
 * Returns the value of an AVTP CRF field as laid out by version 0. No version
 * dispatch is performed.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @param field Specifies the position of the data field to be read
 * @returns This function returns the value of the field.
 * @see Avtp_Crf_GetField
 */
OPEN1722_INLINE uint64_t Avtp_Crf_GetField_V0(const Avtp_Crf_t *const pdu, Avtp_CrfFields_t field)
{
    return Avtp_GetField(Avtp_CrfFieldDescV0, AVTP_CRF_FIELD_MAX, (const uint8_t *)pdu,
                         (uint8_t)field);
}

/**
 * Returns the value of an AVTP CRF field as laid out by version 1. No version
 * dispatch is performed.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @param field Specifies the position of the data field to be read
 * @returns This function returns the value of the field.
 * @see Avtp_Crf_GetField
 */
OPEN1722_INLINE uint64_t Avtp_Crf_GetField_V1(const Avtp_CrfV1_t *const pdu, Avtp_CrfFields_t field)
{
    return Avtp_GetField(Avtp_CrfFieldDescV1, AVTP_CRF_FIELD_MAX, (const uint8_t *)pdu,
                         (uint8_t)field);
}

/**
 * Returns the value of an AVTP CRF field, dispatching on the version field of
 * the PDU.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @param field Specifies the position of the data field to be read
 * @returns This function returns the value of the field.
 */
OPEN1722_INLINE uint64_t Avtp_Crf_GetField(const Avtp_Crf_t *const pdu, Avtp_CrfFields_t field)
{
    return Avtp_AlternativeHeader_GetVersion((const Avtp_AlternativeHeader_t *)pdu) ==
                   AVTP_VERSION_1
               ? Avtp_Crf_GetField_V1((const Avtp_CrfV1_t *)pdu, field)
               : Avtp_Crf_GetField_V0(pdu, field);
}

/**
 * Sets the value of an AVTP CRF field as laid out by version 0. No version
 * dispatch is performed.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @param field Specifies the position of the data field to be written
 * @param value The value to set.
 * @see Avtp_Crf_SetField
 */
OPEN1722_INLINE void Avtp_Crf_SetField_V0(Avtp_Crf_t *pdu, Avtp_CrfFields_t field, uint64_t value)
{
    Avtp_SetField(Avtp_CrfFieldDescV0, AVTP_CRF_FIELD_MAX, (uint8_t *)pdu, (uint8_t)field, value);
}

/**
 * Sets the value of an AVTP CRF field as laid out by version 1. No version
 * dispatch is performed.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @param field Specifies the position of the data field to be written
 * @param value The value to set.
 * @see Avtp_Crf_SetField
 */
OPEN1722_INLINE void Avtp_Crf_SetField_V1(Avtp_CrfV1_t *pdu, Avtp_CrfFields_t field, uint64_t value)
{
    Avtp_SetField(Avtp_CrfFieldDescV1, AVTP_CRF_FIELD_MAX, (uint8_t *)pdu, (uint8_t)field, value);
}

/**
 * Sets the value of an AVTP CRF field, dispatching on the version field of the
 * PDU.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @param field Specifies the position of the data field to be written
 * @param value The value to set.
 */
OPEN1722_INLINE void Avtp_Crf_SetField(Avtp_Crf_t *pdu, Avtp_CrfFields_t field, uint64_t value)
{
    if (Avtp_AlternativeHeader_GetVersion((const Avtp_AlternativeHeader_t *)pdu) ==
        AVTP_VERSION_1) {
        Avtp_Crf_SetField_V1((Avtp_CrfV1_t *)pdu, field, value);
    } else {
        Avtp_Crf_SetField_V0(pdu, field, value);
    }
}

/**
 * Returns the length of the version 0 CRF header in octets (20). The PDU
 * pointer is not read; it keeps the signature aligned with the
 * version-dispatched accessors.
 */
OPEN1722_INLINE uint8_t Avtp_Crf_GetHeaderLen_V0(const Avtp_Crf_t *const pdu)
{
    (void)pdu;
    return (uint8_t)AVTP_CRF_HEADER_LEN_V0;
}

/**
 * Returns the length of the version 1 CRF header in octets (36). The PDU
 * pointer is not read; it keeps the signature aligned with the
 * version-dispatched accessors.
 */
OPEN1722_INLINE uint8_t Avtp_Crf_GetHeaderLen_V1(const Avtp_CrfV1_t *const pdu)
{
    (void)pdu;
    return (uint8_t)AVTP_CRF_HEADER_LEN_V1;
}

/**
 * Returns the length of the CRF header in octets (20 or 36), dispatching on the
 * version field of the PDU.
 */
OPEN1722_INLINE uint8_t Avtp_Crf_GetHeaderLen(const Avtp_Crf_t *const pdu)
{
    return Avtp_AlternativeHeader_GetVersion((const Avtp_AlternativeHeader_t *)pdu) ==
                   AVTP_VERSION_1
               ? Avtp_Crf_GetHeaderLen_V1((const Avtp_CrfV1_t *)pdu)
               : Avtp_Crf_GetHeaderLen_V0(pdu);
}

/**
 * Return the value of the CRF SV field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @returns Value of the CRF SV field.
 */
OPEN1722_INLINE bool Avtp_Crf_IsSv(const Avtp_Crf_t *const pdu)
{
    return (bool)Avtp_Crf_GetField(pdu, AVTP_CRF_FIELD_SV);
}

/**
 * Return the value of the CRF MR field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @returns Value of the CRF MR field.
 */
OPEN1722_INLINE bool Avtp_Crf_IsMr(const Avtp_Crf_t *const pdu)
{
    return (bool)Avtp_Crf_GetField(pdu, AVTP_CRF_FIELD_MR);
}

/**
 * Return the value of the CRF FS field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @returns Value of the CRF FS field.
 */
OPEN1722_INLINE bool Avtp_Crf_IsFs(const Avtp_Crf_t *const pdu)
{
    return (bool)Avtp_Crf_GetField(pdu, AVTP_CRF_FIELD_FS);
}

/**
 * Return the value of the CRF TU field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @returns Value of the CRF TU field.
 */
OPEN1722_INLINE bool Avtp_Crf_IsTu(const Avtp_Crf_t *const pdu)
{
    return (bool)Avtp_Crf_GetField(pdu, AVTP_CRF_FIELD_TU);
}

/**
 * Return the effective CRF Sequence Number field as specified in the IEEE 1722
 * Specification. The field is the 8-bit sequence_num_lsb in version 0 and the
 * 32-bit sequence_num in version 1.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @returns Value of the CRF Sequence Number field.
 */
OPEN1722_INLINE uint32_t Avtp_Crf_GetSequenceNum(const Avtp_Crf_t *const pdu)
{
    return Avtp_AlternativeHeader_GetVersion((const Avtp_AlternativeHeader_t *)pdu) ==
                   AVTP_VERSION_1
               ? (uint32_t)Avtp_Crf_GetField_V1((const Avtp_CrfV1_t *)pdu,
                                                AVTP_CRF_FIELD_SEQUENCE_NUM)
               : (uint8_t)Avtp_Crf_GetField_V0(pdu, AVTP_CRF_FIELD_SEQUENCE_NUM_LSB);
}

/**
 * Return the value of the CRF sequence_num_lsb field. In version 1 it contains
 * a copy of the eight least significant bits of the sequence_num field in the
 * alternative header (CRF-25).
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @returns Value of the CRF sequence_num_lsb field.
 */
OPEN1722_INLINE uint8_t Avtp_Crf_GetSequenceNumLsb(const Avtp_Crf_t *const pdu)
{
    return (uint8_t)Avtp_Crf_GetField(pdu, AVTP_CRF_FIELD_SEQUENCE_NUM_LSB);
}

/**
 * Return the value of the CRF ptp_grandmaster_identity field. The field only
 * exists in version 1; version 0 returns 0.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @returns Value of the CRF ptp_grandmaster_identity field.
 */
OPEN1722_INLINE uint64_t Avtp_Crf_GetPtpGrandmasterIdentity(const Avtp_Crf_t *const pdu)
{
    return Avtp_Crf_GetField(pdu, AVTP_CRF_FIELD_PTP_GRANDMASTER_IDENTITY);
}

/**
 * Return the value of the CRF Type field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @returns Value of the CRF Type field.
 */
OPEN1722_INLINE Avtp_CrfType_t Avtp_Crf_GetType(const Avtp_Crf_t *const pdu)
{
    return (Avtp_CrfType_t)Avtp_Crf_GetField(pdu, AVTP_CRF_FIELD_TYPE);
}

/**
 * Return the value of the CRF Stream ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @returns Value of the CRF Stream ID field.
 */
OPEN1722_INLINE uint64_t Avtp_Crf_GetStreamId(const Avtp_Crf_t *const pdu)
{
    return Avtp_Crf_GetField(pdu, AVTP_CRF_FIELD_STREAM_ID);
}

/**
 * Return the value of the CRF Pull field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @returns Value of the CRF Pull field.
 */
OPEN1722_INLINE Avtp_CrfPull_t Avtp_Crf_GetPull(const Avtp_Crf_t *const pdu)
{
    return (Avtp_CrfPull_t)Avtp_Crf_GetField(pdu, AVTP_CRF_FIELD_PULL);
}

/**
 * Return the value of the CRF Base Frequency field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @returns Value of the CRF Base Frequency field.
 */
OPEN1722_INLINE uint32_t Avtp_Crf_GetBaseFrequency(const Avtp_Crf_t *const pdu)
{
    return (uint32_t)Avtp_Crf_GetField(pdu, AVTP_CRF_FIELD_BASE_FREQUENCY);
}

/**
 * Return the value of the CRF Data Length field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @returns Value of the CRF Data Length field.
 */
OPEN1722_INLINE uint16_t Avtp_Crf_GetCrfDataLength(const Avtp_Crf_t *const pdu)
{
    return (uint16_t)Avtp_Crf_GetField(pdu, AVTP_CRF_FIELD_CRF_DATA_LENGTH);
}

/**
 * Return the value of the CRF Timestamp Interval field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @returns Value of the CRF Timestamp Interval field.
 */
OPEN1722_INLINE uint16_t Avtp_Crf_GetTimestampInterval(const Avtp_Crf_t *const pdu)
{
    return (uint16_t)Avtp_Crf_GetField(pdu, AVTP_CRF_FIELD_TIMESTAMP_INTERVAL);
}

/**
 * Set the SV bit in a CRF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @param sv Value to set the CRF SV field to.
 */
OPEN1722_INLINE void Avtp_Crf_SetSv(Avtp_Crf_t *pdu, bool sv)
{
    Avtp_Crf_SetField(pdu, AVTP_CRF_FIELD_SV, sv);
}

/**
 * Set the MR bit in a CRF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @param mr Value to set the CRF MR field to.
 */
OPEN1722_INLINE void Avtp_Crf_SetMr(Avtp_Crf_t *pdu, bool mr)
{
    Avtp_Crf_SetField(pdu, AVTP_CRF_FIELD_MR, mr);
}

/**
 * Set the FS bit in a CRF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @param fs Value to set the CRF FS field to.
 */
OPEN1722_INLINE void Avtp_Crf_SetFs(Avtp_Crf_t *pdu, bool fs)
{
    Avtp_Crf_SetField(pdu, AVTP_CRF_FIELD_FS, fs);
}

/**
 * Set the TU bit in a CRF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @param tu Value to set the CRF TU field to.
 */
OPEN1722_INLINE void Avtp_Crf_SetTu(Avtp_Crf_t *pdu, bool tu)
{
    Avtp_Crf_SetField(pdu, AVTP_CRF_FIELD_TU, tu);
}

/**
 * Set the effective CRF Sequence Number field as specified in the IEEE 1722
 * Specification. In version 1 the eight least significant bits are also written
 * to the sequence_num_lsb copy (CRF-25); in version 0 they are the sequence
 * number itself.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @param value Value to set the CRF Sequence Number field to.
 */
OPEN1722_INLINE void Avtp_Crf_SetSequenceNum(Avtp_Crf_t *pdu, uint32_t value)
{
    if (Avtp_AlternativeHeader_GetVersion((const Avtp_AlternativeHeader_t *)pdu) ==
        AVTP_VERSION_1) {
        Avtp_Crf_SetField_V1((Avtp_CrfV1_t *)pdu, AVTP_CRF_FIELD_SEQUENCE_NUM, value);
        Avtp_Crf_SetField_V1((Avtp_CrfV1_t *)pdu, AVTP_CRF_FIELD_SEQUENCE_NUM_LSB,
                             (uint8_t)(value & 0xFFU));
    } else {
        Avtp_Crf_SetField_V0(pdu, AVTP_CRF_FIELD_SEQUENCE_NUM_LSB, (uint8_t)(value & 0xFFU));
    }
}

/**
 * Set the value of the CRF ptp_grandmaster_identity field. The field only
 * exists in version 1; on version 0 this is a no-op.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @param value Value to set the CRF ptp_grandmaster_identity field to.
 */
OPEN1722_INLINE void Avtp_Crf_SetPtpGrandmasterIdentity(Avtp_Crf_t *pdu, uint64_t value)
{
    Avtp_Crf_SetField(pdu, AVTP_CRF_FIELD_PTP_GRANDMASTER_IDENTITY, value);
}

/**
 * Set the value of the CRF Type field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @param value Value to set the CRF Type field to.
 */
OPEN1722_INLINE void Avtp_Crf_SetType(Avtp_Crf_t *pdu, Avtp_CrfType_t value)
{
    Avtp_Crf_SetField(pdu, AVTP_CRF_FIELD_TYPE, (uint64_t)value);
}

/**
 * Set the value of the CRF Stream ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @param value Value to set the CRF Stream ID field to.
 */
OPEN1722_INLINE void Avtp_Crf_SetStreamId(Avtp_Crf_t *pdu, uint64_t value)
{
    Avtp_Crf_SetField(pdu, AVTP_CRF_FIELD_STREAM_ID, value);
}

/**
 * Set the value of the CRF Pull field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @param value Value to set the CRF Pull field to.
 */
OPEN1722_INLINE void Avtp_Crf_SetPull(Avtp_Crf_t *pdu, Avtp_CrfPull_t value)
{
    Avtp_Crf_SetField(pdu, AVTP_CRF_FIELD_PULL, (uint64_t)value);
}

/**
 * Set the value of the CRF Base Frequency field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @param value Value to set the CRF Base Frequency field to.
 */
OPEN1722_INLINE void Avtp_Crf_SetBaseFrequency(Avtp_Crf_t *pdu, uint32_t value)
{
    Avtp_Crf_SetField(pdu, AVTP_CRF_FIELD_BASE_FREQUENCY, value);
}

/**
 * Set the value of the CRF Data Length field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @param value Value to set the CRF Data Length field to.
 */
OPEN1722_INLINE void Avtp_Crf_SetCrfDataLength(Avtp_Crf_t *pdu, uint16_t value)
{
    Avtp_Crf_SetField(pdu, AVTP_CRF_FIELD_CRF_DATA_LENGTH, value);
}

/**
 * Set the value of the CRF Timestamp Interval field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @param value Value to set the CRF Timestamp Interval field to.
 */
OPEN1722_INLINE void Avtp_Crf_SetTimestampInterval(Avtp_Crf_t *pdu, uint16_t value)
{
    Avtp_Crf_SetField(pdu, AVTP_CRF_FIELD_TIMESTAMP_INTERVAL, value);
}

/**
 * Returns a pointer to the CRF data of a version 0 CRF frame.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @return Pointer to CRF data
 * @see Avtp_Crf_GetPayload
 */
OPEN1722_INLINE const uint8_t *Avtp_Crf_GetPayload_V0(const Avtp_Crf_t *const pdu)
{
    return (const uint8_t *)pdu + AVTP_CRF_HEADER_LEN_V0;
}

/**
 * Returns a pointer to the CRF data of a version 1 CRF frame.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @return Pointer to CRF data
 * @see Avtp_Crf_GetPayload
 */
OPEN1722_INLINE const uint8_t *Avtp_Crf_GetPayload_V1(const Avtp_CrfV1_t *const pdu)
{
    return (const uint8_t *)pdu + AVTP_CRF_HEADER_LEN_V1;
}

/**
 * Returns pointer to the CRF data of a CRF frame. The CRF data starts after the
 * version-dependent CRF header.
 *
 * The CRF data contains the timestamps of the stream. Each timestamp is
 * 8 octets long.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @return Pointer to CRF data
 */
OPEN1722_INLINE const uint8_t *Avtp_Crf_GetPayload(const Avtp_Crf_t *const pdu)
{
    return Avtp_AlternativeHeader_GetVersion((const Avtp_AlternativeHeader_t *)pdu) ==
                   AVTP_VERSION_1
               ? Avtp_Crf_GetPayload_V1((const Avtp_CrfV1_t *)pdu)
               : Avtp_Crf_GetPayload_V0(pdu);
}

/**
 * Sets the CRF data of a version 0 CRF frame.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload
 * @see Avtp_Crf_SetPayload
 */
OPEN1722_INLINE void Avtp_Crf_SetPayload_V0(Avtp_Crf_t *pdu, uint8_t *payload,
                                            uint16_t payload_length)
{
    memcpy((uint8_t *)pdu + AVTP_CRF_HEADER_LEN_V0, payload, payload_length);
}

/**
 * Sets the CRF data of a version 1 CRF frame.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload
 * @see Avtp_Crf_SetPayload
 */
OPEN1722_INLINE void Avtp_Crf_SetPayload_V1(Avtp_CrfV1_t *pdu, uint8_t *payload,
                                            uint16_t payload_length)
{
    memcpy((uint8_t *)pdu + AVTP_CRF_HEADER_LEN_V1, payload, payload_length);
}

/**
 * Sets the CRF data of a CRF frame.
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload
 */
OPEN1722_INLINE void Avtp_Crf_SetPayload(Avtp_Crf_t *pdu, uint8_t *payload, uint16_t payload_length)
{
    if (Avtp_AlternativeHeader_GetVersion((const Avtp_AlternativeHeader_t *)pdu) ==
        AVTP_VERSION_1) {
        Avtp_Crf_SetPayload_V1((Avtp_CrfV1_t *)pdu, payload, payload_length);
    } else {
        Avtp_Crf_SetPayload_V0(pdu, payload, payload_length);
    }
}

/**
 * Initializes a version 0 CRF PDU as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of a 1722 CRF PDU.
 */
OPEN1722_INLINE void Avtp_Crf_Init(Avtp_Crf_t *pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_Crf_t));
        Avtp_CommonHeader_SetSubtype((Avtp_CommonHeader_t *)pdu, AVTP_SUBTYPE_CRF);
        Avtp_Crf_SetSv(pdu, true);
    }
}

/**
 * Initializes a version 1 CRF PDU. The caller must provide a buffer of at least
 * AVTP_CRF_HEADER_LEN_V1 octets.
 *
 * @param pdu Pointer to the first bit of a 1722 CRF PDU.
 */
OPEN1722_INLINE void Avtp_Crf_InitV1(Avtp_CrfV1_t *pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_CrfV1_t));
        Avtp_CommonHeader_SetSubtype((Avtp_CommonHeader_t *)pdu, AVTP_SUBTYPE_CRF);
        Avtp_CommonHeader_SetVersion((Avtp_CommonHeader_t *)pdu, AVTP_VERSION_1);
        Avtp_Crf_SetSv((Avtp_Crf_t *)pdu, true);
    }
}

/**
 * Checks if the CRF frame is valid by checking:
 *     1) that the subtype is CRF and the version is supported,
 *     2) that the version-dependent header fits into the buffer,
 *     3) that crf_data_length is a non-zero multiple of 8 and fits into the
 *        buffer.
 *
 * The crf_data_length field contains the length (in octets) of the crf_data
 * field (IEEE 1722-2025, 10.4.11), so the whole AVTPDU must fit into bufferSize.
 * The crf_data field contains one or more 8-octet timestamps, so crf_data_length
 * shall be a non-zero multiple of 8 (IEEE 1722-2025, 10.4.11).
 *
 * @param pdu Pointer to the first bit of an 1722 CRF PDU.
 * @param bufferSize Size of the buffer containing the CRF frame.
 * @return true if the CRF frame is valid, false otherwise.
 */
OPEN1722_INLINE bool Avtp_Crf_IsValid(const Avtp_Crf_t *const pdu, size_t bufferSize)
{
    if (pdu == NULL) {
        return false;
    }

    if (Avtp_CommonHeader_GetSubtype((const Avtp_CommonHeader_t *)pdu) != AVTP_SUBTYPE_CRF) {
        return false;
    }

    uint8_t version = Avtp_AlternativeHeader_GetVersion((const Avtp_AlternativeHeader_t *)pdu);
    if (!Avtp_Version_IsSupported(AVTP_CRF_SUPPORTED_VERSIONS, version)) {
        return false;
    }

    size_t headerLen = Avtp_Crf_GetHeaderLen(pdu);
    if (bufferSize < headerLen) {
        return false;
    }

    uint16_t crf_data_length = Avtp_Crf_GetCrfDataLength(pdu);

    if (crf_data_length == 0 || (crf_data_length % 8) != 0) {
        return false;
    }

    if (headerLen + (size_t)crf_data_length > bufferSize) {
        return false;
    }

    return true;
}

/*
 * Version-typed named accessors. These select the field layout for one
 * explicit version and never read the version field; the version-dispatched
 * accessors above delegate to them. Alternative header fields delegate to the
 * shared Avtp_AlternativeHeader_* variants. See each version-dispatched
 * accessor for the full field documentation.
 */

/**
 * Version 0 variant of Avtp_Crf_IsSv().
 * @see Avtp_Crf_IsSv
 */
OPEN1722_INLINE bool Avtp_Crf_IsSv_V0(const Avtp_Crf_t *const pdu)
{
    return (bool)Avtp_Crf_GetField_V0(pdu, AVTP_CRF_FIELD_SV);
}

/**
 * Version 1 variant of Avtp_Crf_IsSv().
 * @see Avtp_Crf_IsSv
 */
OPEN1722_INLINE bool Avtp_Crf_IsSv_V1(const Avtp_CrfV1_t *const pdu)
{
    return (bool)Avtp_Crf_GetField_V1(pdu, AVTP_CRF_FIELD_SV);
}

/**
 * Version 0 variant of Avtp_Crf_IsMr().
 * @see Avtp_Crf_IsMr
 */
OPEN1722_INLINE bool Avtp_Crf_IsMr_V0(const Avtp_Crf_t *const pdu)
{
    return (bool)Avtp_Crf_GetField_V0(pdu, AVTP_CRF_FIELD_MR);
}

/**
 * Version 1 variant of Avtp_Crf_IsMr().
 * @see Avtp_Crf_IsMr
 */
OPEN1722_INLINE bool Avtp_Crf_IsMr_V1(const Avtp_CrfV1_t *const pdu)
{
    return (bool)Avtp_Crf_GetField_V1(pdu, AVTP_CRF_FIELD_MR);
}

/**
 * Version 0 variant of Avtp_Crf_IsFs().
 * @see Avtp_Crf_IsFs
 */
OPEN1722_INLINE bool Avtp_Crf_IsFs_V0(const Avtp_Crf_t *const pdu)
{
    return (bool)Avtp_Crf_GetField_V0(pdu, AVTP_CRF_FIELD_FS);
}

/**
 * Version 1 variant of Avtp_Crf_IsFs().
 * @see Avtp_Crf_IsFs
 */
OPEN1722_INLINE bool Avtp_Crf_IsFs_V1(const Avtp_CrfV1_t *const pdu)
{
    return (bool)Avtp_Crf_GetField_V1(pdu, AVTP_CRF_FIELD_FS);
}

/**
 * Version 0 variant of Avtp_Crf_IsTu().
 * @see Avtp_Crf_IsTu
 */
OPEN1722_INLINE bool Avtp_Crf_IsTu_V0(const Avtp_Crf_t *const pdu)
{
    return (bool)Avtp_Crf_GetField_V0(pdu, AVTP_CRF_FIELD_TU);
}

/**
 * Version 1 variant of Avtp_Crf_IsTu().
 * @see Avtp_Crf_IsTu
 */
OPEN1722_INLINE bool Avtp_Crf_IsTu_V1(const Avtp_CrfV1_t *const pdu)
{
    return (bool)Avtp_Crf_GetField_V1(pdu, AVTP_CRF_FIELD_TU);
}

/**
 * Version 0 variant of Avtp_Crf_GetSequenceNum(). In version 0 the sequence
 * number is the 8-bit sequence_num_lsb field.
 * @see Avtp_Crf_GetSequenceNum
 */
OPEN1722_INLINE uint32_t Avtp_Crf_GetSequenceNum_V0(const Avtp_Crf_t *const pdu)
{
    return (uint32_t)Avtp_Crf_GetField_V0(pdu, AVTP_CRF_FIELD_SEQUENCE_NUM_LSB);
}

/**
 * Version 1 variant of Avtp_Crf_GetSequenceNum().
 * @see Avtp_Crf_GetSequenceNum
 */
OPEN1722_INLINE uint32_t Avtp_Crf_GetSequenceNum_V1(const Avtp_CrfV1_t *const pdu)
{
    return (uint32_t)Avtp_Crf_GetField_V1(pdu, AVTP_CRF_FIELD_SEQUENCE_NUM);
}

/**
 * Version 0 variant of Avtp_Crf_GetSequenceNumLsb().
 * @see Avtp_Crf_GetSequenceNumLsb
 */
OPEN1722_INLINE uint8_t Avtp_Crf_GetSequenceNumLsb_V0(const Avtp_Crf_t *const pdu)
{
    return (uint8_t)Avtp_Crf_GetField_V0(pdu, AVTP_CRF_FIELD_SEQUENCE_NUM_LSB);
}

/**
 * Version 1 variant of Avtp_Crf_GetSequenceNumLsb().
 * @see Avtp_Crf_GetSequenceNumLsb
 */
OPEN1722_INLINE uint8_t Avtp_Crf_GetSequenceNumLsb_V1(const Avtp_CrfV1_t *const pdu)
{
    return (uint8_t)Avtp_Crf_GetField_V1(pdu, AVTP_CRF_FIELD_SEQUENCE_NUM_LSB);
}

/**
 * Version 0 variant of Avtp_Crf_GetPtpGrandmasterIdentity(). The field is
 * absent from version 0, so this always returns 0.
 * @see Avtp_Crf_GetPtpGrandmasterIdentity
 */
OPEN1722_INLINE uint64_t Avtp_Crf_GetPtpGrandmasterIdentity_V0(const Avtp_Crf_t *const pdu)
{
    return Avtp_AlternativeHeader_GetPtpGrandmasterIdentity_V0(
        (const Avtp_AlternativeHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Crf_GetPtpGrandmasterIdentity().
 * @see Avtp_Crf_GetPtpGrandmasterIdentity
 */
OPEN1722_INLINE uint64_t Avtp_Crf_GetPtpGrandmasterIdentity_V1(const Avtp_CrfV1_t *const pdu)
{
    return Avtp_AlternativeHeader_GetPtpGrandmasterIdentity_V1(
        (const Avtp_AlternativeHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Crf_GetType().
 * @see Avtp_Crf_GetType
 */
OPEN1722_INLINE Avtp_CrfType_t Avtp_Crf_GetType_V0(const Avtp_Crf_t *const pdu)
{
    return (Avtp_CrfType_t)Avtp_Crf_GetField_V0(pdu, AVTP_CRF_FIELD_TYPE);
}

/**
 * Version 1 variant of Avtp_Crf_GetType().
 * @see Avtp_Crf_GetType
 */
OPEN1722_INLINE Avtp_CrfType_t Avtp_Crf_GetType_V1(const Avtp_CrfV1_t *const pdu)
{
    return (Avtp_CrfType_t)Avtp_Crf_GetField_V1(pdu, AVTP_CRF_FIELD_TYPE);
}

/**
 * Version 0 variant of Avtp_Crf_GetStreamId().
 * @see Avtp_Crf_GetStreamId
 */
OPEN1722_INLINE uint64_t Avtp_Crf_GetStreamId_V0(const Avtp_Crf_t *const pdu)
{
    return Avtp_Crf_GetField_V0(pdu, AVTP_CRF_FIELD_STREAM_ID);
}

/**
 * Version 1 variant of Avtp_Crf_GetStreamId().
 * @see Avtp_Crf_GetStreamId
 */
OPEN1722_INLINE uint64_t Avtp_Crf_GetStreamId_V1(const Avtp_CrfV1_t *const pdu)
{
    return Avtp_Crf_GetField_V1(pdu, AVTP_CRF_FIELD_STREAM_ID);
}

/**
 * Version 0 variant of Avtp_Crf_GetPull().
 * @see Avtp_Crf_GetPull
 */
OPEN1722_INLINE Avtp_CrfPull_t Avtp_Crf_GetPull_V0(const Avtp_Crf_t *const pdu)
{
    return (Avtp_CrfPull_t)Avtp_Crf_GetField_V0(pdu, AVTP_CRF_FIELD_PULL);
}

/**
 * Version 1 variant of Avtp_Crf_GetPull().
 * @see Avtp_Crf_GetPull
 */
OPEN1722_INLINE Avtp_CrfPull_t Avtp_Crf_GetPull_V1(const Avtp_CrfV1_t *const pdu)
{
    return (Avtp_CrfPull_t)Avtp_Crf_GetField_V1(pdu, AVTP_CRF_FIELD_PULL);
}

/**
 * Version 0 variant of Avtp_Crf_GetBaseFrequency().
 * @see Avtp_Crf_GetBaseFrequency
 */
OPEN1722_INLINE uint32_t Avtp_Crf_GetBaseFrequency_V0(const Avtp_Crf_t *const pdu)
{
    return (uint32_t)Avtp_Crf_GetField_V0(pdu, AVTP_CRF_FIELD_BASE_FREQUENCY);
}

/**
 * Version 1 variant of Avtp_Crf_GetBaseFrequency().
 * @see Avtp_Crf_GetBaseFrequency
 */
OPEN1722_INLINE uint32_t Avtp_Crf_GetBaseFrequency_V1(const Avtp_CrfV1_t *const pdu)
{
    return (uint32_t)Avtp_Crf_GetField_V1(pdu, AVTP_CRF_FIELD_BASE_FREQUENCY);
}

/**
 * Version 0 variant of Avtp_Crf_GetCrfDataLength().
 * @see Avtp_Crf_GetCrfDataLength
 */
OPEN1722_INLINE uint16_t Avtp_Crf_GetCrfDataLength_V0(const Avtp_Crf_t *const pdu)
{
    return (uint16_t)Avtp_Crf_GetField_V0(pdu, AVTP_CRF_FIELD_CRF_DATA_LENGTH);
}

/**
 * Version 1 variant of Avtp_Crf_GetCrfDataLength().
 * @see Avtp_Crf_GetCrfDataLength
 */
OPEN1722_INLINE uint16_t Avtp_Crf_GetCrfDataLength_V1(const Avtp_CrfV1_t *const pdu)
{
    return (uint16_t)Avtp_Crf_GetField_V1(pdu, AVTP_CRF_FIELD_CRF_DATA_LENGTH);
}

/**
 * Version 0 variant of Avtp_Crf_GetTimestampInterval().
 * @see Avtp_Crf_GetTimestampInterval
 */
OPEN1722_INLINE uint16_t Avtp_Crf_GetTimestampInterval_V0(const Avtp_Crf_t *const pdu)
{
    return (uint16_t)Avtp_Crf_GetField_V0(pdu, AVTP_CRF_FIELD_TIMESTAMP_INTERVAL);
}

/**
 * Version 1 variant of Avtp_Crf_GetTimestampInterval().
 * @see Avtp_Crf_GetTimestampInterval
 */
OPEN1722_INLINE uint16_t Avtp_Crf_GetTimestampInterval_V1(const Avtp_CrfV1_t *const pdu)
{
    return (uint16_t)Avtp_Crf_GetField_V1(pdu, AVTP_CRF_FIELD_TIMESTAMP_INTERVAL);
}

/**
 * Version 0 variant of Avtp_Crf_SetSv().
 * @see Avtp_Crf_SetSv
 */
OPEN1722_INLINE void Avtp_Crf_SetSv_V0(Avtp_Crf_t *pdu, bool sv)
{
    Avtp_Crf_SetField_V0(pdu, AVTP_CRF_FIELD_SV, sv);
}

/**
 * Version 1 variant of Avtp_Crf_SetSv().
 * @see Avtp_Crf_SetSv
 */
OPEN1722_INLINE void Avtp_Crf_SetSv_V1(Avtp_CrfV1_t *pdu, bool sv)
{
    Avtp_Crf_SetField_V1(pdu, AVTP_CRF_FIELD_SV, sv);
}

/**
 * Version 0 variant of Avtp_Crf_SetMr().
 * @see Avtp_Crf_SetMr
 */
OPEN1722_INLINE void Avtp_Crf_SetMr_V0(Avtp_Crf_t *pdu, bool mr)
{
    Avtp_Crf_SetField_V0(pdu, AVTP_CRF_FIELD_MR, mr);
}

/**
 * Version 1 variant of Avtp_Crf_SetMr().
 * @see Avtp_Crf_SetMr
 */
OPEN1722_INLINE void Avtp_Crf_SetMr_V1(Avtp_CrfV1_t *pdu, bool mr)
{
    Avtp_Crf_SetField_V1(pdu, AVTP_CRF_FIELD_MR, mr);
}

/**
 * Version 0 variant of Avtp_Crf_SetFs().
 * @see Avtp_Crf_SetFs
 */
OPEN1722_INLINE void Avtp_Crf_SetFs_V0(Avtp_Crf_t *pdu, bool fs)
{
    Avtp_Crf_SetField_V0(pdu, AVTP_CRF_FIELD_FS, fs);
}

/**
 * Version 1 variant of Avtp_Crf_SetFs().
 * @see Avtp_Crf_SetFs
 */
OPEN1722_INLINE void Avtp_Crf_SetFs_V1(Avtp_CrfV1_t *pdu, bool fs)
{
    Avtp_Crf_SetField_V1(pdu, AVTP_CRF_FIELD_FS, fs);
}

/**
 * Version 0 variant of Avtp_Crf_SetTu().
 * @see Avtp_Crf_SetTu
 */
OPEN1722_INLINE void Avtp_Crf_SetTu_V0(Avtp_Crf_t *pdu, bool tu)
{
    Avtp_Crf_SetField_V0(pdu, AVTP_CRF_FIELD_TU, tu);
}

/**
 * Version 1 variant of Avtp_Crf_SetTu().
 * @see Avtp_Crf_SetTu
 */
OPEN1722_INLINE void Avtp_Crf_SetTu_V1(Avtp_CrfV1_t *pdu, bool tu)
{
    Avtp_Crf_SetField_V1(pdu, AVTP_CRF_FIELD_TU, tu);
}

/**
 * Version 0 variant of Avtp_Crf_SetSequenceNum(). The value is truncated to the
 * 8-bit version 0 sequence_num_lsb field.
 * @see Avtp_Crf_SetSequenceNum
 */
OPEN1722_INLINE void Avtp_Crf_SetSequenceNum_V0(Avtp_Crf_t *pdu, uint32_t value)
{
    Avtp_Crf_SetField_V0(pdu, AVTP_CRF_FIELD_SEQUENCE_NUM_LSB, (uint8_t)(value & 0xFFU));
}

/**
 * Version 1 variant of Avtp_Crf_SetSequenceNum(). The eight least significant
 * bits are also written to the sequence_num_lsb copy (CRF-25).
 * @see Avtp_Crf_SetSequenceNum
 */
OPEN1722_INLINE void Avtp_Crf_SetSequenceNum_V1(Avtp_CrfV1_t *pdu, uint32_t value)
{
    Avtp_Crf_SetField_V1(pdu, AVTP_CRF_FIELD_SEQUENCE_NUM, value);
    Avtp_Crf_SetField_V1(pdu, AVTP_CRF_FIELD_SEQUENCE_NUM_LSB, (uint8_t)(value & 0xFFU));
}

/**
 * Version 0 variant of Avtp_Crf_SetPtpGrandmasterIdentity(). The field is
 * absent from version 0, so this is a no-op.
 * @see Avtp_Crf_SetPtpGrandmasterIdentity
 */
OPEN1722_INLINE void Avtp_Crf_SetPtpGrandmasterIdentity_V0(Avtp_Crf_t *pdu, uint64_t value)
{
    Avtp_AlternativeHeader_SetPtpGrandmasterIdentity_V0((Avtp_AlternativeHeader_t *)pdu, value);
}

/**
 * Version 1 variant of Avtp_Crf_SetPtpGrandmasterIdentity().
 * @see Avtp_Crf_SetPtpGrandmasterIdentity
 */
OPEN1722_INLINE void Avtp_Crf_SetPtpGrandmasterIdentity_V1(Avtp_CrfV1_t *pdu, uint64_t value)
{
    Avtp_AlternativeHeader_SetPtpGrandmasterIdentity_V1((Avtp_AlternativeHeader_t *)pdu, value);
}

/**
 * Version 0 variant of Avtp_Crf_SetType().
 * @see Avtp_Crf_SetType
 */
OPEN1722_INLINE void Avtp_Crf_SetType_V0(Avtp_Crf_t *pdu, Avtp_CrfType_t value)
{
    Avtp_Crf_SetField_V0(pdu, AVTP_CRF_FIELD_TYPE, (uint64_t)value);
}

/**
 * Version 1 variant of Avtp_Crf_SetType().
 * @see Avtp_Crf_SetType
 */
OPEN1722_INLINE void Avtp_Crf_SetType_V1(Avtp_CrfV1_t *pdu, Avtp_CrfType_t value)
{
    Avtp_Crf_SetField_V1(pdu, AVTP_CRF_FIELD_TYPE, (uint64_t)value);
}

/**
 * Version 0 variant of Avtp_Crf_SetStreamId().
 * @see Avtp_Crf_SetStreamId
 */
OPEN1722_INLINE void Avtp_Crf_SetStreamId_V0(Avtp_Crf_t *pdu, uint64_t value)
{
    Avtp_Crf_SetField_V0(pdu, AVTP_CRF_FIELD_STREAM_ID, value);
}

/**
 * Version 1 variant of Avtp_Crf_SetStreamId().
 * @see Avtp_Crf_SetStreamId
 */
OPEN1722_INLINE void Avtp_Crf_SetStreamId_V1(Avtp_CrfV1_t *pdu, uint64_t value)
{
    Avtp_Crf_SetField_V1(pdu, AVTP_CRF_FIELD_STREAM_ID, value);
}

/**
 * Version 0 variant of Avtp_Crf_SetPull().
 * @see Avtp_Crf_SetPull
 */
OPEN1722_INLINE void Avtp_Crf_SetPull_V0(Avtp_Crf_t *pdu, Avtp_CrfPull_t value)
{
    Avtp_Crf_SetField_V0(pdu, AVTP_CRF_FIELD_PULL, (uint64_t)value);
}

/**
 * Version 1 variant of Avtp_Crf_SetPull().
 * @see Avtp_Crf_SetPull
 */
OPEN1722_INLINE void Avtp_Crf_SetPull_V1(Avtp_CrfV1_t *pdu, Avtp_CrfPull_t value)
{
    Avtp_Crf_SetField_V1(pdu, AVTP_CRF_FIELD_PULL, (uint64_t)value);
}

/**
 * Version 0 variant of Avtp_Crf_SetBaseFrequency().
 * @see Avtp_Crf_SetBaseFrequency
 */
OPEN1722_INLINE void Avtp_Crf_SetBaseFrequency_V0(Avtp_Crf_t *pdu, uint32_t value)
{
    Avtp_Crf_SetField_V0(pdu, AVTP_CRF_FIELD_BASE_FREQUENCY, value);
}

/**
 * Version 1 variant of Avtp_Crf_SetBaseFrequency().
 * @see Avtp_Crf_SetBaseFrequency
 */
OPEN1722_INLINE void Avtp_Crf_SetBaseFrequency_V1(Avtp_CrfV1_t *pdu, uint32_t value)
{
    Avtp_Crf_SetField_V1(pdu, AVTP_CRF_FIELD_BASE_FREQUENCY, value);
}

/**
 * Version 0 variant of Avtp_Crf_SetCrfDataLength().
 * @see Avtp_Crf_SetCrfDataLength
 */
OPEN1722_INLINE void Avtp_Crf_SetCrfDataLength_V0(Avtp_Crf_t *pdu, uint16_t value)
{
    Avtp_Crf_SetField_V0(pdu, AVTP_CRF_FIELD_CRF_DATA_LENGTH, value);
}

/**
 * Version 1 variant of Avtp_Crf_SetCrfDataLength().
 * @see Avtp_Crf_SetCrfDataLength
 */
OPEN1722_INLINE void Avtp_Crf_SetCrfDataLength_V1(Avtp_CrfV1_t *pdu, uint16_t value)
{
    Avtp_Crf_SetField_V1(pdu, AVTP_CRF_FIELD_CRF_DATA_LENGTH, value);
}

/**
 * Version 0 variant of Avtp_Crf_SetTimestampInterval().
 * @see Avtp_Crf_SetTimestampInterval
 */
OPEN1722_INLINE void Avtp_Crf_SetTimestampInterval_V0(Avtp_Crf_t *pdu, uint16_t value)
{
    Avtp_Crf_SetField_V0(pdu, AVTP_CRF_FIELD_TIMESTAMP_INTERVAL, value);
}

/**
 * Version 1 variant of Avtp_Crf_SetTimestampInterval().
 * @see Avtp_Crf_SetTimestampInterval
 */
OPEN1722_INLINE void Avtp_Crf_SetTimestampInterval_V1(Avtp_CrfV1_t *pdu, uint16_t value)
{
    Avtp_Crf_SetField_V1(pdu, AVTP_CRF_FIELD_TIMESTAMP_INTERVAL, value);
}

#ifdef __cplusplus
}
#endif
