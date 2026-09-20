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
 * This file contains the fields descriptions of the IEEE 1722 AAF common stream PDUs and
 * functions to invoke corresponding parser and deparser.
 *
 * AAF uses the AVTPDU common stream header (4.7.4) and declares a complete
 * descriptor table per version in absolute coordinates: the common stream
 * header fields reuse the positions from CommonStreamHeader.h and the
 * AAF-specific fields are added by this module. A consistency test keeps the
 * common entries aligned with the common stream header module.
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
#include "avtp/CommonStreamHeader.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AVTP_AAF_HEADER_LEN_V0 AVTPDU_CSH_LEN_V0 /* 24 */
#define AVTP_AAF_HEADER_LEN_V1 AVTPDU_CSH_LEN_V1 /* 40 */
/* Kept for compatibility: the version 0 header length. */
#define AVTP_AAF_HEADER_LEN AVTP_AAF_HEADER_LEN_V0

/* AAF supports both versions of the common stream header (Table 7). */
#define AVTP_AAF_SUPPORTED_VERSIONS ((1u << AVTP_VERSION_0) | (1u << AVTP_VERSION_1))

typedef struct {
    uint8_t header[AVTP_AAF_HEADER_LEN_V0];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_Aaf_t;

typedef struct {
    uint8_t header[AVTP_AAF_HEADER_LEN_V1];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_AafV1_t;

/**
 * AAF 'format' field values (IEEE 1722-2025, Table 10). Values 0x06-0xFF are
 * reserved.
 */
typedef enum {
    AVTP_AAF_FORMAT_USER = 0x0,
    AVTP_AAF_FORMAT_FLOAT_32BIT = 0x1,
    AVTP_AAF_FORMAT_INT_32BIT = 0x2,
    AVTP_AAF_FORMAT_INT_24BIT = 0x3,
    AVTP_AAF_FORMAT_INT_16BIT = 0x4,
    AVTP_AAF_FORMAT_AES3_32BIT = 0x5,
} Avtp_AafFormat_t;

/**
 * AAF 'sp' (sparse timestamp) field values.
 */
typedef enum {
    AVTP_AAF_SP_NORMAL = 0x0,
    AVTP_AAF_SP_SPARSE = 0x1,
} Avtp_AafSp_t;

typedef enum {

    /* Common AVTP stream header fields */
    AVTP_AAF_FIELD_SV = 0,
    AVTP_AAF_FIELD_MR,
    AVTP_AAF_FIELD_FSD,
    AVTP_AAF_FIELD_TV,
    AVTP_AAF_FIELD_SEQUENCE_NUM,
    AVTP_AAF_FIELD_FSD0,
    AVTP_AAF_FIELD_FSD1,
    AVTP_AAF_FIELD_TU,
    AVTP_AAF_FIELD_STREAM_ID,
    AVTP_AAF_FIELD_AVTP_TIMESTAMP,
    AVTP_AAF_FIELD_PTP_GRANDMASTER_IDENTITY,
    AVTP_AAF_FIELD_STREAM_DATA_LENGTH,

    /* AAF format-specific fields */
    AVTP_AAF_FIELD_FORMAT,
    AVTP_AAF_FIELD_AAF_FORMAT_SPECIFIC_DATA_1,
    AVTP_AAF_FIELD_AFSD,
    AVTP_AAF_FIELD_SP,
    AVTP_AAF_FIELD_EVT,
    AVTP_AAF_FIELD_AAF_FORMAT_SPECIFIC_DATA_2,

    /* Count number of fields for bound checks */
    AVTP_AAF_FIELD_MAX
} Avtp_AafFields_t;

/**
 * This table maps all IEEE 1722 AAF header fields to a descriptor for version 0.
 * It is complete and in absolute coordinates; the common stream header fields
 * use the same positions as Avtp_CshFieldDescV0.
 */
static const Avtp_FieldDescriptor_t Avtp_AafFieldDescV0[AVTP_AAF_FIELD_MAX] = {
    [AVTP_AAF_FIELD_SV] = {.quadlet = 0, .offset = 8, .bits = 1},
    [AVTP_AAF_FIELD_MR] = {.quadlet = 0, .offset = 12, .bits = 1},
    [AVTP_AAF_FIELD_FSD] = {.quadlet = 0, .offset = 13, .bits = 2},
    [AVTP_AAF_FIELD_TV] = {.quadlet = 0, .offset = 15, .bits = 1},
    [AVTP_AAF_FIELD_SEQUENCE_NUM] = {.quadlet = 0, .offset = 16, .bits = 8},
    [AVTP_AAF_FIELD_FSD0] = {.quadlet = 0, .offset = 0, .bits = 0},
    [AVTP_AAF_FIELD_FSD1] = {.quadlet = 0, .offset = 24, .bits = 7},
    [AVTP_AAF_FIELD_TU] = {.quadlet = 0, .offset = 31, .bits = 1},
    [AVTP_AAF_FIELD_STREAM_ID] = {.quadlet = 1, .offset = 0, .bits = 64},
    [AVTP_AAF_FIELD_AVTP_TIMESTAMP] = {.quadlet = 3, .offset = 0, .bits = 32},
    [AVTP_AAF_FIELD_PTP_GRANDMASTER_IDENTITY] = {.quadlet = 0, .offset = 0, .bits = 0},
    [AVTP_AAF_FIELD_STREAM_DATA_LENGTH] = {.quadlet = 5, .offset = 0, .bits = 16},
    [AVTP_AAF_FIELD_FORMAT] = {.quadlet = 4, .offset = 0, .bits = 8},
    [AVTP_AAF_FIELD_AAF_FORMAT_SPECIFIC_DATA_1] = {.quadlet = 4, .offset = 8, .bits = 24},
    [AVTP_AAF_FIELD_AFSD] = {.quadlet = 5, .offset = 16, .bits = 3},
    [AVTP_AAF_FIELD_SP] = {.quadlet = 5, .offset = 19, .bits = 1},
    [AVTP_AAF_FIELD_EVT] = {.quadlet = 5, .offset = 20, .bits = 4},
    [AVTP_AAF_FIELD_AAF_FORMAT_SPECIFIC_DATA_2] = {.quadlet = 5, .offset = 24, .bits = 8},
};

/**
 * This table maps all IEEE 1722 AAF header fields to a descriptor for version 1.
 * It is complete and in absolute coordinates; the common stream header fields
 * use the same positions as Avtp_CshFieldDescV1.
 */
static const Avtp_FieldDescriptor_t Avtp_AafFieldDescV1[AVTP_AAF_FIELD_MAX] = {
    [AVTP_AAF_FIELD_SV] = {.quadlet = 0, .offset = 8, .bits = 1},
    [AVTP_AAF_FIELD_MR] = {.quadlet = 0, .offset = 12, .bits = 1},
    [AVTP_AAF_FIELD_FSD] = {.quadlet = 0, .offset = 13, .bits = 2},
    [AVTP_AAF_FIELD_TV] = {.quadlet = 0, .offset = 15, .bits = 1},
    [AVTP_AAF_FIELD_SEQUENCE_NUM] = {.quadlet = 3, .offset = 0, .bits = 32},
    [AVTP_AAF_FIELD_FSD0] = {.quadlet = 0, .offset = 16, .bits = 8},
    [AVTP_AAF_FIELD_FSD1] = {.quadlet = 0, .offset = 24, .bits = 7},
    [AVTP_AAF_FIELD_TU] = {.quadlet = 0, .offset = 31, .bits = 1},
    [AVTP_AAF_FIELD_STREAM_ID] = {.quadlet = 1, .offset = 0, .bits = 64},
    [AVTP_AAF_FIELD_AVTP_TIMESTAMP] = {.quadlet = 4, .offset = 0, .bits = 64},
    [AVTP_AAF_FIELD_PTP_GRANDMASTER_IDENTITY] = {.quadlet = 6, .offset = 0, .bits = 64},
    [AVTP_AAF_FIELD_STREAM_DATA_LENGTH] = {.quadlet = 9, .offset = 0, .bits = 16},
    [AVTP_AAF_FIELD_FORMAT] = {.quadlet = 8, .offset = 0, .bits = 8},
    [AVTP_AAF_FIELD_AAF_FORMAT_SPECIFIC_DATA_1] = {.quadlet = 8, .offset = 8, .bits = 24},
    [AVTP_AAF_FIELD_AFSD] = {.quadlet = 9, .offset = 16, .bits = 3},
    [AVTP_AAF_FIELD_SP] = {.quadlet = 9, .offset = 19, .bits = 1},
    [AVTP_AAF_FIELD_EVT] = {.quadlet = 9, .offset = 20, .bits = 4},
    [AVTP_AAF_FIELD_AAF_FORMAT_SPECIFIC_DATA_2] = {.quadlet = 9, .offset = 24, .bits = 8},
};

/**
 * Returns the value of an AVTP AAF field as laid out by version 0. No version
 * dispatch is performed.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param field Specifies the position of the data field to be read
 * @returns This function returns the value of the field.
 * @see Avtp_Aaf_GetField
 */
OPEN1722_INLINE uint64_t Avtp_Aaf_GetField_V0(const Avtp_Aaf_t *const pdu, Avtp_AafFields_t field)
{
    return Avtp_GetField(Avtp_AafFieldDescV0, AVTP_AAF_FIELD_MAX, (const uint8_t *)pdu,
                         (uint8_t)field);
}

/**
 * Returns the value of an AVTP AAF field as laid out by version 1. No version
 * dispatch is performed.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param field Specifies the position of the data field to be read
 * @returns This function returns the value of the field.
 * @see Avtp_Aaf_GetField
 */
OPEN1722_INLINE uint64_t Avtp_Aaf_GetField_V1(const Avtp_AafV1_t *const pdu, Avtp_AafFields_t field)
{
    return Avtp_GetField(Avtp_AafFieldDescV1, AVTP_AAF_FIELD_MAX, (const uint8_t *)pdu,
                         (uint8_t)field);
}

/**
 * Returns the value of an AVTP AAF field, dispatching on the version field of
 * the PDU.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param field Specifies the position of the data field to be read
 * @returns This function returns the value of the field.
 */
OPEN1722_INLINE uint64_t Avtp_Aaf_GetField(const Avtp_Aaf_t *const pdu, Avtp_AafFields_t field)
{
    return Avtp_CommonStreamHeader_GetVersion((const Avtp_CommonStreamHeader_t *)pdu) ==
                   AVTP_VERSION_1
               ? Avtp_Aaf_GetField_V1((const Avtp_AafV1_t *)pdu, field)
               : Avtp_Aaf_GetField_V0(pdu, field);
}

/**
 * Sets the value of an AVTP AAF field as laid out by version 0. No version
 * dispatch is performed.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param field Specifies the position of the data field to be written
 * @param value The value to set.
 * @see Avtp_Aaf_SetField
 */
OPEN1722_INLINE void Avtp_Aaf_SetField_V0(Avtp_Aaf_t *pdu, Avtp_AafFields_t field, uint64_t value)
{
    Avtp_SetField(Avtp_AafFieldDescV0, AVTP_AAF_FIELD_MAX, (uint8_t *)pdu, (uint8_t)field, value);
}

/**
 * Sets the value of an AVTP AAF field as laid out by version 1. No version
 * dispatch is performed.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param field Specifies the position of the data field to be written
 * @param value The value to set.
 * @see Avtp_Aaf_SetField
 */
OPEN1722_INLINE void Avtp_Aaf_SetField_V1(Avtp_AafV1_t *pdu, Avtp_AafFields_t field, uint64_t value)
{
    Avtp_SetField(Avtp_AafFieldDescV1, AVTP_AAF_FIELD_MAX, (uint8_t *)pdu, (uint8_t)field, value);
}

/**
 * Sets the value of an AVTP AAF field, dispatching on the version field of the
 * PDU.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param field Specifies the position of the data field to be written
 * @param value The value to set.
 */
OPEN1722_INLINE void Avtp_Aaf_SetField(Avtp_Aaf_t *pdu, Avtp_AafFields_t field, uint64_t value)
{
    if (Avtp_CommonStreamHeader_GetVersion((const Avtp_CommonStreamHeader_t *)pdu) ==
        AVTP_VERSION_1) {
        Avtp_Aaf_SetField_V1((Avtp_AafV1_t *)pdu, field, value);
    } else {
        Avtp_Aaf_SetField_V0(pdu, field, value);
    }
}

/**
 * Returns the length of the version 0 AAF header in octets (24). The PDU
 * pointer is not read; it keeps the signature aligned with the
 * version-dispatched accessors.
 */
OPEN1722_INLINE uint8_t Avtp_Aaf_GetHeaderLen_V0(const Avtp_Aaf_t *const pdu)
{
    (void)pdu;
    return (uint8_t)AVTP_AAF_HEADER_LEN_V0;
}

/**
 * Returns the length of the version 1 AAF header in octets (40). The PDU
 * pointer is not read; it keeps the signature aligned with the
 * version-dispatched accessors.
 */
OPEN1722_INLINE uint8_t Avtp_Aaf_GetHeaderLen_V1(const Avtp_AafV1_t *const pdu)
{
    (void)pdu;
    return (uint8_t)AVTP_AAF_HEADER_LEN_V1;
}

/**
 * Returns the length of the AAF header in octets (24 or 40), dispatching on the
 * version field of the PDU.
 */
OPEN1722_INLINE uint8_t Avtp_Aaf_GetHeaderLen(const Avtp_Aaf_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetVersion((const Avtp_CommonStreamHeader_t *)pdu) ==
                   AVTP_VERSION_1
               ? Avtp_Aaf_GetHeaderLen_V1((const Avtp_AafV1_t *)pdu)
               : Avtp_Aaf_GetHeaderLen_V0(pdu);
}

/**
 * Return the value of the AAF SV field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @returns Value of the AAF SV field.
 */
OPEN1722_INLINE bool Avtp_Aaf_IsSv(const Avtp_Aaf_t *const pdu)
{
    return (bool)Avtp_Aaf_GetField(pdu, AVTP_AAF_FIELD_SV);
}

/**
 * Return the value of the AAF MR field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @returns Value of the AAF MR field.
 */
OPEN1722_INLINE bool Avtp_Aaf_IsMr(const Avtp_Aaf_t *const pdu)
{
    return (bool)Avtp_Aaf_GetField(pdu, AVTP_AAF_FIELD_MR);
}

/**
 * Return the value of the AAF TV field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @returns Value of the AAF TV field.
 */
OPEN1722_INLINE bool Avtp_Aaf_IsTv(const Avtp_Aaf_t *const pdu)
{
    return (bool)Avtp_Aaf_GetField(pdu, AVTP_AAF_FIELD_TV);
}

/**
 * Return the value of the AAF Sequence Number field as specified in the IEEE 1722 Specification.
 * The field is 8 bits in version 0 and 32 bits in version 1.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @returns Value of the AAF Sequence Number field.
 */
OPEN1722_INLINE uint32_t Avtp_Aaf_GetSequenceNum(const Avtp_Aaf_t *const pdu)
{
    return (uint32_t)Avtp_Aaf_GetField(pdu, AVTP_AAF_FIELD_SEQUENCE_NUM);
}

/**
 * Return the value of the AAF TU field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @returns Value of the AAF TU field.
 */
OPEN1722_INLINE bool Avtp_Aaf_IsTu(const Avtp_Aaf_t *const pdu)
{
    return (bool)Avtp_Aaf_GetField(pdu, AVTP_AAF_FIELD_TU);
}

/**
 * Return the value of the AAF Stream ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @returns Value of the AAF Stream ID field.
 */
OPEN1722_INLINE uint64_t Avtp_Aaf_GetStreamId(const Avtp_Aaf_t *const pdu)
{
    return Avtp_Aaf_GetField(pdu, AVTP_AAF_FIELD_STREAM_ID);
}

/**
 * Return the value of the AAF AVTP Timestamp field as specified in the IEEE 1722 Specification.
 * The field is 32 bits in version 0 and 64 bits in version 1.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @returns Value of the AAF AVTP Timestamp field.
 */
OPEN1722_INLINE uint64_t Avtp_Aaf_GetAvtpTimestamp(const Avtp_Aaf_t *const pdu)
{
    return Avtp_Aaf_GetField(pdu, AVTP_AAF_FIELD_AVTP_TIMESTAMP);
}

/**
 * Return the value of the AAF ptp_grandmaster_identity field. The field only
 * exists in version 1; version 0 returns 0.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @returns Value of the AAF ptp_grandmaster_identity field.
 */
OPEN1722_INLINE uint64_t Avtp_Aaf_GetPtpGrandmasterIdentity(const Avtp_Aaf_t *const pdu)
{
    return Avtp_Aaf_GetField(pdu, AVTP_AAF_FIELD_PTP_GRANDMASTER_IDENTITY);
}

/**
 * Return the value of the AAF Format field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @returns Value of the AAF Format field.
 */
OPEN1722_INLINE Avtp_AafFormat_t Avtp_Aaf_GetFormat(const Avtp_Aaf_t *const pdu)
{
    return (Avtp_AafFormat_t)Avtp_Aaf_GetField(pdu, AVTP_AAF_FIELD_FORMAT);
}

/**
 * Return the value of the AAF format-specific data 1 field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @returns Value of the AAF format-specific data 1 field.
 */
OPEN1722_INLINE uint32_t Avtp_Aaf_GetAafFormatSpecificData1(const Avtp_Aaf_t *const pdu)
{
    return (uint32_t)Avtp_Aaf_GetField(pdu, AVTP_AAF_FIELD_AAF_FORMAT_SPECIFIC_DATA_1);
}

/**
 * Return the value of the AAF Stream Data Length field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @returns Value of the AAF Stream Data Length field.
 */
OPEN1722_INLINE uint16_t Avtp_Aaf_GetStreamDataLength(const Avtp_Aaf_t *const pdu)
{
    return (uint16_t)Avtp_Aaf_GetField(pdu, AVTP_AAF_FIELD_STREAM_DATA_LENGTH);
}

/**
 * Return the value of the AAF AFSD field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @returns Value of the AAF AFSD field.
 */
OPEN1722_INLINE uint8_t Avtp_Aaf_GetAfsd(const Avtp_Aaf_t *const pdu)
{
    return (uint8_t)Avtp_Aaf_GetField(pdu, AVTP_AAF_FIELD_AFSD);
}

/**
 * Return the value of the AAF SP field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @returns Value of the AAF SP field.
 */
OPEN1722_INLINE bool Avtp_Aaf_IsSp(const Avtp_Aaf_t *const pdu)
{
    return (bool)Avtp_Aaf_GetField(pdu, AVTP_AAF_FIELD_SP);
}

/**
 * Return the value of the AAF EVT field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @returns Value of the AAF EVT field.
 */
OPEN1722_INLINE uint8_t Avtp_Aaf_GetEvt(const Avtp_Aaf_t *const pdu)
{
    return (uint8_t)Avtp_Aaf_GetField(pdu, AVTP_AAF_FIELD_EVT);
}

/**
 * Return the value of the AAF format-specific data 2 field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @returns Value of the AAF format-specific data 2 field.
 */
OPEN1722_INLINE uint8_t Avtp_Aaf_GetAafFormatSpecificData2(const Avtp_Aaf_t *const pdu)
{
    return (uint8_t)Avtp_Aaf_GetField(pdu, AVTP_AAF_FIELD_AAF_FORMAT_SPECIFIC_DATA_2);
}

/**
 * Set the SV bit in an AAF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param sv Value to set the AAF SV field to.
 */
OPEN1722_INLINE void Avtp_Aaf_SetSv(Avtp_Aaf_t *pdu, bool sv)
{
    Avtp_Aaf_SetField(pdu, AVTP_AAF_FIELD_SV, sv);
}

/**
 * Set the MR bit in an AAF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param mr Value to set the AAF MR field to.
 */
OPEN1722_INLINE void Avtp_Aaf_SetMr(Avtp_Aaf_t *pdu, bool mr)
{
    Avtp_Aaf_SetField(pdu, AVTP_AAF_FIELD_MR, mr);
}

/**
 * Set the TV bit in an AAF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param tv Value to set the AAF TV field to.
 */
OPEN1722_INLINE void Avtp_Aaf_SetTv(Avtp_Aaf_t *pdu, bool tv)
{
    Avtp_Aaf_SetField(pdu, AVTP_AAF_FIELD_TV, tv);
}

/**
 * Set the value of the AAF Sequence Number field as specified in the IEEE 1722 Specification.
 * The field is 8 bits in version 0 and 32 bits in version 1; values are truncated to the
 * width of the version in use.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param value Value to set the AAF Sequence Number field to.
 */
OPEN1722_INLINE void Avtp_Aaf_SetSequenceNum(Avtp_Aaf_t *pdu, uint32_t value)
{
    Avtp_Aaf_SetField(pdu, AVTP_AAF_FIELD_SEQUENCE_NUM, value);
}

/**
 * Set the TU bit in an AAF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param tu Value to set the AAF TU field to.
 */
OPEN1722_INLINE void Avtp_Aaf_SetTu(Avtp_Aaf_t *pdu, bool tu)
{
    Avtp_Aaf_SetField(pdu, AVTP_AAF_FIELD_TU, tu);
}

/**
 * Set the value of the AAF Stream ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param value Value to set the AAF Stream ID field to.
 */
OPEN1722_INLINE void Avtp_Aaf_SetStreamId(Avtp_Aaf_t *pdu, uint64_t value)
{
    Avtp_Aaf_SetField(pdu, AVTP_AAF_FIELD_STREAM_ID, value);
}

/**
 * Set the value of the AAF AVTP Timestamp field as specified in the IEEE 1722 Specification.
 * The field is 32 bits in version 0 and 64 bits in version 1; values are truncated to the
 * width of the version in use.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param value Value to set the AAF AVTP Timestamp field to.
 */
OPEN1722_INLINE void Avtp_Aaf_SetAvtpTimestamp(Avtp_Aaf_t *pdu, uint64_t value)
{
    Avtp_Aaf_SetField(pdu, AVTP_AAF_FIELD_AVTP_TIMESTAMP, value);
}

/**
 * Set the value of the AAF ptp_grandmaster_identity field. The field only
 * exists in version 1; on version 0 this is a no-op.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param value Value to set the AAF ptp_grandmaster_identity field to.
 */
OPEN1722_INLINE void Avtp_Aaf_SetPtpGrandmasterIdentity(Avtp_Aaf_t *pdu, uint64_t value)
{
    Avtp_Aaf_SetField(pdu, AVTP_AAF_FIELD_PTP_GRANDMASTER_IDENTITY, value);
}

/**
 * Set the value of the AAF Format field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param value Value to set the AAF Format field to.
 */
OPEN1722_INLINE void Avtp_Aaf_SetFormat(Avtp_Aaf_t *pdu, Avtp_AafFormat_t value)
{
    Avtp_Aaf_SetField(pdu, AVTP_AAF_FIELD_FORMAT, (uint64_t)value);
}

/**
 * Set the value of the AAF format-specific data 1 field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param value Value to set the AAF format-specific data 1 field to.
 */
OPEN1722_INLINE void Avtp_Aaf_SetAafFormatSpecificData1(Avtp_Aaf_t *pdu, uint32_t value)
{
    Avtp_Aaf_SetField(pdu, AVTP_AAF_FIELD_AAF_FORMAT_SPECIFIC_DATA_1, value);
}

/**
 * Set the value of the AAF Stream Data Length field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param value Value to set the AAF Stream Data Length field to.
 */
OPEN1722_INLINE void Avtp_Aaf_SetStreamDataLength(Avtp_Aaf_t *pdu, uint16_t value)
{
    Avtp_Aaf_SetField(pdu, AVTP_AAF_FIELD_STREAM_DATA_LENGTH, value);
}

/**
 * Set the value of the AAF AFSD field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param value Value to set the AAF AFSD field to.
 */
OPEN1722_INLINE void Avtp_Aaf_SetAfsd(Avtp_Aaf_t *pdu, uint8_t value)
{
    Avtp_Aaf_SetField(pdu, AVTP_AAF_FIELD_AFSD, value);
}

/**
 * Set the SP bit in an AAF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param sp Value to set the AAF SP field to.
 */
OPEN1722_INLINE void Avtp_Aaf_SetSp(Avtp_Aaf_t *pdu, bool sp)
{
    Avtp_Aaf_SetField(pdu, AVTP_AAF_FIELD_SP, sp);
}

/**
 * Set the value of the AAF EVT field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param value Value to set the AAF EVT field to.
 */
OPEN1722_INLINE void Avtp_Aaf_SetEvt(Avtp_Aaf_t *pdu, uint8_t value)
{
    Avtp_Aaf_SetField(pdu, AVTP_AAF_FIELD_EVT, value);
}

/**
 * Set the value of the AAF format-specific data 2 field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param value Value to set the AAF format-specific data 2 field to.
 */
OPEN1722_INLINE void Avtp_Aaf_SetAafFormatSpecificData2(Avtp_Aaf_t *pdu, uint8_t value)
{
    Avtp_Aaf_SetField(pdu, AVTP_AAF_FIELD_AAF_FORMAT_SPECIFIC_DATA_2, value);
}

/**
 * Returns a pointer to the payload of a version 0 AAF frame.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @return Pointer to AAF frame payload
 * @see Avtp_Aaf_GetPayload
 */
OPEN1722_INLINE const uint8_t *Avtp_Aaf_GetPayload_V0(const Avtp_Aaf_t *const pdu)
{
    return (const uint8_t *)pdu + AVTP_AAF_HEADER_LEN_V0;
}

/**
 * Returns a pointer to the payload of a version 1 AAF frame.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @return Pointer to AAF frame payload
 * @see Avtp_Aaf_GetPayload
 */
OPEN1722_INLINE const uint8_t *Avtp_Aaf_GetPayload_V1(const Avtp_AafV1_t *const pdu)
{
    return (const uint8_t *)pdu + AVTP_AAF_HEADER_LEN_V1;
}

/**
 * Returns pointer to payload of an AAF frame. The payload starts after the
 * version-dependent common stream header.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @return Pointer to AAF frame payload
 */
OPEN1722_INLINE const uint8_t *Avtp_Aaf_GetPayload(const Avtp_Aaf_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetVersion((const Avtp_CommonStreamHeader_t *)pdu) ==
                   AVTP_VERSION_1
               ? Avtp_Aaf_GetPayload_V1((const Avtp_AafV1_t *)pdu)
               : Avtp_Aaf_GetPayload_V0(pdu);
}

/**
 * Sets the payload of a version 0 AAF frame.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload
 * @see Avtp_Aaf_SetPayload
 */
OPEN1722_INLINE void Avtp_Aaf_SetPayload_V0(Avtp_Aaf_t *pdu, uint8_t *payload,
                                            uint16_t payload_length)
{
    memcpy((uint8_t *)pdu + AVTP_AAF_HEADER_LEN_V0, payload, payload_length);
}

/**
 * Sets the payload of a version 1 AAF frame.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload
 * @see Avtp_Aaf_SetPayload
 */
OPEN1722_INLINE void Avtp_Aaf_SetPayload_V1(Avtp_AafV1_t *pdu, uint8_t *payload,
                                            uint16_t payload_length)
{
    memcpy((uint8_t *)pdu + AVTP_AAF_HEADER_LEN_V1, payload, payload_length);
}

/**
 * Sets the AAF payload in an AAF frame.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload
 */
OPEN1722_INLINE void Avtp_Aaf_SetPayload(Avtp_Aaf_t *pdu, uint8_t *payload, uint16_t payload_length)
{
    if (Avtp_CommonStreamHeader_GetVersion((const Avtp_CommonStreamHeader_t *)pdu) ==
        AVTP_VERSION_1) {
        Avtp_Aaf_SetPayload_V1((Avtp_AafV1_t *)pdu, payload, payload_length);
    } else {
        Avtp_Aaf_SetPayload_V0(pdu, payload, payload_length);
    }
}

/**
 * Initializes a version 0 AAF PDU as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of a 1722 AAF PDU.
 */
OPEN1722_INLINE void Avtp_Aaf_Init(Avtp_Aaf_t *pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_Aaf_t));
        Avtp_CommonHeader_SetSubtype((Avtp_CommonHeader_t *)pdu, AVTP_SUBTYPE_AAF);
        Avtp_Aaf_SetSv(pdu, true);
    }
}

/**
 * Initializes a version 1 AAF PDU. The caller must provide a buffer of at least
 * AVTP_AAF_HEADER_LEN_V1 octets.
 *
 * @param pdu Pointer to the first bit of a 1722 AAF PDU.
 */
OPEN1722_INLINE void Avtp_Aaf_InitV1(Avtp_AafV1_t *pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_AafV1_t));
        Avtp_CommonHeader_SetSubtype((Avtp_CommonHeader_t *)pdu, AVTP_SUBTYPE_AAF);
        Avtp_CommonHeader_SetVersion((Avtp_CommonHeader_t *)pdu, AVTP_VERSION_1);
        Avtp_Aaf_SetSv((Avtp_Aaf_t *)pdu, true);
    }
}

/**
 * Checks if the AAF frame is valid by checking:
 *     1) that the subtype is AAF and the version is supported,
 *     2) that the version-dependent header fits into the buffer,
 *     3) that the declared stream_data_length fits into the buffer.
 *
 * The stream_data_length field contains the length (in octets) of the
 * stream_data_payload field (IEEE 1722-2025, 4.7.4.12), so the whole AVTPDU
 * must fit into bufferSize.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param bufferSize Size of the buffer containing the AAF frame.
 * @return true if the AAF frame is valid, false otherwise.
 */
OPEN1722_INLINE bool Avtp_Aaf_IsValid(const Avtp_Aaf_t *const pdu, size_t bufferSize)
{
    if (pdu == NULL) {
        return false;
    }

    if (Avtp_CommonHeader_GetSubtype((const Avtp_CommonHeader_t *)pdu) != AVTP_SUBTYPE_AAF) {
        return false;
    }

    uint8_t version = Avtp_CommonStreamHeader_GetVersion((const Avtp_CommonStreamHeader_t *)pdu);
    if (!Avtp_Version_IsSupported(AVTP_AAF_SUPPORTED_VERSIONS, version)) {
        return false;
    }

    size_t headerLen = Avtp_Aaf_GetHeaderLen(pdu);
    if (bufferSize < headerLen) {
        return false;
    }

    if ((size_t)Avtp_Aaf_GetStreamDataLength(pdu) > bufferSize - headerLen) {
        return false;
    }

    return true;
}

/*
 * Version-typed named accessors. These select the field layout for one
 * explicit version and never read the version field; the version-dispatched
 * accessors above delegate to them. Common stream header fields delegate to
 * the shared Avtp_CommonStreamHeader_* variants. See each version-dispatched
 * accessor for the full field documentation.
 */

/**
 * Version 0 variant of Avtp_Aaf_IsSv().
 * @see Avtp_Aaf_IsSv
 */
OPEN1722_INLINE bool Avtp_Aaf_IsSv_V0(const Avtp_Aaf_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsSv_V0((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Aaf_IsSv().
 * @see Avtp_Aaf_IsSv
 */
OPEN1722_INLINE bool Avtp_Aaf_IsSv_V1(const Avtp_AafV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsSv_V1((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Aaf_IsMr().
 * @see Avtp_Aaf_IsMr
 */
OPEN1722_INLINE bool Avtp_Aaf_IsMr_V0(const Avtp_Aaf_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsMr_V0((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Aaf_IsMr().
 * @see Avtp_Aaf_IsMr
 */
OPEN1722_INLINE bool Avtp_Aaf_IsMr_V1(const Avtp_AafV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsMr_V1((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Aaf_IsTv().
 * @see Avtp_Aaf_IsTv
 */
OPEN1722_INLINE bool Avtp_Aaf_IsTv_V0(const Avtp_Aaf_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsTv_V0((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Aaf_IsTv().
 * @see Avtp_Aaf_IsTv
 */
OPEN1722_INLINE bool Avtp_Aaf_IsTv_V1(const Avtp_AafV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsTv_V1((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Aaf_IsTu().
 * @see Avtp_Aaf_IsTu
 */
OPEN1722_INLINE bool Avtp_Aaf_IsTu_V0(const Avtp_Aaf_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsTu_V0((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Aaf_IsTu().
 * @see Avtp_Aaf_IsTu
 */
OPEN1722_INLINE bool Avtp_Aaf_IsTu_V1(const Avtp_AafV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsTu_V1((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Aaf_GetSequenceNum(). Values are truncated to the
 * 8-bit version 0 field width.
 * @see Avtp_Aaf_GetSequenceNum
 */
OPEN1722_INLINE uint32_t Avtp_Aaf_GetSequenceNum_V0(const Avtp_Aaf_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetSequenceNum_V0((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Aaf_GetSequenceNum().
 * @see Avtp_Aaf_GetSequenceNum
 */
OPEN1722_INLINE uint32_t Avtp_Aaf_GetSequenceNum_V1(const Avtp_AafV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetSequenceNum_V1((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Aaf_GetStreamId().
 * @see Avtp_Aaf_GetStreamId
 */
OPEN1722_INLINE uint64_t Avtp_Aaf_GetStreamId_V0(const Avtp_Aaf_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetStreamId_V0((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Aaf_GetStreamId().
 * @see Avtp_Aaf_GetStreamId
 */
OPEN1722_INLINE uint64_t Avtp_Aaf_GetStreamId_V1(const Avtp_AafV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetStreamId_V1((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Aaf_GetAvtpTimestamp().
 * @see Avtp_Aaf_GetAvtpTimestamp
 */
OPEN1722_INLINE uint64_t Avtp_Aaf_GetAvtpTimestamp_V0(const Avtp_Aaf_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetAvtpTimestamp_V0((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Aaf_GetAvtpTimestamp().
 * @see Avtp_Aaf_GetAvtpTimestamp
 */
OPEN1722_INLINE uint64_t Avtp_Aaf_GetAvtpTimestamp_V1(const Avtp_AafV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetAvtpTimestamp_V1((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Aaf_GetPtpGrandmasterIdentity(). The field is
 * absent from version 0, so this always returns 0.
 * @see Avtp_Aaf_GetPtpGrandmasterIdentity
 */
OPEN1722_INLINE uint64_t Avtp_Aaf_GetPtpGrandmasterIdentity_V0(const Avtp_Aaf_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetPtpGrandmasterIdentity_V0(
        (const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Aaf_GetPtpGrandmasterIdentity().
 * @see Avtp_Aaf_GetPtpGrandmasterIdentity
 */
OPEN1722_INLINE uint64_t Avtp_Aaf_GetPtpGrandmasterIdentity_V1(const Avtp_AafV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetPtpGrandmasterIdentity_V1(
        (const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Aaf_GetFormat().
 * @see Avtp_Aaf_GetFormat
 */
OPEN1722_INLINE Avtp_AafFormat_t Avtp_Aaf_GetFormat_V0(const Avtp_Aaf_t *const pdu)
{
    return (Avtp_AafFormat_t)Avtp_Aaf_GetField_V0(pdu, AVTP_AAF_FIELD_FORMAT);
}

/**
 * Version 1 variant of Avtp_Aaf_GetFormat().
 * @see Avtp_Aaf_GetFormat
 */
OPEN1722_INLINE Avtp_AafFormat_t Avtp_Aaf_GetFormat_V1(const Avtp_AafV1_t *const pdu)
{
    return (Avtp_AafFormat_t)Avtp_Aaf_GetField_V1(pdu, AVTP_AAF_FIELD_FORMAT);
}

/**
 * Version 0 variant of Avtp_Aaf_GetAafFormatSpecificData1().
 * @see Avtp_Aaf_GetAafFormatSpecificData1
 */
OPEN1722_INLINE uint32_t Avtp_Aaf_GetAafFormatSpecificData1_V0(const Avtp_Aaf_t *const pdu)
{
    return (uint32_t)Avtp_Aaf_GetField_V0(pdu, AVTP_AAF_FIELD_AAF_FORMAT_SPECIFIC_DATA_1);
}

/**
 * Version 1 variant of Avtp_Aaf_GetAafFormatSpecificData1().
 * @see Avtp_Aaf_GetAafFormatSpecificData1
 */
OPEN1722_INLINE uint32_t Avtp_Aaf_GetAafFormatSpecificData1_V1(const Avtp_AafV1_t *const pdu)
{
    return (uint32_t)Avtp_Aaf_GetField_V1(pdu, AVTP_AAF_FIELD_AAF_FORMAT_SPECIFIC_DATA_1);
}

/**
 * Version 0 variant of Avtp_Aaf_GetStreamDataLength().
 * @see Avtp_Aaf_GetStreamDataLength
 */
OPEN1722_INLINE uint16_t Avtp_Aaf_GetStreamDataLength_V0(const Avtp_Aaf_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetStreamDataLength_V0((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Aaf_GetStreamDataLength().
 * @see Avtp_Aaf_GetStreamDataLength
 */
OPEN1722_INLINE uint16_t Avtp_Aaf_GetStreamDataLength_V1(const Avtp_AafV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetStreamDataLength_V1((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Aaf_GetAfsd().
 * @see Avtp_Aaf_GetAfsd
 */
OPEN1722_INLINE uint8_t Avtp_Aaf_GetAfsd_V0(const Avtp_Aaf_t *const pdu)
{
    return (uint8_t)Avtp_Aaf_GetField_V0(pdu, AVTP_AAF_FIELD_AFSD);
}

/**
 * Version 1 variant of Avtp_Aaf_GetAfsd().
 * @see Avtp_Aaf_GetAfsd
 */
OPEN1722_INLINE uint8_t Avtp_Aaf_GetAfsd_V1(const Avtp_AafV1_t *const pdu)
{
    return (uint8_t)Avtp_Aaf_GetField_V1(pdu, AVTP_AAF_FIELD_AFSD);
}

/**
 * Version 0 variant of Avtp_Aaf_IsSp().
 * @see Avtp_Aaf_IsSp
 */
OPEN1722_INLINE bool Avtp_Aaf_IsSp_V0(const Avtp_Aaf_t *const pdu)
{
    return (bool)Avtp_Aaf_GetField_V0(pdu, AVTP_AAF_FIELD_SP);
}

/**
 * Version 1 variant of Avtp_Aaf_IsSp().
 * @see Avtp_Aaf_IsSp
 */
OPEN1722_INLINE bool Avtp_Aaf_IsSp_V1(const Avtp_AafV1_t *const pdu)
{
    return (bool)Avtp_Aaf_GetField_V1(pdu, AVTP_AAF_FIELD_SP);
}

/**
 * Version 0 variant of Avtp_Aaf_GetEvt().
 * @see Avtp_Aaf_GetEvt
 */
OPEN1722_INLINE uint8_t Avtp_Aaf_GetEvt_V0(const Avtp_Aaf_t *const pdu)
{
    return (uint8_t)Avtp_Aaf_GetField_V0(pdu, AVTP_AAF_FIELD_EVT);
}

/**
 * Version 1 variant of Avtp_Aaf_GetEvt().
 * @see Avtp_Aaf_GetEvt
 */
OPEN1722_INLINE uint8_t Avtp_Aaf_GetEvt_V1(const Avtp_AafV1_t *const pdu)
{
    return (uint8_t)Avtp_Aaf_GetField_V1(pdu, AVTP_AAF_FIELD_EVT);
}

/**
 * Version 0 variant of Avtp_Aaf_GetAafFormatSpecificData2().
 * @see Avtp_Aaf_GetAafFormatSpecificData2
 */
OPEN1722_INLINE uint8_t Avtp_Aaf_GetAafFormatSpecificData2_V0(const Avtp_Aaf_t *const pdu)
{
    return (uint8_t)Avtp_Aaf_GetField_V0(pdu, AVTP_AAF_FIELD_AAF_FORMAT_SPECIFIC_DATA_2);
}

/**
 * Version 1 variant of Avtp_Aaf_GetAafFormatSpecificData2().
 * @see Avtp_Aaf_GetAafFormatSpecificData2
 */
OPEN1722_INLINE uint8_t Avtp_Aaf_GetAafFormatSpecificData2_V1(const Avtp_AafV1_t *const pdu)
{
    return (uint8_t)Avtp_Aaf_GetField_V1(pdu, AVTP_AAF_FIELD_AAF_FORMAT_SPECIFIC_DATA_2);
}

/**
 * Version 0 variant of Avtp_Aaf_SetSv().
 * @see Avtp_Aaf_SetSv
 */
OPEN1722_INLINE void Avtp_Aaf_SetSv_V0(Avtp_Aaf_t *pdu, bool sv)
{
    Avtp_CommonStreamHeader_SetSv_V0((Avtp_CommonStreamHeader_t *)pdu, sv);
}

/**
 * Version 1 variant of Avtp_Aaf_SetSv().
 * @see Avtp_Aaf_SetSv
 */
OPEN1722_INLINE void Avtp_Aaf_SetSv_V1(Avtp_AafV1_t *pdu, bool sv)
{
    Avtp_CommonStreamHeader_SetSv_V1((Avtp_CommonStreamHeader_t *)pdu, sv);
}

/**
 * Version 0 variant of Avtp_Aaf_SetMr().
 * @see Avtp_Aaf_SetMr
 */
OPEN1722_INLINE void Avtp_Aaf_SetMr_V0(Avtp_Aaf_t *pdu, bool mr)
{
    Avtp_CommonStreamHeader_SetMr_V0((Avtp_CommonStreamHeader_t *)pdu, mr);
}

/**
 * Version 1 variant of Avtp_Aaf_SetMr().
 * @see Avtp_Aaf_SetMr
 */
OPEN1722_INLINE void Avtp_Aaf_SetMr_V1(Avtp_AafV1_t *pdu, bool mr)
{
    Avtp_CommonStreamHeader_SetMr_V1((Avtp_CommonStreamHeader_t *)pdu, mr);
}

/**
 * Version 0 variant of Avtp_Aaf_SetTv().
 * @see Avtp_Aaf_SetTv
 */
OPEN1722_INLINE void Avtp_Aaf_SetTv_V0(Avtp_Aaf_t *pdu, bool tv)
{
    Avtp_CommonStreamHeader_SetTv_V0((Avtp_CommonStreamHeader_t *)pdu, tv);
}

/**
 * Version 1 variant of Avtp_Aaf_SetTv().
 * @see Avtp_Aaf_SetTv
 */
OPEN1722_INLINE void Avtp_Aaf_SetTv_V1(Avtp_AafV1_t *pdu, bool tv)
{
    Avtp_CommonStreamHeader_SetTv_V1((Avtp_CommonStreamHeader_t *)pdu, tv);
}

/**
 * Version 0 variant of Avtp_Aaf_SetTu().
 * @see Avtp_Aaf_SetTu
 */
OPEN1722_INLINE void Avtp_Aaf_SetTu_V0(Avtp_Aaf_t *pdu, bool tu)
{
    Avtp_CommonStreamHeader_SetTu_V0((Avtp_CommonStreamHeader_t *)pdu, tu);
}

/**
 * Version 1 variant of Avtp_Aaf_SetTu().
 * @see Avtp_Aaf_SetTu
 */
OPEN1722_INLINE void Avtp_Aaf_SetTu_V1(Avtp_AafV1_t *pdu, bool tu)
{
    Avtp_CommonStreamHeader_SetTu_V1((Avtp_CommonStreamHeader_t *)pdu, tu);
}

/**
 * Version 0 variant of Avtp_Aaf_SetSequenceNum(). Values are truncated to the
 * 8-bit version 0 field width.
 * @see Avtp_Aaf_SetSequenceNum
 */
OPEN1722_INLINE void Avtp_Aaf_SetSequenceNum_V0(Avtp_Aaf_t *pdu, uint32_t value)
{
    Avtp_CommonStreamHeader_SetSequenceNum_V0((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 1 variant of Avtp_Aaf_SetSequenceNum().
 * @see Avtp_Aaf_SetSequenceNum
 */
OPEN1722_INLINE void Avtp_Aaf_SetSequenceNum_V1(Avtp_AafV1_t *pdu, uint32_t value)
{
    Avtp_CommonStreamHeader_SetSequenceNum_V1((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 0 variant of Avtp_Aaf_SetStreamId().
 * @see Avtp_Aaf_SetStreamId
 */
OPEN1722_INLINE void Avtp_Aaf_SetStreamId_V0(Avtp_Aaf_t *pdu, uint64_t value)
{
    Avtp_CommonStreamHeader_SetStreamId_V0((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 1 variant of Avtp_Aaf_SetStreamId().
 * @see Avtp_Aaf_SetStreamId
 */
OPEN1722_INLINE void Avtp_Aaf_SetStreamId_V1(Avtp_AafV1_t *pdu, uint64_t value)
{
    Avtp_CommonStreamHeader_SetStreamId_V1((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 0 variant of Avtp_Aaf_SetAvtpTimestamp().
 * @see Avtp_Aaf_SetAvtpTimestamp
 */
OPEN1722_INLINE void Avtp_Aaf_SetAvtpTimestamp_V0(Avtp_Aaf_t *pdu, uint64_t value)
{
    Avtp_CommonStreamHeader_SetAvtpTimestamp_V0((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 1 variant of Avtp_Aaf_SetAvtpTimestamp().
 * @see Avtp_Aaf_SetAvtpTimestamp
 */
OPEN1722_INLINE void Avtp_Aaf_SetAvtpTimestamp_V1(Avtp_AafV1_t *pdu, uint64_t value)
{
    Avtp_CommonStreamHeader_SetAvtpTimestamp_V1((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 0 variant of Avtp_Aaf_SetPtpGrandmasterIdentity(). The field is
 * absent from version 0, so this is a no-op.
 * @see Avtp_Aaf_SetPtpGrandmasterIdentity
 */
OPEN1722_INLINE void Avtp_Aaf_SetPtpGrandmasterIdentity_V0(Avtp_Aaf_t *pdu, uint64_t value)
{
    Avtp_CommonStreamHeader_SetPtpGrandmasterIdentity_V0((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 1 variant of Avtp_Aaf_SetPtpGrandmasterIdentity().
 * @see Avtp_Aaf_SetPtpGrandmasterIdentity
 */
OPEN1722_INLINE void Avtp_Aaf_SetPtpGrandmasterIdentity_V1(Avtp_AafV1_t *pdu, uint64_t value)
{
    Avtp_CommonStreamHeader_SetPtpGrandmasterIdentity_V1((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 0 variant of Avtp_Aaf_SetFormat().
 * @see Avtp_Aaf_SetFormat
 */
OPEN1722_INLINE void Avtp_Aaf_SetFormat_V0(Avtp_Aaf_t *pdu, Avtp_AafFormat_t value)
{
    Avtp_Aaf_SetField_V0(pdu, AVTP_AAF_FIELD_FORMAT, (uint64_t)value);
}

/**
 * Version 1 variant of Avtp_Aaf_SetFormat().
 * @see Avtp_Aaf_SetFormat
 */
OPEN1722_INLINE void Avtp_Aaf_SetFormat_V1(Avtp_AafV1_t *pdu, Avtp_AafFormat_t value)
{
    Avtp_Aaf_SetField_V1(pdu, AVTP_AAF_FIELD_FORMAT, (uint64_t)value);
}

/**
 * Version 0 variant of Avtp_Aaf_SetAafFormatSpecificData1().
 * @see Avtp_Aaf_SetAafFormatSpecificData1
 */
OPEN1722_INLINE void Avtp_Aaf_SetAafFormatSpecificData1_V0(Avtp_Aaf_t *pdu, uint32_t value)
{
    Avtp_Aaf_SetField_V0(pdu, AVTP_AAF_FIELD_AAF_FORMAT_SPECIFIC_DATA_1, value);
}

/**
 * Version 1 variant of Avtp_Aaf_SetAafFormatSpecificData1().
 * @see Avtp_Aaf_SetAafFormatSpecificData1
 */
OPEN1722_INLINE void Avtp_Aaf_SetAafFormatSpecificData1_V1(Avtp_AafV1_t *pdu, uint32_t value)
{
    Avtp_Aaf_SetField_V1(pdu, AVTP_AAF_FIELD_AAF_FORMAT_SPECIFIC_DATA_1, value);
}

/**
 * Version 0 variant of Avtp_Aaf_SetStreamDataLength().
 * @see Avtp_Aaf_SetStreamDataLength
 */
OPEN1722_INLINE void Avtp_Aaf_SetStreamDataLength_V0(Avtp_Aaf_t *pdu, uint16_t value)
{
    Avtp_CommonStreamHeader_SetStreamDataLength_V0((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 1 variant of Avtp_Aaf_SetStreamDataLength().
 * @see Avtp_Aaf_SetStreamDataLength
 */
OPEN1722_INLINE void Avtp_Aaf_SetStreamDataLength_V1(Avtp_AafV1_t *pdu, uint16_t value)
{
    Avtp_CommonStreamHeader_SetStreamDataLength_V1((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 0 variant of Avtp_Aaf_SetAfsd().
 * @see Avtp_Aaf_SetAfsd
 */
OPEN1722_INLINE void Avtp_Aaf_SetAfsd_V0(Avtp_Aaf_t *pdu, uint8_t value)
{
    Avtp_Aaf_SetField_V0(pdu, AVTP_AAF_FIELD_AFSD, value);
}

/**
 * Version 1 variant of Avtp_Aaf_SetAfsd().
 * @see Avtp_Aaf_SetAfsd
 */
OPEN1722_INLINE void Avtp_Aaf_SetAfsd_V1(Avtp_AafV1_t *pdu, uint8_t value)
{
    Avtp_Aaf_SetField_V1(pdu, AVTP_AAF_FIELD_AFSD, value);
}

/**
 * Version 0 variant of Avtp_Aaf_SetSp().
 * @see Avtp_Aaf_SetSp
 */
OPEN1722_INLINE void Avtp_Aaf_SetSp_V0(Avtp_Aaf_t *pdu, bool sp)
{
    Avtp_Aaf_SetField_V0(pdu, AVTP_AAF_FIELD_SP, sp);
}

/**
 * Version 1 variant of Avtp_Aaf_SetSp().
 * @see Avtp_Aaf_SetSp
 */
OPEN1722_INLINE void Avtp_Aaf_SetSp_V1(Avtp_AafV1_t *pdu, bool sp)
{
    Avtp_Aaf_SetField_V1(pdu, AVTP_AAF_FIELD_SP, sp);
}

/**
 * Version 0 variant of Avtp_Aaf_SetEvt().
 * @see Avtp_Aaf_SetEvt
 */
OPEN1722_INLINE void Avtp_Aaf_SetEvt_V0(Avtp_Aaf_t *pdu, uint8_t value)
{
    Avtp_Aaf_SetField_V0(pdu, AVTP_AAF_FIELD_EVT, value);
}

/**
 * Version 1 variant of Avtp_Aaf_SetEvt().
 * @see Avtp_Aaf_SetEvt
 */
OPEN1722_INLINE void Avtp_Aaf_SetEvt_V1(Avtp_AafV1_t *pdu, uint8_t value)
{
    Avtp_Aaf_SetField_V1(pdu, AVTP_AAF_FIELD_EVT, value);
}

/**
 * Version 0 variant of Avtp_Aaf_SetAafFormatSpecificData2().
 * @see Avtp_Aaf_SetAafFormatSpecificData2
 */
OPEN1722_INLINE void Avtp_Aaf_SetAafFormatSpecificData2_V0(Avtp_Aaf_t *pdu, uint8_t value)
{
    Avtp_Aaf_SetField_V0(pdu, AVTP_AAF_FIELD_AAF_FORMAT_SPECIFIC_DATA_2, value);
}

/**
 * Version 1 variant of Avtp_Aaf_SetAafFormatSpecificData2().
 * @see Avtp_Aaf_SetAafFormatSpecificData2
 */
OPEN1722_INLINE void Avtp_Aaf_SetAafFormatSpecificData2_V1(Avtp_AafV1_t *pdu, uint8_t value)
{
    Avtp_Aaf_SetField_V1(pdu, AVTP_AAF_FIELD_AAF_FORMAT_SPECIFIC_DATA_2, value);
}

#ifdef __cplusplus
}
#endif
