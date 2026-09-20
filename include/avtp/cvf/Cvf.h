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
 *    * Neither the name of COVESA, Intel Corporation nor the names of its
 *      contributors  may be used to endorse or promote products derived from
 *      this software without specific prior written permission.
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
 * This file contains the fields descriptions of the IEEE 1722 CVF PDUs and
 * functions to invoke corresponding parser and deparser.
 *
 * CVF uses the AVTPDU common stream header (4.7.4) and declares a complete
 * descriptor table per version in absolute coordinates: the common stream
 * header fields reuse the positions from CommonStreamHeader.h and the
 * CVF-specific fields are added by this module. A consistency test keeps the
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

#define AVTP_CVF_HEADER_LEN_V0 AVTPDU_CSH_LEN_V0 /* 24 */
#define AVTP_CVF_HEADER_LEN_V1 AVTPDU_CSH_LEN_V1 /* 40 */
/* Kept for compatibility: the version 0 header length. */
#define AVTP_CVF_HEADER_LEN AVTP_CVF_HEADER_LEN_V0

/* CVF supports both versions of the common stream header (Table 7). */
#define AVTP_CVF_SUPPORTED_VERSIONS ((1u << AVTP_VERSION_0) | (1u << AVTP_VERSION_1))

typedef struct {
    uint8_t header[AVTP_CVF_HEADER_LEN_V0];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_Cvf_t;

typedef struct {
    uint8_t header[AVTP_CVF_HEADER_LEN_V1];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_CvfV1_t;

/**
 * CVF 'format' field values (IEEE 1722-2025, Table 20). Values 0x00-0x01 and
 * 0x03-0xFF are reserved.
 */
typedef enum {
    AVTP_CVF_FORMAT_RFC = 0x2,
} Avtp_CvfFormat_t;

/**
 * CVF 'format_subtype' field values for the RFC format (IEEE 1722-2025,
 * Table 21). Values 0x04-0xFF are reserved.
 */
typedef enum {
    AVTP_CVF_FORMAT_SUBTYPE_MJPEG = 0x0,
    AVTP_CVF_FORMAT_SUBTYPE_H264 = 0x1,
    AVTP_CVF_FORMAT_SUBTYPE_JPEG2000 = 0x2,
    AVTP_CVF_FORMAT_SUBTYPE_H265 = 0x3,
} Avtp_CvfFormatSubtype_t;

typedef enum {

    /* Common AVTP stream header fields */
    AVTP_CVF_FIELD_SV = 0,
    AVTP_CVF_FIELD_MR,
    AVTP_CVF_FIELD_FSD,
    AVTP_CVF_FIELD_TV,
    AVTP_CVF_FIELD_SEQUENCE_NUM,
    AVTP_CVF_FIELD_FSD0,
    AVTP_CVF_FIELD_FSD1,
    AVTP_CVF_FIELD_TU,
    AVTP_CVF_FIELD_STREAM_ID,
    AVTP_CVF_FIELD_AVTP_TIMESTAMP,
    AVTP_CVF_FIELD_PTP_GRANDMASTER_IDENTITY,
    AVTP_CVF_FIELD_STREAM_DATA_LENGTH,

    /* CVF format-specific fields */
    AVTP_CVF_FIELD_FORMAT,
    AVTP_CVF_FIELD_FORMAT_SUBTYPE,
    AVTP_CVF_FIELD_RESERVED2,
    AVTP_CVF_FIELD_RSV2,
    AVTP_CVF_FIELD_PTV, /* ptv for H.264/H.265, reserved for the other subtypes */
    AVTP_CVF_FIELD_M,
    AVTP_CVF_FIELD_EVT,
    AVTP_CVF_FIELD_RESERVED3,

    /* Count number of fields for bound checks */
    AVTP_CVF_FIELD_MAX
} Avtp_CvfFields_t;

/**
 * This table maps all IEEE 1722 CVF header fields to a descriptor for version 0.
 * It is complete and in absolute coordinates; the common stream header fields
 * use the same positions as Avtp_CshFieldDescV0.
 */
static const Avtp_FieldDescriptor_t Avtp_CvfFieldDescV0[AVTP_CVF_FIELD_MAX] = {
    [AVTP_CVF_FIELD_SV] = {.quadlet = 0, .offset = 8, .bits = 1},
    [AVTP_CVF_FIELD_MR] = {.quadlet = 0, .offset = 12, .bits = 1},
    [AVTP_CVF_FIELD_FSD] = {.quadlet = 0, .offset = 13, .bits = 2},
    [AVTP_CVF_FIELD_TV] = {.quadlet = 0, .offset = 15, .bits = 1},
    [AVTP_CVF_FIELD_SEQUENCE_NUM] = {.quadlet = 0, .offset = 16, .bits = 8},
    [AVTP_CVF_FIELD_FSD0] = {.quadlet = 0, .offset = 0, .bits = 0},
    [AVTP_CVF_FIELD_FSD1] = {.quadlet = 0, .offset = 24, .bits = 7},
    [AVTP_CVF_FIELD_TU] = {.quadlet = 0, .offset = 31, .bits = 1},
    [AVTP_CVF_FIELD_STREAM_ID] = {.quadlet = 1, .offset = 0, .bits = 64},
    [AVTP_CVF_FIELD_AVTP_TIMESTAMP] = {.quadlet = 3, .offset = 0, .bits = 32},
    [AVTP_CVF_FIELD_PTP_GRANDMASTER_IDENTITY] = {.quadlet = 0, .offset = 0, .bits = 0},
    [AVTP_CVF_FIELD_STREAM_DATA_LENGTH] = {.quadlet = 5, .offset = 0, .bits = 16},
    [AVTP_CVF_FIELD_FORMAT] = {.quadlet = 4, .offset = 0, .bits = 8},
    [AVTP_CVF_FIELD_FORMAT_SUBTYPE] = {.quadlet = 4, .offset = 8, .bits = 8},
    [AVTP_CVF_FIELD_RESERVED2] = {.quadlet = 4, .offset = 16, .bits = 16},
    [AVTP_CVF_FIELD_RSV2] = {.quadlet = 5, .offset = 16, .bits = 2},
    [AVTP_CVF_FIELD_PTV] = {.quadlet = 5, .offset = 18, .bits = 1},
    [AVTP_CVF_FIELD_M] = {.quadlet = 5, .offset = 19, .bits = 1},
    [AVTP_CVF_FIELD_EVT] = {.quadlet = 5, .offset = 20, .bits = 4},
    [AVTP_CVF_FIELD_RESERVED3] = {.quadlet = 5, .offset = 24, .bits = 8},
};

/**
 * This table maps all IEEE 1722 CVF header fields to a descriptor for version 1.
 * It is complete and in absolute coordinates; the common stream header fields
 * use the same positions as Avtp_CshFieldDescV1.
 */
static const Avtp_FieldDescriptor_t Avtp_CvfFieldDescV1[AVTP_CVF_FIELD_MAX] = {
    [AVTP_CVF_FIELD_SV] = {.quadlet = 0, .offset = 8, .bits = 1},
    [AVTP_CVF_FIELD_MR] = {.quadlet = 0, .offset = 12, .bits = 1},
    [AVTP_CVF_FIELD_FSD] = {.quadlet = 0, .offset = 13, .bits = 2},
    [AVTP_CVF_FIELD_TV] = {.quadlet = 0, .offset = 15, .bits = 1},
    [AVTP_CVF_FIELD_SEQUENCE_NUM] = {.quadlet = 3, .offset = 0, .bits = 32},
    [AVTP_CVF_FIELD_FSD0] = {.quadlet = 0, .offset = 16, .bits = 8},
    [AVTP_CVF_FIELD_FSD1] = {.quadlet = 0, .offset = 24, .bits = 7},
    [AVTP_CVF_FIELD_TU] = {.quadlet = 0, .offset = 31, .bits = 1},
    [AVTP_CVF_FIELD_STREAM_ID] = {.quadlet = 1, .offset = 0, .bits = 64},
    [AVTP_CVF_FIELD_AVTP_TIMESTAMP] = {.quadlet = 4, .offset = 0, .bits = 64},
    [AVTP_CVF_FIELD_PTP_GRANDMASTER_IDENTITY] = {.quadlet = 6, .offset = 0, .bits = 64},
    [AVTP_CVF_FIELD_STREAM_DATA_LENGTH] = {.quadlet = 9, .offset = 0, .bits = 16},
    [AVTP_CVF_FIELD_FORMAT] = {.quadlet = 8, .offset = 0, .bits = 8},
    [AVTP_CVF_FIELD_FORMAT_SUBTYPE] = {.quadlet = 8, .offset = 8, .bits = 8},
    [AVTP_CVF_FIELD_RESERVED2] = {.quadlet = 8, .offset = 16, .bits = 16},
    [AVTP_CVF_FIELD_RSV2] = {.quadlet = 9, .offset = 16, .bits = 2},
    [AVTP_CVF_FIELD_PTV] = {.quadlet = 9, .offset = 18, .bits = 1},
    [AVTP_CVF_FIELD_M] = {.quadlet = 9, .offset = 19, .bits = 1},
    [AVTP_CVF_FIELD_EVT] = {.quadlet = 9, .offset = 20, .bits = 4},
    [AVTP_CVF_FIELD_RESERVED3] = {.quadlet = 9, .offset = 24, .bits = 8},
};

/**
 * Returns the value of an AVTP CVF field as laid out by version 0. No version
 * dispatch is performed.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param field Specifies the position of the data field to be read
 * @returns This function returns the value of the field.
 * @see Avtp_Cvf_GetField
 */
OPEN1722_INLINE uint64_t Avtp_Cvf_GetField_V0(const Avtp_Cvf_t *const pdu, Avtp_CvfFields_t field)
{
    return Avtp_GetField(Avtp_CvfFieldDescV0, AVTP_CVF_FIELD_MAX, (const uint8_t *)pdu,
                         (uint8_t)field);
}

/**
 * Returns the value of an AVTP CVF field as laid out by version 1. No version
 * dispatch is performed.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param field Specifies the position of the data field to be read
 * @returns This function returns the value of the field.
 * @see Avtp_Cvf_GetField
 */
OPEN1722_INLINE uint64_t Avtp_Cvf_GetField_V1(const Avtp_CvfV1_t *const pdu, Avtp_CvfFields_t field)
{
    return Avtp_GetField(Avtp_CvfFieldDescV1, AVTP_CVF_FIELD_MAX, (const uint8_t *)pdu,
                         (uint8_t)field);
}

/**
 * Returns the value of an AVTP CVF field, dispatching on the version field of
 * the PDU.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param field Specifies the position of the data field to be read
 * @returns This function returns the value of the field.
 */
OPEN1722_INLINE uint64_t Avtp_Cvf_GetField(const Avtp_Cvf_t *const pdu, Avtp_CvfFields_t field)
{
    return Avtp_CommonStreamHeader_GetVersion((const Avtp_CommonStreamHeader_t *)pdu) ==
                   AVTP_VERSION_1
               ? Avtp_Cvf_GetField_V1((const Avtp_CvfV1_t *)pdu, field)
               : Avtp_Cvf_GetField_V0(pdu, field);
}

/**
 * Sets the value of an AVTP CVF field as laid out by version 0. No version
 * dispatch is performed.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param field Specifies the position of the data field to be written
 * @param value The value to set.
 * @see Avtp_Cvf_SetField
 */
OPEN1722_INLINE void Avtp_Cvf_SetField_V0(Avtp_Cvf_t *pdu, Avtp_CvfFields_t field, uint64_t value)
{
    Avtp_SetField(Avtp_CvfFieldDescV0, AVTP_CVF_FIELD_MAX, (uint8_t *)pdu, (uint8_t)field, value);
}

/**
 * Sets the value of an AVTP CVF field as laid out by version 1. No version
 * dispatch is performed.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param field Specifies the position of the data field to be written
 * @param value The value to set.
 * @see Avtp_Cvf_SetField
 */
OPEN1722_INLINE void Avtp_Cvf_SetField_V1(Avtp_CvfV1_t *pdu, Avtp_CvfFields_t field, uint64_t value)
{
    Avtp_SetField(Avtp_CvfFieldDescV1, AVTP_CVF_FIELD_MAX, (uint8_t *)pdu, (uint8_t)field, value);
}

/**
 * Sets the value of an AVTP CVF field, dispatching on the version field of the
 * PDU.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param field Specifies the position of the data field to be written
 * @param value The value to set.
 */
OPEN1722_INLINE void Avtp_Cvf_SetField(Avtp_Cvf_t *pdu, Avtp_CvfFields_t field, uint64_t value)
{
    if (Avtp_CommonStreamHeader_GetVersion((const Avtp_CommonStreamHeader_t *)pdu) ==
        AVTP_VERSION_1) {
        Avtp_Cvf_SetField_V1((Avtp_CvfV1_t *)pdu, field, value);
    } else {
        Avtp_Cvf_SetField_V0(pdu, field, value);
    }
}

/**
 * Returns the length of the version 0 CVF header in octets (24). The PDU
 * pointer is not read; it keeps the signature aligned with the
 * version-dispatched accessors.
 */
OPEN1722_INLINE uint8_t Avtp_Cvf_GetHeaderLen_V0(const Avtp_Cvf_t *const pdu)
{
    (void)pdu;
    return (uint8_t)AVTP_CVF_HEADER_LEN_V0;
}

/**
 * Returns the length of the version 1 CVF header in octets (40). The PDU
 * pointer is not read; it keeps the signature aligned with the
 * version-dispatched accessors.
 */
OPEN1722_INLINE uint8_t Avtp_Cvf_GetHeaderLen_V1(const Avtp_CvfV1_t *const pdu)
{
    (void)pdu;
    return (uint8_t)AVTP_CVF_HEADER_LEN_V1;
}

/**
 * Returns the length of the CVF header in octets (24 or 40), dispatching on the
 * version field of the PDU.
 */
OPEN1722_INLINE uint8_t Avtp_Cvf_GetHeaderLen(const Avtp_Cvf_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetVersion((const Avtp_CommonStreamHeader_t *)pdu) ==
                   AVTP_VERSION_1
               ? Avtp_Cvf_GetHeaderLen_V1((const Avtp_CvfV1_t *)pdu)
               : Avtp_Cvf_GetHeaderLen_V0(pdu);
}

/**
 * Return the value of the CVF SV field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @returns Value of the CVF SV field.
 */
OPEN1722_INLINE bool Avtp_Cvf_IsSv(const Avtp_Cvf_t *const pdu)
{
    return (bool)Avtp_Cvf_GetField(pdu, AVTP_CVF_FIELD_SV);
}

/**
 * Return the value of the CVF MR field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @returns Value of the CVF MR field.
 */
OPEN1722_INLINE bool Avtp_Cvf_IsMr(const Avtp_Cvf_t *const pdu)
{
    return (bool)Avtp_Cvf_GetField(pdu, AVTP_CVF_FIELD_MR);
}

/**
 * Return the value of the CVF TV field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @returns Value of the CVF TV field.
 */
OPEN1722_INLINE bool Avtp_Cvf_IsTv(const Avtp_Cvf_t *const pdu)
{
    return (bool)Avtp_Cvf_GetField(pdu, AVTP_CVF_FIELD_TV);
}

/**
 * Return the value of the CVF Sequence Number field as specified in the IEEE 1722
 * Specification. The field is 8 bits in version 0 and 32 bits in version 1.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @returns Value of the CVF Sequence Number field.
 */
OPEN1722_INLINE uint32_t Avtp_Cvf_GetSequenceNum(const Avtp_Cvf_t *const pdu)
{
    return (uint32_t)Avtp_Cvf_GetField(pdu, AVTP_CVF_FIELD_SEQUENCE_NUM);
}

/**
 * Return the value of the CVF TU field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @returns Value of the CVF TU field.
 */
OPEN1722_INLINE bool Avtp_Cvf_IsTu(const Avtp_Cvf_t *const pdu)
{
    return (bool)Avtp_Cvf_GetField(pdu, AVTP_CVF_FIELD_TU);
}

/**
 * Return the value of the CVF Stream ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @returns Value of the CVF Stream ID field.
 */
OPEN1722_INLINE uint64_t Avtp_Cvf_GetStreamId(const Avtp_Cvf_t *const pdu)
{
    return Avtp_Cvf_GetField(pdu, AVTP_CVF_FIELD_STREAM_ID);
}

/**
 * Return the value of the CVF AVTP Timestamp field as specified in the IEEE 1722
 * Specification. The field is 32 bits in version 0 and 64 bits in version 1.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @returns Value of the CVF AVTP Timestamp field.
 */
OPEN1722_INLINE uint64_t Avtp_Cvf_GetAvtpTimestamp(const Avtp_Cvf_t *const pdu)
{
    return Avtp_Cvf_GetField(pdu, AVTP_CVF_FIELD_AVTP_TIMESTAMP);
}

/**
 * Return the value of the CVF ptp_grandmaster_identity field. The field only
 * exists in version 1; version 0 returns 0.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @returns Value of the CVF ptp_grandmaster_identity field.
 */
OPEN1722_INLINE uint64_t Avtp_Cvf_GetPtpGrandmasterIdentity(const Avtp_Cvf_t *const pdu)
{
    return Avtp_Cvf_GetField(pdu, AVTP_CVF_FIELD_PTP_GRANDMASTER_IDENTITY);
}

/**
 * Return the value of the CVF Format field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @returns Value of the CVF Format field.
 */
OPEN1722_INLINE Avtp_CvfFormat_t Avtp_Cvf_GetFormat(const Avtp_Cvf_t *const pdu)
{
    return (Avtp_CvfFormat_t)Avtp_Cvf_GetField(pdu, AVTP_CVF_FIELD_FORMAT);
}

/**
 * Return the value of the CVF Format Subtype field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @returns Value of the CVF Format Subtype field.
 */
OPEN1722_INLINE Avtp_CvfFormatSubtype_t Avtp_Cvf_GetFormatSubtype(const Avtp_Cvf_t *const pdu)
{
    return (Avtp_CvfFormatSubtype_t)Avtp_Cvf_GetField(pdu, AVTP_CVF_FIELD_FORMAT_SUBTYPE);
}

/**
 * Return the value of the CVF Stream Data Length field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @returns Value of the CVF Stream Data Length field.
 */
OPEN1722_INLINE uint16_t Avtp_Cvf_GetStreamDataLength(const Avtp_Cvf_t *const pdu)
{
    return (uint16_t)Avtp_Cvf_GetField(pdu, AVTP_CVF_FIELD_STREAM_DATA_LENGTH);
}

/**
 * Return the value of the CVF PTV field as specified in the IEEE 1722 Specification.
 * The field is defined for the H.264/H.265 format subtypes.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @returns Value of the CVF PTV field.
 */
OPEN1722_INLINE bool Avtp_Cvf_IsPtv(const Avtp_Cvf_t *const pdu)
{
    return (bool)Avtp_Cvf_GetField(pdu, AVTP_CVF_FIELD_PTV);
}

/**
 * Return the value of the CVF M field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @returns Value of the CVF M field.
 */
OPEN1722_INLINE bool Avtp_Cvf_IsM(const Avtp_Cvf_t *const pdu)
{
    return (bool)Avtp_Cvf_GetField(pdu, AVTP_CVF_FIELD_M);
}

/**
 * Return the value of the CVF EVT field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @returns Value of the CVF EVT field.
 */
OPEN1722_INLINE uint8_t Avtp_Cvf_GetEvt(const Avtp_Cvf_t *const pdu)
{
    return (uint8_t)Avtp_Cvf_GetField(pdu, AVTP_CVF_FIELD_EVT);
}

/**
 * Set the SV bit in a CVF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param sv Value to set the CVF SV field to.
 */
OPEN1722_INLINE void Avtp_Cvf_SetSv(Avtp_Cvf_t *pdu, bool sv)
{
    Avtp_Cvf_SetField(pdu, AVTP_CVF_FIELD_SV, sv);
}

/**
 * Set the MR bit in a CVF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param mr Value to set the CVF MR field to.
 */
OPEN1722_INLINE void Avtp_Cvf_SetMr(Avtp_Cvf_t *pdu, bool mr)
{
    Avtp_Cvf_SetField(pdu, AVTP_CVF_FIELD_MR, mr);
}

/**
 * Set the TV bit in a CVF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param tv Value to set the CVF TV field to.
 */
OPEN1722_INLINE void Avtp_Cvf_SetTv(Avtp_Cvf_t *pdu, bool tv)
{
    Avtp_Cvf_SetField(pdu, AVTP_CVF_FIELD_TV, tv);
}

/**
 * Set the value of the CVF Sequence Number field as specified in the IEEE 1722
 * Specification. The field is 8 bits in version 0 and 32 bits in version 1; values are
 * truncated to the width of the version in use.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param value Value to set the CVF Sequence Number field to.
 */
OPEN1722_INLINE void Avtp_Cvf_SetSequenceNum(Avtp_Cvf_t *pdu, uint32_t value)
{
    Avtp_Cvf_SetField(pdu, AVTP_CVF_FIELD_SEQUENCE_NUM, value);
}

/**
 * Set the TU bit in a CVF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param tu Value to set the CVF TU field to.
 */
OPEN1722_INLINE void Avtp_Cvf_SetTu(Avtp_Cvf_t *pdu, bool tu)
{
    Avtp_Cvf_SetField(pdu, AVTP_CVF_FIELD_TU, tu);
}

/**
 * Set the value of the CVF Stream ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param value Value to set the CVF Stream ID field to.
 */
OPEN1722_INLINE void Avtp_Cvf_SetStreamId(Avtp_Cvf_t *pdu, uint64_t value)
{
    Avtp_Cvf_SetField(pdu, AVTP_CVF_FIELD_STREAM_ID, value);
}

/**
 * Set the value of the CVF AVTP Timestamp field as specified in the IEEE 1722
 * Specification. The field is 32 bits in version 0 and 64 bits in version 1; values are
 * truncated to the width of the version in use.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param value Value to set the CVF AVTP Timestamp field to.
 */
OPEN1722_INLINE void Avtp_Cvf_SetAvtpTimestamp(Avtp_Cvf_t *pdu, uint64_t value)
{
    Avtp_Cvf_SetField(pdu, AVTP_CVF_FIELD_AVTP_TIMESTAMP, value);
}

/**
 * Set the value of the CVF ptp_grandmaster_identity field. The field only
 * exists in version 1; on version 0 this is a no-op.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param value Value to set the CVF ptp_grandmaster_identity field to.
 */
OPEN1722_INLINE void Avtp_Cvf_SetPtpGrandmasterIdentity(Avtp_Cvf_t *pdu, uint64_t value)
{
    Avtp_Cvf_SetField(pdu, AVTP_CVF_FIELD_PTP_GRANDMASTER_IDENTITY, value);
}

/**
 * Set the value of the CVF Format field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param value Value to set the CVF Format field to.
 */
OPEN1722_INLINE void Avtp_Cvf_SetFormat(Avtp_Cvf_t *pdu, Avtp_CvfFormat_t value)
{
    Avtp_Cvf_SetField(pdu, AVTP_CVF_FIELD_FORMAT, (uint64_t)value);
}

/**
 * Set the value of the CVF Format Subtype field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param value Value to set the CVF Format Subtype field to.
 */
OPEN1722_INLINE void Avtp_Cvf_SetFormatSubtype(Avtp_Cvf_t *pdu, Avtp_CvfFormatSubtype_t value)
{
    Avtp_Cvf_SetField(pdu, AVTP_CVF_FIELD_FORMAT_SUBTYPE, (uint64_t)value);
}

/**
 * Set the value of the CVF Stream Data Length field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param value Value to set the CVF Stream Data Length field to.
 */
OPEN1722_INLINE void Avtp_Cvf_SetStreamDataLength(Avtp_Cvf_t *pdu, uint16_t value)
{
    Avtp_Cvf_SetField(pdu, AVTP_CVF_FIELD_STREAM_DATA_LENGTH, value);
}

/**
 * Set the PTV bit in a CVF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param ptv Value to set the CVF PTV field to.
 */
OPEN1722_INLINE void Avtp_Cvf_SetPtv(Avtp_Cvf_t *pdu, bool ptv)
{
    Avtp_Cvf_SetField(pdu, AVTP_CVF_FIELD_PTV, ptv);
}

/**
 * Set the M bit in a CVF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param m Value to set the CVF M field to.
 */
OPEN1722_INLINE void Avtp_Cvf_SetM(Avtp_Cvf_t *pdu, bool m)
{
    Avtp_Cvf_SetField(pdu, AVTP_CVF_FIELD_M, m);
}

/**
 * Set the value of the CVF EVT field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param value Value to set the CVF EVT field to.
 */
OPEN1722_INLINE void Avtp_Cvf_SetEvt(Avtp_Cvf_t *pdu, uint8_t value)
{
    Avtp_Cvf_SetField(pdu, AVTP_CVF_FIELD_EVT, value);
}

/**
 * Returns a pointer to the stream data of a version 0 CVF frame.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @return Pointer to CVF stream data
 * @see Avtp_Cvf_GetPayload
 */
OPEN1722_INLINE const uint8_t *Avtp_Cvf_GetPayload_V0(const Avtp_Cvf_t *const pdu)
{
    return (const uint8_t *)pdu + AVTP_CVF_HEADER_LEN_V0;
}

/**
 * Returns a pointer to the stream data of a version 1 CVF frame.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @return Pointer to CVF stream data
 * @see Avtp_Cvf_GetPayload
 */
OPEN1722_INLINE const uint8_t *Avtp_Cvf_GetPayload_V1(const Avtp_CvfV1_t *const pdu)
{
    return (const uint8_t *)pdu + AVTP_CVF_HEADER_LEN_V1;
}

/**
 * Returns pointer to the CVF stream data. The stream data starts after the
 * version-dependent common stream header.
 *
 * The stream data contains the format-specific header (e.g. the MJPEG or
 * H.264 header) followed by the video payload.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @return Pointer to CVF stream data
 */
OPEN1722_INLINE const uint8_t *Avtp_Cvf_GetPayload(const Avtp_Cvf_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetVersion((const Avtp_CommonStreamHeader_t *)pdu) ==
                   AVTP_VERSION_1
               ? Avtp_Cvf_GetPayload_V1((const Avtp_CvfV1_t *)pdu)
               : Avtp_Cvf_GetPayload_V0(pdu);
}

/**
 * Sets the stream data of a version 0 CVF frame.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload
 * @see Avtp_Cvf_SetPayload
 */
OPEN1722_INLINE void Avtp_Cvf_SetPayload_V0(Avtp_Cvf_t *pdu, uint8_t *payload,
                                            uint16_t payload_length)
{
    memcpy((uint8_t *)pdu + AVTP_CVF_HEADER_LEN_V0, payload, payload_length);
}

/**
 * Sets the stream data of a version 1 CVF frame.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload
 * @see Avtp_Cvf_SetPayload
 */
OPEN1722_INLINE void Avtp_Cvf_SetPayload_V1(Avtp_CvfV1_t *pdu, uint8_t *payload,
                                            uint16_t payload_length)
{
    memcpy((uint8_t *)pdu + AVTP_CVF_HEADER_LEN_V1, payload, payload_length);
}

/**
 * Sets the stream data of a CVF frame.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload
 */
OPEN1722_INLINE void Avtp_Cvf_SetPayload(Avtp_Cvf_t *pdu, uint8_t *payload, uint16_t payload_length)
{
    if (Avtp_CommonStreamHeader_GetVersion((const Avtp_CommonStreamHeader_t *)pdu) ==
        AVTP_VERSION_1) {
        Avtp_Cvf_SetPayload_V1((Avtp_CvfV1_t *)pdu, payload, payload_length);
    } else {
        Avtp_Cvf_SetPayload_V0(pdu, payload, payload_length);
    }
}

/**
 * Initializes a version 0 CVF PDU as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of a 1722 CVF PDU.
 */
OPEN1722_INLINE void Avtp_Cvf_Init(Avtp_Cvf_t *pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_Cvf_t));
        Avtp_CommonHeader_SetSubtype((Avtp_CommonHeader_t *)pdu, AVTP_SUBTYPE_CVF);
        Avtp_Cvf_SetFormat(pdu, AVTP_CVF_FORMAT_RFC);
        Avtp_Cvf_SetSv(pdu, true);
    }
}

/**
 * Initializes a version 1 CVF PDU. The caller must provide a buffer of at least
 * AVTP_CVF_HEADER_LEN_V1 octets.
 *
 * @param pdu Pointer to the first bit of a 1722 CVF PDU.
 */
OPEN1722_INLINE void Avtp_Cvf_InitV1(Avtp_CvfV1_t *pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_CvfV1_t));
        Avtp_CommonHeader_SetSubtype((Avtp_CommonHeader_t *)pdu, AVTP_SUBTYPE_CVF);
        Avtp_CommonHeader_SetVersion((Avtp_CommonHeader_t *)pdu, AVTP_VERSION_1);
        Avtp_Cvf_SetFormat((Avtp_Cvf_t *)pdu, AVTP_CVF_FORMAT_RFC);
        Avtp_Cvf_SetSv((Avtp_Cvf_t *)pdu, true);
    }
}

/**
 * Checks if the CVF frame is valid by checking:
 *     1) that the subtype is CVF and the version is supported,
 *     2) that the version-dependent header fits into the buffer,
 *     3) that the declared stream_data_length fits into the buffer.
 *
 * The stream_data_length field contains the length (in octets) of the
 * video_data_payload field (IEEE 1722-2025, 4.7.4.12), which includes the
 * format-specific header, so the whole AVTPDU must fit into bufferSize.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param bufferSize Size of the buffer containing the CVF frame.
 * @return true if the CVF frame is valid, false otherwise.
 */
OPEN1722_INLINE bool Avtp_Cvf_IsValid(const Avtp_Cvf_t *const pdu, size_t bufferSize)
{
    if (pdu == NULL) {
        return false;
    }

    if (Avtp_CommonHeader_GetSubtype((const Avtp_CommonHeader_t *)pdu) != AVTP_SUBTYPE_CVF) {
        return false;
    }

    uint8_t version = Avtp_CommonStreamHeader_GetVersion((const Avtp_CommonStreamHeader_t *)pdu);
    if (!Avtp_Version_IsSupported(AVTP_CVF_SUPPORTED_VERSIONS, version)) {
        return false;
    }

    size_t headerLen = Avtp_Cvf_GetHeaderLen(pdu);
    if (bufferSize < headerLen) {
        return false;
    }

    if ((size_t)Avtp_Cvf_GetStreamDataLength(pdu) > bufferSize - headerLen) {
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
 * Version 0 variant of Avtp_Cvf_IsSv().
 * @see Avtp_Cvf_IsSv
 */
OPEN1722_INLINE bool Avtp_Cvf_IsSv_V0(const Avtp_Cvf_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsSv_V0((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Cvf_IsSv().
 * @see Avtp_Cvf_IsSv
 */
OPEN1722_INLINE bool Avtp_Cvf_IsSv_V1(const Avtp_CvfV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsSv_V1((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Cvf_IsMr().
 * @see Avtp_Cvf_IsMr
 */
OPEN1722_INLINE bool Avtp_Cvf_IsMr_V0(const Avtp_Cvf_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsMr_V0((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Cvf_IsMr().
 * @see Avtp_Cvf_IsMr
 */
OPEN1722_INLINE bool Avtp_Cvf_IsMr_V1(const Avtp_CvfV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsMr_V1((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Cvf_IsTv().
 * @see Avtp_Cvf_IsTv
 */
OPEN1722_INLINE bool Avtp_Cvf_IsTv_V0(const Avtp_Cvf_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsTv_V0((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Cvf_IsTv().
 * @see Avtp_Cvf_IsTv
 */
OPEN1722_INLINE bool Avtp_Cvf_IsTv_V1(const Avtp_CvfV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsTv_V1((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Cvf_IsTu().
 * @see Avtp_Cvf_IsTu
 */
OPEN1722_INLINE bool Avtp_Cvf_IsTu_V0(const Avtp_Cvf_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsTu_V0((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Cvf_IsTu().
 * @see Avtp_Cvf_IsTu
 */
OPEN1722_INLINE bool Avtp_Cvf_IsTu_V1(const Avtp_CvfV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsTu_V1((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Cvf_GetSequenceNum(). Values are truncated to the
 * 8-bit version 0 field width.
 * @see Avtp_Cvf_GetSequenceNum
 */
OPEN1722_INLINE uint32_t Avtp_Cvf_GetSequenceNum_V0(const Avtp_Cvf_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetSequenceNum_V0((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Cvf_GetSequenceNum().
 * @see Avtp_Cvf_GetSequenceNum
 */
OPEN1722_INLINE uint32_t Avtp_Cvf_GetSequenceNum_V1(const Avtp_CvfV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetSequenceNum_V1((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Cvf_GetStreamId().
 * @see Avtp_Cvf_GetStreamId
 */
OPEN1722_INLINE uint64_t Avtp_Cvf_GetStreamId_V0(const Avtp_Cvf_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetStreamId_V0((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Cvf_GetStreamId().
 * @see Avtp_Cvf_GetStreamId
 */
OPEN1722_INLINE uint64_t Avtp_Cvf_GetStreamId_V1(const Avtp_CvfV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetStreamId_V1((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Cvf_GetAvtpTimestamp().
 * @see Avtp_Cvf_GetAvtpTimestamp
 */
OPEN1722_INLINE uint64_t Avtp_Cvf_GetAvtpTimestamp_V0(const Avtp_Cvf_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetAvtpTimestamp_V0((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Cvf_GetAvtpTimestamp().
 * @see Avtp_Cvf_GetAvtpTimestamp
 */
OPEN1722_INLINE uint64_t Avtp_Cvf_GetAvtpTimestamp_V1(const Avtp_CvfV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetAvtpTimestamp_V1((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Cvf_GetPtpGrandmasterIdentity(). The field is
 * absent from version 0, so this always returns 0.
 * @see Avtp_Cvf_GetPtpGrandmasterIdentity
 */
OPEN1722_INLINE uint64_t Avtp_Cvf_GetPtpGrandmasterIdentity_V0(const Avtp_Cvf_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetPtpGrandmasterIdentity_V0(
        (const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Cvf_GetPtpGrandmasterIdentity().
 * @see Avtp_Cvf_GetPtpGrandmasterIdentity
 */
OPEN1722_INLINE uint64_t Avtp_Cvf_GetPtpGrandmasterIdentity_V1(const Avtp_CvfV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetPtpGrandmasterIdentity_V1(
        (const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Cvf_GetFormat().
 * @see Avtp_Cvf_GetFormat
 */
OPEN1722_INLINE Avtp_CvfFormat_t Avtp_Cvf_GetFormat_V0(const Avtp_Cvf_t *const pdu)
{
    return (Avtp_CvfFormat_t)Avtp_Cvf_GetField_V0(pdu, AVTP_CVF_FIELD_FORMAT);
}

/**
 * Version 1 variant of Avtp_Cvf_GetFormat().
 * @see Avtp_Cvf_GetFormat
 */
OPEN1722_INLINE Avtp_CvfFormat_t Avtp_Cvf_GetFormat_V1(const Avtp_CvfV1_t *const pdu)
{
    return (Avtp_CvfFormat_t)Avtp_Cvf_GetField_V1(pdu, AVTP_CVF_FIELD_FORMAT);
}

/**
 * Version 0 variant of Avtp_Cvf_GetFormatSubtype().
 * @see Avtp_Cvf_GetFormatSubtype
 */
OPEN1722_INLINE Avtp_CvfFormatSubtype_t Avtp_Cvf_GetFormatSubtype_V0(const Avtp_Cvf_t *const pdu)
{
    return (Avtp_CvfFormatSubtype_t)Avtp_Cvf_GetField_V0(pdu, AVTP_CVF_FIELD_FORMAT_SUBTYPE);
}

/**
 * Version 1 variant of Avtp_Cvf_GetFormatSubtype().
 * @see Avtp_Cvf_GetFormatSubtype
 */
OPEN1722_INLINE Avtp_CvfFormatSubtype_t Avtp_Cvf_GetFormatSubtype_V1(const Avtp_CvfV1_t *const pdu)
{
    return (Avtp_CvfFormatSubtype_t)Avtp_Cvf_GetField_V1(pdu, AVTP_CVF_FIELD_FORMAT_SUBTYPE);
}

/**
 * Version 0 variant of Avtp_Cvf_GetStreamDataLength().
 * @see Avtp_Cvf_GetStreamDataLength
 */
OPEN1722_INLINE uint16_t Avtp_Cvf_GetStreamDataLength_V0(const Avtp_Cvf_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetStreamDataLength_V0((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Cvf_GetStreamDataLength().
 * @see Avtp_Cvf_GetStreamDataLength
 */
OPEN1722_INLINE uint16_t Avtp_Cvf_GetStreamDataLength_V1(const Avtp_CvfV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetStreamDataLength_V1((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Cvf_IsPtv().
 * @see Avtp_Cvf_IsPtv
 */
OPEN1722_INLINE bool Avtp_Cvf_IsPtv_V0(const Avtp_Cvf_t *const pdu)
{
    return (bool)Avtp_Cvf_GetField_V0(pdu, AVTP_CVF_FIELD_PTV);
}

/**
 * Version 1 variant of Avtp_Cvf_IsPtv().
 * @see Avtp_Cvf_IsPtv
 */
OPEN1722_INLINE bool Avtp_Cvf_IsPtv_V1(const Avtp_CvfV1_t *const pdu)
{
    return (bool)Avtp_Cvf_GetField_V1(pdu, AVTP_CVF_FIELD_PTV);
}

/**
 * Version 0 variant of Avtp_Cvf_IsM().
 * @see Avtp_Cvf_IsM
 */
OPEN1722_INLINE bool Avtp_Cvf_IsM_V0(const Avtp_Cvf_t *const pdu)
{
    return (bool)Avtp_Cvf_GetField_V0(pdu, AVTP_CVF_FIELD_M);
}

/**
 * Version 1 variant of Avtp_Cvf_IsM().
 * @see Avtp_Cvf_IsM
 */
OPEN1722_INLINE bool Avtp_Cvf_IsM_V1(const Avtp_CvfV1_t *const pdu)
{
    return (bool)Avtp_Cvf_GetField_V1(pdu, AVTP_CVF_FIELD_M);
}

/**
 * Version 0 variant of Avtp_Cvf_GetEvt().
 * @see Avtp_Cvf_GetEvt
 */
OPEN1722_INLINE uint8_t Avtp_Cvf_GetEvt_V0(const Avtp_Cvf_t *const pdu)
{
    return (uint8_t)Avtp_Cvf_GetField_V0(pdu, AVTP_CVF_FIELD_EVT);
}

/**
 * Version 1 variant of Avtp_Cvf_GetEvt().
 * @see Avtp_Cvf_GetEvt
 */
OPEN1722_INLINE uint8_t Avtp_Cvf_GetEvt_V1(const Avtp_CvfV1_t *const pdu)
{
    return (uint8_t)Avtp_Cvf_GetField_V1(pdu, AVTP_CVF_FIELD_EVT);
}

/**
 * Version 0 variant of Avtp_Cvf_SetSv().
 * @see Avtp_Cvf_SetSv
 */
OPEN1722_INLINE void Avtp_Cvf_SetSv_V0(Avtp_Cvf_t *pdu, bool sv)
{
    Avtp_CommonStreamHeader_SetSv_V0((Avtp_CommonStreamHeader_t *)pdu, sv);
}

/**
 * Version 1 variant of Avtp_Cvf_SetSv().
 * @see Avtp_Cvf_SetSv
 */
OPEN1722_INLINE void Avtp_Cvf_SetSv_V1(Avtp_CvfV1_t *pdu, bool sv)
{
    Avtp_CommonStreamHeader_SetSv_V1((Avtp_CommonStreamHeader_t *)pdu, sv);
}

/**
 * Version 0 variant of Avtp_Cvf_SetMr().
 * @see Avtp_Cvf_SetMr
 */
OPEN1722_INLINE void Avtp_Cvf_SetMr_V0(Avtp_Cvf_t *pdu, bool mr)
{
    Avtp_CommonStreamHeader_SetMr_V0((Avtp_CommonStreamHeader_t *)pdu, mr);
}

/**
 * Version 1 variant of Avtp_Cvf_SetMr().
 * @see Avtp_Cvf_SetMr
 */
OPEN1722_INLINE void Avtp_Cvf_SetMr_V1(Avtp_CvfV1_t *pdu, bool mr)
{
    Avtp_CommonStreamHeader_SetMr_V1((Avtp_CommonStreamHeader_t *)pdu, mr);
}

/**
 * Version 0 variant of Avtp_Cvf_SetTv().
 * @see Avtp_Cvf_SetTv
 */
OPEN1722_INLINE void Avtp_Cvf_SetTv_V0(Avtp_Cvf_t *pdu, bool tv)
{
    Avtp_CommonStreamHeader_SetTv_V0((Avtp_CommonStreamHeader_t *)pdu, tv);
}

/**
 * Version 1 variant of Avtp_Cvf_SetTv().
 * @see Avtp_Cvf_SetTv
 */
OPEN1722_INLINE void Avtp_Cvf_SetTv_V1(Avtp_CvfV1_t *pdu, bool tv)
{
    Avtp_CommonStreamHeader_SetTv_V1((Avtp_CommonStreamHeader_t *)pdu, tv);
}

/**
 * Version 0 variant of Avtp_Cvf_SetTu().
 * @see Avtp_Cvf_SetTu
 */
OPEN1722_INLINE void Avtp_Cvf_SetTu_V0(Avtp_Cvf_t *pdu, bool tu)
{
    Avtp_CommonStreamHeader_SetTu_V0((Avtp_CommonStreamHeader_t *)pdu, tu);
}

/**
 * Version 1 variant of Avtp_Cvf_SetTu().
 * @see Avtp_Cvf_SetTu
 */
OPEN1722_INLINE void Avtp_Cvf_SetTu_V1(Avtp_CvfV1_t *pdu, bool tu)
{
    Avtp_CommonStreamHeader_SetTu_V1((Avtp_CommonStreamHeader_t *)pdu, tu);
}

/**
 * Version 0 variant of Avtp_Cvf_SetSequenceNum(). Values are truncated to the
 * 8-bit version 0 field width.
 * @see Avtp_Cvf_SetSequenceNum
 */
OPEN1722_INLINE void Avtp_Cvf_SetSequenceNum_V0(Avtp_Cvf_t *pdu, uint32_t value)
{
    Avtp_CommonStreamHeader_SetSequenceNum_V0((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 1 variant of Avtp_Cvf_SetSequenceNum().
 * @see Avtp_Cvf_SetSequenceNum
 */
OPEN1722_INLINE void Avtp_Cvf_SetSequenceNum_V1(Avtp_CvfV1_t *pdu, uint32_t value)
{
    Avtp_CommonStreamHeader_SetSequenceNum_V1((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 0 variant of Avtp_Cvf_SetStreamId().
 * @see Avtp_Cvf_SetStreamId
 */
OPEN1722_INLINE void Avtp_Cvf_SetStreamId_V0(Avtp_Cvf_t *pdu, uint64_t value)
{
    Avtp_CommonStreamHeader_SetStreamId_V0((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 1 variant of Avtp_Cvf_SetStreamId().
 * @see Avtp_Cvf_SetStreamId
 */
OPEN1722_INLINE void Avtp_Cvf_SetStreamId_V1(Avtp_CvfV1_t *pdu, uint64_t value)
{
    Avtp_CommonStreamHeader_SetStreamId_V1((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 0 variant of Avtp_Cvf_SetAvtpTimestamp().
 * @see Avtp_Cvf_SetAvtpTimestamp
 */
OPEN1722_INLINE void Avtp_Cvf_SetAvtpTimestamp_V0(Avtp_Cvf_t *pdu, uint64_t value)
{
    Avtp_CommonStreamHeader_SetAvtpTimestamp_V0((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 1 variant of Avtp_Cvf_SetAvtpTimestamp().
 * @see Avtp_Cvf_SetAvtpTimestamp
 */
OPEN1722_INLINE void Avtp_Cvf_SetAvtpTimestamp_V1(Avtp_CvfV1_t *pdu, uint64_t value)
{
    Avtp_CommonStreamHeader_SetAvtpTimestamp_V1((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 0 variant of Avtp_Cvf_SetPtpGrandmasterIdentity(). The field is
 * absent from version 0, so this is a no-op.
 * @see Avtp_Cvf_SetPtpGrandmasterIdentity
 */
OPEN1722_INLINE void Avtp_Cvf_SetPtpGrandmasterIdentity_V0(Avtp_Cvf_t *pdu, uint64_t value)
{
    Avtp_CommonStreamHeader_SetPtpGrandmasterIdentity_V0((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 1 variant of Avtp_Cvf_SetPtpGrandmasterIdentity().
 * @see Avtp_Cvf_SetPtpGrandmasterIdentity
 */
OPEN1722_INLINE void Avtp_Cvf_SetPtpGrandmasterIdentity_V1(Avtp_CvfV1_t *pdu, uint64_t value)
{
    Avtp_CommonStreamHeader_SetPtpGrandmasterIdentity_V1((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 0 variant of Avtp_Cvf_SetFormat().
 * @see Avtp_Cvf_SetFormat
 */
OPEN1722_INLINE void Avtp_Cvf_SetFormat_V0(Avtp_Cvf_t *pdu, Avtp_CvfFormat_t value)
{
    Avtp_Cvf_SetField_V0(pdu, AVTP_CVF_FIELD_FORMAT, (uint64_t)value);
}

/**
 * Version 1 variant of Avtp_Cvf_SetFormat().
 * @see Avtp_Cvf_SetFormat
 */
OPEN1722_INLINE void Avtp_Cvf_SetFormat_V1(Avtp_CvfV1_t *pdu, Avtp_CvfFormat_t value)
{
    Avtp_Cvf_SetField_V1(pdu, AVTP_CVF_FIELD_FORMAT, (uint64_t)value);
}

/**
 * Version 0 variant of Avtp_Cvf_SetFormatSubtype().
 * @see Avtp_Cvf_SetFormatSubtype
 */
OPEN1722_INLINE void Avtp_Cvf_SetFormatSubtype_V0(Avtp_Cvf_t *pdu, Avtp_CvfFormatSubtype_t value)
{
    Avtp_Cvf_SetField_V0(pdu, AVTP_CVF_FIELD_FORMAT_SUBTYPE, (uint64_t)value);
}

/**
 * Version 1 variant of Avtp_Cvf_SetFormatSubtype().
 * @see Avtp_Cvf_SetFormatSubtype
 */
OPEN1722_INLINE void Avtp_Cvf_SetFormatSubtype_V1(Avtp_CvfV1_t *pdu, Avtp_CvfFormatSubtype_t value)
{
    Avtp_Cvf_SetField_V1(pdu, AVTP_CVF_FIELD_FORMAT_SUBTYPE, (uint64_t)value);
}

/**
 * Version 0 variant of Avtp_Cvf_SetStreamDataLength().
 * @see Avtp_Cvf_SetStreamDataLength
 */
OPEN1722_INLINE void Avtp_Cvf_SetStreamDataLength_V0(Avtp_Cvf_t *pdu, uint16_t value)
{
    Avtp_CommonStreamHeader_SetStreamDataLength_V0((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 1 variant of Avtp_Cvf_SetStreamDataLength().
 * @see Avtp_Cvf_SetStreamDataLength
 */
OPEN1722_INLINE void Avtp_Cvf_SetStreamDataLength_V1(Avtp_CvfV1_t *pdu, uint16_t value)
{
    Avtp_CommonStreamHeader_SetStreamDataLength_V1((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 0 variant of Avtp_Cvf_SetPtv().
 * @see Avtp_Cvf_SetPtv
 */
OPEN1722_INLINE void Avtp_Cvf_SetPtv_V0(Avtp_Cvf_t *pdu, bool ptv)
{
    Avtp_Cvf_SetField_V0(pdu, AVTP_CVF_FIELD_PTV, ptv);
}

/**
 * Version 1 variant of Avtp_Cvf_SetPtv().
 * @see Avtp_Cvf_SetPtv
 */
OPEN1722_INLINE void Avtp_Cvf_SetPtv_V1(Avtp_CvfV1_t *pdu, bool ptv)
{
    Avtp_Cvf_SetField_V1(pdu, AVTP_CVF_FIELD_PTV, ptv);
}

/**
 * Version 0 variant of Avtp_Cvf_SetM().
 * @see Avtp_Cvf_SetM
 */
OPEN1722_INLINE void Avtp_Cvf_SetM_V0(Avtp_Cvf_t *pdu, bool m)
{
    Avtp_Cvf_SetField_V0(pdu, AVTP_CVF_FIELD_M, m);
}

/**
 * Version 1 variant of Avtp_Cvf_SetM().
 * @see Avtp_Cvf_SetM
 */
OPEN1722_INLINE void Avtp_Cvf_SetM_V1(Avtp_CvfV1_t *pdu, bool m)
{
    Avtp_Cvf_SetField_V1(pdu, AVTP_CVF_FIELD_M, m);
}

/**
 * Version 0 variant of Avtp_Cvf_SetEvt().
 * @see Avtp_Cvf_SetEvt
 */
OPEN1722_INLINE void Avtp_Cvf_SetEvt_V0(Avtp_Cvf_t *pdu, uint8_t value)
{
    Avtp_Cvf_SetField_V0(pdu, AVTP_CVF_FIELD_EVT, value);
}

/**
 * Version 1 variant of Avtp_Cvf_SetEvt().
 * @see Avtp_Cvf_SetEvt
 */
OPEN1722_INLINE void Avtp_Cvf_SetEvt_V1(Avtp_CvfV1_t *pdu, uint8_t value)
{
    Avtp_Cvf_SetField_V1(pdu, AVTP_CVF_FIELD_EVT, value);
}

#ifdef __cplusplus
}
#endif
