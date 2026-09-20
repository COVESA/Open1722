/*
 * Copyright (c) 2024, COVESA
 * Copyright (c) 2021, Fastree3D
 * Adrian Fiergolski <Adrian.Fiergolski@fastree3d.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of Fastree3D, COVESA nor the names of their
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
 * This file contains the fields descriptions of the IEEE 1722 RVF PDUs and
 * functions to invoke corresponding parser and deparser.
 *
 * RVF uses the AVTPDU common stream header (4.7.4) and declares a complete
 * descriptor table per version in absolute coordinates: the common stream
 * header fields reuse the positions from CommonStreamHeader.h and the
 * RVF-specific fields are added by this module. A consistency test keeps the
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

#define AVTP_RVF_HEADER_LEN_V0 AVTPDU_CSH_LEN_V0 /* 24 */
#define AVTP_RVF_HEADER_LEN_V1 AVTPDU_CSH_LEN_V1 /* 40 */
/* Kept for compatibility: the version 0 header length. */
#define AVTP_RVF_HEADER_LEN AVTP_RVF_HEADER_LEN_V0
#define AVTP_RVF_RAW_HEADER_LEN (2 * AVTP_QUADLET_SIZE)

/* RVF supports both versions of the common stream header (Table 7). */
#define AVTP_RVF_SUPPORTED_VERSIONS ((1u << AVTP_VERSION_0) | (1u << AVTP_VERSION_1))

typedef struct {
    uint8_t header[AVTP_RVF_HEADER_LEN_V0];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_Rvf_t;

typedef struct {
    uint8_t header[AVTP_RVF_HEADER_LEN_V1];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_RvfV1_t;

typedef enum Avtp_RvfPixelDepth {
    AVTP_RVF_PIXEL_DEPTH_8 = 0x01,
    AVTP_RVF_PIXEL_DEPTH_10 = 0x02,
    AVTP_RVF_PIXEL_DEPTH_12 = 0x03,
    AVTP_RVF_PIXEL_DEPTH_16 = 0x04,
    AVTP_RVF_PIXEL_DEPTH_USER = 0x0F
} Avtp_RvfPixelDepth_t;

typedef enum Avtp_RvfPixelFormat {
    AVTP_RVF_PIXEL_FORMAT_MONO = 0x00,
    AVTP_RVF_PIXEL_FORMAT_411 = 0x01,
    AVTP_RVF_PIXEL_FORMAT_420 = 0x02,
    AVTP_RVF_PIXEL_FORMAT_422 = 0x03,
    AVTP_RVF_PIXEL_FORMAT_444 = 0x04,
    AVTP_RVF_PIXEL_FORMAT_4224 = 0x06,
    AVTP_RVF_PIXEL_FORMAT_4444 = 0x07,
    AVTP_RVF_PIXEL_FORMAT_BAYER_GRBG = 0x08,
    AVTP_RVF_PIXEL_FORMAT_BAYER_RGGB = 0x09,
    AVTP_RVF_PIXEL_FORMAT_BAYER_BGGR = 0x0A,
    AVTP_RVF_PIXEL_FORMAT_BAYER_GBRG = 0x0B,
    AVTP_RVF_PIXEL_FORMAT_USER = 0x0F
} Avtp_RvfPixelFormat_t;

typedef enum Avtp_RvfFrameRate {
    AVTP_RVF_FRAME_RATE_1 = 0x01,
    AVTP_RVF_FRAME_RATE_2 = 0x02,
    AVTP_RVF_FRAME_RATE_5 = 0x03,
    AVTP_RVF_FRAME_RATE_10 = 0x10,
    AVTP_RVF_FRAME_RATE_15 = 0x11,
    AVTP_RVF_FRAME_RATE_20 = 0x12,
    AVTP_RVF_FRAME_RATE_24 = 0x13,
    AVTP_RVF_FRAME_RATE_25 = 0x14,
    AVTP_RVF_FRAME_RATE_30 = 0x15,
    AVTP_RVF_FRAME_RATE_48 = 0x16,
    AVTP_RVF_FRAME_RATE_50 = 0x17,
    AVTP_RVF_FRAME_RATE_60 = 0x18,
    AVTP_RVF_FRAME_RATE_72 = 0x19,
    AVTP_RVF_FRAME_RATE_85 = 0x1A,
    AVTP_RVF_FRAME_RATE_100 = 0x30,
    AVTP_RVF_FRAME_RATE_120 = 0x31,
    AVTP_RVF_FRAME_RATE_150 = 0x32,
    AVTP_RVF_FRAME_RATE_200 = 0x33,
    AVTP_RVF_FRAME_RATE_240 = 0x34,
    AVTP_RVF_FRAME_RATE_300 = 0x35,
    AVTP_RVF_FRAME_RATE_USER = 0xFF
} Avtp_RvfFrameRate_t;

/* RVF 'colorspace' field values. */
typedef enum Avtp_RvfColorspace {
    AVTP_RVF_COLORSPACE_YCbCr = 0x01,
    AVTP_RVF_COLORSPACE_SRGB = 0x02,
    AVTP_RVF_COLORSPACE_YCgCo = 0x03,
    AVTP_RVF_COLORSPACE_GRAY = 0x04,
    AVTP_RVF_COLORSPACE_XYZ = 0x05,
    AVTP_RVF_COLORSPACE_YCM = 0x06,
    AVTP_RVF_COLORSPACE_BT_601 = 0x07,
    AVTP_RVF_COLORSPACE_BT_709 = 0x08,
    AVTP_RVF_COLORSPACE_ITU_BT = 0x09,
    AVTP_RVF_COLORSPACE_USER = 0x0F
} Avtp_RvfColorspace_t;

typedef enum {

    /* Common AVTP stream header fields */
    AVTP_RVF_FIELD_SV = 0,
    AVTP_RVF_FIELD_MR,
    AVTP_RVF_FIELD_FSD,
    AVTP_RVF_FIELD_TV,
    AVTP_RVF_FIELD_SEQUENCE_NUM,
    AVTP_RVF_FIELD_FSD0,
    AVTP_RVF_FIELD_FSD1,
    AVTP_RVF_FIELD_TU,
    AVTP_RVF_FIELD_STREAM_ID,
    AVTP_RVF_FIELD_AVTP_TIMESTAMP,
    AVTP_RVF_FIELD_PTP_GRANDMASTER_IDENTITY,
    AVTP_RVF_FIELD_STREAM_DATA_LENGTH,

    /* RVF format-specific fields */
    AVTP_RVF_FIELD_ACTIVE_PIXELS,
    AVTP_RVF_FIELD_TOTAL_LINES,
    AVTP_RVF_FIELD_AP,
    AVTP_RVF_FIELD_R,
    AVTP_RVF_FIELD_F,
    AVTP_RVF_FIELD_EF,
    AVTP_RVF_FIELD_EVT,
    AVTP_RVF_FIELD_PD,
    AVTP_RVF_FIELD_I,
    AVTP_RVF_FIELD_RESERVED2,

    /* Count number of fields for bound checks */
    AVTP_RVF_FIELD_MAX
} Avtp_RvfFields_t;

/**
 * This table maps all IEEE 1722 RVF header fields to a descriptor for version 0.
 * It is complete and in absolute coordinates; the common stream header fields
 * use the same positions as Avtp_CshFieldDescV0.
 */
static const Avtp_FieldDescriptor_t Avtp_RvfFieldDescV0[AVTP_RVF_FIELD_MAX] = {
    [AVTP_RVF_FIELD_SV] = {.quadlet = 0, .offset = 8, .bits = 1},
    [AVTP_RVF_FIELD_MR] = {.quadlet = 0, .offset = 12, .bits = 1},
    [AVTP_RVF_FIELD_FSD] = {.quadlet = 0, .offset = 13, .bits = 2},
    [AVTP_RVF_FIELD_TV] = {.quadlet = 0, .offset = 15, .bits = 1},
    [AVTP_RVF_FIELD_SEQUENCE_NUM] = {.quadlet = 0, .offset = 16, .bits = 8},
    [AVTP_RVF_FIELD_FSD0] = {.quadlet = 0, .offset = 0, .bits = 0},
    [AVTP_RVF_FIELD_FSD1] = {.quadlet = 0, .offset = 24, .bits = 7},
    [AVTP_RVF_FIELD_TU] = {.quadlet = 0, .offset = 31, .bits = 1},
    [AVTP_RVF_FIELD_STREAM_ID] = {.quadlet = 1, .offset = 0, .bits = 64},
    [AVTP_RVF_FIELD_AVTP_TIMESTAMP] = {.quadlet = 3, .offset = 0, .bits = 32},
    [AVTP_RVF_FIELD_PTP_GRANDMASTER_IDENTITY] = {.quadlet = 0, .offset = 0, .bits = 0},
    [AVTP_RVF_FIELD_STREAM_DATA_LENGTH] = {.quadlet = 5, .offset = 0, .bits = 16},
    [AVTP_RVF_FIELD_ACTIVE_PIXELS] = {.quadlet = 4, .offset = 0, .bits = 16},
    [AVTP_RVF_FIELD_TOTAL_LINES] = {.quadlet = 4, .offset = 16, .bits = 16},
    [AVTP_RVF_FIELD_AP] = {.quadlet = 5, .offset = 16, .bits = 1},
    [AVTP_RVF_FIELD_R] = {.quadlet = 5, .offset = 17, .bits = 1},
    [AVTP_RVF_FIELD_F] = {.quadlet = 5, .offset = 18, .bits = 1},
    [AVTP_RVF_FIELD_EF] = {.quadlet = 5, .offset = 19, .bits = 1},
    [AVTP_RVF_FIELD_EVT] = {.quadlet = 5, .offset = 20, .bits = 4},
    [AVTP_RVF_FIELD_PD] = {.quadlet = 5, .offset = 24, .bits = 1},
    [AVTP_RVF_FIELD_I] = {.quadlet = 5, .offset = 25, .bits = 1},
    [AVTP_RVF_FIELD_RESERVED2] = {.quadlet = 5, .offset = 26, .bits = 6},
};

/**
 * This table maps all IEEE 1722 RVF header fields to a descriptor for version 1.
 * It is complete and in absolute coordinates; the common stream header fields
 * use the same positions as Avtp_CshFieldDescV1.
 */
static const Avtp_FieldDescriptor_t Avtp_RvfFieldDescV1[AVTP_RVF_FIELD_MAX] = {
    [AVTP_RVF_FIELD_SV] = {.quadlet = 0, .offset = 8, .bits = 1},
    [AVTP_RVF_FIELD_MR] = {.quadlet = 0, .offset = 12, .bits = 1},
    [AVTP_RVF_FIELD_FSD] = {.quadlet = 0, .offset = 13, .bits = 2},
    [AVTP_RVF_FIELD_TV] = {.quadlet = 0, .offset = 15, .bits = 1},
    [AVTP_RVF_FIELD_SEQUENCE_NUM] = {.quadlet = 3, .offset = 0, .bits = 32},
    [AVTP_RVF_FIELD_FSD0] = {.quadlet = 0, .offset = 16, .bits = 8},
    [AVTP_RVF_FIELD_FSD1] = {.quadlet = 0, .offset = 24, .bits = 7},
    [AVTP_RVF_FIELD_TU] = {.quadlet = 0, .offset = 31, .bits = 1},
    [AVTP_RVF_FIELD_STREAM_ID] = {.quadlet = 1, .offset = 0, .bits = 64},
    [AVTP_RVF_FIELD_AVTP_TIMESTAMP] = {.quadlet = 4, .offset = 0, .bits = 64},
    [AVTP_RVF_FIELD_PTP_GRANDMASTER_IDENTITY] = {.quadlet = 6, .offset = 0, .bits = 64},
    [AVTP_RVF_FIELD_STREAM_DATA_LENGTH] = {.quadlet = 9, .offset = 0, .bits = 16},
    [AVTP_RVF_FIELD_ACTIVE_PIXELS] = {.quadlet = 8, .offset = 0, .bits = 16},
    [AVTP_RVF_FIELD_TOTAL_LINES] = {.quadlet = 8, .offset = 16, .bits = 16},
    [AVTP_RVF_FIELD_AP] = {.quadlet = 9, .offset = 16, .bits = 1},
    [AVTP_RVF_FIELD_R] = {.quadlet = 9, .offset = 17, .bits = 1},
    [AVTP_RVF_FIELD_F] = {.quadlet = 9, .offset = 18, .bits = 1},
    [AVTP_RVF_FIELD_EF] = {.quadlet = 9, .offset = 19, .bits = 1},
    [AVTP_RVF_FIELD_EVT] = {.quadlet = 9, .offset = 20, .bits = 4},
    [AVTP_RVF_FIELD_PD] = {.quadlet = 9, .offset = 24, .bits = 1},
    [AVTP_RVF_FIELD_I] = {.quadlet = 9, .offset = 25, .bits = 1},
    [AVTP_RVF_FIELD_RESERVED2] = {.quadlet = 9, .offset = 26, .bits = 6},
};

/**
 * Returns the value of an AVTP RVF field as laid out by version 0. No version
 * dispatch is performed.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param field Specifies the position of the data field to be read
 * @returns This function returns the value of the field.
 * @see Avtp_Rvf_GetField
 */
OPEN1722_INLINE uint64_t Avtp_Rvf_GetField_V0(const Avtp_Rvf_t *const pdu, Avtp_RvfFields_t field)
{
    return Avtp_GetField(Avtp_RvfFieldDescV0, AVTP_RVF_FIELD_MAX, (const uint8_t *)pdu,
                         (uint8_t)field);
}

/**
 * Returns the value of an AVTP RVF field as laid out by version 1. No version
 * dispatch is performed.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param field Specifies the position of the data field to be read
 * @returns This function returns the value of the field.
 * @see Avtp_Rvf_GetField
 */
OPEN1722_INLINE uint64_t Avtp_Rvf_GetField_V1(const Avtp_RvfV1_t *const pdu, Avtp_RvfFields_t field)
{
    return Avtp_GetField(Avtp_RvfFieldDescV1, AVTP_RVF_FIELD_MAX, (const uint8_t *)pdu,
                         (uint8_t)field);
}

/**
 * Returns the value of an AVTP RVF field, dispatching on the version field of
 * the PDU.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param field Specifies the position of the data field to be read
 * @returns This function returns the value of the field.
 */
OPEN1722_INLINE uint64_t Avtp_Rvf_GetField(const Avtp_Rvf_t *const pdu, Avtp_RvfFields_t field)
{
    return Avtp_CommonStreamHeader_GetVersion((const Avtp_CommonStreamHeader_t *)pdu) ==
                   AVTP_VERSION_1
               ? Avtp_Rvf_GetField_V1((const Avtp_RvfV1_t *)pdu, field)
               : Avtp_Rvf_GetField_V0(pdu, field);
}

/**
 * Sets the value of an AVTP RVF field as laid out by version 0. No version
 * dispatch is performed.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param field Specifies the position of the data field to be written
 * @param value The value to set.
 * @see Avtp_Rvf_SetField
 */
OPEN1722_INLINE void Avtp_Rvf_SetField_V0(Avtp_Rvf_t *pdu, Avtp_RvfFields_t field, uint64_t value)
{
    Avtp_SetField(Avtp_RvfFieldDescV0, AVTP_RVF_FIELD_MAX, (uint8_t *)pdu, (uint8_t)field, value);
}

/**
 * Sets the value of an AVTP RVF field as laid out by version 1. No version
 * dispatch is performed.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param field Specifies the position of the data field to be written
 * @param value The value to set.
 * @see Avtp_Rvf_SetField
 */
OPEN1722_INLINE void Avtp_Rvf_SetField_V1(Avtp_RvfV1_t *pdu, Avtp_RvfFields_t field, uint64_t value)
{
    Avtp_SetField(Avtp_RvfFieldDescV1, AVTP_RVF_FIELD_MAX, (uint8_t *)pdu, (uint8_t)field, value);
}

/**
 * Sets the value of an AVTP RVF field, dispatching on the version field of the
 * PDU.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param field Specifies the position of the data field to be written
 * @param value The value to set.
 */
OPEN1722_INLINE void Avtp_Rvf_SetField(Avtp_Rvf_t *pdu, Avtp_RvfFields_t field, uint64_t value)
{
    if (Avtp_CommonStreamHeader_GetVersion((const Avtp_CommonStreamHeader_t *)pdu) ==
        AVTP_VERSION_1) {
        Avtp_Rvf_SetField_V1((Avtp_RvfV1_t *)pdu, field, value);
    } else {
        Avtp_Rvf_SetField_V0(pdu, field, value);
    }
}

/**
 * Returns the length of the version 0 RVF header in octets (24). The PDU
 * pointer is not read; it keeps the signature aligned with the
 * version-dispatched accessors.
 */
OPEN1722_INLINE uint8_t Avtp_Rvf_GetHeaderLen_V0(const Avtp_Rvf_t *const pdu)
{
    (void)pdu;
    return (uint8_t)AVTP_RVF_HEADER_LEN_V0;
}

/**
 * Returns the length of the version 1 RVF header in octets (40). The PDU
 * pointer is not read; it keeps the signature aligned with the
 * version-dispatched accessors.
 */
OPEN1722_INLINE uint8_t Avtp_Rvf_GetHeaderLen_V1(const Avtp_RvfV1_t *const pdu)
{
    (void)pdu;
    return (uint8_t)AVTP_RVF_HEADER_LEN_V1;
}

/**
 * Returns the length of the RVF header in octets (24 or 40), dispatching on the
 * version field of the PDU.
 */
OPEN1722_INLINE uint8_t Avtp_Rvf_GetHeaderLen(const Avtp_Rvf_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetVersion((const Avtp_CommonStreamHeader_t *)pdu) ==
                   AVTP_VERSION_1
               ? Avtp_Rvf_GetHeaderLen_V1((const Avtp_RvfV1_t *)pdu)
               : Avtp_Rvf_GetHeaderLen_V0(pdu);
}

/**
 * Return the value of the RVF SV field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @returns Value of the RVF SV field.
 */
OPEN1722_INLINE bool Avtp_Rvf_IsSv(const Avtp_Rvf_t *const pdu)
{
    return (bool)Avtp_Rvf_GetField(pdu, AVTP_RVF_FIELD_SV);
}

/**
 * Return the value of the RVF MR field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @returns Value of the RVF MR field.
 */
OPEN1722_INLINE bool Avtp_Rvf_IsMr(const Avtp_Rvf_t *const pdu)
{
    return (bool)Avtp_Rvf_GetField(pdu, AVTP_RVF_FIELD_MR);
}

/**
 * Return the value of the RVF TV field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @returns Value of the RVF TV field.
 */
OPEN1722_INLINE bool Avtp_Rvf_IsTv(const Avtp_Rvf_t *const pdu)
{
    return (bool)Avtp_Rvf_GetField(pdu, AVTP_RVF_FIELD_TV);
}

/**
 * Return the value of the RVF Sequence Number field as specified in the IEEE 1722
 * Specification. The field is 8 bits in version 0 and 32 bits in version 1.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @returns Value of the RVF Sequence Number field.
 */
OPEN1722_INLINE uint32_t Avtp_Rvf_GetSequenceNum(const Avtp_Rvf_t *const pdu)
{
    return (uint32_t)Avtp_Rvf_GetField(pdu, AVTP_RVF_FIELD_SEQUENCE_NUM);
}

/**
 * Return the value of the RVF TU field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @returns Value of the RVF TU field.
 */
OPEN1722_INLINE bool Avtp_Rvf_IsTu(const Avtp_Rvf_t *const pdu)
{
    return (bool)Avtp_Rvf_GetField(pdu, AVTP_RVF_FIELD_TU);
}

/**
 * Return the value of the RVF Stream ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @returns Value of the RVF Stream ID field.
 */
OPEN1722_INLINE uint64_t Avtp_Rvf_GetStreamId(const Avtp_Rvf_t *const pdu)
{
    return Avtp_Rvf_GetField(pdu, AVTP_RVF_FIELD_STREAM_ID);
}

/**
 * Return the value of the RVF AVTP Timestamp field as specified in the IEEE 1722
 * Specification. The field is 32 bits in version 0 and 64 bits in version 1.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @returns Value of the RVF AVTP Timestamp field.
 */
OPEN1722_INLINE uint64_t Avtp_Rvf_GetAvtpTimestamp(const Avtp_Rvf_t *const pdu)
{
    return Avtp_Rvf_GetField(pdu, AVTP_RVF_FIELD_AVTP_TIMESTAMP);
}

/**
 * Return the value of the RVF ptp_grandmaster_identity field. The field only
 * exists in version 1; version 0 returns 0.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @returns Value of the RVF ptp_grandmaster_identity field.
 */
OPEN1722_INLINE uint64_t Avtp_Rvf_GetPtpGrandmasterIdentity(const Avtp_Rvf_t *const pdu)
{
    return Avtp_Rvf_GetField(pdu, AVTP_RVF_FIELD_PTP_GRANDMASTER_IDENTITY);
}

/**
 * Return the value of the RVF Active Pixels field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @returns Value of the RVF Active Pixels field.
 */
OPEN1722_INLINE uint16_t Avtp_Rvf_GetActivePixels(const Avtp_Rvf_t *const pdu)
{
    return (uint16_t)Avtp_Rvf_GetField(pdu, AVTP_RVF_FIELD_ACTIVE_PIXELS);
}

/**
 * Return the value of the RVF Total Lines field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @returns Value of the RVF Total Lines field.
 */
OPEN1722_INLINE uint16_t Avtp_Rvf_GetTotalLines(const Avtp_Rvf_t *const pdu)
{
    return (uint16_t)Avtp_Rvf_GetField(pdu, AVTP_RVF_FIELD_TOTAL_LINES);
}

/**
 * Return the value of the RVF Stream Data Length field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @returns Value of the RVF Stream Data Length field.
 */
OPEN1722_INLINE uint16_t Avtp_Rvf_GetStreamDataLength(const Avtp_Rvf_t *const pdu)
{
    return (uint16_t)Avtp_Rvf_GetField(pdu, AVTP_RVF_FIELD_STREAM_DATA_LENGTH);
}

/**
 * Return the value of the RVF AP field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @returns Value of the RVF AP field.
 */
OPEN1722_INLINE bool Avtp_Rvf_IsAp(const Avtp_Rvf_t *const pdu)
{
    return (bool)Avtp_Rvf_GetField(pdu, AVTP_RVF_FIELD_AP);
}

/**
 * Return the value of the RVF F field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @returns Value of the RVF F field.
 */
OPEN1722_INLINE bool Avtp_Rvf_IsF(const Avtp_Rvf_t *const pdu)
{
    return (bool)Avtp_Rvf_GetField(pdu, AVTP_RVF_FIELD_F);
}

/**
 * Return the value of the RVF EF field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @returns Value of the RVF EF field.
 */
OPEN1722_INLINE bool Avtp_Rvf_IsEf(const Avtp_Rvf_t *const pdu)
{
    return (bool)Avtp_Rvf_GetField(pdu, AVTP_RVF_FIELD_EF);
}

/**
 * Return the value of the RVF EVT field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @returns Value of the RVF EVT field.
 */
OPEN1722_INLINE uint8_t Avtp_Rvf_GetEvt(const Avtp_Rvf_t *const pdu)
{
    return (uint8_t)Avtp_Rvf_GetField(pdu, AVTP_RVF_FIELD_EVT);
}

/**
 * Return the value of the RVF PD field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @returns Value of the RVF PD field.
 */
OPEN1722_INLINE bool Avtp_Rvf_IsPd(const Avtp_Rvf_t *const pdu)
{
    return (bool)Avtp_Rvf_GetField(pdu, AVTP_RVF_FIELD_PD);
}

/**
 * Return the value of the RVF I field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @returns Value of the RVF I field.
 */
OPEN1722_INLINE bool Avtp_Rvf_IsI(const Avtp_Rvf_t *const pdu)
{
    return (bool)Avtp_Rvf_GetField(pdu, AVTP_RVF_FIELD_I);
}

/**
 * Set the SV bit in an RVF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param sv Value to set the RVF SV field to.
 */
OPEN1722_INLINE void Avtp_Rvf_SetSv(Avtp_Rvf_t *pdu, bool sv)
{
    Avtp_Rvf_SetField(pdu, AVTP_RVF_FIELD_SV, sv);
}

/**
 * Set the MR bit in an RVF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param mr Value to set the RVF MR field to.
 */
OPEN1722_INLINE void Avtp_Rvf_SetMr(Avtp_Rvf_t *pdu, bool mr)
{
    Avtp_Rvf_SetField(pdu, AVTP_RVF_FIELD_MR, mr);
}

/**
 * Set the TV bit in an RVF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param tv Value to set the RVF TV field to.
 */
OPEN1722_INLINE void Avtp_Rvf_SetTv(Avtp_Rvf_t *pdu, bool tv)
{
    Avtp_Rvf_SetField(pdu, AVTP_RVF_FIELD_TV, tv);
}

/**
 * Set the value of the RVF Sequence Number field as specified in the IEEE 1722
 * Specification. The field is 8 bits in version 0 and 32 bits in version 1; values are
 * truncated to the width of the version in use.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param value Value to set the RVF Sequence Number field to.
 */
OPEN1722_INLINE void Avtp_Rvf_SetSequenceNum(Avtp_Rvf_t *pdu, uint32_t value)
{
    Avtp_Rvf_SetField(pdu, AVTP_RVF_FIELD_SEQUENCE_NUM, value);
}

/**
 * Set the TU bit in an RVF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param tu Value to set the RVF TU field to.
 */
OPEN1722_INLINE void Avtp_Rvf_SetTu(Avtp_Rvf_t *pdu, bool tu)
{
    Avtp_Rvf_SetField(pdu, AVTP_RVF_FIELD_TU, tu);
}

/**
 * Set the value of the RVF Stream ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param value Value to set the RVF Stream ID field to.
 */
OPEN1722_INLINE void Avtp_Rvf_SetStreamId(Avtp_Rvf_t *pdu, uint64_t value)
{
    Avtp_Rvf_SetField(pdu, AVTP_RVF_FIELD_STREAM_ID, value);
}

/**
 * Set the value of the RVF AVTP Timestamp field as specified in the IEEE 1722
 * Specification. The field is 32 bits in version 0 and 64 bits in version 1; values are
 * truncated to the width of the version in use.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param value Value to set the RVF AVTP Timestamp field to.
 */
OPEN1722_INLINE void Avtp_Rvf_SetAvtpTimestamp(Avtp_Rvf_t *pdu, uint64_t value)
{
    Avtp_Rvf_SetField(pdu, AVTP_RVF_FIELD_AVTP_TIMESTAMP, value);
}

/**
 * Set the value of the RVF ptp_grandmaster_identity field. The field only
 * exists in version 1; on version 0 this is a no-op.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param value Value to set the RVF ptp_grandmaster_identity field to.
 */
OPEN1722_INLINE void Avtp_Rvf_SetPtpGrandmasterIdentity(Avtp_Rvf_t *pdu, uint64_t value)
{
    Avtp_Rvf_SetField(pdu, AVTP_RVF_FIELD_PTP_GRANDMASTER_IDENTITY, value);
}

/**
 * Set the value of the RVF Active Pixels field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param value Value to set the RVF Active Pixels field to.
 */
OPEN1722_INLINE void Avtp_Rvf_SetActivePixels(Avtp_Rvf_t *pdu, uint16_t value)
{
    Avtp_Rvf_SetField(pdu, AVTP_RVF_FIELD_ACTIVE_PIXELS, value);
}

/**
 * Set the value of the RVF Total Lines field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param value Value to set the RVF Total Lines field to.
 */
OPEN1722_INLINE void Avtp_Rvf_SetTotalLines(Avtp_Rvf_t *pdu, uint16_t value)
{
    Avtp_Rvf_SetField(pdu, AVTP_RVF_FIELD_TOTAL_LINES, value);
}

/**
 * Set the value of the RVF Stream Data Length field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param value Value to set the RVF Stream Data Length field to.
 */
OPEN1722_INLINE void Avtp_Rvf_SetStreamDataLength(Avtp_Rvf_t *pdu, uint16_t value)
{
    Avtp_Rvf_SetField(pdu, AVTP_RVF_FIELD_STREAM_DATA_LENGTH, value);
}

/**
 * Set the AP bit in an RVF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param ap Value to set the RVF AP field to.
 */
OPEN1722_INLINE void Avtp_Rvf_SetAp(Avtp_Rvf_t *pdu, bool ap)
{
    Avtp_Rvf_SetField(pdu, AVTP_RVF_FIELD_AP, ap);
}

/**
 * Set the F bit in an RVF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param f Value to set the RVF F field to.
 */
OPEN1722_INLINE void Avtp_Rvf_SetF(Avtp_Rvf_t *pdu, bool f)
{
    Avtp_Rvf_SetField(pdu, AVTP_RVF_FIELD_F, f);
}

/**
 * Set the EF bit in an RVF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param ef Value to set the RVF EF field to.
 */
OPEN1722_INLINE void Avtp_Rvf_SetEf(Avtp_Rvf_t *pdu, bool ef)
{
    Avtp_Rvf_SetField(pdu, AVTP_RVF_FIELD_EF, ef);
}

/**
 * Set the value of the RVF EVT field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param value Value to set the RVF EVT field to.
 */
OPEN1722_INLINE void Avtp_Rvf_SetEvt(Avtp_Rvf_t *pdu, uint8_t value)
{
    Avtp_Rvf_SetField(pdu, AVTP_RVF_FIELD_EVT, value);
}

/**
 * Set the PD bit in an RVF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param pd Value to set the RVF PD field to.
 */
OPEN1722_INLINE void Avtp_Rvf_SetPd(Avtp_Rvf_t *pdu, bool pd)
{
    Avtp_Rvf_SetField(pdu, AVTP_RVF_FIELD_PD, pd);
}

/**
 * Set the I bit in an RVF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param i Value to set the RVF I field to.
 */
OPEN1722_INLINE void Avtp_Rvf_SetI(Avtp_Rvf_t *pdu, bool i)
{
    Avtp_Rvf_SetField(pdu, AVTP_RVF_FIELD_I, i);
}

/**
 * Returns a pointer to the stream data of a version 0 RVF frame.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @return Pointer to RVF stream data
 * @see Avtp_Rvf_GetPayload
 */
OPEN1722_INLINE const uint8_t *Avtp_Rvf_GetPayload_V0(const Avtp_Rvf_t *const pdu)
{
    return (const uint8_t *)pdu + AVTP_RVF_HEADER_LEN_V0;
}

/**
 * Returns a pointer to the stream data of a version 1 RVF frame.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @return Pointer to RVF stream data
 * @see Avtp_Rvf_GetPayload
 */
OPEN1722_INLINE const uint8_t *Avtp_Rvf_GetPayload_V1(const Avtp_RvfV1_t *const pdu)
{
    return (const uint8_t *)pdu + AVTP_RVF_HEADER_LEN_V1;
}

/**
 * Returns pointer to the RVF stream data. The stream data starts after the
 * version-dependent common stream header.
 *
 * The stream data contains the raw header (an Avtp_RvfRawHeader_t) followed by
 * the video data payload. Its length is given by the stream_data_length field.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @return Pointer to RVF stream data
 */
OPEN1722_INLINE const uint8_t *Avtp_Rvf_GetPayload(const Avtp_Rvf_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetVersion((const Avtp_CommonStreamHeader_t *)pdu) ==
                   AVTP_VERSION_1
               ? Avtp_Rvf_GetPayload_V1((const Avtp_RvfV1_t *)pdu)
               : Avtp_Rvf_GetPayload_V0(pdu);
}

/**
 * Sets the stream data of a version 0 RVF frame.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload
 * @see Avtp_Rvf_SetPayload
 */
OPEN1722_INLINE void Avtp_Rvf_SetPayload_V0(Avtp_Rvf_t *pdu, uint8_t *payload,
                                            uint16_t payload_length)
{
    memcpy((uint8_t *)pdu + AVTP_RVF_HEADER_LEN_V0, payload, payload_length);
}

/**
 * Sets the stream data of a version 1 RVF frame.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload
 * @see Avtp_Rvf_SetPayload
 */
OPEN1722_INLINE void Avtp_Rvf_SetPayload_V1(Avtp_RvfV1_t *pdu, uint8_t *payload,
                                            uint16_t payload_length)
{
    memcpy((uint8_t *)pdu + AVTP_RVF_HEADER_LEN_V1, payload, payload_length);
}

/**
 * Sets the stream data of an RVF frame.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload
 */
OPEN1722_INLINE void Avtp_Rvf_SetPayload(Avtp_Rvf_t *pdu, uint8_t *payload, uint16_t payload_length)
{
    if (Avtp_CommonStreamHeader_GetVersion((const Avtp_CommonStreamHeader_t *)pdu) ==
        AVTP_VERSION_1) {
        Avtp_Rvf_SetPayload_V1((Avtp_RvfV1_t *)pdu, payload, payload_length);
    } else {
        Avtp_Rvf_SetPayload_V0(pdu, payload, payload_length);
    }
}

/**
 * Initializes a version 0 RVF PDU as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of a 1722 RVF PDU.
 */
OPEN1722_INLINE void Avtp_Rvf_Init(Avtp_Rvf_t *pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_Rvf_t));
        Avtp_CommonHeader_SetSubtype((Avtp_CommonHeader_t *)pdu, AVTP_SUBTYPE_RVF);
        Avtp_Rvf_SetSv(pdu, true);
    }
}

/**
 * Initializes a version 1 RVF PDU. The caller must provide a buffer of at least
 * AVTP_RVF_HEADER_LEN_V1 octets.
 *
 * @param pdu Pointer to the first bit of a 1722 RVF PDU.
 */
OPEN1722_INLINE void Avtp_Rvf_InitV1(Avtp_RvfV1_t *pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_RvfV1_t));
        Avtp_CommonHeader_SetSubtype((Avtp_CommonHeader_t *)pdu, AVTP_SUBTYPE_RVF);
        Avtp_CommonHeader_SetVersion((Avtp_CommonHeader_t *)pdu, AVTP_VERSION_1);
        Avtp_Rvf_SetSv((Avtp_Rvf_t *)pdu, true);
    }
}

/**
 * Checks if the RVF frame is valid by checking:
 *     1) that the subtype is RVF and the version is supported,
 *     2) that the version-dependent header fits into the buffer,
 *     3) that stream_data_length contains at least the raw header and fits into
 *        the buffer.
 *
 * The stream_data_length field contains the length (in octets) of the
 * stream_data_payload field (IEEE 1722-2025, 4.7.4.12), which for RVF consists
 * of the 8-octet raw header followed by the video data payload, so the whole
 * AVTPDU must fit into bufferSize.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param bufferSize Size of the buffer containing the RVF frame.
 * @return true if the RVF frame is valid, false otherwise.
 */
OPEN1722_INLINE bool Avtp_Rvf_IsValid(const Avtp_Rvf_t *const pdu, size_t bufferSize)
{
    if (pdu == NULL) {
        return false;
    }

    if (Avtp_CommonHeader_GetSubtype((const Avtp_CommonHeader_t *)pdu) != AVTP_SUBTYPE_RVF) {
        return false;
    }

    uint8_t version = Avtp_CommonStreamHeader_GetVersion((const Avtp_CommonStreamHeader_t *)pdu);
    if (!Avtp_Version_IsSupported(AVTP_RVF_SUPPORTED_VERSIONS, version)) {
        return false;
    }

    size_t headerLen = Avtp_Rvf_GetHeaderLen(pdu);
    if (bufferSize < headerLen) {
        return false;
    }

    uint16_t stream_data_length = Avtp_Rvf_GetStreamDataLength(pdu);

    /* Every RVF AVTPDU contains the raw header in its stream data. */
    if (stream_data_length < AVTP_RVF_RAW_HEADER_LEN) {
        return false;
    }

    if ((size_t)stream_data_length > bufferSize - headerLen) {
        return false;
    }

    return true;
}

/******************************************************************************
 * RVF raw header
 *
 * The raw header is a fragment of the RVF stream data (IEEE 1722-2025,
 * 12.2.10 to 12.2.17) rather than a standalone PDU: it is validated through
 * the enclosing RVF PDU (Avtp_Rvf_IsValid) and the shallow
 * Avtp_RvfRawHeader_IsValid only checks that the fragment fits into the given
 * buffer.
 *****************************************************************************/

#define GET_RVF_RAW_HEADER_FIELD(field)                                                            \
    (Avtp_GetField(Avtp_RvfRawHeaderFieldDesc, AVTP_RVF_RAW_HEADER_FIELD_MAX,                      \
                   (const uint8_t *)pdu, field))
#define SET_RVF_RAW_HEADER_FIELD(field, value)                                                     \
    (Avtp_SetField(Avtp_RvfRawHeaderFieldDesc, AVTP_RVF_RAW_HEADER_FIELD_MAX, (uint8_t *)pdu,      \
                   field, value))

typedef struct {
    uint8_t header[AVTP_RVF_RAW_HEADER_LEN];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_RvfRawHeader_t;

typedef enum {

    /* RVF raw header fields */
    AVTP_RVF_RAW_HEADER_FIELD_RESERVED1,
    AVTP_RVF_RAW_HEADER_FIELD_PIXEL_DEPTH,
    AVTP_RVF_RAW_HEADER_FIELD_PIXEL_FORMAT,
    AVTP_RVF_RAW_HEADER_FIELD_FRAME_RATE,
    AVTP_RVF_RAW_HEADER_FIELD_COLORSPACE,
    AVTP_RVF_RAW_HEADER_FIELD_NUM_LINES,
    AVTP_RVF_RAW_HEADER_FIELD_RESERVED2,
    AVTP_RVF_RAW_HEADER_FIELD_I_SEQ_NUM,
    AVTP_RVF_RAW_HEADER_FIELD_LINE_NUMBER,

    /* Count number of fields for bound checks */
    AVTP_RVF_RAW_HEADER_FIELD_MAX
} Avtp_RvfRawHeaderFields_t;

/**
 * This table maps all IEEE 1722 RVF raw header fields to a descriptor.
 */
static const Avtp_FieldDescriptor_t Avtp_RvfRawHeaderFieldDesc[AVTP_RVF_RAW_HEADER_FIELD_MAX] = {
    [AVTP_RVF_RAW_HEADER_FIELD_RESERVED1] = {.quadlet = 0, .offset = 0, .bits = 8},
    [AVTP_RVF_RAW_HEADER_FIELD_PIXEL_DEPTH] = {.quadlet = 0, .offset = 8, .bits = 4},
    [AVTP_RVF_RAW_HEADER_FIELD_PIXEL_FORMAT] = {.quadlet = 0, .offset = 12, .bits = 4},
    [AVTP_RVF_RAW_HEADER_FIELD_FRAME_RATE] = {.quadlet = 0, .offset = 16, .bits = 8},
    [AVTP_RVF_RAW_HEADER_FIELD_COLORSPACE] = {.quadlet = 0, .offset = 24, .bits = 4},
    [AVTP_RVF_RAW_HEADER_FIELD_NUM_LINES] = {.quadlet = 0, .offset = 28, .bits = 4},
    [AVTP_RVF_RAW_HEADER_FIELD_RESERVED2] = {.quadlet = 1, .offset = 0, .bits = 8},
    [AVTP_RVF_RAW_HEADER_FIELD_I_SEQ_NUM] = {.quadlet = 1, .offset = 8, .bits = 8},
    [AVTP_RVF_RAW_HEADER_FIELD_LINE_NUMBER] = {.quadlet = 1, .offset = 16, .bits = 16},
};

/**
 * Return the value of the RVF raw header Pixel Depth field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF raw header.
 * @returns Value of the RVF raw header Pixel Depth field.
 */
OPEN1722_INLINE Avtp_RvfPixelDepth_t
Avtp_RvfRawHeader_GetPixelDepth(const Avtp_RvfRawHeader_t *const pdu)
{
    return (Avtp_RvfPixelDepth_t)GET_RVF_RAW_HEADER_FIELD(AVTP_RVF_RAW_HEADER_FIELD_PIXEL_DEPTH);
}

/**
 * Return the value of the RVF raw header Pixel Format field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF raw header.
 * @returns Value of the RVF raw header Pixel Format field.
 */
OPEN1722_INLINE Avtp_RvfPixelFormat_t
Avtp_RvfRawHeader_GetPixelFormat(const Avtp_RvfRawHeader_t *const pdu)
{
    return (Avtp_RvfPixelFormat_t)GET_RVF_RAW_HEADER_FIELD(AVTP_RVF_RAW_HEADER_FIELD_PIXEL_FORMAT);
}

/**
 * Return the value of the RVF raw header Frame Rate field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF raw header.
 * @returns Value of the RVF raw header Frame Rate field.
 */
OPEN1722_INLINE Avtp_RvfFrameRate_t
Avtp_RvfRawHeader_GetFrameRate(const Avtp_RvfRawHeader_t *const pdu)
{
    return (Avtp_RvfFrameRate_t)GET_RVF_RAW_HEADER_FIELD(AVTP_RVF_RAW_HEADER_FIELD_FRAME_RATE);
}

/**
 * Return the value of the RVF raw header Colorspace field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF raw header.
 * @returns Value of the RVF raw header Colorspace field.
 */
OPEN1722_INLINE Avtp_RvfColorspace_t
Avtp_RvfRawHeader_GetColorspace(const Avtp_RvfRawHeader_t *const pdu)
{
    return (Avtp_RvfColorspace_t)GET_RVF_RAW_HEADER_FIELD(AVTP_RVF_RAW_HEADER_FIELD_COLORSPACE);
}

/**
 * Return the value of the RVF raw header Num Lines field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF raw header.
 * @returns Value of the RVF raw header Num Lines field.
 */
OPEN1722_INLINE uint8_t Avtp_RvfRawHeader_GetNumLines(const Avtp_RvfRawHeader_t *const pdu)
{
    return (uint8_t)GET_RVF_RAW_HEADER_FIELD(AVTP_RVF_RAW_HEADER_FIELD_NUM_LINES);
}

/**
 * Return the value of the RVF raw header I Sequence Number field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF raw header.
 * @returns Value of the RVF raw header I Sequence Number field.
 */
OPEN1722_INLINE uint8_t Avtp_RvfRawHeader_GetISeqNum(const Avtp_RvfRawHeader_t *const pdu)
{
    return (uint8_t)GET_RVF_RAW_HEADER_FIELD(AVTP_RVF_RAW_HEADER_FIELD_I_SEQ_NUM);
}

/**
 * Return the value of the RVF raw header Line Number field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF raw header.
 * @returns Value of the RVF raw header Line Number field.
 */
OPEN1722_INLINE uint16_t Avtp_RvfRawHeader_GetLineNumber(const Avtp_RvfRawHeader_t *const pdu)
{
    return (uint16_t)GET_RVF_RAW_HEADER_FIELD(AVTP_RVF_RAW_HEADER_FIELD_LINE_NUMBER);
}

/**
 * Set the value of the RVF raw header Pixel Depth field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF raw header.
 * @param value Value to set the RVF raw header Pixel Depth field to.
 */
OPEN1722_INLINE void Avtp_RvfRawHeader_SetPixelDepth(Avtp_RvfRawHeader_t *pdu,
                                                     Avtp_RvfPixelDepth_t value)
{
    SET_RVF_RAW_HEADER_FIELD(AVTP_RVF_RAW_HEADER_FIELD_PIXEL_DEPTH, (uint64_t)value);
}

/**
 * Set the value of the RVF raw header Pixel Format field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF raw header.
 * @param value Value to set the RVF raw header Pixel Format field to.
 */
OPEN1722_INLINE void Avtp_RvfRawHeader_SetPixelFormat(Avtp_RvfRawHeader_t *pdu,
                                                      Avtp_RvfPixelFormat_t value)
{
    SET_RVF_RAW_HEADER_FIELD(AVTP_RVF_RAW_HEADER_FIELD_PIXEL_FORMAT, (uint64_t)value);
}

/**
 * Set the value of the RVF raw header Frame Rate field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF raw header.
 * @param value Value to set the RVF raw header Frame Rate field to.
 */
OPEN1722_INLINE void Avtp_RvfRawHeader_SetFrameRate(Avtp_RvfRawHeader_t *pdu,
                                                    Avtp_RvfFrameRate_t value)
{
    SET_RVF_RAW_HEADER_FIELD(AVTP_RVF_RAW_HEADER_FIELD_FRAME_RATE, (uint64_t)value);
}

/**
 * Set the value of the RVF raw header Colorspace field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF raw header.
 * @param value Value to set the RVF raw header Colorspace field to.
 */
OPEN1722_INLINE void Avtp_RvfRawHeader_SetColorspace(Avtp_RvfRawHeader_t *pdu,
                                                     Avtp_RvfColorspace_t value)
{
    SET_RVF_RAW_HEADER_FIELD(AVTP_RVF_RAW_HEADER_FIELD_COLORSPACE, (uint64_t)value);
}

/**
 * Set the value of the RVF raw header Num Lines field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF raw header.
 * @param value Value to set the RVF raw header Num Lines field to.
 */
OPEN1722_INLINE void Avtp_RvfRawHeader_SetNumLines(Avtp_RvfRawHeader_t *pdu, uint8_t value)
{
    SET_RVF_RAW_HEADER_FIELD(AVTP_RVF_RAW_HEADER_FIELD_NUM_LINES, value);
}

/**
 * Set the value of the RVF raw header I Sequence Number field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF raw header.
 * @param value Value to set the RVF raw header I Sequence Number field to.
 */
OPEN1722_INLINE void Avtp_RvfRawHeader_SetISeqNum(Avtp_RvfRawHeader_t *pdu, uint8_t value)
{
    SET_RVF_RAW_HEADER_FIELD(AVTP_RVF_RAW_HEADER_FIELD_I_SEQ_NUM, value);
}

/**
 * Set the value of the RVF raw header Line Number field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF raw header.
 * @param value Value to set the RVF raw header Line Number field to.
 */
OPEN1722_INLINE void Avtp_RvfRawHeader_SetLineNumber(Avtp_RvfRawHeader_t *pdu, uint16_t value)
{
    SET_RVF_RAW_HEADER_FIELD(AVTP_RVF_RAW_HEADER_FIELD_LINE_NUMBER, value);
}

/**
 * Returns pointer to the video data payload of an RVF raw header.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF raw header.
 * @return Pointer to the video data payload
 */
OPEN1722_INLINE const uint8_t *Avtp_RvfRawHeader_GetPayload(const Avtp_RvfRawHeader_t *const pdu)
{
    return pdu->payload;
}

/**
 * Sets the video data payload of an RVF raw header.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF raw header.
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload
 */
OPEN1722_INLINE void Avtp_RvfRawHeader_SetPayload(Avtp_RvfRawHeader_t *pdu, uint8_t *payload,
                                                  uint16_t payload_length)
{
    memcpy(pdu->payload, payload, payload_length);
}

/**
 * Initializes an RVF raw header.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF raw header.
 */
OPEN1722_INLINE void Avtp_RvfRawHeader_Init(Avtp_RvfRawHeader_t *pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_RvfRawHeader_t));
    }
}

/**
 * Checks if the RVF raw header fits into the given buffer. This is a shallow
 * check: the raw header is a fragment of the RVF stream data and semantic
 * validation is done through Avtp_Rvf_IsValid on the enclosing RVF PDU.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF raw header.
 * @param bufferSize Size of the buffer containing the RVF raw header.
 * @return true if the RVF raw header fits into the buffer, false otherwise.
 */
OPEN1722_INLINE bool Avtp_RvfRawHeader_IsValid(const Avtp_RvfRawHeader_t *const pdu,
                                               size_t bufferSize)
{
    if (pdu == NULL) {
        return false;
    }

    if (bufferSize < AVTP_RVF_RAW_HEADER_LEN) {
        return false;
    }

    return true;
}

/**
 * Returns the value of an AVTP RVF raw header field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF raw header.
 * @param field Specifies the position of the data field to be read
 * @returns This function returns the value of the field.
 */
OPEN1722_INLINE uint64_t Avtp_RvfRawHeader_GetField(const Avtp_RvfRawHeader_t *const pdu,
                                                    Avtp_RvfRawHeaderFields_t field)
{
    return (uint64_t)GET_RVF_RAW_HEADER_FIELD(field);
}

/**
 * Sets the value of an AVTP RVF raw header field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF raw header.
 * @param field Specifies the position of the data field to be written
 * @param value The value to set.
 */
OPEN1722_INLINE void Avtp_RvfRawHeader_SetField(Avtp_RvfRawHeader_t *pdu,
                                                Avtp_RvfRawHeaderFields_t field, uint64_t value)
{
    SET_RVF_RAW_HEADER_FIELD(field, value);
}

/*
 * Version-typed named accessors. These select the field layout for one
 * explicit version and never read the version field; the version-dispatched
 * accessors above delegate to them. Common stream header fields delegate to
 * the shared Avtp_CommonStreamHeader_* variants. See each version-dispatched
 * accessor for the full field documentation.
 */

/**
 * Version 0 variant of Avtp_Rvf_IsSv().
 * @see Avtp_Rvf_IsSv
 */
OPEN1722_INLINE bool Avtp_Rvf_IsSv_V0(const Avtp_Rvf_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsSv_V0((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Rvf_IsSv().
 * @see Avtp_Rvf_IsSv
 */
OPEN1722_INLINE bool Avtp_Rvf_IsSv_V1(const Avtp_RvfV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsSv_V1((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Rvf_IsMr().
 * @see Avtp_Rvf_IsMr
 */
OPEN1722_INLINE bool Avtp_Rvf_IsMr_V0(const Avtp_Rvf_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsMr_V0((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Rvf_IsMr().
 * @see Avtp_Rvf_IsMr
 */
OPEN1722_INLINE bool Avtp_Rvf_IsMr_V1(const Avtp_RvfV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsMr_V1((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Rvf_IsTv().
 * @see Avtp_Rvf_IsTv
 */
OPEN1722_INLINE bool Avtp_Rvf_IsTv_V0(const Avtp_Rvf_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsTv_V0((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Rvf_IsTv().
 * @see Avtp_Rvf_IsTv
 */
OPEN1722_INLINE bool Avtp_Rvf_IsTv_V1(const Avtp_RvfV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsTv_V1((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Rvf_IsTu().
 * @see Avtp_Rvf_IsTu
 */
OPEN1722_INLINE bool Avtp_Rvf_IsTu_V0(const Avtp_Rvf_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsTu_V0((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Rvf_IsTu().
 * @see Avtp_Rvf_IsTu
 */
OPEN1722_INLINE bool Avtp_Rvf_IsTu_V1(const Avtp_RvfV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_IsTu_V1((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Rvf_GetSequenceNum(). Values are truncated to the
 * 8-bit version 0 field width.
 * @see Avtp_Rvf_GetSequenceNum
 */
OPEN1722_INLINE uint32_t Avtp_Rvf_GetSequenceNum_V0(const Avtp_Rvf_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetSequenceNum_V0((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Rvf_GetSequenceNum().
 * @see Avtp_Rvf_GetSequenceNum
 */
OPEN1722_INLINE uint32_t Avtp_Rvf_GetSequenceNum_V1(const Avtp_RvfV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetSequenceNum_V1((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Rvf_GetStreamId().
 * @see Avtp_Rvf_GetStreamId
 */
OPEN1722_INLINE uint64_t Avtp_Rvf_GetStreamId_V0(const Avtp_Rvf_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetStreamId_V0((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Rvf_GetStreamId().
 * @see Avtp_Rvf_GetStreamId
 */
OPEN1722_INLINE uint64_t Avtp_Rvf_GetStreamId_V1(const Avtp_RvfV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetStreamId_V1((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Rvf_GetAvtpTimestamp().
 * @see Avtp_Rvf_GetAvtpTimestamp
 */
OPEN1722_INLINE uint64_t Avtp_Rvf_GetAvtpTimestamp_V0(const Avtp_Rvf_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetAvtpTimestamp_V0((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Rvf_GetAvtpTimestamp().
 * @see Avtp_Rvf_GetAvtpTimestamp
 */
OPEN1722_INLINE uint64_t Avtp_Rvf_GetAvtpTimestamp_V1(const Avtp_RvfV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetAvtpTimestamp_V1((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Rvf_GetPtpGrandmasterIdentity(). The field is
 * absent from version 0, so this always returns 0.
 * @see Avtp_Rvf_GetPtpGrandmasterIdentity
 */
OPEN1722_INLINE uint64_t Avtp_Rvf_GetPtpGrandmasterIdentity_V0(const Avtp_Rvf_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetPtpGrandmasterIdentity_V0(
        (const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Rvf_GetPtpGrandmasterIdentity().
 * @see Avtp_Rvf_GetPtpGrandmasterIdentity
 */
OPEN1722_INLINE uint64_t Avtp_Rvf_GetPtpGrandmasterIdentity_V1(const Avtp_RvfV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetPtpGrandmasterIdentity_V1(
        (const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Rvf_GetStreamDataLength().
 * @see Avtp_Rvf_GetStreamDataLength
 */
OPEN1722_INLINE uint16_t Avtp_Rvf_GetStreamDataLength_V0(const Avtp_Rvf_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetStreamDataLength_V0((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 1 variant of Avtp_Rvf_GetStreamDataLength().
 * @see Avtp_Rvf_GetStreamDataLength
 */
OPEN1722_INLINE uint16_t Avtp_Rvf_GetStreamDataLength_V1(const Avtp_RvfV1_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetStreamDataLength_V1((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Version 0 variant of Avtp_Rvf_GetActivePixels().
 * @see Avtp_Rvf_GetActivePixels
 */
OPEN1722_INLINE uint16_t Avtp_Rvf_GetActivePixels_V0(const Avtp_Rvf_t *const pdu)
{
    return (uint16_t)Avtp_Rvf_GetField_V0(pdu, AVTP_RVF_FIELD_ACTIVE_PIXELS);
}

/**
 * Version 1 variant of Avtp_Rvf_GetActivePixels().
 * @see Avtp_Rvf_GetActivePixels
 */
OPEN1722_INLINE uint16_t Avtp_Rvf_GetActivePixels_V1(const Avtp_RvfV1_t *const pdu)
{
    return (uint16_t)Avtp_Rvf_GetField_V1(pdu, AVTP_RVF_FIELD_ACTIVE_PIXELS);
}

/**
 * Version 0 variant of Avtp_Rvf_GetTotalLines().
 * @see Avtp_Rvf_GetTotalLines
 */
OPEN1722_INLINE uint16_t Avtp_Rvf_GetTotalLines_V0(const Avtp_Rvf_t *const pdu)
{
    return (uint16_t)Avtp_Rvf_GetField_V0(pdu, AVTP_RVF_FIELD_TOTAL_LINES);
}

/**
 * Version 1 variant of Avtp_Rvf_GetTotalLines().
 * @see Avtp_Rvf_GetTotalLines
 */
OPEN1722_INLINE uint16_t Avtp_Rvf_GetTotalLines_V1(const Avtp_RvfV1_t *const pdu)
{
    return (uint16_t)Avtp_Rvf_GetField_V1(pdu, AVTP_RVF_FIELD_TOTAL_LINES);
}

/**
 * Version 0 variant of Avtp_Rvf_IsAp().
 * @see Avtp_Rvf_IsAp
 */
OPEN1722_INLINE bool Avtp_Rvf_IsAp_V0(const Avtp_Rvf_t *const pdu)
{
    return (bool)Avtp_Rvf_GetField_V0(pdu, AVTP_RVF_FIELD_AP);
}

/**
 * Version 1 variant of Avtp_Rvf_IsAp().
 * @see Avtp_Rvf_IsAp
 */
OPEN1722_INLINE bool Avtp_Rvf_IsAp_V1(const Avtp_RvfV1_t *const pdu)
{
    return (bool)Avtp_Rvf_GetField_V1(pdu, AVTP_RVF_FIELD_AP);
}

/**
 * Version 0 variant of Avtp_Rvf_IsF().
 * @see Avtp_Rvf_IsF
 */
OPEN1722_INLINE bool Avtp_Rvf_IsF_V0(const Avtp_Rvf_t *const pdu)
{
    return (bool)Avtp_Rvf_GetField_V0(pdu, AVTP_RVF_FIELD_F);
}

/**
 * Version 1 variant of Avtp_Rvf_IsF().
 * @see Avtp_Rvf_IsF
 */
OPEN1722_INLINE bool Avtp_Rvf_IsF_V1(const Avtp_RvfV1_t *const pdu)
{
    return (bool)Avtp_Rvf_GetField_V1(pdu, AVTP_RVF_FIELD_F);
}

/**
 * Version 0 variant of Avtp_Rvf_IsEf().
 * @see Avtp_Rvf_IsEf
 */
OPEN1722_INLINE bool Avtp_Rvf_IsEf_V0(const Avtp_Rvf_t *const pdu)
{
    return (bool)Avtp_Rvf_GetField_V0(pdu, AVTP_RVF_FIELD_EF);
}

/**
 * Version 1 variant of Avtp_Rvf_IsEf().
 * @see Avtp_Rvf_IsEf
 */
OPEN1722_INLINE bool Avtp_Rvf_IsEf_V1(const Avtp_RvfV1_t *const pdu)
{
    return (bool)Avtp_Rvf_GetField_V1(pdu, AVTP_RVF_FIELD_EF);
}

/**
 * Version 0 variant of Avtp_Rvf_GetEvt().
 * @see Avtp_Rvf_GetEvt
 */
OPEN1722_INLINE uint8_t Avtp_Rvf_GetEvt_V0(const Avtp_Rvf_t *const pdu)
{
    return (uint8_t)Avtp_Rvf_GetField_V0(pdu, AVTP_RVF_FIELD_EVT);
}

/**
 * Version 1 variant of Avtp_Rvf_GetEvt().
 * @see Avtp_Rvf_GetEvt
 */
OPEN1722_INLINE uint8_t Avtp_Rvf_GetEvt_V1(const Avtp_RvfV1_t *const pdu)
{
    return (uint8_t)Avtp_Rvf_GetField_V1(pdu, AVTP_RVF_FIELD_EVT);
}

/**
 * Version 0 variant of Avtp_Rvf_IsPd().
 * @see Avtp_Rvf_IsPd
 */
OPEN1722_INLINE bool Avtp_Rvf_IsPd_V0(const Avtp_Rvf_t *const pdu)
{
    return (bool)Avtp_Rvf_GetField_V0(pdu, AVTP_RVF_FIELD_PD);
}

/**
 * Version 1 variant of Avtp_Rvf_IsPd().
 * @see Avtp_Rvf_IsPd
 */
OPEN1722_INLINE bool Avtp_Rvf_IsPd_V1(const Avtp_RvfV1_t *const pdu)
{
    return (bool)Avtp_Rvf_GetField_V1(pdu, AVTP_RVF_FIELD_PD);
}

/**
 * Version 0 variant of Avtp_Rvf_IsI().
 * @see Avtp_Rvf_IsI
 */
OPEN1722_INLINE bool Avtp_Rvf_IsI_V0(const Avtp_Rvf_t *const pdu)
{
    return (bool)Avtp_Rvf_GetField_V0(pdu, AVTP_RVF_FIELD_I);
}

/**
 * Version 1 variant of Avtp_Rvf_IsI().
 * @see Avtp_Rvf_IsI
 */
OPEN1722_INLINE bool Avtp_Rvf_IsI_V1(const Avtp_RvfV1_t *const pdu)
{
    return (bool)Avtp_Rvf_GetField_V1(pdu, AVTP_RVF_FIELD_I);
}

/**
 * Version 0 variant of Avtp_Rvf_SetSv().
 * @see Avtp_Rvf_SetSv
 */
OPEN1722_INLINE void Avtp_Rvf_SetSv_V0(Avtp_Rvf_t *pdu, bool sv)
{
    Avtp_CommonStreamHeader_SetSv_V0((Avtp_CommonStreamHeader_t *)pdu, sv);
}

/**
 * Version 1 variant of Avtp_Rvf_SetSv().
 * @see Avtp_Rvf_SetSv
 */
OPEN1722_INLINE void Avtp_Rvf_SetSv_V1(Avtp_RvfV1_t *pdu, bool sv)
{
    Avtp_CommonStreamHeader_SetSv_V1((Avtp_CommonStreamHeader_t *)pdu, sv);
}

/**
 * Version 0 variant of Avtp_Rvf_SetMr().
 * @see Avtp_Rvf_SetMr
 */
OPEN1722_INLINE void Avtp_Rvf_SetMr_V0(Avtp_Rvf_t *pdu, bool mr)
{
    Avtp_CommonStreamHeader_SetMr_V0((Avtp_CommonStreamHeader_t *)pdu, mr);
}

/**
 * Version 1 variant of Avtp_Rvf_SetMr().
 * @see Avtp_Rvf_SetMr
 */
OPEN1722_INLINE void Avtp_Rvf_SetMr_V1(Avtp_RvfV1_t *pdu, bool mr)
{
    Avtp_CommonStreamHeader_SetMr_V1((Avtp_CommonStreamHeader_t *)pdu, mr);
}

/**
 * Version 0 variant of Avtp_Rvf_SetTv().
 * @see Avtp_Rvf_SetTv
 */
OPEN1722_INLINE void Avtp_Rvf_SetTv_V0(Avtp_Rvf_t *pdu, bool tv)
{
    Avtp_CommonStreamHeader_SetTv_V0((Avtp_CommonStreamHeader_t *)pdu, tv);
}

/**
 * Version 1 variant of Avtp_Rvf_SetTv().
 * @see Avtp_Rvf_SetTv
 */
OPEN1722_INLINE void Avtp_Rvf_SetTv_V1(Avtp_RvfV1_t *pdu, bool tv)
{
    Avtp_CommonStreamHeader_SetTv_V1((Avtp_CommonStreamHeader_t *)pdu, tv);
}

/**
 * Version 0 variant of Avtp_Rvf_SetTu().
 * @see Avtp_Rvf_SetTu
 */
OPEN1722_INLINE void Avtp_Rvf_SetTu_V0(Avtp_Rvf_t *pdu, bool tu)
{
    Avtp_CommonStreamHeader_SetTu_V0((Avtp_CommonStreamHeader_t *)pdu, tu);
}

/**
 * Version 1 variant of Avtp_Rvf_SetTu().
 * @see Avtp_Rvf_SetTu
 */
OPEN1722_INLINE void Avtp_Rvf_SetTu_V1(Avtp_RvfV1_t *pdu, bool tu)
{
    Avtp_CommonStreamHeader_SetTu_V1((Avtp_CommonStreamHeader_t *)pdu, tu);
}

/**
 * Version 0 variant of Avtp_Rvf_SetSequenceNum(). Values are truncated to the
 * 8-bit version 0 field width.
 * @see Avtp_Rvf_SetSequenceNum
 */
OPEN1722_INLINE void Avtp_Rvf_SetSequenceNum_V0(Avtp_Rvf_t *pdu, uint32_t value)
{
    Avtp_CommonStreamHeader_SetSequenceNum_V0((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 1 variant of Avtp_Rvf_SetSequenceNum().
 * @see Avtp_Rvf_SetSequenceNum
 */
OPEN1722_INLINE void Avtp_Rvf_SetSequenceNum_V1(Avtp_RvfV1_t *pdu, uint32_t value)
{
    Avtp_CommonStreamHeader_SetSequenceNum_V1((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 0 variant of Avtp_Rvf_SetStreamId().
 * @see Avtp_Rvf_SetStreamId
 */
OPEN1722_INLINE void Avtp_Rvf_SetStreamId_V0(Avtp_Rvf_t *pdu, uint64_t value)
{
    Avtp_CommonStreamHeader_SetStreamId_V0((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 1 variant of Avtp_Rvf_SetStreamId().
 * @see Avtp_Rvf_SetStreamId
 */
OPEN1722_INLINE void Avtp_Rvf_SetStreamId_V1(Avtp_RvfV1_t *pdu, uint64_t value)
{
    Avtp_CommonStreamHeader_SetStreamId_V1((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 0 variant of Avtp_Rvf_SetAvtpTimestamp().
 * @see Avtp_Rvf_SetAvtpTimestamp
 */
OPEN1722_INLINE void Avtp_Rvf_SetAvtpTimestamp_V0(Avtp_Rvf_t *pdu, uint64_t value)
{
    Avtp_CommonStreamHeader_SetAvtpTimestamp_V0((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 1 variant of Avtp_Rvf_SetAvtpTimestamp().
 * @see Avtp_Rvf_SetAvtpTimestamp
 */
OPEN1722_INLINE void Avtp_Rvf_SetAvtpTimestamp_V1(Avtp_RvfV1_t *pdu, uint64_t value)
{
    Avtp_CommonStreamHeader_SetAvtpTimestamp_V1((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 0 variant of Avtp_Rvf_SetPtpGrandmasterIdentity(). The field is
 * absent from version 0, so this is a no-op.
 * @see Avtp_Rvf_SetPtpGrandmasterIdentity
 */
OPEN1722_INLINE void Avtp_Rvf_SetPtpGrandmasterIdentity_V0(Avtp_Rvf_t *pdu, uint64_t value)
{
    Avtp_CommonStreamHeader_SetPtpGrandmasterIdentity_V0((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 1 variant of Avtp_Rvf_SetPtpGrandmasterIdentity().
 * @see Avtp_Rvf_SetPtpGrandmasterIdentity
 */
OPEN1722_INLINE void Avtp_Rvf_SetPtpGrandmasterIdentity_V1(Avtp_RvfV1_t *pdu, uint64_t value)
{
    Avtp_CommonStreamHeader_SetPtpGrandmasterIdentity_V1((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 0 variant of Avtp_Rvf_SetStreamDataLength().
 * @see Avtp_Rvf_SetStreamDataLength
 */
OPEN1722_INLINE void Avtp_Rvf_SetStreamDataLength_V0(Avtp_Rvf_t *pdu, uint16_t value)
{
    Avtp_CommonStreamHeader_SetStreamDataLength_V0((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 1 variant of Avtp_Rvf_SetStreamDataLength().
 * @see Avtp_Rvf_SetStreamDataLength
 */
OPEN1722_INLINE void Avtp_Rvf_SetStreamDataLength_V1(Avtp_RvfV1_t *pdu, uint16_t value)
{
    Avtp_CommonStreamHeader_SetStreamDataLength_V1((Avtp_CommonStreamHeader_t *)pdu, value);
}

/**
 * Version 0 variant of Avtp_Rvf_SetActivePixels().
 * @see Avtp_Rvf_SetActivePixels
 */
OPEN1722_INLINE void Avtp_Rvf_SetActivePixels_V0(Avtp_Rvf_t *pdu, uint16_t value)
{
    Avtp_Rvf_SetField_V0(pdu, AVTP_RVF_FIELD_ACTIVE_PIXELS, value);
}

/**
 * Version 1 variant of Avtp_Rvf_SetActivePixels().
 * @see Avtp_Rvf_SetActivePixels
 */
OPEN1722_INLINE void Avtp_Rvf_SetActivePixels_V1(Avtp_RvfV1_t *pdu, uint16_t value)
{
    Avtp_Rvf_SetField_V1(pdu, AVTP_RVF_FIELD_ACTIVE_PIXELS, value);
}

/**
 * Version 0 variant of Avtp_Rvf_SetTotalLines().
 * @see Avtp_Rvf_SetTotalLines
 */
OPEN1722_INLINE void Avtp_Rvf_SetTotalLines_V0(Avtp_Rvf_t *pdu, uint16_t value)
{
    Avtp_Rvf_SetField_V0(pdu, AVTP_RVF_FIELD_TOTAL_LINES, value);
}

/**
 * Version 1 variant of Avtp_Rvf_SetTotalLines().
 * @see Avtp_Rvf_SetTotalLines
 */
OPEN1722_INLINE void Avtp_Rvf_SetTotalLines_V1(Avtp_RvfV1_t *pdu, uint16_t value)
{
    Avtp_Rvf_SetField_V1(pdu, AVTP_RVF_FIELD_TOTAL_LINES, value);
}

/**
 * Version 0 variant of Avtp_Rvf_SetAp().
 * @see Avtp_Rvf_SetAp
 */
OPEN1722_INLINE void Avtp_Rvf_SetAp_V0(Avtp_Rvf_t *pdu, bool ap)
{
    Avtp_Rvf_SetField_V0(pdu, AVTP_RVF_FIELD_AP, ap);
}

/**
 * Version 1 variant of Avtp_Rvf_SetAp().
 * @see Avtp_Rvf_SetAp
 */
OPEN1722_INLINE void Avtp_Rvf_SetAp_V1(Avtp_RvfV1_t *pdu, bool ap)
{
    Avtp_Rvf_SetField_V1(pdu, AVTP_RVF_FIELD_AP, ap);
}

/**
 * Version 0 variant of Avtp_Rvf_SetF().
 * @see Avtp_Rvf_SetF
 */
OPEN1722_INLINE void Avtp_Rvf_SetF_V0(Avtp_Rvf_t *pdu, bool f)
{
    Avtp_Rvf_SetField_V0(pdu, AVTP_RVF_FIELD_F, f);
}

/**
 * Version 1 variant of Avtp_Rvf_SetF().
 * @see Avtp_Rvf_SetF
 */
OPEN1722_INLINE void Avtp_Rvf_SetF_V1(Avtp_RvfV1_t *pdu, bool f)
{
    Avtp_Rvf_SetField_V1(pdu, AVTP_RVF_FIELD_F, f);
}

/**
 * Version 0 variant of Avtp_Rvf_SetEf().
 * @see Avtp_Rvf_SetEf
 */
OPEN1722_INLINE void Avtp_Rvf_SetEf_V0(Avtp_Rvf_t *pdu, bool ef)
{
    Avtp_Rvf_SetField_V0(pdu, AVTP_RVF_FIELD_EF, ef);
}

/**
 * Version 1 variant of Avtp_Rvf_SetEf().
 * @see Avtp_Rvf_SetEf
 */
OPEN1722_INLINE void Avtp_Rvf_SetEf_V1(Avtp_RvfV1_t *pdu, bool ef)
{
    Avtp_Rvf_SetField_V1(pdu, AVTP_RVF_FIELD_EF, ef);
}

/**
 * Version 0 variant of Avtp_Rvf_SetEvt().
 * @see Avtp_Rvf_SetEvt
 */
OPEN1722_INLINE void Avtp_Rvf_SetEvt_V0(Avtp_Rvf_t *pdu, uint8_t value)
{
    Avtp_Rvf_SetField_V0(pdu, AVTP_RVF_FIELD_EVT, value);
}

/**
 * Version 1 variant of Avtp_Rvf_SetEvt().
 * @see Avtp_Rvf_SetEvt
 */
OPEN1722_INLINE void Avtp_Rvf_SetEvt_V1(Avtp_RvfV1_t *pdu, uint8_t value)
{
    Avtp_Rvf_SetField_V1(pdu, AVTP_RVF_FIELD_EVT, value);
}

/**
 * Version 0 variant of Avtp_Rvf_SetPd().
 * @see Avtp_Rvf_SetPd
 */
OPEN1722_INLINE void Avtp_Rvf_SetPd_V0(Avtp_Rvf_t *pdu, bool pd)
{
    Avtp_Rvf_SetField_V0(pdu, AVTP_RVF_FIELD_PD, pd);
}

/**
 * Version 1 variant of Avtp_Rvf_SetPd().
 * @see Avtp_Rvf_SetPd
 */
OPEN1722_INLINE void Avtp_Rvf_SetPd_V1(Avtp_RvfV1_t *pdu, bool pd)
{
    Avtp_Rvf_SetField_V1(pdu, AVTP_RVF_FIELD_PD, pd);
}

/**
 * Version 0 variant of Avtp_Rvf_SetI().
 * @see Avtp_Rvf_SetI
 */
OPEN1722_INLINE void Avtp_Rvf_SetI_V0(Avtp_Rvf_t *pdu, bool i)
{
    Avtp_Rvf_SetField_V0(pdu, AVTP_RVF_FIELD_I, i);
}

/**
 * Version 1 variant of Avtp_Rvf_SetI().
 * @see Avtp_Rvf_SetI
 */
OPEN1722_INLINE void Avtp_Rvf_SetI_V1(Avtp_RvfV1_t *pdu, bool i)
{
    Avtp_Rvf_SetField_V1(pdu, AVTP_RVF_FIELD_I, i);
}

#ifdef __cplusplus
}
#endif
