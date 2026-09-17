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

#ifdef __cplusplus
extern "C" {
#endif

#define AVTP_RVF_HEADER_LEN (6 * AVTP_QUADLET_SIZE)
#define AVTP_RVF_RAW_HEADER_LEN (2 * AVTP_QUADLET_SIZE)

#define GET_RVF_FIELD(field)                                                                       \
    (Avtp_GetField(Avtp_RvfFieldDesc, AVTP_RVF_FIELD_MAX, (const uint8_t *)pdu, field))
#define SET_RVF_FIELD(field, value)                                                                \
    (Avtp_SetField(Avtp_RvfFieldDesc, AVTP_RVF_FIELD_MAX, (uint8_t *)pdu, field, value))

typedef struct {
    uint8_t header[AVTP_RVF_HEADER_LEN];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_Rvf_t;

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
    AVTP_RVF_FIELD_SUBTYPE,
    AVTP_RVF_FIELD_SV,
    AVTP_RVF_FIELD_VERSION,
    AVTP_RVF_FIELD_MR,
    AVTP_RVF_FIELD_RSV,
    AVTP_RVF_FIELD_TV,
    AVTP_RVF_FIELD_SEQUENCE_NUM,
    AVTP_RVF_FIELD_RESERVED1,
    AVTP_RVF_FIELD_TU,

    /* RVF header fields */
    AVTP_RVF_FIELD_STREAM_ID,
    AVTP_RVF_FIELD_AVTP_TIMESTAMP,
    AVTP_RVF_FIELD_ACTIVE_PIXELS,
    AVTP_RVF_FIELD_TOTAL_LINES,
    AVTP_RVF_FIELD_STREAM_DATA_LENGTH,
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
 * This table maps all IEEE 1722 RVF header fields to a descriptor.
 */
static const Avtp_FieldDescriptor_t Avtp_RvfFieldDesc[AVTP_RVF_FIELD_MAX] = {
    /* Common AVTP stream header fields */
    [AVTP_RVF_FIELD_SUBTYPE] = {.quadlet = 0, .offset = 0, .bits = 8},
    [AVTP_RVF_FIELD_SV] = {.quadlet = 0, .offset = 8, .bits = 1},
    [AVTP_RVF_FIELD_VERSION] = {.quadlet = 0, .offset = 9, .bits = 3},
    [AVTP_RVF_FIELD_MR] = {.quadlet = 0, .offset = 12, .bits = 1},
    [AVTP_RVF_FIELD_RSV] = {.quadlet = 0, .offset = 13, .bits = 2},
    [AVTP_RVF_FIELD_TV] = {.quadlet = 0, .offset = 15, .bits = 1},
    [AVTP_RVF_FIELD_SEQUENCE_NUM] = {.quadlet = 0, .offset = 16, .bits = 8},
    [AVTP_RVF_FIELD_RESERVED1] = {.quadlet = 0, .offset = 24, .bits = 7},
    [AVTP_RVF_FIELD_TU] = {.quadlet = 0, .offset = 31, .bits = 1},
    /* RVF header fields */
    [AVTP_RVF_FIELD_STREAM_ID] = {.quadlet = 1, .offset = 0, .bits = 64},
    [AVTP_RVF_FIELD_AVTP_TIMESTAMP] = {.quadlet = 3, .offset = 0, .bits = 32},
    [AVTP_RVF_FIELD_ACTIVE_PIXELS] = {.quadlet = 4, .offset = 0, .bits = 16},
    [AVTP_RVF_FIELD_TOTAL_LINES] = {.quadlet = 4, .offset = 16, .bits = 16},
    [AVTP_RVF_FIELD_STREAM_DATA_LENGTH] = {.quadlet = 5, .offset = 0, .bits = 16},
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
 * Return the value of the RVF SV field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @returns Value of the RVF SV field.
 */
OPEN1722_INLINE bool Avtp_Rvf_IsSv(const Avtp_Rvf_t *const pdu)
{
    return (bool)GET_RVF_FIELD(AVTP_RVF_FIELD_SV);
}

/**
 * Return the value of the RVF MR field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @returns Value of the RVF MR field.
 */
OPEN1722_INLINE bool Avtp_Rvf_IsMr(const Avtp_Rvf_t *const pdu)
{
    return (bool)GET_RVF_FIELD(AVTP_RVF_FIELD_MR);
}

/**
 * Return the value of the RVF TV field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @returns Value of the RVF TV field.
 */
OPEN1722_INLINE bool Avtp_Rvf_IsTv(const Avtp_Rvf_t *const pdu)
{
    return (bool)GET_RVF_FIELD(AVTP_RVF_FIELD_TV);
}

/**
 * Return the value of the RVF Sequence Number field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @returns Value of the RVF Sequence Number field.
 */
OPEN1722_INLINE uint8_t Avtp_Rvf_GetSequenceNum(const Avtp_Rvf_t *const pdu)
{
    return (uint8_t)GET_RVF_FIELD(AVTP_RVF_FIELD_SEQUENCE_NUM);
}

/**
 * Return the value of the RVF TU field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @returns Value of the RVF TU field.
 */
OPEN1722_INLINE bool Avtp_Rvf_IsTu(const Avtp_Rvf_t *const pdu)
{
    return (bool)GET_RVF_FIELD(AVTP_RVF_FIELD_TU);
}

/**
 * Return the value of the RVF Stream ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @returns Value of the RVF Stream ID field.
 */
OPEN1722_INLINE uint64_t Avtp_Rvf_GetStreamId(const Avtp_Rvf_t *const pdu)
{
    return (uint64_t)GET_RVF_FIELD(AVTP_RVF_FIELD_STREAM_ID);
}

/**
 * Return the value of the RVF AVTP Timestamp field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @returns Value of the RVF AVTP Timestamp field.
 */
OPEN1722_INLINE uint32_t Avtp_Rvf_GetAvtpTimestamp(const Avtp_Rvf_t *const pdu)
{
    return (uint32_t)GET_RVF_FIELD(AVTP_RVF_FIELD_AVTP_TIMESTAMP);
}

/**
 * Return the value of the RVF Active Pixels field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @returns Value of the RVF Active Pixels field.
 */
OPEN1722_INLINE uint16_t Avtp_Rvf_GetActivePixels(const Avtp_Rvf_t *const pdu)
{
    return (uint16_t)GET_RVF_FIELD(AVTP_RVF_FIELD_ACTIVE_PIXELS);
}

/**
 * Return the value of the RVF Total Lines field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @returns Value of the RVF Total Lines field.
 */
OPEN1722_INLINE uint16_t Avtp_Rvf_GetTotalLines(const Avtp_Rvf_t *const pdu)
{
    return (uint16_t)GET_RVF_FIELD(AVTP_RVF_FIELD_TOTAL_LINES);
}

/**
 * Return the value of the RVF Stream Data Length field as specified in the IEEE 1722 Specification.
 *
 * The stream_data_length field contains the length (in octets) of the
 * stream_data_payload field, which for RVF consists of the raw header and the
 * video data payload.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @returns Value of the RVF Stream Data Length field.
 */
OPEN1722_INLINE uint16_t Avtp_Rvf_GetStreamDataLength(const Avtp_Rvf_t *const pdu)
{
    return (uint16_t)GET_RVF_FIELD(AVTP_RVF_FIELD_STREAM_DATA_LENGTH);
}

/**
 * Return the value of the RVF AP field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @returns Value of the RVF AP field.
 */
OPEN1722_INLINE bool Avtp_Rvf_IsAp(const Avtp_Rvf_t *const pdu)
{
    return (bool)GET_RVF_FIELD(AVTP_RVF_FIELD_AP);
}

/**
 * Return the value of the RVF F field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @returns Value of the RVF F field.
 */
OPEN1722_INLINE bool Avtp_Rvf_IsF(const Avtp_Rvf_t *const pdu)
{
    return (bool)GET_RVF_FIELD(AVTP_RVF_FIELD_F);
}

/**
 * Return the value of the RVF EF field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @returns Value of the RVF EF field.
 */
OPEN1722_INLINE bool Avtp_Rvf_IsEf(const Avtp_Rvf_t *const pdu)
{
    return (bool)GET_RVF_FIELD(AVTP_RVF_FIELD_EF);
}

/**
 * Return the value of the RVF EVT field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @returns Value of the RVF EVT field.
 */
OPEN1722_INLINE uint8_t Avtp_Rvf_GetEvt(const Avtp_Rvf_t *const pdu)
{
    return (uint8_t)GET_RVF_FIELD(AVTP_RVF_FIELD_EVT);
}

/**
 * Return the value of the RVF PD field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @returns Value of the RVF PD field.
 */
OPEN1722_INLINE bool Avtp_Rvf_IsPd(const Avtp_Rvf_t *const pdu)
{
    return (bool)GET_RVF_FIELD(AVTP_RVF_FIELD_PD);
}

/**
 * Return the value of the RVF I field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @returns Value of the RVF I field.
 */
OPEN1722_INLINE bool Avtp_Rvf_IsI(const Avtp_Rvf_t *const pdu)
{
    return (bool)GET_RVF_FIELD(AVTP_RVF_FIELD_I);
}

/**
 * Set the SV bit in a RVF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param sv Value to set the RVF SV field to.
 */
OPEN1722_INLINE void Avtp_Rvf_SetSv(Avtp_Rvf_t *pdu, bool sv)
{
    SET_RVF_FIELD(AVTP_RVF_FIELD_SV, sv);
}

/**
 * Set the MR bit in a RVF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param mr Value to set the RVF MR field to.
 */
OPEN1722_INLINE void Avtp_Rvf_SetMr(Avtp_Rvf_t *pdu, bool mr)
{
    SET_RVF_FIELD(AVTP_RVF_FIELD_MR, mr);
}

/**
 * Set the TV bit in a RVF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param tv Value to set the RVF TV field to.
 */
OPEN1722_INLINE void Avtp_Rvf_SetTv(Avtp_Rvf_t *pdu, bool tv)
{
    SET_RVF_FIELD(AVTP_RVF_FIELD_TV, tv);
}

/**
 * Set the value of the RVF Sequence Number field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param value Value to set the RVF Sequence Number field to.
 */
OPEN1722_INLINE void Avtp_Rvf_SetSequenceNum(Avtp_Rvf_t *pdu, uint8_t value)
{
    SET_RVF_FIELD(AVTP_RVF_FIELD_SEQUENCE_NUM, value);
}

/**
 * Set the TU bit in a RVF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param tu Value to set the RVF TU field to.
 */
OPEN1722_INLINE void Avtp_Rvf_SetTu(Avtp_Rvf_t *pdu, bool tu)
{
    SET_RVF_FIELD(AVTP_RVF_FIELD_TU, tu);
}

/**
 * Set the value of the RVF Stream ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param value Value to set the RVF Stream ID field to.
 */
OPEN1722_INLINE void Avtp_Rvf_SetStreamId(Avtp_Rvf_t *pdu, uint64_t value)
{
    SET_RVF_FIELD(AVTP_RVF_FIELD_STREAM_ID, value);
}

/**
 * Set the value of the RVF AVTP Timestamp field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param value Value to set the RVF AVTP Timestamp field to.
 */
OPEN1722_INLINE void Avtp_Rvf_SetAvtpTimestamp(Avtp_Rvf_t *pdu, uint32_t value)
{
    SET_RVF_FIELD(AVTP_RVF_FIELD_AVTP_TIMESTAMP, value);
}

/**
 * Set the value of the RVF Active Pixels field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param value Value to set the RVF Active Pixels field to.
 */
OPEN1722_INLINE void Avtp_Rvf_SetActivePixels(Avtp_Rvf_t *pdu, uint16_t value)
{
    SET_RVF_FIELD(AVTP_RVF_FIELD_ACTIVE_PIXELS, value);
}

/**
 * Set the value of the RVF Total Lines field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param value Value to set the RVF Total Lines field to.
 */
OPEN1722_INLINE void Avtp_Rvf_SetTotalLines(Avtp_Rvf_t *pdu, uint16_t value)
{
    SET_RVF_FIELD(AVTP_RVF_FIELD_TOTAL_LINES, value);
}

/**
 * Set the value of the RVF Stream Data Length field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param value Value to set the RVF Stream Data Length field to.
 */
OPEN1722_INLINE void Avtp_Rvf_SetStreamDataLength(Avtp_Rvf_t *pdu, uint16_t value)
{
    SET_RVF_FIELD(AVTP_RVF_FIELD_STREAM_DATA_LENGTH, value);
}

/**
 * Set the AP bit in a RVF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param ap Value to set the RVF AP field to.
 */
OPEN1722_INLINE void Avtp_Rvf_SetAp(Avtp_Rvf_t *pdu, bool ap)
{
    SET_RVF_FIELD(AVTP_RVF_FIELD_AP, ap);
}

/**
 * Set the F bit in a RVF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param f Value to set the RVF F field to.
 */
OPEN1722_INLINE void Avtp_Rvf_SetF(Avtp_Rvf_t *pdu, bool f)
{
    SET_RVF_FIELD(AVTP_RVF_FIELD_F, f);
}

/**
 * Set the EF bit in a RVF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param ef Value to set the RVF EF field to.
 */
OPEN1722_INLINE void Avtp_Rvf_SetEf(Avtp_Rvf_t *pdu, bool ef)
{
    SET_RVF_FIELD(AVTP_RVF_FIELD_EF, ef);
}

/**
 * Set the value of the RVF EVT field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param value Value to set the RVF EVT field to.
 */
OPEN1722_INLINE void Avtp_Rvf_SetEvt(Avtp_Rvf_t *pdu, uint8_t value)
{
    SET_RVF_FIELD(AVTP_RVF_FIELD_EVT, value);
}

/**
 * Set the PD bit in a RVF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param pd Value to set the RVF PD field to.
 */
OPEN1722_INLINE void Avtp_Rvf_SetPd(Avtp_Rvf_t *pdu, bool pd)
{
    SET_RVF_FIELD(AVTP_RVF_FIELD_PD, pd);
}

/**
 * Set the I bit in a RVF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param i Value to set the RVF I field to.
 */
OPEN1722_INLINE void Avtp_Rvf_SetI(Avtp_Rvf_t *pdu, bool i)
{
    SET_RVF_FIELD(AVTP_RVF_FIELD_I, i);
}

/**
 * Returns pointer to the stream data of an RVF frame.
 *
 * The stream data contains the raw header (an Avtp_RvfRawHeader_t) followed by
 * the video data payload. Its length is given by the stream_data_length field.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @return Pointer to RVF stream data
 */
OPEN1722_INLINE const uint8_t *Avtp_Rvf_GetPayload(const Avtp_Rvf_t *const pdu)
{
    return pdu->payload;
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
    memcpy(pdu->payload, payload, payload_length);
}

/**
 * Initializes an RVF PDU as specified in the IEEE 1722 Specification.
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
 * Checks if the RVF frame is valid by checking:
 *     1) if the stream_data_length field contains a value larger than the actual size of the
 * buffer that contains the AVTP message. 2) if other format specific invariants are not upheld.
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

    if (bufferSize < AVTP_RVF_HEADER_LEN) {
        return false;
    }

    if (Avtp_CommonHeader_GetSubtype((const Avtp_CommonHeader_t *)pdu) != AVTP_SUBTYPE_RVF) {
        return false;
    }

    uint16_t stream_data_length = Avtp_Rvf_GetStreamDataLength(pdu);

    /* Every RVF AVTPDU contains the raw header in its stream data. */
    if (stream_data_length < AVTP_RVF_RAW_HEADER_LEN) {
        return false;
    }

    if ((size_t)AVTP_RVF_HEADER_LEN + (size_t)stream_data_length > bufferSize) {
        return false;
    }

    return true;
}

/**
 * Returns the value of an AVTP RVF field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param field Specifies the position of the data field to be read
 * @returns This function returns the value of the field.
 */
OPEN1722_INLINE uint64_t Avtp_Rvf_GetField(const Avtp_Rvf_t *const pdu, Avtp_RvfFields_t field)
{
    return (uint64_t)GET_RVF_FIELD(field);
}

/**
 * Sets the value of an AVTP RVF field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 RVF PDU.
 * @param field Specifies the position of the data field to be written
 * @param value The value to set.
 */
OPEN1722_INLINE void Avtp_Rvf_SetField(Avtp_Rvf_t *pdu, Avtp_RvfFields_t field, uint64_t value)
{
    SET_RVF_FIELD(field, value);
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

#ifdef __cplusplus
}
#endif
