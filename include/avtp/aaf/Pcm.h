/*
 * Copyright (c) 2024, COVESA
 * Copyright (c) 2019, Intel Corporation
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
 * This file contains the fields descriptions of the IEEE 1722 AAF PCM PDUs and
 * functions to invoke corresponding parser and deparser.
 *
 * PCM is an AAF subformat (subtype AAF, format field selects PCM). It declares
 * a complete descriptor table per version in absolute coordinates: the common
 * stream header fields reuse the positions from CommonStreamHeader.h and the
 * PCM-specific fields are added by this module. A consistency test keeps the
 * common entries aligned with the common stream header module and the fields
 * shared with AAF aligned with the AAF module.
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
#include "avtp/aaf/Aaf.h"
#include "avtp/CommonStreamHeader.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AVTP_PCM_HEADER_LEN_V0 AVTPDU_CSH_LEN_V0 /* 24 */
#define AVTP_PCM_HEADER_LEN_V1 AVTPDU_CSH_LEN_V1 /* 40 */
/* Kept for compatibility: the version 0 header length. */
#define AVTP_PCM_HEADER_LEN AVTP_PCM_HEADER_LEN_V0

/* PCM (AAF) supports both versions of the common stream header (Table 7). */
#define AVTP_PCM_SUPPORTED_VERSIONS ((1u << AVTP_VERSION_0) | (1u << AVTP_VERSION_1))

typedef struct {
    uint8_t header[AVTP_PCM_HEADER_LEN_V0];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_Pcm_t;

typedef struct {
    uint8_t header[AVTP_PCM_HEADER_LEN_V1];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_PcmV1_t;

/**
 * AAF PCM 'nsr' (nominal sample rate) field values (IEEE 1722-2025, Table 12).
 * Values 0x0B-0x0F are reserved.
 */
typedef enum {
    AVTP_PCM_NSR_USER = 0x0,
    AVTP_PCM_NSR_8KHZ = 0x1,
    AVTP_PCM_NSR_16KHZ = 0x2,
    AVTP_PCM_NSR_32KHZ = 0x3,
    AVTP_PCM_NSR_44_1KHZ = 0x4,
    AVTP_PCM_NSR_48KHZ = 0x5,
    AVTP_PCM_NSR_88_2KHZ = 0x6,
    AVTP_PCM_NSR_96KHZ = 0x7,
    AVTP_PCM_NSR_176_4KHZ = 0x8,
    AVTP_PCM_NSR_192KHZ = 0x9,
    AVTP_PCM_NSR_24KHZ = 0xA,
} Avtp_PcmNsr_t;

typedef enum {

    /* Common AVTP stream header fields */
    AVTP_PCM_FIELD_SV = 0,
    AVTP_PCM_FIELD_MR,
    AVTP_PCM_FIELD_FSD,
    AVTP_PCM_FIELD_TV,
    AVTP_PCM_FIELD_SEQUENCE_NUM,
    AVTP_PCM_FIELD_FSD0,
    AVTP_PCM_FIELD_FSD1,
    AVTP_PCM_FIELD_TU,
    AVTP_PCM_FIELD_STREAM_ID,
    AVTP_PCM_FIELD_AVTP_TIMESTAMP,
    AVTP_PCM_FIELD_PTP_GRANDMASTER_IDENTITY,
    AVTP_PCM_FIELD_STREAM_DATA_LENGTH,

    /* AAF PCM format-specific fields */
    AVTP_PCM_FIELD_FORMAT,
    AVTP_PCM_FIELD_NSR,
    AVTP_PCM_FIELD_RSV2,
    AVTP_PCM_FIELD_CHANNELS_PER_FRAME,
    AVTP_PCM_FIELD_BIT_DEPTH,
    AVTP_PCM_FIELD_RSV3,
    AVTP_PCM_FIELD_SP,
    AVTP_PCM_FIELD_EVT,
    AVTP_PCM_FIELD_RESERVED2,

    /* Count number of fields for bound checks */
    AVTP_PCM_FIELD_MAX
} Avtp_PcmFields_t;

/**
 * This table maps all IEEE 1722 AAF PCM header fields to a descriptor for
 * version 0. It is complete and in absolute coordinates; the common stream
 * header fields use the same positions as Avtp_CshFieldDescV0.
 */
static const Avtp_FieldDescriptor_t Avtp_PcmFieldDescV0[AVTP_PCM_FIELD_MAX] = {
    [AVTP_PCM_FIELD_SV] = {.quadlet = 0, .offset = 8, .bits = 1},
    [AVTP_PCM_FIELD_MR] = {.quadlet = 0, .offset = 12, .bits = 1},
    [AVTP_PCM_FIELD_FSD] = {.quadlet = 0, .offset = 13, .bits = 2},
    [AVTP_PCM_FIELD_TV] = {.quadlet = 0, .offset = 15, .bits = 1},
    [AVTP_PCM_FIELD_SEQUENCE_NUM] = {.quadlet = 0, .offset = 16, .bits = 8},
    [AVTP_PCM_FIELD_FSD0] = {.quadlet = 0, .offset = 0, .bits = 0},
    [AVTP_PCM_FIELD_FSD1] = {.quadlet = 0, .offset = 24, .bits = 7},
    [AVTP_PCM_FIELD_TU] = {.quadlet = 0, .offset = 31, .bits = 1},
    [AVTP_PCM_FIELD_STREAM_ID] = {.quadlet = 1, .offset = 0, .bits = 64},
    [AVTP_PCM_FIELD_AVTP_TIMESTAMP] = {.quadlet = 3, .offset = 0, .bits = 32},
    [AVTP_PCM_FIELD_PTP_GRANDMASTER_IDENTITY] = {.quadlet = 0, .offset = 0, .bits = 0},
    [AVTP_PCM_FIELD_STREAM_DATA_LENGTH] = {.quadlet = 5, .offset = 0, .bits = 16},
    [AVTP_PCM_FIELD_FORMAT] = {.quadlet = 4, .offset = 0, .bits = 8},
    [AVTP_PCM_FIELD_NSR] = {.quadlet = 4, .offset = 8, .bits = 4},
    [AVTP_PCM_FIELD_RSV2] = {.quadlet = 4, .offset = 12, .bits = 2},
    [AVTP_PCM_FIELD_CHANNELS_PER_FRAME] = {.quadlet = 4, .offset = 14, .bits = 10},
    [AVTP_PCM_FIELD_BIT_DEPTH] = {.quadlet = 4, .offset = 24, .bits = 8},
    [AVTP_PCM_FIELD_RSV3] = {.quadlet = 5, .offset = 16, .bits = 3},
    [AVTP_PCM_FIELD_SP] = {.quadlet = 5, .offset = 19, .bits = 1},
    [AVTP_PCM_FIELD_EVT] = {.quadlet = 5, .offset = 20, .bits = 4},
    [AVTP_PCM_FIELD_RESERVED2] = {.quadlet = 5, .offset = 24, .bits = 8},
};

/**
 * This table maps all IEEE 1722 AAF PCM header fields to a descriptor for
 * version 1. It is complete and in absolute coordinates; the common stream
 * header fields use the same positions as Avtp_CshFieldDescV1.
 */
static const Avtp_FieldDescriptor_t Avtp_PcmFieldDescV1[AVTP_PCM_FIELD_MAX] = {
    [AVTP_PCM_FIELD_SV] = {.quadlet = 0, .offset = 8, .bits = 1},
    [AVTP_PCM_FIELD_MR] = {.quadlet = 0, .offset = 12, .bits = 1},
    [AVTP_PCM_FIELD_FSD] = {.quadlet = 0, .offset = 13, .bits = 2},
    [AVTP_PCM_FIELD_TV] = {.quadlet = 0, .offset = 15, .bits = 1},
    [AVTP_PCM_FIELD_SEQUENCE_NUM] = {.quadlet = 3, .offset = 0, .bits = 32},
    [AVTP_PCM_FIELD_FSD0] = {.quadlet = 0, .offset = 16, .bits = 8},
    [AVTP_PCM_FIELD_FSD1] = {.quadlet = 0, .offset = 24, .bits = 7},
    [AVTP_PCM_FIELD_TU] = {.quadlet = 0, .offset = 31, .bits = 1},
    [AVTP_PCM_FIELD_STREAM_ID] = {.quadlet = 1, .offset = 0, .bits = 64},
    [AVTP_PCM_FIELD_AVTP_TIMESTAMP] = {.quadlet = 4, .offset = 0, .bits = 64},
    [AVTP_PCM_FIELD_PTP_GRANDMASTER_IDENTITY] = {.quadlet = 6, .offset = 0, .bits = 64},
    [AVTP_PCM_FIELD_STREAM_DATA_LENGTH] = {.quadlet = 9, .offset = 0, .bits = 16},
    [AVTP_PCM_FIELD_FORMAT] = {.quadlet = 8, .offset = 0, .bits = 8},
    [AVTP_PCM_FIELD_NSR] = {.quadlet = 8, .offset = 8, .bits = 4},
    [AVTP_PCM_FIELD_RSV2] = {.quadlet = 8, .offset = 12, .bits = 2},
    [AVTP_PCM_FIELD_CHANNELS_PER_FRAME] = {.quadlet = 8, .offset = 14, .bits = 10},
    [AVTP_PCM_FIELD_BIT_DEPTH] = {.quadlet = 8, .offset = 24, .bits = 8},
    [AVTP_PCM_FIELD_RSV3] = {.quadlet = 9, .offset = 16, .bits = 3},
    [AVTP_PCM_FIELD_SP] = {.quadlet = 9, .offset = 19, .bits = 1},
    [AVTP_PCM_FIELD_EVT] = {.quadlet = 9, .offset = 20, .bits = 4},
    [AVTP_PCM_FIELD_RESERVED2] = {.quadlet = 9, .offset = 24, .bits = 8},
};

/**
 * Returns the value of an AVTP AAF PCM field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @param field Specifies the position of the data field to be read
 * @returns This function returns the value of the field.
 */
OPEN1722_INLINE uint64_t Avtp_Pcm_GetField(const Avtp_Pcm_t *const pdu, Avtp_PcmFields_t field)
{
    const Avtp_FieldDescriptor_t *desc =
        Avtp_CommonStreamHeader_GetVersion((const Avtp_CommonStreamHeader_t *)pdu) == AVTP_VERSION_1
            ? Avtp_PcmFieldDescV1
            : Avtp_PcmFieldDescV0;
    return Avtp_GetField(desc, AVTP_PCM_FIELD_MAX, (const uint8_t *)pdu, (uint8_t)field);
}

/**
 * Sets the value of an AVTP AAF PCM field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @param field Specifies the position of the data field to be written
 * @param value The value to set.
 */
OPEN1722_INLINE void Avtp_Pcm_SetField(Avtp_Pcm_t *pdu, Avtp_PcmFields_t field, uint64_t value)
{
    const Avtp_FieldDescriptor_t *desc =
        Avtp_CommonStreamHeader_GetVersion((const Avtp_CommonStreamHeader_t *)pdu) == AVTP_VERSION_1
            ? Avtp_PcmFieldDescV1
            : Avtp_PcmFieldDescV0;
    Avtp_SetField(desc, AVTP_PCM_FIELD_MAX, (uint8_t *)pdu, (uint8_t)field, value);
}

/**
 * Returns the length of the AAF PCM header in octets (24 or 40).
 */
OPEN1722_INLINE uint8_t Avtp_Pcm_GetHeaderLen(const Avtp_Pcm_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetHeaderLen((const Avtp_CommonStreamHeader_t *)pdu);
}

/**
 * Return the value of the AAF PCM SV field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @returns Value of the AAF PCM SV field.
 */
OPEN1722_INLINE bool Avtp_Pcm_IsSv(const Avtp_Pcm_t *const pdu)
{
    return (bool)Avtp_Pcm_GetField(pdu, AVTP_PCM_FIELD_SV);
}

/**
 * Return the value of the AAF PCM MR field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @returns Value of the AAF PCM MR field.
 */
OPEN1722_INLINE bool Avtp_Pcm_IsMr(const Avtp_Pcm_t *const pdu)
{
    return (bool)Avtp_Pcm_GetField(pdu, AVTP_PCM_FIELD_MR);
}

/**
 * Return the value of the AAF PCM TV field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @returns Value of the AAF PCM TV field.
 */
OPEN1722_INLINE bool Avtp_Pcm_IsTv(const Avtp_Pcm_t *const pdu)
{
    return (bool)Avtp_Pcm_GetField(pdu, AVTP_PCM_FIELD_TV);
}

/**
 * Return the value of the AAF PCM Sequence Number field as specified in the IEEE 1722
 * Specification. The field is 8 bits in version 0 and 32 bits in version 1.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @returns Value of the AAF PCM Sequence Number field.
 */
OPEN1722_INLINE uint32_t Avtp_Pcm_GetSequenceNum(const Avtp_Pcm_t *const pdu)
{
    return (uint32_t)Avtp_Pcm_GetField(pdu, AVTP_PCM_FIELD_SEQUENCE_NUM);
}

/**
 * Return the value of the AAF PCM TU field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @returns Value of the AAF PCM TU field.
 */
OPEN1722_INLINE bool Avtp_Pcm_IsTu(const Avtp_Pcm_t *const pdu)
{
    return (bool)Avtp_Pcm_GetField(pdu, AVTP_PCM_FIELD_TU);
}

/**
 * Return the value of the AAF PCM Stream ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @returns Value of the AAF PCM Stream ID field.
 */
OPEN1722_INLINE uint64_t Avtp_Pcm_GetStreamId(const Avtp_Pcm_t *const pdu)
{
    return Avtp_Pcm_GetField(pdu, AVTP_PCM_FIELD_STREAM_ID);
}

/**
 * Return the value of the AAF PCM AVTP Timestamp field as specified in the IEEE 1722
 * Specification. The field is 32 bits in version 0 and 64 bits in version 1.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @returns Value of the AAF PCM AVTP Timestamp field.
 */
OPEN1722_INLINE uint64_t Avtp_Pcm_GetAvtpTimestamp(const Avtp_Pcm_t *const pdu)
{
    return Avtp_Pcm_GetField(pdu, AVTP_PCM_FIELD_AVTP_TIMESTAMP);
}

/**
 * Return the value of the AAF PCM ptp_grandmaster_identity field. The field only
 * exists in version 1; version 0 returns 0.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @returns Value of the AAF PCM ptp_grandmaster_identity field.
 */
OPEN1722_INLINE uint64_t Avtp_Pcm_GetPtpGrandmasterIdentity(const Avtp_Pcm_t *const pdu)
{
    return Avtp_Pcm_GetField(pdu, AVTP_PCM_FIELD_PTP_GRANDMASTER_IDENTITY);
}

/**
 * Return the value of the AAF PCM Format field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @returns Value of the AAF PCM Format field.
 */
OPEN1722_INLINE Avtp_AafFormat_t Avtp_Pcm_GetFormat(const Avtp_Pcm_t *const pdu)
{
    return (Avtp_AafFormat_t)Avtp_Pcm_GetField(pdu, AVTP_PCM_FIELD_FORMAT);
}

/**
 * Return the value of the AAF PCM NSR field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @returns Value of the AAF PCM NSR field.
 */
OPEN1722_INLINE Avtp_PcmNsr_t Avtp_Pcm_GetNsr(const Avtp_Pcm_t *const pdu)
{
    return (Avtp_PcmNsr_t)Avtp_Pcm_GetField(pdu, AVTP_PCM_FIELD_NSR);
}

/**
 * Return the value of the AAF PCM Channels Per Frame field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @returns Value of the AAF PCM Channels Per Frame field.
 */
OPEN1722_INLINE uint16_t Avtp_Pcm_GetChannelsPerFrame(const Avtp_Pcm_t *const pdu)
{
    return (uint16_t)Avtp_Pcm_GetField(pdu, AVTP_PCM_FIELD_CHANNELS_PER_FRAME);
}

/**
 * Return the value of the AAF PCM Bit Depth field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @returns Value of the AAF PCM Bit Depth field.
 */
OPEN1722_INLINE uint8_t Avtp_Pcm_GetBitDepth(const Avtp_Pcm_t *const pdu)
{
    return (uint8_t)Avtp_Pcm_GetField(pdu, AVTP_PCM_FIELD_BIT_DEPTH);
}

/**
 * Return the value of the AAF PCM Stream Data Length field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @returns Value of the AAF PCM Stream Data Length field.
 */
OPEN1722_INLINE uint16_t Avtp_Pcm_GetStreamDataLength(const Avtp_Pcm_t *const pdu)
{
    return (uint16_t)Avtp_Pcm_GetField(pdu, AVTP_PCM_FIELD_STREAM_DATA_LENGTH);
}

/**
 * Return the value of the AAF PCM SP field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @returns Value of the AAF PCM SP field.
 */
OPEN1722_INLINE bool Avtp_Pcm_IsSp(const Avtp_Pcm_t *const pdu)
{
    return (bool)Avtp_Pcm_GetField(pdu, AVTP_PCM_FIELD_SP);
}

/**
 * Return the value of the AAF PCM EVT field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @returns Value of the AAF PCM EVT field.
 */
OPEN1722_INLINE uint8_t Avtp_Pcm_GetEvt(const Avtp_Pcm_t *const pdu)
{
    return (uint8_t)Avtp_Pcm_GetField(pdu, AVTP_PCM_FIELD_EVT);
}

/**
 * Set the SV bit in an AAF PCM frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @param sv Value to set the AAF PCM SV field to.
 */
OPEN1722_INLINE void Avtp_Pcm_SetSv(Avtp_Pcm_t *pdu, bool sv)
{
    Avtp_Pcm_SetField(pdu, AVTP_PCM_FIELD_SV, sv);
}

/**
 * Set the MR bit in an AAF PCM frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @param mr Value to set the AAF PCM MR field to.
 */
OPEN1722_INLINE void Avtp_Pcm_SetMr(Avtp_Pcm_t *pdu, bool mr)
{
    Avtp_Pcm_SetField(pdu, AVTP_PCM_FIELD_MR, mr);
}

/**
 * Set the TV bit in an AAF PCM frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @param tv Value to set the AAF PCM TV field to.
 */
OPEN1722_INLINE void Avtp_Pcm_SetTv(Avtp_Pcm_t *pdu, bool tv)
{
    Avtp_Pcm_SetField(pdu, AVTP_PCM_FIELD_TV, tv);
}

/**
 * Set the value of the AAF PCM Sequence Number field as specified in the IEEE 1722
 * Specification. The field is 8 bits in version 0 and 32 bits in version 1; values are
 * truncated to the width of the version in use.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @param value Value to set the AAF PCM Sequence Number field to.
 */
OPEN1722_INLINE void Avtp_Pcm_SetSequenceNum(Avtp_Pcm_t *pdu, uint32_t value)
{
    Avtp_Pcm_SetField(pdu, AVTP_PCM_FIELD_SEQUENCE_NUM, value);
}

/**
 * Set the TU bit in an AAF PCM frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @param tu Value to set the AAF PCM TU field to.
 */
OPEN1722_INLINE void Avtp_Pcm_SetTu(Avtp_Pcm_t *pdu, bool tu)
{
    Avtp_Pcm_SetField(pdu, AVTP_PCM_FIELD_TU, tu);
}

/**
 * Set the value of the AAF PCM Stream ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @param value Value to set the AAF PCM Stream ID field to.
 */
OPEN1722_INLINE void Avtp_Pcm_SetStreamId(Avtp_Pcm_t *pdu, uint64_t value)
{
    Avtp_Pcm_SetField(pdu, AVTP_PCM_FIELD_STREAM_ID, value);
}

/**
 * Set the value of the AAF PCM AVTP Timestamp field as specified in the IEEE 1722
 * Specification. The field is 32 bits in version 0 and 64 bits in version 1; values are
 * truncated to the width of the version in use.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @param value Value to set the AAF PCM AVTP Timestamp field to.
 */
OPEN1722_INLINE void Avtp_Pcm_SetAvtpTimestamp(Avtp_Pcm_t *pdu, uint64_t value)
{
    Avtp_Pcm_SetField(pdu, AVTP_PCM_FIELD_AVTP_TIMESTAMP, value);
}

/**
 * Set the value of the AAF PCM ptp_grandmaster_identity field. The field only
 * exists in version 1; on version 0 this is a no-op.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @param value Value to set the AAF PCM ptp_grandmaster_identity field to.
 */
OPEN1722_INLINE void Avtp_Pcm_SetPtpGrandmasterIdentity(Avtp_Pcm_t *pdu, uint64_t value)
{
    Avtp_Pcm_SetField(pdu, AVTP_PCM_FIELD_PTP_GRANDMASTER_IDENTITY, value);
}

/**
 * Set the value of the AAF PCM Format field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @param value Value to set the AAF PCM Format field to.
 */
OPEN1722_INLINE void Avtp_Pcm_SetFormat(Avtp_Pcm_t *pdu, Avtp_AafFormat_t value)
{
    Avtp_Pcm_SetField(pdu, AVTP_PCM_FIELD_FORMAT, (uint64_t)value);
}

/**
 * Set the value of the AAF PCM NSR field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @param value Value to set the AAF PCM NSR field to.
 */
OPEN1722_INLINE void Avtp_Pcm_SetNsr(Avtp_Pcm_t *pdu, Avtp_PcmNsr_t value)
{
    Avtp_Pcm_SetField(pdu, AVTP_PCM_FIELD_NSR, (uint64_t)value);
}

/**
 * Set the value of the AAF PCM Channels Per Frame field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @param value Value to set the AAF PCM Channels Per Frame field to.
 */
OPEN1722_INLINE void Avtp_Pcm_SetChannelsPerFrame(Avtp_Pcm_t *pdu, uint16_t value)
{
    Avtp_Pcm_SetField(pdu, AVTP_PCM_FIELD_CHANNELS_PER_FRAME, value);
}

/**
 * Set the value of the AAF PCM Bit Depth field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @param value Value to set the AAF PCM Bit Depth field to.
 */
OPEN1722_INLINE void Avtp_Pcm_SetBitDepth(Avtp_Pcm_t *pdu, uint8_t value)
{
    Avtp_Pcm_SetField(pdu, AVTP_PCM_FIELD_BIT_DEPTH, value);
}

/**
 * Set the value of the AAF PCM Stream Data Length field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @param value Value to set the AAF PCM Stream Data Length field to.
 */
OPEN1722_INLINE void Avtp_Pcm_SetStreamDataLength(Avtp_Pcm_t *pdu, uint16_t value)
{
    Avtp_Pcm_SetField(pdu, AVTP_PCM_FIELD_STREAM_DATA_LENGTH, value);
}

/**
 * Set the SP bit in an AAF PCM frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @param sp Value to set the AAF PCM SP field to.
 */
OPEN1722_INLINE void Avtp_Pcm_SetSp(Avtp_Pcm_t *pdu, bool sp)
{
    Avtp_Pcm_SetField(pdu, AVTP_PCM_FIELD_SP, sp);
}

/**
 * Set the value of the AAF PCM EVT field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @param value Value to set the AAF PCM EVT field to.
 */
OPEN1722_INLINE void Avtp_Pcm_SetEvt(Avtp_Pcm_t *pdu, uint8_t value)
{
    Avtp_Pcm_SetField(pdu, AVTP_PCM_FIELD_EVT, value);
}

/**
 * Returns pointer to payload of an AAF PCM frame. The payload starts after the
 * version-dependent common stream header.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @return Pointer to AAF PCM frame payload
 */
OPEN1722_INLINE const uint8_t *Avtp_Pcm_GetPayload(const Avtp_Pcm_t *const pdu)
{
    return (const uint8_t *)pdu + Avtp_Pcm_GetHeaderLen(pdu);
}

/**
 * Sets the AAF PCM payload in an AAF PCM frame.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload
 */
OPEN1722_INLINE void Avtp_Pcm_SetPayload(Avtp_Pcm_t *pdu, uint8_t *payload, uint16_t payload_length)
{
    memcpy((uint8_t *)pdu + Avtp_Pcm_GetHeaderLen(pdu), payload, payload_length);
}

/**
 * Initializes a version 0 AAF PCM PDU as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of a 1722 AAF PCM PDU.
 */
OPEN1722_INLINE void Avtp_Pcm_Init(Avtp_Pcm_t *pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_Pcm_t));
        Avtp_CommonHeader_SetSubtype((Avtp_CommonHeader_t *)pdu, AVTP_SUBTYPE_AAF);
        Avtp_Pcm_SetSv(pdu, true);
    }
}

/**
 * Initializes a version 1 AAF PCM PDU. The caller must provide a buffer of at
 * least AVTP_PCM_HEADER_LEN_V1 octets.
 *
 * @param pdu Pointer to the first bit of a 1722 AAF PCM PDU.
 */
OPEN1722_INLINE void Avtp_Pcm_InitV1(Avtp_PcmV1_t *pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_PcmV1_t));
        Avtp_CommonHeader_SetSubtype((Avtp_CommonHeader_t *)pdu, AVTP_SUBTYPE_AAF);
        Avtp_CommonHeader_SetVersion((Avtp_CommonHeader_t *)pdu, AVTP_VERSION_1);
        Avtp_Pcm_SetSv((Avtp_Pcm_t *)pdu, true);
    }
}

/**
 * Checks if the AAF PCM frame is valid by checking:
 *     1) that the subtype is AAF and the version is supported,
 *     2) that the version-dependent header and the stream_data_length fit into
 *        the buffer (via Avtp_Aaf_IsValid), and
 *     3) the PCM-specific invariants.
 *
 * The PCM specific invariants are defined in IEEE 1722-2025, 7.3:
 *     - only the PCM formats (Table 10, values 0x00-0x04) use this encapsulation,
 *     - channels_per_frame shall be a positive integer (7.3.3),
 *     - bit_depth shall not be zero and shall not exceed the sample container size
 *       implied by the format field (7.3.4).
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PCM PDU.
 * @param bufferSize Size of the buffer containing the AAF PCM frame.
 * @return true if the AAF PCM frame is valid, false otherwise.
 */
OPEN1722_INLINE bool Avtp_Pcm_IsValid(const Avtp_Pcm_t *const pdu, size_t bufferSize)
{
    if (!Avtp_Aaf_IsValid((const Avtp_Aaf_t *)pdu, bufferSize)) {
        return false;
    }

    /* Only the PCM formats use this encapsulation: format values 0x00-0x04 are PCM,
     * 0x05 is AES3 and 0x06-0xFF are reserved (IEEE 1722-2025, Table 10). */
    Avtp_AafFormat_t format = Avtp_Pcm_GetFormat(pdu);
    if (format > AVTP_AAF_FORMAT_INT_16BIT) {
        return false;
    }

    /* channels_per_frame shall be a positive integer (IEEE 1722-2025, 7.3.3). */
    if (Avtp_Pcm_GetChannelsPerFrame(pdu) == 0) {
        return false;
    }

    /* bit_depth shall not be zero (IEEE 1722-2025, 7.3.4). */
    uint8_t bit_depth = Avtp_Pcm_GetBitDepth(pdu);
    if (bit_depth == 0) {
        return false;
    }

    /* bit_depth shall not be larger than the sample container size of the format.
     * For FLOAT_32BIT it shall be exactly 32 (IEEE 1722-2025, 7.3.4). */
    switch (format) {
    case AVTP_AAF_FORMAT_USER:
        /* The sample container size of a user-specified format is not defined by
         * the standard, so bit_depth cannot be constrained (IEEE 1722-2025, 7.3.1). */
        break;
    case AVTP_AAF_FORMAT_FLOAT_32BIT:
        if (bit_depth != 32) {
            return false;
        }
        break;
    case AVTP_AAF_FORMAT_INT_32BIT:
        if (bit_depth > 32) {
            return false;
        }
        break;
    case AVTP_AAF_FORMAT_INT_24BIT:
        if (bit_depth > 24) {
            return false;
        }
        break;
    case AVTP_AAF_FORMAT_INT_16BIT:
        if (bit_depth > 16) {
            return false;
        }
        break;
    default:
        /* AES3 and reserved format values are not PCM (IEEE 1722-2025, Table 10). */
        return false;
    }

    return true;
}

#ifdef __cplusplus
}
#endif
