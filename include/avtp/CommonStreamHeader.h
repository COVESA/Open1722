/*
 * Copyright (c) 2026, COVESA
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
 * This file contains the field descriptions of the IEEE 1722 AVTPDU common
 * stream header (4.7.4) for versions 0 and 1 and functions to invoke the
 * corresponding parser and deparser. The format-specific data slots 2 and 3
 * are not covered here; their contents are defined by the individual formats.
 *
 * Format modules declare complete descriptor tables per version in absolute
 * coordinates, reusing these positions for the common fields. A consistency
 * test keeps the common entries of each format aligned with the tables here.
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

#ifdef __cplusplus
extern "C" {
#endif

/* AVTPDU common stream header length in octets (IEEE 1722-2025, 4.7.4). */
#define AVTPDU_CSH_LEN_V0 (6 * AVTP_QUADLET_SIZE)  /* 24 */
#define AVTPDU_CSH_LEN_V1 (10 * AVTP_QUADLET_SIZE) /* 40 */

/**
 * View type for the AVTPDU common stream header. The header is 24 octets for
 * version 0 and 40 octets for version 1, so the view is sized for the largest
 * version. Every accessor dispatches on the version field of the common header.
 */
typedef struct {
    uint8_t header[AVTPDU_CSH_LEN_V1];
    uint8_t payload[0];
} Avtp_CommonStreamHeader_t;

/**
 * Enumeration over all IEEE 1722 AVTPDU common stream header fields. The
 * naming convention used is AVTPDU_<HEADER>_FIELD_<FIELD_NAME>.
 */
typedef enum {
    AVTPDU_CSH_FIELD_SV = 0,
    AVTPDU_CSH_FIELD_MR,
    AVTPDU_CSH_FIELD_FSD,
    AVTPDU_CSH_FIELD_TV,
    AVTPDU_CSH_FIELD_SEQUENCE_NUM,
    AVTPDU_CSH_FIELD_FSD0,
    AVTPDU_CSH_FIELD_FSD1,
    AVTPDU_CSH_FIELD_TU,
    AVTPDU_CSH_FIELD_STREAM_ID,
    AVTPDU_CSH_FIELD_AVTP_TIMESTAMP,
    AVTPDU_CSH_FIELD_PTP_GRANDMASTER_IDENTITY,
    AVTPDU_CSH_FIELD_STREAM_DATA_LENGTH,

    /* Count number of fields for bound checks */
    AVTPDU_CSH_FIELD_MAX
} Avtp_CommonStreamHeaderField_t;

/**
 * These tables map all IEEE 1722 AVTPDU common stream header fields to a
 * descriptor, one table per version. Fields that are absent from a version
 * have a zero-initialized descriptor (bits = 0): reading them returns 0 and
 * writing them is a no-op. The accessors select the table that matches the
 * version field of the PDU.
 */
static const Avtp_FieldDescriptor_t Avtp_CshFieldDescV0[AVTPDU_CSH_FIELD_MAX] = {
    [AVTPDU_CSH_FIELD_SV] = {.quadlet = 0, .offset = 8, .bits = 1},
    [AVTPDU_CSH_FIELD_MR] = {.quadlet = 0, .offset = 12, .bits = 1},
    [AVTPDU_CSH_FIELD_FSD] = {.quadlet = 0, .offset = 13, .bits = 2},
    [AVTPDU_CSH_FIELD_TV] = {.quadlet = 0, .offset = 15, .bits = 1},
    [AVTPDU_CSH_FIELD_SEQUENCE_NUM] = {.quadlet = 0, .offset = 16, .bits = 8},
    [AVTPDU_CSH_FIELD_FSD0] = {.quadlet = 0, .offset = 0, .bits = 0},
    [AVTPDU_CSH_FIELD_FSD1] = {.quadlet = 0, .offset = 24, .bits = 7},
    [AVTPDU_CSH_FIELD_TU] = {.quadlet = 0, .offset = 31, .bits = 1},
    [AVTPDU_CSH_FIELD_STREAM_ID] = {.quadlet = 1, .offset = 0, .bits = 64},
    [AVTPDU_CSH_FIELD_AVTP_TIMESTAMP] = {.quadlet = 3, .offset = 0, .bits = 32},
    [AVTPDU_CSH_FIELD_PTP_GRANDMASTER_IDENTITY] = {.quadlet = 0, .offset = 0, .bits = 0},
    [AVTPDU_CSH_FIELD_STREAM_DATA_LENGTH] = {.quadlet = 5, .offset = 0, .bits = 16},
};

static const Avtp_FieldDescriptor_t Avtp_CshFieldDescV1[AVTPDU_CSH_FIELD_MAX] = {
    [AVTPDU_CSH_FIELD_SV] = {.quadlet = 0, .offset = 8, .bits = 1},
    [AVTPDU_CSH_FIELD_MR] = {.quadlet = 0, .offset = 12, .bits = 1},
    [AVTPDU_CSH_FIELD_FSD] = {.quadlet = 0, .offset = 13, .bits = 2},
    [AVTPDU_CSH_FIELD_TV] = {.quadlet = 0, .offset = 15, .bits = 1},
    [AVTPDU_CSH_FIELD_SEQUENCE_NUM] = {.quadlet = 3, .offset = 0, .bits = 32},
    [AVTPDU_CSH_FIELD_FSD0] = {.quadlet = 0, .offset = 16, .bits = 8},
    [AVTPDU_CSH_FIELD_FSD1] = {.quadlet = 0, .offset = 24, .bits = 7},
    [AVTPDU_CSH_FIELD_TU] = {.quadlet = 0, .offset = 31, .bits = 1},
    [AVTPDU_CSH_FIELD_STREAM_ID] = {.quadlet = 1, .offset = 0, .bits = 64},
    [AVTPDU_CSH_FIELD_AVTP_TIMESTAMP] = {.quadlet = 4, .offset = 0, .bits = 64},
    [AVTPDU_CSH_FIELD_PTP_GRANDMASTER_IDENTITY] = {.quadlet = 6, .offset = 0, .bits = 64},
    [AVTPDU_CSH_FIELD_STREAM_DATA_LENGTH] = {.quadlet = 9, .offset = 0, .bits = 16},
};

/**
 * Returns the raw version field of the AVTPDU common header. Values other than
 * 0 or 1 are reserved; the accessors treat anything other than 1 as version 0.
 */
OPEN1722_INLINE uint8_t
Avtp_CommonStreamHeader_GetVersion(const Avtp_CommonStreamHeader_t *const pdu)
{
    return Avtp_CommonHeader_GetVersion((const Avtp_CommonHeader_t *)pdu);
}

/**
 * Returns the length of the common stream header in octets (24 or 40).
 */
OPEN1722_INLINE uint8_t
Avtp_CommonStreamHeader_GetHeaderLen(const Avtp_CommonStreamHeader_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetVersion(pdu) == AVTP_VERSION_1 ? (uint8_t)AVTPDU_CSH_LEN_V1
                                                                     : (uint8_t)AVTPDU_CSH_LEN_V0;
}

/**
 * Returns the value of an AVTPDU common stream header field.
 *
 * @param pdu Pointer to the first bit of an 1722 AVTP PDU.
 * @param field Specifies the position of the data field to be read.
 * @returns The value of the specified field.
 */
OPEN1722_INLINE uint64_t Avtp_CommonStreamHeader_GetField(
    const Avtp_CommonStreamHeader_t *const pdu, Avtp_CommonStreamHeaderField_t field)
{
    const Avtp_FieldDescriptor_t *desc = Avtp_CommonStreamHeader_GetVersion(pdu) == AVTP_VERSION_1
                                             ? Avtp_CshFieldDescV1
                                             : Avtp_CshFieldDescV0;
    return Avtp_GetField(desc, AVTPDU_CSH_FIELD_MAX, (const uint8_t *)pdu, (uint8_t)field);
}

/**
 * Sets the value of an AVTPDU common stream header field. Fields absent from
 * the version in use are left untouched.
 *
 * @param pdu Pointer to the first bit of an 1722 AVTP PDU.
 * @param field Specifies the position of the data field to be written.
 * @param value The value to set.
 */
OPEN1722_INLINE void Avtp_CommonStreamHeader_SetField(Avtp_CommonStreamHeader_t *pdu,
                                                      Avtp_CommonStreamHeaderField_t field,
                                                      uint64_t value)
{
    const Avtp_FieldDescriptor_t *desc = Avtp_CommonStreamHeader_GetVersion(pdu) == AVTP_VERSION_1
                                             ? Avtp_CshFieldDescV1
                                             : Avtp_CshFieldDescV0;
    Avtp_SetField(desc, AVTPDU_CSH_FIELD_MAX, (uint8_t *)pdu, (uint8_t)field, value);
}

/**
 * Returns the sv (stream_id valid) bit of the AVTPDU common stream header.
 */
OPEN1722_INLINE bool Avtp_CommonStreamHeader_IsSv(const Avtp_CommonStreamHeader_t *const pdu)
{
    return (bool)Avtp_CommonStreamHeader_GetField(pdu, AVTPDU_CSH_FIELD_SV);
}

/**
 * Sets the sv (stream_id valid) bit of the AVTPDU common stream header.
 */
OPEN1722_INLINE void Avtp_CommonStreamHeader_SetSv(Avtp_CommonStreamHeader_t *pdu, bool sv)
{
    Avtp_CommonStreamHeader_SetField(pdu, AVTPDU_CSH_FIELD_SV, sv);
}

/**
 * Returns the mr (media clock restart) bit of the AVTPDU common stream header.
 */
OPEN1722_INLINE bool Avtp_CommonStreamHeader_IsMr(const Avtp_CommonStreamHeader_t *const pdu)
{
    return (bool)Avtp_CommonStreamHeader_GetField(pdu, AVTPDU_CSH_FIELD_MR);
}

/**
 * Sets the mr (media clock restart) bit of the AVTPDU common stream header.
 */
OPEN1722_INLINE void Avtp_CommonStreamHeader_SetMr(Avtp_CommonStreamHeader_t *pdu, bool mr)
{
    Avtp_CommonStreamHeader_SetField(pdu, AVTPDU_CSH_FIELD_MR, mr);
}

/**
 * Returns the tv (avtp_timestamp valid) bit of the AVTPDU common stream header.
 */
OPEN1722_INLINE bool Avtp_CommonStreamHeader_IsTv(const Avtp_CommonStreamHeader_t *const pdu)
{
    return (bool)Avtp_CommonStreamHeader_GetField(pdu, AVTPDU_CSH_FIELD_TV);
}

/**
 * Sets the tv (avtp_timestamp valid) bit of the AVTPDU common stream header.
 */
OPEN1722_INLINE void Avtp_CommonStreamHeader_SetTv(Avtp_CommonStreamHeader_t *pdu, bool tv)
{
    Avtp_CommonStreamHeader_SetField(pdu, AVTPDU_CSH_FIELD_TV, tv);
}

/**
 * Returns the tu (timestamp uncertain) bit of the AVTPDU common stream header.
 */
OPEN1722_INLINE bool Avtp_CommonStreamHeader_IsTu(const Avtp_CommonStreamHeader_t *const pdu)
{
    return (bool)Avtp_CommonStreamHeader_GetField(pdu, AVTPDU_CSH_FIELD_TU);
}

/**
 * Sets the tu (timestamp uncertain) bit of the AVTPDU common stream header.
 */
OPEN1722_INLINE void Avtp_CommonStreamHeader_SetTu(Avtp_CommonStreamHeader_t *pdu, bool tu)
{
    Avtp_CommonStreamHeader_SetField(pdu, AVTPDU_CSH_FIELD_TU, tu);
}

/**
 * Returns the f_s_d (format-specific data) field of the AVTPDU common stream
 * header. Its interpretation is defined by the format.
 */
OPEN1722_INLINE uint8_t Avtp_CommonStreamHeader_GetFsd(const Avtp_CommonStreamHeader_t *const pdu)
{
    return (uint8_t)Avtp_CommonStreamHeader_GetField(pdu, AVTPDU_CSH_FIELD_FSD);
}

/**
 * Sets the f_s_d (format-specific data) field of the AVTPDU common stream
 * header. Its interpretation is defined by the format.
 */
OPEN1722_INLINE void Avtp_CommonStreamHeader_SetFsd(Avtp_CommonStreamHeader_t *pdu, uint8_t fsd)
{
    Avtp_CommonStreamHeader_SetField(pdu, AVTPDU_CSH_FIELD_FSD, fsd);
}

/**
 * Returns the format_specific_data_0 field of the AVTPDU common stream header.
 * The field only exists in version 1; version 0 returns 0.
 */
OPEN1722_INLINE uint8_t
Avtp_CommonStreamHeader_GetFormatSpecificData0(const Avtp_CommonStreamHeader_t *const pdu)
{
    return (uint8_t)Avtp_CommonStreamHeader_GetField(pdu, AVTPDU_CSH_FIELD_FSD0);
}

/**
 * Sets the format_specific_data_0 field of the AVTPDU common stream header.
 * The field only exists in version 1; on version 0 this is a no-op.
 */
OPEN1722_INLINE void Avtp_CommonStreamHeader_SetFormatSpecificData0(Avtp_CommonStreamHeader_t *pdu,
                                                                    uint8_t value)
{
    Avtp_CommonStreamHeader_SetField(pdu, AVTPDU_CSH_FIELD_FSD0, value);
}

/**
 * Returns the format_specific_data_1 field of the AVTPDU common stream header.
 * Its interpretation is defined by the format.
 */
OPEN1722_INLINE uint8_t
Avtp_CommonStreamHeader_GetFormatSpecificData1(const Avtp_CommonStreamHeader_t *const pdu)
{
    return (uint8_t)Avtp_CommonStreamHeader_GetField(pdu, AVTPDU_CSH_FIELD_FSD1);
}

/**
 * Sets the format_specific_data_1 field of the AVTPDU common stream header.
 * Its interpretation is defined by the format.
 */
OPEN1722_INLINE void Avtp_CommonStreamHeader_SetFormatSpecificData1(Avtp_CommonStreamHeader_t *pdu,
                                                                    uint8_t value)
{
    Avtp_CommonStreamHeader_SetField(pdu, AVTPDU_CSH_FIELD_FSD1, value);
}

/**
 * Returns the sequence_num field of the AVTPDU common stream header. The field
 * is 8 bits in version 0 and 32 bits in version 1.
 */
OPEN1722_INLINE uint32_t
Avtp_CommonStreamHeader_GetSequenceNum(const Avtp_CommonStreamHeader_t *const pdu)
{
    return (uint32_t)Avtp_CommonStreamHeader_GetField(pdu, AVTPDU_CSH_FIELD_SEQUENCE_NUM);
}

/**
 * Sets the sequence_num field of the AVTPDU common stream header. The field is
 * 8 bits in version 0 and 32 bits in version 1; values are truncated to the
 * width of the version in use.
 */
OPEN1722_INLINE void Avtp_CommonStreamHeader_SetSequenceNum(Avtp_CommonStreamHeader_t *pdu,
                                                            uint32_t value)
{
    Avtp_CommonStreamHeader_SetField(pdu, AVTPDU_CSH_FIELD_SEQUENCE_NUM, value);
}

/**
 * Returns the stream_id field of the AVTPDU common stream header.
 */
OPEN1722_INLINE uint64_t
Avtp_CommonStreamHeader_GetStreamId(const Avtp_CommonStreamHeader_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetField(pdu, AVTPDU_CSH_FIELD_STREAM_ID);
}

/**
 * Sets the stream_id field of the AVTPDU common stream header.
 */
OPEN1722_INLINE void Avtp_CommonStreamHeader_SetStreamId(Avtp_CommonStreamHeader_t *pdu,
                                                         uint64_t value)
{
    Avtp_CommonStreamHeader_SetField(pdu, AVTPDU_CSH_FIELD_STREAM_ID, value);
}

/**
 * Returns the avtp_timestamp field of the AVTPDU common stream header. The
 * field is 32 bits in version 0 and 64 bits in version 1.
 */
OPEN1722_INLINE uint64_t
Avtp_CommonStreamHeader_GetAvtpTimestamp(const Avtp_CommonStreamHeader_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetField(pdu, AVTPDU_CSH_FIELD_AVTP_TIMESTAMP);
}

/**
 * Sets the avtp_timestamp field of the AVTPDU common stream header. The field
 * is 32 bits in version 0 and 64 bits in version 1; values are truncated to
 * the width of the version in use.
 */
OPEN1722_INLINE void Avtp_CommonStreamHeader_SetAvtpTimestamp(Avtp_CommonStreamHeader_t *pdu,
                                                              uint64_t value)
{
    Avtp_CommonStreamHeader_SetField(pdu, AVTPDU_CSH_FIELD_AVTP_TIMESTAMP, value);
}

/**
 * Returns the ptp_grandmaster_identity field of the AVTPDU common stream
 * header. The field only exists in version 1; version 0 returns 0.
 */
OPEN1722_INLINE uint64_t
Avtp_CommonStreamHeader_GetPtpGrandmasterIdentity(const Avtp_CommonStreamHeader_t *const pdu)
{
    return Avtp_CommonStreamHeader_GetField(pdu, AVTPDU_CSH_FIELD_PTP_GRANDMASTER_IDENTITY);
}

/**
 * Sets the ptp_grandmaster_identity field of the AVTPDU common stream header.
 * The field only exists in version 1; on version 0 this is a no-op.
 */
OPEN1722_INLINE void
Avtp_CommonStreamHeader_SetPtpGrandmasterIdentity(Avtp_CommonStreamHeader_t *pdu, uint64_t value)
{
    Avtp_CommonStreamHeader_SetField(pdu, AVTPDU_CSH_FIELD_PTP_GRANDMASTER_IDENTITY, value);
}

/**
 * Returns the stream_data_length field of the AVTPDU common stream header. The
 * value is the length in octets of the stream_data_payload field.
 */
OPEN1722_INLINE uint16_t
Avtp_CommonStreamHeader_GetStreamDataLength(const Avtp_CommonStreamHeader_t *const pdu)
{
    return (uint16_t)Avtp_CommonStreamHeader_GetField(pdu, AVTPDU_CSH_FIELD_STREAM_DATA_LENGTH);
}

/**
 * Sets the stream_data_length field of the AVTPDU common stream header. The
 * value is the length in octets of the stream_data_payload field.
 */
OPEN1722_INLINE void Avtp_CommonStreamHeader_SetStreamDataLength(Avtp_CommonStreamHeader_t *pdu,
                                                                 uint16_t value)
{
    Avtp_CommonStreamHeader_SetField(pdu, AVTPDU_CSH_FIELD_STREAM_DATA_LENGTH, value);
}

#ifdef __cplusplus
}
#endif
