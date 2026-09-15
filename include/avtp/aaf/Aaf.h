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

#define AVTP_AAF_HEADER_LEN (6 * AVTP_QUADLET_SIZE)

#define GET_AAF_FIELD(field)                                                                       \
    (Avtp_GetField(Avtp_AafFieldDesc, AVTP_AAF_FIELD_MAX, (const uint8_t *)pdu, field))
#define SET_AAF_FIELD(field, value)                                                                \
    (Avtp_SetField(Avtp_AafFieldDesc, AVTP_AAF_FIELD_MAX, (uint8_t *)pdu, field, value))

typedef struct {
    uint8_t header[AVTP_AAF_HEADER_LEN];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_Aaf_t;

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
    AVTP_AAF_FIELD_SUBTYPE,
    AVTP_AAF_FIELD_SV,
    AVTP_AAF_FIELD_VERSION,
    AVTP_AAF_FIELD_MR,
    AVTP_AAF_FIELD_RSV,
    AVTP_AAF_FIELD_TV,
    AVTP_AAF_FIELD_SEQUENCE_NUM,
    AVTP_AAF_FIELD_RESERVED,
    AVTP_AAF_FIELD_TU,

    /* AAF common stream header fields */
    AVTP_AAF_FIELD_STREAM_ID,
    AVTP_AAF_FIELD_AVTP_TIMESTAMP,
    AVTP_AAF_FIELD_FORMAT,
    AVTP_AAF_FIELD_AAF_FORMAT_SPECIFIC_DATA_1,
    AVTP_AAF_FIELD_STREAM_DATA_LENGTH,
    AVTP_AAF_FIELD_AFSD,
    AVTP_AAF_FIELD_SP,
    AVTP_AAF_FIELD_EVT,
    AVTP_AAF_FIELD_AAF_FORMAT_SPECIFIC_DATA_2,

    /* Count number of fields for bound checks */
    AVTP_AAF_FIELD_MAX
} Avtp_AafFields_t;

/**
 * This table maps all IEEE 1722 AAF common stream header fields to a descriptor.
 */
static const Avtp_FieldDescriptor_t Avtp_AafFieldDesc[AVTP_AAF_FIELD_MAX] = {
    /* Common AVTP stream header fields */
    [AVTP_AAF_FIELD_SUBTYPE] = {.quadlet = 0, .offset = 0, .bits = 8},
    [AVTP_AAF_FIELD_SV] = {.quadlet = 0, .offset = 8, .bits = 1},
    [AVTP_AAF_FIELD_VERSION] = {.quadlet = 0, .offset = 9, .bits = 3},
    [AVTP_AAF_FIELD_MR] = {.quadlet = 0, .offset = 12, .bits = 1},
    [AVTP_AAF_FIELD_RSV] = {.quadlet = 0, .offset = 13, .bits = 2},
    [AVTP_AAF_FIELD_TV] = {.quadlet = 0, .offset = 15, .bits = 1},
    [AVTP_AAF_FIELD_SEQUENCE_NUM] = {.quadlet = 0, .offset = 16, .bits = 8},
    [AVTP_AAF_FIELD_RESERVED] = {.quadlet = 0, .offset = 24, .bits = 7},
    [AVTP_AAF_FIELD_TU] = {.quadlet = 0, .offset = 31, .bits = 1},
    /* AAF common stream header fields */
    [AVTP_AAF_FIELD_STREAM_ID] = {.quadlet = 1, .offset = 0, .bits = 64},
    [AVTP_AAF_FIELD_AVTP_TIMESTAMP] = {.quadlet = 3, .offset = 0, .bits = 32},
    [AVTP_AAF_FIELD_FORMAT] = {.quadlet = 4, .offset = 0, .bits = 8},
    [AVTP_AAF_FIELD_AAF_FORMAT_SPECIFIC_DATA_1] = {.quadlet = 4, .offset = 8, .bits = 24},
    [AVTP_AAF_FIELD_STREAM_DATA_LENGTH] = {.quadlet = 5, .offset = 0, .bits = 16},
    [AVTP_AAF_FIELD_AFSD] = {.quadlet = 5, .offset = 16, .bits = 3},
    [AVTP_AAF_FIELD_SP] = {.quadlet = 5, .offset = 19, .bits = 1},
    [AVTP_AAF_FIELD_EVT] = {.quadlet = 5, .offset = 20, .bits = 4},
    [AVTP_AAF_FIELD_AAF_FORMAT_SPECIFIC_DATA_2] = {.quadlet = 5, .offset = 24, .bits = 8},
};

/**
 * Return the value of the AAF SV field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @returns Value of the AAF SV field.
 */
OPEN1722_INLINE bool Avtp_Aaf_IsSv(const Avtp_Aaf_t *const pdu)
{
    return (bool)GET_AAF_FIELD(AVTP_AAF_FIELD_SV);
}

/**
 * Return the value of the AAF MR field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @returns Value of the AAF MR field.
 */
OPEN1722_INLINE bool Avtp_Aaf_IsMr(const Avtp_Aaf_t *const pdu)
{
    return (bool)GET_AAF_FIELD(AVTP_AAF_FIELD_MR);
}

/**
 * Return the value of the AAF TV field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @returns Value of the AAF TV field.
 */
OPEN1722_INLINE bool Avtp_Aaf_IsTv(const Avtp_Aaf_t *const pdu)
{
    return (bool)GET_AAF_FIELD(AVTP_AAF_FIELD_TV);
}

/**
 * Return the value of the AAF Sequence Number field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @returns Value of the AAF Sequence Number field.
 */
OPEN1722_INLINE uint8_t Avtp_Aaf_GetSequenceNum(const Avtp_Aaf_t *const pdu)
{
    return (uint8_t)GET_AAF_FIELD(AVTP_AAF_FIELD_SEQUENCE_NUM);
}

/**
 * Return the value of the AAF TU field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @returns Value of the AAF TU field.
 */
OPEN1722_INLINE bool Avtp_Aaf_IsTu(const Avtp_Aaf_t *const pdu)
{
    return (bool)GET_AAF_FIELD(AVTP_AAF_FIELD_TU);
}

/**
 * Return the value of the AAF Stream ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @returns Value of the AAF Stream ID field.
 */
OPEN1722_INLINE uint64_t Avtp_Aaf_GetStreamId(const Avtp_Aaf_t *const pdu)
{
    return (uint64_t)GET_AAF_FIELD(AVTP_AAF_FIELD_STREAM_ID);
}

/**
 * Return the value of the AAF AVTP Timestamp field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @returns Value of the AAF AVTP Timestamp field.
 */
OPEN1722_INLINE uint32_t Avtp_Aaf_GetAvtpTimestamp(const Avtp_Aaf_t *const pdu)
{
    return (uint32_t)GET_AAF_FIELD(AVTP_AAF_FIELD_AVTP_TIMESTAMP);
}

/**
 * Return the value of the AAF Format field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @returns Value of the AAF Format field.
 */
OPEN1722_INLINE Avtp_AafFormat_t Avtp_Aaf_GetFormat(const Avtp_Aaf_t *const pdu)
{
    return (Avtp_AafFormat_t)GET_AAF_FIELD(AVTP_AAF_FIELD_FORMAT);
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
    return (uint32_t)GET_AAF_FIELD(AVTP_AAF_FIELD_AAF_FORMAT_SPECIFIC_DATA_1);
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
    return (uint16_t)GET_AAF_FIELD(AVTP_AAF_FIELD_STREAM_DATA_LENGTH);
}

/**
 * Return the value of the AAF AFSD field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @returns Value of the AAF AFSD field.
 */
OPEN1722_INLINE uint8_t Avtp_Aaf_GetAfsd(const Avtp_Aaf_t *const pdu)
{
    return (uint8_t)GET_AAF_FIELD(AVTP_AAF_FIELD_AFSD);
}

/**
 * Return the value of the AAF SP field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @returns Value of the AAF SP field.
 */
OPEN1722_INLINE bool Avtp_Aaf_IsSp(const Avtp_Aaf_t *const pdu)
{
    return (bool)GET_AAF_FIELD(AVTP_AAF_FIELD_SP);
}

/**
 * Return the value of the AAF EVT field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @returns Value of the AAF EVT field.
 */
OPEN1722_INLINE uint8_t Avtp_Aaf_GetEvt(const Avtp_Aaf_t *const pdu)
{
    return (uint8_t)GET_AAF_FIELD(AVTP_AAF_FIELD_EVT);
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
    return (uint8_t)GET_AAF_FIELD(AVTP_AAF_FIELD_AAF_FORMAT_SPECIFIC_DATA_2);
}

/**
 * Set the SV bit in an AAF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param sv Value to set the AAF SV field to.
 */
OPEN1722_INLINE void Avtp_Aaf_SetSv(Avtp_Aaf_t *pdu, bool sv)
{
    SET_AAF_FIELD(AVTP_AAF_FIELD_SV, sv);
}

/**
 * Set the MR bit in an AAF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param mr Value to set the AAF MR field to.
 */
OPEN1722_INLINE void Avtp_Aaf_SetMr(Avtp_Aaf_t *pdu, bool mr)
{
    SET_AAF_FIELD(AVTP_AAF_FIELD_MR, mr);
}

/**
 * Set the TV bit in an AAF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param tv Value to set the AAF TV field to.
 */
OPEN1722_INLINE void Avtp_Aaf_SetTv(Avtp_Aaf_t *pdu, bool tv)
{
    SET_AAF_FIELD(AVTP_AAF_FIELD_TV, tv);
}

/**
 * Set the value of the AAF Sequence Number field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param value Value to set the AAF Sequence Number field to.
 */
OPEN1722_INLINE void Avtp_Aaf_SetSequenceNum(Avtp_Aaf_t *pdu, uint8_t value)
{
    SET_AAF_FIELD(AVTP_AAF_FIELD_SEQUENCE_NUM, value);
}

/**
 * Set the TU bit in an AAF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param tu Value to set the AAF TU field to.
 */
OPEN1722_INLINE void Avtp_Aaf_SetTu(Avtp_Aaf_t *pdu, bool tu)
{
    SET_AAF_FIELD(AVTP_AAF_FIELD_TU, tu);
}

/**
 * Set the value of the AAF Stream ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param value Value to set the AAF Stream ID field to.
 */
OPEN1722_INLINE void Avtp_Aaf_SetStreamId(Avtp_Aaf_t *pdu, uint64_t value)
{
    SET_AAF_FIELD(AVTP_AAF_FIELD_STREAM_ID, value);
}

/**
 * Set the value of the AAF AVTP Timestamp field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param value Value to set the AAF AVTP Timestamp field to.
 */
OPEN1722_INLINE void Avtp_Aaf_SetAvtpTimestamp(Avtp_Aaf_t *pdu, uint32_t value)
{
    SET_AAF_FIELD(AVTP_AAF_FIELD_AVTP_TIMESTAMP, value);
}

/**
 * Set the value of the AAF Format field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param value Value to set the AAF Format field to.
 */
OPEN1722_INLINE void Avtp_Aaf_SetFormat(Avtp_Aaf_t *pdu, Avtp_AafFormat_t value)
{
    SET_AAF_FIELD(AVTP_AAF_FIELD_FORMAT, (uint64_t)value);
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
    SET_AAF_FIELD(AVTP_AAF_FIELD_AAF_FORMAT_SPECIFIC_DATA_1, value);
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
    SET_AAF_FIELD(AVTP_AAF_FIELD_STREAM_DATA_LENGTH, value);
}

/**
 * Set the value of the AAF AFSD field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param value Value to set the AAF AFSD field to.
 */
OPEN1722_INLINE void Avtp_Aaf_SetAfsd(Avtp_Aaf_t *pdu, uint8_t value)
{
    SET_AAF_FIELD(AVTP_AAF_FIELD_AFSD, value);
}

/**
 * Set the SP bit in an AAF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param sp Value to set the AAF SP field to.
 */
OPEN1722_INLINE void Avtp_Aaf_SetSp(Avtp_Aaf_t *pdu, bool sp)
{
    SET_AAF_FIELD(AVTP_AAF_FIELD_SP, sp);
}

/**
 * Set the value of the AAF EVT field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param value Value to set the AAF EVT field to.
 */
OPEN1722_INLINE void Avtp_Aaf_SetEvt(Avtp_Aaf_t *pdu, uint8_t value)
{
    SET_AAF_FIELD(AVTP_AAF_FIELD_EVT, value);
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
    SET_AAF_FIELD(AVTP_AAF_FIELD_AAF_FORMAT_SPECIFIC_DATA_2, value);
}

/**
 * Returns pointer to payload of an AAF frame.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @return Pointer to AAF frame payload
 */
OPEN1722_INLINE const uint8_t *Avtp_Aaf_GetPayload(const Avtp_Aaf_t *const pdu)
{
    return pdu->payload;
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
    memcpy(pdu->payload, payload, payload_length);
}

/**
 * Initializes an AAF PDU as specified in the IEEE 1722 Specification.
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
 * Checks if the AAF frame is valid by checking:
 *     1) if the length field of the AAF stream data contains a value larger than the actual size of
 * the buffer that contains the AVTP message. 2) if other format specific invariants are not upheld.
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

    if (bufferSize < AVTP_AAF_HEADER_LEN) {
        return false;
    }

    if (Avtp_CommonHeader_GetSubtype((const Avtp_CommonHeader_t *)pdu) != AVTP_SUBTYPE_AAF) {
        return false;
    }

    if ((size_t)AVTP_AAF_HEADER_LEN + (size_t)Avtp_Aaf_GetStreamDataLength(pdu) > bufferSize) {
        return false;
    }

    return true;
}

/**
 * Returns the value of an AVTP AAF field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param field Specifies the position of the data field to be read
 * @returns This function returns the value of the field.
 */
OPEN1722_INLINE uint64_t Avtp_Aaf_GetField(const Avtp_Aaf_t *const pdu, Avtp_AafFields_t field)
{
    return (uint64_t)GET_AAF_FIELD(field);
}

/**
 * Sets the value of an AVTP AAF field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AAF PDU.
 * @param field Specifies the position of the data field to be written
 * @param value The value to set.
 */
OPEN1722_INLINE void Avtp_Aaf_SetField(Avtp_Aaf_t *pdu, Avtp_AafFields_t field, uint64_t value)
{
    SET_AAF_FIELD(field, value);
}

#ifdef __cplusplus
}
#endif
