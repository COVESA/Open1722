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

#define AVTP_CVF_HEADER_LEN (6 * AVTP_QUADLET_SIZE)

#define GET_CVF_FIELD(field)                                                                       \
    (Avtp_GetField(Avtp_CvfFieldDesc, AVTP_CVF_FIELD_MAX, (const uint8_t *)pdu, field))
#define SET_CVF_FIELD(field, value)                                                                \
    (Avtp_SetField(Avtp_CvfFieldDesc, AVTP_CVF_FIELD_MAX, (uint8_t *)pdu, field, value))

typedef struct {
    uint8_t header[AVTP_CVF_HEADER_LEN];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_Cvf_t;

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
    AVTP_CVF_FIELD_SUBTYPE,
    AVTP_CVF_FIELD_SV,
    AVTP_CVF_FIELD_VERSION,
    AVTP_CVF_FIELD_MR,
    AVTP_CVF_FIELD_RSV1,
    AVTP_CVF_FIELD_TV,
    AVTP_CVF_FIELD_SEQUENCE_NUM,
    AVTP_CVF_FIELD_RESERVED1,
    AVTP_CVF_FIELD_TU,

    /* CVF header fields */
    AVTP_CVF_FIELD_STREAM_ID,
    AVTP_CVF_FIELD_AVTP_TIMESTAMP,
    AVTP_CVF_FIELD_FORMAT,
    AVTP_CVF_FIELD_FORMAT_SUBTYPE,
    AVTP_CVF_FIELD_RESERVED2,
    AVTP_CVF_FIELD_STREAM_DATA_LENGTH,
    AVTP_CVF_FIELD_RSV2,
    AVTP_CVF_FIELD_PTV, /* ptv for H.264/H.265, reserved for the other subtypes */
    AVTP_CVF_FIELD_M,
    AVTP_CVF_FIELD_EVT,
    AVTP_CVF_FIELD_RESERVED3,

    /* Count number of fields for bound checks */
    AVTP_CVF_FIELD_MAX
} Avtp_CvfFields_t;

/**
 * This table maps all IEEE 1722 CVF header fields to a descriptor.
 */
static const Avtp_FieldDescriptor_t Avtp_CvfFieldDesc[AVTP_CVF_FIELD_MAX] = {
    /* Common AVTP stream header fields */
    [AVTP_CVF_FIELD_SUBTYPE] = {.quadlet = 0, .offset = 0, .bits = 8},
    [AVTP_CVF_FIELD_SV] = {.quadlet = 0, .offset = 8, .bits = 1},
    [AVTP_CVF_FIELD_VERSION] = {.quadlet = 0, .offset = 9, .bits = 3},
    [AVTP_CVF_FIELD_MR] = {.quadlet = 0, .offset = 12, .bits = 1},
    [AVTP_CVF_FIELD_RSV1] = {.quadlet = 0, .offset = 13, .bits = 2},
    [AVTP_CVF_FIELD_TV] = {.quadlet = 0, .offset = 15, .bits = 1},
    [AVTP_CVF_FIELD_SEQUENCE_NUM] = {.quadlet = 0, .offset = 16, .bits = 8},
    [AVTP_CVF_FIELD_RESERVED1] = {.quadlet = 0, .offset = 24, .bits = 7},
    [AVTP_CVF_FIELD_TU] = {.quadlet = 0, .offset = 31, .bits = 1},
    /* CVF header fields */
    [AVTP_CVF_FIELD_STREAM_ID] = {.quadlet = 1, .offset = 0, .bits = 64},
    [AVTP_CVF_FIELD_AVTP_TIMESTAMP] = {.quadlet = 3, .offset = 0, .bits = 32},
    [AVTP_CVF_FIELD_FORMAT] = {.quadlet = 4, .offset = 0, .bits = 8},
    [AVTP_CVF_FIELD_FORMAT_SUBTYPE] = {.quadlet = 4, .offset = 8, .bits = 8},
    [AVTP_CVF_FIELD_RESERVED2] = {.quadlet = 4, .offset = 16, .bits = 16},
    [AVTP_CVF_FIELD_STREAM_DATA_LENGTH] = {.quadlet = 5, .offset = 0, .bits = 16},
    [AVTP_CVF_FIELD_RSV2] = {.quadlet = 5, .offset = 16, .bits = 2},
    [AVTP_CVF_FIELD_PTV] = {.quadlet = 5, .offset = 18, .bits = 1}, /* H.264/H.265 only */
    [AVTP_CVF_FIELD_M] = {.quadlet = 5, .offset = 19, .bits = 1},
    [AVTP_CVF_FIELD_EVT] = {.quadlet = 5, .offset = 20, .bits = 4},
    [AVTP_CVF_FIELD_RESERVED3] = {.quadlet = 5, .offset = 24, .bits = 8},
};

/**
 * Return the value of the CVF SV field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @returns Value of the CVF SV field.
 */
OPEN1722_INLINE bool Avtp_Cvf_IsSv(const Avtp_Cvf_t *const pdu)
{
    return (bool)GET_CVF_FIELD(AVTP_CVF_FIELD_SV);
}

/**
 * Return the value of the CVF MR field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @returns Value of the CVF MR field.
 */
OPEN1722_INLINE bool Avtp_Cvf_IsMr(const Avtp_Cvf_t *const pdu)
{
    return (bool)GET_CVF_FIELD(AVTP_CVF_FIELD_MR);
}

/**
 * Return the value of the CVF TV field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @returns Value of the CVF TV field.
 */
OPEN1722_INLINE bool Avtp_Cvf_IsTv(const Avtp_Cvf_t *const pdu)
{
    return (bool)GET_CVF_FIELD(AVTP_CVF_FIELD_TV);
}

/**
 * Return the value of the CVF Sequence Number field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @returns Value of the CVF Sequence Number field.
 */
OPEN1722_INLINE uint8_t Avtp_Cvf_GetSequenceNum(const Avtp_Cvf_t *const pdu)
{
    return (uint8_t)GET_CVF_FIELD(AVTP_CVF_FIELD_SEQUENCE_NUM);
}

/**
 * Return the value of the CVF TU field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @returns Value of the CVF TU field.
 */
OPEN1722_INLINE bool Avtp_Cvf_IsTu(const Avtp_Cvf_t *const pdu)
{
    return (bool)GET_CVF_FIELD(AVTP_CVF_FIELD_TU);
}

/**
 * Return the value of the CVF Stream ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @returns Value of the CVF Stream ID field.
 */
OPEN1722_INLINE uint64_t Avtp_Cvf_GetStreamId(const Avtp_Cvf_t *const pdu)
{
    return (uint64_t)GET_CVF_FIELD(AVTP_CVF_FIELD_STREAM_ID);
}

/**
 * Return the value of the CVF AVTP Timestamp field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @returns Value of the CVF AVTP Timestamp field.
 */
OPEN1722_INLINE uint32_t Avtp_Cvf_GetAvtpTimestamp(const Avtp_Cvf_t *const pdu)
{
    return (uint32_t)GET_CVF_FIELD(AVTP_CVF_FIELD_AVTP_TIMESTAMP);
}

/**
 * Return the value of the CVF Format field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @returns Value of the CVF Format field.
 */
OPEN1722_INLINE Avtp_CvfFormat_t Avtp_Cvf_GetFormat(const Avtp_Cvf_t *const pdu)
{
    return (Avtp_CvfFormat_t)GET_CVF_FIELD(AVTP_CVF_FIELD_FORMAT);
}

/**
 * Return the value of the CVF Format Subtype field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @returns Value of the CVF Format Subtype field.
 */
OPEN1722_INLINE Avtp_CvfFormatSubtype_t Avtp_Cvf_GetFormatSubtype(const Avtp_Cvf_t *const pdu)
{
    return (Avtp_CvfFormatSubtype_t)GET_CVF_FIELD(AVTP_CVF_FIELD_FORMAT_SUBTYPE);
}

/**
 * Return the value of the CVF Stream Data Length field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @returns Value of the CVF Stream Data Length field.
 */
OPEN1722_INLINE uint16_t Avtp_Cvf_GetStreamDataLength(const Avtp_Cvf_t *const pdu)
{
    return (uint16_t)GET_CVF_FIELD(AVTP_CVF_FIELD_STREAM_DATA_LENGTH);
}

/**
 * Return the value of the CVF PTV field as specified in the IEEE 1722 Specification.
 *
 * The ptv (payload timestamp valid) bit is defined by the H.264 (IEEE 1722-2025,
 * 8.5.2.3) and H.265 (8.7.2.3) encapsulations, where it indicates the validity
 * of the format-specific timestamp. For the other format subtypes (MJPEG,
 * JPEG 2000) the bit belongs to the generic CVF rsv field (8.3.1.1, Figure 39)
 * and shall be zero.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @returns Value of the CVF PTV field.
 */
OPEN1722_INLINE bool Avtp_Cvf_IsPtv(const Avtp_Cvf_t *const pdu)
{
    return (bool)GET_CVF_FIELD(AVTP_CVF_FIELD_PTV);
}

/**
 * Return the value of the CVF M field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @returns Value of the CVF M field.
 */
OPEN1722_INLINE bool Avtp_Cvf_IsM(const Avtp_Cvf_t *const pdu)
{
    return (bool)GET_CVF_FIELD(AVTP_CVF_FIELD_M);
}

/**
 * Return the value of the CVF EVT field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @returns Value of the CVF EVT field.
 */
OPEN1722_INLINE uint8_t Avtp_Cvf_GetEvt(const Avtp_Cvf_t *const pdu)
{
    return (uint8_t)GET_CVF_FIELD(AVTP_CVF_FIELD_EVT);
}

/**
 * Set the SV bit in a CVF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param sv Value to set the CVF SV field to.
 */
OPEN1722_INLINE void Avtp_Cvf_SetSv(Avtp_Cvf_t *pdu, bool sv)
{
    SET_CVF_FIELD(AVTP_CVF_FIELD_SV, sv);
}

/**
 * Set the MR bit in a CVF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param mr Value to set the CVF MR field to.
 */
OPEN1722_INLINE void Avtp_Cvf_SetMr(Avtp_Cvf_t *pdu, bool mr)
{
    SET_CVF_FIELD(AVTP_CVF_FIELD_MR, mr);
}

/**
 * Set the TV bit in a CVF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param tv Value to set the CVF TV field to.
 */
OPEN1722_INLINE void Avtp_Cvf_SetTv(Avtp_Cvf_t *pdu, bool tv)
{
    SET_CVF_FIELD(AVTP_CVF_FIELD_TV, tv);
}

/**
 * Set the value of the CVF Sequence Number field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param value Value to set the CVF Sequence Number field to.
 */
OPEN1722_INLINE void Avtp_Cvf_SetSequenceNum(Avtp_Cvf_t *pdu, uint8_t value)
{
    SET_CVF_FIELD(AVTP_CVF_FIELD_SEQUENCE_NUM, value);
}

/**
 * Set the TU bit in a CVF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param tu Value to set the CVF TU field to.
 */
OPEN1722_INLINE void Avtp_Cvf_SetTu(Avtp_Cvf_t *pdu, bool tu)
{
    SET_CVF_FIELD(AVTP_CVF_FIELD_TU, tu);
}

/**
 * Set the value of the CVF Stream ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param value Value to set the CVF Stream ID field to.
 */
OPEN1722_INLINE void Avtp_Cvf_SetStreamId(Avtp_Cvf_t *pdu, uint64_t value)
{
    SET_CVF_FIELD(AVTP_CVF_FIELD_STREAM_ID, value);
}

/**
 * Set the value of the CVF AVTP Timestamp field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param value Value to set the CVF AVTP Timestamp field to.
 */
OPEN1722_INLINE void Avtp_Cvf_SetAvtpTimestamp(Avtp_Cvf_t *pdu, uint32_t value)
{
    SET_CVF_FIELD(AVTP_CVF_FIELD_AVTP_TIMESTAMP, value);
}

/**
 * Set the value of the CVF Format field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param value Value to set the CVF Format field to.
 */
OPEN1722_INLINE void Avtp_Cvf_SetFormat(Avtp_Cvf_t *pdu, Avtp_CvfFormat_t value)
{
    SET_CVF_FIELD(AVTP_CVF_FIELD_FORMAT, (uint64_t)value);
}

/**
 * Set the value of the CVF Format Subtype field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param value Value to set the CVF Format Subtype field to.
 */
OPEN1722_INLINE void Avtp_Cvf_SetFormatSubtype(Avtp_Cvf_t *pdu, Avtp_CvfFormatSubtype_t value)
{
    SET_CVF_FIELD(AVTP_CVF_FIELD_FORMAT_SUBTYPE, (uint64_t)value);
}

/**
 * Set the value of the CVF Stream Data Length field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param value Value to set the CVF Stream Data Length field to.
 */
OPEN1722_INLINE void Avtp_Cvf_SetStreamDataLength(Avtp_Cvf_t *pdu, uint16_t value)
{
    SET_CVF_FIELD(AVTP_CVF_FIELD_STREAM_DATA_LENGTH, value);
}

/**
 * Set the PTV bit in a CVF frame as specified in the IEEE 1722 Specification.
 *
 * The ptv (payload timestamp valid) bit is defined by the H.264 (IEEE 1722-2025,
 * 8.5.2.3) and H.265 (8.7.2.3) encapsulations. For the other format subtypes
 * (MJPEG, JPEG 2000) the bit belongs to the generic CVF rsv field (8.3.1.1,
 * Figure 39) and shall be set to zero.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param ptv Value to set the CVF PTV field to.
 */
OPEN1722_INLINE void Avtp_Cvf_SetPtv(Avtp_Cvf_t *pdu, bool ptv)
{
    SET_CVF_FIELD(AVTP_CVF_FIELD_PTV, ptv);
}

/**
 * Set the M bit in a CVF frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param m Value to set the CVF M field to.
 */
OPEN1722_INLINE void Avtp_Cvf_SetM(Avtp_Cvf_t *pdu, bool m)
{
    SET_CVF_FIELD(AVTP_CVF_FIELD_M, m);
}

/**
 * Set the value of the CVF EVT field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param value Value to set the CVF EVT field to.
 */
OPEN1722_INLINE void Avtp_Cvf_SetEvt(Avtp_Cvf_t *pdu, uint8_t value)
{
    SET_CVF_FIELD(AVTP_CVF_FIELD_EVT, value);
}

/**
 * Returns pointer to the stream data of a CVF frame.
 *
 * The stream data contains the format-specific header (e.g. the MJPEG or
 * H.264 header) followed by the video payload.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @return Pointer to CVF stream data
 */
OPEN1722_INLINE const uint8_t *Avtp_Cvf_GetPayload(const Avtp_Cvf_t *const pdu)
{
    return pdu->payload;
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
    memcpy(pdu->payload, payload, payload_length);
}

/**
 * Initializes a CVF PDU as specified in the IEEE 1722 Specification.
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
 * Checks if the CVF frame is valid by checking:
 *     1) if the length field of the CVF stream data contains a value larger than the actual size of
 * the buffer that contains the AVTP message. 2) if other format specific invariants are not upheld.
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

    if (bufferSize < AVTP_CVF_HEADER_LEN) {
        return false;
    }

    if (Avtp_CommonHeader_GetSubtype((const Avtp_CommonHeader_t *)pdu) != AVTP_SUBTYPE_CVF) {
        return false;
    }

    if ((size_t)AVTP_CVF_HEADER_LEN + (size_t)Avtp_Cvf_GetStreamDataLength(pdu) > bufferSize) {
        return false;
    }

    return true;
}

/**
 * Returns the value of an AVTP CVF field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param field Specifies the position of the data field to be read
 * @returns This function returns the value of the field.
 */
OPEN1722_INLINE uint64_t Avtp_Cvf_GetField(const Avtp_Cvf_t *const pdu, Avtp_CvfFields_t field)
{
    return (uint64_t)GET_CVF_FIELD(field);
}

/**
 * Sets the value of an AVTP CVF field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF PDU.
 * @param field Specifies the position of the data field to be written
 * @param value The value to set.
 */
OPEN1722_INLINE void Avtp_Cvf_SetField(Avtp_Cvf_t *pdu, Avtp_CvfFields_t field, uint64_t value)
{
    SET_CVF_FIELD(field, value);
}

#ifdef __cplusplus
}
#endif
