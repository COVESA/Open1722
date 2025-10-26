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
 */

#pragma once

#ifdef LINUX_KERNEL1722
#include <linux/string.h>
#else
#include <string.h>
#endif

#include "avtp/Defines.h"
#include "avtp/Utils.h"
#include "avtp/CommonHeader.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AVTP_TSCF_HEADER_LEN               (6 * AVTP_QUADLET_SIZE)

#define GET_TSCF_FIELD(field) \
        (Avtp_GetField(Avtp_TscfFieldDesc, AVTP_TSCF_FIELD_MAX, (uint8_t*)pdu, field))
#define SET_TSCF_FIELD(field, value) \
        (Avtp_SetField(Avtp_TscfFieldDesc, AVTP_TSCF_FIELD_MAX, (uint8_t*)pdu, field, value))

typedef struct {
    uint8_t header[AVTP_TSCF_HEADER_LEN];
    uint8_t payload[0];
} Avtp_Tscf_t;

typedef enum {

    /* Common AVTP header */
    AVTP_TSCF_FIELD_SUBTYPE,
    AVTP_TSCF_FIELD_SV,
    AVTP_TSCF_FIELD_VERSION,

    /* TSCF header fields */
    AVTP_TSCF_FIELD_MR,
    AVTP_TSCF_FIELD_TV,
    AVTP_TSCF_FIELD_SEQUENCE_NUM,
    AVTP_TSCF_FIELD_TU,
    AVTP_TSCF_FIELD_STREAM_ID,
    AVTP_TSCF_FIELD_AVTP_TIMESTAMP,
    AVTP_TSCF_FIELD_STREAM_DATA_LENGTH,

    /* Count number of fields for bound checks */
    AVTP_TSCF_FIELD_MAX
} Avtp_TscfFields_t;

/**
 * This table maps all IEEE 1722 TSCF-specific header fields to a descriptor.
 */
static const Avtp_FieldDescriptor_t Avtp_TscfFieldDesc[AVTP_TSCF_FIELD_MAX] =
{
    /* Common AVTP header */
    [AVTP_TSCF_FIELD_SUBTYPE]                  = { .quadlet = 0, .offset = 0, .bits = 8 },
    [AVTP_TSCF_FIELD_SV]                       = { .quadlet = 0, .offset = 8, .bits = 1 },
    [AVTP_TSCF_FIELD_VERSION]                  = { .quadlet = 0, .offset = 9, .bits = 3 },
    /* TSCF header*/
    [AVTP_TSCF_FIELD_MR]                       = { .quadlet = 0, .offset = 12, .bits = 1 },
    [AVTP_TSCF_FIELD_TV]                       = { .quadlet = 0, .offset = 15, .bits = 1 },
    [AVTP_TSCF_FIELD_SEQUENCE_NUM]             = { .quadlet = 0, .offset = 16, .bits = 8 },
    [AVTP_TSCF_FIELD_TU]                       = { .quadlet = 0, .offset = 31, .bits = 1 },
    [AVTP_TSCF_FIELD_STREAM_ID]                = { .quadlet = 1, .offset = 0, .bits = 64 },
    [AVTP_TSCF_FIELD_AVTP_TIMESTAMP]           = { .quadlet = 3, .offset = 0, .bits = 32 },
    [AVTP_TSCF_FIELD_STREAM_DATA_LENGTH]       = { .quadlet = 5, .offset = 0, .bits = 16 },
};

/**
 * Return the value of an an TSCF PDU subtype field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @returns Value of the TSCF PDU subtype field.
 */
static inline uint8_t Avtp_Tscf_GetSubtype(const Avtp_Tscf_t* const pdu) {
    return GET_TSCF_FIELD(AVTP_TSCF_FIELD_SUBTYPE);
}

/**
 * Return the value of an an TSCF PDU SV field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @returns Value of the TSCF PDU SV field.
 */
static inline uint8_t Avtp_Tscf_GetSv(const Avtp_Tscf_t* const pdu) {
    return GET_TSCF_FIELD(AVTP_TSCF_FIELD_SV);
}

/**
 * Return the value of an an TSCF PDU version field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @returns Value of the TSCF PDU version field.
 */
static inline uint8_t Avtp_Tscf_GetVersion(const Avtp_Tscf_t* const pdu) {
    return GET_TSCF_FIELD(AVTP_TSCF_FIELD_VERSION);
}

/**
 * Return the value of an an TSCF PDU MR field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @returns Value of the TSCF PDU MR field.
 */
static inline uint8_t Avtp_Tscf_GetMr(const Avtp_Tscf_t* const pdu) {
    return GET_TSCF_FIELD(AVTP_TSCF_FIELD_MR);
}

/**
 * Return the value of an an TSCF PDU TV field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @returns Value of the TSCF PDU TV field.
 */
static inline uint8_t Avtp_Tscf_GetTv(const Avtp_Tscf_t* const pdu) {
    return GET_TSCF_FIELD(AVTP_TSCF_FIELD_TV);
}

/**
 * Return the value of an an TSCF PDU Sequence Number field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @returns Value of the TSCF PDU Sequence Number field.
 */
static inline uint8_t Avtp_Tscf_GetSequenceNum(const Avtp_Tscf_t* const pdu) {
    return GET_TSCF_FIELD(AVTP_TSCF_FIELD_SEQUENCE_NUM);
}

/**
 * Return the value of an an TSCF PDU TU field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @returns Value of the TSCF PDU TU field.
 */
static inline uint8_t Avtp_Tscf_GetTu(const Avtp_Tscf_t* const pdu) {
    return GET_TSCF_FIELD(AVTP_TSCF_FIELD_TU);
}

/**
 * Return the value of an an TSCF PDU Stream ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @returns Value of the TSCF PDU Stream ID field.
 */
static inline uint64_t Avtp_Tscf_GetStreamId(const Avtp_Tscf_t* const pdu) {
    return GET_TSCF_FIELD(AVTP_TSCF_FIELD_STREAM_ID);
}

/**
 * Return the value of an an TSCF PDU AVTP Timestamp field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @returns Value of the TSCF PDU AVTP Timestamp field.
 */
static inline uint32_t Avtp_Tscf_GetAvtpTimestamp(const Avtp_Tscf_t* const pdu) {
    return GET_TSCF_FIELD(AVTP_TSCF_FIELD_AVTP_TIMESTAMP);
}

/**
 * Return the value of an an TSCF PDU Stream Data Length field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @returns Value of the TSCF PDU Stream Data Length field.
 */
static inline uint16_t Avtp_Tscf_GetStreamDataLength(const Avtp_Tscf_t* const pdu) {
    return GET_TSCF_FIELD(AVTP_TSCF_FIELD_STREAM_DATA_LENGTH);
}

/**
 * Set the value of an an TSCF PDU subtype field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @param value Value to set the TSCF PDU subtype field to.
 */
static inline void Avtp_Tscf_SetSubtype(Avtp_Tscf_t* pdu, uint8_t value) {
    SET_TSCF_FIELD(AVTP_TSCF_FIELD_SUBTYPE, value);
}

/**
 * Enable the SV bit in an ACF Tscf frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 */
static inline void Avtp_Tscf_EnableSv(Avtp_Tscf_t* pdu) {
    SET_TSCF_FIELD(AVTP_TSCF_FIELD_SV, 1);
}

/**
 * Disable the SV bit in an ACF Tscf frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 */
static inline void Avtp_Tscf_DisableSv(Avtp_Tscf_t* pdu)
{
    SET_TSCF_FIELD(AVTP_TSCF_FIELD_SV, 0);
}

/**
 * Set the value of an an TSCF PDU version field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @param value Value to set the TSCF PDU version field to.
 */
static inline void Avtp_Tscf_SetVersion(Avtp_Tscf_t* pdu, uint8_t value) {
    SET_TSCF_FIELD(AVTP_TSCF_FIELD_VERSION, value);
}

/**
 * Enable the MR bit in an ACF Tscf frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 */
static inline void Avtp_Tscf_EnableMr(Avtp_Tscf_t* pdu) {
    SET_TSCF_FIELD(AVTP_TSCF_FIELD_MR, 1);
}

/**
 * Disable the MR bit in an ACF Tscf frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 */
static inline void Avtp_Tscf_DisableMr(Avtp_Tscf_t* pdu) {
    SET_TSCF_FIELD(AVTP_TSCF_FIELD_MR, 0);
}

/**
 * Enable the TV bit in an ACF Tscf frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 */
static inline void Avtp_Tscf_EnableTv(Avtp_Tscf_t* pdu) {
    SET_TSCF_FIELD(AVTP_TSCF_FIELD_TV, 1);
}

/**
 * Disable the TV bit in an ACF Tscf frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 */
static inline void Avtp_Tscf_DisableTv(Avtp_Tscf_t* pdu) {
    SET_TSCF_FIELD(AVTP_TSCF_FIELD_TV, 0);
}

/**
 * Set the value of an an TSCF PDU Sequence Number field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @param value Value to set the TSCF PDU Sequence Number field to.
 */
static inline void Avtp_Tscf_SetSequenceNum(Avtp_Tscf_t* pdu, uint8_t value) {
    SET_TSCF_FIELD(AVTP_TSCF_FIELD_SEQUENCE_NUM, value);
}

/**
 * Enable the TU bit in an ACF Tscf frame as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 */
static inline void Avtp_Tscf_EnableTu(Avtp_Tscf_t* pdu) {
    SET_TSCF_FIELD(AVTP_TSCF_FIELD_TU, 1);
}   

/**
 * Disable the TU bit in an ACF Tscf frame as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 */
static inline void Avtp_Tscf_DisableTu(Avtp_Tscf_t* pdu) {
    SET_TSCF_FIELD(AVTP_TSCF_FIELD_TU, 0);
}

/**
 * Set the value of an an TSCF PDU Stream ID field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @param value Value to set the TSCF PDU Stream ID field to.
 */
static inline void Avtp_Tscf_SetStreamId(Avtp_Tscf_t* pdu, uint64_t value) {
    SET_TSCF_FIELD(AVTP_TSCF_FIELD_STREAM_ID, value);
}

/**
 * Set the value of an an TSCF PDU AVTP Timestamp field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @param value Value to set the TSCF PDU AVTP Timestamp field to.
 */
static inline void Avtp_Tscf_SetAvtpTimestamp(Avtp_Tscf_t* pdu, uint32_t value) {
    SET_TSCF_FIELD(AVTP_TSCF_FIELD_AVTP_TIMESTAMP, value);
}

/**
 * Set the value of an an TSCF PDU Stream Data Length field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF TSCF PDU.
 * @param value Value to set the TSCF PDU Stream Data Length field to.
 */
static inline void Avtp_Tscf_SetStreamDataLength(Avtp_Tscf_t* pdu, uint16_t value) {
    SET_TSCF_FIELD(AVTP_TSCF_FIELD_STREAM_DATA_LENGTH, value);
}

/**
 * Checks if the ACF Tscf frame is valid by checking:
 *     1) if the length field of AVTP/ACF messages contains a value larger than the actual size of the buffer that contains the AVTP message.
 *     2) if other format specific invariants are not upheld
 * @param pdu Pointer to the first bit of an 1722 ACF Tscf PDU.
 * @param bufferSize Size of the buffer containing the ACF Tscf frame.
 * @return true if the ACF Tscf frame is valid, false otherwise.
 */
uint8_t Avtp_Tscf_IsValid(const Avtp_Tscf_t* const pdu, size_t bufferSize);

/**
 * Initializes a TSCF PDU as specified in the IEEE 1722-2016 Specification.
 *
 * @param pdu Pointer to the first bit of a 1722 PDU. This is typically an AVTP-
 * or an ACF header.
 */
static inline void Avtp_Tscf_Init(Avtp_Tscf_t* pdu) {
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_Tscf_t));
        Avtp_Tscf_SetSubtype(pdu, AVTP_SUBTYPE_TSCF);
        Avtp_Tscf_EnableSv(pdu);
    }
}

#ifdef __cplusplus
}
#endif
