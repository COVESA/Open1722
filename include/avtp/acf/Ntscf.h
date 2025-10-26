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
 * This file contains the fields descriptions of the IEEE 1722 NTSCF PDUs and
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
#include "avtp/Defines.h"
#include "avtp/CommonHeader.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AVTP_NTSCF_HEADER_LEN              (3 * AVTP_QUADLET_SIZE)

#define GET_NTSCF_FIELD(field) \
        (Avtp_GetField(Avtp_NtscfFieldDesc, AVTP_NTSCF_FIELD_MAX, (uint8_t*)pdu, field))
#define SET_NTSCF_FIELD(field, value) \
        (Avtp_SetField(Avtp_NtscfFieldDesc, AVTP_NTSCF_FIELD_MAX, (uint8_t*)pdu, field, value))

typedef struct {
    uint8_t header[AVTP_NTSCF_HEADER_LEN];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_Ntscf_t;

typedef enum {
    AVTP_NTSCF_FIELD_SUBTYPE,
    AVTP_NTSCF_FIELD_SV,
    AVTP_NTSCF_FIELD_VERSION,
    /* NTSCF header fields */
    AVTP_NTSCF_FIELD_NTSCF_DATA_LENGTH,
    AVTP_NTSCF_FIELD_SEQUENCE_NUM,
    AVTP_NTSCF_FIELD_STREAM_ID,
    /* Count number of fields for bound checks */
    AVTP_NTSCF_FIELD_MAX
} Avtp_NtscfFields_t;

/**
 * This table maps all IEEE 1722 NTSCF-specific header fields to a descriptor.
 */
static const Avtp_FieldDescriptor_t Avtp_NtscfFieldDesc[AVTP_NTSCF_FIELD_MAX] =
{
    /* Common AVTP header */
    [AVTP_NTSCF_FIELD_SUBTYPE]              = { .quadlet = 0, .offset = 0, .bits = 8 },
    [AVTP_NTSCF_FIELD_SV]                   = { .quadlet = 0, .offset = 8, .bits = 1 },
    [AVTP_NTSCF_FIELD_VERSION]              = { .quadlet = 0, .offset = 9, .bits = 3 },
    /* NTSCF header */
    [AVTP_NTSCF_FIELD_NTSCF_DATA_LENGTH]    = { .quadlet = 0, .offset = 13, .bits = 11 },
    [AVTP_NTSCF_FIELD_SEQUENCE_NUM]         = { .quadlet = 0, .offset = 24, .bits = 8 },
    [AVTP_NTSCF_FIELD_STREAM_ID]            = { .quadlet = 1, .offset = 0, .bits = 64 },
};

/**
 * Return the value of an an NTSCF PDU subtype field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF Ntscf PDU.
 * @returns Value of the NTSCF PDU subtype field.
 */
static inline uint8_t Avtp_Ntscf_GetSubtype(const Avtp_Ntscf_t* const pdu) {
    return GET_NTSCF_FIELD(AVTP_NTSCF_FIELD_SUBTYPE);
}

/**
 * Return the value of an an NTSCF PDU SV field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Ntscf PDU.
 * @returns Value of the NTSCF PDU SV field.
 */
static inline uint8_t Avtp_Ntscf_GetSv(const Avtp_Ntscf_t* const pdu) {
    return GET_NTSCF_FIELD(AVTP_NTSCF_FIELD_SV);
}

/**
 * Return the value of an an NTSCF PDU version field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Ntscf PDU.
 * @returns Value of the NTSCF PDU version field.
 */
static inline uint8_t Avtp_Ntscf_GetVersion(const Avtp_Ntscf_t* const pdu) {
    return GET_NTSCF_FIELD(AVTP_NTSCF_FIELD_VERSION);
}

/**
 * Return the value of an an NTSCF PDU Ntscf Data Length field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Ntscf PDU.
 * @returns Value of the NTSCF PDU Ntscf Data Length field.
 */
static inline uint16_t Avtp_Ntscf_GetNtscfDataLength(const Avtp_Ntscf_t* const pdu) {
    return GET_NTSCF_FIELD(AVTP_NTSCF_FIELD_NTSCF_DATA_LENGTH);
}

/**
 * Return the value of an an NTSCF PDU Sequence Number field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Ntscf PDU.
 * @returns Value of the NTSCF PDU Sequence Number field.
 */
static inline uint8_t Avtp_Ntscf_GetSequenceNum(const Avtp_Ntscf_t* const pdu) {
    return GET_NTSCF_FIELD(AVTP_NTSCF_FIELD_SEQUENCE_NUM);
}

/**
 * Return the value of an an NTSCF PDU Stream ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Ntscf PDU.
 * @returns Value of the NTSCF PDU Stream ID field.
 */
static inline uint64_t Avtp_Ntscf_GetStreamId(const Avtp_Ntscf_t* const pdu) {
    return GET_NTSCF_FIELD(AVTP_NTSCF_FIELD_STREAM_ID);
}

/**
 * Set the value of an an NTSCF PDU subtype field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF Ntscf PDU.
 * @param value Value to set the NTSCF PDU subtype field to.
 */
static inline void Avtp_Ntscf_SetSubtype(Avtp_Ntscf_t* pdu, uint8_t value) {
    SET_NTSCF_FIELD(AVTP_NTSCF_FIELD_SUBTYPE, value);
}

/**
 * Enable the SV bit in an ACF Ntscf frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Ntscf PDU.
 */
static inline void Avtp_Ntscf_EnableSv(Avtp_Ntscf_t* pdu) {
    SET_NTSCF_FIELD(AVTP_NTSCF_FIELD_SV, 1);
}

/**
 * Disable the SV bit in an ACF Ntscf frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Ntscf PDU.
 */
static inline void Avtp_Ntscf_DisableSv(Avtp_Ntscf_t* pdu) {
    SET_NTSCF_FIELD(AVTP_NTSCF_FIELD_SV, 0);
}

/**
 * Set the value of an an NTSCF PDU version field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Ntscf PDU.
 * @param value Value to set the NTSCF PDU version field to.
 */
static inline void Avtp_Ntscf_SetVersion(Avtp_Ntscf_t* pdu, uint8_t value) {
    SET_NTSCF_FIELD(AVTP_NTSCF_FIELD_VERSION, value);
}

/**
 * Set the value of an an NTSCF PDU Ntscf Data Length field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Ntscf PDU.
 * @param value Value to set the NTSCF PDU Ntscf Data Length field to.
 */
static inline void Avtp_Ntscf_SetNtscfDataLength(Avtp_Ntscf_t* pdu, uint16_t value) {
    SET_NTSCF_FIELD(AVTP_NTSCF_FIELD_NTSCF_DATA_LENGTH, value);
}

/**
 * Set the value of an an NTSCF PDU Sequence Number field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Ntscf PDU.
 * @param value Value to set the NTSCF PDU Sequence Number field to.
 */
static inline void Avtp_Ntscf_SetSequenceNum(Avtp_Ntscf_t* pdu, uint8_t value) {
    SET_NTSCF_FIELD(AVTP_NTSCF_FIELD_SEQUENCE_NUM, value);
}

/**
 * Set the value of an an NTSCF PDU Stream ID field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF Ntscf PDU.
 * @param value Value to set the NTSCF PDU Stream ID field to.
 */
static inline void Avtp_Ntscf_SetStreamId(Avtp_Ntscf_t* pdu, uint64_t value) {
    SET_NTSCF_FIELD(AVTP_NTSCF_FIELD_STREAM_ID, value);
}

/**
 * Checks if the ACF Ntscf frame is valid by checking:
 *     1) if the length field of AVTP/ACF messages contains a value larger than the actual size of the buffer that contains the AVTP message.
 *     2) if other format specific invariants are not upheld
 * @param pdu Pointer to the first bit of an 1722 ACF Ntscf PDU.
 * @param bufferSize Size of the buffer containing the ACF Ntscf frame.
 * @return true if the ACF Ntscf frame is valid, false otherwise.
 */
uint8_t Avtp_Ntscf_IsValid(const Avtp_Ntscf_t* const pdu, size_t bufferSize);

/**
 * Initializes a NTSCF PDU as specified in the IEEE 1722-2016 Specification.
 *
 * @param pdu Pointer to the first bit of a 1722 PDU. This is typically an AVTP-
 * or an ACF header.
 */
static inline void Avtp_Ntscf_Init(Avtp_Ntscf_t* pdu) {
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_Ntscf_t));
        Avtp_Ntscf_SetSubtype(pdu, AVTP_SUBTYPE_NTSCF);
        Avtp_Ntscf_EnableSv(pdu);
    }
}

#ifdef __cplusplus
}
#endif
