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
 * This file contains the fields descriptions of the IEEE 1722 CVF H.264 header
 * and functions to invoke corresponding parser and deparser.
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

#ifdef __cplusplus
extern "C" {
#endif

#define AVTP_H264_HEADER_LEN (1 * AVTP_QUADLET_SIZE)

#define GET_H264_FIELD(field)                                                                      \
    (Avtp_GetField(Avtp_H264FieldDesc, AVTP_H264_FIELD_MAX, (const uint8_t *)pdu, field))
#define SET_H264_FIELD(field, value)                                                               \
    (Avtp_SetField(Avtp_H264FieldDesc, AVTP_H264_FIELD_MAX, (uint8_t *)pdu, field, value))

typedef struct {
    uint8_t header[AVTP_H264_HEADER_LEN];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_H264_t;

typedef enum {

    /* H.264 header fields */
    AVTP_H264_FIELD_TIMESTAMP,

    /* Count number of fields for bound checks */
    AVTP_H264_FIELD_MAX
} Avtp_H264Fields_t;

/**
 * This table maps all IEEE 1722 CVF H.264 header fields to a descriptor.
 */
static const Avtp_FieldDescriptor_t Avtp_H264FieldDesc[AVTP_H264_FIELD_MAX] = {
    [AVTP_H264_FIELD_TIMESTAMP] = {.quadlet = 0, .offset = 0, .bits = 32},
};

/**
 * Return the value of the CVF H.264 Timestamp field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF H.264 header.
 * @returns Value of the CVF H.264 Timestamp field.
 */
OPEN1722_INLINE uint32_t Avtp_H264_GetTimestamp(const Avtp_H264_t *const pdu)
{
    return (uint32_t)GET_H264_FIELD(AVTP_H264_FIELD_TIMESTAMP);
}

/**
 * Set the value of the CVF H.264 Timestamp field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF H.264 header.
 * @param value Value to set the CVF H.264 Timestamp field to.
 */
OPEN1722_INLINE void Avtp_H264_SetTimestamp(Avtp_H264_t *pdu, uint32_t value)
{
    SET_H264_FIELD(AVTP_H264_FIELD_TIMESTAMP, value);
}

/**
 * Returns pointer to the payload of a CVF H.264 frame.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF H.264 header.
 * @return Pointer to the H.264 payload
 */
OPEN1722_INLINE const uint8_t *Avtp_H264_GetPayload(const Avtp_H264_t *const pdu)
{
    return pdu->payload;
}

/**
 * Sets the payload of a CVF H.264 frame.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF H.264 header.
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload
 */
OPEN1722_INLINE void Avtp_H264_SetPayload(Avtp_H264_t *pdu, uint8_t *payload,
                                          uint16_t payload_length)
{
    memcpy(pdu->payload, payload, payload_length);
}

/**
 * Initializes a CVF H.264 header.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF H.264 header.
 */
OPEN1722_INLINE void Avtp_H264_Init(Avtp_H264_t *pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_H264_t));
    }
}

/**
 * Checks if the CVF H.264 header fits into the buffer that contains it.
 *
 * The H.264 header is a fragment of a CVF PDU: the enclosing CVF PDU is
 * validated with Avtp_Cvf_IsValid() and the CVF format_subtype must be
 * AVTP_CVF_FORMAT_SUBTYPE_H264 before this function is called. bufferSize is
 * the number of bytes available at the start of the H.264 header.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF H.264 header.
 * @param bufferSize Size of the buffer containing the CVF H.264 header.
 * @return true if the CVF H.264 header is valid, false otherwise.
 */
OPEN1722_INLINE bool Avtp_H264_IsValid(const Avtp_H264_t *const pdu, size_t bufferSize)
{
    if (pdu == NULL) {
        return false;
    }

    if (bufferSize < AVTP_H264_HEADER_LEN) {
        return false;
    }

    return true;
}

/**
 * Returns the value of a CVF H.264 field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF H.264 header.
 * @param field Specifies the position of the data field to be read
 * @returns This function returns the value of the field.
 */
OPEN1722_INLINE uint64_t Avtp_H264_GetField(const Avtp_H264_t *const pdu, Avtp_H264Fields_t field)
{
    return (uint64_t)GET_H264_FIELD(field);
}

/**
 * Sets the value of a CVF H.264 field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF H.264 header.
 * @param field Specifies the position of the data field to be written
 * @param value The value to set.
 */
OPEN1722_INLINE void Avtp_H264_SetField(Avtp_H264_t *pdu, Avtp_H264Fields_t field, uint64_t value)
{
    SET_H264_FIELD(field, value);
}

#ifdef __cplusplus
}
#endif
