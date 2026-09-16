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
 * This file contains the fields descriptions of the IEEE 1722 CVF MJPEG header
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

#define AVTP_MJPEG_HEADER_LEN (2 * AVTP_QUADLET_SIZE)

#define GET_MJPEG_FIELD(field)                                                                     \
    (Avtp_GetField(Avtp_MjpegFieldDesc, AVTP_MJPEG_FIELD_MAX, (const uint8_t *)pdu, field))
#define SET_MJPEG_FIELD(field, value)                                                              \
    (Avtp_SetField(Avtp_MjpegFieldDesc, AVTP_MJPEG_FIELD_MAX, (uint8_t *)pdu, field, value))

typedef struct {
    uint8_t header[AVTP_MJPEG_HEADER_LEN];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_Mjpeg_t;

typedef enum {

    /* MJPEG header fields */
    AVTP_MJPEG_FIELD_TYPE_SPECIFIC,
    AVTP_MJPEG_FIELD_FRAGMENT_OFFSET,
    AVTP_MJPEG_FIELD_TYPE,
    AVTP_MJPEG_FIELD_Q,
    AVTP_MJPEG_FIELD_WIDTH,
    AVTP_MJPEG_FIELD_HEIGHT,

    /* Count number of fields for bound checks */
    AVTP_MJPEG_FIELD_MAX
} Avtp_MjpegFields_t;

/**
 * This table maps all IEEE 1722 CVF MJPEG header fields to a descriptor.
 */
static const Avtp_FieldDescriptor_t Avtp_MjpegFieldDesc[AVTP_MJPEG_FIELD_MAX] = {
    [AVTP_MJPEG_FIELD_TYPE_SPECIFIC] = {.quadlet = 0, .offset = 0, .bits = 8},
    [AVTP_MJPEG_FIELD_FRAGMENT_OFFSET] = {.quadlet = 0, .offset = 8, .bits = 24},
    [AVTP_MJPEG_FIELD_TYPE] = {.quadlet = 1, .offset = 0, .bits = 8},
    [AVTP_MJPEG_FIELD_Q] = {.quadlet = 1, .offset = 8, .bits = 8},
    [AVTP_MJPEG_FIELD_WIDTH] = {.quadlet = 1, .offset = 16, .bits = 8},
    [AVTP_MJPEG_FIELD_HEIGHT] = {.quadlet = 1, .offset = 24, .bits = 8},
};

/**
 * Return the value of the CVF MJPEG Type Specific field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF MJPEG header.
 * @returns Value of the CVF MJPEG Type Specific field.
 */
OPEN1722_INLINE uint8_t Avtp_Mjpeg_GetTypeSpecific(const Avtp_Mjpeg_t *const pdu)
{
    return (uint8_t)GET_MJPEG_FIELD(AVTP_MJPEG_FIELD_TYPE_SPECIFIC);
}

/**
 * Return the value of the CVF MJPEG Fragment Offset field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF MJPEG header.
 * @returns Value of the CVF MJPEG Fragment Offset field.
 */
OPEN1722_INLINE uint32_t Avtp_Mjpeg_GetFragmentOffset(const Avtp_Mjpeg_t *const pdu)
{
    return (uint32_t)GET_MJPEG_FIELD(AVTP_MJPEG_FIELD_FRAGMENT_OFFSET);
}

/**
 * Return the value of the CVF MJPEG Type field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF MJPEG header.
 * @returns Value of the CVF MJPEG Type field.
 */
OPEN1722_INLINE uint8_t Avtp_Mjpeg_GetType(const Avtp_Mjpeg_t *const pdu)
{
    return (uint8_t)GET_MJPEG_FIELD(AVTP_MJPEG_FIELD_TYPE);
}

/**
 * Return the value of the CVF MJPEG Q field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF MJPEG header.
 * @returns Value of the CVF MJPEG Q field.
 */
OPEN1722_INLINE uint8_t Avtp_Mjpeg_GetQ(const Avtp_Mjpeg_t *const pdu)
{
    return (uint8_t)GET_MJPEG_FIELD(AVTP_MJPEG_FIELD_Q);
}

/**
 * Return the value of the CVF MJPEG Width field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF MJPEG header.
 * @returns Value of the CVF MJPEG Width field.
 */
OPEN1722_INLINE uint8_t Avtp_Mjpeg_GetWidth(const Avtp_Mjpeg_t *const pdu)
{
    return (uint8_t)GET_MJPEG_FIELD(AVTP_MJPEG_FIELD_WIDTH);
}

/**
 * Return the value of the CVF MJPEG Height field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF MJPEG header.
 * @returns Value of the CVF MJPEG Height field.
 */
OPEN1722_INLINE uint8_t Avtp_Mjpeg_GetHeight(const Avtp_Mjpeg_t *const pdu)
{
    return (uint8_t)GET_MJPEG_FIELD(AVTP_MJPEG_FIELD_HEIGHT);
}

/**
 * Set the value of the CVF MJPEG Type Specific field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF MJPEG header.
 * @param value Value to set the CVF MJPEG Type Specific field to.
 */
OPEN1722_INLINE void Avtp_Mjpeg_SetTypeSpecific(Avtp_Mjpeg_t *pdu, uint8_t value)
{
    SET_MJPEG_FIELD(AVTP_MJPEG_FIELD_TYPE_SPECIFIC, value);
}

/**
 * Set the value of the CVF MJPEG Fragment Offset field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF MJPEG header.
 * @param value Value to set the CVF MJPEG Fragment Offset field to.
 */
OPEN1722_INLINE void Avtp_Mjpeg_SetFragmentOffset(Avtp_Mjpeg_t *pdu, uint32_t value)
{
    SET_MJPEG_FIELD(AVTP_MJPEG_FIELD_FRAGMENT_OFFSET, value);
}

/**
 * Set the value of the CVF MJPEG Type field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF MJPEG header.
 * @param value Value to set the CVF MJPEG Type field to.
 */
OPEN1722_INLINE void Avtp_Mjpeg_SetType(Avtp_Mjpeg_t *pdu, uint8_t value)
{
    SET_MJPEG_FIELD(AVTP_MJPEG_FIELD_TYPE, value);
}

/**
 * Set the value of the CVF MJPEG Q field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF MJPEG header.
 * @param value Value to set the CVF MJPEG Q field to.
 */
OPEN1722_INLINE void Avtp_Mjpeg_SetQ(Avtp_Mjpeg_t *pdu, uint8_t value)
{
    SET_MJPEG_FIELD(AVTP_MJPEG_FIELD_Q, value);
}

/**
 * Set the value of the CVF MJPEG Width field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF MJPEG header.
 * @param value Value to set the CVF MJPEG Width field to.
 */
OPEN1722_INLINE void Avtp_Mjpeg_SetWidth(Avtp_Mjpeg_t *pdu, uint8_t value)
{
    SET_MJPEG_FIELD(AVTP_MJPEG_FIELD_WIDTH, value);
}

/**
 * Set the value of the CVF MJPEG Height field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF MJPEG header.
 * @param value Value to set the CVF MJPEG Height field to.
 */
OPEN1722_INLINE void Avtp_Mjpeg_SetHeight(Avtp_Mjpeg_t *pdu, uint8_t value)
{
    SET_MJPEG_FIELD(AVTP_MJPEG_FIELD_HEIGHT, value);
}

/**
 * Returns pointer to the payload of a CVF MJPEG frame.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF MJPEG header.
 * @return Pointer to the MJPEG payload
 */
OPEN1722_INLINE const uint8_t *Avtp_Mjpeg_GetPayload(const Avtp_Mjpeg_t *const pdu)
{
    return pdu->payload;
}

/**
 * Sets the payload of a CVF MJPEG frame.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF MJPEG header.
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload
 */
OPEN1722_INLINE void Avtp_Mjpeg_SetPayload(Avtp_Mjpeg_t *pdu, uint8_t *payload,
                                           uint16_t payload_length)
{
    memcpy(pdu->payload, payload, payload_length);
}

/**
 * Initializes a CVF MJPEG header.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF MJPEG header.
 */
OPEN1722_INLINE void Avtp_Mjpeg_Init(Avtp_Mjpeg_t *pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_Mjpeg_t));
    }
}

/**
 * Checks if the CVF MJPEG header fits into the buffer that contains it.
 *
 * The MJPEG header is a fragment of a CVF PDU: the enclosing CVF PDU is
 * validated with Avtp_Cvf_IsValid() and the CVF format_subtype must be
 * AVTP_CVF_FORMAT_SUBTYPE_MJPEG before this function is called. bufferSize is
 * the number of bytes available at the start of the MJPEG header.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF MJPEG header.
 * @param bufferSize Size of the buffer containing the CVF MJPEG header.
 * @return true if the CVF MJPEG header is valid, false otherwise.
 */
OPEN1722_INLINE bool Avtp_Mjpeg_IsValid(const Avtp_Mjpeg_t *const pdu, size_t bufferSize)
{
    if (pdu == NULL) {
        return false;
    }

    if (bufferSize < AVTP_MJPEG_HEADER_LEN) {
        return false;
    }

    return true;
}

/**
 * Returns the value of a CVF MJPEG field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF MJPEG header.
 * @param field Specifies the position of the data field to be read
 * @returns This function returns the value of the field.
 */
OPEN1722_INLINE uint64_t Avtp_Mjpeg_GetField(const Avtp_Mjpeg_t *const pdu,
                                             Avtp_MjpegFields_t field)
{
    return (uint64_t)GET_MJPEG_FIELD(field);
}

/**
 * Sets the value of a CVF MJPEG field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF MJPEG header.
 * @param field Specifies the position of the data field to be written
 * @param value The value to set.
 */
OPEN1722_INLINE void Avtp_Mjpeg_SetField(Avtp_Mjpeg_t *pdu, Avtp_MjpegFields_t field,
                                         uint64_t value)
{
    SET_MJPEG_FIELD(field, value);
}

#ifdef __cplusplus
}
#endif
