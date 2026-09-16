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
 * This file contains the fields descriptions of the IEEE 1722 CVF JPEG 2000 header
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

#define AVTP_JPEG2000_HEADER_LEN (2 * AVTP_QUADLET_SIZE)

#define GET_JPEG2000_FIELD(field)                                                                  \
    (Avtp_GetField(Avtp_Jpeg2000FieldDesc, AVTP_JPEG2000_FIELD_MAX, (const uint8_t *)pdu, field))
#define SET_JPEG2000_FIELD(field, value)                                                           \
    (Avtp_SetField(Avtp_Jpeg2000FieldDesc, AVTP_JPEG2000_FIELD_MAX, (uint8_t *)pdu, field, value))

typedef struct {
    uint8_t header[AVTP_JPEG2000_HEADER_LEN];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_Jpeg2000_t;

typedef enum {

    /* JPEG 2000 header fields */
    AVTP_JPEG2000_FIELD_TP,
    AVTP_JPEG2000_FIELD_MHF,
    AVTP_JPEG2000_FIELD_MH_ID,
    AVTP_JPEG2000_FIELD_T,
    AVTP_JPEG2000_FIELD_PRIORITY,
    AVTP_JPEG2000_FIELD_TILE_NUMBER,
    AVTP_JPEG2000_FIELD_RESERVED,
    AVTP_JPEG2000_FIELD_FRAGMENT_OFFSET,

    /* Count number of fields for bound checks */
    AVTP_JPEG2000_FIELD_MAX
} Avtp_Jpeg2000Fields_t;

/**
 * This table maps all IEEE 1722 CVF JPEG 2000 header fields to a descriptor.
 */
static const Avtp_FieldDescriptor_t Avtp_Jpeg2000FieldDesc[AVTP_JPEG2000_FIELD_MAX] = {
    [AVTP_JPEG2000_FIELD_TP] = {.quadlet = 0, .offset = 0, .bits = 2},
    [AVTP_JPEG2000_FIELD_MHF] = {.quadlet = 0, .offset = 2, .bits = 2},
    [AVTP_JPEG2000_FIELD_MH_ID] = {.quadlet = 0, .offset = 4, .bits = 3},
    [AVTP_JPEG2000_FIELD_T] = {.quadlet = 0, .offset = 7, .bits = 1},
    [AVTP_JPEG2000_FIELD_PRIORITY] = {.quadlet = 0, .offset = 8, .bits = 8},
    [AVTP_JPEG2000_FIELD_TILE_NUMBER] = {.quadlet = 0, .offset = 16, .bits = 16},
    [AVTP_JPEG2000_FIELD_RESERVED] = {.quadlet = 1, .offset = 0, .bits = 8},
    [AVTP_JPEG2000_FIELD_FRAGMENT_OFFSET] = {.quadlet = 1, .offset = 8, .bits = 24},
};

/**
 * Return the value of the CVF JPEG 2000 TP field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF JPEG 2000 header.
 * @returns Value of the CVF JPEG 2000 TP field.
 */
OPEN1722_INLINE uint8_t Avtp_Jpeg2000_GetTp(const Avtp_Jpeg2000_t *const pdu)
{
    return (uint8_t)GET_JPEG2000_FIELD(AVTP_JPEG2000_FIELD_TP);
}

/**
 * Return the value of the CVF JPEG 2000 MHF field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF JPEG 2000 header.
 * @returns Value of the CVF JPEG 2000 MHF field.
 */
OPEN1722_INLINE uint8_t Avtp_Jpeg2000_GetMhf(const Avtp_Jpeg2000_t *const pdu)
{
    return (uint8_t)GET_JPEG2000_FIELD(AVTP_JPEG2000_FIELD_MHF);
}

/**
 * Return the value of the CVF JPEG 2000 MH ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF JPEG 2000 header.
 * @returns Value of the CVF JPEG 2000 MH ID field.
 */
OPEN1722_INLINE uint8_t Avtp_Jpeg2000_GetMhId(const Avtp_Jpeg2000_t *const pdu)
{
    return (uint8_t)GET_JPEG2000_FIELD(AVTP_JPEG2000_FIELD_MH_ID);
}

/**
 * Return the value of the CVF JPEG 2000 T field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF JPEG 2000 header.
 * @returns Value of the CVF JPEG 2000 T field.
 */
OPEN1722_INLINE bool Avtp_Jpeg2000_IsT(const Avtp_Jpeg2000_t *const pdu)
{
    return (bool)GET_JPEG2000_FIELD(AVTP_JPEG2000_FIELD_T);
}

/**
 * Return the value of the CVF JPEG 2000 Priority field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF JPEG 2000 header.
 * @returns Value of the CVF JPEG 2000 Priority field.
 */
OPEN1722_INLINE uint8_t Avtp_Jpeg2000_GetPriority(const Avtp_Jpeg2000_t *const pdu)
{
    return (uint8_t)GET_JPEG2000_FIELD(AVTP_JPEG2000_FIELD_PRIORITY);
}

/**
 * Return the value of the CVF JPEG 2000 Tile Number field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF JPEG 2000 header.
 * @returns Value of the CVF JPEG 2000 Tile Number field.
 */
OPEN1722_INLINE uint16_t Avtp_Jpeg2000_GetTileNumber(const Avtp_Jpeg2000_t *const pdu)
{
    return (uint16_t)GET_JPEG2000_FIELD(AVTP_JPEG2000_FIELD_TILE_NUMBER);
}

/**
 * Return the value of the CVF JPEG 2000 Fragment Offset field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF JPEG 2000 header.
 * @returns Value of the CVF JPEG 2000 Fragment Offset field.
 */
OPEN1722_INLINE uint32_t Avtp_Jpeg2000_GetFragmentOffset(const Avtp_Jpeg2000_t *const pdu)
{
    return (uint32_t)GET_JPEG2000_FIELD(AVTP_JPEG2000_FIELD_FRAGMENT_OFFSET);
}

/**
 * Set the value of the CVF JPEG 2000 TP field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF JPEG 2000 header.
 * @param value Value to set the CVF JPEG 2000 TP field to.
 */
OPEN1722_INLINE void Avtp_Jpeg2000_SetTp(Avtp_Jpeg2000_t *pdu, uint8_t value)
{
    SET_JPEG2000_FIELD(AVTP_JPEG2000_FIELD_TP, value);
}

/**
 * Set the value of the CVF JPEG 2000 MHF field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF JPEG 2000 header.
 * @param value Value to set the CVF JPEG 2000 MHF field to.
 */
OPEN1722_INLINE void Avtp_Jpeg2000_SetMhf(Avtp_Jpeg2000_t *pdu, uint8_t value)
{
    SET_JPEG2000_FIELD(AVTP_JPEG2000_FIELD_MHF, value);
}

/**
 * Set the value of the CVF JPEG 2000 MH ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF JPEG 2000 header.
 * @param value Value to set the CVF JPEG 2000 MH ID field to.
 */
OPEN1722_INLINE void Avtp_Jpeg2000_SetMhId(Avtp_Jpeg2000_t *pdu, uint8_t value)
{
    SET_JPEG2000_FIELD(AVTP_JPEG2000_FIELD_MH_ID, value);
}

/**
 * Set the T bit in a CVF JPEG 2000 frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF JPEG 2000 header.
 * @param t Value to set the CVF JPEG 2000 T field to.
 */
OPEN1722_INLINE void Avtp_Jpeg2000_SetT(Avtp_Jpeg2000_t *pdu, bool t)
{
    SET_JPEG2000_FIELD(AVTP_JPEG2000_FIELD_T, t);
}

/**
 * Set the value of the CVF JPEG 2000 Priority field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF JPEG 2000 header.
 * @param value Value to set the CVF JPEG 2000 Priority field to.
 */
OPEN1722_INLINE void Avtp_Jpeg2000_SetPriority(Avtp_Jpeg2000_t *pdu, uint8_t value)
{
    SET_JPEG2000_FIELD(AVTP_JPEG2000_FIELD_PRIORITY, value);
}

/**
 * Set the value of the CVF JPEG 2000 Tile Number field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF JPEG 2000 header.
 * @param value Value to set the CVF JPEG 2000 Tile Number field to.
 */
OPEN1722_INLINE void Avtp_Jpeg2000_SetTileNumber(Avtp_Jpeg2000_t *pdu, uint16_t value)
{
    SET_JPEG2000_FIELD(AVTP_JPEG2000_FIELD_TILE_NUMBER, value);
}

/**
 * Set the value of the CVF JPEG 2000 Fragment Offset field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF JPEG 2000 header.
 * @param value Value to set the CVF JPEG 2000 Fragment Offset field to.
 */
OPEN1722_INLINE void Avtp_Jpeg2000_SetFragmentOffset(Avtp_Jpeg2000_t *pdu, uint32_t value)
{
    SET_JPEG2000_FIELD(AVTP_JPEG2000_FIELD_FRAGMENT_OFFSET, value);
}

/**
 * Returns pointer to the payload of a CVF JPEG 2000 frame.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF JPEG 2000 header.
 * @return Pointer to the JPEG 2000 payload
 */
OPEN1722_INLINE const uint8_t *Avtp_Jpeg2000_GetPayload(const Avtp_Jpeg2000_t *const pdu)
{
    return pdu->payload;
}

/**
 * Sets the payload of a CVF JPEG 2000 frame.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF JPEG 2000 header.
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload
 */
OPEN1722_INLINE void Avtp_Jpeg2000_SetPayload(Avtp_Jpeg2000_t *pdu, uint8_t *payload,
                                              uint16_t payload_length)
{
    memcpy(pdu->payload, payload, payload_length);
}

/**
 * Initializes a CVF JPEG 2000 header.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF JPEG 2000 header.
 */
OPEN1722_INLINE void Avtp_Jpeg2000_Init(Avtp_Jpeg2000_t *pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_Jpeg2000_t));
    }
}

/**
 * Checks if the CVF JPEG 2000 header fits into the buffer that contains it.
 *
 * The JPEG 2000 header is a fragment of a CVF PDU: the enclosing CVF PDU is
 * validated with Avtp_Cvf_IsValid() and the CVF format_subtype must be
 * AVTP_CVF_FORMAT_SUBTYPE_JPEG2000 before this function is called. bufferSize is
 * the number of bytes available at the start of the JPEG 2000 header.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF JPEG 2000 header.
 * @param bufferSize Size of the buffer containing the CVF JPEG 2000 header.
 * @return true if the CVF JPEG 2000 header is valid, false otherwise.
 */
OPEN1722_INLINE bool Avtp_Jpeg2000_IsValid(const Avtp_Jpeg2000_t *const pdu, size_t bufferSize)
{
    if (pdu == NULL) {
        return false;
    }

    if (bufferSize < AVTP_JPEG2000_HEADER_LEN) {
        return false;
    }

    return true;
}

/**
 * Returns the value of a CVF JPEG 2000 field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF JPEG 2000 header.
 * @param field Specifies the position of the data field to be read
 * @returns This function returns the value of the field.
 */
OPEN1722_INLINE uint64_t Avtp_Jpeg2000_GetField(const Avtp_Jpeg2000_t *const pdu,
                                                Avtp_Jpeg2000Fields_t field)
{
    return (uint64_t)GET_JPEG2000_FIELD(field);
}

/**
 * Sets the value of a CVF JPEG 2000 field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 CVF JPEG 2000 header.
 * @param field Specifies the position of the data field to be written
 * @param value The value to set.
 */
OPEN1722_INLINE void Avtp_Jpeg2000_SetField(Avtp_Jpeg2000_t *pdu, Avtp_Jpeg2000Fields_t field,
                                            uint64_t value)
{
    SET_JPEG2000_FIELD(field, value);
}

#ifdef __cplusplus
}
#endif
