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
 * @file This file contains functions for de-/serialization of the ACF_CRC
 * message format. For details see IEEE Std. 1722-2025, chapter 9.4.21.
 */

#pragma once
#include "avtp/Inline.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "avtp/Utils.h"
#include "avtp/Defines.h"
#include "avtp/acf/AcfCommon.h"

#define GET_CRC_FIELD(field)                                                                       \
    (Avtp_GetField(Avtp_CrcFieldDesc, AVTP_CRC_FIELD_MAX, (const uint8_t *)pdu, field))
#define SET_CRC_FIELD(field, value)                                                                \
    (Avtp_SetField(Avtp_CrcFieldDesc, AVTP_CRC_FIELD_MAX, (uint8_t *)pdu, field, value))

/**
 * Length of ACF_CRC message header in bytes.
 */
#define AVTP_CRC_HEADER_LEN (1 * AVTP_QUADLET_SIZE)

/**
 * ACF_CRC message structure suitable for in-place de-/serialization of fields
 * in the ACF_CRC message header.
 */
typedef struct {
    uint8_t header[AVTP_CRC_HEADER_LEN];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_Crc_t;

/**
 * Fields encoded in the ACF_CRC header.
 */
typedef enum {
    /* ACF common header fields */
    AVTP_CRC_FIELD_ACF_MSG_TYPE = 0,
    AVTP_CRC_FIELD_ACF_MSG_LENGTH,
    /* ACF_CRC header fields */
    AVTP_CRC_FIELD_RESERVED,
    AVTP_CRC_FIELD_CRC_TYPE,
    /* Count number of fields for bound checks */
    AVTP_CRC_FIELD_MAX
} Avtp_CrcFields_t;

/**
 * CRC types encoded in the ACF_CRC header.
 */
typedef enum {
    AVTP_CRC_TYPE_CRC_ETH = 0,
    AVTP_CRC_TYPE_CRC_32P4 = 1,
    AVTP_CRC_TYPE_CRC_USER = 0xF,
} Avtp_CrcType_t;

/**
 * This table describes all the offsets of the ACF_CRC header fields.
 */
static const Avtp_FieldDescriptor_t Avtp_CrcFieldDesc[AVTP_CRC_FIELD_MAX] = {
    /* ACF common header fields */
    [AVTP_CRC_FIELD_ACF_MSG_TYPE] = {.quadlet = 0, .offset = 0, .bits = 7},
    [AVTP_CRC_FIELD_ACF_MSG_LENGTH] = {.quadlet = 0, .offset = 7, .bits = 9},
    /* ACF_CRC header fields */
    [AVTP_CRC_FIELD_RESERVED] = {.quadlet = 0, .offset = 16, .bits = 12},
    [AVTP_CRC_FIELD_CRC_TYPE] = {.quadlet = 0, .offset = 28, .bits = 4},
};

/**
 * Sets the CRC type field in an ACF_CRC message header.
 *
 * @param pdu Pointer to an ACF_CRC message.
 * @param crc_type The value to set.
 */
OPEN1722_INLINE void Avtp_Crc_SetCrcType(Avtp_Crc_t *pdu, Avtp_CrcType_t crc_type)
{
    SET_CRC_FIELD(AVTP_CRC_FIELD_CRC_TYPE, crc_type);
}

/**
 * Returns the value of the CRC type field from an ACF_CRC message header.
 *
 * @param pdu Pointer to an ACF_CRC message.
 * @returns The value of the CRC type field.
 */
OPEN1722_INLINE Avtp_CrcType_t Avtp_Crc_GetCrcType(const Avtp_Crc_t *const pdu)
{
    return (Avtp_CrcType_t)GET_CRC_FIELD(AVTP_CRC_FIELD_CRC_TYPE);
}

/**
 * Returns pointer to payload of an ACF CRC frame.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF CRC PDU.
 * @return Pointer to ACF CRC frame payload
 */
OPEN1722_INLINE const uint8_t *Avtp_Crc_GetPayload(const Avtp_Crc_t *const pdu)
{
    return pdu->payload;
}

/**
 * Sets the CRC payload in an ACF CRC frame.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF CRC PDU.
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload
 */
OPEN1722_INLINE void Avtp_Crc_SetPayload(Avtp_Crc_t *pdu, uint8_t *payload, uint16_t payload_length)
{
    memcpy(pdu->payload, payload, payload_length);
}

/**
 * Finalizes the ACF CRC frame. This function sets the quadlet-encoded
 * length field based on the given payload length and zeroes the trailing
 * padding octets.
 *
 * The ACF CRC format has no explicit pad field. The number of padding
 * octets is determined by the payload length. Trailing padding octets
 * are set to zero to make the ACF CRC frame a multiple of 4 octets in length.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CRC PDU.
 * @param payload_length Length of the CRC payload.
 */
OPEN1722_INLINE void Avtp_Crc_SetPayloadLength(Avtp_Crc_t *pdu, uint16_t payload_length)
{
    uint16_t msgLenBytes = AVTP_CRC_HEADER_LEN + payload_length;
    uint8_t pad = (uint8_t)(4 - (msgLenBytes % 4)) % 4;
    if (pad > 0) {
        memset(pdu->payload + payload_length, 0, pad);
    }
    uint16_t msgLenQuadlets = (uint16_t)((msgLenBytes + pad) / 4);
    Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)pdu, msgLenQuadlets);
}

/*
 * Note: there is intentionally no Avtp_Crc_GetPayloadLength() function.
 *
 * The ACF CRC header carries neither a pad field nor a payload-length field, so
 * the true payload length cannot be recovered from the wire format alone.
 *
 * If the CRC type is AVTP_CRC_TYPE_CRC_ETH, the payload length is always 4 bytes.
 * If the CRC type is AVTP_CRC_TYPE_CRC_32P4, the payload length is always 4 bytes.
 *
 * If the CRC type is AVTP_CRC_TYPE_CRC_USER, the payload length is variable and
 * must be tracked by the caller. There is no way to determine the payload length
 * from the ACF CRC header alone.
 */

/**
 * Initializes an ACF CRC PDU header as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF CRC PDU.
 */
OPEN1722_INLINE void Avtp_Crc_Init(Avtp_Crc_t *pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_Crc_t));
        Avtp_AcfCommon_SetAcfMsgType((Avtp_AcfCommon_t *)pdu, AVTP_ACF_TYPE_CRC);
    }
}

/**
 * Copies the payload data and CRC type into the ACF CRC frame.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CRC PDU.
 * @param crc_type CRC type
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload.
 */
OPEN1722_INLINE void Avtp_Crc_CreateAcfMessage(Avtp_Crc_t *pdu, Avtp_CrcType_t crc_type,
                                               uint8_t *payload, uint16_t payload_length)
{
    // Initialize the ACF CRC header
    Avtp_Crc_Init(pdu);

    // Set the CRC type
    Avtp_Crc_SetCrcType(pdu, crc_type);

    // Copy the payload into the CRC PDU
    Avtp_Crc_SetPayload(pdu, payload, payload_length);

    // Finalize the AVTP CRC Frame
    Avtp_Crc_SetPayloadLength(pdu, payload_length);
}

/**
 * Checks if the ACF CRC frame is valid by checking:
 *     1) if the length field of AVTP/ACF messages contains a value larger than the actual size of
 * the buffer that contains the AVTP message. 2) if other format specific invariants are not upheld
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CRC PDU.
 * @param bufferSize Size of the buffer containing the ACF CRC frame.
 * @return true if the ACF CRC frame is valid, false otherwise.
 */
OPEN1722_INLINE bool Avtp_Crc_IsValid(const Avtp_Crc_t *const pdu, size_t bufferSize)
{
    if (pdu == NULL) {
        return false;
    }

    if (bufferSize < AVTP_CRC_HEADER_LEN) {
        return false;
    }

    if (Avtp_AcfCommon_GetAcfMsgType((const Avtp_AcfCommon_t *)pdu) != AVTP_ACF_TYPE_CRC) {
        return false;
    }

    uint16_t msg_length_bytes =
        Avtp_AcfCommon_GetAcfMsgLengthInBytes((const Avtp_AcfCommon_t *)pdu);
    if (Avtp_Crc_GetCrcType(pdu) == AVTP_CRC_TYPE_CRC_ETH ||
        Avtp_Crc_GetCrcType(pdu) == AVTP_CRC_TYPE_CRC_32P4) {
        if (msg_length_bytes != (AVTP_CRC_HEADER_LEN + 4)) {
            return false;
        }
    }

    if (msg_length_bytes > bufferSize) {
        return false;
    }

    if (msg_length_bytes < AVTP_CRC_HEADER_LEN) {
        return false;
    }

    return true;
}

#ifdef __cplusplus
}
#endif
