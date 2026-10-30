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
 * @file This file contains functions for de-/serialization of the ACF_LIN_V2_V2
 * message format. For details see IEEE Std. 1722-2025 chapter 9.4.5.
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
#include "avtp/acf/AcfCommon.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GET_LIN_V2_FIELD(field)                                                                    \
    (Avtp_GetField(Avtp_LinV2FieldDesc, AVTP_LIN_V2_FIELD_MAX, (const uint8_t *)pdu, field))
#define SET_LIN_V2_FIELD(field, value)                                                             \
    (Avtp_SetField(Avtp_LinV2FieldDesc, AVTP_LIN_V2_FIELD_MAX, (uint8_t *)pdu, field, value))

/** Length of ACF LIN header. */
#define AVTP_LIN_V2_HEADER_LEN (4 * AVTP_QUADLET_SIZE)

/** ACF LIN V2 PDU. */
typedef struct {
    uint8_t header[AVTP_LIN_V2_HEADER_LEN];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_LinV2_t;

/** Fields of ACF LIN V2 PDU. */
typedef enum {
    /* ACF common header fields */
    AVTP_LIN_V2_FIELD_ACF_MSG_TYPE = 0,
    AVTP_LIN_V2_FIELD_ACF_MSG_LENGTH,
    /* ACF LIN header fields */
    AVTP_LIN_V2_FIELD_PAD,
    AVTP_LIN_V2_FIELD_MTV,
    AVTP_LIN_V2_FIELD_RSV,
    AVTP_LIN_V2_FIELD_LIN_V2_BUS_ID,
    AVTP_LIN_V2_FIELD_MESSAGE_TIMESTAMP,
    AVTP_LIN_V2_FIELD_LIN_V2_RESERVED,
    AVTP_LIN_V2_FIELD_LIN_V2_IDENTIFIER,
    /* Count number of fields for bound checks */
    AVTP_LIN_V2_FIELD_MAX
} Avtp_LinV2Fields_t;

/**
 * This table describes all the offsets of the ACF LIN V2 header fields.
 */
static const Avtp_FieldDescriptor_t Avtp_LinV2FieldDesc[AVTP_LIN_V2_FIELD_MAX] = {
    /* ACF common header fields */
    [AVTP_LIN_V2_FIELD_ACF_MSG_TYPE] = {.quadlet = 0, .offset = 0, .bits = 7},
    [AVTP_LIN_V2_FIELD_ACF_MSG_LENGTH] = {.quadlet = 0, .offset = 7, .bits = 9},
    /* ACF LIN header fields */
    [AVTP_LIN_V2_FIELD_PAD] = {.quadlet = 0, .offset = 16, .bits = 2},
    [AVTP_LIN_V2_FIELD_MTV] = {.quadlet = 0, .offset = 18, .bits = 1},
    [AVTP_LIN_V2_FIELD_RSV] = {.quadlet = 0, .offset = 19, .bits = 2},
    [AVTP_LIN_V2_FIELD_LIN_V2_BUS_ID] = {.quadlet = 0, .offset = 21, .bits = 11},
    [AVTP_LIN_V2_FIELD_MESSAGE_TIMESTAMP] = {.quadlet = 1, .offset = 0, .bits = 64},
    [AVTP_LIN_V2_FIELD_LIN_V2_RESERVED] = {.quadlet = 3, .offset = 0, .bits = 24},
    [AVTP_LIN_V2_FIELD_LIN_V2_IDENTIFIER] = {.quadlet = 3, .offset = 24, .bits = 8},
};

/**
 * Returns the value of an an ACF LIN V2 PDU Pad field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF LIN V2 PDU.
 * @returns The value of the ACF LIN V2 PDU Pad field.
 */
OPEN1722_INLINE uint8_t Avtp_LinV2_GetPad(const Avtp_LinV2_t *const pdu)
{
    return (uint8_t)GET_LIN_V2_FIELD(AVTP_LIN_V2_FIELD_PAD);
}

/**
 * Returns the value of an an ACF LIN V2 PDU MTV field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF LIN V2 PDU.
 * @returns The value of the ACF LIN V2 PDU MTV field.
 */
OPEN1722_INLINE bool Avtp_LinV2_IsMtv(const Avtp_LinV2_t *const pdu)
{
    return (bool)GET_LIN_V2_FIELD(AVTP_LIN_V2_FIELD_MTV);
}

/**
 * Returns the value of an an ACF LIN V2 PDU LIN Bus ID field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF LIN V2 PDU.
 * @returns The value of the ACF LIN V2 PDU LIN Bus ID field.
 */
OPEN1722_INLINE uint16_t Avtp_LinV2_GetLinBusId(const Avtp_LinV2_t *const pdu)
{
    return (uint16_t)GET_LIN_V2_FIELD(AVTP_LIN_V2_FIELD_LIN_V2_BUS_ID);
}

/**
 * Returns the value of an an ACF LIN V2 PDU LIN Identifier field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF LIN V2 PDU.
 * @returns The value of the ACF LIN V2 PDU LIN Identifier field.
 */
OPEN1722_INLINE uint8_t Avtp_LinV2_GetLinIdentifier(const Avtp_LinV2_t *const pdu)
{
    return (uint8_t)GET_LIN_V2_FIELD(AVTP_LIN_V2_FIELD_LIN_V2_IDENTIFIER);
}

/**
 * Returns the value of an an ACF LIN V2 PDU Message Timestamp field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF LIN V2 PDU.
 * @returns The value of the ACF LIN V2 PDU Message Timestamp field.
 */
OPEN1722_INLINE uint64_t Avtp_LinV2_GetMessageTimestamp(const Avtp_LinV2_t *const pdu)
{
    return (uint64_t)GET_LIN_V2_FIELD(AVTP_LIN_V2_FIELD_MESSAGE_TIMESTAMP);
}

/**
 * Sets the value of an an ACF LIN V2 PDU Pad field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF LIN V2 PDU.
 * @param value Value to set the ACF LIN V2 PDU Pad field to.
 */
OPEN1722_INLINE void Avtp_LinV2_SetPad(Avtp_LinV2_t *pdu, uint8_t value)
{
    SET_LIN_V2_FIELD(AVTP_LIN_V2_FIELD_PAD, value);
}

/**
 * Set the MTV bit in an ACF LIN frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF LIN V2 PDU.
 * @param mtv Value to set the MTV bit to.
 */
OPEN1722_INLINE void Avtp_LinV2_SetMtv(Avtp_LinV2_t *pdu, bool mtv)
{
    SET_LIN_V2_FIELD(AVTP_LIN_V2_FIELD_MTV, mtv);
}

/**
 * Set the value of an an ACF LIN V2 PDU LIN Bus ID field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF LIN V2 PDU.
 * @param value Value to set the ACF LIN V2 PDU LIN Bus ID field to.
 */
OPEN1722_INLINE void Avtp_LinV2_SetLinBusId(Avtp_LinV2_t *pdu, uint16_t value)
{
    SET_LIN_V2_FIELD(AVTP_LIN_V2_FIELD_LIN_V2_BUS_ID, value);
}

/**
 * Set the value of an an ACF LIN V2 PDU LIN Identifier field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF LIN V2 PDU.
 * @param value Value to set the ACF LIN V2 PDU LIN Identifier field to.
 */
OPEN1722_INLINE void Avtp_LinV2_SetLinIdentifier(Avtp_LinV2_t *pdu, uint8_t value)
{
    SET_LIN_V2_FIELD(AVTP_LIN_V2_FIELD_LIN_V2_IDENTIFIER, value);
}

/**
 * Set the value of an an ACF LIN V2 PDU Message Timestamp field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF LIN V2 PDU.
 * @param value Value to set the ACF LIN V2 PDU Message Timestamp field to.
 */
OPEN1722_INLINE void Avtp_LinV2_SetMessageTimestamp(Avtp_LinV2_t *pdu, uint64_t value)
{
    SET_LIN_V2_FIELD(AVTP_LIN_V2_FIELD_MESSAGE_TIMESTAMP, value);
}

/**
 * Returns pointer to payload of an ACF LIN V2 PDU.
 *
 * @param lin_pdu Pointer to the first bit of an 1722 ACF LIN V2 PDU.
 * @return Pointer to ACF LIN V2 PDU payload
 */
OPEN1722_INLINE const uint8_t *Avtp_LinV2_GetPayload(const Avtp_LinV2_t *const lin_pdu)
{
    return lin_pdu->payload;
}

/**
 * Sets the LIN payload in an ACF LIN V2 PDU.
 *
 * @param lin_pdu Pointer to the first bit of an 1722 ACF LIN V2 PDU.
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload
 */
OPEN1722_INLINE void Avtp_LinV2_SetPayload(Avtp_LinV2_t *lin_pdu, uint8_t *payload,
                                           uint16_t payload_length)
{
    memcpy(lin_pdu->payload, payload, payload_length);
}

/**
 * Finalizes the ACF LIN V2 PDU. This function will set the length and pad fields
 * while inserting the padded bytes. This will also set padding bytes to zero if
 * the payload length is not a multiple of 4 to avoid leaking information.
 *
 * @param lin_pdu Pointer to the first bit of an 1722 ACF LIN V2 PDU.
 * @param payload_length Length of the LIN frame payload.
 */
OPEN1722_INLINE void Avtp_LinV2_SetPayloadLength(Avtp_LinV2_t *lin_pdu, uint16_t payload_length)
{
    uint16_t msgLenBytes = AVTP_LIN_V2_HEADER_LEN + payload_length;
    uint8_t pad = (uint8_t)(4 - (msgLenBytes % 4)) % 4;
    if (pad > 0) {
        memset(lin_pdu->payload + payload_length, 0, pad);
    }
    uint16_t msgLenQuadlets = (uint16_t)((msgLenBytes + pad) / 4);
    Avtp_LinV2_SetPad(lin_pdu, pad);
    Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)lin_pdu, msgLenQuadlets);
}

/**
 * Returns the length of the LIN payload without the padding bytes and the
 * header length of the encapsulating ACF Frame.
 *
 * Precondition: the caller must have validated the PDU with
 * Avtp_LinV2_IsValid(). IsValid checks both buffer-size containment and the
 * LIN payload-length invariant (<= 8 bytes). This function performs no
 * further bounds checking and assumes those invariants already hold.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF LIN V2 PDU.
 * @return  Length of LIN payload in bytes
 */
OPEN1722_INLINE uint8_t Avtp_LinV2_GetPayloadLength(const Avtp_LinV2_t *const pdu)
{
    uint8_t pad_length = Avtp_LinV2_GetPad(pdu);
    uint16_t acf_length_bytes =
        Avtp_AcfCommon_GetAcfMsgLengthInBytes((const Avtp_AcfCommon_t *)pdu);
    return (uint8_t)(acf_length_bytes - AVTP_LIN_V2_HEADER_LEN - pad_length);
}

/**
 * Initializes an ACF LIN V2 PDU.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF LIN V2 PDU.
 */
OPEN1722_INLINE void Avtp_LinV2_Init(Avtp_LinV2_t *pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_LinV2_t));
        Avtp_AcfCommon_SetAcfMsgType((Avtp_AcfCommon_t *)pdu, AVTP_ACF_TYPE_LIN_V2);
    }
}

/**
 * Copies the payload data, LIN bus ID, LIN identifier and message timestamp into
 * the ACF LIN V2 PDU. This function will also set the length and pad fields while
 * inserting the padded bytes.
 *
 * @param lin_pdu Pointer to the first bit of an 1722 ACF LIN V2 PDU.
 * @param lin_bus_id LIN bus ID
 * @param lin_identifier LIN frame identifier
 * @param message_timestamp Message timestamp
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload.
 */
OPEN1722_INLINE void Avtp_LinV2_CreateAcfMessage(Avtp_LinV2_t *lin_pdu, uint16_t lin_bus_id,
                                                 uint8_t lin_identifier, uint64_t message_timestamp,
                                                 uint8_t *payload, uint16_t payload_length)
{
    // Initialize the ACF LIN header
    Avtp_LinV2_Init(lin_pdu);

    // Copy the payload into the LIN V2 PDU
    Avtp_LinV2_SetPayload(lin_pdu, payload, payload_length);

    // Set the LIN bus ID, identifier and message timestamp
    Avtp_LinV2_SetLinBusId(lin_pdu, lin_bus_id);
    Avtp_LinV2_SetLinIdentifier(lin_pdu, lin_identifier);
    Avtp_LinV2_SetMessageTimestamp(lin_pdu, message_timestamp);

    // Finalize the AVTP LIN Frame
    Avtp_LinV2_SetPayloadLength(lin_pdu, payload_length);
}

/**
 * Checks if the ACF LIN V2 PDU is valid by checking:
 *     1) if the length field of AVTP/ACF messages contains a value larger than the actual size of
 * the buffer that contains the AVTP message. 2) if other format specific invariants are not upheld
 * @param pdu Pointer to the first bit of an 1722 ACF LIN V2 PDU.
 * @param bufferSize Size of the buffer containing the ACF LIN V2 PDU.
 * @return true if the ACF LIN V2 PDU is valid, false otherwise.
 */
OPEN1722_INLINE bool Avtp_LinV2_IsValid(const Avtp_LinV2_t *const pdu, size_t bufferSize)
{
    if (pdu == NULL) {
        return false;
    }

    if (bufferSize < AVTP_LIN_V2_HEADER_LEN) {
        return false;
    }

    if (Avtp_AcfCommon_GetAcfMsgType((const Avtp_AcfCommon_t *)pdu) != AVTP_ACF_TYPE_LIN_V2) {
        return false;
    }

    uint16_t msg_length_bytes =
        Avtp_AcfCommon_GetAcfMsgLengthInBytes((const Avtp_AcfCommon_t *)pdu);
    if (msg_length_bytes > bufferSize) {
        return false;
    }

    /* LIN payload-length invariant: the encoded message length must also
     * accommodate header + declared padding so the payload computation in
     * Avtp_LinV2_GetPayloadLength() doesn't underflow. */
    uint8_t pad_length = Avtp_LinV2_GetPad(pdu);
    uint16_t header_and_pad = (uint16_t)AVTP_LIN_V2_HEADER_LEN + pad_length;
    if (msg_length_bytes < header_and_pad) {
        return false;
    }
    uint16_t payload_length = msg_length_bytes - header_and_pad;
    if (payload_length > 8u) {
        return false;
    }
    return true;
}

#ifdef __cplusplus
}
#endif
