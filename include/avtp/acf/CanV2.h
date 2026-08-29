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
 * @file This file contains functions for de-/serialization of the ACF_CAN_V2
 * message format (CAN V2). For details see IEEE Std. 1722-2025,
 * chapter 9.4.3.
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

#define GET_CAN_V2_FIELD(field)                                                                    \
    (Avtp_GetField(Avtp_CanV2FieldDesc, AVTP_CAN_V2_FIELD_MAX, (uint8_t *)pdu, field))
#define SET_CAN_V2_FIELD(field, value)                                                             \
    (Avtp_SetField(Avtp_CanV2FieldDesc, AVTP_CAN_V2_FIELD_MAX, (uint8_t *)pdu, field, value))

/**
 * Length of ACF_CAN_V2 message header in bytes.
 */
#define AVTP_CAN_V2_HEADER_LEN (4 * AVTP_QUADLET_SIZE)

/**
 * ACF_CAN_V2 message structure suitable for in-place de-/serialization of fields
 * in the ACF_CAN_V2 message header.
 */
typedef struct {
    uint8_t header[AVTP_CAN_V2_HEADER_LEN];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_CanV2_t;

/**
 * Fields encoded in the ACF_CAN_V2 header.
 */
typedef enum {
    /* ACF common header fields */
    AVTP_CAN_V2_FIELD_ACF_MSG_TYPE = 0,
    AVTP_CAN_V2_FIELD_ACF_MSG_LENGTH,
    /* ACF CAN header fields */
    AVTP_CAN_V2_FIELD_PAD,
    AVTP_CAN_V2_FIELD_MTV,
    AVTP_CAN_V2_FIELD_RTR,
    AVTP_CAN_V2_FIELD_EFF,
    AVTP_CAN_V2_FIELD_CAN_BUS_ID,
    AVTP_CAN_V2_FIELD_MESSAGE_TIMESTAMP,
    AVTP_CAN_V2_FIELD_BRS,
    AVTP_CAN_V2_FIELD_FDF,
    AVTP_CAN_V2_FIELD_ESI,
    AVTP_CAN_V2_FIELD_CAN_IDENTIFIER,
    /* Count number of fields for bound checks */
    AVTP_CAN_V2_FIELD_MAX
} Avtp_CanV2Fields_t;

/**
 * This table describes all the offsets of the ACF_CAN_V2 header fields.
 */
static const Avtp_FieldDescriptor_t Avtp_CanV2FieldDesc[AVTP_CAN_V2_FIELD_MAX] = {
    /* ACF common header fields */
    [AVTP_CAN_V2_FIELD_ACF_MSG_TYPE] = {.quadlet = 0, .offset = 0, .bits = 7},
    [AVTP_CAN_V2_FIELD_ACF_MSG_LENGTH] = {.quadlet = 0, .offset = 7, .bits = 9},
    /* ACF CAN header fields */
    [AVTP_CAN_V2_FIELD_PAD] = {.quadlet = 0, .offset = 16, .bits = 2},
    [AVTP_CAN_V2_FIELD_MTV] = {.quadlet = 0, .offset = 18, .bits = 1},
    [AVTP_CAN_V2_FIELD_RTR] = {.quadlet = 0, .offset = 19, .bits = 1},
    [AVTP_CAN_V2_FIELD_EFF] = {.quadlet = 0, .offset = 20, .bits = 1},
    [AVTP_CAN_V2_FIELD_CAN_BUS_ID] = {.quadlet = 0, .offset = 21, .bits = 11},
    [AVTP_CAN_V2_FIELD_MESSAGE_TIMESTAMP] = {.quadlet = 1, .offset = 0, .bits = 64},
    [AVTP_CAN_V2_FIELD_BRS] = {.quadlet = 3, .offset = 0, .bits = 1},
    [AVTP_CAN_V2_FIELD_FDF] = {.quadlet = 3, .offset = 1, .bits = 1},
    [AVTP_CAN_V2_FIELD_ESI] = {.quadlet = 3, .offset = 2, .bits = 1},
    [AVTP_CAN_V2_FIELD_CAN_IDENTIFIER] = {.quadlet = 3, .offset = 3, .bits = 29},
};

/**
 * Return the value of the ACF message type field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF CAN V2 PDU.
 * @returns Value of the ACF message type field.
 */
OPEN1722_INLINE uint8_t Avtp_CanV2_GetAcfMsgType(const Avtp_CanV2_t *const pdu)
{
    return (uint8_t)GET_CAN_V2_FIELD(AVTP_CAN_V2_FIELD_ACF_MSG_TYPE);
}

/**
 * Return the value of the ACF message length field as specified in the IEEE 1722 Specification.
 * This returns the length in Quadlets as specified in the IEEE 1722 Specification.
 *
 * You can use Avtp_CanV2_GetPayloadLength to get the length in bytes without padding.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF CAN V2 PDU.
 * @returns Value of the ACF message length field.
 */
OPEN1722_INLINE uint16_t Avtp_CanV2_GetAcfMsgLength(const Avtp_CanV2_t *const pdu)
{
    return (uint16_t)GET_CAN_V2_FIELD(AVTP_CAN_V2_FIELD_ACF_MSG_LENGTH);
}

/**
 * Return the ACF message length in bytes.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF CAN V2 PDU.
 * @returns Length of the ACF message in bytes.
 */
OPEN1722_INLINE uint16_t Avtp_CanV2_GetAcfMsgLengthInBytes(const Avtp_CanV2_t *const pdu)
{
    return (uint16_t)GET_CAN_V2_FIELD(AVTP_CAN_V2_FIELD_ACF_MSG_LENGTH) * 4;
}

/**
 * Set the value of the ACF message type field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF CAN V2 PDU.
 * @param value Value to set the ACF message type field to.
 */
OPEN1722_INLINE void Avtp_CanV2_SetAcfMsgType(Avtp_CanV2_t *pdu, uint8_t value)
{
    SET_CAN_V2_FIELD(AVTP_CAN_V2_FIELD_ACF_MSG_TYPE, value);
}

/**
 * Set the value of the ACF message length field as specified in the IEEE 1722 Specification.
 * Note: the size is in Quadlets as specified in the IEEE 1722 Specification.
 * You can use Avtp_CanV2_SetPayloadLength to set length in bytes and automatically set the
 * correct padding.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF CAN V2 PDU.
 * @param value Value to set the ACF message length field to.
 */
OPEN1722_INLINE void Avtp_CanV2_SetAcfMsgLength(Avtp_CanV2_t *pdu, uint16_t value)
{
    SET_CAN_V2_FIELD(AVTP_CAN_V2_FIELD_ACF_MSG_LENGTH, value);
}

/**
 * Returns the pad field from an ACF_CAN_V2 message header.
 *
 * @param pdu Pointer to an ACF_CAN_V2 message.
 * @returns The value of the pad field.
 */
OPEN1722_INLINE uint8_t Avtp_CanV2_GetPad(const Avtp_CanV2_t *const pdu)
{
    return (uint8_t)GET_CAN_V2_FIELD(AVTP_CAN_V2_FIELD_PAD);
}

/**
 * Sets the pad field in an ACF_CAN_V2 message header.
 *
 * @param pdu Pointer to an ACF_CAN_V2 message.
 * @param pad The value to set.
 */
OPEN1722_INLINE void Avtp_CanV2_SetPad(Avtp_CanV2_t *pdu, uint8_t pad)
{
    SET_CAN_V2_FIELD(AVTP_CAN_V2_FIELD_PAD, pad);
}

/**
 * Returns the message timestamp valid flag (mtv) from an ACF_CAN_V2 message header.
 *
 * @param pdu Pointer to an ACF_CAN_V2 message.
 * @returns The value of the mtv flag.
 */
OPEN1722_INLINE bool Avtp_CanV2_IsMtv(const Avtp_CanV2_t *const pdu)
{
    return (bool)GET_CAN_V2_FIELD(AVTP_CAN_V2_FIELD_MTV);
}

/**
 * Returns the remote transmission request flag (rtr) from an ACF_CAN_V2 message header.
 *
 * @param pdu Pointer to an ACF_CAN_V2 message.
 * @returns The value of the rtr flag.
 */
OPEN1722_INLINE bool Avtp_CanV2_IsRtr(const Avtp_CanV2_t *const pdu)
{
    return (bool)GET_CAN_V2_FIELD(AVTP_CAN_V2_FIELD_RTR);
}

/**
 * Returns the extended frame format flag (eff) from an ACF_CAN_V2 message header.
 *
 * @param pdu Pointer to an ACF_CAN_V2 message.
 * @returns The value of the eff flag.
 */
OPEN1722_INLINE bool Avtp_CanV2_IsEff(const Avtp_CanV2_t *const pdu)
{
    return (bool)GET_CAN_V2_FIELD(AVTP_CAN_V2_FIELD_EFF);
}

/**
 * Returns the value of the can_bus_id field from an ACF_CAN_V2 message header.
 *
 * @param pdu Pointer to an ACF_CAN_V2 message.
 * @returns The value of the can_bus_id field.
 */
OPEN1722_INLINE uint16_t Avtp_CanV2_GetCanBusId(const Avtp_CanV2_t *const pdu)
{
    return (uint16_t)GET_CAN_V2_FIELD(AVTP_CAN_V2_FIELD_CAN_BUS_ID);
}

/**
 * Returns the value of the message_timestamp field from an ACF_CAN_V2 message header.
 *
 * @param pdu Pointer to an ACF_CAN_V2 message.
 * @returns The value of the message_timestamp field.
 */
OPEN1722_INLINE uint64_t Avtp_CanV2_GetMessageTimestamp(const Avtp_CanV2_t *const pdu)
{
    return (uint64_t)GET_CAN_V2_FIELD(AVTP_CAN_V2_FIELD_MESSAGE_TIMESTAMP);
}

/**
 * Returns the bit rate switch flag (brs) from an ACF_CAN_V2 message header.
 *
 * @param pdu Pointer to an ACF_CAN_V2 message.
 * @returns The value of the brs flag.
 */
OPEN1722_INLINE bool Avtp_CanV2_IsBrs(const Avtp_CanV2_t *const pdu)
{
    return (bool)GET_CAN_V2_FIELD(AVTP_CAN_V2_FIELD_BRS);
}

/**
 * Returns the FD frame flag (fdf) from an ACF_CAN_V2 message header.
 *
 * @param pdu Pointer to an ACF_CAN_V2 message.
 * @returns The value of the fdf flag.
 */
OPEN1722_INLINE bool Avtp_CanV2_IsFdf(const Avtp_CanV2_t *const pdu)
{
    return (bool)GET_CAN_V2_FIELD(AVTP_CAN_V2_FIELD_FDF);
}

/**
 * Returns the error state indicator flag (esi) from an ACF_CAN_V2 message header.
 *
 * @param pdu Pointer to an ACF_CAN_V2 message.
 * @returns The value of the esi flag.
 */
OPEN1722_INLINE bool Avtp_CanV2_IsEsi(const Avtp_CanV2_t *const pdu)
{
    return (bool)GET_CAN_V2_FIELD(AVTP_CAN_V2_FIELD_ESI);
}

/**
 * Returns the value of the can_identifier field from an ACF_CAN_V2 message header.
 *
 * @param pdu Pointer to an ACF_CAN_V2 message.
 * @returns The value of the can_identifier field.
 */
OPEN1722_INLINE uint32_t Avtp_CanV2_GetCanIdentifier(const Avtp_CanV2_t *const pdu)
{
    return (uint32_t)GET_CAN_V2_FIELD(AVTP_CAN_V2_FIELD_CAN_IDENTIFIER);
}

/**
 * Sets the value of the mtv flag in an ACF_CAN_V2 message header.
 *
 * @param pdu Pointer to an ACF_CAN_V2 message.
 * @param mtv The value to set.
 */
OPEN1722_INLINE void Avtp_CanV2_SetMtv(Avtp_CanV2_t *pdu, bool mtv)
{
    SET_CAN_V2_FIELD(AVTP_CAN_V2_FIELD_MTV, mtv);
}

/**
 * Sets the value of the rtr flag in an ACF_CAN_V2 message header.
 *
 * @param pdu Pointer to an ACF_CAN_V2 message.
 * @param rtr The value to set.
 */
OPEN1722_INLINE void Avtp_CanV2_SetRtr(Avtp_CanV2_t *pdu, bool rtr)
{
    SET_CAN_V2_FIELD(AVTP_CAN_V2_FIELD_RTR, rtr);
}

/**
 * Sets the value of the eff flag in an ACF_CAN_V2 message header.
 *
 * @param pdu Pointer to an ACF_CAN_V2 message.
 * @param eff The value to set.
 */
OPEN1722_INLINE void Avtp_CanV2_SetEff(Avtp_CanV2_t *pdu, bool eff)
{
    SET_CAN_V2_FIELD(AVTP_CAN_V2_FIELD_EFF, eff);
}

/**
 * Sets the value of the can_bus_id field in an ACF_CAN_V2 message header.
 *
 * @param pdu Pointer to an ACF_CAN_V2 message.
 * @param canBusId The value to set.
 */
OPEN1722_INLINE void Avtp_CanV2_SetCanBusId(Avtp_CanV2_t *pdu, uint16_t canBusId)
{
    SET_CAN_V2_FIELD(AVTP_CAN_V2_FIELD_CAN_BUS_ID, canBusId);
}

/**
 * Sets the value of the message_timestamp field in an ACF_CAN_V2 message header.
 *
 * @param pdu Pointer to an ACF_CAN_V2 message.
 * @param messageTimestamp The value to set.
 */
OPEN1722_INLINE void Avtp_CanV2_SetMessageTimestamp(Avtp_CanV2_t *pdu, uint64_t messageTimestamp)
{
    SET_CAN_V2_FIELD(AVTP_CAN_V2_FIELD_MESSAGE_TIMESTAMP, messageTimestamp);
}

/**
 * Sets the value of the brs flag in an ACF_CAN_V2 message header.
 *
 * @param pdu Pointer to an ACF_CAN_V2 message.
 * @param brs The value to set.
 */
OPEN1722_INLINE void Avtp_CanV2_SetBrs(Avtp_CanV2_t *pdu, bool brs)
{
    SET_CAN_V2_FIELD(AVTP_CAN_V2_FIELD_BRS, brs);
}

/**
 * Sets the value of the fdf flag in an ACF_CAN_V2 message header.
 *
 * @param pdu Pointer to an ACF_CAN_V2 message.
 * @param fdf The value to set.
 */
OPEN1722_INLINE void Avtp_CanV2_SetFdf(Avtp_CanV2_t *pdu, bool fdf)
{
    SET_CAN_V2_FIELD(AVTP_CAN_V2_FIELD_FDF, fdf);
}

/**
 * Sets the value of the esi flag in an ACF_CAN_V2 message header.
 *
 * @param pdu Pointer to an ACF_CAN_V2 message.
 * @param esi The value to set.
 */
OPEN1722_INLINE void Avtp_CanV2_SetEsi(Avtp_CanV2_t *pdu, bool esi)
{
    SET_CAN_V2_FIELD(AVTP_CAN_V2_FIELD_ESI, esi);
}

/**
 * Sets the value of the can_identifier field in an ACF_CAN_V2 message header.
 *
 * @param pdu Pointer to an ACF_CAN_V2 message.
 * @param canIdentifier The value to set.
 */
OPEN1722_INLINE void Avtp_CanV2_SetCanIdentifier(Avtp_CanV2_t *pdu, uint32_t canIdentifier)
{
    SET_CAN_V2_FIELD(AVTP_CAN_V2_FIELD_CAN_IDENTIFIER, canIdentifier);
}

/**
 * Returns pointer to payload of an ACF CAN V2 frame.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF CAN V2 PDU.
 * @return Pointer to ACF CAN V2 frame payload
 */
OPEN1722_INLINE const uint8_t *Avtp_CanV2_GetPayload(const Avtp_CanV2_t *const pdu)
{
    return pdu->payload;
}

/**
 * Sets the CAN payload in an ACF CAN V2 frame.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF CAN V2 PDU.
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload
 */
OPEN1722_INLINE void Avtp_CanV2_SetPayload(Avtp_CanV2_t *pdu, uint8_t *payload,
                                           uint16_t payload_length)
{
    memcpy(pdu->payload, payload, payload_length);
}

/**
 * Finalizes the ACF CAN V2 frame. This function will set the
 * length and pad fields while inserting the padded bytes. This will also
 * set padding bytes to zero if the payload length is not a multiple of 4.
 * to avoid leaking information
 *
 * @param pdu Pointer to the first bit of a 1722 ACF CAN V2 PDU.
 * @param payload_length Length of the CAN frame payload.
 */
OPEN1722_INLINE void Avtp_CanV2_SetPayloadLength(Avtp_CanV2_t *pdu, uint16_t payload_length)
{
    uint16_t msgLenBytes = AVTP_CAN_V2_HEADER_LEN + payload_length;
    uint8_t pad = (uint8_t)(4 - (msgLenBytes % 4)) % 4;
    if (pad > 0) {
        memset(pdu->payload + payload_length, 0, pad);
    }
    uint16_t msgLenQuadlets = (uint16_t)((msgLenBytes + pad) / 4);
    Avtp_CanV2_SetPad(pdu, pad);
    Avtp_CanV2_SetAcfMsgLength(pdu, msgLenQuadlets);
}

/**
 * Returns the length of the CAN payload without the padding bytes and the
 * header length of the encapsulating ACF Frame.
 *
 * Precondition: the caller must have validated the PDU with
 * Avtp_CanV2_IsValid(). IsValid checks both buffer-size containment and the
 * CAN payload-length invariant (<= 8 bytes for classic CAN, <= 64 bytes
 * for CAN-FD). This function performs no further bounds checking and
 * assumes those invariants already hold.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF CAN V2 PDU.
 * @return  Length of CAN payload in bytes
 */
OPEN1722_INLINE uint8_t Avtp_CanV2_GetPayloadLength(const Avtp_CanV2_t *const pdu)
{
    uint8_t pad_length = Avtp_CanV2_GetPad(pdu);
    uint16_t acf_length_bytes = Avtp_CanV2_GetAcfMsgLengthInBytes(pdu);
    return (uint8_t)(acf_length_bytes - AVTP_CAN_V2_HEADER_LEN - pad_length);
}

/**
 * Initializes an ACF_CAN_V2 message header as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF CAN V2 PDU.
 */
OPEN1722_INLINE void Avtp_CanV2_Init(Avtp_CanV2_t *pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_CanV2_t));
        Avtp_CanV2_SetAcfMsgType(pdu, AVTP_ACF_TYPE_CAN_V2);
    }
}

/**
 * Copies the payload data and CAN frame ID into the ACF CAN V2 frame. This function will
 * also set the length and pad fields while inserting the padded bytes.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF CAN V2 PDU.
 * @param frame_id ID of the CAN frame
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload.
 * @param can_variant Classic CAN or CAN-FD
 */
OPEN1722_INLINE void Avtp_CanV2_CreateAcfMessage(Avtp_CanV2_t *pdu, uint32_t frame_id,
                                                 uint8_t *payload, uint16_t payload_length,
                                                 Avtp_CanVariant_t can_variant)
{
    // Initialize the ACF CAN V2 header
    Avtp_CanV2_Init(pdu);

    // Copy the payload into the CAN PDU
    Avtp_CanV2_SetPayload(pdu, payload, payload_length);

    // Set the Frame ID and CAN variant
    if (frame_id > 0x7ff) {
        Avtp_CanV2_SetEff(pdu, true);
    }

    Avtp_CanV2_SetCanIdentifier(pdu, frame_id);
    if (can_variant == AVTP_CAN_FD) {
        Avtp_CanV2_SetFdf(pdu, true);
    }

    // Finalize the AVTP CAN Frame
    Avtp_CanV2_SetPayloadLength(pdu, payload_length);
}

/**
 * Checks if the ACF CAN V2 frame is valid by checking:
 *     1) if the length field of AVTP/ACF messages contains a value larger than the actual size of
 * the buffer that contains the AVTP message. 2) if other format specific invariants are not upheld
 * @param pdu Pointer to the first bit of a 1722 ACF CAN V2 PDU.
 * @param bufferSize Size of the buffer containing the ACF CAN V2 frame.
 * @return true if the ACF CAN V2 frame is valid, false otherwise.
 */
OPEN1722_INLINE bool Avtp_CanV2_IsValid(const Avtp_CanV2_t *const pdu, size_t bufferSize)
{
    if (pdu == NULL) {
        return false;
    }

    if (bufferSize < AVTP_CAN_V2_HEADER_LEN) {
        return false;
    }

    if (Avtp_CanV2_GetAcfMsgType(pdu) != AVTP_ACF_TYPE_CAN_V2) {
        return false;
    }

    // Avtp_CanV2_GetAcfMsgLength returns quadlets. Convert the length field to octets.
    uint16_t msg_length_bytes = (uint16_t)Avtp_CanV2_GetAcfMsgLength(pdu) * 4;
    if (msg_length_bytes > bufferSize) {
        return false;
    }

    /* CAN payload-length invariant: classic CAN ≤ 8 bytes, CAN-FD ≤ 64
     * bytes (selected by the FDF bit). The encoded message length must
     * also accommodate header + declared padding so the payload
     * computation in Avtp_CanV2_GetPayloadLength() doesn't underflow. */
    uint8_t pad_length = Avtp_CanV2_GetPad(pdu);
    uint16_t header_and_pad = (uint16_t)AVTP_CAN_V2_HEADER_LEN + pad_length;
    if (msg_length_bytes < header_and_pad) {
        return false;
    }
    uint16_t payload_length = msg_length_bytes - header_and_pad;
    uint16_t max_payload = Avtp_CanV2_IsFdf(pdu) ? 64u : 8u;
    if (payload_length > max_payload) {
        return false;
    }
    return true;
}

#ifdef __cplusplus
}
#endif
