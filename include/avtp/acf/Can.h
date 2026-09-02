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
 * This file contains the fields descriptions of the IEEE 1722-2016 ACF CAN PDUs and
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
#include "avtp/acf/AcfCommon.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GET_CAN_FIELD(field)                                                                       \
    (Avtp_GetField(Avtp_CanFieldDesc, AVTP_CAN_FIELD_MAX, (uint8_t *)pdu, field))
#define SET_CAN_FIELD(field, value)                                                                \
    (Avtp_SetField(Avtp_CanFieldDesc, AVTP_CAN_FIELD_MAX, (uint8_t *)pdu, field, value))

#define AVTP_CAN_HEADER_LEN (4 * AVTP_QUADLET_SIZE)

typedef struct {
    uint8_t header[AVTP_CAN_HEADER_LEN];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_Can_t;

typedef enum {

    /* ACF common header fields */
    AVTP_CAN_FIELD_ACF_MSG_TYPE = 0,
    AVTP_CAN_FIELD_ACF_MSG_LENGTH,

    /* ACF CAN header fields */
    AVTP_CAN_FIELD_PAD,
    AVTP_CAN_FIELD_MTV,
    AVTP_CAN_FIELD_RTR,
    AVTP_CAN_FIELD_EFF,
    AVTP_CAN_FIELD_BRS,
    AVTP_CAN_FIELD_FDF,
    AVTP_CAN_FIELD_ESI,
    AVTP_CAN_FIELD_CAN_BUS_ID,
    AVTP_CAN_FIELD_MESSAGE_TIMESTAMP,
    AVTP_CAN_FIELD_CAN_IDENTIFIER,

    /* Count number of fields for bound checks */
    AVTP_CAN_FIELD_MAX
} Avtp_CanFields_t;

/**
 * This table maps all IEEE 1722 ACF CAN header fields to a descriptor.
 */
static const Avtp_FieldDescriptor_t Avtp_CanFieldDesc[AVTP_CAN_FIELD_MAX] = {
    /* ACF common header fields */
    [AVTP_CAN_FIELD_ACF_MSG_TYPE] = {.quadlet = 0, .offset = 0, .bits = 7},
    [AVTP_CAN_FIELD_ACF_MSG_LENGTH] = {.quadlet = 0, .offset = 7, .bits = 9},
    /* ACF CAN header fields */
    [AVTP_CAN_FIELD_PAD] = {.quadlet = 0, .offset = 16, .bits = 2},
    [AVTP_CAN_FIELD_MTV] = {.quadlet = 0, .offset = 18, .bits = 1},
    [AVTP_CAN_FIELD_RTR] = {.quadlet = 0, .offset = 19, .bits = 1},
    [AVTP_CAN_FIELD_EFF] = {.quadlet = 0, .offset = 20, .bits = 1},
    [AVTP_CAN_FIELD_BRS] = {.quadlet = 0, .offset = 21, .bits = 1},
    [AVTP_CAN_FIELD_FDF] = {.quadlet = 0, .offset = 22, .bits = 1},
    [AVTP_CAN_FIELD_ESI] = {.quadlet = 0, .offset = 23, .bits = 1},
    [AVTP_CAN_FIELD_CAN_BUS_ID] = {.quadlet = 0, .offset = 27, .bits = 5},
    [AVTP_CAN_FIELD_MESSAGE_TIMESTAMP] = {.quadlet = 1, .offset = 0, .bits = 64},
    [AVTP_CAN_FIELD_CAN_IDENTIFIER] = {.quadlet = 3, .offset = 3, .bits = 29},
};

/**
 * Return the value of an an ACF padding field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @returns Value of the ACF padding field.
 */
OPEN1722_INLINE uint8_t Avtp_Can_GetPad(const Avtp_Can_t *const pdu)
{
    return (uint8_t)GET_CAN_FIELD(AVTP_CAN_FIELD_PAD);
}

/**
 * Return the value of an an ACF CAN PDU MTV field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @returns Value of the ACF CAN PDU MTV field.
 */
OPEN1722_INLINE bool Avtp_Can_IsMtv(const Avtp_Can_t *const pdu)
{
    return (bool)GET_CAN_FIELD(AVTP_CAN_FIELD_MTV);
}

/**
 * Return the value of an an ACF CAN PDU RTR field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @returns Value of the ACF CAN PDU RTR field.
 */
OPEN1722_INLINE bool Avtp_Can_IsRtr(const Avtp_Can_t *const pdu)
{
    return (bool)GET_CAN_FIELD(AVTP_CAN_FIELD_RTR);
}

/**
 * Return the value of an an ACF CAN PDU EFF field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @returns Value of the ACF CAN PDU EFF field.
 */
OPEN1722_INLINE bool Avtp_Can_IsEff(const Avtp_Can_t *const pdu)
{
    return (bool)GET_CAN_FIELD(AVTP_CAN_FIELD_EFF);
}

/**
 * Return the value of an an ACF CAN PDU BRS field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @returns Value of the ACF CAN PDU BRS field.
 */
OPEN1722_INLINE bool Avtp_Can_IsBrs(const Avtp_Can_t *const pdu)
{
    return (bool)GET_CAN_FIELD(AVTP_CAN_FIELD_BRS);
}

/**
 * Return the value of an an ACF CAN PDU FDF field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @returns Value of the ACF CAN PDU FDF field.
 */
OPEN1722_INLINE bool Avtp_Can_IsFdf(const Avtp_Can_t *const pdu)
{
    return (bool)GET_CAN_FIELD(AVTP_CAN_FIELD_FDF);
}

/**
 * Return the value of an an ACF CAN PDU ESI field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @returns Value of the ACF CAN PDU ESI field.
 */
OPEN1722_INLINE bool Avtp_Can_IsEsi(const Avtp_Can_t *const pdu)
{
    return (bool)GET_CAN_FIELD(AVTP_CAN_FIELD_ESI);
}

/**
 * Return the value of an an ACF CAN PDU CAN Bus ID field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @returns Value of the ACF CAN PDU CAN Bus ID field.
 */
OPEN1722_INLINE uint8_t Avtp_Can_GetCanBusId(const Avtp_Can_t *const pdu)
{
    return (uint8_t)GET_CAN_FIELD(AVTP_CAN_FIELD_CAN_BUS_ID);
}

/**
 * Return the value of an an ACF CAN PDU Message Timestamp field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @returns Value of the ACF CAN PDU Message Timestamp field.
 */
OPEN1722_INLINE uint64_t Avtp_Can_GetMessageTimestamp(const Avtp_Can_t *const pdu)
{
    return GET_CAN_FIELD(AVTP_CAN_FIELD_MESSAGE_TIMESTAMP);
}

/**
 * Return the value of an an ACF CAN PDU CAN Identifier field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @returns Value of the ACF CAN PDU CAN Identifier field.
 */
OPEN1722_INLINE uint32_t Avtp_Can_GetCanIdentifier(const Avtp_Can_t *const pdu)
{
    return (uint32_t)GET_CAN_FIELD(AVTP_CAN_FIELD_CAN_IDENTIFIER);
}

/**
 * Set the value of an an ACF padding field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @param value Value to set the ACF padding field to.
 */
OPEN1722_INLINE void Avtp_Can_SetPad(Avtp_Can_t *pdu, uint8_t value)
{
    SET_CAN_FIELD(AVTP_CAN_FIELD_PAD, value);
}

/**
 * Set the value of an an ACF CAN Bus ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @param value Value to set the ACF CAN Bus ID field to.
 */
OPEN1722_INLINE void Avtp_Can_SetCanBusId(Avtp_Can_t *pdu, uint8_t value)
{
    SET_CAN_FIELD(AVTP_CAN_FIELD_CAN_BUS_ID, value);
}

/**
 * Set the value of an an ACF CAN Message Timestamp field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @param value Value to set the ACF CAN Message Timestamp field to.
 */
OPEN1722_INLINE void Avtp_Can_SetMessageTimestamp(Avtp_Can_t *pdu, uint64_t value)
{
    SET_CAN_FIELD(AVTP_CAN_FIELD_MESSAGE_TIMESTAMP, value);
}

/**
 * Set the value of an an ACF CAN Identifier field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @param value Value to set the ACF CAN Identifier field to.
 */
OPEN1722_INLINE void Avtp_Can_SetCanIdentifier(Avtp_Can_t *pdu, uint32_t value)
{
    SET_CAN_FIELD(AVTP_CAN_FIELD_CAN_IDENTIFIER, value);
}

/**
 * Set the MTV bit in an ACF CAN frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @param mtv Value to set the MTV bit to.
 */
OPEN1722_INLINE void Avtp_Can_SetMtv(Avtp_Can_t *pdu, bool mtv)
{
    SET_CAN_FIELD(AVTP_CAN_FIELD_MTV, mtv);
}

/**
 * Set the RTR bit in an ACF CAN frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @param rtr Value to set the RTR bit to.
 */
OPEN1722_INLINE void Avtp_Can_SetRtr(Avtp_Can_t *pdu, bool rtr)
{
    SET_CAN_FIELD(AVTP_CAN_FIELD_RTR, rtr);
}

/**
 * Set the EFF bit in an ACF CAN frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @param eff Value to set the EFF bit to.
 */
OPEN1722_INLINE void Avtp_Can_SetEff(Avtp_Can_t *pdu, bool eff)
{
    SET_CAN_FIELD(AVTP_CAN_FIELD_EFF, eff);
}

/**
 * Set the BRS bit in an ACF CAN frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @param brs Value to set the BRS bit to.
 */
OPEN1722_INLINE void Avtp_Can_SetBrs(Avtp_Can_t *pdu, bool brs)
{
    SET_CAN_FIELD(AVTP_CAN_FIELD_BRS, brs);
}

/**
 * Set the FDF bit in an ACF CAN frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @param fdf Value to set the FDF bit to.
 */
OPEN1722_INLINE void Avtp_Can_SetFdf(Avtp_Can_t *pdu, bool fdf)
{
    SET_CAN_FIELD(AVTP_CAN_FIELD_FDF, fdf);
}

/**
 * Set the ESI bit in an ACF CAN frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @param esi Value to set the ESI bit to.
 */
OPEN1722_INLINE void Avtp_Can_SetEsi(Avtp_Can_t *pdu, bool esi)
{
    SET_CAN_FIELD(AVTP_CAN_FIELD_ESI, esi);
}

/**
 * Returns pointer to payload of an ACF CAN frame.
 *
 * @param can_pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @return Pointer to ACF CAN frame payload
 */
OPEN1722_INLINE const uint8_t *Avtp_Can_GetPayload(const Avtp_Can_t *const can_pdu)
{
    return can_pdu->payload;
}

/**
 * Sets the CAN payload in an ACF CAN frame.
 *
 * @param can_pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload
 */
OPEN1722_INLINE void Avtp_Can_SetPayload(Avtp_Can_t *can_pdu, uint8_t *payload,
                                         uint16_t payload_length)
{
    memcpy(can_pdu->payload, payload, payload_length);
}

/**
 * Finalizes the ACF CAN frame. This function will set the
 * length and pad fields while inserting the padded bytes. This will also
 * set padding bytes to zero if the payload length is not a multiple of 4.
 * to avoid leaking information
 *
 * @param can_pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the CAN frame payload.
 */
OPEN1722_INLINE void Avtp_Can_SetPayloadLength(Avtp_Can_t *can_pdu, uint16_t payload_length)
{
    uint16_t msgLenBytes = AVTP_CAN_HEADER_LEN + payload_length;
    uint8_t pad = (uint8_t)(4 - (msgLenBytes % 4)) % 4;
    if (pad > 0) {
        memset(can_pdu->payload + payload_length, 0, pad);
    }
    uint16_t msgLenQuadlets = (uint16_t)((msgLenBytes + pad) / 4);
    Avtp_Can_SetPad(can_pdu, pad);
    Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)can_pdu, msgLenQuadlets);
}

/**
 * Returns the length of the CAN payload without the padding bytes and the
 * header length of the encapsulating ACF Frame.
 *
 * Precondition: the caller must have validated the PDU with
 * Avtp_Can_IsValid(). IsValid checks both buffer-size containment and the
 * CAN payload-length invariant (<= 8 bytes for classic CAN, <= 64 bytes
 * for CAN-FD). This function performs no further bounds checking and
 * assumes those invariants already hold.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @return  Length of CAN payload in bytes
 */
OPEN1722_INLINE uint8_t Avtp_Can_GetPayloadLength(const Avtp_Can_t *const pdu)
{
    uint8_t pad_length = Avtp_Can_GetPad(pdu);
    uint16_t acf_length_bytes =
        Avtp_AcfCommon_GetAcfMsgLengthInBytes((const Avtp_AcfCommon_t *)pdu);
    return (uint8_t)(acf_length_bytes - AVTP_CAN_HEADER_LEN - pad_length);
}

/**
 * Initializes an ACF CAN PDU header as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF CAN PDU.
 */
OPEN1722_INLINE void Avtp_Can_Init(Avtp_Can_t *pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_Can_t));
        Avtp_AcfCommon_SetAcfMsgType((Avtp_AcfCommon_t *)pdu, AVTP_ACF_TYPE_CAN);
    }
}

/**
 * Copies the payload data and CAN frame ID into the ACF CAN frame. This function will
 * also set the length and pad fields while inserting the padded bytes.
 *
 * @param can_pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @param frame_id ID of the CAN frame
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload.
 * @param can_variant Classic CAN or CAN-FD
 */
OPEN1722_INLINE void Avtp_Can_CreateAcfMessage(Avtp_Can_t *can_pdu, uint32_t frame_id,
                                               uint8_t *payload, uint16_t payload_length,
                                               Avtp_CanVariant_t can_variant)
{
    // Initialize the ACF CAN header
    Avtp_Can_Init(can_pdu);

    // Copy the payload into the CAN PDU
    Avtp_Can_SetPayload(can_pdu, payload, payload_length);

    // Set the Frame ID and CAN variant
    if (frame_id > 0x7ff) {
        Avtp_Can_SetEff(can_pdu, true);
    }

    Avtp_Can_SetCanIdentifier(can_pdu, frame_id);
    if (can_variant == AVTP_CAN_FD) {
        Avtp_Can_SetFdf(can_pdu, true);
    }

    // Finalize the AVTP CAN Frame
    Avtp_Can_SetPayloadLength(can_pdu, payload_length);
}

/**
 * Checks if the ACF CAN frame is valid by checking:
 *     1) if the length field of AVTP/ACF messages contains a value larger than the actual size of
 * the buffer that contains the AVTP message. 2) if other format specific invariants are not upheld
 * @param pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @param bufferSize Size of the buffer containing the ACF CAN frame.
 * @return true if the ACF CAN frame is valid, false otherwise.
 */
OPEN1722_INLINE bool Avtp_Can_IsValid(const Avtp_Can_t *const pdu, size_t bufferSize)
{
    if (pdu == NULL) {
        return false;
    }

    if (bufferSize < AVTP_CAN_HEADER_LEN) {
        return false;
    }

    if (Avtp_AcfCommon_GetAcfMsgType((const Avtp_AcfCommon_t *)pdu) != AVTP_ACF_TYPE_CAN) {
        return false;
    }

    uint16_t msg_length_bytes =
        Avtp_AcfCommon_GetAcfMsgLengthInBytes((const Avtp_AcfCommon_t *)pdu);
    if (msg_length_bytes > bufferSize) {
        return false;
    }

    /* CAN payload-length invariant: classic CAN ≤ 8 bytes, CAN-FD ≤ 64
     * bytes (selected by the FDF bit). The encoded message length must
     * also accommodate header + declared padding so the payload
     * computation in Avtp_Can_GetPayloadLength() doesn't underflow. */
    uint8_t pad_length = Avtp_Can_GetPad(pdu);
    uint16_t header_and_pad = (uint16_t)AVTP_CAN_HEADER_LEN + pad_length;
    if (msg_length_bytes < header_and_pad) {
        return false;
    }
    uint16_t payload_length = msg_length_bytes - header_and_pad;
    uint16_t max_payload = Avtp_Can_IsFdf(pdu) ? 64u : 8u;
    if (payload_length > max_payload) {
        return false;
    }
    return true;
}

#ifdef __cplusplus
}
#endif
