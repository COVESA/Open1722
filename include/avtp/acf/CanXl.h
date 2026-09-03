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
 * @file This file contains functions for de-/serialization of the ACF_CANXL
 * message format (CAN XL). For details see IEEE Std. 1722-2025,
 * chapter 9.4.18.
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

#define GET_CANXL_FIELD(field)                                                                     \
    (Avtp_GetField(Avtp_CanXlFieldDesc, AVTP_CANXL_FIELD_MAX, (const uint8_t *)pdu, field))
#define SET_CANXL_FIELD(field, value)                                                              \
    (Avtp_SetField(Avtp_CanXlFieldDesc, AVTP_CANXL_FIELD_MAX, (uint8_t *)pdu, field, value))

/**
 * Length of ACF_CANXL message header in bytes.
 */
#define AVTP_CANXL_HEADER_LEN (6 * AVTP_QUADLET_SIZE)

/**
 * ACF_CANXL message structure suitable for in-place de-/serialization of fields
 * in the ACF_CANXL message header.
 */
typedef struct {
    uint8_t header[AVTP_CANXL_HEADER_LEN];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_CanXl_t;

/**
 * Fields encoded in the ACF_CANXL header.
 */
typedef enum {
    /* ACF common header fields */
    AVTP_CANXL_FIELD_ACF_MSG_TYPE = 0,
    AVTP_CANXL_FIELD_ACF_MSG_LENGTH,
    /* ACF CANXL header fields */
    AVTP_CANXL_FIELD_PAD,
    AVTP_CANXL_FIELD_MTV,
    AVTP_CANXL_FIELD_CAN_BUS_ID,
    AVTP_CANXL_FIELD_MESSAGE_TIMESTAMP,
    AVTP_CANXL_FIELD_VCID,
    AVTP_CANXL_FIELD_SDT,
    AVTP_CANXL_FIELD_RRS,
    AVTP_CANXL_FIELD_SEC,
    AVTP_CANXL_FIELD_PRIORITY_ID,
    AVTP_CANXL_FIELD_ACCEPTANCE_FIELD,
    AVTP_CANXL_FIELD_TRANSACTION_NUM,
    AVTP_CANXL_FIELD_MS,
    AVTP_CANXL_FIELD_SEGMENT_NUM,
    /* Count number of fields for bound checks */
    AVTP_CANXL_FIELD_MAX
} Avtp_CanXlFields_t;

/**
 * This table describes all the offsets of the ACF_CANXL header fields.
 */
static const Avtp_FieldDescriptor_t Avtp_CanXlFieldDesc[AVTP_CANXL_FIELD_MAX] = {
    /* ACF common header fields */
    [AVTP_CANXL_FIELD_ACF_MSG_TYPE] = {.quadlet = 0, .offset = 0, .bits = 7},
    [AVTP_CANXL_FIELD_ACF_MSG_LENGTH] = {.quadlet = 0, .offset = 7, .bits = 9},
    /* ACF CANXL header fields */
    [AVTP_CANXL_FIELD_PAD] = {.quadlet = 0, .offset = 16, .bits = 2},
    [AVTP_CANXL_FIELD_MTV] = {.quadlet = 0, .offset = 18, .bits = 1},
    [AVTP_CANXL_FIELD_CAN_BUS_ID] = {.quadlet = 0, .offset = 21, .bits = 11},
    [AVTP_CANXL_FIELD_MESSAGE_TIMESTAMP] = {.quadlet = 1, .offset = 0, .bits = 64},
    [AVTP_CANXL_FIELD_VCID] = {.quadlet = 3, .offset = 0, .bits = 8},
    [AVTP_CANXL_FIELD_SDT] = {.quadlet = 3, .offset = 8, .bits = 8},
    [AVTP_CANXL_FIELD_RRS] = {.quadlet = 3, .offset = 19, .bits = 1},
    [AVTP_CANXL_FIELD_SEC] = {.quadlet = 3, .offset = 20, .bits = 1},
    [AVTP_CANXL_FIELD_PRIORITY_ID] = {.quadlet = 3, .offset = 21, .bits = 11},
    [AVTP_CANXL_FIELD_ACCEPTANCE_FIELD] = {.quadlet = 4, .offset = 0, .bits = 32},
    [AVTP_CANXL_FIELD_TRANSACTION_NUM] = {.quadlet = 5, .offset = 8, .bits = 8},
    [AVTP_CANXL_FIELD_MS] = {.quadlet = 5, .offset = 19, .bits = 1},
    [AVTP_CANXL_FIELD_SEGMENT_NUM] = {.quadlet = 5, .offset = 20, .bits = 12},
};

/**
 * Returns the pad field from an ACF_CANXL message header.
 *
 * @param pdu Pointer to an ACF_CANXL message.
 * @returns The value of the pad field.
 */
OPEN1722_INLINE uint8_t Avtp_CanXl_GetPad(const Avtp_CanXl_t *const pdu)
{
    return (uint8_t)GET_CANXL_FIELD(AVTP_CANXL_FIELD_PAD);
}

/**
 * Sets the pad field in an ACF_CANXL message header.
 *
 * @param pdu Pointer to an ACF_CANXL message.
 * @param pad The value to set.
 */
OPEN1722_INLINE void Avtp_CanXl_SetPad(Avtp_CanXl_t *pdu, uint8_t pad)
{
    SET_CANXL_FIELD(AVTP_CANXL_FIELD_PAD, pad);
}

/**
 * Returns the message timestamp valid flag (mtv) from an ACF_CANXL message header.
 *
 * @param pdu Pointer to an ACF_CANXL message.
 * @returns The value of the mtv flag.
 */
OPEN1722_INLINE bool Avtp_CanXl_IsMtv(const Avtp_CanXl_t *const pdu)
{
    return (bool)GET_CANXL_FIELD(AVTP_CANXL_FIELD_MTV);
}

/**
 * Returns the value of the can_bus_id field from an ACF_CANXL message header.
 *
 * @param pdu Pointer to an ACF_CANXL message.
 * @returns The value of the can_bus_id field.
 */
OPEN1722_INLINE uint16_t Avtp_CanXl_GetCanBusId(const Avtp_CanXl_t *const pdu)
{
    return (uint16_t)GET_CANXL_FIELD(AVTP_CANXL_FIELD_CAN_BUS_ID);
}

/**
 * Returns the value of the message_timestamp field from an ACF_CANXL message header.
 *
 * @param pdu Pointer to an ACF_CANXL message.
 * @returns The value of the message_timestamp field.
 */
OPEN1722_INLINE uint64_t Avtp_CanXl_GetMessageTimestamp(const Avtp_CanXl_t *const pdu)
{
    return (uint64_t)GET_CANXL_FIELD(AVTP_CANXL_FIELD_MESSAGE_TIMESTAMP);
}

/**
 * Returns the value of the vcid field from an ACF_CANXL message header.
 *
 * @param pdu Pointer to an ACF_CANXL message.
 * @returns The value of the vcid field.
 */
OPEN1722_INLINE uint8_t Avtp_CanXl_GetVcid(const Avtp_CanXl_t *const pdu)
{
    return (uint8_t)GET_CANXL_FIELD(AVTP_CANXL_FIELD_VCID);
}

/**
 * Returns the value of the sdt field from an ACF_CANXL message header.
 *
 * @param pdu Pointer to an ACF_CANXL message.
 * @returns The value of the sdt field.
 */
OPEN1722_INLINE uint8_t Avtp_CanXl_GetSdt(const Avtp_CanXl_t *const pdu)
{
    return (uint8_t)GET_CANXL_FIELD(AVTP_CANXL_FIELD_SDT);
}

/**
 * Returns the value of the rrs flag from an ACF_CANXL message header.
 *
 * @param pdu Pointer to an ACF_CANXL message.
 * @returns The value of the rrs flag.
 */
OPEN1722_INLINE bool Avtp_CanXl_IsRrs(const Avtp_CanXl_t *const pdu)
{
    return (bool)GET_CANXL_FIELD(AVTP_CANXL_FIELD_RRS);
}

/**
 * Returns the value of the sec flag from an ACF_CANXL message header.
 *
 * @param pdu Pointer to an ACF_CANXL message.
 * @returns The value of the sec flag.
 */
OPEN1722_INLINE bool Avtp_CanXl_IsSec(const Avtp_CanXl_t *const pdu)
{
    return (bool)GET_CANXL_FIELD(AVTP_CANXL_FIELD_SEC);
}

/**
 * Returns the value of the priority_id field from an ACF_CANXL message header.
 *
 * @param pdu Pointer to an ACF_CANXL message.
 * @returns The value of the priority_id field.
 */
OPEN1722_INLINE uint16_t Avtp_CanXl_GetPriorityId(const Avtp_CanXl_t *const pdu)
{
    return (uint16_t)GET_CANXL_FIELD(AVTP_CANXL_FIELD_PRIORITY_ID);
}

/**
 * Returns the value of the acceptance_field from an ACF_CANXL message header.
 *
 * @param pdu Pointer to an ACF_CANXL message.
 * @returns The value of the acceptance_field.
 */
OPEN1722_INLINE uint32_t Avtp_CanXl_GetAcceptanceField(const Avtp_CanXl_t *const pdu)
{
    return (uint32_t)GET_CANXL_FIELD(AVTP_CANXL_FIELD_ACCEPTANCE_FIELD);
}

/**
 * Returns the value of the transaction_num field from an ACF_CANXL message header.
 *
 * @param pdu Pointer to an ACF_CANXL message.
 * @returns The value of the transaction_num field.
 */
OPEN1722_INLINE uint8_t Avtp_CanXl_GetTransactionNum(const Avtp_CanXl_t *const pdu)
{
    return (uint8_t)GET_CANXL_FIELD(AVTP_CANXL_FIELD_TRANSACTION_NUM);
}

/**
 * Returns the value of the ms flag from an ACF_CANXL message header.
 *
 * @param pdu Pointer to an ACF_CANXL message.
 * @returns The value of the ms flag.
 */
OPEN1722_INLINE bool Avtp_CanXl_IsMs(const Avtp_CanXl_t *const pdu)
{
    return (bool)GET_CANXL_FIELD(AVTP_CANXL_FIELD_MS);
}

/**
 * Returns the value of the segment_num field from an ACF_CANXL message header.
 *
 * @param pdu Pointer to an ACF_CANXL message.
 * @returns The value of the segment_num field.
 */
OPEN1722_INLINE uint16_t Avtp_CanXl_GetSegmentNum(const Avtp_CanXl_t *const pdu)
{
    return (uint16_t)GET_CANXL_FIELD(AVTP_CANXL_FIELD_SEGMENT_NUM);
}

/**
 * Sets the value of the mtv flag in an ACF_CANXL message header.
 *
 * @param pdu Pointer to an ACF_CANXL message.
 * @param mtv The value to set.
 */
OPEN1722_INLINE void Avtp_CanXl_SetMtv(Avtp_CanXl_t *pdu, bool mtv)
{
    SET_CANXL_FIELD(AVTP_CANXL_FIELD_MTV, mtv);
}

/**
 * Sets the value of the can_bus_id field in an ACF_CANXL message header.
 *
 * @param pdu Pointer to an ACF_CANXL message.
 * @param canBusId The value to set.
 */
OPEN1722_INLINE void Avtp_CanXl_SetCanBusId(Avtp_CanXl_t *pdu, uint16_t canBusId)
{
    SET_CANXL_FIELD(AVTP_CANXL_FIELD_CAN_BUS_ID, canBusId);
}

/**
 * Sets the value of the message_timestamp field in an ACF_CANXL message header.
 *
 * @param pdu Pointer to an ACF_CANXL message.
 * @param messageTimestamp The value to set.
 */
OPEN1722_INLINE void Avtp_CanXl_SetMessageTimestamp(Avtp_CanXl_t *pdu, uint64_t messageTimestamp)
{
    SET_CANXL_FIELD(AVTP_CANXL_FIELD_MESSAGE_TIMESTAMP, messageTimestamp);
}

/**
 * Sets the value of the vcid field in an ACF_CANXL message header.
 *
 * @param pdu Pointer to an ACF_CANXL message.
 * @param vcid The value to set.
 */
OPEN1722_INLINE void Avtp_CanXl_SetVcid(Avtp_CanXl_t *pdu, uint8_t vcid)
{
    SET_CANXL_FIELD(AVTP_CANXL_FIELD_VCID, vcid);
}

/**
 * Sets the value of the sdt field in an ACF_CANXL message header.
 *
 * @param pdu Pointer to an ACF_CANXL message.
 * @param sdt The value to set.
 */
OPEN1722_INLINE void Avtp_CanXl_SetSdt(Avtp_CanXl_t *pdu, uint8_t sdt)
{
    SET_CANXL_FIELD(AVTP_CANXL_FIELD_SDT, sdt);
}

/**
 * Sets the value of the rrs flag in an ACF_CANXL message header.
 *
 * @param pdu Pointer to an ACF_CANXL message.
 * @param rrs The value to set.
 */
OPEN1722_INLINE void Avtp_CanXl_SetRrs(Avtp_CanXl_t *pdu, bool rrs)
{
    SET_CANXL_FIELD(AVTP_CANXL_FIELD_RRS, rrs);
}

/**
 * Sets the value of the sec flag in an ACF_CANXL message header.
 *
 * @param pdu Pointer to an ACF_CANXL message.
 * @param sec The value to set.
 */
OPEN1722_INLINE void Avtp_CanXl_SetSec(Avtp_CanXl_t *pdu, bool sec)
{
    SET_CANXL_FIELD(AVTP_CANXL_FIELD_SEC, sec);
}

/**
 * Sets the value of the priority_id field in an ACF_CANXL message header.
 *
 * @param pdu Pointer to an ACF_CANXL message.
 * @param priorityId The value to set.
 */
OPEN1722_INLINE void Avtp_CanXl_SetPriorityId(Avtp_CanXl_t *pdu, uint16_t priorityId)
{
    SET_CANXL_FIELD(AVTP_CANXL_FIELD_PRIORITY_ID, priorityId);
}

/**
 * Sets the value of the acceptance_field in an ACF_CANXL message header.
 *
 * @param pdu Pointer to an ACF_CANXL message.
 * @param acceptanceField The value to set.
 */
OPEN1722_INLINE void Avtp_CanXl_SetAcceptanceField(Avtp_CanXl_t *pdu, uint32_t acceptanceField)
{
    SET_CANXL_FIELD(AVTP_CANXL_FIELD_ACCEPTANCE_FIELD, acceptanceField);
}

/**
 * Sets the value of the transaction_num field in an ACF_CANXL message header.
 *
 * @param pdu Pointer to an ACF_CANXL message.
 * @param transactionNum The value to set.
 */
OPEN1722_INLINE void Avtp_CanXl_SetTransactionNum(Avtp_CanXl_t *pdu, uint8_t transactionNum)
{
    SET_CANXL_FIELD(AVTP_CANXL_FIELD_TRANSACTION_NUM, transactionNum);
}

/**
 * Sets the value of the ms flag in an ACF_CANXL message header.
 *
 * @param pdu Pointer to an ACF_CANXL message.
 * @param ms The value to set.
 */
OPEN1722_INLINE void Avtp_CanXl_SetMs(Avtp_CanXl_t *pdu, bool ms)
{
    SET_CANXL_FIELD(AVTP_CANXL_FIELD_MS, ms);
}

/**
 * Sets the value of the segment_num field in an ACF_CANXL message header.
 *
 * @param pdu Pointer to an ACF_CANXL message.
 * @param segmentNum The value to set.
 */
OPEN1722_INLINE void Avtp_CanXl_SetSegmentNum(Avtp_CanXl_t *pdu, uint16_t segmentNum)
{
    SET_CANXL_FIELD(AVTP_CANXL_FIELD_SEGMENT_NUM, segmentNum);
}

/**
 * Returns pointer to payload of an ACF CAN XL frame.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF CANXL PDU.
 * @return Pointer to ACF CAN XL frame payload
 */
OPEN1722_INLINE const uint8_t *Avtp_CanXl_GetPayload(const Avtp_CanXl_t *const pdu)
{
    return pdu->payload;
}

/**
 * Sets the CAN payload in an ACF CAN XL frame.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF CANXL PDU.
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload
 */
OPEN1722_INLINE void Avtp_CanXl_SetPayload(Avtp_CanXl_t *pdu, uint8_t *payload,
                                           uint16_t payload_length)
{
    memcpy(pdu->payload, payload, payload_length);
}

/**
 * Finalizes the ACF CAN XL frame. This function will set the
 * length and pad fields while inserting the padded bytes. This will also
 * set padding bytes to zero if the payload length is not a multiple of 4.
 * to avoid leaking information
 *
 * @param pdu Pointer to the first bit of a 1722 ACF CANXL PDU.
 * @param payload_length Length of the CAN frame payload.
 */
OPEN1722_INLINE void Avtp_CanXl_SetPayloadLength(Avtp_CanXl_t *pdu, uint16_t payload_length)
{
    uint16_t msgLenBytes = AVTP_CANXL_HEADER_LEN + payload_length;
    uint8_t pad = (uint8_t)(4 - (msgLenBytes % 4)) % 4;
    if (pad > 0) {
        memset(pdu->payload + payload_length, 0, pad);
    }
    uint16_t msgLenQuadlets = (uint16_t)((msgLenBytes + pad) / 4);
    Avtp_CanXl_SetPad(pdu, pad);
    Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)pdu, msgLenQuadlets);
}

/**
 * Returns the length of the CAN payload without the padding bytes and the
 * header length of the encapsulating ACF Frame.
 *
 * Precondition: the caller must have validated the PDU with
 * Avtp_CanXl_IsValid(). This function performs no further bounds checking
 * and assumes those invariants already hold.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF CANXL PDU.
 * @return  Length of CAN payload in bytes
 */
OPEN1722_INLINE uint8_t Avtp_CanXl_GetPayloadLength(const Avtp_CanXl_t *const pdu)
{
    uint8_t pad_length = Avtp_CanXl_GetPad(pdu);
    uint16_t acf_length_bytes =
        Avtp_AcfCommon_GetAcfMsgLengthInBytes((const Avtp_AcfCommon_t *)pdu);
    return (uint8_t)(acf_length_bytes - AVTP_CANXL_HEADER_LEN - pad_length);
}

/**
 * Initializes an ACF_CANXL message header as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF CANXL PDU.
 */
OPEN1722_INLINE void Avtp_CanXl_Init(Avtp_CanXl_t *pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_CanXl_t));
        Avtp_AcfCommon_SetAcfMsgType((Avtp_AcfCommon_t *)pdu, AVTP_ACF_TYPE_CAN_XL);
    }
}

/**
 * Copies the payload data, priority ID, acceptance field and SDT into the ACF CAN XL frame. This
 * function will also set the length and pad fields while inserting the padded bytes.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF CANXL PDU.
 * @param priority_id Priority ID
 * @param acceptance_field Acceptance field
 * @param sdt SDT value
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload.
 */
OPEN1722_INLINE void Avtp_CanXl_CreateAcfMessage(Avtp_CanXl_t *pdu, uint16_t priority_id,
                                                 uint32_t acceptance_field, uint8_t sdt,
                                                 uint8_t *payload, uint16_t payload_length)
{
    // Initialize the ACF CAN XL header
    Avtp_CanXl_Init(pdu);

    // Set the priority ID, acceptance field and SDT
    Avtp_CanXl_SetPriorityId(pdu, priority_id);
    Avtp_CanXl_SetAcceptanceField(pdu, acceptance_field);
    Avtp_CanXl_SetSdt(pdu, sdt);

    // Copy the payload into the CAN PDU
    Avtp_CanXl_SetPayload(pdu, payload, payload_length);

    // Finalize the AVTP CAN XL Frame
    Avtp_CanXl_SetPayloadLength(pdu, payload_length);
}

/**
 * Checks if the ACF CAN XL frame is valid by checking:
 *     1) if the length field of AVTP/ACF messages contains a value larger than the actual size of
 * the buffer that contains the AVTP message. 2) if other format specific invariants are not upheld
 * @param pdu Pointer to the first bit of a 1722 ACF CANXL PDU.
 * @param bufferSize Size of the buffer containing the ACF CAN XL frame.
 * @return true if the ACF CAN XL frame is valid, false otherwise.
 */
OPEN1722_INLINE bool Avtp_CanXl_IsValid(const Avtp_CanXl_t *const pdu, size_t bufferSize)
{
    if (pdu == NULL) {
        return false;
    }

    if (bufferSize < AVTP_CANXL_HEADER_LEN) {
        return false;
    }

    if (Avtp_AcfCommon_GetAcfMsgType((const Avtp_AcfCommon_t *)pdu) != AVTP_ACF_TYPE_CAN_XL) {
        return false;
    }

    uint16_t msg_length_bytes =
        Avtp_AcfCommon_GetAcfMsgLengthInBytes((const Avtp_AcfCommon_t *)pdu);
    if (msg_length_bytes > bufferSize) {
        return false;
    }

    /* The encoded message length must accommodate header + declared padding
     * so the payload computation in Avtp_CanXl_GetPayloadLength() doesn't
     * underflow. */
    uint8_t pad_length = Avtp_CanXl_GetPad(pdu);
    uint16_t header_and_pad = (uint16_t)AVTP_CANXL_HEADER_LEN + pad_length;
    if (msg_length_bytes < header_and_pad) {
        return false;
    }
    return true;
}

#ifdef __cplusplus
}
#endif
