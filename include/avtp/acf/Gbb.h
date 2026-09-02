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
 * @file This files contains functions for de-/serialization of the ACF_GBB
 * message format (Generic Byte bus). For details see IEEE Std. 1722-2025,
 * chapter 9.4.14.
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

#define GET_GBB_FIELD(field)                                                                       \
    (Avtp_GetField(Avtp_GbbFieldDesc, AVTP_GBB_FIELD_MAX, (uint8_t *)pdu, field))
#define SET_GBB_FIELD(field, value)                                                                \
    (Avtp_SetField(Avtp_GbbFieldDesc, AVTP_GBB_FIELD_MAX, (uint8_t *)pdu, field, value))

/**
 * Length of ACF_GBB message header in bytes.
 */
#define AVTP_GBB_HEADER_LEN (4 * AVTP_QUADLET_SIZE)

/**
 * ACF_GBB message structure suitable for in-place de-/serialization of fields
 * in the ACF_GBB message header.
 */
typedef struct {
    uint8_t header[AVTP_GBB_HEADER_LEN];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_Gbb_t;

/**
 * Fields encoded in the ACF_GBB header.
 */
typedef enum {
    /* ACF common header fields */
    AVTP_GBB_FIELD_ACF_MSG_TYPE = 0,
    AVTP_GBB_FIELD_ACF_MSG_LENGTH,
    /* ACF GBB header fields */
    AVTP_GBB_FIELD_PAD,
    AVTP_GBB_FIELD_MTV,
    AVTP_GBB_FIELD_BYTE_BUS_ID,
    AVTP_GBB_FIELD_MESSAGE_TIMESTAMP,
    AVTP_GBB_FIELD_EVT,
    AVTP_GBB_FIELD_HS,
    AVTP_GBB_FIELD_CS,
    AVTP_GBB_FIELD_TRANSACTION_NUM,
    AVTP_GBB_FIELD_OP,
    AVTP_GBB_FIELD_RSP,
    AVTP_GBB_FIELD_ERR,
    AVTP_GBB_FIELD_MS,
    AVTP_GBB_FIELD_READ_SIZE_SEGMENT_NUM,
    /* Count number of fields for bound checks */
    AVTP_GBB_FIELD_MAX
} Avtp_GbbFields_t;

/**
 * This table describes all the offsets of the ACF_GBB header fields.
 */
static const Avtp_FieldDescriptor_t Avtp_GbbFieldDesc[AVTP_GBB_FIELD_MAX] = {
    /* ACF common header fields */
    [AVTP_GBB_FIELD_ACF_MSG_TYPE] = {.quadlet = 0, .offset = 0, .bits = 7},
    [AVTP_GBB_FIELD_ACF_MSG_LENGTH] = {.quadlet = 0, .offset = 7, .bits = 9},
    /* ACF GBB header fields */
    [AVTP_GBB_FIELD_PAD] = {.quadlet = 0, .offset = 16, .bits = 2},
    [AVTP_GBB_FIELD_MTV] = {.quadlet = 0, .offset = 18, .bits = 1},
    [AVTP_GBB_FIELD_BYTE_BUS_ID] = {.quadlet = 0, .offset = 21, .bits = 11},
    [AVTP_GBB_FIELD_MESSAGE_TIMESTAMP] = {.quadlet = 1, .offset = 0, .bits = 64},
    [AVTP_GBB_FIELD_EVT] = {.quadlet = 3, .offset = 0, .bits = 4},
    [AVTP_GBB_FIELD_HS] = {.quadlet = 3, .offset = 6, .bits = 1},
    [AVTP_GBB_FIELD_CS] = {.quadlet = 3, .offset = 7, .bits = 1},
    [AVTP_GBB_FIELD_TRANSACTION_NUM] = {.quadlet = 3, .offset = 8, .bits = 8},
    [AVTP_GBB_FIELD_OP] = {.quadlet = 3, .offset = 16, .bits = 1},
    [AVTP_GBB_FIELD_RSP] = {.quadlet = 3, .offset = 17, .bits = 1},
    [AVTP_GBB_FIELD_ERR] = {.quadlet = 3, .offset = 18, .bits = 1},
    [AVTP_GBB_FIELD_MS] = {.quadlet = 3, .offset = 19, .bits = 1},
    [AVTP_GBB_FIELD_READ_SIZE_SEGMENT_NUM] = {.quadlet = 3, .offset = 20, .bits = 12},
};

/**
 * Return the value of the ACF message length field as specified in the IEEE 1722 Specification.
 * This returns the length in Quadlets as specified in the IEEE 1722 Specification.
 *
 * You can use Avtp_Gbb_GetPayloadLength to get the length in bytes without padding.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF GBB PDU.
 * @returns Value of the ACF message length field.
 */
OPEN1722_INLINE uint16_t Avtp_Gbb_GetAcfMsgLength(const Avtp_Gbb_t *const pdu)
{
    return Avtp_AcfCommon_GetAcfMsgLength((const Avtp_AcfCommon_t *)pdu);
}

/**
 * Return the ACF message length in bytes.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF GBB PDU.
 * @returns Length of the ACF message in bytes.
 */
OPEN1722_INLINE uint16_t Avtp_Gbb_GetAcfMsgLengthInBytes(const Avtp_Gbb_t *const pdu)
{
    return (uint16_t)Avtp_AcfCommon_GetAcfMsgLength((const Avtp_AcfCommon_t *)pdu) * 4;
}

/**
 * Set the value of the ACF message length field as specified in the IEEE 1722 Specification.
 * Note: the size is in Quadlets as specified in the IEEE 1722 Specification.
 * You can use Avtp_Gbb_SetPayloadLength to set length in bytes and automatically set the
 * correct padding.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF GBB PDU.
 * @param value Value to set the ACF message length field to.
 */
OPEN1722_INLINE void Avtp_Gbb_SetAcfMsgLength(Avtp_Gbb_t *pdu, uint16_t value)
{
    Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)pdu, value);
}

/**
 * Returns the pad field from an ACF_GBB message header.
 *
 * @param pdu Pointer to an ACF_GBB message.
 * @returns The value of the pad field.
 */
OPEN1722_INLINE uint8_t Avtp_Gbb_GetPad(const Avtp_Gbb_t *const pdu)
{
    return (uint8_t)GET_GBB_FIELD(AVTP_GBB_FIELD_PAD);
}

/**
 * Sets the pad field in an ACF_GBB message header.
 *
 * @param pdu Pointer to an ACF_GBB message.
 * @param pad The value to set.
 */
OPEN1722_INLINE void Avtp_Gbb_SetPad(Avtp_Gbb_t *pdu, uint8_t pad)
{
    SET_GBB_FIELD(AVTP_GBB_FIELD_PAD, pad);
}

/**
 * Returns the message timestamp valid flag (mtv) from an ACF_GBB message header.
 *
 * @param pdu Pointer to an ACF_GBB message.
 * @returns The value of the mtv flag.
 */
OPEN1722_INLINE bool Avtp_Gbb_IsMtv(const Avtp_Gbb_t *const pdu)
{
    return (bool)GET_GBB_FIELD(AVTP_GBB_FIELD_MTV);
}

/**
 * Returns the value of the byte_bus_id field from an ACF_GBB message header.
 *
 * @param pdu Pointer to an ACF_GBB message.
 * @returns The value of the byte_bus_id field.
 */
OPEN1722_INLINE uint16_t Avtp_Gbb_GetByteBusId(const Avtp_Gbb_t *const pdu)
{
    return (uint16_t)GET_GBB_FIELD(AVTP_GBB_FIELD_BYTE_BUS_ID);
}

/**
 * Returns the value of the message_timestamp field from an ACF_GBB message header.
 *
 * @param pdu Pointer to an ACF_GBB message.
 * @returns The value of the message_timestamp field.
 */
OPEN1722_INLINE uint64_t Avtp_Gbb_GetMessageTimestamp(const Avtp_Gbb_t *const pdu)
{
    return (uint64_t)GET_GBB_FIELD(AVTP_GBB_FIELD_MESSAGE_TIMESTAMP);
}

/**
 * Returns the value of the evt field from an ACF_GBB message header.
 *
 * @param pdu Pointer to an ACF_GBB message.
 * @returns The value of the evt field.
 */
OPEN1722_INLINE uint8_t Avtp_Gbb_GetEvt(const Avtp_Gbb_t *const pdu)
{
    return (uint8_t)GET_GBB_FIELD(AVTP_GBB_FIELD_EVT);
}

/**
 * Returns the value of the hs field from an ACF_GBB message header.
 *
 * @param pdu Pointer to an ACF_GBB message.
 * @returns The value of the hs field.
 */
OPEN1722_INLINE bool Avtp_Gbb_IsHs(const Avtp_Gbb_t *const pdu)
{
    return (bool)GET_GBB_FIELD(AVTP_GBB_FIELD_HS);
}

/**
 * Returns the value of the cs field from an ACF_GBB message header.
 *
 * @param pdu Pointer to an ACF_GBB message.
 * @returns The value of the cs field.
 */
OPEN1722_INLINE bool Avtp_Gbb_IsCs(const Avtp_Gbb_t *const pdu)
{
    return (bool)GET_GBB_FIELD(AVTP_GBB_FIELD_CS);
}

/**
 * Returns the value of the transaction_num field from an ACF_GBB message header.
 *
 * @param pdu Pointer to an ACF_GBB message.
 * @returns The value of the transaction_num field.
 */
OPEN1722_INLINE uint8_t Avtp_Gbb_GetTransactionNum(const Avtp_Gbb_t *const pdu)
{
    return (uint8_t)GET_GBB_FIELD(AVTP_GBB_FIELD_TRANSACTION_NUM);
}

/**
 * Returns the value of the op flag from an ACF_GBB message header.
 *
 * @param pdu Pointer to an ACF_GBB message.
 * @returns The value of the op flag.
 */
OPEN1722_INLINE bool Avtp_Gbb_IsOp(const Avtp_Gbb_t *const pdu)
{
    return (bool)GET_GBB_FIELD(AVTP_GBB_FIELD_OP);
}

/**
 * Returns the value of the rsp flag from an ACF_GBB message header.
 *
 * @param pdu Pointer to an ACF_GBB message.
 * @returns The value of the rsp flag.
 */
OPEN1722_INLINE bool Avtp_Gbb_IsRsp(const Avtp_Gbb_t *const pdu)
{
    return (bool)GET_GBB_FIELD(AVTP_GBB_FIELD_RSP);
}

/**
 * Returns the value of the err flag from an ACF_GBB message header.
 *
 * @param pdu Pointer to an ACF_GBB message.
 * @returns The value of the err flag.
 */
OPEN1722_INLINE bool Avtp_Gbb_IsErr(const Avtp_Gbb_t *const pdu)
{
    return (bool)GET_GBB_FIELD(AVTP_GBB_FIELD_ERR);
}

/**
 * Returns the value of the ms flag from an ACF_GBB message header.
 *
 * @param pdu Pointer to an ACF_GBB message.
 * @returns The value of the ms flag.
 */
OPEN1722_INLINE bool Avtp_Gbb_IsMs(const Avtp_Gbb_t *const pdu)
{
    return (bool)GET_GBB_FIELD(AVTP_GBB_FIELD_MS);
}

/**
 * Returns the value of the read_size/segment_num field from an ACF_GBB message header.
 *
 * @param pdu Pointer to an ACF_GBB message.
 * @returns The value of the read_size/segment_num field.
 */
OPEN1722_INLINE uint16_t Avtp_Gbb_GetReadSize(const Avtp_Gbb_t *const pdu)
{
    return (uint16_t)GET_GBB_FIELD(AVTP_GBB_FIELD_READ_SIZE_SEGMENT_NUM);
}

/**
 * Returns the value of the read_size/segment_num field from an ACF_GBB message header.
 *
 * @param pdu Pointer to an ACF_GBB message.
 * @returns The value of the read_size/segment_num field.
 */
OPEN1722_INLINE uint16_t Avtp_Gbb_GetSegmentNum(const Avtp_Gbb_t *const pdu)
{
    return (uint16_t)GET_GBB_FIELD(AVTP_GBB_FIELD_READ_SIZE_SEGMENT_NUM);
}

/**
 * Sets the value of the mtv flag in an ACF_GBB message header.
 *
 * @param pdu Pointer to an ACF_GBB message.
 * @param mtv The value to set.
 */
OPEN1722_INLINE void Avtp_Gbb_SetMtv(Avtp_Gbb_t *pdu, bool mtv)
{
    SET_GBB_FIELD(AVTP_GBB_FIELD_MTV, mtv);
}

/**
 * Sets the value of the byte_bus_id field in an ACF_GBB message header.
 *
 * @param pdu Pointer to an ACF_GBB message.
 * @param byteBusId The value to set.
 */
OPEN1722_INLINE void Avtp_Gbb_SetByteBusId(Avtp_Gbb_t *pdu, uint16_t byteBusId)
{
    SET_GBB_FIELD(AVTP_GBB_FIELD_BYTE_BUS_ID, byteBusId);
}

/**
 * Sets the value of the message_timestamp field in an ACF_GBB message header.
 *
 * @param pdu Pointer to an ACF_GBB message.
 * @param messageTimestamp The value to set.
 */
OPEN1722_INLINE void Avtp_Gbb_SetMessageTimestamp(Avtp_Gbb_t *pdu, uint64_t messageTimestamp)
{
    SET_GBB_FIELD(AVTP_GBB_FIELD_MESSAGE_TIMESTAMP, messageTimestamp);
}

/**
 * Sets the value of the evt field in an ACF_GBB message header.
 *
 * @param pdu Pointer to an ACF_GBB message.
 * @param evt The value to set.
 */
OPEN1722_INLINE void Avtp_Gbb_SetEvt(Avtp_Gbb_t *pdu, uint8_t evt)
{
    SET_GBB_FIELD(AVTP_GBB_FIELD_EVT, evt);
}

/**
 * Sets the value of the hs flag in an ACF_GBB message header.
 *
 * @param pdu Pointer to an ACF_GBB message.
 * @param hs The value to set.
 */
OPEN1722_INLINE void Avtp_Gbb_SetHs(Avtp_Gbb_t *pdu, bool hs)
{
    SET_GBB_FIELD(AVTP_GBB_FIELD_HS, hs);
}

/**
 * Sets the value of the cs flag in an ACF_GBB message header.
 *
 * @param pdu Pointer to an ACF_GBB message.
 * @param cs The value to set.
 */
OPEN1722_INLINE void Avtp_Gbb_SetCs(Avtp_Gbb_t *pdu, bool cs)
{
    SET_GBB_FIELD(AVTP_GBB_FIELD_CS, cs);
}

/**
 * Sets the value of the transaction_num field in an ACF_GBB message header.
 *
 * @param pdu Pointer to an ACF_GBB message.
 * @param transactionNum The value to set.
 */
OPEN1722_INLINE void Avtp_Gbb_SetTransactionNum(Avtp_Gbb_t *pdu, uint8_t transactionNum)
{
    SET_GBB_FIELD(AVTP_GBB_FIELD_TRANSACTION_NUM, transactionNum);
}

/**
 * Sets the value of the op flag in an ACF_GBB message header.
 *
 * @param pdu Pointer to an ACF_GBB message.
 * @param op The value to set.
 */
OPEN1722_INLINE void Avtp_Gbb_SetOp(Avtp_Gbb_t *pdu, bool op)
{
    SET_GBB_FIELD(AVTP_GBB_FIELD_OP, op);
}

/**
 * Sets the value of the rsp flag in an ACF_GBB message header.
 *
 * @param pdu Pointer to an ACF_GBB message.
 * @param rsp The value to set.
 */
OPEN1722_INLINE void Avtp_Gbb_SetRsp(Avtp_Gbb_t *pdu, bool rsp)
{
    SET_GBB_FIELD(AVTP_GBB_FIELD_RSP, rsp);
}

/**
 * Sets the value of the err flag in an ACF_GBB message header.
 *
 * @param pdu Pointer to an ACF_GBB message.
 * @param err The value to set.
 */
OPEN1722_INLINE void Avtp_Gbb_SetErr(Avtp_Gbb_t *pdu, bool err)
{
    SET_GBB_FIELD(AVTP_GBB_FIELD_ERR, err);
}

/**
 * Sets the value of the ms flag in an ACF_GBB message header.
 *
 * @param pdu Pointer to an ACF_GBB message.
 * @param ms The value to set.
 */
OPEN1722_INLINE void Avtp_Gbb_SetMs(Avtp_Gbb_t *pdu, bool ms)
{
    SET_GBB_FIELD(AVTP_GBB_FIELD_MS, ms);
}

/**
 * Sets the value of the read_size/segment_num field in an ACF_GBB message header.
 *
 * @param pdu Pointer to an ACF_GBB message.
 * @param readSize The value to set.
 */
OPEN1722_INLINE void Avtp_Gbb_SetReadSize(Avtp_Gbb_t *pdu, uint16_t readSize)
{
    SET_GBB_FIELD(AVTP_GBB_FIELD_READ_SIZE_SEGMENT_NUM, readSize);
}

/**
 * Sets the value of the read_size/segment_num field in an ACF_GBB message header.
 *
 * @param pdu Pointer to an ACF_GBB message.
 * @param segmentNum The value to set.
 */
OPEN1722_INLINE void Avtp_Gbb_SetSegmentNum(Avtp_Gbb_t *pdu, uint16_t segmentNum)
{
    SET_GBB_FIELD(AVTP_GBB_FIELD_READ_SIZE_SEGMENT_NUM, segmentNum);
}

/**
 * Returns pointer to payload of an ACF GBB frame.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF GBB PDU.
 * @return Pointer to ACF GBB frame payload
 */
OPEN1722_INLINE const uint8_t *Avtp_Gbb_GetPayload(const Avtp_Gbb_t *const pdu)
{
    return pdu->payload;
}

/**
 * Sets the payload in an ACF GBB frame.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF GBB PDU.
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload
 */
OPEN1722_INLINE void Avtp_Gbb_SetPayload(Avtp_Gbb_t *pdu, uint8_t *payload, uint16_t payload_length)
{
    memcpy(pdu->payload, payload, payload_length);
}

/**
 * Finalizes the ACF GBB frame. This function will set the
 * length and pad fields while inserting the padded bytes. This will also
 * set padding bytes to zero if the payload length is not a multiple of 4.
 * to avoid leaking information
 *
 * @param pdu Pointer to the first bit of a 1722 ACF GBB PDU.
 * @param payload_length Length of the frame payload.
 */
OPEN1722_INLINE void Avtp_Gbb_SetPayloadLength(Avtp_Gbb_t *pdu, uint16_t payload_length)
{
    uint16_t msgLenBytes = AVTP_GBB_HEADER_LEN + payload_length;
    uint8_t pad = (uint8_t)(4 - (msgLenBytes % 4)) % 4;
    if (pad > 0) {
        memset(pdu->payload + payload_length, 0, pad);
    }
    uint16_t msgLenQuadlets = (uint16_t)((msgLenBytes + pad) / 4);
    Avtp_Gbb_SetPad(pdu, pad);
    Avtp_Gbb_SetAcfMsgLength(pdu, msgLenQuadlets);
}

/**
 * Returns the length of the payload without the padding bytes and the
 * header length of the encapsulating ACF Frame.
 *
 * Precondition: the caller must have validated the PDU with
 * Avtp_Gbb_IsValid(). This function performs no further bounds checking
 * and assumes those invariants already hold.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF GBB PDU.
 * @return  Length of payload in bytes
 */
OPEN1722_INLINE uint8_t Avtp_Gbb_GetPayloadLength(const Avtp_Gbb_t *const pdu)
{
    uint8_t pad_length = Avtp_Gbb_GetPad(pdu);
    uint16_t acf_length_bytes = Avtp_Gbb_GetAcfMsgLengthInBytes(pdu);
    return (uint8_t)(acf_length_bytes - AVTP_GBB_HEADER_LEN - pad_length);
}

/**
 * Initializes an ACF_GBB message header as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF GBB PDU.
 */
OPEN1722_INLINE void Avtp_Gbb_Init(Avtp_Gbb_t *pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_Gbb_t));
        Avtp_AcfCommon_SetAcfMsgType((Avtp_AcfCommon_t *)pdu, AVTP_ACF_TYPE_BYTE_BUS);
    }
}

/**
 * Copies the payload data, byte bus ID, op flag and transaction number into the ACF GBB frame.
 * This function will also set the length and pad fields while inserting the padded bytes.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF GBB PDU.
 * @param byte_bus_id Byte bus ID
 * @param op Operation flag
 * @param transaction_num Transaction number
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload.
 */
OPEN1722_INLINE void Avtp_Gbb_CreateAcfMessage(Avtp_Gbb_t *pdu, uint16_t byte_bus_id, bool op,
                                               uint8_t transaction_num, uint8_t *payload,
                                               uint16_t payload_length)
{
    // Initialize the ACF GBB header
    Avtp_Gbb_Init(pdu);

    // Set the byte bus ID, op flag and transaction number
    Avtp_Gbb_SetByteBusId(pdu, byte_bus_id);
    Avtp_Gbb_SetOp(pdu, op);
    Avtp_Gbb_SetTransactionNum(pdu, transaction_num);

    // Copy the payload into the PDU
    Avtp_Gbb_SetPayload(pdu, payload, payload_length);

    // Finalize the AVTP GBB Frame
    Avtp_Gbb_SetPayloadLength(pdu, payload_length);
}

/**
 * Checks if the ACF GBB frame is valid by checking:
 *     1) if the length field of AVTP/ACF messages contains a value larger than the actual size of
 * the buffer that contains the AVTP message. 2) if other format specific invariants are not upheld
 * @param pdu Pointer to the first bit of a 1722 ACF GBB PDU.
 * @param bufferSize Size of the buffer containing the ACF GBB frame.
 * @return true if the ACF GBB frame is valid, false otherwise.
 */
OPEN1722_INLINE bool Avtp_Gbb_IsValid(const Avtp_Gbb_t *const pdu, size_t bufferSize)
{
    if (pdu == NULL) {
        return false;
    }

    if (bufferSize < AVTP_GBB_HEADER_LEN) {
        return false;
    }

    if (Avtp_AcfCommon_GetAcfMsgType((const Avtp_AcfCommon_t *)pdu) != AVTP_ACF_TYPE_BYTE_BUS) {
        return false;
    }

    // Avtp_Gbb_GetAcfMsgLength returns quadlets. Convert the length field to octets.
    uint16_t msg_length_bytes = (uint16_t)Avtp_Gbb_GetAcfMsgLength(pdu) * 4;
    if (msg_length_bytes > bufferSize) {
        return false;
    }

    /* The encoded message length must accommodate header + declared padding
     * so the payload computation in Avtp_Gbb_GetPayloadLength() doesn't
     * underflow. */
    uint8_t pad_length = Avtp_Gbb_GetPad(pdu);
    uint16_t header_and_pad = (uint16_t)AVTP_GBB_HEADER_LEN + pad_length;
    if (msg_length_bytes < header_and_pad) {
        return false;
    }
    return true;
}

#ifdef __cplusplus
}
#endif
