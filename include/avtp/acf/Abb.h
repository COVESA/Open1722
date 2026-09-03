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
 * @file This files contains functions for de-/serialization of the ACF_ABB
 * message format (Abbreviated Byte bus). For details see IEEE Std. 1722-2025,
 * chapter 9.4.15.
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

#define GET_ABB_FIELD(field)                                                                       \
    (Avtp_GetField(Avtp_AbbFieldDesc, AVTP_ABB_FIELD_MAX, (const uint8_t *)pdu, field))
#define SET_ABB_FIELD(field, value)                                                                \
    (Avtp_SetField(Avtp_AbbFieldDesc, AVTP_ABB_FIELD_MAX, (uint8_t *)pdu, field, value))

/**
 * Length of ACF_ABB message header in bytes.
 */
#define AVTP_ABB_HEADER_LEN (2 * AVTP_QUADLET_SIZE)

/**
 * ACF_ABB message structure suitable for in-place de-/serialization of fields
 * in the ACF_ABB message header.
 */
typedef struct {
    uint8_t header[AVTP_ABB_HEADER_LEN];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_Abb_t;

/**
 * Fields encoded in the ACF_ABB header.
 */
typedef enum {
    /* ACF common header fields */
    AVTP_ABB_FIELD_ACF_MSG_TYPE = 0,
    AVTP_ABB_FIELD_ACF_MSG_LENGTH,
    /* ACF ABB header fields */
    AVTP_ABB_FIELD_PAD,
    AVTP_ABB_FIELD_MTV,
    AVTP_ABB_FIELD_BYTE_BUS_ID,
    AVTP_ABB_FIELD_EVT,
    AVTP_ABB_FIELD_HS,
    AVTP_ABB_FIELD_CS,
    AVTP_ABB_FIELD_TRANSACTION_NUM,
    AVTP_ABB_FIELD_OP,
    AVTP_ABB_FIELD_RSP,
    AVTP_ABB_FIELD_ERR,
    AVTP_ABB_FIELD_MS,
    AVTP_ABB_FIELD_READ_SIZE_SEGMENT_NUM,
    /* Count number of fields for bound checks */
    AVTP_ABB_FIELD_MAX
} Avtp_AbbFields_t;

/**
 * This table describes all the offsets of the ACF_ABB header fields.
 */
static const Avtp_FieldDescriptor_t Avtp_AbbFieldDesc[AVTP_ABB_FIELD_MAX] = {
    /* ACF common header fields */
    [AVTP_ABB_FIELD_ACF_MSG_TYPE] = {.quadlet = 0, .offset = 0, .bits = 7},
    [AVTP_ABB_FIELD_ACF_MSG_LENGTH] = {.quadlet = 0, .offset = 7, .bits = 9},
    /* ACF ABB header fields */
    [AVTP_ABB_FIELD_PAD] = {.quadlet = 0, .offset = 16, .bits = 2},
    [AVTP_ABB_FIELD_MTV] = {.quadlet = 0, .offset = 18, .bits = 1},
    [AVTP_ABB_FIELD_BYTE_BUS_ID] = {.quadlet = 0, .offset = 21, .bits = 11},
    [AVTP_ABB_FIELD_EVT] = {.quadlet = 1, .offset = 0, .bits = 4},
    [AVTP_ABB_FIELD_HS] = {.quadlet = 1, .offset = 6, .bits = 1},
    [AVTP_ABB_FIELD_CS] = {.quadlet = 1, .offset = 7, .bits = 1},
    [AVTP_ABB_FIELD_TRANSACTION_NUM] = {.quadlet = 1, .offset = 8, .bits = 8},
    [AVTP_ABB_FIELD_OP] = {.quadlet = 1, .offset = 16, .bits = 1},
    [AVTP_ABB_FIELD_RSP] = {.quadlet = 1, .offset = 17, .bits = 1},
    [AVTP_ABB_FIELD_ERR] = {.quadlet = 1, .offset = 18, .bits = 1},
    [AVTP_ABB_FIELD_MS] = {.quadlet = 1, .offset = 19, .bits = 1},
    [AVTP_ABB_FIELD_READ_SIZE_SEGMENT_NUM] = {.quadlet = 1, .offset = 20, .bits = 12},
};

/**
 * Returns the pad field from an ACF_ABB message header.
 *
 * @param pdu Pointer to an ACF_ABB message.
 * @returns The value of the pad field.
 */
OPEN1722_INLINE uint8_t Avtp_Abb_GetPad(const Avtp_Abb_t *const pdu)
{
    return (uint8_t)GET_ABB_FIELD(AVTP_ABB_FIELD_PAD);
}

/**
 * Sets the pad field in an ACF_ABB message header.
 *
 * @param pdu Pointer to an ACF_ABB message.
 * @param pad The value to set.
 */
OPEN1722_INLINE void Avtp_Abb_SetPad(Avtp_Abb_t *pdu, uint8_t pad)
{
    SET_ABB_FIELD(AVTP_ABB_FIELD_PAD, pad);
}

/**
 * Returns the message timestamp valid flag (mtv) from an ACF_ABB message header.
 *
 * @param pdu Pointer to an ACF_ABB message.
 * @returns The value of the mtv flag.
 */
OPEN1722_INLINE bool Avtp_Abb_IsMtv(const Avtp_Abb_t *const pdu)
{
    return (bool)GET_ABB_FIELD(AVTP_ABB_FIELD_MTV);
}

/**
 * Returns the value of the byte_bus_id field from an ACF_ABB message header.
 *
 * @param pdu Pointer to an ACF_ABB message.
 * @returns The value of the byte_bus_id field.
 */
OPEN1722_INLINE uint16_t Avtp_Abb_GetByteBusId(const Avtp_Abb_t *const pdu)
{
    return (uint16_t)GET_ABB_FIELD(AVTP_ABB_FIELD_BYTE_BUS_ID);
}

/**
 * Returns the value of the evt field from an ACF_ABB message header.
 *
 * @param pdu Pointer to an ACF_ABB message.
 * @returns The value of the evt field.
 */
OPEN1722_INLINE uint8_t Avtp_Abb_GetEvt(const Avtp_Abb_t *const pdu)
{
    return (uint8_t)GET_ABB_FIELD(AVTP_ABB_FIELD_EVT);
}

/**
 * Returns the value of the hs field from an ACF_ABB message header.
 *
 * @param pdu Pointer to an ACF_ABB message.
 * @returns The value of the hs field.
 */
OPEN1722_INLINE bool Avtp_Abb_IsHs(const Avtp_Abb_t *const pdu)
{
    return (bool)GET_ABB_FIELD(AVTP_ABB_FIELD_HS);
}

/**
 * Returns the value of the cs field from an ACF_ABB message header.
 *
 * @param pdu Pointer to an ACF_ABB message.
 * @returns The value of the cs field.
 */
OPEN1722_INLINE bool Avtp_Abb_IsCs(const Avtp_Abb_t *const pdu)
{
    return (bool)GET_ABB_FIELD(AVTP_ABB_FIELD_CS);
}

/**
 * Returns the value of the transaction_num field from an ACF_ABB message header.
 *
 * @param pdu Pointer to an ACF_ABB message.
 * @returns The value of the transaction_num field.
 */
OPEN1722_INLINE uint8_t Avtp_Abb_GetTransactionNum(const Avtp_Abb_t *const pdu)
{
    return (uint8_t)GET_ABB_FIELD(AVTP_ABB_FIELD_TRANSACTION_NUM);
}

/**
 * Returns the value of the op flag from an ACF_ABB message header.
 *
 * @param pdu Pointer to an ACF_ABB message.
 * @returns The value of the op flag.
 */
OPEN1722_INLINE bool Avtp_Abb_IsOp(const Avtp_Abb_t *const pdu)
{
    return (bool)GET_ABB_FIELD(AVTP_ABB_FIELD_OP);
}

/**
 * Returns the value of the rsp flag from an ACF_ABB message header.
 *
 * @param pdu Pointer to an ACF_ABB message.
 * @returns The value of the rsp flag.
 */
OPEN1722_INLINE bool Avtp_Abb_IsRsp(const Avtp_Abb_t *const pdu)
{
    return (bool)GET_ABB_FIELD(AVTP_ABB_FIELD_RSP);
}

/**
 * Returns the value of the err flag from an ACF_ABB message header.
 *
 * @param pdu Pointer to an ACF_ABB message.
 * @returns The value of the err flag.
 */
OPEN1722_INLINE bool Avtp_Abb_IsErr(const Avtp_Abb_t *const pdu)
{
    return (bool)GET_ABB_FIELD(AVTP_ABB_FIELD_ERR);
}

/**
 * Returns the value of the ms flag from an ACF_ABB message header.
 *
 * @param pdu Pointer to an ACF_ABB message.
 * @returns The value of the ms flag.
 */
OPEN1722_INLINE bool Avtp_Abb_IsMs(const Avtp_Abb_t *const pdu)
{
    return (bool)GET_ABB_FIELD(AVTP_ABB_FIELD_MS);
}

/**
 * Returns the value of the read_size/segment_num field from an ACF_ABB message header.
 *
 * @param pdu Pointer to an ACF_ABB message.
 * @returns The value of the read_size/segment_num field.
 */
OPEN1722_INLINE uint16_t Avtp_Abb_GetReadSize(const Avtp_Abb_t *const pdu)
{
    return (uint16_t)GET_ABB_FIELD(AVTP_ABB_FIELD_READ_SIZE_SEGMENT_NUM);
}

/**
 * Returns the value of the read_size/segment_num field from an ACF_ABB message header.
 *
 * @param pdu Pointer to an ACF_ABB message.
 * @returns The value of the read_size/segment_num field.
 */
OPEN1722_INLINE uint16_t Avtp_Abb_GetSegmentNum(const Avtp_Abb_t *const pdu)
{
    return (uint16_t)GET_ABB_FIELD(AVTP_ABB_FIELD_READ_SIZE_SEGMENT_NUM);
}

/**
 * Sets the value of the mtv flag in an ACF_ABB message header.
 *
 * @param pdu Pointer to an ACF_ABB message.
 * @param mtv The value to set.
 */
OPEN1722_INLINE void Avtp_Abb_SetMtv(Avtp_Abb_t *pdu, bool mtv)
{
    SET_ABB_FIELD(AVTP_ABB_FIELD_MTV, mtv);
}

/**
 * Sets the value of the byte_bus_id field in an ACF_ABB message header.
 *
 * @param pdu Pointer to an ACF_ABB message.
 * @param byteBusId The value to set.
 */
OPEN1722_INLINE void Avtp_Abb_SetByteBusId(Avtp_Abb_t *pdu, uint16_t byteBusId)
{
    SET_ABB_FIELD(AVTP_ABB_FIELD_BYTE_BUS_ID, byteBusId);
}

/**
 * Sets the value of the evt field in an ACF_ABB message header.
 *
 * @param pdu Pointer to an ACF_ABB message.
 * @param evt The value to set.
 */
OPEN1722_INLINE void Avtp_Abb_SetEvt(Avtp_Abb_t *pdu, uint8_t evt)
{
    SET_ABB_FIELD(AVTP_ABB_FIELD_EVT, evt);
}

/**
 * Sets the value of the hs flag in an ACF_ABB message header.
 *
 * @param pdu Pointer to an ACF_ABB message.
 * @param hs The value to set.
 */
OPEN1722_INLINE void Avtp_Abb_SetHs(Avtp_Abb_t *pdu, bool hs)
{
    SET_ABB_FIELD(AVTP_ABB_FIELD_HS, hs);
}

/**
 * Sets the value of the cs flag in an ACF_ABB message header.
 *
 * @param pdu Pointer to an ACF_ABB message.
 * @param cs The value to set.
 */
OPEN1722_INLINE void Avtp_Abb_SetCs(Avtp_Abb_t *pdu, bool cs)
{
    SET_ABB_FIELD(AVTP_ABB_FIELD_CS, cs);
}

/**
 * Sets the value of the transaction_num field in an ACF_ABB message header.
 *
 * @param pdu Pointer to an ACF_ABB message.
 * @param transactionNum The value to set.
 */
OPEN1722_INLINE void Avtp_Abb_SetTransactionNum(Avtp_Abb_t *pdu, uint8_t transactionNum)
{
    SET_ABB_FIELD(AVTP_ABB_FIELD_TRANSACTION_NUM, transactionNum);
}

/**
 * Sets the value of the op flag in an ACF_ABB message header.
 *
 * @param pdu Pointer to an ACF_ABB message.
 * @param op The value to set.
 */
OPEN1722_INLINE void Avtp_Abb_SetOp(Avtp_Abb_t *pdu, bool op)
{
    SET_ABB_FIELD(AVTP_ABB_FIELD_OP, op);
}

/**
 * Sets the value of the rsp flag in an ACF_ABB message header.
 *
 * @param pdu Pointer to an ACF_ABB message.
 * @param rsp The value to set.
 */
OPEN1722_INLINE void Avtp_Abb_SetRsp(Avtp_Abb_t *pdu, bool rsp)
{
    SET_ABB_FIELD(AVTP_ABB_FIELD_RSP, rsp);
}

/**
 * Sets the value of the err flag in an ACF_ABB message header.
 *
 * @param pdu Pointer to an ACF_ABB message.
 * @param err The value to set.
 */
OPEN1722_INLINE void Avtp_Abb_SetErr(Avtp_Abb_t *pdu, bool err)
{
    SET_ABB_FIELD(AVTP_ABB_FIELD_ERR, err);
}

/**
 * Sets the value of the ms flag in an ACF_ABB message header.
 *
 * @param pdu Pointer to an ACF_ABB message.
 * @param ms The value to set.
 */
OPEN1722_INLINE void Avtp_Abb_SetMs(Avtp_Abb_t *pdu, bool ms)
{
    SET_ABB_FIELD(AVTP_ABB_FIELD_MS, ms);
}

/**
 * Sets the value of the read_size/segment_num field in an ACF_ABB message header.
 *
 * @param pdu Pointer to an ACF_ABB message.
 * @param readSize The value to set.
 */
OPEN1722_INLINE void Avtp_Abb_SetReadSize(Avtp_Abb_t *pdu, uint16_t readSize)
{
    SET_ABB_FIELD(AVTP_ABB_FIELD_READ_SIZE_SEGMENT_NUM, readSize);
}

/**
 * Sets the value of the read_size/segment_num field in an ACF_ABB message header.
 *
 * @param pdu Pointer to an ACF_ABB message.
 * @param segmentNum The value to set.
 */
OPEN1722_INLINE void Avtp_Abb_SetSegmentNum(Avtp_Abb_t *pdu, uint16_t segmentNum)
{
    SET_ABB_FIELD(AVTP_ABB_FIELD_READ_SIZE_SEGMENT_NUM, segmentNum);
}

/**
 * Returns pointer to payload of an ACF ABB frame.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF ABB PDU.
 * @return Pointer to ACF ABB frame payload
 */
OPEN1722_INLINE const uint8_t *Avtp_Abb_GetPayload(const Avtp_Abb_t *const pdu)
{
    return pdu->payload;
}

/**
 * Sets the payload in an ACF ABB frame.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF ABB PDU.
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload
 */
OPEN1722_INLINE void Avtp_Abb_SetPayload(Avtp_Abb_t *pdu, uint8_t *payload, uint16_t payload_length)
{
    memcpy(pdu->payload, payload, payload_length);
}

/**
 * Finalizes the ACF ABB frame. This function will set the
 * length and pad fields while inserting the padded bytes. This will also
 * set padding bytes to zero if the payload length is not a multiple of 4.
 * to avoid leaking information
 *
 * @param pdu Pointer to the first bit of a 1722 ACF ABB PDU.
 * @param payload_length Length of the frame payload.
 */
OPEN1722_INLINE void Avtp_Abb_SetPayloadLength(Avtp_Abb_t *pdu, uint16_t payload_length)
{
    uint16_t msgLenBytes = AVTP_ABB_HEADER_LEN + payload_length;
    uint8_t pad = (uint8_t)(4 - (msgLenBytes % 4)) % 4;
    if (pad > 0) {
        memset(pdu->payload + payload_length, 0, pad);
    }
    uint16_t msgLenQuadlets = (uint16_t)((msgLenBytes + pad) / 4);
    Avtp_Abb_SetPad(pdu, pad);
    Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)pdu, msgLenQuadlets);
}

/**
 * Returns the length of the payload without the padding bytes and the
 * header length of the encapsulating ACF Frame.
 *
 * Precondition: the caller must have validated the PDU with
 * Avtp_Abb_IsValid(). This function performs no further bounds checking
 * and assumes those invariants already hold.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF ABB PDU.
 * @return  Length of payload in bytes
 */
OPEN1722_INLINE uint8_t Avtp_Abb_GetPayloadLength(const Avtp_Abb_t *const pdu)
{
    uint8_t pad_length = Avtp_Abb_GetPad(pdu);
    uint16_t acf_length_bytes =
        Avtp_AcfCommon_GetAcfMsgLengthInBytes((const Avtp_AcfCommon_t *)pdu);
    return (uint8_t)(acf_length_bytes - AVTP_ABB_HEADER_LEN - pad_length);
}

/**
 * Initializes an ACF_ABB message header as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF ABB PDU.
 */
OPEN1722_INLINE void Avtp_Abb_Init(Avtp_Abb_t *pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_Abb_t));
        Avtp_AcfCommon_SetAcfMsgType((Avtp_AcfCommon_t *)pdu, AVTP_ACF_TYPE_BYTE_BUS_BRIEF);
    }
}

/**
 * Copies the payload data, byte bus ID, op flag and transaction number into the ACF ABB frame.
 * This function will also set the length and pad fields while inserting the padded bytes.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF ABB PDU.
 * @param byte_bus_id Byte bus ID
 * @param op Operation flag
 * @param transaction_num Transaction number
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload.
 */
OPEN1722_INLINE void Avtp_Abb_CreateAcfMessage(Avtp_Abb_t *pdu, uint16_t byte_bus_id, bool op,
                                               uint8_t transaction_num, uint8_t *payload,
                                               uint16_t payload_length)
{
    // Initialize the ACF ABB header
    Avtp_Abb_Init(pdu);

    // Set the byte bus ID, op flag and transaction number
    Avtp_Abb_SetByteBusId(pdu, byte_bus_id);
    Avtp_Abb_SetOp(pdu, op);
    Avtp_Abb_SetTransactionNum(pdu, transaction_num);

    // Copy the payload into the PDU
    Avtp_Abb_SetPayload(pdu, payload, payload_length);

    // Finalize the AVTP ABB Frame
    Avtp_Abb_SetPayloadLength(pdu, payload_length);
}

/**
 * Checks if the ACF ABB frame is valid by checking:
 *     1) if the length field of AVTP/ACF messages contains a value larger than the actual size of
 * the buffer that contains the AVTP message. 2) if other format specific invariants are not upheld
 * @param pdu Pointer to the first bit of a 1722 ACF ABB PDU.
 * @param bufferSize Size of the buffer containing the ACF ABB frame.
 * @return true if the ACF ABB frame is valid, false otherwise.
 */
OPEN1722_INLINE bool Avtp_Abb_IsValid(const Avtp_Abb_t *const pdu, size_t bufferSize)
{
    if (pdu == NULL) {
        return false;
    }

    if (bufferSize < AVTP_ABB_HEADER_LEN) {
        return false;
    }

    if (Avtp_AcfCommon_GetAcfMsgType((const Avtp_AcfCommon_t *)pdu) !=
        AVTP_ACF_TYPE_BYTE_BUS_BRIEF) {
        return false;
    }

    uint16_t msg_length_bytes =
        Avtp_AcfCommon_GetAcfMsgLengthInBytes((const Avtp_AcfCommon_t *)pdu);
    if (msg_length_bytes > bufferSize) {
        return false;
    }

    /* The encoded message length must accommodate header + declared padding
     * so the payload computation in Avtp_Abb_GetPayloadLength() doesn't
     * underflow. */
    uint8_t pad_length = Avtp_Abb_GetPad(pdu);
    uint16_t header_and_pad = (uint16_t)AVTP_ABB_HEADER_LEN + pad_length;
    if (msg_length_bytes < header_and_pad) {
        return false;
    }
    return true;
}

#ifdef __cplusplus
}
#endif
