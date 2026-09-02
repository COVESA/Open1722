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
 * @file This files contains functions for de-/serialization of IEEE1722's ACF
 * Most PDU formats. For details see IEEE Std. 1722-2016, chapter 9.4.6.
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

/** Length of ACF Most header. */
#define AVTP_MOST_HEADER_LEN (5 * AVTP_QUADLET_SIZE)

#define GET_MOST_FIELD(field)                                                                      \
    (Avtp_GetField(Avtp_MostFieldDesc, AVTP_MOST_FIELD_MAX, (uint8_t *)pdu, field))
#define SET_MOST_FIELD(field, value)                                                               \
    (Avtp_SetField(Avtp_MostFieldDesc, AVTP_MOST_FIELD_MAX, (uint8_t *)pdu, field, value))

/** ACF Most PDU. */
typedef struct {
    uint8_t header[AVTP_MOST_HEADER_LEN];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_Most_t;

/** Fields of ACF Most PDU. */
typedef enum {
    /* ACF common header fields */
    AVTP_MOST_FIELD_ACF_MSG_TYPE = 0,
    AVTP_MOST_FIELD_ACF_MSG_LENGTH,
    /* ACF Most header fields */
    AVTP_MOST_FIELD_PAD,
    AVTP_MOST_FIELD_MTV,
    AVTP_MOST_FIELD_MOST_NET_ID,
    AVTP_MOST_FIELD_RESERVED,
    AVTP_MOST_FIELD_MESSAGE_TIMESTAMP,
    AVTP_MOST_FIELD_DEVICE_ID,
    AVTP_MOST_FIELD_FBLOCK_ID,
    AVTP_MOST_FIELD_INST_ID,
    AVTP_MOST_FIELD_FUNC_ID,
    AVTP_MOST_FIELD_OP_TYPE,
    AVTP_MOST_FIELD_RESERVED_2,
    /* Count number of fields for bound checks */
    AVTP_MOST_FIELD_MAX
} Avtp_MostFields_t;

/**
 * This table describes all the offsets of the ACF Most header fields.
 */
static const Avtp_FieldDescriptor_t Avtp_MostFieldDesc[AVTP_MOST_FIELD_MAX] = {
    /* ACF common header fields */
    [AVTP_MOST_FIELD_ACF_MSG_TYPE] = {.quadlet = 0, .offset = 0, .bits = 7},
    [AVTP_MOST_FIELD_ACF_MSG_LENGTH] = {.quadlet = 0, .offset = 7, .bits = 9},
    /* ACF Most header fields */
    [AVTP_MOST_FIELD_PAD] = {.quadlet = 0, .offset = 16, .bits = 2},
    [AVTP_MOST_FIELD_MTV] = {.quadlet = 0, .offset = 18, .bits = 1},
    [AVTP_MOST_FIELD_MOST_NET_ID] = {.quadlet = 0, .offset = 19, .bits = 5},
    [AVTP_MOST_FIELD_RESERVED] = {.quadlet = 0, .offset = 24, .bits = 8},
    [AVTP_MOST_FIELD_MESSAGE_TIMESTAMP] = {.quadlet = 1, .offset = 0, .bits = 64},
    [AVTP_MOST_FIELD_DEVICE_ID] = {.quadlet = 3, .offset = 0, .bits = 16},
    [AVTP_MOST_FIELD_FBLOCK_ID] = {.quadlet = 3, .offset = 16, .bits = 8},
    [AVTP_MOST_FIELD_INST_ID] = {.quadlet = 3, .offset = 24, .bits = 8},
    [AVTP_MOST_FIELD_FUNC_ID] = {.quadlet = 4, .offset = 0, .bits = 12},
    [AVTP_MOST_FIELD_OP_TYPE] = {.quadlet = 4, .offset = 12, .bits = 4},
    [AVTP_MOST_FIELD_RESERVED_2] = {.quadlet = 4, .offset = 16, .bits = 16},
};

/**
 * Return the value of an an ACF Most PDU padding field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Most PDU.
 * @returns Value of the ACF Most PDU padding field.
 */
OPEN1722_INLINE uint8_t Avtp_Most_GetPad(const Avtp_Most_t *const pdu)
{
    return (uint8_t)GET_MOST_FIELD(AVTP_MOST_FIELD_PAD);
}

/**
 * Return the value of an an ACF Most PDU MTV field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Most PDU.
 * @returns Value of the ACF Most PDU MTV field.
 */
OPEN1722_INLINE bool Avtp_Most_IsMtv(const Avtp_Most_t *const pdu)
{
    return (bool)GET_MOST_FIELD(AVTP_MOST_FIELD_MTV);
}

/**
 * Return the value of an an ACF Most PDU Most Net ID field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Most PDU.
 * @returns Value of the ACF Most PDU Most Net ID field.
 */
OPEN1722_INLINE uint8_t Avtp_Most_GetMostNetId(const Avtp_Most_t *const pdu)
{
    return (uint8_t)GET_MOST_FIELD(AVTP_MOST_FIELD_MOST_NET_ID);
}

/**
 * Return the value of an an ACF Most PDU Message Timestamp field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Most PDU.
 * @returns Value of the ACF Most PDU Message Timestamp field.
 */
OPEN1722_INLINE uint64_t Avtp_Most_GetMessageTimestamp(const Avtp_Most_t *const pdu)
{
    return (uint64_t)GET_MOST_FIELD(AVTP_MOST_FIELD_MESSAGE_TIMESTAMP);
}

/**
 * Return the value of an an ACF Most PDU Device ID field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Most PDU.
 * @returns Value of the ACF Most PDU Device ID field.
 */
OPEN1722_INLINE uint16_t Avtp_Most_GetDeviceId(const Avtp_Most_t *const pdu)
{
    return (uint16_t)GET_MOST_FIELD(AVTP_MOST_FIELD_DEVICE_ID);
}

/**
 * Return the value of an an ACF Most PDU FBlock ID field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Most PDU.
 * @returns Value of the ACF Most PDU FBlock ID field.
 */
OPEN1722_INLINE uint8_t Avtp_Most_GetFblockId(const Avtp_Most_t *const pdu)
{
    return (uint8_t)GET_MOST_FIELD(AVTP_MOST_FIELD_FBLOCK_ID);
}

/**
 * Return the value of an an ACF Most PDU Inst ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Most PDU.
 * @returns Value of the ACF Most PDU Inst ID field.
 */
OPEN1722_INLINE uint8_t Avtp_Most_GetInstId(const Avtp_Most_t *const pdu)
{
    return (uint8_t)GET_MOST_FIELD(AVTP_MOST_FIELD_INST_ID);
}

/**
 * Return the value of an an ACF Most PDU Func ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Most PDU.
 * @returns Value of the ACF Most PDU Func ID field.
 */
OPEN1722_INLINE uint16_t Avtp_Most_GetFuncId(const Avtp_Most_t *const pdu)
{
    return (uint16_t)GET_MOST_FIELD(AVTP_MOST_FIELD_FUNC_ID);
}

/**
 * Return the value of an an ACF Most PDU Op Type field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Most PDU.
 * @returns Value of the ACF Most PDU Op Type field.
 */
OPEN1722_INLINE uint8_t Avtp_Most_GetOpType(const Avtp_Most_t *const pdu)
{
    return (uint8_t)GET_MOST_FIELD(AVTP_MOST_FIELD_OP_TYPE);
}

/**
 * Set the value of an an ACF Most PDU padding field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Most PDU.
 * @param value Value to set the ACF Most PDU padding field to.
 */
OPEN1722_INLINE void Avtp_Most_SetPad(Avtp_Most_t *pdu, uint8_t value)
{
    SET_MOST_FIELD(AVTP_MOST_FIELD_PAD, value);
}

/**
 * Set the MTV bit in an ACF Most frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Most PDU.
 * @param mtv Value to set the MTV bit to.
 */
OPEN1722_INLINE void Avtp_Most_SetMtv(Avtp_Most_t *pdu, bool mtv)
{
    SET_MOST_FIELD(AVTP_MOST_FIELD_MTV, mtv);
}

/**
 * Set the value of an an ACF Most PDU Most Net ID field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Most PDU.
 * @param value Value to set the ACF Most PDU Most Net ID field to.
 */
OPEN1722_INLINE void Avtp_Most_SetMostNetId(Avtp_Most_t *pdu, uint8_t value)
{
    SET_MOST_FIELD(AVTP_MOST_FIELD_MOST_NET_ID, value);
}

/**
 * Set the value of an an ACF Most PDU Message Timestamp field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Most PDU.
 * @param value Value to set the ACF Most PDU Message Timestamp field to.
 */
OPEN1722_INLINE void Avtp_Most_SetMessageTimestamp(Avtp_Most_t *pdu, uint64_t value)
{
    SET_MOST_FIELD(AVTP_MOST_FIELD_MESSAGE_TIMESTAMP, value);
}

/**
 * Set the value of an an ACF Most PDU Device ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Most PDU.
 * @param value Value to set the ACF Most PDU Device ID field to.
 */
OPEN1722_INLINE void Avtp_Most_SetDeviceId(Avtp_Most_t *pdu, uint16_t value)
{
    SET_MOST_FIELD(AVTP_MOST_FIELD_DEVICE_ID, value);
}

/**
 * Set the value of an an ACF Most PDU FBlock ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Most PDU.
 * @param value Value to set the ACF Most PDU FBlock ID field to.
 */
OPEN1722_INLINE void Avtp_Most_SetFblockId(Avtp_Most_t *pdu, uint8_t value)
{
    SET_MOST_FIELD(AVTP_MOST_FIELD_FBLOCK_ID, value);
}

/**
 * Set the value of an an ACF Most PDU Inst ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Most PDU.
 * @param value Value to set the ACF Most PDU Inst ID field to.
 */
OPEN1722_INLINE void Avtp_Most_SetInstId(Avtp_Most_t *pdu, uint8_t value)
{
    SET_MOST_FIELD(AVTP_MOST_FIELD_INST_ID, value);
}

/**
 * Set the value of an an ACF Most PDU Func ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Most PDU.
 * @param value Value to set the ACF Most PDU Func ID field to.
 */
OPEN1722_INLINE void Avtp_Most_SetFuncId(Avtp_Most_t *pdu, uint16_t value)
{
    SET_MOST_FIELD(AVTP_MOST_FIELD_FUNC_ID, value);
}

/**
 * Set the value of an an ACF Most PDU Op Type field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Most PDU.
 * @param value Value to set the ACF Most PDU Op Type field to.
 */
OPEN1722_INLINE void Avtp_Most_SetOpType(Avtp_Most_t *pdu, uint8_t value)
{
    SET_MOST_FIELD(AVTP_MOST_FIELD_OP_TYPE, value);
}

/**
 * Returns pointer to payload of an ACF Most frame.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Most PDU.
 * @return Pointer to ACF Most frame payload
 */
OPEN1722_INLINE const uint8_t *Avtp_Most_GetPayload(const Avtp_Most_t *const pdu)
{
    return pdu->payload;
}

/**
 * Sets the Most payload in an ACF Most frame.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Most PDU.
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload
 */
OPEN1722_INLINE void Avtp_Most_SetPayload(Avtp_Most_t *pdu, uint8_t *payload,
                                          uint16_t payload_length)
{
    memcpy(pdu->payload, payload, payload_length);
}

/**
 * Finalizes the ACF Most frame. This function will set the length and pad
 * fields while inserting the padded bytes. This will also set padding bytes to
 * zero if the payload length is not a multiple of 4 to avoid leaking information.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Most PDU.
 * @param payload_length Length of the Most frame payload.
 */
OPEN1722_INLINE void Avtp_Most_SetPayloadLength(Avtp_Most_t *pdu, uint16_t payload_length)
{
    uint16_t msgLenBytes = AVTP_MOST_HEADER_LEN + payload_length;
    uint8_t pad = (uint8_t)(4 - (msgLenBytes % 4)) % 4;
    if (pad > 0) {
        memset(pdu->payload + payload_length, 0, pad);
    }
    uint16_t msgLenQuadlets = (uint16_t)((msgLenBytes + pad) / 4);
    Avtp_Most_SetPad(pdu, pad);
    Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)pdu, msgLenQuadlets);
}

/**
 * Returns the length of the Most payload without the padding bytes and the
 * header length of the encapsulating ACF Frame.
 *
 * Precondition: the caller must have validated the PDU with
 * Avtp_Most_IsValid(). This function performs no further bounds checking
 * and assumes those invariants already hold.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Most PDU.
 * @return  Length of Most payload in bytes
 */
OPEN1722_INLINE uint8_t Avtp_Most_GetPayloadLength(const Avtp_Most_t *const pdu)
{
    uint8_t pad_length = Avtp_Most_GetPad(pdu);
    uint16_t acf_length_bytes = Avtp_AcfCommon_GetAcfMsgLengthInBytes((const Avtp_AcfCommon_t *)pdu);
    return (uint8_t)(acf_length_bytes - AVTP_MOST_HEADER_LEN - pad_length);
}

/**
 * Initializes an ACF Most PDU.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF Most PDU.
 */
OPEN1722_INLINE void Avtp_Most_Init(Avtp_Most_t *pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_Most_t));
        Avtp_AcfCommon_SetAcfMsgType((Avtp_AcfCommon_t *)pdu, AVTP_ACF_TYPE_MOST);
    }
}

/**
 * Copies the payload data, device ID, FBlock ID, instance ID, function ID and
 * op type into the ACF Most frame. This function will also set the length and
 * pad fields while inserting the padded bytes.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Most PDU.
 * @param device_id Device ID
 * @param fblock_id FBlock ID
 * @param inst_id Instance ID
 * @param func_id Function ID
 * @param op_type Op type
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload.
 */
OPEN1722_INLINE void Avtp_Most_CreateAcfMessage(Avtp_Most_t *pdu, uint16_t device_id,
                                                uint8_t fblock_id, uint8_t inst_id,
                                                uint16_t func_id, uint8_t op_type, uint8_t *payload,
                                                uint16_t payload_length)
{
    // Initialize the ACF Most header
    Avtp_Most_Init(pdu);

    // Set the device ID, FBlock ID, instance ID, function ID and op type
    Avtp_Most_SetDeviceId(pdu, device_id);
    Avtp_Most_SetFblockId(pdu, fblock_id);
    Avtp_Most_SetInstId(pdu, inst_id);
    Avtp_Most_SetFuncId(pdu, func_id);
    Avtp_Most_SetOpType(pdu, op_type);

    // Copy the payload into the Most PDU
    Avtp_Most_SetPayload(pdu, payload, payload_length);

    // Finalize the AVTP Most Frame
    Avtp_Most_SetPayloadLength(pdu, payload_length);
}

/**
 * Checks if the ACF Most frame is valid by checking:
 *     1) if the length field of AVTP/ACF messages contains a value larger than the actual size of
 * the buffer that contains the AVTP message. 2) if other format specific invariants are not upheld
 * @param pdu Pointer to the first bit of an 1722 ACF Most PDU.
 * @param bufferSize Size of the buffer containing the ACF Most frame.
 * @return true if the ACF Most frame is valid, false otherwise.
 */
OPEN1722_INLINE bool Avtp_Most_IsValid(const Avtp_Most_t *const pdu, size_t bufferSize)
{
    if (pdu == NULL) {
        return false;
    }

    if (bufferSize < AVTP_MOST_HEADER_LEN) {
        return false;
    }

    if (Avtp_AcfCommon_GetAcfMsgType((const Avtp_AcfCommon_t *)pdu) != AVTP_ACF_TYPE_MOST) {
        return false;
    }

    uint16_t msg_length_bytes = Avtp_AcfCommon_GetAcfMsgLengthInBytes((const Avtp_AcfCommon_t *)pdu);
    if (msg_length_bytes > bufferSize) {
        return false;
    }

    /* The encoded message length must accommodate header + declared padding
     * so the payload computation in Avtp_Most_GetPayloadLength() doesn't
     * underflow. */
    uint8_t pad_length = Avtp_Most_GetPad(pdu);
    uint16_t header_and_pad = (uint16_t)AVTP_MOST_HEADER_LEN + pad_length;
    if (msg_length_bytes < header_and_pad) {
        return false;
    }
    return true;
}

#ifdef __cplusplus
}
#endif
