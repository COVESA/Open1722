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
 * @file This files contains functions for de-/serialization of the ACF_GISF
 * message format (Generic Image Sensor Format). For details see IEEE Std.
 * 1722-2025, chapter 18.
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

#define GET_GISF_FIELD(field)                                                                      \
    (Avtp_GetField(Avtp_GisfFieldDesc, AVTP_GISF_FIELD_MAX, (uint8_t *)pdu, field))
#define SET_GISF_FIELD(field, value)                                                               \
    (Avtp_SetField(Avtp_GisfFieldDesc, AVTP_GISF_FIELD_MAX, (uint8_t *)pdu, field, value))

/**
 * Length of ACF_GISF message header in bytes.
 */
#define AVTP_GISF_HEADER_LEN (5 * AVTP_QUADLET_SIZE)

/**
 * ACF_GISF message structure suitable for in-place de-/serialization of fields
 * in the ACF_GISF message header.
 */
typedef struct {
    uint8_t header[AVTP_GISF_HEADER_LEN];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_Gisf_t;

/**
 * Fields encoded in the ACF_GISF header.
 */
typedef enum {
    /* ACF common header fields */
    AVTP_GISF_FIELD_ACF_MSG_TYPE = 0,
    AVTP_GISF_FIELD_ACF_MSG_LENGTH,
    /* ACF GISF header fields */
    AVTP_GISF_FIELD_PAD,
    AVTP_GISF_FIELD_MTV,
    AVTP_GISF_FIELD_IMAGE_SENSOR_ID,
    AVTP_GISF_FIELD_MESSAGE_TIMESTAMP,
    AVTP_GISF_FIELD_EL,
    AVTP_GISF_FIELD_TL,
    AVTP_GISF_FIELD_EF,
    AVTP_GISF_FIELD_EVT,
    AVTP_GISF_FIELD_BF,
    AVTP_GISF_FIELD_LINE_TYPE_ID,
    AVTP_GISF_FIELD_EVT2,
    AVTP_GISF_FIELD_I_SEQ_NUM,
    AVTP_GISF_FIELD_LINE_NUMBER,
    /* Count number of fields for bound checks */
    AVTP_GISF_FIELD_MAX
} Avtp_GisfFields_t;

/**
 * This table describes all the offsets of the ACF_GISF header fields.
 */
static const Avtp_FieldDescriptor_t Avtp_GisfFieldDesc[AVTP_GISF_FIELD_MAX] = {
    /* ACF common header fields */
    [AVTP_GISF_FIELD_ACF_MSG_TYPE] = {.quadlet = 0, .offset = 0, .bits = 7},
    [AVTP_GISF_FIELD_ACF_MSG_LENGTH] = {.quadlet = 0, .offset = 7, .bits = 9},
    /* ACF GISF header fields */
    [AVTP_GISF_FIELD_PAD] = {.quadlet = 0, .offset = 16, .bits = 2},
    [AVTP_GISF_FIELD_MTV] = {.quadlet = 0, .offset = 18, .bits = 1},
    [AVTP_GISF_FIELD_IMAGE_SENSOR_ID] = {.quadlet = 0, .offset = 21, .bits = 11},
    [AVTP_GISF_FIELD_MESSAGE_TIMESTAMP] = {.quadlet = 1, .offset = 0, .bits = 64},
    [AVTP_GISF_FIELD_EL] = {.quadlet = 3, .offset = 17, .bits = 1},
    [AVTP_GISF_FIELD_TL] = {.quadlet = 3, .offset = 18, .bits = 1},
    [AVTP_GISF_FIELD_EF] = {.quadlet = 3, .offset = 19, .bits = 1},
    [AVTP_GISF_FIELD_EVT] = {.quadlet = 3, .offset = 20, .bits = 4},
    [AVTP_GISF_FIELD_BF] = {.quadlet = 3, .offset = 26, .bits = 1},
    [AVTP_GISF_FIELD_LINE_TYPE_ID] = {.quadlet = 3, .offset = 27, .bits = 5},
    [AVTP_GISF_FIELD_EVT2] = {.quadlet = 4, .offset = 0, .bits = 8},
    [AVTP_GISF_FIELD_I_SEQ_NUM] = {.quadlet = 4, .offset = 8, .bits = 8},
    [AVTP_GISF_FIELD_LINE_NUMBER] = {.quadlet = 4, .offset = 16, .bits = 16},
};

/**
 * Returns the pad field from an ACF_GISF message header.
 *
 * @param pdu Pointer to an ACF_GISF message.
 * @returns The value of the pad field.
 */
OPEN1722_INLINE uint8_t Avtp_Gisf_GetPad(const Avtp_Gisf_t *const pdu)
{
    return (uint8_t)GET_GISF_FIELD(AVTP_GISF_FIELD_PAD);
}

/**
 * Sets the pad field in an ACF_GISF message header.
 *
 * @param pdu Pointer to an ACF_GISF message.
 * @param pad The value to set.
 */
OPEN1722_INLINE void Avtp_Gisf_SetPad(Avtp_Gisf_t *pdu, uint8_t pad)
{
    SET_GISF_FIELD(AVTP_GISF_FIELD_PAD, pad);
}

/**
 * Returns the message timestamp valid flag (mtv) from an ACF_GISF message header.
 *
 * @param pdu Pointer to an ACF_GISF message.
 * @returns The value of the mtv flag.
 */
OPEN1722_INLINE bool Avtp_Gisf_IsMtv(const Avtp_Gisf_t *const pdu)
{
    return (bool)GET_GISF_FIELD(AVTP_GISF_FIELD_MTV);
}

/**
 * Returns the value of the image_sensor_id field from an ACF_GISF message header.
 *
 * @param pdu Pointer to an ACF_GISF message.
 * @returns The value of the image_sensor_id field.
 */
OPEN1722_INLINE uint16_t Avtp_Gisf_GetImageSensorId(const Avtp_Gisf_t *const pdu)
{
    return (uint16_t)GET_GISF_FIELD(AVTP_GISF_FIELD_IMAGE_SENSOR_ID);
}

/**
 * Returns the value of the message_timestamp field from an ACF_GISF message header.
 *
 * @param pdu Pointer to an ACF_GISF message.
 * @returns The value of the message_timestamp field.
 */
OPEN1722_INLINE uint64_t Avtp_Gisf_GetMessageTimestamp(const Avtp_Gisf_t *const pdu)
{
    return (uint64_t)GET_GISF_FIELD(AVTP_GISF_FIELD_MESSAGE_TIMESTAMP);
}

/**
 * Returns the value of the el (end line) flag from an ACF_GISF message header.
 *
 * @param pdu Pointer to an ACF_GISF message.
 * @returns The value of the el flag.
 */
OPEN1722_INLINE bool Avtp_Gisf_IsEl(const Avtp_Gisf_t *const pdu)
{
    return (bool)GET_GISF_FIELD(AVTP_GISF_FIELD_EL);
}

/**
 * Returns the value of the tl (timestamp line) flag from an ACF_GISF message header.
 *
 * @param pdu Pointer to an ACF_GISF message.
 * @returns The value of the tl flag.
 */
OPEN1722_INLINE bool Avtp_Gisf_IsTl(const Avtp_Gisf_t *const pdu)
{
    return (bool)GET_GISF_FIELD(AVTP_GISF_FIELD_TL);
}

/**
 * Returns the value of the ef (end frame) flag from an ACF_GISF message header.
 *
 * @param pdu Pointer to an ACF_GISF message.
 * @returns The value of the ef flag.
 */
OPEN1722_INLINE bool Avtp_Gisf_IsEf(const Avtp_Gisf_t *const pdu)
{
    return (bool)GET_GISF_FIELD(AVTP_GISF_FIELD_EF);
}

/**
 * Returns the value of the evt (event) field from an ACF_GISF message header.
 *
 * @param pdu Pointer to an ACF_GISF message.
 * @returns The value of the evt field.
 */
OPEN1722_INLINE uint8_t Avtp_Gisf_GetEvt(const Avtp_Gisf_t *const pdu)
{
    return (uint8_t)GET_GISF_FIELD(AVTP_GISF_FIELD_EVT);
}

/**
 * Returns the value of the bf (begin frame) flag from an ACF_GISF message header.
 *
 * @param pdu Pointer to an ACF_GISF message.
 * @returns The value of the bf flag.
 */
OPEN1722_INLINE bool Avtp_Gisf_IsBf(const Avtp_Gisf_t *const pdu)
{
    return (bool)GET_GISF_FIELD(AVTP_GISF_FIELD_BF);
}

/**
 * Returns the value of the line_type_id field from an ACF_GISF message header.
 *
 * @param pdu Pointer to an ACF_GISF message.
 * @returns The value of the line_type_id value.
 */
OPEN1722_INLINE uint8_t Avtp_Gisf_GetLineTypeId(const Avtp_Gisf_t *const pdu)
{
    return (uint8_t)GET_GISF_FIELD(AVTP_GISF_FIELD_LINE_TYPE_ID);
}

/**
 * Returns the value of the evt2 (event 2) field from an ACF_GISF message header.
 *
 * @param pdu Pointer to an ACF_GISF message.
 * @returns The value of the evt2 field.
 */
OPEN1722_INLINE uint8_t Avtp_Gisf_GetEvt2(const Avtp_Gisf_t *const pdu)
{
    return (uint8_t)GET_GISF_FIELD(AVTP_GISF_FIELD_EVT2);
}

/**
 * Returns the value of the i_seq_num (intra line sequence number) field from an ACF_GISF message
 * header.
 *
 * @param pdu Pointer to an ACF_GISF message.
 * @returns The value of the i_seq_num field.
 */
OPEN1722_INLINE uint8_t Avtp_Gisf_GetISeqNum(const Avtp_Gisf_t *const pdu)
{
    return (uint8_t)GET_GISF_FIELD(AVTP_GISF_FIELD_I_SEQ_NUM);
}

/**
 * Returns the value of the line_number field from an ACF_GISF message header.
 *
 * @param pdu Pointer to an ACF_GISF message.
 * @returns The value of the line_number field.
 */
OPEN1722_INLINE uint16_t Avtp_Gisf_GetLineNumber(const Avtp_Gisf_t *const pdu)
{
    return (uint16_t)GET_GISF_FIELD(AVTP_GISF_FIELD_LINE_NUMBER);
}

/**
 * Sets the value of the mtv flag in an ACF_GISF message header.
 *
 * @param pdu Pointer to an ACF_GISF message.
 * @param mtv The value to set.
 */
OPEN1722_INLINE void Avtp_Gisf_SetMtv(Avtp_Gisf_t *pdu, bool mtv)
{
    SET_GISF_FIELD(AVTP_GISF_FIELD_MTV, mtv);
}

/**
 * Sets the value of the image_sensor_id field in an ACF_GISF message header.
 *
 * @param pdu Pointer to an ACF_GISF message.
 * @param imageSensorId The value to set.
 */
OPEN1722_INLINE void Avtp_Gisf_SetImageSensorId(Avtp_Gisf_t *pdu, uint16_t imageSensorId)
{
    SET_GISF_FIELD(AVTP_GISF_FIELD_IMAGE_SENSOR_ID, imageSensorId);
}

/**
 * Sets the value of the message_timestamp field in an ACF_GISF message header.
 *
 * @param pdu Pointer to an ACF_GISF message.
 * @param messageTimestamp The value to set.
 */
OPEN1722_INLINE void Avtp_Gisf_SetMessageTimestamp(Avtp_Gisf_t *pdu, uint64_t messageTimestamp)
{
    SET_GISF_FIELD(AVTP_GISF_FIELD_MESSAGE_TIMESTAMP, messageTimestamp);
}

/**
 * Sets the value of the end line (el) flag in an ACF_GISF message header.
 *
 * @param pdu Pointer to an ACF_GISF message.
 * @param el The value to set.
 */
OPEN1722_INLINE void Avtp_Gisf_SetEl(Avtp_Gisf_t *pdu, bool el)
{
    SET_GISF_FIELD(AVTP_GISF_FIELD_EL, el);
}

/**
 * Sets the value of the timestamp line (tl) flag in an ACF_GISF message header.
 *
 * @param pdu Pointer to an ACF_GISF message.
 * @param tl The value to set.
 */
OPEN1722_INLINE void Avtp_Gisf_SetTl(Avtp_Gisf_t *pdu, bool tl)
{
    SET_GISF_FIELD(AVTP_GISF_FIELD_TL, tl);
}

/**
 * Sets the value of the end frame (ef) flag in an ACF_GISF message header.
 *
 * @param pdu Pointer to an ACF_GISF message.
 * @param ef The value to set.
 */
OPEN1722_INLINE void Avtp_Gisf_SetEf(Avtp_Gisf_t *pdu, bool ef)
{
    SET_GISF_FIELD(AVTP_GISF_FIELD_EF, ef);
}

/**
 * Sets the value of the event field in an ACF_GISF message header.
 *
 * @param pdu Pointer to an ACF_GISF message.
 * @param evt The value to set.
 */
OPEN1722_INLINE void Avtp_Gisf_SetEvt(Avtp_Gisf_t *pdu, uint8_t evt)
{
    SET_GISF_FIELD(AVTP_GISF_FIELD_EVT, evt);
}

/**
 * Sets the value of the begin frame (bf) flag in an ACF_GISF message header.
 *
 * @param pdu Pointer to an ACF_GISF message.
 * @param bf The value to set.
 */
OPEN1722_INLINE void Avtp_Gisf_SetBf(Avtp_Gisf_t *pdu, bool bf)
{
    SET_GISF_FIELD(AVTP_GISF_FIELD_BF, bf);
}

/**
 * Sets the value of the line_type_id field in an ACF_GISF message header.
 *
 * @param pdu Pointer to an ACF_GISF message.
 * @param lineTypeId The value to set.
 */
OPEN1722_INLINE void Avtp_Gisf_SetLineTypeId(Avtp_Gisf_t *pdu, uint8_t lineTypeId)
{
    SET_GISF_FIELD(AVTP_GISF_FIELD_LINE_TYPE_ID, lineTypeId);
}

/**
 * Sets the value of the event_2 field in an ACF_GISF message header.
 *
 * @param pdu Pointer to an ACF_GISF message.
 * @param evt2 The value to set.
 */
OPEN1722_INLINE void Avtp_Gisf_SetEvt2(Avtp_Gisf_t *pdu, uint8_t evt2)
{
    SET_GISF_FIELD(AVTP_GISF_FIELD_EVT2, evt2);
}

/**
 * Sets the value of the i_seq_num field in an ACF_GISF message header.
 *
 * @param pdu Pointer to an ACF_GISF message.
 * @param iSeqNum The value to set.
 */
OPEN1722_INLINE void Avtp_Gisf_SetISeqNum(Avtp_Gisf_t *pdu, uint8_t iSeqNum)
{
    SET_GISF_FIELD(AVTP_GISF_FIELD_I_SEQ_NUM, iSeqNum);
}

/**
 * Sets the value of the line_number field in an ACF_GISF message header.
 *
 * @param pdu Pointer to an ACF_GISF message.
 * @param lineNumber The value to set.
 */
OPEN1722_INLINE void Avtp_Gisf_SetLineNumber(Avtp_Gisf_t *pdu, uint16_t lineNumber)
{
    SET_GISF_FIELD(AVTP_GISF_FIELD_LINE_NUMBER, lineNumber);
}

/**
 * Returns pointer to payload of an ACF GISF frame.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF GISF PDU.
 * @return Pointer to ACF GISF frame payload
 */
OPEN1722_INLINE const uint8_t *Avtp_Gisf_GetPayload(const Avtp_Gisf_t *const pdu)
{
    return pdu->payload;
}

/**
 * Sets the payload in an ACF GISF frame.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF GISF PDU.
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload
 */
OPEN1722_INLINE void Avtp_Gisf_SetPayload(Avtp_Gisf_t *pdu, uint8_t *payload,
                                          uint16_t payload_length)
{
    memcpy(pdu->payload, payload, payload_length);
}

/**
 * Finalizes the ACF GISF frame. This function will set the
 * length and pad fields while inserting the padded bytes. This will also
 * set padding bytes to zero if the payload length is not a multiple of 4.
 * to avoid leaking information
 *
 * @param pdu Pointer to the first bit of a 1722 ACF GISF PDU.
 * @param payload_length Length of the frame payload.
 */
OPEN1722_INLINE void Avtp_Gisf_SetPayloadLength(Avtp_Gisf_t *pdu, uint16_t payload_length)
{
    uint16_t msgLenBytes = AVTP_GISF_HEADER_LEN + payload_length;
    uint8_t pad = (uint8_t)(4 - (msgLenBytes % 4)) % 4;
    if (pad > 0) {
        memset(pdu->payload + payload_length, 0, pad);
    }
    uint16_t msgLenQuadlets = (uint16_t)((msgLenBytes + pad) / 4);
    Avtp_Gisf_SetPad(pdu, pad);
    Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)pdu, msgLenQuadlets);
}

/**
 * Returns the length of the payload without the padding bytes and the
 * header length of the encapsulating ACF Frame.
 *
 * Precondition: the caller must have validated the PDU with
 * Avtp_Gisf_IsValid(). This function performs no further bounds checking
 * and assumes those invariants already hold.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF GISF PDU.
 * @return  Length of payload in bytes
 */
OPEN1722_INLINE uint16_t Avtp_Gisf_GetPayloadLength(const Avtp_Gisf_t *const pdu)
{
    uint8_t pad_length = Avtp_Gisf_GetPad(pdu);
    uint16_t acf_length_bytes = Avtp_AcfCommon_GetAcfMsgLengthInBytes((const Avtp_AcfCommon_t *)pdu);
    return (uint16_t)(acf_length_bytes - AVTP_GISF_HEADER_LEN - pad_length);
}

/**
 * Initializes an ACF_GISF message header as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF GISF PDU.
 */
OPEN1722_INLINE void Avtp_Gisf_Init(Avtp_Gisf_t *pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_Gisf_t));
        Avtp_AcfCommon_SetAcfMsgType((Avtp_AcfCommon_t *)pdu, AVTP_ACF_TYPE_GISF);
    }
}

/**
 * Copies the payload data and image sensor ID into the ACF GISF frame. This
 * function will also set the length and pad fields while inserting the padded
 * bytes.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF GISF PDU.
 * @param image_sensor_id Image sensor ID
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload.
 */
OPEN1722_INLINE void Avtp_Gisf_CreateAcfMessage(Avtp_Gisf_t *pdu, uint16_t image_sensor_id,
                                                uint8_t *payload, uint16_t payload_length)
{
    // Initialize the ACF GISF header
    Avtp_Gisf_Init(pdu);

    // Set the image sensor ID
    Avtp_Gisf_SetImageSensorId(pdu, image_sensor_id);

    // Copy the payload into the GISF PDU
    Avtp_Gisf_SetPayload(pdu, payload, payload_length);

    // Finalize the AVTP GISF Frame
    Avtp_Gisf_SetPayloadLength(pdu, payload_length);
}

/**
 * Checks if the ACF GISF frame is valid by checking:
 *     1) if the length field of AVTP/ACF messages contains a value larger than the actual size of
 * the buffer that contains the AVTP message. 2) if other format specific invariants are not upheld
 * @param pdu Pointer to the first bit of a 1722 ACF GISF PDU.
 * @param bufferSize Size of the buffer containing the ACF GISF frame.
 * @return true if the ACF GISF frame is valid, false otherwise.
 */
OPEN1722_INLINE bool Avtp_Gisf_IsValid(const Avtp_Gisf_t *const pdu, size_t bufferSize)
{
    if (pdu == NULL) {
        return false;
    }

    if (bufferSize < AVTP_GISF_HEADER_LEN) {
        return false;
    }

    if (Avtp_AcfCommon_GetAcfMsgType((const Avtp_AcfCommon_t *)pdu) != AVTP_ACF_TYPE_GISF) {
        return false;
    }

    uint16_t msg_length_bytes = Avtp_AcfCommon_GetAcfMsgLengthInBytes((const Avtp_AcfCommon_t *)pdu);
    if (msg_length_bytes > bufferSize) {
        return false;
    }

    /* The encoded message length must accommodate header + declared padding
     * so the payload computation in Avtp_Gisf_GetPayloadLength() doesn't
     * underflow. */
    uint8_t pad_length = Avtp_Gisf_GetPad(pdu);
    uint16_t header_and_pad = (uint16_t)AVTP_GISF_HEADER_LEN + pad_length;
    if (msg_length_bytes < header_and_pad) {
        return false;
    }
    return true;
}

#ifdef __cplusplus
}
#endif
