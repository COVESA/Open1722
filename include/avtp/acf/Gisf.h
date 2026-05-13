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

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "avtp/Defines.h"
#include "avtp/acf/AcfCommon.h"
#include "avtp/Utils.h"

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
} Avtp_Gisf_t;

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
} Avtp_GisfField_t;

/**
 * This table describes all the offsets of the ACF_GISF header fields.
 */
static const Avtp_FieldDescriptor_t __AVTP_GISF_FIELDS[AVTP_GISF_FIELD_MAX] =
{
    /* ACF common header fields */
    [AVTP_GISF_FIELD_ACF_MSG_TYPE]      = { .quadlet = 0, .offset =  0, .bits =  7 },
    [AVTP_GISF_FIELD_ACF_MSG_LENGTH]    = { .quadlet = 0, .offset =  7, .bits =  9 },
    /* ACF GISF header fields */
    [AVTP_GISF_FIELD_PAD]               = { .quadlet = 0, .offset = 16, .bits =  2 },
    [AVTP_GISF_FIELD_MTV]               = { .quadlet = 0, .offset = 18, .bits =  1 },
    [AVTP_GISF_FIELD_IMAGE_SENSOR_ID]   = { .quadlet = 0, .offset = 21, .bits = 11 },
    [AVTP_GISF_FIELD_MESSAGE_TIMESTAMP] = { .quadlet = 1, .offset =  0, .bits = 64 },
    [AVTP_GISF_FIELD_EL]                = { .quadlet = 3, .offset = 17, .bits =  1 },
    [AVTP_GISF_FIELD_TL]                = { .quadlet = 3, .offset = 18, .bits =  1 },
    [AVTP_GISF_FIELD_EF]                = { .quadlet = 3, .offset = 19, .bits =  1 },
    [AVTP_GISF_FIELD_EVT]               = { .quadlet = 3, .offset = 20, .bits =  4 },
    [AVTP_GISF_FIELD_BF]                = { .quadlet = 3, .offset = 26, .bits =  1 },
    [AVTP_GISF_FIELD_LINE_TYPE_ID]      = { .quadlet = 3, .offset = 27, .bits =  5 },
    [AVTP_GISF_FIELD_EVT2]              = { .quadlet = 4, .offset =  0, .bits =  8 },
    [AVTP_GISF_FIELD_I_SEQ_NUM]         = { .quadlet = 4, .offset =  8, .bits =  8 },
    [AVTP_GISF_FIELD_LINE_NUMBER]       = { .quadlet = 4, .offset = 16, .bits = 16 },
};

/**
 * Macro to get the value of a field from an ACF_GISF message header.
 * 
 * @note This macro should not be used directly, instead use the field specific
 * getter functions defined below.
 */
#define __Avtp_Gisf_GetField(field) \
        (Avtp_GetField(__AVTP_GISF_FIELDS, AVTP_GISF_FIELD_MAX, (uint8_t*)msg, field))

/**
 * Macro to set the value of a field in an ACF_GISF message header.
 * 
 * @note This macro should not be used directly, instead use the field specific
 * setter functions defined below.
 */
#define __Avtp_Gisf_SetField(field, value) \
        (Avtp_SetField(__AVTP_GISF_FIELDS, AVTP_GISF_FIELD_MAX, (uint8_t*)msg, field, value))

/**
 * Initializes an ACF_GISF message with default values for the header fields
 * including acf_msg_type and acf_msg_length.
 *
 * @param msg Pointer to the ACF_GISF message to initialize.
 */
static inline void Avtp_Gisf_Init(Avtp_Gisf_t* msg) {
    memset(msg, 0, sizeof(Avtp_Gisf_t));
    __Avtp_Gisf_SetField(AVTP_GISF_FIELD_ACF_MSG_TYPE, AVTP_ACF_TYPE_GISF);
    __Avtp_Gisf_SetField(AVTP_GISF_FIELD_ACF_MSG_LENGTH, AVTP_GISF_HEADER_LEN / AVTP_QUADLET_SIZE);
}

/**
 * Returns the pad field from an ACF_GISF message header.
 * 
 * @param msg Pointer to an ACF_GISF message.
 * @returns The value of the pad field.
 */
static inline uint8_t Avtp_Gisf_GetPad(const Avtp_Gisf_t* msg) {
    return (uint8_t) __Avtp_Gisf_GetField(AVTP_GISF_FIELD_PAD);
}

/**
 * Returns the message timestamp valid flag (mtv) from an ACF_GISF message
 * header.
 * 
 * @param msg Pointer to an ACF_GISF message.
 * @returns The value of the mtv flag.
 */
static inline bool Avtp_Gisf_IsMtv(const Avtp_Gisf_t* msg) {
    return (bool) __Avtp_Gisf_GetField(AVTP_GISF_FIELD_MTV);
}

/**
 * Returns the value of the image_sensor_id field from an ACF_GISF message
 * header.
 * 
 * @param msg Pointer to an ACF_GISF message.
 * @returns The value of the image_sensor_id field.
 */
static inline uint16_t Avtp_Gisf_GetImageSensorId(const Avtp_Gisf_t* msg) {
    return (uint16_t) __Avtp_Gisf_GetField(AVTP_GISF_FIELD_IMAGE_SENSOR_ID);
}

/**
 * Returns the value of the message_timestamp field from an ACF_GISF message
 * header.
 * 
 * @param msg Pointer to an ACF_GISF message.
 * @returns The value of the message_timestamp field.
 */
static inline uint64_t Avtp_Gisf_GetMessageTimestamp(const Avtp_Gisf_t* msg) {
    return (uint64_t) __Avtp_Gisf_GetField(AVTP_GISF_FIELD_MESSAGE_TIMESTAMP);
}

/**
 * Returns the value of the el (end line) flag from an ACF_GISF message header.
 * 
 * @param msg Pointer to an ACF_GISF message.
 * @returns The value of the el flag.
 */
static inline bool Avtp_Gisf_IsEl(const Avtp_Gisf_t* msg) {
    return (bool) __Avtp_Gisf_GetField(AVTP_GISF_FIELD_EL);
}

/**
 * Returns the value of the tl (timestamp line) flag from an ACF_GISF message
 * header.
 * 
 * @param msg Pointer to an ACF_GISF message.
 * @returns The value of the tl flag.
 */
static inline bool Avtp_Gisf_IsTl(const Avtp_Gisf_t* msg) {
    return (bool) __Avtp_Gisf_GetField(AVTP_GISF_FIELD_TL);
}

/**
 * Returns the value of the ef (end frame) flag from an ACF_GISF message
 * header.
 * 
 * @param msg Pointer to an ACF_GISF message.
 * @returns The value of the ef flag.
 */
static inline bool Avtp_Gisf_IsEf(const Avtp_Gisf_t* msg) {
    return (bool) __Avtp_Gisf_GetField(AVTP_GISF_FIELD_EF);
}

/**
 * Returns the value of the evt (event) field from an ACF_GISF message header.
 * 
 * @param msg Pointer to an ACF_GISF message.
 * @returns The value of the evt field.
 */
static inline uint8_t Avtp_Gisf_GetEvt(const Avtp_Gisf_t* msg) {
    return (uint8_t) __Avtp_Gisf_GetField(AVTP_GISF_FIELD_EVT);
}

/**
 * Returns the value of the bf (begin frame) flag from an ACF_GISF message
 * header.
 * 
 * @param msg Pointer to an ACF_GISF message.
 * @returns The value of the bf flag.
 */
static inline bool Avtp_Gisf_IsBf(const Avtp_Gisf_t* msg) {
    return (bool) __Avtp_Gisf_GetField(AVTP_GISF_FIELD_BF);
}

/**
 * Returns the value of the line_type_id field from an ACF_GISF message header.
 * 
 * @param msg Pointer to an ACF_GISF message.
 * @returns The value of the line_type_id value.
 */
static inline uint8_t Avtp_Gisf_GetLineTypeId(const Avtp_Gisf_t* msg) {
    return (uint8_t) __Avtp_Gisf_GetField(AVTP_GISF_FIELD_LINE_TYPE_ID);
}

/**
 * Returns the value of the evt2 (event 2) field from an ACF_GISF message
 * header.
 * 
 * @param msg Pointer to an ACF_GISF message.
 * @returns The value of the evt2 field.
 */
static inline uint8_t Avtp_Gisf_GetEvt2(const Avtp_Gisf_t* msg) {
    return (uint8_t) __Avtp_Gisf_GetField(AVTP_GISF_FIELD_EVT2);
}

/**
 * Returns the value of the i_seq_num (intra line sequence number) field from
 * an ACF_GISF message header.
 * 
 * @param msg Pointer to an ACF_GISF message.
 * @returns The value of the i_seq_num field.
 */
static inline uint8_t Avtp_Gisf_GetISeqNum(const Avtp_Gisf_t* msg) {
    return (uint8_t) __Avtp_Gisf_GetField(AVTP_GISF_FIELD_I_SEQ_NUM);
}

/**
 * Returns the value of the line_number field from an ACF_GISF message header.
 * 
 * @param msg Pointer to an ACF_GISF message.
 * @returns The value of the line_number field.
 */
static inline uint16_t Avtp_Gisf_GetLineNumber(const Avtp_Gisf_t* msg) {
    return (uint16_t) __Avtp_Gisf_GetField(AVTP_GISF_FIELD_LINE_NUMBER);
}

/**
 * Returns the paload length from an ACF_GISF message (in bytes). This is
 * calculated based on the value of the acf_msg_length field in the header
 * as well as the value of the pad field.
 * 
 * @param msg Pointer to an ACF_GISF message.
 * @returns The payload length in bytes.
 */
static inline uint16_t Avtp_Gisf_GetPayloadLen(const Avtp_Gisf_t* msg) {
    return (uint16_t) (__Avtp_Gisf_GetField(AVTP_GISF_FIELD_ACF_MSG_LENGTH) * AVTP_QUADLET_SIZE
           - AVTP_GISF_HEADER_LEN
           - __Avtp_Gisf_GetField(AVTP_GISF_FIELD_PAD));
}

/**
 * Returns the total message length from an ACF_GISF message (in bytes)
 * including header and payload section.
 * 
 * @param msg Pointer to an ACF_GISF message.
 * @returns The total message length in bytes.
 */
static inline uint16_t Avtp_Gisf_GetLen(const Avtp_Gisf_t* msg) {
    return (uint16_t) (__Avtp_Gisf_GetField(AVTP_GISF_FIELD_ACF_MSG_LENGTH) * AVTP_QUADLET_SIZE);
}

/**
 * Sets the value of the mtv flag in an ACF_GISF message header.
 * 
 * @param msg Pointer to an ACF_GISF message.
 * @param mtv The value to set.
 */
static inline void Avtp_Gisf_SetMtv(Avtp_Gisf_t* msg, bool mtv) {
    __Avtp_Gisf_SetField(AVTP_GISF_FIELD_MTV, mtv);
}

/**
 * Sets the value of the image_sensor_id field in an ACF_GISF message header.
 * 
 * @param msg Pointer to an ACF_GISF message.
 * @param byteBusId The value to set.
 */
static inline void Avtp_Gisf_SetImageSensorId(Avtp_Gisf_t* msg, uint16_t imageSensorId) {
    __Avtp_Gisf_SetField(AVTP_GISF_FIELD_IMAGE_SENSOR_ID, imageSensorId);
}

/**
 * Sets the value of the message_timestamp field in an ACF_GISF message header.
 * 
 * @param msg Pointer to an ACF_GISF message.
 * @param messageTimestamp The value to set.
 */
static inline void Avtp_Gisf_SetMessageTimestamp(Avtp_Gisf_t* msg, uint64_t messageTimestamp) {
    __Avtp_Gisf_SetField(AVTP_GISF_FIELD_MESSAGE_TIMESTAMP, messageTimestamp);
}

/**
 * Sets the value of the end line (el) flag in an ACF_GISF message header.
 * 
 * @param msg Pointer to an ACF_GISF message.
 * @param hs The value to set.
 */
static inline void Avtp_Gisf_SetEl(Avtp_Gisf_t* msg, bool el) {
    __Avtp_Gisf_SetField(AVTP_GISF_FIELD_EL, el);
}

/**
 * Sets the value of the timestamp line (tl) flag in an ACF_GISF message
 * header.
 * 
 * @param msg Pointer to an ACF_GISF message.
 * @param cs The value to set.
 */
static inline void Avtp_Gisf_SetTl(Avtp_Gisf_t* msg, bool tl) {
    __Avtp_Gisf_SetField(AVTP_GISF_FIELD_TL, tl);
}

/**
 * Sets the value of the end frame (ef) flag in an ACF_GISF message header.
 * 
 * @param msg Pointer to an ACF_GISF message.
 * @param transactionNum The value to set.
 */
static inline void Avtp_Gisf_SetEf(Avtp_Gisf_t* msg, bool ef) {
    __Avtp_Gisf_SetField(AVTP_GISF_FIELD_EF, ef);
}

/**
 * Sets the value of the event field in an ACF_GISF message header.
 * 
 * @param msg Pointer to an ACF_GISF message.
 * @param op The value to set.
 */
static inline void Avtp_Gisf_SetEvt(Avtp_Gisf_t* msg, uint8_t evt) {
    __Avtp_Gisf_SetField(AVTP_GISF_FIELD_EVT, evt);
}

/**
 * Sets the value of the begin frame (bf) flag in an ACF_GISF message header.
 * 
 * @param msg Pointer to an ACF_GISF message.
 * @param rsp The value to set.
 */
static inline void Avtp_Gisf_SetBf(Avtp_Gisf_t* msg, bool bf) {
    __Avtp_Gisf_SetField(AVTP_GISF_FIELD_BF, bf);
}

/**
 * Sets the value of the line_type_id field in an ACF_GISF message header.
 * 
 * @param msg Pointer to an ACF_GISF message.
 * @param err The value to set.
 */
static inline void Avtp_Gisf_SetLineTypeId(Avtp_Gisf_t* msg, uint8_t lineTypeId) {
    __Avtp_Gisf_SetField(AVTP_GISF_FIELD_LINE_TYPE_ID, lineTypeId);
}

/**
 * Sets the value of the event_2 field in an ACF_GISF message header.
 * 
 * @param msg Pointer to an ACF_GISF message.
 * @param ms The value to set.
 */
static inline void Avtp_Gisf_SetEvt2(Avtp_Gisf_t* msg, uint8_t evt2) {
    __Avtp_Gisf_SetField(AVTP_GISF_FIELD_EVT2, evt2);
}

/**
 * Sets the value of the i_seq_num field in an ACF_GISF message header.
 * 
 * @param msg Pointer to an ACF_GISF message.
 * @param readSize The value to set.
 */
static inline void Avtp_Gisf_SetISeqNum(Avtp_Gisf_t* msg, uint8_t iSeqNum) {
    __Avtp_Gisf_SetField(AVTP_GISF_FIELD_I_SEQ_NUM, iSeqNum);
}

/**
 * Sets the value of the read_size/segment_num field in an ACF_GISF message header.
 * 
 * @param msg Pointer to an ACF_GISF message.
 * @param segmentNum The value to set.
 */
static inline void Avtp_Gisf_SetLineNumber(Avtp_Gisf_t* msg, uint16_t lineNumber) {
    __Avtp_Gisf_SetField(AVTP_GISF_FIELD_LINE_NUMBER, lineNumber);
}

/**
 * Sets the value of the acf_msg_length field in an ACF_GISF message header
 * based on the given payload length. This function also calculates the
 * required padding and sets the value of the pad field accordingly.
 * 
 * @param msg Pointer to an ACF_GISF message.
 * @param payloadLen The length of the payload in bytes.
 */
static inline void Avtp_Gisf_SetPayloadLen(Avtp_Gisf_t* msg, uint16_t payloadLen) {
    uint16_t msgLenBytes = AVTP_GISF_HEADER_LEN + payloadLen;
    uint8_t pad = (4 - (msgLenBytes % 4)) % 4;
    uint16_t msgLenQuadlets = (msgLenBytes + pad) / 4;
    __Avtp_Gisf_SetField(AVTP_GISF_FIELD_ACF_MSG_LENGTH, msgLenQuadlets);
    __Avtp_Gisf_SetField(AVTP_GISF_FIELD_PAD, pad);
}

#ifdef __cplusplus
}
#endif
