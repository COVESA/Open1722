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
} Avtp_Gbb_t;

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
} Avtp_GbbField_t;

/**
 * This table describes all the offsets of the ACF_GBB header fields.
 */
static const Avtp_FieldDescriptor_t __AVTP_GBB_FIELDS[AVTP_GBB_FIELD_MAX] =
{
    /* ACF common header fields */
    [AVTP_GBB_FIELD_ACF_MSG_TYPE]           = { .quadlet = 0, .offset =  0, .bits = 7 },
    [AVTP_GBB_FIELD_ACF_MSG_LENGTH]         = { .quadlet = 0, .offset =  7, .bits = 9 },
    /* ACF GBB header fields */
    [AVTP_GBB_FIELD_PAD]                    = { .quadlet = 0, .offset = 16, .bits =   2 },
    [AVTP_GBB_FIELD_MTV]                    = { .quadlet = 0, .offset = 18, .bits =   1 },
    [AVTP_GBB_FIELD_BYTE_BUS_ID]            = { .quadlet = 0, .offset = 21, .bits =  11 },
    [AVTP_GBB_FIELD_MESSAGE_TIMESTAMP]      = { .quadlet = 1, .offset =  0, .bits =  64 },
    [AVTP_GBB_FIELD_EVT]                    = { .quadlet = 3, .offset =  0, .bits =   4 },
    [AVTP_GBB_FIELD_HS]                     = { .quadlet = 3, .offset =  6, .bits =   1 },
    [AVTP_GBB_FIELD_CS]                     = { .quadlet = 3, .offset =  7, .bits =   1 },
    [AVTP_GBB_FIELD_TRANSACTION_NUM]        = { .quadlet = 3, .offset =  8, .bits =   8 },
    [AVTP_GBB_FIELD_OP]                     = { .quadlet = 3, .offset = 16, .bits =   1 },
    [AVTP_GBB_FIELD_RSP]                    = { .quadlet = 3, .offset = 17, .bits =   1 },
    [AVTP_GBB_FIELD_ERR]                    = { .quadlet = 3, .offset = 18, .bits =   1 },
    [AVTP_GBB_FIELD_MS]                     = { .quadlet = 3, .offset = 19, .bits =   1 },
    [AVTP_GBB_FIELD_READ_SIZE_SEGMENT_NUM]  = { .quadlet = 3, .offset = 20, .bits =  12 },
};

/**
 * Macro to get the value of a field from an ACF_GBB message header.
 * 
 * @note This macro should not be used directly, instead use the field specific
 * getter functions defined below.
 */
#define __Avtp_Gbb_GetField(field) \
        (Avtp_GetField(__AVTP_GBB_FIELDS, AVTP_GBB_FIELD_MAX, (uint8_t*)msg, field))

/**
 * Macro to set the value of a field in an ACF_GBB message header.
 * 
 * @note This macro should not be used directly, instead use the field specific
 * setter functions defined below.
 */
#define __Avtp_Gbb_SetField(field, value) \
        (Avtp_SetField(__AVTP_GBB_FIELDS, AVTP_GBB_FIELD_MAX, (uint8_t*)msg, field, value))

/**
 * Initializes an ACF_GBB message with default values for the header fields
 * including acf_msg_type and acf_msg_length.
 *
 * @param msg Pointer to the ACF_GBB message to initialize.
 */
static inline void Avtp_Gbb_Init(Avtp_Gbb_t* msg) {
    memset(msg, 0, sizeof(Avtp_Gbb_t));
    __Avtp_Gbb_SetField(AVTP_GBB_FIELD_ACF_MSG_TYPE, AVTP_ACF_TYPE_BYTE_BUS);
    __Avtp_Gbb_SetField(AVTP_GBB_FIELD_ACF_MSG_LENGTH, AVTP_GBB_HEADER_LEN / AVTP_QUADLET_SIZE);
}

/**
 * Returns the pad field from an ACF_GBB message header.
 * 
 * @param msg Pointer to an ACF_GBB message.
 * @returns The value of the pad field.
 */
static inline uint8_t Avtp_Gbb_GetPad(const Avtp_Gbb_t* msg) {
    return (uint8_t) __Avtp_Gbb_GetField(AVTP_GBB_FIELD_PAD);
}

/**
 * Returns the message timestamp valid flag (mtv) from an ACF_GBB message
 * header.
 * 
 * @param msg Pointer to an ACF_GBB message.
 * @returns The value of the mtv flag.
 */
static inline bool Avtp_Gbb_IsMtv(const Avtp_Gbb_t* msg) {
    return (bool) __Avtp_Gbb_GetField(AVTP_GBB_FIELD_MTV);
}

/**
 * Returns the value of the byte_bus_id field from an ACF_GBB message header.
 * 
 * @param msg Pointer to an ACF_GBB message.
 * @returns The value of the byte_bus_id field.
 */
static inline uint16_t Avtp_Gbb_GetByteBusId(const Avtp_Gbb_t* msg) {
    return (uint16_t) __Avtp_Gbb_GetField(AVTP_GBB_FIELD_BYTE_BUS_ID);
}

/**
 * Returns the value of the message_timestamp field from an ACF_GBB message
 * header.
 * 
 * @param msg Pointer to an ACF_GBB message.
 * @returns The value of the message_timestamp field.
 */
static inline uint64_t Avtp_Gbb_GetMessageTimestamp(const Avtp_Gbb_t* msg) {
    return (uint64_t) __Avtp_Gbb_GetField(AVTP_GBB_FIELD_MESSAGE_TIMESTAMP);
}

/**
 * Returns the value of the evt field from an ACF_GBB message header.
 * 
 * @param msg Pointer to an ACF_GBB message.
 * @returns The value of the evt field.
 */
static inline uint8_t Avtp_Gbb_GetEvt(const Avtp_Gbb_t* msg) {
    return (uint8_t) __Avtp_Gbb_GetField(AVTP_GBB_FIELD_EVT);
}

/**
 * Returns the value of the hs field from an ACF_GBB message header.
 * 
 * @param msg Pointer to an ACF_GBB message.
 * @returns The value of the hs field.
 */
static inline bool Avtp_Gbb_IsHs(const Avtp_Gbb_t* msg) {
    return (bool) __Avtp_Gbb_GetField(AVTP_GBB_FIELD_HS);
}

/**
 * Returns the value of the cs field from an ACF_GBB message header.
 * 
 * @param msg Pointer to an ACF_GBB message.
 * @returns The value of the cs field.
 */
static inline bool Avtp_Gbb_IsCs(const Avtp_Gbb_t* msg) {
    return (bool) __Avtp_Gbb_GetField(AVTP_GBB_FIELD_CS);
}

/**
 * Returns the value of the transaction_num field from an ACF_GBB message
 * header.
 * 
 * @param msg Pointer to an ACF_GBB message.
 * @returns The value of the transaction_num field.
 */
static inline uint8_t Avtp_Gbb_GetTransactionNum(const Avtp_Gbb_t* msg) {
    return (uint8_t) __Avtp_Gbb_GetField(AVTP_GBB_FIELD_TRANSACTION_NUM);
}

/**
 * Returns the value of the op flag from an ACF_GBB message header.
 * 
 * @param msg Pointer to an ACF_GBB message.
 * @returns The value of the op flag.
 */
static inline bool Avtp_Gbb_IsOp(const Avtp_Gbb_t* msg) {
    return (bool) __Avtp_Gbb_GetField(AVTP_GBB_FIELD_OP);
}

/**
 * Returns the value of the rsp flag from an ACF_GBB message header.
 * 
 * @param msg Pointer to an ACF_GBB message.
 * @returns The value of the rsp flag.
 */
static inline bool Avtp_Gbb_IsRsp(const Avtp_Gbb_t* msg) {
    return (bool) __Avtp_Gbb_GetField(AVTP_GBB_FIELD_RSP);
}

/**
 * Returns the value of the err flag from an ACF_GBB message header.
 * 
 * @param msg Pointer to an ACF_GBB message.
 * @returns The value of the err flag.
 */
static inline bool Avtp_Gbb_IsErr(const Avtp_Gbb_t* msg) {
    return (bool) __Avtp_Gbb_GetField(AVTP_GBB_FIELD_ERR);
}

/**
 * Returns the value of the ms flag from an ACF_GBB message header.
 * 
 * @param msg Pointer to an ACF_GBB message.
 * @returns The value of the ms flag.
 */
static inline bool Avtp_Gbb_IsMs(const Avtp_Gbb_t* msg) {
    return (bool) __Avtp_Gbb_GetField(AVTP_GBB_FIELD_MS);
}

/**
 * Returns the value of the read_size/segment_num field from an ACF_GBB message
 * header.
 * 
 * @param msg Pointer to an ACF_GBB message.
 * @returns The value of the read_size/segment_num field.
 */
static inline uint16_t Avtp_Gbb_GetReadSize(const Avtp_Gbb_t* msg) {
    return (uint16_t) __Avtp_Gbb_GetField(AVTP_GBB_FIELD_READ_SIZE_SEGMENT_NUM);
}

/**
 * Returns the value of the read_size/segment_num field from an ACF_GBB message
 * header.
 * 
 * @param msg Pointer to an ACF_GBB message.
 * @returns The value of the read_size/segment_num field.
 */
static inline uint16_t Avtp_Gbb_GetSegmentNum(const Avtp_Gbb_t* msg) {
    return (uint16_t) __Avtp_Gbb_GetField(AVTP_GBB_FIELD_READ_SIZE_SEGMENT_NUM);
}

/**
 * Returns the paload length from an ACF_GBB message (in bytes). This is
 * calculated based on the value of the acf_msg_length field in the header
 * as well as the value of the pad field.
 * 
 * @param msg Pointer to an ACF_GBB message.
 * @returns The payload length in bytes.
 */
static inline uint16_t Avtp_Gbb_GetPayloadLen(const Avtp_Gbb_t* msg) {
    return (uint16_t) (__Avtp_Gbb_GetField(AVTP_GBB_FIELD_ACF_MSG_LENGTH) * AVTP_QUADLET_SIZE
           - AVTP_GBB_HEADER_LEN
           - __Avtp_Gbb_GetField(AVTP_GBB_FIELD_PAD));
}

/**
 * Returns the total message length from an ACF_GBB message (in bytes)
 * including header and payload section.
 * 
 * @param msg Pointer to an ACF_GBB message.
 * @returns The total message length in bytes.
 */
static inline uint16_t Avtp_Gbb_GetLen(const Avtp_Gbb_t* msg) {
    return (uint16_t) (__Avtp_Gbb_GetField(AVTP_GBB_FIELD_ACF_MSG_LENGTH) * AVTP_QUADLET_SIZE);
}

/**
 * Sets the value of the mtv flag in an ACF_GBB message header.
 * 
 * @param msg Pointer to an ACF_GBB message.
 * @param mtv The value to set.
 */
static inline void Avtp_Gbb_SetMtv(Avtp_Gbb_t* msg, bool mtv) {
    __Avtp_Gbb_SetField(AVTP_GBB_FIELD_MTV, mtv);
}

/**
 * Sets the value of the byte_bus_id field in an ACF_GBB message header.
 * 
 * @param msg Pointer to an ACF_GBB message.
 * @param byteBusId The value to set.
 */
static inline void Avtp_Gbb_SetByteBusId(Avtp_Gbb_t* msg, uint16_t byteBusId) {
    __Avtp_Gbb_SetField(AVTP_GBB_FIELD_BYTE_BUS_ID, byteBusId);
}

/**
 * Sets the value of the message_timestamp field in an ACF_GBB message header.
 * 
 * @param msg Pointer to an ACF_GBB message.
 * @param messageTimestamp The value to set.
 */
static inline void Avtp_Gbb_SetMessageTimestamp(Avtp_Gbb_t* msg, uint64_t messageTimestamp) {
    __Avtp_Gbb_SetField(AVTP_GBB_FIELD_MESSAGE_TIMESTAMP, messageTimestamp);
}

/**
 * Sets the value of the evt field in an ACF_GBB message header.
 * 
 * @param msg Pointer to an ACF_GBB message.
 * @param evt The value to set.
 */

static inline void Avtp_Gbb_SetEvt(Avtp_Gbb_t* msg, uint8_t evt) {
    __Avtp_Gbb_SetField(AVTP_GBB_FIELD_EVT, evt);
}

/**
 * Sets the value of the hs flag in an ACF_GBB message header.
 * 
 * @param msg Pointer to an ACF_GBB message.
 * @param hs The value to set.
 */
static inline void Avtp_Gbb_SetHs(Avtp_Gbb_t* msg, bool hs) {
    __Avtp_Gbb_SetField(AVTP_GBB_FIELD_HS, hs);
}


/**
 * Sets the value of the cs flag in an ACF_GBB message header.
 * 
 * @param msg Pointer to an ACF_GBB message.
 * @param cs The value to set.
 */
static inline void Avtp_Gbb_SetCs(Avtp_Gbb_t* msg, bool cs) {
    __Avtp_Gbb_SetField(AVTP_GBB_FIELD_CS, cs);
}

/**
 * Sets the value of the transaction_num field in an ACF_GBB message header.
 * 
 * @param msg Pointer to an ACF_GBB message.
 * @param transactionNum The value to set.
 */
static inline void Avtp_Gbb_SetTransactionNum(Avtp_Gbb_t* msg, uint8_t transactionNum) {
    __Avtp_Gbb_SetField(AVTP_GBB_FIELD_TRANSACTION_NUM, transactionNum);
}

/**
 * Sets the value of the op flag in an ACF_GBB message header.
 * 
 * @param msg Pointer to an ACF_GBB message.
 * @param op The value to set.
 */
static inline void Avtp_Gbb_SetOp(Avtp_Gbb_t* msg, bool op) {
    __Avtp_Gbb_SetField(AVTP_GBB_FIELD_OP, op);
}

/**
 * Sets the value of the rsp flag in an ACF_GBB message header.
 * 
 * @param msg Pointer to an ACF_GBB message.
 * @param rsp The value to set.
 */
static inline void Avtp_Gbb_SetRsp(Avtp_Gbb_t* msg, bool rsp) {
    __Avtp_Gbb_SetField(AVTP_GBB_FIELD_RSP, rsp);
}

/**
 * Sets the value of the err flag in an ACF_GBB message header.
 * 
 * @param msg Pointer to an ACF_GBB message.
 * @param err The value to set.
 */
static inline void Avtp_Gbb_SetErr(Avtp_Gbb_t* msg, bool err) {
    __Avtp_Gbb_SetField(AVTP_GBB_FIELD_ERR, err);
}

/**
 * Sets the value of the ms flag in an ACF_GBB message header.
 * 
 * @param msg Pointer to an ACF_GBB message.
 * @param ms The value to set.
 */
static inline void Avtp_Gbb_SetMs(Avtp_Gbb_t* msg, bool ms) {
    __Avtp_Gbb_SetField(AVTP_GBB_FIELD_MS, ms);
}

/**
 * Sets the value of the read_size/segment_num field in an ACF_GBB message header.
 * 
 * @param msg Pointer to an ACF_GBB message.
 * @param readSize The value to set.
 */
static inline void Avtp_Gbb_SetReadSize(Avtp_Gbb_t* msg, uint16_t readSize) {
    __Avtp_Gbb_SetField(AVTP_GBB_FIELD_READ_SIZE_SEGMENT_NUM, readSize);
}

/**
 * Sets the value of the read_size/segment_num field in an ACF_GBB message header.
 * 
 * @param msg Pointer to an ACF_GBB message.
 * @param segmentNum The value to set.
 */
static inline void Avtp_Gbb_SetSegmentNum(Avtp_Gbb_t* msg, uint16_t segmentNum) {
    __Avtp_Gbb_SetField(AVTP_GBB_FIELD_READ_SIZE_SEGMENT_NUM, segmentNum);
}

/**
 * Sets the value of the acf_msg_length field in an ACF_GBB message header
 * based on the given payload length. This function also calculates the
 * required padding and sets the value of the pad field accordingly.
 * 
 * @param msg Pointer to an ACF_GBB message.
 * @param payloadLen The length of the payload in bytes.
 */
static inline void Avtp_Gbb_SetPayloadLen(Avtp_Gbb_t* msg, uint16_t payloadLen) {
    uint16_t msgLenBytes = AVTP_GBB_HEADER_LEN + payloadLen;
    uint8_t pad = (4 - (msgLenBytes % 4)) % 4;
    uint16_t msgLenQuadlets = (msgLenBytes + pad) / 4;
    __Avtp_Gbb_SetField(AVTP_GBB_FIELD_ACF_MSG_LENGTH, msgLenQuadlets);
    __Avtp_Gbb_SetField(AVTP_GBB_FIELD_PAD, pad);
}

#ifdef __cplusplus
}
#endif
