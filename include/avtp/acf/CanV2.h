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
} Avtp_CanV2_t;

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
} Avtp_CanV2Field_t;

/**
 * This table describes all the offsets of the ACF_CAN_V2 header fields.
 */
static const Avtp_FieldDescriptor_t __AVTP_CAN_V2_FIELDS[AVTP_CAN_V2_FIELD_MAX] =
{
    /* ACF common header fields */
    [AVTP_CAN_V2_FIELD_ACF_MSG_TYPE]       = { .quadlet = 0, .offset =  0, .bits =  7 },
    [AVTP_CAN_V2_FIELD_ACF_MSG_LENGTH]     = { .quadlet = 0, .offset =  7, .bits =  9 },
    /* ACF CAN header fields */
    [AVTP_CAN_V2_FIELD_PAD]                = { .quadlet = 0, .offset = 16, .bits =  2 },
    [AVTP_CAN_V2_FIELD_MTV]                = { .quadlet = 0, .offset = 18, .bits =  1 },
    [AVTP_CAN_V2_FIELD_RTR]                = { .quadlet = 0, .offset = 19, .bits =  1 },
    [AVTP_CAN_V2_FIELD_EFF]                = { .quadlet = 0, .offset = 20, .bits =  1 },
    [AVTP_CAN_V2_FIELD_CAN_BUS_ID]         = { .quadlet = 0, .offset = 21, .bits = 11 },
    [AVTP_CAN_V2_FIELD_MESSAGE_TIMESTAMP]  = { .quadlet = 1, .offset =  0, .bits = 64 },
    [AVTP_CAN_V2_FIELD_BRS]                = { .quadlet = 3, .offset =  0, .bits =  1 },
    [AVTP_CAN_V2_FIELD_FDF]                = { .quadlet = 3, .offset =  1, .bits =  1 },
    [AVTP_CAN_V2_FIELD_ESI]                = { .quadlet = 3, .offset =  2, .bits =  1 },
    [AVTP_CAN_V2_FIELD_CAN_IDENTIFIER]     = { .quadlet = 3, .offset =  3, .bits = 29 },
};

/**
 * Macro to get the value of a field from an ACF_CAN_V2 message header.
 *
 * @note This macro should not be used directly, instead use the field specific
 * getter functions defined below.
 */
#define __Avtp_CanV2_GetField(field) \
        (Avtp_GetField(__AVTP_CAN_V2_FIELDS, AVTP_CAN_V2_FIELD_MAX, (uint8_t*)msg, field))

/**
 * Macro to set the value of a field in an ACF_CAN_V2 message header.
 *
 * @note This macro should not be used directly, instead use the field specific
 * setter functions defined below.
 */
#define __Avtp_CanV2_SetField(field, value) \
        (Avtp_SetField(__AVTP_CAN_V2_FIELDS, AVTP_CAN_V2_FIELD_MAX, (uint8_t*)msg, field, value))

/**
 * Initializes an ACF_CAN_V2 message with default values for the header fields
 * including acf_msg_type and acf_msg_length.
 *
 * @param msg Pointer to the ACF_CAN_V2 message to initialize.
 */
static inline void Avtp_CanV2_Init(Avtp_CanV2_t* msg) {
    memset(msg, 0, sizeof(Avtp_CanV2_t));
    __Avtp_CanV2_SetField(AVTP_CAN_V2_FIELD_ACF_MSG_TYPE, AVTP_ACF_TYPE_CAN_V2);
    __Avtp_CanV2_SetField(AVTP_CAN_V2_FIELD_ACF_MSG_LENGTH, AVTP_CAN_V2_HEADER_LEN / AVTP_QUADLET_SIZE);
}

/**
 * Returns the pad field from an ACF_CAN_V2 message header.
 *
 * @param msg Pointer to an ACF_CAN_V2 message.
 * @returns The value of the pad field.
 */
static inline uint8_t Avtp_CanV2_GetPad(const Avtp_CanV2_t* msg) {
    return __Avtp_CanV2_GetField(AVTP_CAN_V2_FIELD_PAD);
}

/**
 * Returns the message timestamp valid flag (mtv) from an ACF_CAN_V2 message
 * header.
 *
 * @param msg Pointer to an ACF_CAN_V2 message.
 * @returns The value of the mtv flag.
 */
static inline bool Avtp_CanV2_IsMtv(const Avtp_CanV2_t* msg) {
    return __Avtp_CanV2_GetField(AVTP_CAN_V2_FIELD_MTV);
}

/**
 * Returns the remote transmission request flag (rtr) from an ACF_CAN_V2 message
 * header.
 *
 * @param msg Pointer to an ACF_CAN_V2 message.
 * @returns The value of the rtr flag.
 */
static inline bool Avtp_CanV2_IsRtr(const Avtp_CanV2_t* msg) {
    return __Avtp_CanV2_GetField(AVTP_CAN_V2_FIELD_RTR);
}

/**
 * Returns the extended frame format flag (eff) from an ACF_CAN_V2 message
 * header.
 *
 * @param msg Pointer to an ACF_CAN_V2 message.
 * @returns The value of the eff flag.
 */
static inline bool Avtp_CanV2_IsEff(const Avtp_CanV2_t* msg) {
    return __Avtp_CanV2_GetField(AVTP_CAN_V2_FIELD_EFF);
}

/**
 * Returns the value of the can_bus_id field from an ACF_CAN_V2 message header.
 *
 * @param msg Pointer to an ACF_CAN_V2 message.
 * @returns The value of the can_bus_id field.
 */
static inline uint16_t Avtp_CanV2_GetCanBusId(const Avtp_CanV2_t* msg) {
    return __Avtp_CanV2_GetField(AVTP_CAN_V2_FIELD_CAN_BUS_ID);
}

/**
 * Returns the value of the message_timestamp field from an ACF_CAN_V2 message
 * header.
 *
 * @param msg Pointer to an ACF_CAN_V2 message.
 * @returns The value of the message_timestamp field.
 */
static inline uint64_t Avtp_CanV2_GetMessageTimestamp(const Avtp_CanV2_t* msg) {
    return __Avtp_CanV2_GetField(AVTP_CAN_V2_FIELD_MESSAGE_TIMESTAMP);
}

/**
 * Returns the bit rate switch flag (brs) from an ACF_CAN_V2 message header.
 *
 * @param msg Pointer to an ACF_CAN_V2 message.
 * @returns The value of the brs flag.
 */
static inline bool Avtp_CanV2_IsBrs(const Avtp_CanV2_t* msg) {
    return __Avtp_CanV2_GetField(AVTP_CAN_V2_FIELD_BRS);
}

/**
 * Returns the FD frame flag (fdf) from an ACF_CAN_V2 message header.
 *
 * @param msg Pointer to an ACF_CAN_V2 message.
 * @returns The value of the fdf flag.
 */
static inline bool Avtp_CanV2_IsFdf(const Avtp_CanV2_t* msg) {
    return __Avtp_CanV2_GetField(AVTP_CAN_V2_FIELD_FDF);
}

/**
 * Returns the error state indicator flag (esi) from an ACF_CAN_V2 message header.
 *
 * @param msg Pointer to an ACF_CAN_V2 message.
 * @returns The value of the esi flag.
 */
static inline bool Avtp_CanV2_IsEsi(const Avtp_CanV2_t* msg) {
    return __Avtp_CanV2_GetField(AVTP_CAN_V2_FIELD_ESI);
}

/**
 * Returns the value of the can_identifier field from an ACF_CAN_V2 message header.
 *
 * @param msg Pointer to an ACF_CAN_V2 message.
 * @returns The value of the can_identifier field.
 */
static inline uint32_t Avtp_CanV2_GetCanIdentifier(const Avtp_CanV2_t* msg) {
    return __Avtp_CanV2_GetField(AVTP_CAN_V2_FIELD_CAN_IDENTIFIER);
}

/**
 * Returns the payload length from an ACF_CAN_V2 message (in bytes). This is
 * calculated based on the value of the acf_msg_length field in the header
 * as well as the value of the pad field.
 *
 * @param msg Pointer to an ACF_CAN_V2 message.
 * @returns The payload length in bytes.
 */
static inline uint16_t Avtp_CanV2_GetPayloadLen(const Avtp_CanV2_t* msg) {
    return __Avtp_CanV2_GetField(AVTP_CAN_V2_FIELD_ACF_MSG_LENGTH) * AVTP_QUADLET_SIZE
           - AVTP_CAN_V2_HEADER_LEN
           - __Avtp_CanV2_GetField(AVTP_CAN_V2_FIELD_PAD);
}

/**
 * Returns the total message length from an ACF_CAN_V2 message (in bytes)
 * including header and payload section.
 *
 * @param msg Pointer to an ACF_CAN_V2 message.
 * @returns The total message length in bytes.
 */
static inline uint16_t Avtp_CanV2_GetLen(const Avtp_CanV2_t* msg) {
    return __Avtp_CanV2_GetField(AVTP_CAN_V2_FIELD_ACF_MSG_LENGTH) * AVTP_QUADLET_SIZE;
}

/**
 * Sets the value of the mtv flag in an ACF_CAN_V2 message header.
 *
 * @param msg Pointer to an ACF_CAN_V2 message.
 * @param mtv The value to set.
 */
static inline void Avtp_CanV2_SetMtv(Avtp_CanV2_t* msg, bool mtv) {
    __Avtp_CanV2_SetField(AVTP_CAN_V2_FIELD_MTV, mtv);
}

/**
 * Sets the value of the rtr flag in an ACF_CAN_V2 message header.
 *
 * @param msg Pointer to an ACF_CAN_V2 message.
 * @param rtr The value to set.
 */
static inline void Avtp_CanV2_SetRtr(Avtp_CanV2_t* msg, bool rtr) {
    __Avtp_CanV2_SetField(AVTP_CAN_V2_FIELD_RTR, rtr);
}

/**
 * Sets the value of the eff flag in an ACF_CAN_V2 message header.
 *
 * @param msg Pointer to an ACF_CAN_V2 message.
 * @param eff The value to set.
 */
static inline void Avtp_CanV2_SetEff(Avtp_CanV2_t* msg, bool eff) {
    __Avtp_CanV2_SetField(AVTP_CAN_V2_FIELD_EFF, eff);
}

/**
 * Sets the value of the can_bus_id field in an ACF_CAN_V2 message header.
 *
 * @param msg Pointer to an ACF_CAN_V2 message.
 * @param canBusId The value to set.
 */
static inline void Avtp_CanV2_SetCanBusId(Avtp_CanV2_t* msg, uint16_t canBusId) {
    __Avtp_CanV2_SetField(AVTP_CAN_V2_FIELD_CAN_BUS_ID, canBusId);
}

/**
 * Sets the value of the message_timestamp field in an ACF_CAN_V2 message header.
 *
 * @param msg Pointer to an ACF_CAN_V2 message.
 * @param messageTimestamp The value to set.
 */
static inline void Avtp_CanV2_SetMessageTimestamp(Avtp_CanV2_t* msg, uint64_t messageTimestamp) {
    __Avtp_CanV2_SetField(AVTP_CAN_V2_FIELD_MESSAGE_TIMESTAMP, messageTimestamp);
}

/**
 * Sets the value of the brs flag in an ACF_CAN_V2 message header.
 *
 * @param msg Pointer to an ACF_CAN_V2 message.
 * @param brs The value to set.
 */
static inline void Avtp_CanV2_SetBrs(Avtp_CanV2_t* msg, bool brs) {
    __Avtp_CanV2_SetField(AVTP_CAN_V2_FIELD_BRS, brs);
}

/**
 * Sets the value of the fdf flag in an ACF_CAN_V2 message header.
 *
 * @param msg Pointer to an ACF_CAN_V2 message.
 * @param fdf The value to set.
 */
static inline void Avtp_CanV2_SetFdf(Avtp_CanV2_t* msg, bool fdf) {
    __Avtp_CanV2_SetField(AVTP_CAN_V2_FIELD_FDF, fdf);
}

/**
 * Sets the value of the esi flag in an ACF_CAN_V2 message header.
 *
 * @param msg Pointer to an ACF_CAN_V2 message.
 * @param esi The value to set.
 */
static inline void Avtp_CanV2_SetEsi(Avtp_CanV2_t* msg, bool esi) {
    __Avtp_CanV2_SetField(AVTP_CAN_V2_FIELD_ESI, esi);
}

/**
 * Sets the value of the can_identifier field in an ACF_CAN_V2 message header.
 *
 * @param msg Pointer to an ACF_CAN_V2 message.
 * @param canIdentifier The value to set.
 */
static inline void Avtp_CanV2_SetCanIdentifier(Avtp_CanV2_t* msg, uint32_t canIdentifier) {
    __Avtp_CanV2_SetField(AVTP_CAN_V2_FIELD_CAN_IDENTIFIER, canIdentifier);
}

/**
 * Sets the value of the acf_msg_length field in an ACF_CAN_V2 message header
 * based on the given payload length. This function also calculates the
 * required padding and sets the value of the pad field accordingly.
 *
 * @param msg Pointer to an ACF_CAN_V2 message.
 * @param payloadLen The length of the payload in bytes.
 */
static inline void Avtp_CanV2_SetPayloadLen(Avtp_CanV2_t* msg, uint16_t payloadLen) {
    uint16_t msgLenBytes = AVTP_CAN_V2_HEADER_LEN + payloadLen;
    uint8_t pad = (4 - (msgLenBytes % 4)) % 4;
    uint16_t msgLenQuadlets = (msgLenBytes + pad) / 4;
    __Avtp_CanV2_SetField(AVTP_CAN_V2_FIELD_ACF_MSG_LENGTH, msgLenQuadlets);
    __Avtp_CanV2_SetField(AVTP_CAN_V2_FIELD_PAD, pad);
}

#ifdef __cplusplus
}
#endif
