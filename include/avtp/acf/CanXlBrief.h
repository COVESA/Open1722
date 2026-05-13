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
 * @file This file contains functions for de-/serialization of the ACF_CAN_XL_BRIEF
 * message format (CAN XL Brief). For details see IEEE Std. 1722-2025,
 * chapter 9.4.19.
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
 * Length of ACF_CAN_XL_BRIEF message header in bytes.
 */
#define AVTP_CANXL_BRIEF_HEADER_LEN (4 * AVTP_QUADLET_SIZE)

/**
 * ACF_CAN_XL_BRIEF message structure suitable for in-place de-/serialization of fields
 * in the ACF_CAN_XL_BRIEF message header.
 */
typedef struct {
    uint8_t header[AVTP_CANXL_BRIEF_HEADER_LEN];
    uint8_t payload[0];
} Avtp_CanXlBrief_t;

/**
 * Fields encoded in the ACF_CAN_XL_BRIEF header.
 */
typedef enum {
    /* ACF common header fields */
    AVTP_CANXL_BRIEF_FIELD_ACF_MSG_TYPE = 0,
    AVTP_CANXL_BRIEF_FIELD_ACF_MSG_LENGTH,
    /* ACF CAN_XL_BRIEF header fields */
    AVTP_CANXL_BRIEF_FIELD_PAD,
    AVTP_CANXL_BRIEF_FIELD_MTV,
    AVTP_CANXL_BRIEF_FIELD_CAN_BUS_ID,
    AVTP_CANXL_BRIEF_FIELD_VCID,
    AVTP_CANXL_BRIEF_FIELD_SDT,
    AVTP_CANXL_BRIEF_FIELD_RRS,
    AVTP_CANXL_BRIEF_FIELD_SEC,
    AVTP_CANXL_BRIEF_FIELD_PRIORITY_ID,
    AVTP_CANXL_BRIEF_FIELD_ACCEPTANCE_FIELD,
    AVTP_CANXL_BRIEF_FIELD_TRANSACTION_NUM,
    AVTP_CANXL_BRIEF_FIELD_MS,
    AVTP_CANXL_BRIEF_FIELD_SEGMENT_NUM,
    /* Count number of fields for bound checks */
    AVTP_CANXL_BRIEF_FIELD_MAX
} Avtp_CanXlBriefField_t;

/**
 * This table describes all the offsets of the ACF_CAN_XL_BRIEF header fields.
 */
static const Avtp_FieldDescriptor_t __AVTP_CANXL_BRIEF_FIELDS[AVTP_CANXL_BRIEF_FIELD_MAX] =
{
    /* ACF common header fields */
    [AVTP_CANXL_BRIEF_FIELD_ACF_MSG_TYPE]           = { .quadlet = 0, .offset =  0, .bits = 7 },
    [AVTP_CANXL_BRIEF_FIELD_ACF_MSG_LENGTH]         = { .quadlet = 0, .offset =  7, .bits = 9 },
    /* ACF CAN_XL_BRIEF header fields */
    [AVTP_CANXL_BRIEF_FIELD_PAD]                    = { .quadlet = 0, .offset = 16, .bits =   2 },
    [AVTP_CANXL_BRIEF_FIELD_MTV]                    = { .quadlet = 0, .offset = 18, .bits =   1 },
    [AVTP_CANXL_BRIEF_FIELD_CAN_BUS_ID]             = { .quadlet = 0, .offset = 21, .bits =  11 },
    [AVTP_CANXL_BRIEF_FIELD_VCID]                   = { .quadlet = 1, .offset =  0, .bits =   8 },
    [AVTP_CANXL_BRIEF_FIELD_SDT]                    = { .quadlet = 1, .offset =  8, .bits =   8 },
    [AVTP_CANXL_BRIEF_FIELD_RRS]                    = { .quadlet = 1, .offset = 19, .bits =   1 },
    [AVTP_CANXL_BRIEF_FIELD_SEC]                    = { .quadlet = 1, .offset = 20, .bits =   1 },
    [AVTP_CANXL_BRIEF_FIELD_PRIORITY_ID]            = { .quadlet = 1, .offset = 21, .bits =  11 },
    [AVTP_CANXL_BRIEF_FIELD_ACCEPTANCE_FIELD]       = { .quadlet = 2, .offset =  0, .bits =  32 },
    [AVTP_CANXL_BRIEF_FIELD_TRANSACTION_NUM]        = { .quadlet = 3, .offset =  8, .bits =   8 },
    [AVTP_CANXL_BRIEF_FIELD_MS]                     = { .quadlet = 3, .offset = 19, .bits =   1 },
    [AVTP_CANXL_BRIEF_FIELD_SEGMENT_NUM]            = { .quadlet = 3, .offset = 20, .bits =  12 },
};

/**
 * Macro to get the value of a field from an ACF_CAN_XL_BRIEF message header.
 * 
 * @note This macro should not be used directly, instead use the field specific
 * getter functions defined below.
 */
#define __Avtp_CanXlBrief_GetField(field) \
        (Avtp_GetField(__AVTP_CANXL_BRIEF_FIELDS, AVTP_CANXL_BRIEF_FIELD_MAX, (uint8_t*)msg, field))

/**
 * Macro to set the value of a field in an ACF_CAN_XL_BRIEF message header.
 * 
 * @note This macro should not be used directly, instead use the field specific
 * setter functions defined below.
 */
#define __Avtp_CanXlBrief_SetField(field, value) \
        (Avtp_SetField(__AVTP_CANXL_BRIEF_FIELDS, AVTP_CANXL_BRIEF_FIELD_MAX, (uint8_t*)msg, field, value))

/**
 * Initializes an ACF_CAN_XL_BRIEF message with default values for the header fields
 * including acf_msg_type and acf_msg_length.
 *
 * @param msg Pointer to the ACF_CAN_XL_BRIEF message to initialize.
 */
static inline void Avtp_CanXlBrief_Init(Avtp_CanXlBrief_t* msg) {
    memset(msg, 0, sizeof(Avtp_CanXlBrief_t));
    __Avtp_CanXlBrief_SetField(AVTP_CANXL_BRIEF_FIELD_ACF_MSG_TYPE, AVTP_ACF_TYPE_CAN_XL_BRIEF);
    __Avtp_CanXlBrief_SetField(AVTP_CANXL_BRIEF_FIELD_ACF_MSG_LENGTH, AVTP_CANXL_BRIEF_HEADER_LEN / AVTP_QUADLET_SIZE);
}

/**
 * Returns the pad field from an ACF_CAN_XL_BRIEF message header.
 * 
 * @param msg Pointer to an ACF_CAN_XL_BRIEF message.
 * @returns The value of the pad field.
 */
static inline uint8_t Avtp_CanXlBrief_GetPad(const Avtp_CanXlBrief_t* msg) {
    return (uint8_t) __Avtp_CanXlBrief_GetField(AVTP_CANXL_BRIEF_FIELD_PAD);
}

/**
 * Returns the message timestamp valid flag (mtv) from an ACF_CAN_XL_BRIEF message
 * header.
 * 
 * @param msg Pointer to an ACF_CAN_XL_BRIEF message.
 * @returns The value of the mtv flag.
 */
static inline bool Avtp_CanXlBrief_IsMtv(const Avtp_CanXlBrief_t* msg) {
    return (bool) __Avtp_CanXlBrief_GetField(AVTP_CANXL_BRIEF_FIELD_MTV);
}

/**
 * Returns the value of the can_bus_id field from an ACF_CAN_XL_BRIEF message header.
 * 
 * @param msg Pointer to an ACF_CAN_XL_BRIEF message.
 * @returns The value of the can_bus_id field.
 */
static inline uint16_t Avtp_CanXlBrief_GetCanBusId(const Avtp_CanXlBrief_t* msg) {
    return (uint16_t) __Avtp_CanXlBrief_GetField(AVTP_CANXL_BRIEF_FIELD_CAN_BUS_ID);
}

/**
 * Returns the value of the vcid field from an ACF_CAN_XL_BRIEF message header.
 * 
 * @param msg Pointer to an ACF_CAN_XL_BRIEF message.
 * @returns The value of the vcid field.
 */
static inline uint8_t Avtp_CanXlBrief_GetVcid(const Avtp_CanXlBrief_t* msg) {
    return (uint8_t) __Avtp_CanXlBrief_GetField(AVTP_CANXL_BRIEF_FIELD_VCID);
}

/**
 * Returns the value of the sdt field from an ACF_CAN_XL_BRIEF message header.
 * 
 * @param msg Pointer to an ACF_CAN_XL_BRIEF message.
 * @returns The value of the sdt field.
 */
static inline uint8_t Avtp_CanXlBrief_GetSdt(const Avtp_CanXlBrief_t* msg) {
    return (uint8_t) __Avtp_CanXlBrief_GetField(AVTP_CANXL_BRIEF_FIELD_SDT);
}

/**
 * Returns the value of the rrs flag from an ACF_CAN_XL_BRIEF message header.
 * 
 * @param msg Pointer to an ACF_CAN_XL_BRIEF message.
 * @returns The value of the rrs flag.
 */
static inline bool Avtp_CanXlBrief_IsRrs(const Avtp_CanXlBrief_t* msg) {
    return (bool) __Avtp_CanXlBrief_GetField(AVTP_CANXL_BRIEF_FIELD_RRS);
}

/**
 * Returns the value of the sec flag from an ACF_CAN_XL_BRIEF message header.
 * 
 * @param msg Pointer to an ACF_CAN_XL_BRIEF message.
 * @returns The value of the sec flag.
 */
static inline bool Avtp_CanXlBrief_IsSec(const Avtp_CanXlBrief_t* msg) {
    return (bool) __Avtp_CanXlBrief_GetField(AVTP_CANXL_BRIEF_FIELD_SEC);
}

/**
 * Returns the value of the priority_id field from an ACF_CAN_XL_BRIEF message
 * header.
 * 
 * @param msg Pointer to an ACF_CAN_XL_BRIEF message.
 * @returns The value of the priority_id field.
 */
static inline uint16_t Avtp_CanXlBrief_GetPriorityId(const Avtp_CanXlBrief_t* msg) {
    return (uint16_t) __Avtp_CanXlBrief_GetField(AVTP_CANXL_BRIEF_FIELD_PRIORITY_ID);
}

/**
 * Returns the value of the acceptance_field from an ACF_CAN_XL_BRIEF message header.
 * 
 * @param msg Pointer to an ACF_CAN_XL_BRIEF message.
 * @returns The value of the acceptance_field.
 */
static inline uint32_t Avtp_CanXlBrief_GetAcceptanceField(const Avtp_CanXlBrief_t* msg) {
    return (uint32_t) __Avtp_CanXlBrief_GetField(AVTP_CANXL_BRIEF_FIELD_ACCEPTANCE_FIELD);
}

/**
 * Returns the value of the transaction_num field from an ACF_CAN_XL_BRIEF message
 * header.
 * 
 * @param msg Pointer to an ACF_CAN_XL_BRIEF message.
 * @returns The value of the transaction_num field.
 */
static inline uint8_t Avtp_CanXlBrief_GetTransactionNum(const Avtp_CanXlBrief_t* msg) {
    return (uint8_t) __Avtp_CanXlBrief_GetField(AVTP_CANXL_BRIEF_FIELD_TRANSACTION_NUM);
}

/**
 * Returns the value of the ms flag from an ACF_CAN_XL_BRIEF message header.
 * 
 * @param msg Pointer to an ACF_CAN_XL_BRIEF message.
 * @returns The value of the ms flag.
 */
static inline bool Avtp_CanXlBrief_IsMs(const Avtp_CanXlBrief_t* msg) {
    return (bool) __Avtp_CanXlBrief_GetField(AVTP_CANXL_BRIEF_FIELD_MS);
}

/**
 * Returns the value of the segment_num field from an ACF_CAN_XL_BRIEF message
 * header.
 * 
 * @param msg Pointer to an ACF_CAN_XL_BRIEF message.
 * @returns The value of the segment_num field.
 */
static inline uint16_t Avtp_CanXlBrief_GetSegmentNum(const Avtp_CanXlBrief_t* msg) {
    return (uint16_t) __Avtp_CanXlBrief_GetField(AVTP_CANXL_BRIEF_FIELD_SEGMENT_NUM);
}

/**
 * Returns the payload length from an ACF_CAN_XL_BRIEF message (in bytes). This is
 * calculated based on the value of the acf_msg_length field in the header
 * as well as the value of the pad field.
 * 
 * @param msg Pointer to an ACF_CAN_XL_BRIEF message.
 * @returns The payload length in bytes.
 */
static inline uint16_t Avtp_CanXlBrief_GetPayloadLen(const Avtp_CanXlBrief_t* msg) {
    return (uint16_t) (__Avtp_CanXlBrief_GetField(AVTP_CANXL_BRIEF_FIELD_ACF_MSG_LENGTH) * AVTP_QUADLET_SIZE
           - AVTP_CANXL_BRIEF_HEADER_LEN
           - __Avtp_CanXlBrief_GetField(AVTP_CANXL_BRIEF_FIELD_PAD));
}

/**
 * Returns the total message length from an ACF_CAN_XL_BRIEF message (in bytes)
 * including header and payload section.
 * 
 * @param msg Pointer to an ACF_CAN_XL_BRIEF message.
 * @returns The total message length in bytes.
 */
static inline uint16_t Avtp_CanXlBrief_GetLen(const Avtp_CanXlBrief_t* msg) {
    return (uint16_t) (__Avtp_CanXlBrief_GetField(AVTP_CANXL_BRIEF_FIELD_ACF_MSG_LENGTH) * AVTP_QUADLET_SIZE);
}

/**
 * Sets the value of the mtv flag in an ACF_CAN_XL_BRIEF message header.
 * 
 * @param msg Pointer to an ACF_CAN_XL_BRIEF message.
 * @param mtv The value to set.
 */
static inline void Avtp_CanXlBrief_SetMtv(Avtp_CanXlBrief_t* msg, bool mtv) {
    __Avtp_CanXlBrief_SetField(AVTP_CANXL_BRIEF_FIELD_MTV, mtv);
}

/**
 * Sets the value of the can_bus_id field in an ACF_CAN_XL_BRIEF message header.
 * 
 * @param msg Pointer to an ACF_CAN_XL_BRIEF message.
 * @param canBusId The value to set.
 */
static inline void Avtp_CanXlBrief_SetCanBusId(Avtp_CanXlBrief_t* msg, uint16_t canBusId) {
    __Avtp_CanXlBrief_SetField(AVTP_CANXL_BRIEF_FIELD_CAN_BUS_ID, canBusId);
}

/**
 * Sets the value of the vcid field in an ACF_CAN_XL_BRIEF message header.
 * 
 * @param msg Pointer to an ACF_CAN_XL_BRIEF message.
 * @param vcid The value to set.
 */
static inline void Avtp_CanXlBrief_SetVcid(Avtp_CanXlBrief_t* msg, uint8_t vcid) {
    __Avtp_CanXlBrief_SetField(AVTP_CANXL_BRIEF_FIELD_VCID, vcid);
}

/**
 * Sets the value of the sdt field in an ACF_CAN_XL_BRIEF message header.
 * 
 * @param msg Pointer to an ACF_CAN_XL_BRIEF message.
 * @param sdt The value to set.
 */
static inline void Avtp_CanXlBrief_SetSdt(Avtp_CanXlBrief_t* msg, uint8_t sdt) {
    __Avtp_CanXlBrief_SetField(AVTP_CANXL_BRIEF_FIELD_SDT, sdt);
}

/**
 * Sets the value of the rrs flag in an ACF_CAN_XL_BRIEF message header.
 * 
 * @param msg Pointer to an ACF_CAN_XL_BRIEF message.
 * @param rrs The value to set.
 */
static inline void Avtp_CanXlBrief_SetRrs(Avtp_CanXlBrief_t* msg, bool rrs) {
    __Avtp_CanXlBrief_SetField(AVTP_CANXL_BRIEF_FIELD_RRS, rrs);
}

/**
 * Sets the value of the sec flag in an ACF_CAN_XL_BRIEF message header.
 * 
 * @param msg Pointer to an ACF_CAN_XL_BRIEF message.
 * @param sec The value to set.
 */
static inline void Avtp_CanXlBrief_SetSec(Avtp_CanXlBrief_t* msg, bool sec) {
    __Avtp_CanXlBrief_SetField(AVTP_CANXL_BRIEF_FIELD_SEC, sec);
}

/**
 * Sets the value of the priority_id field in an ACF_CAN_XL_BRIEF message header.
 * 
 * @param msg Pointer to an ACF_CAN_XL_BRIEF message.
 * @param priorityId The value to set.
 */
static inline void Avtp_CanXlBrief_SetPriorityId(Avtp_CanXlBrief_t* msg, uint16_t priorityId) {
    __Avtp_CanXlBrief_SetField(AVTP_CANXL_BRIEF_FIELD_PRIORITY_ID, priorityId);
}

/**
 * Sets the value of the acceptance_field in an ACF_CAN_XL_BRIEF message header.
 * 
 * @param msg Pointer to an ACF_CAN_XL_BRIEF message.
 * @param acceptanceField The value to set.
 */
static inline void Avtp_CanXlBrief_SetAcceptanceField(Avtp_CanXlBrief_t* msg, uint32_t acceptanceField) {
    __Avtp_CanXlBrief_SetField(AVTP_CANXL_BRIEF_FIELD_ACCEPTANCE_FIELD, acceptanceField);
}

/**
 * Sets the value of the transaction_num field in an ACF_CAN_XL_BRIEF message header.
 * 
 * @param msg Pointer to an ACF_CAN_XL_BRIEF message.
 * @param transactionNum The value to set.
 */
static inline void Avtp_CanXlBrief_SetTransactionNum(Avtp_CanXlBrief_t* msg, uint8_t transactionNum) {
    __Avtp_CanXlBrief_SetField(AVTP_CANXL_BRIEF_FIELD_TRANSACTION_NUM, transactionNum);
}

/**
 * Sets the value of the ms flag in an ACF_CAN_XL_BRIEF message header.
 * 
 * @param msg Pointer to an ACF_CAN_XL_BRIEF message.
 * @param ms The value to set.
 */
static inline void Avtp_CanXlBrief_SetMs(Avtp_CanXlBrief_t* msg, bool ms) {
    __Avtp_CanXlBrief_SetField(AVTP_CANXL_BRIEF_FIELD_MS, ms);
}

/**
 * Sets the value of the segment_num field in an ACF_CAN_XL_BRIEF message header.
 * 
 * @param msg Pointer to an ACF_CAN_XL_BRIEF message.
 * @param segmentNum The value to set.
 */
static inline void Avtp_CanXlBrief_SetSegmentNum(Avtp_CanXlBrief_t* msg, uint16_t segmentNum) {
    __Avtp_CanXlBrief_SetField(AVTP_CANXL_BRIEF_FIELD_SEGMENT_NUM, segmentNum);
}

/**
 * Sets the value of the acf_msg_length field in an ACF_CAN_XL_BRIEF message header
 * based on the given payload length. This function also calculates the
 * required padding and sets the value of the pad field accordingly.
 * 
 * @param msg Pointer to an ACF_CAN_XL_BRIEF message.
 * @param payloadLen The length of the payload in bytes.
 */
static inline void Avtp_CanXlBrief_SetPayloadLen(Avtp_CanXlBrief_t* msg, uint16_t payloadLen) {
    uint16_t msgLenBytes = AVTP_CANXL_BRIEF_HEADER_LEN + payloadLen;
    uint8_t pad = (4 - (msgLenBytes % 4)) % 4;
    uint16_t msgLenQuadlets = (msgLenBytes + pad) / 4;
    __Avtp_CanXlBrief_SetField(AVTP_CANXL_BRIEF_FIELD_ACF_MSG_LENGTH, msgLenQuadlets);
    __Avtp_CanXlBrief_SetField(AVTP_CANXL_BRIEF_FIELD_PAD, pad);
}

#ifdef __cplusplus
}
#endif
