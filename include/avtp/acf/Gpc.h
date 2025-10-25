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
 * This file contains the fields descriptions of the IEEE 1722-2016 ACF GPC PDUs and
 * functions to invoke corresponding parser and deparser.
 */
#pragma once

#include "avtp/Defines.h"
#include "avtp/acf/AcfCommon.h"
#include "avtp/Utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AVTP_GPC_HEADER_LEN         (2 * AVTP_QUADLET_SIZE)

#define GET_GPC_FIELD(field) \
        (Avtp_GetField(Avtp_GpcFieldDesc, AVTP_GPC_FIELD_MAX, (uint8_t*)pdu, field))
#define SET_GPC_FIELD(field, value) \
        (Avtp_SetField(Avtp_GpcFieldDesc, AVTP_GPC_FIELD_MAX, (uint8_t*)pdu, field, value))

typedef struct {
    uint8_t header[AVTP_GPC_HEADER_LEN];
    uint8_t payload[0];
} Avtp_Gpc_t;

/** Fields of ACF GPC PDU. */
typedef enum  {

    /* ACF common header fields */
    AVTP_GPC_FIELD_ACF_MSG_TYPE = 0,
    AVTP_GPC_FIELD_ACF_MSG_LENGTH,

    /* ACF GPC header fields */
    AVTP_GPC_FIELD_GPC_MSG_ID,

    /* Count number of fields for bound checks */
    AVTP_GPC_FIELD_MAX
} Avtp_GpcFields_t;

/**
 * This table maps all IEEE 1722 ACF GPC header fields to a descriptor.
 */
static const Avtp_FieldDescriptor_t Avtp_GpcFieldDesc[AVTP_GPC_FIELD_MAX] =
{
    /* ACF common header fields */
    [AVTP_GPC_FIELD_ACF_MSG_TYPE]       = { .quadlet = 0, .offset =  0, .bits = 7 },
    [AVTP_GPC_FIELD_ACF_MSG_LENGTH]     = { .quadlet = 0, .offset =  7, .bits = 9 },
    /* ACF GPC header fields */
    [AVTP_GPC_FIELD_GPC_MSG_ID]         = { .quadlet = 0, .offset =  16, .bits = 48 },
};

/**
 * Return the value of the ACF Message Type Field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF GPC PDU.
 * @returns The value of the ACF Message Type Field.
 */
static inline uint8_t Avtp_Gpc_GetAcfMsgType(const Avtp_Gpc_t* const pdu) {
    return GET_GPC_FIELD(AVTP_GPC_FIELD_ACF_MSG_TYPE);
}

/**
 * Return the value of the ACF Message Length Field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF GPC PDU.
 * @returns The value of the ACF Message Length Field.
 */
static inline uint16_t Avtp_Gpc_GetAcfMsgLength(const Avtp_Gpc_t* const pdu) {
    return GET_GPC_FIELD(AVTP_GPC_FIELD_ACF_MSG_LENGTH);
}

/**
 * Return the value of the GPC Message ID Field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF GPC PDU.
 * @returns The value of the GPC Message ID Field.
 */
static inline uint64_t Avtp_Gpc_GetGpcMsgId(const Avtp_Gpc_t* const pdu) {
    return GET_GPC_FIELD(AVTP_GPC_FIELD_GPC_MSG_ID);
}

/**
 * Set the value of an ACF Message Type field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF GPC PDU.
 * @param value Value to set the ACF Message Type field to.
 */
static inline void Avtp_Gpc_SetAcfMsgType(Avtp_Gpc_t* pdu, uint8_t value) {
    SET_GPC_FIELD(AVTP_GPC_FIELD_ACF_MSG_TYPE, value);
}

/**
 * Set the value of an ACF Message Length field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF GPC PDU.
 * @param value Value to set the ACF Message Length field to.
 */
static inline void Avtp_Gpc_SetAcfMsgLength(Avtp_Gpc_t* pdu, uint16_t value) {
    SET_GPC_FIELD(AVTP_GPC_FIELD_ACF_MSG_LENGTH, value);
}

/**
 * Set the value of an GPC Message ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF GPC PDU.
 * @param value Value to set the GPC Message ID field to.
 */
static inline void Avtp_Gpc_SetGpcMsgId(Avtp_Gpc_t* pdu, uint64_t value) {
    SET_GPC_FIELD(AVTP_GPC_FIELD_GPC_MSG_ID, value);
}

/**
 * Checks if the ACF Gpc frame is valid by checking:
 *     1) if the length field of AVTP/ACF messages contains a value larger than the actual size of the buffer that contains the AVTP message.
 *     2) if other format specific invariants are not upheld
 * @param pdu Pointer to the first bit of an 1722 ACF Gpc PDU.
 * @param bufferSize Size of the buffer containing the ACF Gpc frame.
 * @return true if the ACF Gpc frame is valid, false otherwise.
 */
uint8_t Avtp_Gpc_IsValid(const Avtp_Gpc_t* const pdu, size_t bufferSize);

/**
 * Initializes an ACF GPC PDU header as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF GPC PDU.
 */
static inline void Avtp_Gpc_Init(Avtp_Gpc_t* pdu) {
    if(pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_Gpc_t));
        Avtp_Gpc_SetAcfMsgType(pdu, AVTP_ACF_TYPE_GPC);
    }
}

#ifdef __cplusplus
}
#endif
