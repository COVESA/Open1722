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

#ifdef __cplusplus
extern "C" {
#endif

#define AVTP_GPC_HEADER_LEN         (2 * AVTP_QUADLET_SIZE)

typedef struct {
    uint8_t header[AVTP_GPC_HEADER_LEN];
    uint8_t payload[0];
} Avtp_Gpc_t;


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
 * Initializes an ACF GPC PDU header as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF GPC PDU.
 */
void Avtp_Gpc_Init(Avtp_Gpc_t* pdu);

/**
 * Returns the value of an an ACF GPC PDU field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF GPC PDU.
 * @param field Specifies the position of the data field to be read
 * @param value Pointer to location to store the value.
 * @returns The value of the GPC field.
 */
uint64_t Avtp_Gpc_GetField(Avtp_Gpc_t* pdu, Avtp_GpcFields_t field);

uint8_t Avtp_Gpc_GetAcfMsgType(Avtp_Gpc_t* pdu);
uint16_t Avtp_Gpc_GetAcfMsgLength(Avtp_Gpc_t* pdu);
uint64_t Avtp_Gpc_GetGpcMsgId(Avtp_Gpc_t* pdu);

/**
 * Sets the value of an an ACF GPC PDU field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF GPC PDU.
 * @param field Specifies the position of the data field to be read
 * @param value Pointer to location to store the value.
 */
void Avtp_Gpc_SetField(Avtp_Gpc_t* pdu, Avtp_GpcFields_t field, uint64_t value);

void Avtp_Gpc_SetAcfMsgType(Avtp_Gpc_t* pdu, uint8_t value);
void Avtp_Gpc_SetAcfMsgLength(Avtp_Gpc_t* pdu, uint16_t value);
void Avtp_Gpc_SetGpcMsgId(Avtp_Gpc_t* pdu, uint64_t value);

/**
 * Checks if the ACF Gpc frame is valid by checking:
 *     1) if the length field of AVTP/ACF messages contains a value larger than the actual size of the buffer that contains the AVTP message.
 *     2) if other format specific invariants are not upheld
 * @param pdu Pointer to the first bit of an 1722 ACF Gpc PDU.
 * @param bufferSize Size of the buffer containing the ACF Gpc frame.
 * @return true if the ACF Gpc frame is valid, false otherwise.
 */
uint8_t Avtp_Gpc_IsValid(Avtp_Gpc_t* pdu, size_t bufferSize);

#ifdef __cplusplus
}
#endif
