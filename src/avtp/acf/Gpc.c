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

#include <errno.h>
#include <string.h>

#include "avtp/acf/Gpc.h"
#include "avtp/Utils.h"
#include "avtp/Defines.h"

#define GET_FIELD(field) \
        (Avtp_GetField(Avtp_GpcFieldDesc, AVTP_GPC_FIELD_MAX, (uint8_t*)pdu, field))
#define SET_FIELD(field, value) \
        (Avtp_SetField(Avtp_GpcFieldDesc, AVTP_GPC_FIELD_MAX, (uint8_t*)pdu, field, value))

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

void Avtp_Gpc_Init(Avtp_Gpc_t* pdu)
{
    if(pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_Gpc_t));
        Avtp_Gpc_SetField(pdu, AVTP_GPC_FIELD_ACF_MSG_TYPE, AVTP_ACF_TYPE_GPC);
    }
}

uint64_t Avtp_Gpc_GetField(Avtp_Gpc_t* pdu, Avtp_GpcFields_t field)
{
    return GET_FIELD(field);
}

uint8_t Avtp_Gpc_GetAcfMsgType(Avtp_Gpc_t* pdu)
{
    return GET_FIELD(AVTP_GPC_FIELD_ACF_MSG_TYPE);
}

uint16_t Avtp_Gpc_GetAcfMsgLength(Avtp_Gpc_t* pdu)
{
    return GET_FIELD(AVTP_GPC_FIELD_ACF_MSG_LENGTH);
}

uint64_t Avtp_Gpc_GetGpcMsgId(Avtp_Gpc_t* pdu)
{
    return GET_FIELD(AVTP_GPC_FIELD_GPC_MSG_ID);
}

void Avtp_Gpc_SetField(Avtp_Gpc_t* pdu, Avtp_GpcFields_t field, uint64_t value)
{
    SET_FIELD(field, value);
}

void Avtp_Gpc_SetAcfMsgType(Avtp_Gpc_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_GPC_FIELD_ACF_MSG_TYPE, value);
}

void Avtp_Gpc_SetAcfMsgLength(Avtp_Gpc_t* pdu, uint16_t value)
{
    SET_FIELD(AVTP_GPC_FIELD_ACF_MSG_LENGTH, value);
}

void Avtp_Gpc_SetGpcMsgId(Avtp_Gpc_t* pdu, uint64_t value)
{
    SET_FIELD(AVTP_GPC_FIELD_GPC_MSG_ID, value);
}

uint8_t Avtp_Gpc_IsValid(Avtp_Gpc_t* pdu, size_t bufferSize)
{
    if (pdu == NULL) {
        return FALSE;
    }

    if (bufferSize < AVTP_GPC_HEADER_LEN) {
        return FALSE;
    }

    if (Avtp_Gpc_GetAcfMsgType(pdu) != AVTP_ACF_TYPE_GPC) {
        return FALSE;
    }

    // Avtp_Gpc_GetAcfMsgLength returns quadlets. Convert the length field to octets
    if (Avtp_Gpc_GetAcfMsgLength(pdu) * 4 > bufferSize) {
        return FALSE;
    }

    return TRUE;
}