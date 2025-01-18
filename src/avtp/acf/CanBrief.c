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

#include "avtp/acf/CanBrief.h"
#include "avtp/Utils.h"
#include "avtp/Defines.h"

#define GET_FIELD(field) \
        (Avtp_GetField(Avtp_CanBriefFieldDesc, AVTP_CAN_BRIEF_FIELD_MAX, (uint8_t*)pdu, field))
#define SET_FIELD(field, value) \
        (Avtp_SetField(Avtp_CanBriefFieldDesc, AVTP_CAN_BRIEF_FIELD_MAX, (uint8_t*)pdu, field, value))

/**
 * This table maps all IEEE 1722 ACF Abbreviated CAN header fields to a descriptor.
 */
static const Avtp_FieldDescriptor_t Avtp_CanBriefFieldDesc[AVTP_CAN_BRIEF_FIELD_MAX] =
{
    /* ACF common header fields */
    [AVTP_CAN_BRIEF_FIELD_ACF_MSG_TYPE]           = { .quadlet = 0, .offset =  0, .bits = 7 },
    [AVTP_CAN_BRIEF_FIELD_ACF_MSG_LENGTH]         = { .quadlet = 0, .offset =  7, .bits = 9 },
    /* ACF Abbreviated CAN header fields */
    [AVTP_CAN_BRIEF_FIELD_PAD]                   = { .quadlet = 0, .offset = 16, .bits =  2 },
    [AVTP_CAN_BRIEF_FIELD_MTV]                   = { .quadlet = 0, .offset = 18, .bits =  1 },
    [AVTP_CAN_BRIEF_FIELD_RTR]                   = { .quadlet = 0, .offset = 19, .bits =  1 },
    [AVTP_CAN_BRIEF_FIELD_EFF]                   = { .quadlet = 0, .offset = 20, .bits =  1 },
    [AVTP_CAN_BRIEF_FIELD_BRS]                   = { .quadlet = 0, .offset = 21, .bits =  1 },
    [AVTP_CAN_BRIEF_FIELD_FDF]                   = { .quadlet = 0, .offset = 22, .bits =  1 },
    [AVTP_CAN_BRIEF_FIELD_ESI]                   = { .quadlet = 0, .offset = 23, .bits =  1 },
    [AVTP_CAN_BRIEF_FIELD_CAN_BUS_ID]            = { .quadlet = 0, .offset = 27, .bits =  5 },
    [AVTP_CAN_BRIEF_FIELD_CAN_IDENTIFIER]        = { .quadlet = 1, .offset =  3, .bits = 29 },
};

void Avtp_CanBrief_Init(Avtp_CanBrief_t* pdu)
{
    if(pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_CanBrief_t));
        Avtp_CanBrief_SetField(pdu, AVTP_CAN_BRIEF_FIELD_ACF_MSG_TYPE, AVTP_ACF_TYPE_CAN_BRIEF);
    }
}

uint64_t Avtp_CanBrief_GetField(Avtp_CanBrief_t* pdu, Avtp_CanBriefFields_t field)
{
    return GET_FIELD(field);
}

uint8_t Avtp_CanBrief_GetAcfMsgType(Avtp_CanBrief_t* pdu)
{
    return GET_FIELD(AVTP_CAN_BRIEF_FIELD_ACF_MSG_TYPE);
}

uint16_t Avtp_CanBrief_GetAcfMsgLength(Avtp_CanBrief_t* pdu)
{
    return GET_FIELD(AVTP_CAN_BRIEF_FIELD_ACF_MSG_LENGTH);
}

uint8_t Avtp_CanBrief_GetPad(Avtp_CanBrief_t* pdu)
{
    return GET_FIELD(AVTP_CAN_BRIEF_FIELD_PAD);
}

uint8_t Avtp_CanBrief_GetMtv(Avtp_CanBrief_t* pdu)
{
    return GET_FIELD(AVTP_CAN_BRIEF_FIELD_MTV);
}

uint8_t Avtp_CanBrief_GetRtr(Avtp_CanBrief_t* pdu)
{
    return GET_FIELD(AVTP_CAN_BRIEF_FIELD_RTR);
}

uint8_t Avtp_CanBrief_GetEff(Avtp_CanBrief_t* pdu)
{
    return GET_FIELD(AVTP_CAN_BRIEF_FIELD_EFF);
}

uint8_t Avtp_CanBrief_GetBrs(Avtp_CanBrief_t* pdu)
{
    return GET_FIELD(AVTP_CAN_BRIEF_FIELD_BRS);
}

uint8_t Avtp_CanBrief_GetFdf(Avtp_CanBrief_t* pdu)
{
    return GET_FIELD(AVTP_CAN_BRIEF_FIELD_FDF);
}

uint8_t Avtp_CanBrief_GetEsi(Avtp_CanBrief_t* pdu)
{
    return GET_FIELD(AVTP_CAN_BRIEF_FIELD_ESI);
}

uint8_t Avtp_CanBrief_GetCanBusId(Avtp_CanBrief_t* pdu)
{
    return GET_FIELD(AVTP_CAN_BRIEF_FIELD_CAN_BUS_ID);
}

uint32_t Avtp_CanBrief_GetCanIdentifier(Avtp_CanBrief_t* pdu)
{
    return GET_FIELD(AVTP_CAN_BRIEF_FIELD_CAN_IDENTIFIER);
}

void Avtp_CanBrief_SetField(Avtp_CanBrief_t* pdu, Avtp_CanBriefFields_t field, uint64_t value)
{
    SET_FIELD(field, value);
}

void Avtp_CanBrief_SetAcfMsgType(Avtp_CanBrief_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_CAN_BRIEF_FIELD_ACF_MSG_TYPE, value);
}

void Avtp_CanBrief_SetAcfMsgLength(Avtp_CanBrief_t* pdu, uint16_t value)
{
    SET_FIELD(AVTP_CAN_BRIEF_FIELD_ACF_MSG_LENGTH, value);
}

void Avtp_CanBrief_SetPad(Avtp_CanBrief_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_CAN_BRIEF_FIELD_PAD, value);
}

void Avtp_CanBrief_EnableMtv(Avtp_Can_t* pdu)
{
    SET_FIELD(AVTP_CAN_FIELD_MTV, 1);
}

void Avtp_CanBrief_DisableMtv(Avtp_Can_t* pdu)
{
    SET_FIELD(AVTP_CAN_FIELD_MTV, 0);
}

void Avtp_CanBrief_EnableRtr(Avtp_Can_t* pdu)
{
    SET_FIELD(AVTP_CAN_FIELD_RTR, 1);
}

void Avtp_CanBrief_DisableRtr(Avtp_Can_t* pdu)
{
    SET_FIELD(AVTP_CAN_FIELD_RTR, 0);
}

void Avtp_CanBrief_EnableEff(Avtp_Can_t* pdu)
{
    SET_FIELD(AVTP_CAN_FIELD_EFF, 1);
}

void Avtp_CanBrief_DisableEff(Avtp_Can_t* pdu)
{
    SET_FIELD(AVTP_CAN_FIELD_EFF, 0);
}

void Avtp_CanBrief_EnableBrs(Avtp_Can_t* pdu)
{
    SET_FIELD(AVTP_CAN_FIELD_BRS, 1);
}

void Avtp_CanBrief_DisableBrs(Avtp_Can_t* pdu)
{
    SET_FIELD(AVTP_CAN_FIELD_BRS, 0);
}

void Avtp_CanBrief_EnableFdf(Avtp_Can_t* pdu)
{
    SET_FIELD(AVTP_CAN_FIELD_FDF, 1);
}

void Avtp_CanBrief_DisableFdf(Avtp_Can_t* pdu)
{
    SET_FIELD(AVTP_CAN_FIELD_FDF, 0);
}

void Avtp_CanBrief_EnableEsi(Avtp_Can_t* pdu)
{
    SET_FIELD(AVTP_CAN_FIELD_ESI, 1);
}

void Avtp_CanBrief_DisableEsi(Avtp_Can_t* pdu)
{
    SET_FIELD(AVTP_CAN_FIELD_ESI, 0);
}

void Avtp_CanBrief_SetCanBusId(Avtp_CanBrief_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_CAN_BRIEF_FIELD_CAN_BUS_ID, value);
}

void Avtp_CanBrief_SetCanIdentifier(Avtp_CanBrief_t* pdu, uint32_t value)
{
    SET_FIELD(AVTP_CAN_BRIEF_FIELD_CAN_IDENTIFIER, value);
}

int Avtp_CanBrief_SetPayload(Avtp_CanBrief_t* pdu, uint32_t frame_id , uint8_t* payload,
                        uint16_t payload_length, Avtp_CanVariant_t can_variant)
{
    // Copy the payload into the CAN PDU
    memcpy(pdu->payload, payload, payload_length);

    // Set the Frame ID and CAN variant
    int eff = frame_id > 0x7ff? 1 : 0;
    Avtp_CanBrief_SetField(pdu, AVTP_CAN_BRIEF_FIELD_EFF, eff);
    Avtp_CanBrief_SetField(pdu, AVTP_CAN_BRIEF_FIELD_CAN_IDENTIFIER, frame_id);
    Avtp_CanBrief_SetField(pdu, AVTP_CAN_BRIEF_FIELD_FDF, (uint8_t) can_variant);

    // Finalize the AVTP CAN Frame
    return Avtp_CanBrief_Finalize(pdu, payload_length);
}

int Avtp_CanBrief_Finalize(Avtp_CanBrief_t* pdu, uint16_t payload_length)
{
    uint8_t padSize;
    uint32_t avtpCanLength = AVTP_CAN_BRIEF_HEADER_LEN + payload_length;

    // Check if padding is required
    padSize = AVTP_QUADLET_SIZE - (payload_length % AVTP_QUADLET_SIZE);
    if (payload_length % AVTP_QUADLET_SIZE) {
        memset(pdu->payload + payload_length, 0, padSize);
        avtpCanLength += padSize;
    }

    // Set the length and padding fields
    Avtp_CanBrief_SetField(pdu, AVTP_CAN_BRIEF_FIELD_ACF_MSG_LENGTH,
            (uint64_t)avtpCanLength/AVTP_QUADLET_SIZE);
    Avtp_CanBrief_SetField(pdu, AVTP_CAN_BRIEF_FIELD_PAD, padSize);

    return avtpCanLength;
}
