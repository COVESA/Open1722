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

#include "avtp/acf/Can.h"
#include "avtp/Utils.h"
#include "avtp/Defines.h"

#define GET_FIELD(field) \
        (Avtp_GetField(Avtp_CanFieldDesc, AVTP_CAN_FIELD_MAX, (uint8_t*)pdu, field))
#define SET_FIELD(field, value) \
        (Avtp_SetField(Avtp_CanFieldDesc, AVTP_CAN_FIELD_MAX, (uint8_t*)pdu, field, value))

/**
 * This table maps all IEEE 1722 ACF CAN header fields to a descriptor.
 */
static const Avtp_FieldDescriptor_t Avtp_CanFieldDesc[AVTP_CAN_FIELD_MAX] =
{
    /* ACF common header fields */
    [AVTP_CAN_FIELD_ACF_MSG_TYPE]       = { .quadlet = 0, .offset =  0, .bits = 7 },
    [AVTP_CAN_FIELD_ACF_MSG_LENGTH]     = { .quadlet = 0, .offset =  7, .bits = 9 },
    /* ACF CAN header fields */
    [AVTP_CAN_FIELD_PAD]                = { .quadlet = 0, .offset = 16, .bits =  2 },
    [AVTP_CAN_FIELD_MTV]                = { .quadlet = 0, .offset = 18, .bits =  1 },
    [AVTP_CAN_FIELD_RTR]                = { .quadlet = 0, .offset = 19, .bits =  1 },
    [AVTP_CAN_FIELD_EFF]                = { .quadlet = 0, .offset = 20, .bits =  1 },
    [AVTP_CAN_FIELD_BRS]                = { .quadlet = 0, .offset = 21, .bits =  1 },
    [AVTP_CAN_FIELD_FDF]                = { .quadlet = 0, .offset = 22, .bits =  1 },
    [AVTP_CAN_FIELD_ESI]                = { .quadlet = 0, .offset = 23, .bits =  1 },
    [AVTP_CAN_FIELD_CAN_BUS_ID]         = { .quadlet = 0, .offset = 27, .bits =  5 },
    [AVTP_CAN_FIELD_MESSAGE_TIMESTAMP]  = { .quadlet = 1, .offset =  0, .bits = 64 },
    [AVTP_CAN_FIELD_CAN_IDENTIFIER]     = { .quadlet = 3, .offset =  3, .bits = 29 },
};

void Avtp_Can_Init(Avtp_Can_t* pdu)
{
    if(pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_Can_t));
        Avtp_Can_SetField(pdu, AVTP_CAN_FIELD_ACF_MSG_TYPE, AVTP_ACF_TYPE_CAN);
    }
}

uint64_t Avtp_Can_GetField(Avtp_Can_t* pdu, Avtp_CanFields_t field)
{
    return GET_FIELD(field);
}

uint8_t Avtp_Can_GetAcfMsgType(Avtp_Can_t* pdu)
{
    return GET_FIELD(AVTP_CAN_FIELD_ACF_MSG_TYPE);
}

uint16_t Avtp_Can_GetAcfMsgLength(Avtp_Can_t* pdu)
{
    return GET_FIELD(AVTP_CAN_FIELD_ACF_MSG_LENGTH);
}

uint8_t Avtp_Can_GetPad(Avtp_Can_t* pdu)
{
    return GET_FIELD(AVTP_CAN_FIELD_PAD);
}

uint8_t Avtp_Can_GetMtv(Avtp_Can_t* pdu)
{
    return GET_FIELD(AVTP_CAN_FIELD_MTV);
}

uint8_t Avtp_Can_GetRtr(Avtp_Can_t* pdu)
{
    return GET_FIELD(AVTP_CAN_FIELD_RTR);
}

uint8_t Avtp_Can_GetEff(Avtp_Can_t* pdu)
{
    return GET_FIELD(AVTP_CAN_FIELD_EFF);
}

uint8_t Avtp_Can_GetBrs(Avtp_Can_t* pdu)
{
    return GET_FIELD(AVTP_CAN_FIELD_BRS);
}

uint8_t Avtp_Can_GetFdf(Avtp_Can_t* pdu)
{
    return GET_FIELD(AVTP_CAN_FIELD_FDF);
}

uint8_t Avtp_Can_GetEsi(Avtp_Can_t* pdu)
{
    return GET_FIELD(AVTP_CAN_FIELD_ESI);
}

uint8_t Avtp_Can_GetCanBusId(Avtp_Can_t* pdu)
{
    return GET_FIELD(AVTP_CAN_FIELD_CAN_BUS_ID);
}

uint64_t Avtp_Can_GetMessageTimestamp(Avtp_Can_t* pdu)
{
    return GET_FIELD(AVTP_CAN_FIELD_MESSAGE_TIMESTAMP);
}

uint32_t Avtp_Can_GetCanIdentifier(Avtp_Can_t* pdu)
{
    return GET_FIELD(AVTP_CAN_FIELD_CAN_IDENTIFIER);
}

void Avtp_Can_SetField(Avtp_Can_t* pdu, Avtp_CanFields_t field, uint64_t value)
{
    SET_FIELD(field, value);
}

void Avtp_Can_SetAcfMsgType(Avtp_Can_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_CAN_FIELD_ACF_MSG_TYPE, value);
}

void Avtp_Can_SetAcfMsgLength(Avtp_Can_t* pdu, uint16_t value)
{
    SET_FIELD(AVTP_CAN_FIELD_ACF_MSG_LENGTH, value);
}

void Avtp_Can_SetPad(Avtp_Can_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_CAN_FIELD_PAD, value);
}

void Avtp_Can_SetMtv(Avtp_Can_t* pdu, uint64_t value)
{
    if (value) {
        SET_FIELD(AVTP_CAN_FIELD_MTV, 1);
    } else {
        SET_FIELD(AVTP_CAN_FIELD_MTV, 0);
    }
}

void Avtp_Can_SetRtr(Avtp_Can_t* pdu, uint32_t value)
{
    if (value) {
        SET_FIELD(AVTP_CAN_FIELD_RTR, 1);
    } else {
        SET_FIELD(AVTP_CAN_FIELD_RTR, 0);
    }
}

void Avtp_Can_SetEff(Avtp_Can_t* pdu, uint32_t value)
{
    if (value) {
        SET_FIELD(AVTP_CAN_FIELD_EFF, 1);
    } else {
        SET_FIELD(AVTP_CAN_FIELD_EFF, 0);
    }
}

void Avtp_Can_SetBrs(Avtp_Can_t* pdu, uint8_t value)
{
    if (value) {
        SET_FIELD(AVTP_CAN_FIELD_BRS, 1);
    } else {
        SET_FIELD(AVTP_CAN_FIELD_BRS, 0);
    }
}

void Avtp_Can_SetFdf(Avtp_Can_t* pdu, uint8_t value)
{
    if (value) {
        SET_FIELD(AVTP_CAN_FIELD_FDF, 1);
    } else {
        SET_FIELD(AVTP_CAN_FIELD_FDF, 0);
    }
}

void Avtp_Can_SetEsi(Avtp_Can_t* pdu, uint8_t value)
{
    if (value) {
        SET_FIELD(AVTP_CAN_FIELD_ESI, 1);
    } else {
        SET_FIELD(AVTP_CAN_FIELD_ESI, 0);
    }
}

void Avtp_Can_SetCanBusId(Avtp_Can_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_CAN_FIELD_CAN_BUS_ID, value);
}

void Avtp_Can_SetMessageTimestamp(Avtp_Can_t* pdu, uint64_t value)
{
    SET_FIELD(AVTP_CAN_FIELD_MESSAGE_TIMESTAMP, value);
}

void Avtp_Can_SetCanIdentifier(Avtp_Can_t* pdu, uint32_t value)
{
    SET_FIELD(AVTP_CAN_FIELD_CAN_IDENTIFIER, value);
}

void Avtp_Can_CreateAcfMessage(Avtp_Can_t* pdu, uint32_t frame_id, uint8_t* payload,
                        uint16_t payload_length, Avtp_CanVariant_t can_variant)
{
    // Copy the payload into the CAN PDU
    Avtp_Can_SetPayload(pdu, payload, payload_length);

    // Set the Frame ID and CAN variant
    int eff = frame_id > 0x7ff? 1 : 0;
    Avtp_Can_SetField(pdu, AVTP_CAN_FIELD_EFF, eff);
    Avtp_Can_SetField(pdu, AVTP_CAN_FIELD_CAN_IDENTIFIER, frame_id);
    Avtp_Can_SetField(pdu, AVTP_CAN_FIELD_FDF, (uint8_t) can_variant);

    // Finalize the AVTP CAN Frame
    Avtp_Can_Finalize(pdu, payload_length);
}

void Avtp_Can_Finalize(Avtp_Can_t* pdu, uint16_t payload_length)
{
    uint8_t padSize;
    uint32_t avtpCanLength = AVTP_CAN_HEADER_LEN + payload_length;

    // Check if padding is required
    padSize = AVTP_QUADLET_SIZE - (payload_length % AVTP_QUADLET_SIZE);
    if (payload_length % AVTP_QUADLET_SIZE) {
        memset(pdu->payload + payload_length, 0, padSize);
        avtpCanLength += padSize;
    }

    // Set the length and padding fields
    Avtp_Can_SetField(pdu, AVTP_CAN_FIELD_ACF_MSG_LENGTH, (uint64_t) avtpCanLength/AVTP_QUADLET_SIZE);
    Avtp_Can_SetField(pdu, AVTP_CAN_FIELD_PAD, padSize);
}

void Avtp_Can_SetPayload(Avtp_Can_t* pdu, uint8_t* payload,
                            uint16_t payload_length)
{
    memcpy(pdu->payload, payload, payload_length);
}

uint8_t* Avtp_Can_GetPayload(Avtp_Can_t* pdu)
{
    return pdu->payload;
}

uint8_t Avtp_Can_GetCanPayloadLength(Avtp_Can_t* pdu)
{
    uint8_t acf_msg_length = Avtp_Can_GetAcfMsgLength(pdu) * 4;
    uint8_t acf_pad_length = Avtp_Can_GetPad(pdu);
    return acf_msg_length - AVTP_CAN_HEADER_LEN - acf_pad_length;
}
