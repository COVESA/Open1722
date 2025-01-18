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

#include "avtp/acf/FlexRay.h"
#include "avtp/Utils.h"

#define GET_FIELD(field) \
        (Avtp_GetField(Avtp_FlexRayFieldDesc, AVTP_FLEXRAY_FIELD_MAX, (uint8_t*)pdu, field))
#define SET_FIELD(field, value) \
        (Avtp_SetField(Avtp_FlexRayFieldDesc, AVTP_FLEXRAY_FIELD_MAX, (uint8_t*)pdu, field, value))

/**
 * This table describes all the offsets of the ACF FlexRay header fields.
 */
static const Avtp_FieldDescriptor_t Avtp_FlexRayFieldDesc[AVTP_FLEXRAY_FIELD_MAX] =
{
    /* ACF common header fields */
    [AVTP_FLEXRAY_FIELD_ACF_MSG_TYPE]       = { .quadlet = 0, .offset = 0, .bits = 7 },
    [AVTP_FLEXRAY_FIELD_ACF_MSG_LENGTH]     = { .quadlet = 0, .offset = 7, .bits = 9 },
    /* ACF Flexray header fields */
    [AVTP_FLEXRAY_FIELD_PAD]                = { .quadlet = 0, .offset = 16, .bits = 2 },
    [AVTP_FLEXRAY_FIELD_MTV]                = { .quadlet = 0, .offset = 18, .bits = 1 },
    [AVTP_FLEXRAY_FIELD_FR_BUS_ID]          = { .quadlet = 0, .offset = 19, .bits = 5 },
    [AVTP_FLEXRAY_FIELD_RESERVED]           = { .quadlet = 0, .offset = 24, .bits = 2 },
    [AVTP_FLEXRAY_FIELD_CHAN]               = { .quadlet = 0, .offset = 26, .bits = 2 },
    [AVTP_FLEXRAY_FIELD_STR]                = { .quadlet = 0, .offset = 28, .bits = 1 },
    [AVTP_FLEXRAY_FIELD_SYN]                = { .quadlet = 0, .offset = 29, .bits = 1 },
    [AVTP_FLEXRAY_FIELD_PRE]                = { .quadlet = 0, .offset = 30, .bits = 1 },
    [AVTP_FLEXRAY_FIELD_NFI]                = { .quadlet = 0, .offset = 31, .bits = 1 },
    [AVTP_FLEXRAY_FIELD_MESSAGE_TIMESTAMP]  = { .quadlet = 1, .offset = 0, .bits = 64 },
    [AVTP_FLEXRAY_FIELD_FR_FRAME_ID]        = { .quadlet = 3, .offset = 0, .bits = 11 },
    [AVTP_FLEXRAY_FIELD_RESERVED_2]         = { .quadlet = 3, .offset = 11, .bits = 15 },
    [AVTP_FLEXRAY_FIELD_CYCLE]              = { .quadlet = 3, .offset = 26, .bits = 6 },
};

void Avtp_FlexRay_Init(Avtp_FlexRay_t* pdu)
{
    if(pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_FlexRay_t));
        Avtp_FlexRay_SetField(pdu, AVTP_FLEXRAY_FIELD_ACF_MSG_TYPE, AVTP_ACF_TYPE_FLEXRAY);
    }
}

uint64_t Avtp_FlexRay_GetField(Avtp_FlexRay_t* pdu, Avtp_FlexRayFields_t field)
{
    return GET_FIELD(field);
}

uint8_t Avtp_FlexRay_GetAcfMsgType(Avtp_FlexRay_t* pdu)
{
    return GET_FIELD(AVTP_FLEXRAY_FIELD_ACF_MSG_TYPE);
}

uint16_t Avtp_FlexRay_GetAcfMsgLength(Avtp_FlexRay_t* pdu)
{
    return GET_FIELD(AVTP_FLEXRAY_FIELD_ACF_MSG_LENGTH);
}

uint8_t Avtp_FlexRay_GetPad(Avtp_FlexRay_t* pdu)
{
    return GET_FIELD(AVTP_FLEXRAY_FIELD_PAD);
}

uint8_t Avtp_FlexRay_GetMtv(Avtp_FlexRay_t* pdu)
{
    return GET_FIELD(AVTP_FLEXRAY_FIELD_MTV);
}

uint8_t Avtp_FlexRay_GetFrBusId(Avtp_FlexRay_t* pdu)
{
    return GET_FIELD(AVTP_FLEXRAY_FIELD_FR_BUS_ID);
}

uint8_t Avtp_FlexRay_GetChan(Avtp_FlexRay_t* pdu)
{
    return GET_FIELD(AVTP_FLEXRAY_FIELD_CHAN);
}

uint8_t Avtp_FlexRay_GetStr(Avtp_FlexRay_t* pdu)
{
    return GET_FIELD(AVTP_FLEXRAY_FIELD_STR);
}

uint8_t Avtp_FlexRay_GetSyn(Avtp_FlexRay_t* pdu)
{
    return GET_FIELD(AVTP_FLEXRAY_FIELD_SYN);
}

uint8_t Avtp_FlexRay_GetPre(Avtp_FlexRay_t* pdu)
{
    return GET_FIELD(AVTP_FLEXRAY_FIELD_PRE);
}

uint8_t Avtp_FlexRay_GetNfi(Avtp_FlexRay_t* pdu)
{
    return GET_FIELD(AVTP_FLEXRAY_FIELD_NFI);
}

uint64_t Avtp_FlexRay_GetMessageTimestamp(Avtp_FlexRay_t* pdu)
{
    return GET_FIELD(AVTP_FLEXRAY_FIELD_MESSAGE_TIMESTAMP);
}

uint16_t Avtp_FlexRay_GetFrFrameId(Avtp_FlexRay_t* pdu)
{
    return GET_FIELD(AVTP_FLEXRAY_FIELD_FR_FRAME_ID);
}

uint8_t Avtp_FlexRay_GetCycle(Avtp_FlexRay_t* pdu)
{
    return GET_FIELD(AVTP_FLEXRAY_FIELD_CYCLE);
}

void Avtp_FlexRay_SetField(Avtp_FlexRay_t* pdu, Avtp_FlexRayFields_t field, uint64_t value)
{
    SET_FIELD(field, value);
}

void Avtp_FlexRay_SetAcfMsgType(Avtp_FlexRay_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_FLEXRAY_FIELD_ACF_MSG_TYPE, value);
}

void Avtp_FlexRay_SetAcfMsgLength(Avtp_FlexRay_t* pdu, uint16_t value)
{
    SET_FIELD(AVTP_FLEXRAY_FIELD_ACF_MSG_LENGTH, value);
}

void Avtp_FlexRay_SetPad(Avtp_FlexRay_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_FLEXRAY_FIELD_PAD, value);
}

void Avtp_FlexRay_EnableMtv(Avtp_FlexRay_t* pdu)
{
    SET_FIELD(AVTP_FLEXRAY_FIELD_MTV, 1);
}

void Avtp_FlexRay_DisableMtv(Avtp_FlexRay_t* pdu)
{
    SET_FIELD(AVTP_FLEXRAY_FIELD_MTV, 0);
}

void Avtp_FlexRay_SetFrBusId(Avtp_FlexRay_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_FLEXRAY_FIELD_FR_BUS_ID, value);
}

void Avtp_FlexRay_SetChan(Avtp_FlexRay_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_FLEXRAY_FIELD_CHAN, value);
}

void Avtp_FlexRay_EnableStr(Avtp_FlexRay_t* pdu)
{
    SET_FIELD(AVTP_FLEXRAY_FIELD_STR, 1);
}

void Avtp_FlexRay_DisableStr(Avtp_FlexRay_t* pdu)
{
    SET_FIELD(AVTP_FLEXRAY_FIELD_STR, 0);
}

void Avtp_FlexRay_EnableSyn(Avtp_FlexRay_t* pdu)
{
    SET_FIELD(AVTP_FLEXRAY_FIELD_SYN, 1);
}

void Avtp_FlexRay_DisableSyn(Avtp_FlexRay_t* pdu)
{
    SET_FIELD(AVTP_FLEXRAY_FIELD_SYN, 0);
}

void Avtp_FlexRay_EnablePre(Avtp_FlexRay_t* pdu)
{
    SET_FIELD(AVTP_FLEXRAY_FIELD_PRE, 1);
}

void Avtp_FlexRay_DisablePre(Avtp_FlexRay_t* pdu)
{
    SET_FIELD(AVTP_FLEXRAY_FIELD_PRE, 0);
}

void Avtp_FlexRay_EnableNfi(Avtp_FlexRay_t* pdu)
{
    SET_FIELD(AVTP_FLEXRAY_FIELD_NFI, 1);
}

void Avtp_FlexRay_DisableNfi(Avtp_FlexRay_t* pdu)
{
    SET_FIELD(AVTP_FLEXRAY_FIELD_NFI, 0);
}

void Avtp_FlexRay_SetMessageTimestamp(Avtp_FlexRay_t* pdu, uint64_t value)
{
    SET_FIELD(AVTP_FLEXRAY_FIELD_MESSAGE_TIMESTAMP, value);
}

void Avtp_FlexRay_SetFrFrameId(Avtp_FlexRay_t* pdu, uint16_t value)
{
    SET_FIELD(AVTP_FLEXRAY_FIELD_FR_FRAME_ID, value);
}

void Avtp_FlexRay_SetCycle(Avtp_FlexRay_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_FLEXRAY_FIELD_CYCLE, value);
}
