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
#include <string.h>
#include <errno.h>

#include "avtp/CommonHeader.h"
#include "avtp/aaf/Aaf.h"
#include "avtp/Utils.h"

#define GET_FIELD(field) \
        (Avtp_GetField(Avtp_AafFieldDesc, AVTP_AAF_FIELD_MAX, (uint8_t*)pdu, field))
#define SET_FIELD(field, value) \
        (Avtp_SetField(Avtp_AafFieldDesc, AVTP_AAF_FIELD_MAX, (uint8_t*)pdu, field, value))

static const Avtp_FieldDescriptor_t Avtp_AafFieldDesc[AVTP_AAF_FIELD_MAX] =
{
    [AVTP_AAF_FIELD_SUBTYPE]                    = { .quadlet = 0, .offset =  0, .bits =  8 },
    [AVTP_AAF_FIELD_SV]                         = { .quadlet = 0, .offset =  8, .bits =  1 },
    [AVTP_AAF_FIELD_VERSION]                    = { .quadlet = 0, .offset =  9, .bits =  3 },
    [AVTP_AAF_FIELD_MR]                         = { .quadlet = 0, .offset = 12, .bits =  1 },
    [AVTP_AAF_FIELD_TV]                         = { .quadlet = 0, .offset = 15, .bits =  1 },
    [AVTP_AAF_FIELD_SEQUENCE_NUM]               = { .quadlet = 0, .offset = 16, .bits =  8 },
    [AVTP_AAF_FIELD_TU]                         = { .quadlet = 0, .offset = 31, .bits =  1 },
    [AVTP_AAF_FIELD_STREAM_ID]                  = { .quadlet = 1, .offset =  0, .bits = 64 },
    [AVTP_AAF_FIELD_AVTP_TIMESTAMP]             = { .quadlet = 3, .offset =  0, .bits = 32 },
    [AVTP_AAF_FIELD_FORMAT]                     = { .quadlet = 4, .offset =  0, .bits =  8 },
    [AVTP_AAF_FIELD_AAF_FORMAT_SPECIFIC_DATA_1] = { .quadlet = 4, .offset =  8, .bits = 24 },
    [AVTP_AAF_FIELD_STREAM_DATA_LENGTH]         = { .quadlet = 5, .offset =  0, .bits = 16 },
    [AVTP_AAF_FIELD_AFSD]                       = { .quadlet = 5, .offset = 16, .bits =  3 },
    [AVTP_AAF_FIELD_SP]                         = { .quadlet = 5, .offset = 19, .bits =  1 },
    [AVTP_AAF_FIELD_EVT]                        = { .quadlet = 5, .offset = 20, .bits =  4 },
    [AVTP_AAF_FIELD_AAF_FORMAT_SPECIFIC_DATA_2] = { .quadlet = 5, .offset = 24, .bits =  8 },
};

uint64_t Avtp_Aaf_GetField(Avtp_Aaf_t* pdu, Avtp_AafFields_t field)
{
    return Avtp_GetField(Avtp_AafFieldDesc, AVTP_AAF_FIELD_MAX, (uint8_t*)pdu, (uint8_t) field);
}

uint8_t Avtp_Aaf_GetSubtype(Avtp_Aaf_t* pdu)
{
    return GET_FIELD(AVTP_AAF_FIELD_SUBTYPE);
}

uint8_t Avtp_Aaf_GetSv(Avtp_Aaf_t* pdu)
{
    return GET_FIELD(AVTP_AAF_FIELD_SV);
}

uint8_t Avtp_Aaf_GetVersion(Avtp_Aaf_t* pdu)
{
    return GET_FIELD(AVTP_AAF_FIELD_VERSION);
}

uint8_t Avtp_Aaf_GetMr(Avtp_Aaf_t* pdu)
{
    return GET_FIELD(AVTP_AAF_FIELD_MR);
}

uint8_t Avtp_Aaf_GetTv(Avtp_Aaf_t* pdu)
{
    return GET_FIELD(AVTP_AAF_FIELD_TV);
}

uint8_t Avtp_Aaf_GetSequenceNum(Avtp_Aaf_t* pdu)
{
    return GET_FIELD(AVTP_AAF_FIELD_SEQUENCE_NUM);
}

uint8_t Avtp_Aaf_GetTu(Avtp_Aaf_t* pdu)
{
    return GET_FIELD(AVTP_AAF_FIELD_TU);
}

uint64_t Avtp_Aaf_GetStreamId(Avtp_Aaf_t* pdu)
{
    return GET_FIELD(AVTP_AAF_FIELD_STREAM_ID);
}

uint32_t Avtp_Aaf_GetAvtpTimestamp(Avtp_Aaf_t* pdu)
{
    return GET_FIELD(AVTP_AAF_FIELD_AVTP_TIMESTAMP);
}

uint8_t Avtp_Aaf_GetFormat(Avtp_Aaf_t* pdu)
{
    return GET_FIELD(AVTP_AAF_FIELD_FORMAT);
}

uint16_t Avtp_Aaf_GetStreamDataLength(Avtp_Aaf_t* pdu)
{
    return GET_FIELD(AVTP_AAF_FIELD_STREAM_DATA_LENGTH);
}

uint8_t Avtp_Aaf_GetAfsd(Avtp_Aaf_t* pdu)
{
    return GET_FIELD(AVTP_AAF_FIELD_AFSD);
}

uint8_t Avtp_Aaf_GetSp(Avtp_Aaf_t* pdu)
{
    return GET_FIELD(AVTP_AAF_FIELD_SP);
}

uint8_t Avtp_Aaf_GetEvt(Avtp_Aaf_t* pdu)
{
    return GET_FIELD(AVTP_AAF_FIELD_EVT);
}

void Avtp_Aaf_SetField(Avtp_Aaf_t* pdu, Avtp_AafFields_t field, uint64_t value)
{
    Avtp_SetField(Avtp_AafFieldDesc, AVTP_AAF_FIELD_MAX, (uint8_t*)pdu, (uint8_t) field, value);
}

void Avtp_Aaf_SetSubtype(Avtp_Aaf_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_AAF_FIELD_SUBTYPE, value);
}

void Avtp_Can_EnableSv(Avtp_Aaf_t* pdu)
{
    SET_FIELD(AVTP_AAF_FIELD_SV, 1);
}

void Avtp_Can_DisableSv(Avtp_Aaf_t* pdu)
{
    SET_FIELD(AVTP_AAF_FIELD_SV, 0);
}

void Avtp_Aaf_SetVersion(Avtp_Aaf_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_AAF_FIELD_VERSION, value);
}

void Avtp_Can_EnableMr(Avtp_Aaf_t* pdu)
{
    SET_FIELD(AVTP_AAF_FIELD_MR, 1);
}

void Avtp_Can_DisableMr(Avtp_Aaf_t* pdu)
{
    SET_FIELD(AVTP_AAF_FIELD_MR, 0);
}

void Avtp_Can_EnableTv(Avtp_Aaf_t* pdu)
{
    SET_FIELD(AVTP_AAF_FIELD_TV, 1);
}

void Avtp_Can_DisableTv(Avtp_Aaf_t* pdu)
{
    SET_FIELD(AVTP_AAF_FIELD_TV, 0);
}

void Avtp_Aaf_SetSequenceNum(Avtp_Aaf_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_AAF_FIELD_SEQUENCE_NUM, value);
}

void Avtp_Can_EnableTu(Avtp_Aaf_t* pdu)
{
    SET_FIELD(AVTP_AAF_FIELD_TU, 1);
}

void Avtp_Can_DisableTu(Avtp_Aaf_t* pdu)
{
    SET_FIELD(AVTP_AAF_FIELD_TU, 0);
}

void Avtp_Aaf_SetStreamId(Avtp_Aaf_t* pdu, uint64_t value)
{
    SET_FIELD(AVTP_AAF_FIELD_STREAM_ID, value);
}

void Avtp_Aaf_SetAvtpTimestamp(Avtp_Aaf_t* pdu, uint32_t value)
{
    SET_FIELD(AVTP_AAF_FIELD_AVTP_TIMESTAMP, value);
}

void Avtp_Aaf_SetFormat(Avtp_Aaf_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_AAF_FIELD_FORMAT, value);
}

void Avtp_Aaf_SetStreamDataLength(Avtp_Aaf_t* pdu, uint16_t value)
{
    SET_FIELD(AVTP_AAF_FIELD_STREAM_DATA_LENGTH, value);
}

void Avtp_Aaf_SetAfsd(Avtp_Aaf_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_AAF_FIELD_AFSD, value);
}

void Avtp_Can_EnableSp(Avtp_Aaf_t* pdu)
{
    SET_FIELD(AVTP_AAF_FIELD_SP, 1);
}

void Avtp_Can_DisableSp(Avtp_Aaf_t* pdu)
{
    SET_FIELD(AVTP_AAF_FIELD_SP, 0);
}

void Avtp_Aaf_SetEvt(Avtp_Aaf_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_AAF_FIELD_EVT, value);
}
