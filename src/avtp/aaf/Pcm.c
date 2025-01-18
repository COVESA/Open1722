/*
 * Copyright (c) 2024, COVESA
 * Copyright (c) 2019, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of COVESA, Intel Corporation nor the names of its
 *      contributors  may be used to endorse or promote products derived from
 *      this software without specific prior written permission.
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
#include "avtp/aaf/Pcm.h"
#include "avtp/Utils.h"

#define GET_FIELD(field) \
        (Avtp_GetField(Avtp_PcmFieldDesc, AVTP_PCM_FIELD_MAX, (uint8_t*)pdu, field))
#define SET_FIELD(field, value) \
        (Avtp_SetField(Avtp_PcmFieldDesc, AVTP_PCM_FIELD_MAX, (uint8_t*)pdu, field, value))

static const Avtp_FieldDescriptor_t Avtp_PcmFieldDesc[AVTP_PCM_FIELD_MAX] =
{
    [AVTP_PCM_FIELD_SUBTYPE]            = { .quadlet = 0, .offset =  0, .bits =  8 },
    [AVTP_PCM_FIELD_SV]                 = { .quadlet = 0, .offset =  8, .bits =  1 },
    [AVTP_PCM_FIELD_VERSION]            = { .quadlet = 0, .offset =  9, .bits =  3 },
    [AVTP_PCM_FIELD_MR]                 = { .quadlet = 0, .offset = 12, .bits =  1 },
    [AVTP_PCM_FIELD_TV]                 = { .quadlet = 0, .offset = 15, .bits =  1 },
    [AVTP_PCM_FIELD_SEQUENCE_NUM]       = { .quadlet = 0, .offset = 16, .bits =  8 },
    [AVTP_PCM_FIELD_TU]                 = { .quadlet = 0, .offset = 31, .bits =  1 },
    [AVTP_PCM_FIELD_STREAM_ID]          = { .quadlet = 1, .offset =  0, .bits = 64 },
    [AVTP_PCM_FIELD_AVTP_TIMESTAMP]     = { .quadlet = 3, .offset =  0, .bits = 32 },
    [AVTP_PCM_FIELD_FORMAT]             = { .quadlet = 4, .offset =  0, .bits =  8 },
    [AVTP_PCM_FIELD_NSR]                = { .quadlet = 4, .offset =  8, .bits =  4 },
    [AVTP_PCM_FIELD_CHANNELS_PER_FRAME] = { .quadlet = 4, .offset = 14, .bits = 10 },
    [AVTP_PCM_FIELD_BIT_DEPTH]          = { .quadlet = 4, .offset = 24, .bits =  8 },
    [AVTP_PCM_FIELD_STREAM_DATA_LENGTH] = { .quadlet = 5, .offset =  0, .bits = 16 },
    [AVTP_PCM_FIELD_SP]                 = { .quadlet = 5, .offset = 19, .bits =  1 },
    [AVTP_PCM_FIELD_EVT]                = { .quadlet = 5, .offset = 20, .bits =  4 },
};

void Avtp_Pcm_Init(Avtp_Pcm_t* pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_Pcm_t));
        Avtp_Pcm_SetField(pdu, AVTP_PCM_FIELD_SUBTYPE, AVTP_SUBTYPE_AAF);
        Avtp_Pcm_SetField(pdu, AVTP_PCM_FIELD_SV, 1);
    }
}

uint64_t Avtp_Pcm_GetField(Avtp_Pcm_t* pdu, Avtp_PcmFields_t field)
{
    return GET_FIELD(field);
}

uint8_t Avtp_Pcm_GetSubtype(Avtp_Pcm_t* pdu)
{
    return GET_FIELD(AVTP_PCM_FIELD_SUBTYPE);
}

uint8_t Avtp_Pcm_GetSv(Avtp_Pcm_t* pdu)
{
    return GET_FIELD(AVTP_PCM_FIELD_SV);
}

uint8_t Avtp_Pcm_GetVersion(Avtp_Pcm_t* pdu)
{
    return GET_FIELD(AVTP_PCM_FIELD_VERSION);
}

uint8_t Avtp_Pcm_GetMr(Avtp_Pcm_t* pdu)
{
    return GET_FIELD(AVTP_PCM_FIELD_MR);
}

uint8_t Avtp_Pcm_GetTv(Avtp_Pcm_t* pdu)
{
    return GET_FIELD(AVTP_PCM_FIELD_TV);
}

uint8_t Avtp_Pcm_GetSequenceNum(Avtp_Pcm_t* pdu)
{
    return GET_FIELD(AVTP_PCM_FIELD_SEQUENCE_NUM);
}

uint8_t Avtp_Pcm_GetTu(Avtp_Pcm_t* pdu)
{
    return GET_FIELD(AVTP_PCM_FIELD_TU);
}

uint64_t Avtp_Pcm_GetStreamId(Avtp_Pcm_t* pdu)
{
    return GET_FIELD(AVTP_PCM_FIELD_STREAM_ID);
}

uint32_t Avtp_Pcm_GetAvtpTimestamp(Avtp_Pcm_t* pdu)
{
    return GET_FIELD(AVTP_PCM_FIELD_AVTP_TIMESTAMP);
}

Avtp_AafFormat_t Avtp_Pcm_GetFormat(Avtp_Pcm_t* pdu)
{
    return GET_FIELD(AVTP_PCM_FIELD_FORMAT);
}

Avtp_AafNsr_t Avtp_Pcm_GetNsr(Avtp_Pcm_t* pdu)
{
    return GET_FIELD(AVTP_PCM_FIELD_NSR);
}

uint16_t Avtp_Pcm_GetChannelsPerFrame(Avtp_Pcm_t* pdu)
{
    return GET_FIELD(AVTP_PCM_FIELD_CHANNELS_PER_FRAME);
}

uint8_t Avtp_Pcm_GetBitDepth(Avtp_Pcm_t* pdu)
{
    return GET_FIELD(AVTP_PCM_FIELD_BIT_DEPTH);
}

uint16_t Avtp_Pcm_GetStreamDataLength(Avtp_Pcm_t* pdu)
{
    return GET_FIELD(AVTP_PCM_FIELD_STREAM_DATA_LENGTH);
}

Avtp_AafSp_t Avtp_Pcm_GetSp(Avtp_Pcm_t* pdu)
{
    return GET_FIELD(AVTP_PCM_FIELD_SP);
}

uint8_t Avtp_Pcm_GetEvt(Avtp_Pcm_t* pdu)
{
    return GET_FIELD(AVTP_PCM_FIELD_EVT);
}

void Avtp_Pcm_SetField(Avtp_Pcm_t* pdu, Avtp_PcmFields_t field, uint64_t value)
{
    SET_FIELD(field, value);
}

void Avtp_Pcm_SetSubtype(Avtp_Pcm_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_PCM_FIELD_SUBTYPE, value);
}

void Avtp_Pcm_EnableSv(Avtp_Pcm_t* pdu)
{
    SET_FIELD(AVTP_PCM_FIELD_SV, 1);
}

void Avtp_Pcm_DisableSv(Avtp_Pcm_t* pdu)
{
    SET_FIELD(AVTP_PCM_FIELD_SV, 0);
}

void Avtp_Pcm_SetVersion(Avtp_Pcm_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_PCM_FIELD_VERSION, value);
}

void Avtp_Pcm_EnableMr(Avtp_Pcm_t* pdu)
{
    SET_FIELD(AVTP_PCM_FIELD_MR, 1);
}

void Avtp_Pcm_DisableMr(Avtp_Pcm_t* pdu)
{
    SET_FIELD(AVTP_PCM_FIELD_MR, 0);
}

void Avtp_Pcm_EnableTv(Avtp_Pcm_t* pdu)
{
    SET_FIELD(AVTP_PCM_FIELD_TV, 1);
}

void Avtp_Pcm_DisableTv(Avtp_Pcm_t* pdu)
{
    SET_FIELD(AVTP_PCM_FIELD_TV, 0);
}

void Avtp_Pcm_SetSequenceNum(Avtp_Pcm_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_PCM_FIELD_SEQUENCE_NUM, value);
}

void Avtp_Pcm_EnableTu(Avtp_Pcm_t* pdu)
{
    SET_FIELD(AVTP_PCM_FIELD_TU, 1);
}

void Avtp_Pcm_DisableTu(Avtp_Pcm_t* pdu)
{
    SET_FIELD(AVTP_PCM_FIELD_TU, 0);
}

void Avtp_Pcm_SetStreamId(Avtp_Pcm_t* pdu, uint64_t value)
{
    SET_FIELD(AVTP_PCM_FIELD_STREAM_ID, value);
}

void Avtp_Pcm_SetAvtpTimestamp(Avtp_Pcm_t* pdu, uint32_t value)
{
    SET_FIELD(AVTP_PCM_FIELD_AVTP_TIMESTAMP, value);
}

void Avtp_Pcm_SetFormat(Avtp_Pcm_t* pdu, Avtp_AafFormat_t value)
{
    SET_FIELD(AVTP_PCM_FIELD_FORMAT, value);
}

void Avtp_Pcm_SetNsr(Avtp_Pcm_t* pdu, Avtp_AafNsr_t value)
{
    SET_FIELD(AVTP_PCM_FIELD_NSR, value);
}

void Avtp_Pcm_SetChannelsPerFrame(Avtp_Pcm_t* pdu, uint16_t value)
{
    SET_FIELD(AVTP_PCM_FIELD_CHANNELS_PER_FRAME, value);
}

void Avtp_Pcm_SetBitDepth(Avtp_Pcm_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_PCM_FIELD_BIT_DEPTH, value);
}

void Avtp_Pcm_SetStreamDataLength(Avtp_Pcm_t* pdu, uint16_t value)
{
    SET_FIELD(AVTP_PCM_FIELD_STREAM_DATA_LENGTH, value);
}

void Avtp_Pcm_EnableSp(Avtp_Pcm_t* pdu)
{
    SET_FIELD(AVTP_PCM_FIELD_SP, 1);
}

void Avtp_Pcm_DisableSp(Avtp_Pcm_t* pdu)
{
    SET_FIELD(AVTP_PCM_FIELD_SP, 0);
}

void Avtp_Pcm_SetEvt(Avtp_Pcm_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_PCM_FIELD_EVT, value);
}

/******************************************************************************
 * Legacy API (deprecated)
 *****************************************************************************/

int avtp_aaf_pdu_get(void *pdu, Avtp_PcmFields_t field, uint64_t *val)
{
    if (pdu == NULL || val == NULL || field >= AVTP_PCM_FIELD_MAX) {
        return -EINVAL;
    } else {
        *val = Avtp_Pcm_GetField((Avtp_Pcm_t*)pdu, field);
        return 0;
    }
}

int avtp_aaf_pdu_set(void *pdu, Avtp_PcmFields_t field,
                                uint64_t val)
{
    if (pdu == NULL || field >= AVTP_PCM_FIELD_MAX) {
        return -EINVAL;
    } else {
        Avtp_Pcm_SetField((Avtp_Pcm_t*)pdu, field, val);
        return 0;
    }
}

int avtp_aaf_pdu_init(void *pdu)
{
    int res;

    if (!pdu)
        return -EINVAL;

    memset(pdu, 0, sizeof(Avtp_Pcm_t));

    res = avtp_aaf_pdu_set(pdu, AVTP_PCM_FIELD_SUBTYPE, AVTP_SUBTYPE_AAF);
    if (res < 0)
        return res;

    res = avtp_aaf_pdu_set(pdu, AVTP_PCM_FIELD_SV, 1);
    if (res < 0)
        return res;

    return 0;
};
