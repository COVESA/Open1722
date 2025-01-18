 /*
 * Copyright (c) 2024, COVESA
 * Copyright (c) 2021, Fastree3D
 * Adrian Fiergolski <Adrian.Fiergolski@fastree3d.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of Fastree3D, COVESA nor the names of their
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

#include "avtp/Rvf.h"
#include "avtp/Utils.h"
#include "avtp/CommonHeader.h"

#define GET_FIELD(field) \
        (Avtp_GetField(Avtp_RvfFieldDesc, AVTP_RVF_FIELD_MAX, (uint8_t*)pdu, field))
#define SET_FIELD(field, value) \
        (Avtp_SetField(Avtp_RvfFieldDesc, AVTP_RVF_FIELD_MAX, (uint8_t*)pdu, field, value))

/**
 * This table maps all IEEE 1722 Raw Video Format (RVF) specific header fields
 * to a descriptor.
 */
static const Avtp_FieldDescriptor_t Avtp_RvfFieldDesc[AVTP_RVF_FIELD_MAX] =
{
    [AVTP_RVF_FIELD_SUBTYPE]               = { .quadlet = 0, .offset = 0, .bits = 8 },
    [AVTP_RVF_FIELD_SV]                    = { .quadlet = 0, .offset = 8, .bits = 1 },
    [AVTP_RVF_FIELD_VERSION]               = { .quadlet = 0, .offset = 9, .bits = 3 },
    [AVTP_RVF_FIELD_MR]                    = { .quadlet = 0, .offset = 12, .bits = 1 },
    [AVTP_RVF_FIELD_RESERVED]              = { .quadlet = 0, .offset = 13, .bits = 2 },
    [AVTP_RVF_FIELD_TV]                    = { .quadlet = 0, .offset = 15, .bits = 1 },
    [AVTP_RVF_FIELD_SEQUENCE_NUM]          = { .quadlet = 0, .offset = 16, .bits = 8 },
    [AVTP_RVF_FIELD_RESERVED_2]            = { .quadlet = 0, .offset = 24, .bits = 7 },
    [AVTP_RVF_FIELD_TU]                    = { .quadlet = 0, .offset = 31, .bits = 1 },
    [AVTP_RVF_FIELD_STREAM_ID]             = { .quadlet = 1, .offset = 0, .bits = 64 },
    [AVTP_RVF_FIELD_AVTP_TIMESTAMP]        = { .quadlet = 3, .offset = 0, .bits = 32 },
    [AVTP_RVF_FIELD_ACTIVE_PIXELS]         = { .quadlet = 4, .offset = 0, .bits = 16 },
    [AVTP_RVF_FIELD_TOTAL_LINES]           = { .quadlet = 4, .offset = 16, .bits = 16 },
    [AVTP_RVF_FIELD_STREAM_DATA_LENGTH]    = { .quadlet = 5, .offset = 0, .bits = 16 },
    [AVTP_RVF_FIELD_AP]                    = { .quadlet = 5, .offset = 16, .bits = 1 },
    [AVTP_RVF_FIELD_RESERVED_3]            = { .quadlet = 5, .offset = 17, .bits = 1 },
    [AVTP_RVF_FIELD_F]                     = { .quadlet = 5, .offset = 18, .bits = 1 },
    [AVTP_RVF_FIELD_EF]                    = { .quadlet = 5, .offset = 19, .bits = 1 },
    [AVTP_RVF_FIELD_EVT]                   = { .quadlet = 5, .offset = 20, .bits = 4 },
    [AVTP_RVF_FIELD_PD]                    = { .quadlet = 5, .offset = 24, .bits = 1 },
    [AVTP_RVF_FIELD_I]                     = { .quadlet = 5, .offset = 25, .bits = 1 },
    [AVTP_RVF_FIELD_RESERVED_4]            = { .quadlet = 5, .offset = 26, .bits = 6 },
    [AVTP_RVF_FIELD_RESERVED_5]            = { .quadlet = 6, .offset = 0, .bits = 8 },
    [AVTP_RVF_FIELD_PIXEL_DEPTH]           = { .quadlet = 6, .offset = 8, .bits = 4 },
    [AVTP_RVF_FIELD_PIXEL_FORMAT]          = { .quadlet = 6, .offset = 12, .bits = 4 },
    [AVTP_RVF_FIELD_FRAME_RATE]            = { .quadlet = 6, .offset = 16, .bits = 8 },
    [AVTP_RVF_FIELD_COLORSPACE]            = { .quadlet = 6, .offset = 24, .bits = 4 },
    [AVTP_RVF_FIELD_NUM_LINES]             = { .quadlet = 6, .offset = 28, .bits = 4 },
    [AVTP_RVF_FIELD_RESERVED_6]            = { .quadlet = 7, .offset = 0, .bits = 8 },
    [AVTP_RVF_FIELD_I_SEQ_NUM]             = { .quadlet = 7, .offset = 8, .bits = 8 },
    [AVTP_RVF_FIELD_LINE_NUMBER]           = { .quadlet = 7, .offset = 16, .bits = 16 },
};

void Avtp_Rvf_Init(Avtp_Rvf_t* pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_Rvf_t));
        Avtp_Rvf_SetField(pdu, AVTP_RVF_FIELD_SUBTYPE, AVTP_SUBTYPE_RVF);
        Avtp_Rvf_SetField(pdu, AVTP_RVF_FIELD_SV, 1);
    }
}

uint64_t Avtp_Rvf_GetField(Avtp_Rvf_t* pdu, Avtp_RvfField_t field)
{
    return GET_FIELD(field);
}

uint8_t Avtp_Rvf_GetSubtype(Avtp_Rvf_t* pdu)
{
    return GET_FIELD(AVTP_RVF_FIELD_SUBTYPE);
}

uint8_t Avtp_Rvf_GetSv(Avtp_Rvf_t* pdu)
{
    return GET_FIELD(AVTP_RVF_FIELD_SV);
}

uint8_t Avtp_Rvf_GetVersion(Avtp_Rvf_t* pdu)
{
    return GET_FIELD(AVTP_RVF_FIELD_VERSION);
}

uint8_t Avtp_Rvf_GetMr(Avtp_Rvf_t* pdu)
{
    return GET_FIELD(AVTP_RVF_FIELD_MR);
}

uint8_t Avtp_Rvf_GetTv(Avtp_Rvf_t* pdu)
{
    return GET_FIELD(AVTP_RVF_FIELD_TV);
}

uint8_t Avtp_Rvf_GetSequenceNum(Avtp_Rvf_t* pdu)
{
    return GET_FIELD(AVTP_RVF_FIELD_SEQUENCE_NUM);
}

uint8_t Avtp_Rvf_GetTu(Avtp_Rvf_t* pdu)
{
    return GET_FIELD(AVTP_RVF_FIELD_TU);
}

uint64_t Avtp_Rvf_GetStreamId(Avtp_Rvf_t* pdu)
{
    return GET_FIELD(AVTP_RVF_FIELD_STREAM_ID);
}

uint32_t Avtp_Rvf_GetAvtpTimestamp(Avtp_Rvf_t* pdu)
{
    return GET_FIELD(AVTP_RVF_FIELD_AVTP_TIMESTAMP);
}

uint16_t Avtp_Rvf_GetActivePixels(Avtp_Rvf_t* pdu)
{
    return GET_FIELD(AVTP_RVF_FIELD_ACTIVE_PIXELS);
}

uint16_t Avtp_Rvf_GetTotalLines(Avtp_Rvf_t* pdu)
{
    return GET_FIELD(AVTP_RVF_FIELD_TOTAL_LINES);
}

uint16_t Avtp_Rvf_GetStreamDataLength(Avtp_Rvf_t* pdu)
{
    return GET_FIELD(AVTP_RVF_FIELD_STREAM_DATA_LEN);
}

uint8_t Avtp_Rvf_GetAp(Avtp_Rvf_t* pdu)
{
    return GET_FIELD(AVTP_RVF_FIELD_AP);
}

uint8_t Avtp_Rvf_GetF(Avtp_Rvf_t* pdu)
{
    return GET_FIELD(AVTP_RVF_FIELD_F);
}

uint8_t Avtp_Rvf_GetEf(Avtp_Rvf_t* pdu)
{
    return GET_FIELD(AVTP_RVF_FIELD_EF);
}

uint8_t Avtp_Rvf_GetEvt(Avtp_Rvf_t* pdu)
{
    return GET_FIELD(AVTP_RVF_FIELD_EVT);
}

uint8_t Avtp_Rvf_GetPd(Avtp_Rvf_t* pdu)
{
    return GET_FIELD(AVTP_RVF_FIELD_PD);
}

uint8_t Avtp_Rvf_GetI(Avtp_Rvf_t* pdu)
{
    return GET_FIELD(AVTP_RVF_FIELD_I);
}

Avtp_RvfPixelDepth_t Avtp_Rvf_GetPixelDepth(Avtp_Rvf_t* pdu)
{
    return GET_FIELD(AVTP_RVF_FIELD_PIXEL_DEPTH);
}

Avtp_RvfPixelFormat_t Avtp_Rvf_GetPixelFormat(Avtp_Rvf_t* pdu)
{
    return GET_FIELD(AVTP_RVF_FIELD_PIXEL_FORMAT);
}

Avtp_RvfFrameRate_t Avtp_Rvf_GetFrameRate(Avtp_Rvf_t* pdu)
{
    return GET_FIELD(AVTP_RVF_FIELD_FRAME_RATE);
}

Avtp_RvfColorspace_t Avtp_Rvf_GetColorspace(Avtp_Rvf_t* pdu)
{
    return GET_FIELD(AVTP_RVF_FIELD_COLORSPACE);
}

uint8_t Avtp_Rvf_GetNumLines(Avtp_Rvf_t* pdu)
{
    return GET_FIELD(AVTP_RVF_FIELD_NUM_LINES);
}

uint8_t Avtp_Rvf_GetISeqNum(Avtp_Rvf_t* pdu)
{
    return GET_FIELD(AVTP_RVF_FIELD_I_SEQ_NUM);
}

uint16_t Avtp_Rvf_GetLineNumber(Avtp_Rvf_t* pdu)
{
    return GET_FIELD(AVTP_RVF_FIELD_LINE_NUMBER);
}

void Avtp_Rvf_SetField(Avtp_Rvf_t* pdu, Avtp_RvfField_t field, uint64_t value)
{
    SET_FIELD(field, value);
}

void Avtp_Rvf_SetSubtype(Avtp_Rvf_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_RVF_FIELD_SUBTYPE, value);
}

void Avtp_Rvf_EnableSv(Avtp_Rvf_t* pdu)
{
    SET_FIELD(AVTP_RVF_FIELD_SV, 1);
}

void Avtp_Rvf_DisableSv(Avtp_Rvf_t* pdu)
{
    SET_FIELD(AVTP_RVF_FIELD_SV, 0);
}

void Avtp_Rvf_SetVersion(Avtp_Rvf_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_RVF_FIELD_VERSION, value);
}

void Avtp_Rvf_EnableMr(Avtp_Rvf_t* pdu)
{
    SET_FIELD(AVTP_RVF_FIELD_MR, 1);
}

void Avtp_Rvf_DisableMr(Avtp_Rvf_t* pdu)
{
    SET_FIELD(AVTP_RVF_FIELD_MR, 0);
}

void Avtp_Rvf_EnableTv(Avtp_Rvf_t* pdu)
{
    SET_FIELD(AVTP_RVF_FIELD_TV, 1);
}

void Avtp_Rvf_DisableTv(Avtp_Rvf_t* pdu)
{
    SET_FIELD(AVTP_RVF_FIELD_TV, 0);
}

void Avtp_Rvf_SetSequenceNum(Avtp_Rvf_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_RVF_FIELD_SEQ_NUM, value);
}

void Avtp_Rvf_EnableTu(Avtp_Rvf_t* pdu)
{
    SET_FIELD(AVTP_RVF_FIELD_TU, 1);
}

void Avtp_Rvf_DisableTu(Avtp_Rvf_t* pdu)
{
    SET_FIELD(AVTP_RVF_FIELD_TU, 0);
}

void Avtp_Rvf_SetStreamId(Avtp_Rvf_t* pdu, uint64_t value)
{
    SET_FIELD(AVTP_RVF_FIELD_STREAM_ID, value);
}

void Avtp_Rvf_SetAvtpTimestamp(Avtp_Rvf_t* pdu, uint32_t value)
{
    SET_FIELD(AVTP_RVF_FIELD_AVTP_TIMESTAMP, value);
}

void Avtp_Rvf_SetActivePixels(Avtp_Rvf_t* pdu, uint16_t value)
{
    SET_FIELD(AVTP_RVF_FIELD_ACTIVE_PIXELS, value);
}

void Avtp_Rvf_SetTotalLines(Avtp_Rvf_t* pdu, uint16_t value)
{
    SET_FIELD(AVTP_RVF_FIELD_TOTAL_LINES, value);
}

void Avtp_Rvf_SetStreamDataLength(Avtp_Rvf_t* pdu, uint16_t value)
{
    SET_FIELD(AVTP_RVF_FIELD_STREAM_DATA_LEN, value);
}

void Avtp_Rvf_EnableAp(Avtp_Rvf_t* pdu)
{
    SET_FIELD(AVTP_RVF_FIELD_AP, 1);
}

void Avtp_Rvf_DisableAp(Avtp_Rvf_t* pdu)
{
    SET_FIELD(AVTP_RVF_FIELD_AP, 0);
}

void Avtp_Rvf_EnableF(Avtp_Rvf_t* pdu)
{
    SET_FIELD(AVTP_RVF_FIELD_F, 1);
}

void Avtp_Rvf_DisableF(Avtp_Rvf_t* pdu)
{
    SET_FIELD(AVTP_RVF_FIELD_F, 0);
}

void Avtp_Rvf_EnableEf(Avtp_Rvf_t* pdu)
{
    SET_FIELD(AVTP_RVF_FIELD_EF, 1);
}

void Avtp_Rvf_DisableEf(Avtp_Rvf_t* pdu)
{
    SET_FIELD(AVTP_RVF_FIELD_EF, 0);
}

void Avtp_Rvf_SetEvt(Avtp_Rvf_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_RVF_FIELD_EVT, value);
}

void Avtp_Rvf_EnablePd(Avtp_Rvf_t* pdu)
{
    SET_FIELD(AVTP_RVF_FIELD_PD, 1);
}

void Avtp_Rvf_DisablePd(Avtp_Rvf_t* pdu)
{
    SET_FIELD(AVTP_RVF_FIELD_PD, 0);
}

void Avtp_Rvf_EnableI(Avtp_Rvf_t* pdu)
{
    SET_FIELD(AVTP_RVF_FIELD_I, 1);
}

void Avtp_Rvf_DisableI(Avtp_Rvf_t* pdu)
{
    SET_FIELD(AVTP_RVF_FIELD_I, 0);
}

void Avtp_Rvf_SetPixelDepth(Avtp_Rvf_t* pdu, Avtp_RvfPixelDepth_t value)
{
    SET_FIELD(AVTP_RVF_FIELD_PIXEL_DEPTH, value);
}

void Avtp_Rvf_SetPixelFormat(Avtp_Rvf_t* pdu, Avtp_RvfPixelFormat_t value)
{
    SET_FIELD(AVTP_RVF_FIELD_PIXEL_FORMAT, value);
}

void Avtp_Rvf_SetFrameRate(Avtp_Rvf_t* pdu, Avtp_RvfFrameRate_t value)
{
    SET_FIELD(AVTP_RVF_FIELD_FRAME_RATE, value);
}

void Avtp_Rvf_SetColorspace(Avtp_Rvf_t* pdu, Avtp_RvfColorspace_t value)
{
    SET_FIELD(AVTP_RVF_FIELD_COLORSPACE, value);
}

void Avtp_Rvf_SetNumLines(Avtp_Rvf_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_RVF_FIELD_NUM_LINES, value);
}

void Avtp_Rvf_SetISeqNum(Avtp_Rvf_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_RVF_FIELD_I_SEQ_NUM, value);
}

void Avtp_Rvf_SetLineNumber(Avtp_Rvf_t* pdu, uint16_t value)
{
    SET_FIELD(AVTP_RVF_FIELD_LINE_NUMBER, value);
}

/******************************************************************************
 * Legacy API
 *****************************************************************************/

int avtp_rvf_pdu_get(const void* pdu, Avtp_RvfField_t field, uint64_t* val)
{
    if (pdu == NULL || val == NULL || field >= AVTP_RVF_FIELD_MAX) {
        return -EINVAL;
    } else {
        *val = Avtp_Rvf_GetField((Avtp_Rvf_t*)pdu, field);
        return 0;
    }
}

int avtp_rvf_pdu_set(void* pdu, Avtp_RvfField_t field, uint64_t val)
{
    if (pdu == NULL || field >= AVTP_RVF_FIELD_MAX) {
        return -EINVAL;
    } else {
        Avtp_Rvf_SetField((Avtp_Rvf_t*)pdu, field, val);
        return 0;
    }
}

int avtp_rvf_pdu_init(void* pdu)
{
    if (pdu == NULL) {
        return -EINVAL;
    } else {
        Avtp_Rvf_Init((Avtp_Rvf_t*)pdu);
        return 0;
    }
}
