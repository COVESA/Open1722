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

#include "avtp/cvf/Cvf.h"
#include "avtp/Utils.h"
#include "avtp/CommonHeader.h"

#define GET_FIELD(field) \
        (Avtp_GetField(fieldDescriptors, AVTP_CVF_FIELD_MAX, (uint8_t*)pdu, field))
#define SET_FIELD(field, value) \
        (Avtp_SetField(fieldDescriptors, AVTP_CVF_FIELD_MAX, (uint8_t*)pdu, field, value))

static const Avtp_FieldDescriptor_t fieldDescriptors[AVTP_CVF_FIELD_MAX] =
{
    [AVTP_CVF_FIELD_SUBTYPE]            = { .quadlet = 0, .offset = 0, .bits = 8 },
    [AVTP_CVF_FIELD_SV]                 = { .quadlet = 0, .offset = 8, .bits = 1 },
    [AVTP_CVF_FIELD_VERSION]            = { .quadlet = 0, .offset = 9, .bits = 3 },
    [AVTP_CVF_FIELD_MR]                 = { .quadlet = 0, .offset = 12, .bits = 1 },
    [AVTP_CVF_FIELD_RESERVED]           = { .quadlet = 0, .offset = 13, .bits = 2 },
    [AVTP_CVF_FIELD_TV]                 = { .quadlet = 0, .offset = 15, .bits = 1 },
    [AVTP_CVF_FIELD_SEQUENCE_NUM]       = { .quadlet = 0, .offset = 16, .bits = 8 },
    [AVTP_CVF_FIELD_RESERVED_2]         = { .quadlet = 0, .offset = 24, .bits = 7 },
    [AVTP_CVF_FIELD_TU]                 = { .quadlet = 0, .offset = 31, .bits = 1 },
    [AVTP_CVF_FIELD_STREAM_ID]          = { .quadlet = 1, .offset = 0, .bits = 64 },
    [AVTP_CVF_FIELD_AVTP_TIMESTAMP]     = { .quadlet = 3, .offset = 0, .bits = 32 },
    [AVTP_CVF_FIELD_FORMAT]             = { .quadlet = 4, .offset = 0, .bits = 8 },
    [AVTP_CVF_FIELD_FORMAT_SUBTYPE]     = { .quadlet = 4, .offset = 8, .bits = 8 },
    [AVTP_CVF_FIELD_RESERVED_3]         = { .quadlet = 4, .offset = 16, .bits = 16 },
    [AVTP_CVF_FIELD_STREAM_DATA_LENGTH] = { .quadlet = 5, .offset = 0, .bits = 16 },
    [AVTP_CVF_FIELD_RESERVED_4]         = { .quadlet = 5, .offset = 16, .bits = 2 },
    [AVTP_CVF_FIELD_PTV]                = { .quadlet = 5, .offset = 18, .bits = 1 },
    [AVTP_CVF_FIELD_M]                  = { .quadlet = 5, .offset = 19, .bits = 1 },
    [AVTP_CVF_FIELD_EVT]                = { .quadlet = 5, .offset = 20, .bits = 4 },
    [AVTP_CVF_FIELD_RESERVED_5]         = { .quadlet = 5, .offset = 24, .bits = 8 },
};

void Avtp_Cvf_Init(Avtp_Cvf_t* pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_Cvf_t));
        Avtp_Cvf_SetField(pdu, AVTP_CVF_FIELD_SUBTYPE, AVTP_SUBTYPE_CVF);
        Avtp_Cvf_SetField(pdu, AVTP_CVF_FIELD_FORMAT, AVTP_CVF_FORMAT_RFC);
        Avtp_Cvf_EnableSv(pdu);
    }
}

uint64_t Avtp_Cvf_GetField(Avtp_Cvf_t* pdu, Avtp_CvfField_t field)
{
    return GET_FIELD(field);
}

uint8_t Avtp_Cvf_GetSubtype(Avtp_Cvf_t* pdu)
{
    return GET_FIELD(AVTP_CVF_FIELD_SUBTYPE);
}

uint8_t Avtp_Cvf_GetSv(Avtp_Cvf_t* pdu)
{
    return GET_FIELD(AVTP_CVF_FIELD_SV);
}

uint8_t Avtp_Cvf_GetVersion(Avtp_Cvf_t* pdu)
{
    return GET_FIELD(AVTP_CVF_FIELD_VERSION);
}

uint8_t Avtp_Cvf_GetMr(Avtp_Cvf_t* pdu)
{
    return GET_FIELD(AVTP_CVF_FIELD_MR);
}

uint8_t Avtp_Cvf_GetTv(Avtp_Cvf_t* pdu)
{
    return GET_FIELD(AVTP_CVF_FIELD_TV);
}

uint8_t Avtp_Cvf_GetSequenceNum(Avtp_Cvf_t* pdu)
{
    return GET_FIELD(AVTP_CVF_FIELD_SEQUENCE_NUM);
}

uint8_t Avtp_Cvf_GetTu(Avtp_Cvf_t* pdu)
{
    return GET_FIELD(AVTP_CVF_FIELD_TU);
}

uint64_t Avtp_Cvf_GetStreamId(Avtp_Cvf_t* pdu)
{
    return GET_FIELD(AVTP_CVF_FIELD_STREAM_ID);
}

uint32_t Avtp_Cvf_GetAvtpTimestamp(Avtp_Cvf_t* pdu)
{
    return GET_FIELD(AVTP_CVF_FIELD_AVTP_TIMESTAMP);
}

Avtp_CvfFormat_t Avtp_Cvf_GetFormat(Avtp_Cvf_t* pdu)
{
    return GET_FIELD(AVTP_CVF_FIELD_FORMAT);
}

Avtp_CvfFormatSubtype_t Avtp_Cvf_GetFormatSubtype(Avtp_Cvf_t* pdu)
{
    return GET_FIELD(AVTP_CVF_FIELD_FORMAT_SUBTYPE);
}

uint16_t Avtp_Cvf_GetStreamDataLength(Avtp_Cvf_t* pdu)
{
    return GET_FIELD(AVTP_CVF_FIELD_STREAM_DATA_LENGTH);
}

uint8_t Avtp_Cvf_GetPtv(Avtp_Cvf_t* pdu)
{
    return GET_FIELD(AVTP_CVF_FIELD_PTV);
}

uint8_t Avtp_Cvf_GetM(Avtp_Cvf_t* pdu)
{
    return GET_FIELD(AVTP_CVF_FIELD_M);
}

uint8_t Avtp_Cvf_GetEvt(Avtp_Cvf_t* pdu)
{
    return GET_FIELD(AVTP_CVF_FIELD_EVT);
}

void Avtp_Cvf_SetField(Avtp_Cvf_t* pdu, Avtp_CvfField_t field, uint64_t value)
{
    SET_FIELD(field, value);
}

void Avtp_Cvf_SetSubtype(Avtp_Cvf_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_CVF_FIELD_SUBTYPE, value);
}

void Avtp_Cvf_EnableSv(Avtp_Cvf_t* pdu)
{
    SET_FIELD(AVTP_CVF_FIELD_SV, 1);
}

void Avtp_Cvf_DisableSv(Avtp_Cvf_t* pdu)
{
    SET_FIELD(AVTP_CVF_FIELD_SV, 0);
}

void Avtp_Cvf_SetVersion(Avtp_Cvf_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_CVF_FIELD_VERSION, value);
}

void Avtp_Cvf_EnableMr(Avtp_Cvf_t* pdu)
{
    SET_FIELD(AVTP_CVF_FIELD_MR, 1);
}

void Avtp_Cvf_DisableMr(Avtp_Cvf_t* pdu)
{
    SET_FIELD(AVTP_CVF_FIELD_MR, 0);
}

void Avtp_Cvf_EnableTv(Avtp_Cvf_t* pdu)
{
    SET_FIELD(AVTP_CVF_FIELD_TV, 1);
}

void Avtp_Cvf_DisableTv(Avtp_Cvf_t* pdu)
{
    SET_FIELD(AVTP_CVF_FIELD_TV, 0);
}

void Avtp_Cvf_SetSequenceNum(Avtp_Cvf_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_CVF_FIELD_SEQUENCE_NUM, value);
}

void Avtp_Cvf_EnableTu(Avtp_Cvf_t* pdu)
{
    SET_FIELD(AVTP_CVF_FIELD_TU, 1);
}

void Avtp_Cvf_DisableTu(Avtp_Cvf_t* pdu)
{
    SET_FIELD(AVTP_CVF_FIELD_TU, 0);
}

void Avtp_Cvf_SetStreamId(Avtp_Cvf_t* pdu, uint64_t value)
{
    SET_FIELD(AVTP_CVF_FIELD_STREAM_ID, value);
}

void Avtp_Cvf_SetAvtpTimestamp(Avtp_Cvf_t* pdu, uint32_t value)
{
    SET_FIELD(AVTP_CVF_FIELD_AVTP_TIMESTAMP, value);
}

void Avtp_Cvf_SetFormat(Avtp_Cvf_t* pdu, Avtp_CvfFormat_t value)
{
    SET_FIELD(AVTP_CVF_FIELD_FORMAT, value);
}

void Avtp_Cvf_SetFormatSubtype(Avtp_Cvf_t* pdu, Avtp_CvfFormatSubtype_t value)
{
    SET_FIELD(AVTP_CVF_FIELD_FORMAT_SUBTYPE, value);
}

void Avtp_Cvf_SetStreamDataLength(Avtp_Cvf_t* pdu, uint16_t value)
{
    SET_FIELD(AVTP_CVF_FIELD_STREAM_DATA_LENGTH, value);
}

void Avtp_Cvf_EnablePtv(Avtp_Cvf_t* pdu)
{
    SET_FIELD(AVTP_CVF_FIELD_PTV, 1);
}

void Avtp_Cvf_DisablePtv(Avtp_Cvf_t* pdu)
{
    SET_FIELD(AVTP_CVF_FIELD_PTV, 0);
}

void Avtp_Cvf_EnableM(Avtp_Cvf_t* pdu)
{
    SET_FIELD(AVTP_CVF_FIELD_M, 1);
}

void Avtp_Cvf_DisableM(Avtp_Cvf_t* pdu)
{
    SET_FIELD(AVTP_CVF_FIELD_M, 0);
}

void Avtp_Cvf_SetEvt(Avtp_Cvf_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_CVF_FIELD_EVT, value);
}

/******************************************************************************
 * Legacy API (deprecated)
 *****************************************************************************/

int avtp_cvf_pdu_get(void* pdu, Avtp_CvfField_t field, uint64_t *val)
{
    if (pdu == NULL || val == NULL || field >= AVTP_CVF_FIELD_MAX) {
        return -EINVAL;
    } else {
        *val = Avtp_Cvf_GetField((Avtp_Cvf_t*)pdu, field);
        return 0;
    }
}

int avtp_cvf_pdu_set(void* pdu, Avtp_CvfField_t field, uint64_t val)
{
    if (pdu == NULL || field >= AVTP_CVF_FIELD_MAX) {
        return -EINVAL;
    } else {
        Avtp_Cvf_SetField((Avtp_Cvf_t*)pdu, field, val);
        return 0;
    }
}

int avtp_cvf_pdu_init(void* pdu, uint8_t format_subtype)
{
    if (pdu == NULL) {
        return -EINVAL;
    } else {
        Avtp_Cvf_Init(pdu);
        Avtp_Cvf_SetFormatSubtype(pdu, format_subtype);
        return 0;
    }
}
