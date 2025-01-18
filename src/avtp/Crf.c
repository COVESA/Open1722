/*
 * Copyright (c) 2024, COVESA
 * Copyright (c) 2018, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of Intel Corporation, COVESA nor the names of their
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

#include "avtp/Crf.h"
#include "avtp/Utils.h"
#include "avtp/CommonHeader.h"

#define GET_FIELD(field) \
        (Avtp_GetField(Avtp_CrfFieldDescriptors, AVTP_CRF_FIELD_MAX, (uint8_t*)pdu, field))
#define SET_FIELD(field, value) \
        (Avtp_SetField(Avtp_CrfFieldDescriptors, AVTP_CRF_FIELD_MAX, (uint8_t*)pdu, field, value))

/**
 * This table maps all IEEE 1722 Clock Reference Format (CRF) specific header fields
 * to a descriptor.
 */
static const Avtp_FieldDescriptor_t Avtp_CrfFieldDescriptors[AVTP_CRF_FIELD_MAX] =
{
    [AVTP_CRF_FIELD_SUBTYPE]                = { .quadlet = 0, .offset = 0, .bits = 8 },
    [AVTP_CRF_FIELD_SV]                     = { .quadlet = 0, .offset = 8, .bits = 1 },
    [AVTP_CRF_FIELD_VERSION]                = { .quadlet = 0, .offset = 9, .bits = 3 },
    [AVTP_CRF_FIELD_MR]                     = { .quadlet = 0, .offset = 12, .bits = 1 },
    [AVTP_CRF_FIELD_RESERVED]               = { .quadlet = 0, .offset = 13, .bits = 1 },
    [AVTP_CRF_FIELD_FS]                     = { .quadlet = 0, .offset = 14, .bits = 1 },
    [AVTP_CRF_FIELD_TU]                     = { .quadlet = 0, .offset = 15, .bits = 1 },
    [AVTP_CRF_FIELD_SEQUENCE_NUM]           = { .quadlet = 0, .offset = 16, .bits = 8 },
    [AVTP_CRF_FIELD_TYPE]                   = { .quadlet = 0, .offset = 24, .bits = 8 },
    [AVTP_CRF_FIELD_STREAM_ID]              = { .quadlet = 1, .offset = 0, .bits = 64 },
    [AVTP_CRF_FIELD_PULL]                   = { .quadlet = 3, .offset = 0, .bits = 3 },
    [AVTP_CRF_FIELD_BASE_FREQUENCY]         = { .quadlet = 3, .offset = 3, .bits = 29 },
    [AVTP_CRF_FIELD_CRF_DATA_LENGTH]        = { .quadlet = 4, .offset = 0, .bits = 16 },
    [AVTP_CRF_FIELD_TIMESTAMP_INTERVAL]     = { .quadlet = 4, .offset = 16, .bits = 16 },
};

void Avtp_Crf_Init(Avtp_Crf_t* pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_Crf_t));
        Avtp_Crf_SetField(pdu, AVTP_CRF_FIELD_SUBTYPE, AVTP_SUBTYPE_CRF);
        Avtp_Crf_SetField(pdu, AVTP_CRF_FIELD_SV, 1);
    }
}

uint64_t Avtp_Crf_GetField(Avtp_Crf_t* pdu, Avtp_CrfField_t field)
{
    return GET_FIELD(field);
}

uint8_t Avtp_Crf_GetSubtype(Avtp_Crf_t* pdu)
{
    return GET_FIELD(AVTP_CRF_FIELD_SUBTYPE);
}

uint8_t Avtp_Crf_GetSv(Avtp_Crf_t* pdu)
{
    return GET_FIELD(AVTP_CRF_FIELD_SV);
}

uint8_t Avtp_Crf_GetVersion(Avtp_Crf_t* pdu)
{
    return GET_FIELD(AVTP_CRF_FIELD_VERSION);
}

uint8_t Avtp_Crf_GetMr(Avtp_Crf_t* pdu)
{
    return GET_FIELD(AVTP_CRF_FIELD_MR);
}

uint8_t Avtp_Crf_GetFs(Avtp_Crf_t* pdu)
{
    return GET_FIELD(AVTP_CRF_FIELD_FS);
}

uint8_t Avtp_Crf_GetTu(Avtp_Crf_t* pdu)
{
    return GET_FIELD(AVTP_CRF_FIELD_TU);
}

uint8_t Avtp_Crf_GetSequenceNum(Avtp_Crf_t* pdu)
{
    return GET_FIELD(AVTP_CRF_FIELD_SEQUENCE_NUM);
}

uint8_t Avtp_Crf_GetType(Avtp_Crf_t* pdu)
{
    return GET_FIELD(AVTP_CRF_FIELD_TYPE);
}

uint64_t Avtp_Crf_GetStreamId(Avtp_Crf_t* pdu)
{
    return GET_FIELD(AVTP_CRF_FIELD_STREAM_ID);
}

uint8_t Avtp_Crf_GetPull(Avtp_Crf_t* pdu)
{
    return GET_FIELD(AVTP_CRF_FIELD_PULL);
}

uint32_t Avtp_Crf_GetBaseFrequency(Avtp_Crf_t* pdu)
{
    return GET_FIELD(AVTP_CRF_FIELD_BASE_FREQUENCY);
}

uint16_t Avtp_Crf_GetCrfDataLength(Avtp_Crf_t* pdu)
{
    return GET_FIELD(AVTP_CRF_FIELD_CRF_DATA_LENGTH);
}

uint16_t Avtp_Crf_GetTimestampInterval(Avtp_Crf_t* pdu)
{
    return GET_FIELD(AVTP_CRF_FIELD_TIMESTAMP_INTERVAL);
}

void Avtp_Crf_SetField(Avtp_Crf_t* pdu, Avtp_CrfField_t field, uint64_t value)
{
    SET_FIELD(field, value);
}

void Avtp_Crf_SetSubtype(Avtp_Crf_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_CRF_FIELD_SUBTYPE, value);
}

void Avtp_Crf_EnableSv(Avtp_Crf_t* pdu)
{
    SET_FIELD(AVTP_CRF_FIELD_SV, 1);
}

void Avtp_Crf_DisableSv(Avtp_Crf_t* pdu)
{
    SET_FIELD(AVTP_CRF_FIELD_SV, 0);
}

void Avtp_Crf_SetVersion(Avtp_Crf_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_CRF_FIELD_VERSION, value);
}

void Avtp_Crf_EnableMr(Avtp_Crf_t* pdu)
{
    SET_FIELD(AVTP_CRF_FIELD_MR, 1);
}

void Avtp_Crf_DisableMr(Avtp_Crf_t* pdu)
{
    SET_FIELD(AVTP_CRF_FIELD_MR, 0);
}

void Avtp_Crf_EnableFs(Avtp_Crf_t* pdu)
{
    SET_FIELD(AVTP_CRF_FIELD_FS, 1);
}

void Avtp_Crf_DisableFs(Avtp_Crf_t* pdu)
{
    SET_FIELD(AVTP_CRF_FIELD_FS, 0);
}

void Avtp_Crf_EnableTu(Avtp_Crf_t* pdu)
{
    SET_FIELD(AVTP_CRF_FIELD_TU, 1);
}

void Avtp_Crf_DisableTu(Avtp_Crf_t* pdu)
{
    SET_FIELD(AVTP_CRF_FIELD_TU, 0);
}

void Avtp_Crf_SetSequenceNum(Avtp_Crf_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_CRF_FIELD_SEQUENCE_NUM, value);
}

void Avtp_Crf_SetType(Avtp_Crf_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_CRF_FIELD_TYPE, value);
}

void Avtp_Crf_SetStreamId(Avtp_Crf_t* pdu, uint64_t value)
{
    SET_FIELD(AVTP_CRF_FIELD_STREAM_ID, value);
}

void Avtp_Crf_SetPull(Avtp_Crf_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_CRF_FIELD_PULL, value);
}

void Avtp_Crf_SetBaseFrequency(Avtp_Crf_t* pdu, uint32_t value)
{
    SET_FIELD(AVTP_CRF_FIELD_BASE_FREQUENCY, value);
}

void Avtp_Crf_SetCrfDataLength(Avtp_Crf_t* pdu, uint16_t value)
{
    SET_FIELD(AVTP_CRF_FIELD_CRF_DATA_LENGTH, value);
}

void Avtp_Crf_SetTimestampInterval(Avtp_Crf_t* pdu, uint16_t value)
{
    SET_FIELD(AVTP_CRF_FIELD_TIMESTAMP_INTERVAL, value);
}

/******************************************************************************
 * Legacy API
 *****************************************************************************/

int avtp_crf_pdu_get(const void *pdu, Avtp_CrfField_t field, uint64_t *val)
{
    if (pdu == NULL || val == NULL || field >= AVTP_CRF_FIELD_MAX) {
        return -EINVAL;
    } else {
        *val = Avtp_Crf_GetField((Avtp_Crf_t*)pdu, field);
        return 0;
    }
}

int avtp_crf_pdu_set(void *pdu, Avtp_CrfField_t field, uint64_t val)
{
    if (pdu == NULL || field >= AVTP_CRF_FIELD_MAX) {
        return -EINVAL;
    } else {
        Avtp_Crf_SetField((Avtp_Crf_t*)pdu, field, val);
        return 0;
    }
}

int avtp_crf_pdu_init(void *pdu)
{
    if (pdu == NULL) {
        return -EINVAL;
    } else {
        Avtp_Crf_Init((Avtp_Crf_t*)pdu);
        return 0;
    }
}
