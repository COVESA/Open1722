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

#include "avtp/cvf/Jpeg2000.h"
#include "avtp/Utils.h"
#include "avtp/CommonHeader.h"

#define GET_FIELD(field) \
        (Avtp_GetField(fieldDescriptors, AVTP_JPEG2000_FIELD_MAX, (uint8_t*)pdu, field))
#define SET_FIELD(field, value) \
        (Avtp_SetField(fieldDescriptors, AVTP_JPEG2000_FIELD_MAX, (uint8_t*)pdu, field, value))

static const Avtp_FieldDescriptor_t fieldDescriptors[AVTP_JPEG2000_FIELD_MAX] =
{
    [AVTP_JPEG2000_FIELD_TP]                = { .quadlet = 0, .offset = 0, .bits = 2 },
    [AVTP_JPEG2000_FIELD_MHF]               = { .quadlet = 0, .offset = 2, .bits = 2 },
    [AVTP_JPEG2000_FIELD_MH_ID]             = { .quadlet = 0, .offset = 4, .bits = 3 },
    [AVTP_JPEG2000_FIELD_T]                 = { .quadlet = 0, .offset = 7, .bits = 1 },
    [AVTP_JPEG2000_FIELD_PRIORITY]          = { .quadlet = 0, .offset = 8, .bits = 8 },
    [AVTP_JPEG2000_FIELD_TILE_NUMBER]       = { .quadlet = 0, .offset = 16, .bits = 16 },
    [AVTP_JPEG2000_FIELD_RESERVED]          = { .quadlet = 1, .offset = 0, .bits = 8 },
    [AVTP_JPEG2000_FIELD_FRAGMENT_OFFSET]   = { .quadlet = 1, .offset = 8, .bits = 24 },
};

void Avtp_Jpeg2000_Init(Avtp_Jpeg2000_t* pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_Jpeg2000_t));
    }
}

uint64_t Avtp_Jpeg2000_GetField(Avtp_Jpeg2000_t* pdu, Avtp_Jpeg2000Field_t field)
{
    return GET_FIELD(field);
}

uint8_t Avtp_Jpeg2000_GetTp(Avtp_Jpeg2000_t* pdu)
{
    return GET_FIELD(AVTP_JPEG2000_FIELD_TP);
}

uint8_t Avtp_Jpeg2000_GetMhf(Avtp_Jpeg2000_t* pdu)
{
    return GET_FIELD(AVTP_JPEG2000_FIELD_MHF);
}

uint8_t Avtp_Jpeg2000_GetMhId(Avtp_Jpeg2000_t* pdu)
{
    return GET_FIELD(AVTP_JPEG2000_FIELD_MH_ID);
}

uint8_t Avtp_Jpeg2000_GetT(Avtp_Jpeg2000_t* pdu)
{
    return GET_FIELD(AVTP_JPEG2000_FIELD_T);
}

uint8_t Avtp_Jpeg2000_GetPriority(Avtp_Jpeg2000_t* pdu)
{
    return GET_FIELD(AVTP_JPEG2000_FIELD_PRIORITY);
}

uint16_t Avtp_Jpeg2000_GetTileNumber(Avtp_Jpeg2000_t* pdu)
{
    return GET_FIELD(AVTP_JPEG2000_FIELD_TILE_NUMBER);
}

uint32_t Avtp_Jpeg2000_GetFragmentOffset(Avtp_Jpeg2000_t* pdu)
{
    return GET_FIELD(AVTP_JPEG2000_FIELD_FRAGMENT_OFFSET);
}

void Avtp_Jpeg2000_SetField(Avtp_Jpeg2000_t* pdu, Avtp_Jpeg2000Field_t field, uint64_t value)
{
    SET_FIELD(field, value);
}

void Avtp_Jpeg2000_SetTp(Avtp_Jpeg2000_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_JPEG2000_FIELD_TP, value);
}

void Avtp_Jpeg2000_SetMhf(Avtp_Jpeg2000_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_JPEG2000_FIELD_MHF, value);
}

void Avtp_Jpeg2000_SetMhId(Avtp_Jpeg2000_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_JPEG2000_FIELD_MH_ID, value);
}

void Avtp_Cvf_EnableT(Avtp_Jpeg2000_t* pdu)
{
    SET_FIELD(AVTP_JPEG2000_FIELD_T, 1);
}

void Avtp_Cvf_DisableT(Avtp_Jpeg2000_t* pdu)
{
    SET_FIELD(AVTP_JPEG2000_FIELD_T, 0);
}

void Avtp_Jpeg2000_SetPriority(Avtp_Jpeg2000_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_JPEG2000_FIELD_PRIORITY, value);
}

void Avtp_Jpeg2000_SetTileNumber(Avtp_Jpeg2000_t* pdu, uint16_t value)
{
    SET_FIELD(AVTP_JPEG2000_FIELD_TILE_NUMBER, value);
}

void Avtp_Jpeg2000_SetFragmentOffset(Avtp_Jpeg2000_t* pdu, uint32_t value)
{
    SET_FIELD(AVTP_JPEG2000_FIELD_FRAGMENT_OFFSET, value);
}
