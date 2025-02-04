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

#ifdef LINUX_KERNEL1722
#include <linux/errno.h>
#include <linux/string.h>
#else
#include <errno.h>
#include <string.h>
#endif


#include "avtp/acf/Tscf.h"
#include "avtp/Utils.h"
#include "avtp/CommonHeader.h"

#define GET_FIELD(field) \
        (Avtp_GetField(Avtp_TscfFieldDesc, AVTP_TSCF_FIELD_MAX, (uint8_t*)pdu, field))
#define SET_FIELD(field, value) \
        (Avtp_SetField(Avtp_TscfFieldDesc, AVTP_TSCF_FIELD_MAX, (uint8_t*)pdu, field, value))

/**
 * This table maps all IEEE 1722 TSCF-specific header fields to a descriptor.
 */
static const Avtp_FieldDescriptor_t Avtp_TscfFieldDesc[AVTP_TSCF_FIELD_MAX] =
{
    /* Common AVTP header */
    [AVTP_TSCF_FIELD_SUBTYPE]                  = { .quadlet = 0, .offset = 0, .bits = 8 },
    [AVTP_TSCF_FIELD_SV]                       = { .quadlet = 0, .offset = 8, .bits = 1 },
    [AVTP_TSCF_FIELD_VERSION]                  = { .quadlet = 0, .offset = 9, .bits = 3 },
    /* TSCF header*/
    [AVTP_TSCF_FIELD_MR]                       = { .quadlet = 0, .offset = 12, .bits = 1 },
    [AVTP_TSCF_FIELD_TV]                       = { .quadlet = 0, .offset = 15, .bits = 1 },
    [AVTP_TSCF_FIELD_SEQUENCE_NUM]             = { .quadlet = 0, .offset = 16, .bits = 8 },
    [AVTP_TSCF_FIELD_TU]                       = { .quadlet = 0, .offset = 31, .bits = 1 },
    [AVTP_TSCF_FIELD_STREAM_ID]                = { .quadlet = 1, .offset = 0, .bits = 64 },
    [AVTP_TSCF_FIELD_AVTP_TIMESTAMP]           = { .quadlet = 3, .offset = 0, .bits = 32 },
    [AVTP_TSCF_FIELD_STREAM_DATA_LENGTH]       = { .quadlet = 5, .offset = 0, .bits = 16 },
};

void Avtp_Tscf_Init(Avtp_Tscf_t* pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_Tscf_t));
        Avtp_Tscf_SetField(pdu, AVTP_TSCF_FIELD_SUBTYPE, AVTP_SUBTYPE_TSCF);
        Avtp_Tscf_SetField(pdu, AVTP_TSCF_FIELD_SV, 1);
    }
}

uint64_t Avtp_Tscf_GetField(Avtp_Tscf_t* pdu, Avtp_TscfFields_t field)
{
    return GET_FIELD(field);
}

uint8_t Avtp_Tscf_GetSubtype(Avtp_Tscf_t* pdu)
{
    return GET_FIELD(AVTP_TSCF_FIELD_SUBTYPE);
}

uint8_t Avtp_Tscf_GetSv(Avtp_Tscf_t* pdu)
{
    return GET_FIELD(AVTP_TSCF_FIELD_SV);
}

uint8_t Avtp_Tscf_GetVersion(Avtp_Tscf_t* pdu)
{
    return GET_FIELD(AVTP_TSCF_FIELD_VERSION);
}

uint8_t Avtp_Tscf_GetMr(Avtp_Tscf_t* pdu)
{
    return GET_FIELD(AVTP_TSCF_FIELD_MR);
}

uint8_t Avtp_Tscf_GetTv(Avtp_Tscf_t* pdu)
{
    return GET_FIELD(AVTP_TSCF_FIELD_TV);
}

uint8_t Avtp_Tscf_GetSequenceNum(Avtp_Tscf_t* pdu)
{
    return GET_FIELD(AVTP_TSCF_FIELD_SEQUENCE_NUM);
}

uint8_t Avtp_Tscf_GetTu(Avtp_Tscf_t* pdu)
{
    return GET_FIELD(AVTP_TSCF_FIELD_TU);
}

uint64_t Avtp_Tscf_GetStreamId(Avtp_Tscf_t* pdu)
{
    return GET_FIELD(AVTP_TSCF_FIELD_STREAM_ID);
}

uint32_t Avtp_Tscf_GetAvtpTimestamp(Avtp_Tscf_t* pdu)
{
    return GET_FIELD(AVTP_TSCF_FIELD_AVTP_TIMESTAMP);
}

uint16_t Avtp_Tscf_GetStreamDataLength(Avtp_Tscf_t* pdu)
{
    return GET_FIELD(AVTP_TSCF_FIELD_STREAM_DATA_LENGTH);
}

void Avtp_Tscf_SetField(Avtp_Tscf_t* pdu, Avtp_TscfFields_t field, uint64_t value)
{
    SET_FIELD(field, value);
}

void Avtp_Tscf_SetSubtype(Avtp_Tscf_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_TSCF_FIELD_SUBTYPE, value);
}

void Avtp_Tscf_EnableSv(Avtp_Tscf_t* pdu)
{
    SET_FIELD(AVTP_TSCF_FIELD_SV, 1);
}

void Avtp_Tscf_DisableSv(Avtp_Tscf_t* pdu)
{
    SET_FIELD(AVTP_TSCF_FIELD_SV, 0);
}

void Avtp_Tscf_SetVersion(Avtp_Tscf_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_TSCF_FIELD_VERSION, value);
}

void Avtp_Tscf_EnableMr(Avtp_Tscf_t* pdu)
{
    SET_FIELD(AVTP_TSCF_FIELD_MR, 1);
}

void Avtp_Tscf_DisableMr(Avtp_Tscf_t* pdu)
{
    SET_FIELD(AVTP_TSCF_FIELD_MR, 0);
}

void Avtp_Tscf_EnableTv(Avtp_Tscf_t* pdu)
{
    SET_FIELD(AVTP_TSCF_FIELD_TV, 1);
}

void Avtp_Tscf_DisableTv(Avtp_Tscf_t* pdu)
{
    SET_FIELD(AVTP_TSCF_FIELD_TV, 0);
}

void Avtp_Tscf_SetSequenceNum(Avtp_Tscf_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_TSCF_FIELD_SEQUENCE_NUM, value);
}

void Avtp_Tscf_EnableTu(Avtp_Tscf_t* pdu)
{
    SET_FIELD(AVTP_TSCF_FIELD_TU, 1);
}

void Avtp_Tscf_DisableTu(Avtp_Tscf_t* pdu)
{
    SET_FIELD(AVTP_TSCF_FIELD_TU, 0);
}

void Avtp_Tscf_SetStreamId(Avtp_Tscf_t* pdu, uint64_t value)
{
    SET_FIELD(AVTP_TSCF_FIELD_STREAM_ID, value);
}

void Avtp_Tscf_SetAvtpTimestamp(Avtp_Tscf_t* pdu, uint32_t value)
{
    SET_FIELD(AVTP_TSCF_FIELD_AVTP_TIMESTAMP, value);
}

void Avtp_Tscf_SetStreamDataLength(Avtp_Tscf_t* pdu, uint16_t value)
{
    SET_FIELD(AVTP_TSCF_FIELD_STREAM_DATA_LENGTH, value);
}

uint8_t Avtp_Tscf_IsValid(Avtp_Tscf_t* pdu, size_t bufferSize)
{
    if (pdu == NULL) {
        return FALSE;
    }

    if (bufferSize < AVTP_TSCF_HEADER_LEN) {
        return FALSE;
    }

    if (Avtp_Tscf_GetSubtype(pdu) != AVTP_SUBTYPE_TSCF) {
        return FALSE;
    }

    // Avtp_Tscf_GetStreamDataLength returns quadlets. Convert the length field to octets
    if (Avtp_Tscf_GetStreamDataLength(pdu) > bufferSize) {
        return FALSE;
    }

    return TRUE;
}