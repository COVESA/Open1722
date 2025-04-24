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

#include "avtp/cvf/H264.h"
#include "avtp/Utils.h"
#include "avtp/CommonHeader.h"

#define GET_FIELD(field) \
        (Avtp_GetField(fieldDescriptors, AVTP_H264_FIELD_MAX, (uint8_t*)pdu, field))
#define SET_FIELD(field, value) \
        (Avtp_SetField(fieldDescriptors, AVTP_H264_FIELD_MAX, (uint8_t*)pdu, field, value))

static const Avtp_FieldDescriptor_t fieldDescriptors[AVTP_H264_FIELD_MAX] =
{
    [AVTP_H264_FIELD_TIMESTAMP] = { .quadlet = 0, .offset = 0, .bits = 32 },
};

void Avtp_H264_Init(Avtp_H264_t* pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_H264_t));
    }
}

uint64_t Avtp_H264_GetField(const Avtp_H264_t* const pdu, Avtp_H264Field_t field)
{
    return GET_FIELD(field);
}

uint32_t Avtp_H264_GetTimestamp(const Avtp_H264_t* const pdu)
{
    return GET_FIELD(AVTP_H264_FIELD_TIMESTAMP);
}

void Avtp_H264_SetField(Avtp_H264_t* pdu, Avtp_H264Field_t field, uint64_t value)
{
    SET_FIELD(field, value);
}

void Avtp_H264_SetTimestamp(Avtp_H264_t* pdu, uint32_t value)
{
    SET_FIELD(AVTP_H264_FIELD_TIMESTAMP, value);
}
