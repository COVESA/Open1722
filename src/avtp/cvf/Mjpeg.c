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

#include "avtp/cvf/Mjpeg.h"
#include "avtp/Utils.h"
#include "avtp/CommonHeader.h"

#define GET_FIELD(field) \
        (Avtp_GetField(fieldDescriptors, AVTP_MJPEG_FIELD_MAX, (uint8_t*)pdu, field))
#define SET_FIELD(field, value) \
        (Avtp_SetField(fieldDescriptors, AVTP_MJPEG_FIELD_MAX, (uint8_t*)pdu, field, value))

static const Avtp_FieldDescriptor_t fieldDescriptors[AVTP_MJPEG_FIELD_MAX] =
{
    [AVTP_MJPEG_FIELD_TYPE_SPECIFIC]    = { .quadlet = 0, .offset = 0, .bits = 8 },
    [AVTP_MJPEG_FIELD_FRAGMENT_OFFSET]  = { .quadlet = 0, .offset = 8, .bits = 24 },
    [AVTP_MJPEG_FIELD_TYPE]             = { .quadlet = 1, .offset = 0, .bits = 8 },
    [AVTP_MJPEG_FIELD_Q]                = { .quadlet = 1, .offset = 8, .bits = 8 },
    [AVTP_MJPEG_FIELD_WIDTH]            = { .quadlet = 1, .offset = 16, .bits = 8 },
    [AVTP_MJPEG_FIELD_HEIGHT]           = { .quadlet = 1, .offset = 24, .bits = 8 },
};

void Avtp_Mjpeg_Init(Avtp_Mjpeg_t* pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_Mjpeg_t));
    }
}

uint64_t Avtp_Mjpeg_GetField(const Avtp_Mjpeg_t* const pdu, Avtp_MjpegField_t field)
{
    return GET_FIELD(field);
}

uint8_t Avtp_Mjpeg_GetTypeSpecific(const Avtp_Mjpeg_t* const pdu)
{
    return GET_FIELD(AVTP_MJPEG_FIELD_TYPE_SPECIFIC);
}

uint32_t Avtp_Mjpeg_GetFragmentOffset(const Avtp_Mjpeg_t* const pdu)
{
    return GET_FIELD(AVTP_MJPEG_FIELD_FRAGMENT_OFFSET);
}

uint8_t Avtp_Mjpeg_GetType(const Avtp_Mjpeg_t* const pdu)
{
    return GET_FIELD(AVTP_MJPEG_FIELD_TYPE);
}

uint8_t Avtp_Mjpeg_GetQ(const Avtp_Mjpeg_t* const pdu)
{
    return GET_FIELD(AVTP_MJPEG_FIELD_Q);
}

uint8_t Avtp_Mjpeg_GetWidth(const Avtp_Mjpeg_t* const pdu)
{
    return GET_FIELD(AVTP_MJPEG_FIELD_WIDTH);
}

uint8_t Avtp_Mjpeg_GetHeight(const Avtp_Mjpeg_t* const pdu)
{
    return GET_FIELD(AVTP_MJPEG_FIELD_HEIGHT);
}

void Avtp_Mjpeg_SetField(Avtp_Mjpeg_t* pdu, Avtp_MjpegField_t field, uint64_t value)
{
    SET_FIELD(field, value);
}

void Avtp_Mjpeg_SetTypeSpecific(Avtp_Mjpeg_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_MJPEG_FIELD_TYPE_SPECIFIC, value);
}

void Avtp_Mjpeg_SetFragmentOffset(Avtp_Mjpeg_t* pdu, uint32_t value)
{
    SET_FIELD(AVTP_MJPEG_FIELD_FRAGMENT_OFFSET, value);
}

void Avtp_Mjpeg_SetType(Avtp_Mjpeg_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_MJPEG_FIELD_TYPE, value);
}

void Avtp_Mjpeg_SetQ(Avtp_Mjpeg_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_MJPEG_FIELD_Q, value);
}

void Avtp_Mjpeg_SetWidth(Avtp_Mjpeg_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_MJPEG_FIELD_WIDTH, value);
}

void Avtp_Mjpeg_SetHeight(Avtp_Mjpeg_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_MJPEG_FIELD_HEIGHT, value);
}
