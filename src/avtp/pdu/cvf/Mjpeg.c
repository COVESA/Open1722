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

#include "avtp/pdu/cvf/Mjpeg.h"
#include "avtp/pdu/Utils.h"
#include "avtp/pdu/CommonHeader.h"

static const Avtp_FieldDescriptor_t fieldDescriptors[AVTP_MJPEG_FIELD_MAX] =
{
    [AVTP_MJPEG_FIELD_TYPE_SPECIFIC]    = { .quadlet = 0, .offset = 0, .bits = 8 },
    [AVTP_MJPEG_FIELD_FRAGMENT_OFFSET]  = { .quadlet = 0, .offset = 8, .bits = 24 },
    [AVTP_MJPEG_FIELD_TYPE]             = { .quadlet = 1, .offset = 0, .bits = 8 },
    [AVTP_MJPEG_FIELD_Q]                = { .quadlet = 1, .offset = 8, .bits = 8 },
    [AVTP_MJPEG_FIELD_WIDTH]            = { .quadlet = 1, .offset = 16, .bits = 8 },
    [AVTP_MJPEG_FIELD_HEIGHT]           = { .quadlet = 1, .offset = 24, .bits = 8 },
};

int Avtp_Mjpeg_Init(Avtp_Mjpeg_t* pdu)
{
    if (pdu == NULL) return -EINVAL;
    memset(pdu, 0, sizeof(Avtp_Mjpeg_t));
    return 0;
}

int Avtp_Mjpeg_GetField(Avtp_Mjpeg_t* pdu, Avtp_MjpegField_t field, uint64_t* value)
{
    return Avtp_GetField(fieldDescriptors, AVTP_MJPEG_FIELD_MAX, (uint8_t*)pdu, field, value);
}

int Avtp_Mjpeg_SetField(Avtp_Mjpeg_t* pdu, Avtp_MjpegField_t field, uint64_t value)
{
    return Avtp_SetField(fieldDescriptors, AVTP_MJPEG_FIELD_MAX, (uint8_t*)pdu, field, value);
}
