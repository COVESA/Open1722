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

#include <errno.h>
#include <string.h>

#include "avtp/acf/AcfCommon.h"
#include "avtp/acf/custom/VssBrief.h"
#include "avtp/Utils.h"
#include "avtp/Defines.h"

/**
 * This table maps all IEEE 1722 ACF VSS header fields to a descriptor.
 */
static const Avtp_FieldDescriptor_t Avtp_VssBriefFieldDesc[AVTP_VSS_BRIEF_FIELD_MAX] =
{
    /* ACF common header fields */
    [AVTP_VSS_BRIEF_FIELD_ACF_MSG_TYPE]       = { .quadlet = 0, .offset =  0, .bits = 7 },
    [AVTP_VSS_BRIEF_FIELD_ACF_MSG_LENGTH]     = { .quadlet = 0, .offset =  7, .bits = 9 },
    /* ACF VSS header fields */
    [AVTP_VSS_BRIEF_FIELD_PAD]                = { .quadlet = 0, .offset = 16, .bits =  2 },
    [AVTP_VSS_BRIEF_FIELD_MTV]                = { .quadlet = 0, .offset = 18, .bits =  1 },
    [AVTP_VSS_BRIEF_FIELD_ADDR_MODE]          = { .quadlet = 0, .offset = 19, .bits =  2 },
    [AVTP_VSS_BRIEF_FIELD_VSS_OP]             = { .quadlet = 0, .offset = 21, .bits =  3 },
    [AVTP_VSS_BRIEF_FIELD_VSS_DATATYPE]       = { .quadlet = 0, .offset = 24, .bits =  8 }
};

void Avtp_VssBrief_Init(Avtp_VssBrief_t* vss_pdu) {

    if(vss_pdu != NULL) {
        memset(vss_pdu, 0, sizeof(Avtp_VssBrief_t));
        Avtp_VssBrief_SetField(vss_pdu, AVTP_VSS_BRIEF_FIELD_ACF_MSG_TYPE, AVTP_ACF_TYPE_VSS_BRIEF);
    }
}

uint64_t Avtp_VssBrief_GetField(Avtp_VssBrief_t* vss_pdu,
                            Avtp_VssBriefFields_t field)
{
    return Avtp_GetField(Avtp_VssBriefFieldDesc, AVTP_VSS_BRIEF_FIELD_MAX,
                         (uint8_t *) vss_pdu, (uint8_t) field);
}

void Avtp_VssBrief_SetField(Avtp_VssBrief_t* vss_pdu,
                            Avtp_VssBriefFields_t field, uint64_t value)
{
    Avtp_SetField(Avtp_VssBriefFieldDesc, AVTP_VSS_BRIEF_FIELD_MAX,
                         (uint8_t *) vss_pdu, (uint8_t) field, value);
}