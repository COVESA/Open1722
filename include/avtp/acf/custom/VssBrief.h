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

/**
 * @file
 * This file contains the fields descriptions of COVESA VSS serailzation over
 * IEEE 1722 and functions to invoke corresponding parser and deparser.
 */

#pragma once

#include <stdint.h>

#include "avtp/Defines.h"

#define AVTP_VSS_BRIEF_HEADER_LEN   (1 * AVTP_QUADLET_SIZE)
#define AVTP_ACF_TYPE_VSS_BRIEF     0x42

typedef struct {
    uint8_t header[AVTP_VSS_BRIEF_HEADER_LEN];
    uint8_t payload[0];
} Avtp_VssBrief_t;

typedef enum  {

    /* ACF common header fields */
    AVTP_VSS_BRIEF_FIELD_ACF_MSG_TYPE = 0,
    AVTP_VSS_BRIEF_FIELD_ACF_MSG_LENGTH,

    /* ACF VSS Brief header fields */
    AVTP_VSS_BRIEF_FIELD_PAD,
    AVTP_VSS_BRIEF_FIELD_MTV,
    AVTP_VSS_BRIEF_FIELD_ADDR_MODE,
    AVTP_VSS_BRIEF_FIELD_VSS_OP,
    AVTP_VSS_BRIEF_FIELD_VSS_DATATYPE,
    AVTP_VSS_BRIEF_FIELD_MSG_TIMESTAMP,
    AVTP_VSS_FIELD_VSS_PATH,
    AVTP_VSS_FIELD_VSS_DATA,

    /* Count number of fields for bound checks */
    AVTP_VSS_BRIEF_FIELD_MAX
} Avtp_VssBriefFields_t;

/**
 * Initializes an ACF VSS PDU header as specified in the VSS - IEEE 1722
 * Mapping Specification.
 *
 * @param vss_pdu Pointer to the first bit of a 1722 ACF VSS PDU.
 */
void Avtp_VssBrief_Init(Avtp_VssBrief_t* vss_pdu);

/**
 * Returns the value of an an ACF VSS PDU field as specified in the
 * VSS - IEEE 1722 Mapping Specification.
 *
 * @param vss_pdu Pointer to the first bit of an IEEE 1722 ACF VSS PDU.
 * @param field Specifies the position of the data field to be read
 * @returns Value of the specified field of the IEEE 1722 ACF VSS PDU.
 */
uint64_t Avtp_VssBrief_GetField(Avtp_VssBrief_t* vss_pdu, Avtp_VssBriefFields_t field);

/**
 * Sets the value of an an ACF VSS PDU field as specified in the
 * VSS - IEEE 1722 Mapping Specification.
 *
 * @param vss_pdu Pointer to the first bit of an 1722 ACF VSS PDU.
 * @param field Specifies the position of the data field to be read
 * @param value Pointer to location to store the value.
 */
void Avtp_VssBrief_SetField(Avtp_VssBrief_t* vss_pdu, Avtp_VssBriefFields_t field, uint64_t value);