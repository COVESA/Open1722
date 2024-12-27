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
 * This file contains the common fields descriptions of the IEEE 1722 ACF PDUs
 */

#pragma once

#include "avtp/Defines.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AVTP_ACF_COMMON_HEADER_LEN         (1 * AVTP_QUADLET_SIZE)

typedef struct {
    uint8_t header[AVTP_ACF_COMMON_HEADER_LEN];
    uint8_t payload[0];
} Avtp_AcfCommon_t;

/**
 * AVTP message types. See IEEE Std 1722-2016 table 22.
 */
typedef enum {
    AVTP_ACF_TYPE_FLEXRAY          = 0x0,
    AVTP_ACF_TYPE_CAN              = 0x1,
    AVTP_ACF_TYPE_CAN_BRIEF        = 0x2,
    AVTP_ACF_TYPE_LIN              = 0x3,
    AVTP_ACF_TYPE_MOST             = 0x4,
    AVTP_ACF_TYPE_GPC              = 0x5,
    AVTP_ACF_TYPE_SERIAL           = 0x6,
    AVTP_ACF_TYPE_PARALLEL         = 0x7,
    AVTP_ACF_TYPE_SENSOR           = 0x8,
    AVTP_ACF_TYPE_SENSOR_BRIEF     = 0x9,
    AVTP_ACF_TYPE_AECP             = 0x10,
    AVTP_ACF_TYPE_ANCILLARY        = 0x11
} Avtp_AcfMsgType_t;

/**
 * This table maps all IEEE 1722 ACF common header fields to a descriptor.
 */
typedef enum {
    /* ACF common header fields */
    AVTP_ACF_FIELD_ACF_MSG_TYPE = 0,
    AVTP_ACF_FIELD_ACF_MSG_LENGTH,

    /* Count number of fields for bound checks */
    AVTP_ACF_COMMON_FIELD_MAX
} Avtp_AcfCommonFields_t;

/**
 * Returns the value of an an ACF common header field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF PDU.
 * @param field Specifies the position of the data field to be read.
 * @returns Returns the field of the PDU.
 */
uint64_t Avtp_AcfCommon_GetField(Avtp_AcfCommon_t* pdu, Avtp_AcfCommonFields_t field);

Avtp_AcfMsgType_t Avtp_AcfCommon_GetAcfMsgType(Avtp_AcfCommon_t* pdu);
uint16_t Avtp_AcfCommon_GetAcfMsgLength(Avtp_AcfCommon_t* pdu);

/**
 * Sets the value of an an ACF common header field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF PDU.
 * @param field Specifies the position of the data field to be read
 * @param value Pointer to location to store the value.
 */
void Avtp_AcfCommon_SetField(Avtp_AcfCommon_t* pdu, Avtp_AcfCommonFields_t field, uint64_t value);

void Avtp_AcfCommon_SetAcfMsgType(Avtp_AcfCommon_t* pdu, Avtp_AcfMsgType_t value);
void Avtp_AcfCommon_SetAcfMsgLength(Avtp_AcfCommon_t* pdu, uint16_t value);

#ifdef __cplusplus
}
#endif
