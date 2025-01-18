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
 * @file This files contains functions for de-/serialization of IEEE1722's ACF
 * FlexRay PDU formats. For details see IEEE Std. 1722-2016, chapter 9.4.2.
 */

#pragma once

#include <stdint.h>

#include "avtp/Defines.h"
#include "avtp/acf/AcfCommon.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Length of ACF FlexRay header. */
#define AVTP_FLEXRAY_HEADER_LEN (4 * AVTP_QUADLET_SIZE)

/** ACF FlexRay PDU. */
typedef struct {
    uint8_t header[AVTP_FLEXRAY_HEADER_LEN];
    uint8_t payload[0];
} Avtp_FlexRay_t;

/** Fields of ACF FlexRay PDU. */
typedef enum  {
    /* ACF common header fields */
    AVTP_FLEXRAY_FIELD_ACF_MSG_TYPE = 0,
    AVTP_FLEXRAY_FIELD_ACF_MSG_LENGTH,
    /* ACF FlexRay header fields */
    AVTP_FLEXRAY_FIELD_PAD,
    AVTP_FLEXRAY_FIELD_MTV,
    AVTP_FLEXRAY_FIELD_FR_BUS_ID,
    AVTP_FLEXRAY_FIELD_RESERVED,
    AVTP_FLEXRAY_FIELD_CHAN,
    AVTP_FLEXRAY_FIELD_STR,
    AVTP_FLEXRAY_FIELD_SYN,
    AVTP_FLEXRAY_FIELD_PRE,
    AVTP_FLEXRAY_FIELD_NFI,
    AVTP_FLEXRAY_FIELD_MESSAGE_TIMESTAMP,
    AVTP_FLEXRAY_FIELD_FR_FRAME_ID,
    AVTP_FLEXRAY_FIELD_RESERVED_2,
    AVTP_FLEXRAY_FIELD_CYCLE,
    /* Count number of fields for bound checks */
    AVTP_FLEXRAY_FIELD_MAX
} Avtp_FlexRayFields_t;

/**
 * Initializes an ACF FlexRay PDU.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF FlexRay PDU.
 */
void Avtp_FlexRay_Init(Avtp_FlexRay_t* pdu);

/**
 * Returns the value of an ACF FlexRay PDU field.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @param field Data field to be read
 * @param value Pointer to location to store the value.
 * @returns Value of the specified PDU field
 */
uint64_t Avtp_FlexRay_GetField(Avtp_FlexRay_t* pdu, Avtp_FlexRayFields_t field);

uint8_t Avtp_FlexRay_GetAcfMsgType(Avtp_FlexRay_t* pdu);
uint16_t Avtp_FlexRay_GetAcfMsgLength(Avtp_FlexRay_t* pdu);
uint8_t Avtp_FlexRay_GetPad(Avtp_FlexRay_t* pdu);
uint8_t Avtp_FlexRay_GetMtv(Avtp_FlexRay_t* pdu);
uint8_t Avtp_FlexRay_GetFrBusId(Avtp_FlexRay_t* pdu);
uint8_t Avtp_FlexRay_GetChan(Avtp_FlexRay_t* pdu);
uint8_t Avtp_FlexRay_GetStr(Avtp_FlexRay_t* pdu);
uint8_t Avtp_FlexRay_GetSyn(Avtp_FlexRay_t* pdu);
uint8_t Avtp_FlexRay_GetPre(Avtp_FlexRay_t* pdu);
uint8_t Avtp_FlexRay_GetNfi(Avtp_FlexRay_t* pdu);
uint64_t Avtp_FlexRay_GetMessageTimestamp(Avtp_FlexRay_t* pdu);
uint16_t Avtp_FlexRay_GetFrFrameId(Avtp_FlexRay_t* pdu);
uint8_t Avtp_FlexRay_GetCycle(Avtp_FlexRay_t* pdu);

/**
 * Sets the value of an ACF FlexRay PDU field.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @param field Specifies the position of the data field to be read
 * @param value Pointer to location to store the value.
 * @returns Returns 0 if the data field was successfully set.
 */
void Avtp_FlexRay_SetField(Avtp_FlexRay_t* pdu, Avtp_FlexRayFields_t field, uint64_t value);

void Avtp_FlexRay_SetAcfMsgType(Avtp_FlexRay_t* pdu, uint8_t value);
void Avtp_FlexRay_SetAcfMsgLength(Avtp_FlexRay_t* pdu, uint16_t value);
void Avtp_FlexRay_SetPad(Avtp_FlexRay_t* pdu, uint8_t value);
void Avtp_FlexRay_EnableMtv(Avtp_FlexRay_t* pdu);
void Avtp_FlexRay_DisableMtv(Avtp_FlexRay_t* pdu);
void Avtp_FlexRay_SetFrBusId(Avtp_FlexRay_t* pdu, uint8_t value);
void Avtp_FlexRay_SetChan(Avtp_FlexRay_t* pdu, uint8_t value);
void Avtp_FlexRay_EnableStr(Avtp_FlexRay_t* pdu);
void Avtp_FlexRay_DisableStr(Avtp_FlexRay_t* pdu);
void Avtp_FlexRay_EnableSyn(Avtp_FlexRay_t* pdu);
void Avtp_FlexRay_DisableSyn(Avtp_FlexRay_t* pdu);
void Avtp_FlexRay_EnablePre(Avtp_FlexRay_t* pdu);
void Avtp_FlexRay_DisablePre(Avtp_FlexRay_t* pdu);
void Avtp_FlexRay_EnableNfi(Avtp_FlexRay_t* pdu);
void Avtp_FlexRay_DisableNfi(Avtp_FlexRay_t* pdu);
void Avtp_FlexRay_SetMessageTimestamp(Avtp_FlexRay_t* pdu, uint64_t value);
void Avtp_FlexRay_SetFrFrameId(Avtp_FlexRay_t* pdu, uint16_t value);
void Avtp_FlexRay_SetCycle(Avtp_FlexRay_t* pdu, uint8_t value);

#ifdef __cplusplus
}
#endif
