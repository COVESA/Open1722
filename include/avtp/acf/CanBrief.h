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
 * This file contains the fields descriptions of the IEEE 1722-2016 ACF Abbreviated CAN PDUs and
 * functions to invoke corresponding parser and deparser.
 */

#pragma once

#include <stdint.h>

#include "avtp/Defines.h"
#include "avtp/acf/AcfCommon.h"
#include "avtp/acf/Can.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AVTP_CAN_BRIEF_HEADER_LEN         (2 * AVTP_QUADLET_SIZE)

typedef struct {
    uint8_t header[AVTP_CAN_BRIEF_HEADER_LEN];
    uint8_t payload[0];
} Avtp_CanBrief_t;

typedef enum {

    /* ACF common header fields */
    AVTP_CAN_BRIEF_FIELD_ACF_MSG_TYPE = 0,
    AVTP_CAN_BRIEF_FIELD_ACF_MSG_LENGTH,

    /* ACF Abbreviated CAN Brief header fields */
    AVTP_CAN_BRIEF_FIELD_PAD,
    AVTP_CAN_BRIEF_FIELD_MTV,
    AVTP_CAN_BRIEF_FIELD_RTR,
    AVTP_CAN_BRIEF_FIELD_EFF,
    AVTP_CAN_BRIEF_FIELD_BRS,
    AVTP_CAN_BRIEF_FIELD_FDF,
    AVTP_CAN_BRIEF_FIELD_ESI,
    AVTP_CAN_BRIEF_FIELD_CAN_BUS_ID,
    AVTP_CAN_BRIEF_FIELD_CAN_IDENTIFIER,

    /* Count number of fields for bound checks */
    AVTP_CAN_BRIEF_FIELD_MAX
} Avtp_CanBriefFields_t;

/**
 * Initializes an ACF Abbreviated CAN PDU header as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF Abbreviated CAN PDU.
 */
void Avtp_CanBrief_Init(Avtp_CanBrief_t* pdu);

/**
 * Returns the value of an an ACF Abbreviated CAN PDU field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Abbreviated CAN PDU.
 * @param field Specifies the position of the data field to be read
 * @returns Field of CAN Brief PDU.
 */
uint64_t Avtp_CanBrief_GetField(Avtp_CanBrief_t* pdu, Avtp_CanBriefFields_t field);

uint8_t Avtp_CanBrief_GetAcfMsgType(Avtp_CanBrief_t* pdu);
uint16_t Avtp_CanBrief_GetAcfMsgLength(Avtp_CanBrief_t* pdu);
uint8_t Avtp_CanBrief_GetPad(Avtp_CanBrief_t* pdu);
uint8_t Avtp_CanBrief_GetMtv(Avtp_CanBrief_t* pdu);
uint8_t Avtp_CanBrief_GetRtr(Avtp_CanBrief_t* pdu);
uint8_t Avtp_CanBrief_GetEff(Avtp_CanBrief_t* pdu);
uint8_t Avtp_CanBrief_GetBrs(Avtp_CanBrief_t* pdu);
uint8_t Avtp_CanBrief_GetFdf(Avtp_CanBrief_t* pdu);
uint8_t Avtp_CanBrief_GetEsi(Avtp_CanBrief_t* pdu);
uint8_t Avtp_CanBrief_GetCanBusId(Avtp_CanBrief_t* pdu);
uint32_t Avtp_CanBrief_GetCanIdentifier(Avtp_CanBrief_t* pdu);

/**
 * Sets the value of an an ACF Abbreviated CAN PDU field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Abbreviated CAN PDU.
 * @param field Specifies the position of the data field to be read
 * @param value Pointer to location to store the value.
 */
void Avtp_CanBrief_SetField(Avtp_CanBrief_t* can_pdu, Avtp_CanBriefFields_t field, uint64_t value);

void Avtp_CanBrief_SetAcfMsgType(Avtp_CanBrief_t* pdu, uint8_t value);
void Avtp_CanBrief_SetAcfMsgLength(Avtp_CanBrief_t* pdu, uint16_t value);
void Avtp_CanBrief_SetPad(Avtp_CanBrief_t* pdu, uint8_t value);
void Avtp_CanBrief_EnableMtv(Avtp_Can_t* pdu);
void Avtp_CanBrief_DisableMtv(Avtp_Can_t* pdu);
void Avtp_CanBrief_EnableRtr(Avtp_Can_t* pdu);
void Avtp_CanBrief_DisableRtr(Avtp_Can_t* pdu);
void Avtp_CanBrief_EnableEff(Avtp_Can_t* pdu);
void Avtp_CanBrief_DisableEff(Avtp_Can_t* pdu);
void Avtp_CanBrief_EnableBrs(Avtp_Can_t* pdu);
void Avtp_CanBrief_DisableBrs(Avtp_Can_t* pdu);
void Avtp_CanBrief_EnableFdf(Avtp_Can_t* pdu);
void Avtp_CanBrief_DisableFdf(Avtp_Can_t* pdu);
void Avtp_CanBrief_EnableEsi(Avtp_Can_t* pdu);
void Avtp_CanBrief_DisableEsi(Avtp_Can_t* pdu);
void Avtp_CanBrief_SetCanBusId(Avtp_CanBrief_t* pdu, uint8_t value);
void Avtp_CanBrief_SetCanIdentifier(Avtp_CanBrief_t* pdu, uint32_t value);

/**
 * Copies the payload data into the ACF CAN Brief frame. This function will also set the
 * length and pad fields while inserting the padded bytes.
 *
 * @param can_pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
 * @param frame_id ID of the CAN frame
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload.
 * @param can_variant Classic CAN or CAN-FD
 * @returns Returns number of processed bytes (header + payload + padding)
 */
int Avtp_CanBrief_SetPayload(Avtp_CanBrief_t* can_pdu, uint32_t frame_id , uint8_t* payload,
                        uint16_t payload_length, Avtp_CanVariant_t can_variant);

/**
 * Finalizes the ACF CAN Brief frame. This function will set the
 * length and pad fields while inserting the padded bytes.
 *
 * @param can_pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload.
 * @returns Returns number of processed bytes (header + payload + padding)
 */
int Avtp_CanBrief_Finalize(Avtp_CanBrief_t* can_pdu, uint16_t payload_length);

#ifdef __cplusplus
}
#endif
