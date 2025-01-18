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
 * Lin PDU formats. For details see IEEE Std. 1722-2016, chapter 9.4.5.
 */

#pragma once

#include <stdint.h>

#include "avtp/Defines.h"
#include "avtp/acf/AcfCommon.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Length of ACF Lin header. */
#define AVTP_LIN_HEADER_LEN (3 * AVTP_QUADLET_SIZE)

/** ACF Lin PDU. */
typedef struct {
    uint8_t header[AVTP_LIN_HEADER_LEN];
    uint8_t payload[0];
} Avtp_Lin_t;


/** Fields of ACF Lin PDU. */
typedef enum  {
    /* ACF common header fields */
    AVTP_LIN_FIELD_ACF_MSG_TYPE = 0,
    AVTP_LIN_FIELD_ACF_MSG_LENGTH,
    /* ACF Lin header fields */
    AVTP_LIN_FIELD_PAD,
    AVTP_LIN_FIELD_MTV,
    AVTP_LIN_FIELD_LIN_BUS_ID,
    AVTP_LIN_FIELD_LIN_IDENTIFIER,
    AVTP_LIN_FIELD_MESSAGE_TIMESTAMP,
    /* Count number of fields for bound checks */
    AVTP_LIN_FIELD_MAX
} Avtp_LinFields_t;

/**
 * Initializes an ACF Lin PDU.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF Lin PDU.
 */
void Avtp_Lin_Init(Avtp_Lin_t* pdu);

/**
 * Returns the value of an ACF Lin PDU field.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Lin PDU.
 * @param field Data field to be read
 * @returns Value of PDU field.
 */
uint64_t Avtp_Lin_GetField(Avtp_Lin_t* pdu, Avtp_LinFields_t field);

uint8_t Avtp_Lin_GetAcfMsgType(Avtp_Lin_t* pdu);
uint16_t Avtp_Lin_GetAcfMsgLength(Avtp_Lin_t* pdu);
uint8_t Avtp_Lin_GetPad(Avtp_Lin_t* pdu);
uint8_t Avtp_Lin_GetMtv(Avtp_Lin_t* pdu);
uint8_t Avtp_Lin_GetLinBusId(Avtp_Lin_t* pdu);
uint8_t Avtp_Lin_GetLinIdentifier(Avtp_Lin_t* pdu);
uint64_t Avtp_Lin_GetMessageTimestamp(Avtp_Lin_t* pdu);

/**
 * Sets the value of an ACF Lin PDU field.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Lin PDU.
 * @param field Specifies the position of the data field to be read
 * @param value Pointer to location to store the value.
 */
void Avtp_Lin_SetField(Avtp_Lin_t* pdu, Avtp_LinFields_t field, uint64_t value);

void Avtp_Lin_SetAcfMsgType(Avtp_Lin_t* pdu, uint8_t value);
void Avtp_Lin_SetAcfMsgLength(Avtp_Lin_t* pdu, uint16_t value);
void Avtp_Lin_SetPad(Avtp_Lin_t* pdu, uint8_t value);
void Avtp_Lin_EnableMtv(Avtp_Lin_t* pdu);
void Avtp_Lin_DisableMtv(Avtp_Lin_t* pdu);
void Avtp_Lin_SetLinBusId(Avtp_Lin_t* pdu, uint8_t value);
void Avtp_Lin_SetLinIdentifier(Avtp_Lin_t* pdu, uint8_t value);
void Avtp_Lin_SetMessageTimestamp(Avtp_Lin_t* pdu, uint64_t value);

#ifdef __cplusplus
}
#endif
