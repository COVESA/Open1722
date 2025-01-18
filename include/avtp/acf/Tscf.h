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
 * This file contains the fields descriptions of the IEEE 1722 TSCF PDUs and
 * functions to invoke corresponding parser and deparser.
 */

#pragma once

#include <stdint.h>

#include "avtp/Defines.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AVTP_TSCF_HEADER_LEN               (6 * AVTP_QUADLET_SIZE)

typedef struct {
    uint8_t header[AVTP_TSCF_HEADER_LEN];
    uint8_t payload[0];
} Avtp_Tscf_t;

typedef enum {

    /* Common AVTP header */
    AVTP_TSCF_FIELD_SUBTYPE,
    AVTP_TSCF_FIELD_SV,
    AVTP_TSCF_FIELD_VERSION,

    /* TSCF header fields */
    AVTP_TSCF_FIELD_MR,
    AVTP_TSCF_FIELD_TV,
    AVTP_TSCF_FIELD_SEQUENCE_NUM,
    AVTP_TSCF_FIELD_TU,
    AVTP_TSCF_FIELD_STREAM_ID,
    AVTP_TSCF_FIELD_AVTP_TIMESTAMP,
    AVTP_TSCF_FIELD_STREAM_DATA_LENGTH,

    /* Count number of fields for bound checks */
    AVTP_TSCF_FIELD_MAX
} Avtp_TscfFields_t;


/**
 * Initializes a TSCF PDU as specified in the IEEE 1722-2016 Specification.
 *
 * @param pdu Pointer to the first bit of a 1722 PDU. This is typically an AVTP-
 * or an ACF header.
 */
void Avtp_Tscf_Init(Avtp_Tscf_t* pdu);

/**
 * Returns the value of an an AVTP TSCF field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AVTP PDU.
 * @param field Specifies the position of the data field to be read
 * @returns The value of the field.
 */
uint64_t Avtp_Tscf_GetField(Avtp_Tscf_t* pdu, Avtp_TscfFields_t field);

uint8_t Avtp_Tscf_GetSubtype(Avtp_Tscf_t* pdu);
uint8_t Avtp_Tscf_GetSv(Avtp_Tscf_t* pdu);
uint8_t Avtp_Tscf_GetVersion(Avtp_Tscf_t* pdu);
uint8_t Avtp_Tscf_GetMr(Avtp_Tscf_t* pdu);
uint8_t Avtp_Tscf_GetTv(Avtp_Tscf_t* pdu);
uint8_t Avtp_Tscf_GetSequenceNum(Avtp_Tscf_t* pdu);
uint8_t Avtp_Tscf_GetTu(Avtp_Tscf_t* pdu);
uint64_t Avtp_Tscf_GetStreamId(Avtp_Tscf_t* pdu);
uint32_t Avtp_Tscf_GetAvtpTimestamp(Avtp_Tscf_t* pdu);
uint16_t Avtp_Tscf_GetStreamDataLength(Avtp_Tscf_t* pdu);

/**
 * Sets the value of an an AVTP TSCF field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AVTP PDU.
 * @param field Specifies the position of the data field to be read
 * @param value Pointer to location to store the value.
 */
void Avtp_Tscf_SetField(Avtp_Tscf_t* pdu, Avtp_TscfFields_t field, uint64_t value);

void Avtp_Tscf_SetSubtype(Avtp_Tscf_t* pdu, uint8_t value);
void Avtp_Tscf_EnableSv(Avtp_Tscf_t* pdu);
void Avtp_Tscf_DisableSv(Avtp_Tscf_t* pdu);
void Avtp_Tscf_SetVersion(Avtp_Tscf_t* pdu, uint8_t value);
void Avtp_Tscf_EnableMr(Avtp_Tscf_t* pdu);
void Avtp_Tscf_DisableMr(Avtp_Tscf_t* pdu);
void Avtp_Tscf_EnableTv(Avtp_Tscf_t* pdu);
void Avtp_Tscf_DisableTv(Avtp_Tscf_t* pdu);
void Avtp_Tscf_SetSequenceNum(Avtp_Tscf_t* pdu, uint8_t value);
void Avtp_Tscf_EnableTu(Avtp_Tscf_t* pdu);
void Avtp_Tscf_DisableTu(Avtp_Tscf_t* pdu);
void Avtp_Tscf_SetStreamId(Avtp_Tscf_t* pdu, uint64_t value);
void Avtp_Tscf_SetAvtpTimestamp(Avtp_Tscf_t* pdu, uint32_t value);
void Avtp_Tscf_SetStreamDataLength(Avtp_Tscf_t* pdu, uint16_t value);

#ifdef __cplusplus
}
#endif
