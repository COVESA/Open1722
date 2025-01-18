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
 * This file contains the fields descriptions of the IEEE 1722 NTSCF PDUs and
 * functions to invoke corresponding parser and deparser.
 */

#pragma once

#include <stdint.h>

#include "avtp/Defines.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AVTP_NTSCF_HEADER_LEN              (3 * AVTP_QUADLET_SIZE)

typedef struct {
    uint8_t header[AVTP_NTSCF_HEADER_LEN];
    uint8_t payload[0];
} Avtp_Ntscf_t;

typedef enum {
    AVTP_NTSCF_FIELD_SUBTYPE,
    AVTP_NTSCF_FIELD_SV,
    AVTP_NTSCF_FIELD_VERSION,
    /* NTSCF header fields */
    AVTP_NTSCF_FIELD_NTSCF_DATA_LENGTH,
    AVTP_NTSCF_FIELD_SEQUENCE_NUM,
    AVTP_NTSCF_FIELD_STREAM_ID,
    /* Count number of fields for bound checks */
    AVTP_NTSCF_FIELD_MAX
} Avtp_NtscfFields_t;

/**
 * Initializes a NTSCF PDU as specified in the IEEE 1722-2016 Specification.
 *
 * @param pdu Pointer to the first bit of a 1722 PDU. This is typically an AVTP-
 * or an ACF header.
 */
void Avtp_Ntscf_Init(Avtp_Ntscf_t* pdu);

/**
 * Returns the value of an an AVTP NTSCF field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AVTP PDU.
 * @param field Specifies the position of the data field to be read
 * @returns The value of the PDU field.
 */
uint64_t Avtp_Ntscf_GetField(Avtp_Ntscf_t* pdu, Avtp_NtscfFields_t field);

uint8_t Avtp_Ntscf_GetSubtype(Avtp_Ntscf_t* pdu);
uint8_t Avtp_Ntscf_GetSv(Avtp_Ntscf_t* pdu);
uint8_t Avtp_Ntscf_GetVersion(Avtp_Ntscf_t* pdu);
uint16_t Avtp_Ntscf_GetNtscfDataLength(Avtp_Ntscf_t* pdu);
uint8_t Avtp_Ntscf_GetSequenceNum(Avtp_Ntscf_t* pdu);
uint64_t Avtp_Ntscf_GetStreamId(Avtp_Ntscf_t* pdu);

/**
 * Sets the value of an an AVTP NTSCF field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AVTP PDU.
 * @param field Specifies the position of the data field to be read
 * @param value Pointer to location to store the value.
 */
void Avtp_Ntscf_SetField(Avtp_Ntscf_t* pdu, Avtp_NtscfFields_t field, uint64_t value);

void Avtp_Ntscf_SetSubtype(Avtp_Ntscf_t* pdu, uint8_t value);
void Avtp_Ntscf_EnableSv(Avtp_Ntscf_t* pdu);
void Avtp_Ntscf_DisableSv(Avtp_Ntscf_t* pdu);
void Avtp_Ntscf_SetVersion(Avtp_Ntscf_t* pdu, uint8_t value);
void Avtp_Ntscf_SetNtscfDataLength(Avtp_Ntscf_t* pdu, uint16_t value);
void Avtp_Ntscf_SetSequenceNum(Avtp_Ntscf_t* pdu, uint8_t value);
void Avtp_Ntscf_SetStreamId(Avtp_Ntscf_t* pdu, uint64_t value);

#ifdef __cplusplus
}
#endif
