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
 * This file contains the fields descriptions of the IEEE 1722 UDP bindings and
 * functions to invoke corresponding parser and deparser.
 */

#pragma once

#include <stdint.h>

#include "avtp/Defines.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AVTP_UDP_HEADER_LEN               (1 * AVTP_QUADLET_SIZE)

typedef struct {
    uint8_t header[AVTP_UDP_HEADER_LEN];
    uint8_t payload[0];
} Avtp_Udp_t;

typedef enum {
    
    /* Common AVTP UDP header */
    AVTP_UDP_FIELD_ENCAPSULATION_SEQ_NO,

    /* Count number of fields for bound checks */
    AVTP_UDP_FIELD_MAX
} Avtp_UdpFields_t;

/**
 * Initializes a UDP PDU as specified in the IEEE 1722-2016 Specification.
 *
 * @param pdu Pointer to the first bit of an IEEE 1722 UDP PDU. 
 */
void Avtp_Udp_Init(Avtp_Udp_t* pdu);

/**
 * Returns the value of an an AVTP UDP field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AVTP UDP PDU.
 * @param field Specifies the position of the data field to be read
 * @param value Pointer to location to store the value.
 * @returns This function returns the value of the field.
 */
uint64_t Avtp_Udp_GetField(const Avtp_Udp_t* const pdu, Avtp_UdpFields_t field);

uint32_t Avtp_Udp_GetEncapsulationSeqNo(const Avtp_Udp_t* const pdu);

/**
 * Sets the value of an an AVTP UDP field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AVTP UDP PDU.
 * @param field Specifies the position of the data field to be read
 * @param value Pointer to location to store the value.
 */
void Avtp_Udp_SetField(Avtp_Udp_t* pdu, Avtp_UdpFields_t field, uint64_t value);

void Avtp_Udp_SetEncapsulationSeqNo(Avtp_Udp_t* pdu, uint32_t value);

#ifdef __cplusplus
}
#endif
