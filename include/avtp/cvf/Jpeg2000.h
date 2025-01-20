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

#pragma once

#include <stdint.h>

#include "avtp/Utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AVTP_JPEG2000_HEADER_LEN (2 * AVTP_QUADLET_SIZE)

typedef struct Avtp_Jpeg2000 {
    uint8_t header[AVTP_JPEG2000_HEADER_LEN];
    uint8_t payload[0];
} Avtp_Jpeg2000_t;

typedef enum Avtp_Jpeg2000Field {
    /* MJPEG header fields */
    AVTP_JPEG2000_FIELD_TP,
    AVTP_JPEG2000_FIELD_MHF,
    AVTP_JPEG2000_FIELD_MH_ID,
    AVTP_JPEG2000_FIELD_T,
    AVTP_JPEG2000_FIELD_PRIORITY,
    AVTP_JPEG2000_FIELD_TILE_NUMBER,
    AVTP_JPEG2000_FIELD_RESERVED,
    AVTP_JPEG2000_FIELD_FRAGMENT_OFFSET,
    /* Count number of fields for bound checks */
    AVTP_JPEG2000_FIELD_MAX
} Avtp_Jpeg2000Field_t;

void Avtp_Jpeg2000_Init(Avtp_Jpeg2000_t* pdu);

uint64_t Avtp_Jpeg2000_GetField(Avtp_Jpeg2000_t* pdu, Avtp_Jpeg2000Field_t field);

uint8_t Avtp_Jpeg2000_GetTp(Avtp_Jpeg2000_t* pdu);
uint8_t Avtp_Jpeg2000_GetMhf(Avtp_Jpeg2000_t* pdu);
uint8_t Avtp_Jpeg2000_GetMhId(Avtp_Jpeg2000_t* pdu);
uint8_t Avtp_Jpeg2000_GetT(Avtp_Jpeg2000_t* pdu);
uint8_t Avtp_Jpeg2000_GetPriority(Avtp_Jpeg2000_t* pdu);
uint16_t Avtp_Jpeg2000_GetTileNumber(Avtp_Jpeg2000_t* pdu);
uint32_t Avtp_Jpeg2000_GetFragmentOffset(Avtp_Jpeg2000_t* pdu);

void Avtp_Jpeg2000_SetField(Avtp_Jpeg2000_t* pdu, Avtp_Jpeg2000Field_t field, uint64_t value);

void Avtp_Jpeg2000_SetTp(Avtp_Jpeg2000_t* pdu, uint8_t value);
void Avtp_Jpeg2000_SetMhf(Avtp_Jpeg2000_t* pdu, uint8_t value);
void Avtp_Jpeg2000_SetMhId(Avtp_Jpeg2000_t* pdu, uint8_t value);
void Avtp_Jpeg2000_EnableT(Avtp_Jpeg2000_t* pdu);
void Avtp_Jpeg2000_DisableT(Avtp_Jpeg2000_t* pdu);
void Avtp_Jpeg2000_SetPriority(Avtp_Jpeg2000_t* pdu, uint8_t value);
void Avtp_Jpeg2000_SetTileNumber(Avtp_Jpeg2000_t* pdu, uint16_t value);
void Avtp_Jpeg2000_SetFragmentOffset(Avtp_Jpeg2000_t* pdu, uint32_t value);

#ifdef __cplusplus
}
#endif
