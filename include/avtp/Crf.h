/*
 * Copyright (c) 2024, COVESA
 * Copyright (c) 2018, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of Intel Corporation, COVESA nor the names of their
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

#define AVTP_CRF_HEADER_LEN     (5 * AVTP_QUADLET_SIZE)

typedef struct Avtp_Cvf {
    uint8_t header[AVTP_CRF_HEADER_LEN];
    uint8_t payload[0];
} Avtp_Crf_t;

/* CRF 'type' field values. */
#define AVTP_CRF_TYPE_USER			0x00
#define AVTP_CRF_TYPE_AUDIO_SAMPLE		0x01
#define AVTP_CRF_TYPE_VIDEO_FRAME		0x02
#define AVTP_CRF_TYPE_VIDEO_LINE		0x03
#define AVTP_CRF_TYPE_MACHINE_CYCLE		0x04

/* CRF 'pull' field values. */
#define AVTP_CRF_PULL_MULT_BY_1			0x00
#define AVTP_CRF_PULL_MULT_BY_1_OVER_1_001	0x01
#define AVTP_CRF_PULL_MULT_BY_1_001		0x02
#define AVTP_CRF_PULL_MULT_BY_24_OVER_25	0x03
#define AVTP_CRF_PULL_MULT_BY_25_OVER_24	0x04
#define AVTP_CRF_PULL_MULT_BY_1_OVER_8		0x05

typedef enum Avtp_CrfField {
    /* CRF header fields */
    AVTP_CRF_FIELD_SUBTYPE,
    AVTP_CRF_FIELD_SV,
    AVTP_CRF_FIELD_VERSION,
    AVTP_CRF_FIELD_MR,
    AVTP_CRF_FIELD_RESERVED,
    AVTP_CRF_FIELD_FS,
    AVTP_CRF_FIELD_TU,
    AVTP_CRF_FIELD_SEQUENCE_NUM,
    AVTP_CRF_FIELD_TYPE,
    AVTP_CRF_FIELD_STREAM_ID,
    AVTP_CRF_FIELD_PULL,
    AVTP_CRF_FIELD_BASE_FREQUENCY,
    AVTP_CRF_FIELD_CRF_DATA_LENGTH,
    AVTP_CRF_FIELD_TIMESTAMP_INTERVAL,
    /* Count number of fields for bound checks */
    AVTP_CRF_FIELD_MAX,
}Avtp_CrfField_t;

void Avtp_Crf_Init(Avtp_Crf_t* pdu);

uint64_t Avtp_Crf_GetField(Avtp_Crf_t* pdu, Avtp_CrfField_t field);

uint8_t Avtp_Crf_GetSubtype(Avtp_Crf_t* pdu);
uint8_t Avtp_Crf_GetSv(Avtp_Crf_t* pdu);
uint8_t Avtp_Crf_GetVersion(Avtp_Crf_t* pdu);
uint8_t Avtp_Crf_GetMr(Avtp_Crf_t* pdu);
uint8_t Avtp_Crf_GetFs(Avtp_Crf_t* pdu);
uint8_t Avtp_Crf_GetTu(Avtp_Crf_t* pdu);
uint8_t Avtp_Crf_GetSequenceNum(Avtp_Crf_t* pdu);
uint8_t Avtp_Crf_GetType(Avtp_Crf_t* pdu);
uint64_t Avtp_Crf_GetStreamId(Avtp_Crf_t* pdu);
uint8_t Avtp_Crf_GetPull(Avtp_Crf_t* pdu);
uint32_t Avtp_Crf_GetBaseFrequency(Avtp_Crf_t* pdu);
uint16_t Avtp_Crf_GetCrfDataLength(Avtp_Crf_t* pdu);
uint16_t Avtp_Crf_GetTimestampInterval(Avtp_Crf_t* pdu);

void Avtp_Crf_SetField(Avtp_Crf_t* pdu, Avtp_CrfField_t field, uint64_t value);

void Avtp_Crf_SetSubtype(Avtp_Crf_t* pdu, uint8_t value);
void Avtp_Crf_EnableSv(Avtp_Crf_t* pdu);
void Avtp_Crf_DisableSv(Avtp_Crf_t* pdu);
void Avtp_Crf_SetVersion(Avtp_Crf_t* pdu, uint8_t value);
void Avtp_Crf_EnableMr(Avtp_Crf_t* pdu);
void Avtp_Crf_DisableMr(Avtp_Crf_t* pdu);
void Avtp_Crf_EnableFs(Avtp_Crf_t* pdu);
void Avtp_Crf_DisableFs(Avtp_Crf_t* pdu);
void Avtp_Crf_EnableTu(Avtp_Crf_t* pdu);
void Avtp_Crf_DisableTu(Avtp_Crf_t* pdu);
void Avtp_Crf_SetSequenceNum(Avtp_Crf_t* pdu, uint8_t value);
void Avtp_Crf_SetType(Avtp_Crf_t* pdu, uint8_t value);
void Avtp_Crf_SetStreamId(Avtp_Crf_t* pdu, uint64_t value);
void Avtp_Crf_SetPull(Avtp_Crf_t* pdu, uint8_t value);
void Avtp_Crf_SetBaseFrequency(Avtp_Crf_t* pdu, uint32_t value);
void Avtp_Crf_SetCrfDataLength(Avtp_Crf_t* pdu, uint16_t value);
void Avtp_Crf_SetTimestampInterval(Avtp_Crf_t* pdu, uint16_t value);

/******************************************************************************
 * Legacy API (deprecated)
 *****************************************************************************/

#define AVTP_CRF_FIELD_SEQ_NUM          AVTP_CRF_FIELD_SEQUENCE_NUM
#define AVTP_CRF_FIELD_BASE_FREQ        AVTP_CRF_FIELD_BASE_FREQUENCY
#define AVTP_CRF_FIELD_CRF_DATA_LEN     AVTP_CRF_FIELD_CRF_DATA_LENGTH

struct avtp_crf_pdu {
    uint32_t subtype_data;
    uint64_t stream_id;
    uint64_t packet_info;
    uint64_t crf_data[0];
} __attribute__ ((__packed__));

/**
 * @deprecated
 * Get value from CRF AVTPDU field.
 * @pdu: Pointer to PDU struct.
 * @field: PDU field to be retrieved.
 * @val: Pointer to variable which the retrieved value should be saved.
 *
 * Returns:
 *    0: Success.
 *    -EINVAL: If any argument is invalid.
 */
int avtp_crf_pdu_get(const void *pdu, Avtp_CrfField_t field, uint64_t *val);

/**
 * @deprecated
 * Set value from CRF AVTPDU field.
 * @pdu: Pointer to PDU struct.
 * @field: PDU field to be set.
 * @val: Value to be set.
 *
 * Returns:
 *    0: Success.
 *    -EINVAL: If any argument is invalid.
 */
int avtp_crf_pdu_set(void *pdu, Avtp_CrfField_t field, uint64_t val);

/**
 * @deprecated
 * Initialize CRF AVTPDU. All AVTPDU fields are initialized with zero except
 * 'subtype' (which is set to AVTP_SUBTYPE_CRF) and 'sv' (which is set to 1).
 * @pdu: Pointer to PDU struct.
 *
 * Return values:
 *    0: Success.
 *    -EINVAL: If any argument is invalid.
 */
int avtp_crf_pdu_init(void *pdu);

#ifdef __cplusplus
}
#endif
