/*
 * Copyright (c) 2024, COVESA
 * Copyright (c) 2019, Intel Corporation
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

#include "avtp/Defines.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AVTP_PCM_HEADER_LEN              (6 * AVTP_QUADLET_SIZE)

typedef struct {
    uint8_t header[AVTP_PCM_HEADER_LEN];
    uint8_t payload[0];
} Avtp_Pcm_t;

typedef enum {
    AVTP_PCM_FIELD_SUBTYPE,
    AVTP_PCM_FIELD_SV,
    AVTP_PCM_FIELD_VERSION,
    AVTP_PCM_FIELD_MR,
    AVTP_PCM_FIELD_TV,
    AVTP_PCM_FIELD_SEQUENCE_NUM,
    AVTP_PCM_FIELD_TU,
    AVTP_PCM_FIELD_STREAM_ID,
    AVTP_PCM_FIELD_AVTP_TIMESTAMP,
    AVTP_PCM_FIELD_FORMAT,
    AVTP_PCM_FIELD_NSR,
    AVTP_PCM_FIELD_CHANNELS_PER_FRAME,
    AVTP_PCM_FIELD_BIT_DEPTH,
    AVTP_PCM_FIELD_STREAM_DATA_LENGTH,
    AVTP_PCM_FIELD_SP,
    AVTP_PCM_FIELD_EVT,
    AVTP_PCM_FIELD_MAX
} Avtp_PcmFields_t;

// AAF 'format' field values
typedef enum {
    AVTP_AAF_FORMAT_USER = 0,
    AVTP_AAF_FORMAT_FLOAT_32BIT,
    AVTP_AAF_FORMAT_INT_32BIT,
    AVTP_AAF_FORMAT_INT_24BIT,
    AVTP_AAF_FORMAT_INT_16BIT,
    AVTP_AAF_FORMAT_AES3_32BIT,
} Avtp_AafFormat_t;

typedef enum {
    AVTP_AAF_PCM_NSR_USER = 0,
    AVTP_AAF_PCM_NSR_8KHZ,
    AVTP_AAF_PCM_NSR_16KHZ,
    AVTP_AAF_PCM_NSR_32KHZ,
    AVTP_AAF_PCM_NSR_44_1KHZ,
    AVTP_AAF_PCM_NSR_48KHZ,
    AVTP_AAF_PCM_NSR_88_2KHZ,
    AVTP_AAF_PCM_NSR_96KHZ,
    AVTP_AAF_PCM_NSR_176_4KHZ,
    AVTP_AAF_PCM_NSR_192KHZ,
    AVTP_AAF_PCM_NSR_24KHZ,
} Avtp_AafNsr_t;

// AAF 'sp' (sparse timestamp) field value
typedef enum {
    AVTP_AAF_PCM_SP_NORMAL = 0,
    AVTP_AAF_PCM_SP_SPARSE,
} Avtp_AafSp_t;

/**
 * Initializes a AAF PCM stream PDU as specified in the IEEE 1722-2016 Specification.
 *
 * @param pdu Pointer to the first bit of a 1722 PDU.
 */
void Avtp_Pcm_Init(Avtp_Pcm_t* pdu);

/**
 * Returns the value of an an AVTP AAF PCM stream field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AVTP PDU.
 * @param field Specifies the position of the data field to be read
 * @param value Pointer to location to store the value.
 * @returns This function returns 0 if the data field was successfully read from
 * the 1722 AVTP PDU.
 */
uint64_t Avtp_Pcm_GetField(Avtp_Pcm_t* pdu, Avtp_PcmFields_t field);

uint8_t Avtp_Pcm_GetSubtype(Avtp_Pcm_t* pdu);
uint8_t Avtp_Pcm_GetSv(Avtp_Pcm_t* pdu);
uint8_t Avtp_Pcm_GetVersion(Avtp_Pcm_t* pdu);
uint8_t Avtp_Pcm_GetMr(Avtp_Pcm_t* pdu);
uint8_t Avtp_Pcm_GetTv(Avtp_Pcm_t* pdu);
uint8_t Avtp_Pcm_GetSequenceNum(Avtp_Pcm_t* pdu);
uint8_t Avtp_Pcm_GetTu(Avtp_Pcm_t* pdu);
uint64_t Avtp_Pcm_GetStreamId(Avtp_Pcm_t* pdu);
uint32_t Avtp_Pcm_GetAvtpTimestamp(Avtp_Pcm_t* pdu);
Avtp_AafFormat_t Avtp_Pcm_GetFormat(Avtp_Pcm_t* pdu);
Avtp_AafNsr_t Avtp_Pcm_GetNsr(Avtp_Pcm_t* pdu);
uint16_t Avtp_Pcm_GetChannelsPerFrame(Avtp_Pcm_t* pdu);
uint8_t Avtp_Pcm_GetBitDepth(Avtp_Pcm_t* pdu);
uint16_t Avtp_Pcm_GetStreamDataLength(Avtp_Pcm_t* pdu);
Avtp_AafSp_t Avtp_Pcm_GetSp(Avtp_Pcm_t* pdu);
uint8_t Avtp_Pcm_GetEvt(Avtp_Pcm_t* pdu);

/**
 * Sets the value of an an AVTP AAF PCM stream field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AVTP PDU.
 * @param field Specifies the position of the data field to be read
 * @param value Pointer to location to store the value.
 * @returns This function returns 0 if the data field was successfully set in
 * the 1722 AVTP PDU.
 */
void Avtp_Pcm_SetField(Avtp_Pcm_t* pdu, Avtp_PcmFields_t field, uint64_t value);

void Avtp_Pcm_SetSubtype(Avtp_Pcm_t* pdu, uint8_t value);
void Avtp_Pcm_EnableSv(Avtp_Pcm_t* pdu);
void Avtp_Pcm_DisableSv(Avtp_Pcm_t* pdu);
void Avtp_Pcm_SetVersion(Avtp_Pcm_t* pdu, uint8_t value);
void Avtp_Pcm_EnableMr(Avtp_Pcm_t* pdu);
void Avtp_Pcm_DisableMr(Avtp_Pcm_t* pdu);
void Avtp_Pcm_EnableTv(Avtp_Pcm_t* pdu);
void Avtp_Pcm_DisableTv(Avtp_Pcm_t* pdu);
void Avtp_Pcm_SetSequenceNum(Avtp_Pcm_t* pdu, uint8_t value);
void Avtp_Pcm_EnableTu(Avtp_Pcm_t* pdu);
void Avtp_Pcm_DisableTu(Avtp_Pcm_t* pdu);
void Avtp_Pcm_SetStreamId(Avtp_Pcm_t* pdu, uint64_t value);
void Avtp_Pcm_SetAvtpTimestamp(Avtp_Pcm_t* pdu, uint32_t value);
void Avtp_Pcm_SetFormat(Avtp_Pcm_t* pdu, Avtp_AafFormat_t value);
void Avtp_Pcm_SetNsr(Avtp_Pcm_t* pdu, Avtp_AafNsr_t value);
void Avtp_Pcm_SetChannelsPerFrame(Avtp_Pcm_t* pdu, uint16_t value);
void Avtp_Pcm_SetBitDepth(Avtp_Pcm_t* pdu, uint8_t value);
void Avtp_Pcm_SetStreamDataLength(Avtp_Pcm_t* pdu, uint16_t value);
void Avtp_Pcm_EnableSp(Avtp_Pcm_t* pdu);
void Avtp_Pcm_DisableSp(Avtp_Pcm_t* pdu);
void Avtp_Pcm_SetEvt(Avtp_Pcm_t* pdu, uint8_t value);

/******************************************************************************
 * Legacy API (deprecated)
 *****************************************************************************/

#define AVTP_AAF_FIELD_SV               AVTP_PCM_FIELD_SV
#define AVTP_AAF_FIELD_MR               AVTP_PCM_FIELD_MR
#define AVTP_AAF_FIELD_TV               AVTP_PCM_FIELD_TV
#define AVTP_AAF_FIELD_SEQ_NUM          AVTP_PCM_FIELD_SEQUENCE_NUM
#define AVTP_AAF_FIELD_TU               AVTP_PCM_FIELD_TU
#define AVTP_AAF_FIELD_STREAM_ID        AVTP_PCM_FIELD_STREAM_ID
#define AVTP_AAF_FIELD_TIMESTAMP        AVTP_PCM_FIELD_AVTP_TIMESTAMP
#define AVTP_AAF_FIELD_STREAM_DATA_LEN  AVTP_PCM_FIELD_STREAM_DATA_LENGTH
#define AVTP_AAF_FIELD_FORMAT           AVTP_PCM_FIELD_FORMAT
#define AVTP_AAF_FIELD_NSR              AVTP_PCM_FIELD_NSR
#define AVTP_AAF_FIELD_CHAN_PER_FRAME   AVTP_PCM_FIELD_CHANNELS_PER_FRAME
#define AVTP_AAF_FIELD_BIT_DEPTH        AVTP_PCM_FIELD_BIT_DEPTH
#define AVTP_AAF_FIELD_SP               AVTP_PCM_FIELD_SP
#define AVTP_AAF_FIELD_EVT              AVTP_PCM_FIELD_EVT
#define AVTP_AAF_FIELD_MAX              AVTP_PCM_FIELD_MAX

/**
 * @deprecated
 * Get value from AAF AVTPDU field.
 * @pdu: Pointer to PDU struct.
 * @field: PDU field to be retrieved.
 * @val: Pointer to variable which the retrieved value should be saved.
 *
 * Returns:
 *    0: Success.
 *    -EINVAL: If any argument is invalid.
 */
int avtp_aaf_pdu_get(void *pdu,
                Avtp_PcmFields_t field, uint64_t *val);

/**
 * @deprecated
 * Set value from AAF AVTPDU field.
 * @pdu: Pointer to PDU struct.
 * @field: PDU field to be set.
 * @val: Value to be set.
 *
 * Returns:
 *    0: Success.
 *    -EINVAL: If any argument is invalid.
 */
int avtp_aaf_pdu_set(void *pdu, Avtp_PcmFields_t field,
                                uint64_t val);

/**
 * @deprecated
 * Initialize AAF AVTPDU. All AVTPDU fields are initialized with zero except
 * 'subtype' (which is set to AVTP_SUBTYPE_AAF) and 'sv' (which is set to 1).
 * @pdu: Pointer to PDU struct.
 *
 * Return values:
 *    0: Success.
 *    -EINVAL: If any argument is invalid.
 */
int avtp_aaf_pdu_init(void *pdu);

#ifdef __cplusplus
}
#endif
