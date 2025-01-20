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

#define AVTP_CVF_HEADER_LEN (6 * AVTP_QUADLET_SIZE)

typedef struct Avtp_Cvf {
    uint8_t header[AVTP_CVF_HEADER_LEN];
    uint8_t payload[0];
} Avtp_Cvf_t;

typedef enum Avtp_CvfField {
    /* CVF header fields */
    AVTP_CVF_FIELD_SUBTYPE,
    AVTP_CVF_FIELD_SV,
    AVTP_CVF_FIELD_VERSION,
    AVTP_CVF_FIELD_MR,
    AVTP_CVF_FIELD_RESERVED,
    AVTP_CVF_FIELD_TV,
    AVTP_CVF_FIELD_SEQUENCE_NUM,
    AVTP_CVF_FIELD_RESERVED_2,
    AVTP_CVF_FIELD_TU,
    AVTP_CVF_FIELD_STREAM_ID,
    AVTP_CVF_FIELD_AVTP_TIMESTAMP,
    AVTP_CVF_FIELD_FORMAT,
    AVTP_CVF_FIELD_FORMAT_SUBTYPE,
    AVTP_CVF_FIELD_RESERVED_3,
    AVTP_CVF_FIELD_STREAM_DATA_LENGTH,
    AVTP_CVF_FIELD_RESERVED_4,
    AVTP_CVF_FIELD_PTV,
    AVTP_CVF_FIELD_M,
    AVTP_CVF_FIELD_EVT,
    AVTP_CVF_FIELD_RESERVED_5,
    /* Count number of fields for bound checks */
    AVTP_CVF_FIELD_MAX
} Avtp_CvfField_t;

typedef enum Avtp_CvfFormat {
    AVTP_CVF_FORMAT_RFC                 = 0x2
} Avtp_CvfFormat_t;

typedef enum Avtp_CvfFormatSubtype {
    AVTP_CVF_FORMAT_SUBTYPE_MJPEG       = 0x0,
    AVTP_CVF_FORMAT_SUBTYPE_H264        = 0x1,
    AVTP_CVF_FORMAT_SUBTYPE_JPEG2000    = 0x2
} Avtp_CvfFormatSubtype_t;

void Avtp_Cvf_Init(Avtp_Cvf_t* pdu);

uint64_t Avtp_Cvf_GetField(Avtp_Cvf_t* pdu, Avtp_CvfField_t field);

uint8_t Avtp_Cvf_GetSubtype(Avtp_Cvf_t* pdu);
uint8_t Avtp_Cvf_GetSv(Avtp_Cvf_t* pdu);
uint8_t Avtp_Cvf_GetVersion(Avtp_Cvf_t* pdu);
uint8_t Avtp_Cvf_GetMr(Avtp_Cvf_t* pdu);
uint8_t Avtp_Cvf_GetTv(Avtp_Cvf_t* pdu);
uint8_t Avtp_Cvf_GetSequenceNum(Avtp_Cvf_t* pdu);
uint8_t Avtp_Cvf_GetTu(Avtp_Cvf_t* pdu);
uint64_t Avtp_Cvf_GetStreamId(Avtp_Cvf_t* pdu);
uint32_t Avtp_Cvf_GetAvtpTimestamp(Avtp_Cvf_t* pdu);
Avtp_CvfFormat_t Avtp_Cvf_GetFormat(Avtp_Cvf_t* pdu);
Avtp_CvfFormatSubtype_t Avtp_Cvf_GetFormatSubtype(Avtp_Cvf_t* pdu);
uint16_t Avtp_Cvf_GetStreamDataLength(Avtp_Cvf_t* pdu);
uint8_t Avtp_Cvf_GetPtv(Avtp_Cvf_t* pdu);
uint8_t Avtp_Cvf_GetM(Avtp_Cvf_t* pdu);
uint8_t Avtp_Cvf_GetEvt(Avtp_Cvf_t* pdu);

void Avtp_Cvf_SetField(Avtp_Cvf_t* pdu, Avtp_CvfField_t field, uint64_t value);

void Avtp_Cvf_SetSubtype(Avtp_Cvf_t* pdu, uint8_t value);
void Avtp_Cvf_EnableSv(Avtp_Cvf_t* pdu);
void Avtp_Cvf_DisableSv(Avtp_Cvf_t* pdu);
void Avtp_Cvf_SetVersion(Avtp_Cvf_t* pdu, uint8_t value);
void Avtp_Cvf_EnableMr(Avtp_Cvf_t* pdu);
void Avtp_Cvf_DisableMr(Avtp_Cvf_t* pdu);
void Avtp_Cvf_EnableTv(Avtp_Cvf_t* pdu);
void Avtp_Cvf_DisableTv(Avtp_Cvf_t* pdu);
void Avtp_Cvf_SetSequenceNum(Avtp_Cvf_t* pdu, uint8_t value);
void Avtp_Cvf_EnableTu(Avtp_Cvf_t* pdu);
void Avtp_Cvf_DisableTu(Avtp_Cvf_t* pdu);
void Avtp_Cvf_SetStreamId(Avtp_Cvf_t* pdu, uint64_t value);
void Avtp_Cvf_SetAvtpTimestamp(Avtp_Cvf_t* pdu, uint32_t value);
void Avtp_Cvf_SetFormat(Avtp_Cvf_t* pdu, Avtp_CvfFormat_t value);
void Avtp_Cvf_SetFormatSubtype(Avtp_Cvf_t* pdu, Avtp_CvfFormatSubtype_t value);
void Avtp_Cvf_SetStreamDataLength(Avtp_Cvf_t* pdu, uint16_t value);
void Avtp_Cvf_EnablePtv(Avtp_Cvf_t* pdu);
void Avtp_Cvf_DisablePtv(Avtp_Cvf_t* pdu);
void Avtp_Cvf_EnableM(Avtp_Cvf_t* pdu);
void Avtp_Cvf_DisableM(Avtp_Cvf_t* pdu);
void Avtp_Cvf_SetEvt(Avtp_Cvf_t* pdu, uint8_t value);

/******************************************************************************
 * Legacy API (deprecated)
 *****************************************************************************/

/**
 * @deprecated
 */
int avtp_cvf_pdu_get(void* pdu, Avtp_CvfField_t field, uint64_t *val);

/**
 * @deprecated
 */
int avtp_cvf_pdu_set(void* pdu, Avtp_CvfField_t field, uint64_t val);

/**
 * @deprecated
 */
int avtp_cvf_pdu_init(void* pdu, uint8_t format_subtype);

#ifdef __cplusplus
}
#endif
