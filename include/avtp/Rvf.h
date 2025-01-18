 /*
 * Copyright (c) 2024, COVESA
 * Copyright (c) 2021, Fastree3D
 * Adrian Fiergolski <Adrian.Fiergolski@fastree3d.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of Fastree3D, COVESA nor the names of their
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
 * SPDX-License-Identifier: BSD3-Clause
 */

#pragma once

#include <stdint.h>

#include "avtp/Utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AVTP_RVF_HEADER_LEN (8 * AVTP_QUADLET_SIZE)

typedef struct Avtp_Rvf {
    uint8_t header[AVTP_RVF_HEADER_LEN];
    uint8_t payload[0];
} Avtp_Rvf_t;

typedef enum Avtp_RvfField {
    /* RVF header fields */
    AVTP_RVF_FIELD_SUBTYPE,
    AVTP_RVF_FIELD_SV,
    AVTP_RVF_FIELD_VERSION,
    AVTP_RVF_FIELD_MR,
    AVTP_RVF_FIELD_RESERVED,
    AVTP_RVF_FIELD_TV,
    AVTP_RVF_FIELD_SEQUENCE_NUM,
    AVTP_RVF_FIELD_RESERVED_2,
    AVTP_RVF_FIELD_TU,
    AVTP_RVF_FIELD_STREAM_ID,
    AVTP_RVF_FIELD_AVTP_TIMESTAMP,
    AVTP_RVF_FIELD_ACTIVE_PIXELS,
    AVTP_RVF_FIELD_TOTAL_LINES,
    AVTP_RVF_FIELD_STREAM_DATA_LENGTH,
    AVTP_RVF_FIELD_AP,                     // Active pixels
    AVTP_RVF_FIELD_RESERVED_3,
    AVTP_RVF_FIELD_F,                      // Field
    AVTP_RVF_FIELD_EF,                     // End frame
    AVTP_RVF_FIELD_EVT,
    AVTP_RVF_FIELD_PD,                     // Pull-down
    AVTP_RVF_FIELD_I,                      // Interlaced
    AVTP_RVF_FIELD_RESERVED_4,
    AVTP_RVF_FIELD_RESERVED_5,
    AVTP_RVF_FIELD_PIXEL_DEPTH,
    AVTP_RVF_FIELD_PIXEL_FORMAT,
    AVTP_RVF_FIELD_FRAME_RATE,
    AVTP_RVF_FIELD_COLORSPACE,
    AVTP_RVF_FIELD_NUM_LINES,
    AVTP_RVF_FIELD_RESERVED_6,
    AVTP_RVF_FIELD_I_SEQ_NUM,              // Intra-line sequence number
    AVTP_RVF_FIELD_LINE_NUMBER,
    /* Count number of fields for bound checks */
    AVTP_RVF_FIELD_MAX
} Avtp_RvfField_t;

typedef enum Avtp_RvfPixelDepth {
    AVTP_RVF_PIXEL_DEPTH_8              = 0x01,
    AVTP_RVF_PIXEL_DEPTH_10             = 0x02,
    AVTP_RVF_PIXEL_DEPTH_12             = 0x03,
    AVTP_RVF_PIXEL_DEPTH_16             = 0x04,
    AVTP_RVF_PIXEL_DEPTH_USER           = 0x0F
} Avtp_RvfPixelDepth_t;

typedef enum Avtp_RvfPixelFormat {
    AVTP_RVF_PIXEL_FORMAT_MONO          = 0x00,
    AVTP_RVF_PIXEL_FORMAT_411           = 0x01,
    AVTP_RVF_PIXEL_FORMAT_420           = 0x02,
    AVTP_RVF_PIXEL_FORMAT_422           = 0x03,
    AVTP_RVF_PIXEL_FORMAT_444           = 0x04,
    AVTP_RVF_PIXEL_FORMAT_4224          = 0x06,
    AVTP_RVF_PIXEL_FORMAT_4444          = 0x07,
    AVTP_RVF_PIXEL_FORMAT_BAYER_GRBG    = 0x08,
    AVTP_RVF_PIXEL_FORMAT_BAYER_RGGB    = 0x09,
    AVTP_RVF_PIXEL_FORMAT_BAYER_BGGR    = 0x0A,
    AVTP_RVF_PIXEL_FORMAT_BAYER_GBRG    = 0x0B,
    AVTP_RVF_PIXEL_FORMAT_USER          = 0x0F
} Avtp_RvfPixelFormat_t;

typedef enum Avtp_RvfFrameRate {
    AVTP_RVF_FRAME_RATE_1               = 0x01,
    AVTP_RVF_FRAME_RATE_2               = 0x02,
    AVTP_RVF_FRAME_RATE_5               = 0x03,
    AVTP_RVF_FRAME_RATE_10              = 0x10,
    AVTP_RVF_FRAME_RATE_15              = 0x11,
    AVTP_RVF_FRAME_RATE_20              = 0x12,
    AVTP_RVF_FRAME_RATE_24              = 0x13,
    AVTP_RVF_FRAME_RATE_25              = 0x14,
    AVTP_RVF_FRAME_RATE_30              = 0x15,
    AVTP_RVF_FRAME_RATE_48              = 0x16,
    AVTP_RVF_FRAME_RATE_50              = 0x17,
    AVTP_RVF_FRAME_RATE_60              = 0x18,
    AVTP_RVF_FRAME_RATE_72              = 0x19,
    AVTP_RVF_FRAME_RATE_85              = 0x1A,
    AVTP_RVF_FRAME_RATE_100             = 0x30,
    AVTP_RVF_FRAME_RATE_120             = 0x31,
    AVTP_RVF_FRAME_RATE_150             = 0x32,
    AVTP_RVF_FRAME_RATE_200             = 0x33,
    AVTP_RVF_FRAME_RATE_240             = 0x34,
    AVTP_RVF_FRAME_RATE_300             = 0x35,
    AVTP_RVF_FRAME_RATE_USER            = 0x0F
} Avtp_RvfFrameRate_t;

/* RVF 'colorspace' field values. */
typedef enum Avtp_RvfColorspace {
    AVTP_RVF_COLORSPACE_YCbCr           = 0x01,
    AVTP_RVF_COLORSPACE_SRGB            = 0x02,
    AVTP_RVF_COLORSPACE_YCgCo           = 0x03,
    AVTP_RVF_COLORSPACE_GRAY            = 0x04,
    AVTP_RVF_COLORSPACE_XYZ             = 0x05,
    AVTP_RVF_COLORSPACE_YCM             = 0x06,
    AVTP_RVF_COLORSPACE_BT_601          = 0x07,
    AVTP_RVF_COLORSPACE_BT_709          = 0x08,
    AVTP_RVF_COLORSPACE_ITU_BT          = 0x09,
    AVTP_RVF_COLORSPACE_USER            = 0x0F
} Avtp_RvfColorspace_t;

void Avtp_Rvf_Init(Avtp_Rvf_t* pdu);

uint64_t Avtp_Rvf_GetField(Avtp_Rvf_t* pdu, Avtp_RvfField_t field);

uint8_t Avtp_Rvf_GetSubtype(Avtp_Rvf_t* pdu);
uint8_t Avtp_Rvf_GetSv(Avtp_Rvf_t* pdu);
uint8_t Avtp_Rvf_GetVersion(Avtp_Rvf_t* pdu);
uint8_t Avtp_Rvf_GetMr(Avtp_Rvf_t* pdu);
uint8_t Avtp_Rvf_GetTv(Avtp_Rvf_t* pdu);
uint8_t Avtp_Rvf_GetSequenceNum(Avtp_Rvf_t* pdu);
uint8_t Avtp_Rvf_GetTu(Avtp_Rvf_t* pdu);
uint64_t Avtp_Rvf_GetStreamId(Avtp_Rvf_t* pdu);
uint32_t Avtp_Rvf_GetAvtpTimestamp(Avtp_Rvf_t* pdu);
uint16_t Avtp_Rvf_GetActivePixels(Avtp_Rvf_t* pdu);
uint16_t Avtp_Rvf_GetTotalLines(Avtp_Rvf_t* pdu);
uint16_t Avtp_Rvf_GetStreamDataLength(Avtp_Rvf_t* pdu);
uint8_t Avtp_Rvf_GetAp(Avtp_Rvf_t* pdu);
uint8_t Avtp_Rvf_GetF(Avtp_Rvf_t* pdu);
uint8_t Avtp_Rvf_GetEf(Avtp_Rvf_t* pdu);
uint8_t Avtp_Rvf_GetEvt(Avtp_Rvf_t* pdu);
uint8_t Avtp_Rvf_GetPd(Avtp_Rvf_t* pdu);
uint8_t Avtp_Rvf_GetI(Avtp_Rvf_t* pdu);
Avtp_RvfPixelDepth_t Avtp_Rvf_GetPixelDepth(Avtp_Rvf_t* pdu);
Avtp_RvfPixelFormat_t Avtp_Rvf_GetPixelFormat(Avtp_Rvf_t* pdu);
Avtp_RvfFrameRate_t Avtp_Rvf_GetFrameRate(Avtp_Rvf_t* pdu);
Avtp_RvfColorspace_t Avtp_Rvf_GetColorspace(Avtp_Rvf_t* pdu);
uint8_t Avtp_Rvf_GetNumLines(Avtp_Rvf_t* pdu);
uint8_t Avtp_Rvf_GetISeqNum(Avtp_Rvf_t* pdu);
uint16_t Avtp_Rvf_GetLineNumber(Avtp_Rvf_t* pdu);

void Avtp_Rvf_SetField(Avtp_Rvf_t* pdu, Avtp_RvfField_t field, uint64_t value);

void Avtp_Rvf_SetSubtype(Avtp_Rvf_t* pdu, uint8_t value);
void Avtp_Rvf_EnableSv(Avtp_Rvf_t* pdu);
void Avtp_Rvf_DisableSv(Avtp_Rvf_t* pdu);
void Avtp_Rvf_SetVersion(Avtp_Rvf_t* pdu, uint8_t value);
void Avtp_Rvf_EnableMr(Avtp_Rvf_t* pdu);
void Avtp_Rvf_DisableMr(Avtp_Rvf_t* pdu);
void Avtp_Rvf_EnableTv(Avtp_Rvf_t* pdu);
void Avtp_Rvf_DisableTv(Avtp_Rvf_t* pdu);
void Avtp_Rvf_SetSequenceNum(Avtp_Rvf_t* pdu, uint8_t value);
void Avtp_Rvf_EnableTu(Avtp_Rvf_t* pdu);
void Avtp_Rvf_DisableTu(Avtp_Rvf_t* pdu);
void Avtp_Rvf_SetStreamId(Avtp_Rvf_t* pdu, uint64_t value);
void Avtp_Rvf_SetAvtpTimestamp(Avtp_Rvf_t* pdu, uint32_t value);
void Avtp_Rvf_SetActivePixels(Avtp_Rvf_t* pdu, uint16_t value);
void Avtp_Rvf_SetTotalLines(Avtp_Rvf_t* pdu, uint16_t value);
void Avtp_Rvf_SetStreamDataLength(Avtp_Rvf_t* pdu, uint16_t value);
void Avtp_Rvf_EnableAp(Avtp_Rvf_t* pdu);
void Avtp_Rvf_DisableAp(Avtp_Rvf_t* pdu);
void Avtp_Rvf_EnableF(Avtp_Rvf_t* pdu);
void Avtp_Rvf_DisableF(Avtp_Rvf_t* pdu);
void Avtp_Rvf_EnableEf(Avtp_Rvf_t* pdu);
void Avtp_Rvf_DisableEf(Avtp_Rvf_t* pdu);
void Avtp_Rvf_SetEvt(Avtp_Rvf_t* pdu, uint8_t value);
void Avtp_Rvf_EnablePd(Avtp_Rvf_t* pdu);
void Avtp_Rvf_DisablePd(Avtp_Rvf_t* pdu);
void Avtp_Rvf_EnableI(Avtp_Rvf_t* pdu);
void Avtp_Rvf_DisableI(Avtp_Rvf_t* pdu);
void Avtp_Rvf_SetPixelDepth(Avtp_Rvf_t* pdu, Avtp_RvfPixelDepth_t value);
void Avtp_Rvf_SetPixelFormat(Avtp_Rvf_t* pdu, Avtp_RvfPixelFormat_t value);
void Avtp_Rvf_SetFrameRate(Avtp_Rvf_t* pdu, Avtp_RvfFrameRate_t value);
void Avtp_Rvf_SetColorspace(Avtp_Rvf_t* pdu, Avtp_RvfColorspace_t value);
void Avtp_Rvf_SetNumLines(Avtp_Rvf_t* pdu, uint8_t value);
void Avtp_Rvf_SetISeqNum(Avtp_Rvf_t* pdu, uint8_t value);
void Avtp_Rvf_SetLineNumber(Avtp_Rvf_t* pdu, uint16_t value);

/******************************************************************************
 * Legacy API (deprecated)
 *****************************************************************************/

#define AVTP_RVF_FIELD_SEQ_NUM          (AVTP_RVF_FIELD_SEQUENCE_NUM)
#define AVTP_RVF_FIELD_TIMESTAMP        (AVTP_RVF_FIELD_AVTP_TIMESTAMP)
#define AVTP_RVF_FIELD_STREAM_DATA_LEN  (AVTP_RVF_FIELD_STREAM_DATA_LENGTH)
#define AVTP_RVF_FIELD_RAW_PIXEL_DEPTH  (AVTP_RVF_FIELD_PIXEL_DEPTH)
#define AVTP_RVF_FIELD_RAW_PIXEL_FORMAT (AVTP_RVF_FIELD_PIXEL_FORMAT)
#define AVTP_RVF_FIELD_RAW_FRAME_RATE   (AVTP_RVF_FIELD_FRAME_RATE)
#define AVTP_RVF_FIELD_RAW_COLORSPACE   (AVTP_RVF_FIELD_COLORSPACE)
#define AVTP_RVF_FIELD_RAW_NUM_LINES    (AVTP_RVF_FIELD_NUM_LINES)
#define AVTP_RVF_FIELD_RAW_I_SEQ_NUM    (AVTP_RVF_FIELD_I_SEQ_NUM)
#define AVTP_RVF_FIELD_RAW_LINE_NUMBER  (AVTP_RVF_FIELD_LINE_NUMBER)

struct avtp_rvf_payload {
    uint64_t raw_header;
    uint8_t raw_data[0];
} __attribute__((__packed__));

/**
 * @deprecated
 * Get value of RVF AVTPDU field.
 * @pdu: Pointer to PDU struct.
 * @field: PDU field to be retrieved.
 * @val: Pointer to variable which the retrieved value should be saved.
 *
 * Returns:
 *    0: Success.
 *    -EINVAL: If any argument is invalid.
 */
int avtp_rvf_pdu_get(const void* pdu, Avtp_RvfField_t field, uint64_t* val);

/**
 * @deprecated
 * Set value of RVF AVTPDU field.
 * @pdu: Pointer to PDU struct.
 * @field: PDU field to be set.
 * @val: Value to be set.
 *
 * Returns:
 *    0: Success.
 *    -EINVAL: If any argument is invalid.
 */
int avtp_rvf_pdu_set(void* pdu, Avtp_RvfField_t field, uint64_t val);

/**
 * @deprecated
 * Initialize RVF AVTPDU. All AVTPDU fields are initialized with zero except
 * 'subtype' (which is set to AVTP_SUBTYPE_RVF), 'sv' (which is set to 1),
 * @pdu: Pointer to PDU struct.
 * @subtype: AVTP CVF Format Subtype of this AVTPDU.
 *
 * Return values:
 *    0: Success.
 *    -EINVAL: If any argument is invalid.
 */
int avtp_rvf_pdu_init(void* pdu);

#ifdef __cplusplus
}
#endif
