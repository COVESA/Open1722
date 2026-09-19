/*
 * Copyright (c) 2019, Intel Corporation
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
 *    * Neither the name of Intel Corporation nor the names of its contributors
 *      may be used to endorse or promote products derived from this software
 *      without specific prior written permission.
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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#if defined(__cplusplus)
extern "C" {
#include <cmocka.h>
}
#else
#include <cmocka.h>
#endif
#include <arpa/inet.h>
#include <string.h>

#include "avtp/CommonHeader.h"
#include "avtp/CommonStreamHeader.h"
#include "avtp/cvf/Cvf.h"
#include "avtp/cvf/H264.h"
#include "avtp/cvf/Jpeg2000.h"
#include "avtp/cvf/Mjpeg.h"

#define MAX_PDU_SIZE 1500

static uint32_t read_quadlet(const uint8_t *pdu, size_t quadlet)
{
    uint32_t word;

    memcpy(&word, pdu + (quadlet * 4), sizeof(word));
    return ntohl(word);
}

/******************************************************************************
 * CVF tests
 *****************************************************************************/

static void cvf_init(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t init_pdu[AVTP_CVF_HEADER_LEN_V0];

    assert_int_equal(sizeof(Avtp_Cvf_t), AVTP_CVF_HEADER_LEN_V0);

    /* Passing a NULL pointer must be a no-op. */
    Avtp_Cvf_Init(NULL);

    Avtp_Cvf_Init((Avtp_Cvf_t *)pdu);
    memset(init_pdu, 0, AVTP_CVF_HEADER_LEN_V0);
    init_pdu[0] = AVTP_SUBTYPE_CVF;     /* subtype = CVF */
    init_pdu[1] = 0x80;                 /* sv = 1, version = 0 */
    init_pdu[16] = AVTP_CVF_FORMAT_RFC; /* format = RFC */
    assert_memory_equal(init_pdu, pdu, AVTP_CVF_HEADER_LEN_V0);
}

static void cvf_init_v1(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t init_pdu[AVTP_CVF_HEADER_LEN_V1];

    assert_int_equal(sizeof(Avtp_CvfV1_t), AVTP_CVF_HEADER_LEN_V1);

    /* Passing a NULL pointer must be a no-op. */
    Avtp_Cvf_InitV1(NULL);

    Avtp_Cvf_InitV1((Avtp_CvfV1_t *)pdu);
    memset(init_pdu, 0, AVTP_CVF_HEADER_LEN_V1);
    init_pdu[0] = AVTP_SUBTYPE_CVF;     /* subtype = CVF */
    init_pdu[1] = 0x90;                 /* sv = 1, version = 1 */
    init_pdu[32] = AVTP_CVF_FORMAT_RFC; /* format = RFC at q8@0 */
    assert_memory_equal(init_pdu, pdu, AVTP_CVF_HEADER_LEN_V1);

    assert_int_equal(Avtp_Cvf_GetHeaderLen((Avtp_Cvf_t *)pdu), AVTP_CVF_HEADER_LEN_V1);
}

static void cvf_is_valid(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];

    Avtp_Cvf_Init((Avtp_Cvf_t *)pdu);
    assert_true(Avtp_Cvf_IsValid((Avtp_Cvf_t *)pdu, AVTP_CVF_HEADER_LEN_V0));

    /* NULL pdu. */
    assert_false(Avtp_Cvf_IsValid(NULL, MAX_PDU_SIZE));

    /* Not a CVF frame. */
    memset(pdu, 0, MAX_PDU_SIZE);
    assert_false(Avtp_Cvf_IsValid((Avtp_Cvf_t *)pdu, MAX_PDU_SIZE));

    /* Buffer smaller than the CVF header. */
    Avtp_Cvf_Init((Avtp_Cvf_t *)pdu);
    assert_false(Avtp_Cvf_IsValid((Avtp_Cvf_t *)pdu, AVTP_CVF_HEADER_LEN_V0 - 1));

    /* stream_data_length does not fit into the buffer. */
    Avtp_Cvf_Init((Avtp_Cvf_t *)pdu);
    Avtp_Cvf_SetStreamDataLength((Avtp_Cvf_t *)pdu, 10);
    assert_false(Avtp_Cvf_IsValid((Avtp_Cvf_t *)pdu, AVTP_CVF_HEADER_LEN_V0 + 9));
    assert_true(Avtp_Cvf_IsValid((Avtp_Cvf_t *)pdu, AVTP_CVF_HEADER_LEN_V0 + 10));

    /* Valid version 1 frame. */
    Avtp_Cvf_InitV1((Avtp_CvfV1_t *)pdu);
    Avtp_Cvf_SetStreamDataLength((Avtp_Cvf_t *)pdu, 10);
    assert_true(Avtp_Cvf_IsValid((Avtp_Cvf_t *)pdu, AVTP_CVF_HEADER_LEN_V1 + 10));
    assert_false(Avtp_Cvf_IsValid((Avtp_Cvf_t *)pdu, AVTP_CVF_HEADER_LEN_V1 + 9));
    assert_false(Avtp_Cvf_IsValid((Avtp_Cvf_t *)pdu, AVTP_CVF_HEADER_LEN_V1 - 1));

    /* Unsupported version is rejected. */
    Avtp_Cvf_Init((Avtp_Cvf_t *)pdu);
    Avtp_CommonHeader_SetVersion((Avtp_CommonHeader_t *)pdu, 2);
    assert_false(Avtp_Cvf_IsValid((Avtp_Cvf_t *)pdu, MAX_PDU_SIZE));
}

static void mark_descriptors(uint8_t *coverage, size_t coverageBits,
                             const Avtp_FieldDescriptor_t *desc, uint8_t numFields)
{
    for (uint8_t i = 0; i < numFields; i++) {
        uint8_t bits = desc[i].bits;
        uint8_t offset = desc[i].offset;
        uint8_t quadlet = desc[i].quadlet;

        for (uint8_t b = 0; b < bits; b++) {
            size_t bit = ((size_t)quadlet * 32) + offset + b;

            assert_true(bit < coverageBits);
            assert_int_equal(coverage[bit], 0);
            coverage[bit] = 1;
        }
    }
}

static void cvf_field_descriptors_cover_header(void **state)
{
    (void)state;

    for (uint8_t version = 0; version <= 1; version++) {
        uint8_t coverage[AVTP_CVF_HEADER_LEN_V1 * 8] = {0};
        size_t coverageBits = sizeof(coverage);
        const Avtp_FieldDescriptor_t *cvfDesc =
            version == AVTP_VERSION_1 ? Avtp_CvfFieldDescV1 : Avtp_CvfFieldDescV0;
        size_t headerBits = (version == AVTP_VERSION_1 ? (size_t)AVTP_CVF_HEADER_LEN_V1
                                                       : (size_t)AVTP_CVF_HEADER_LEN_V0) *
                            8;

        mark_descriptors(coverage, coverageBits,
                         &Avtp_CommonHeaderFieldDesc[AVTPDU_COMMON_FIELD_SUBTYPE], 1);
        mark_descriptors(coverage, coverageBits,
                         &Avtp_CommonHeaderFieldDesc[AVTPDU_COMMON_FIELD_VERSION], 1);
        mark_descriptors(coverage, coverageBits, cvfDesc, AVTP_CVF_FIELD_MAX);

        for (size_t bit = 0; bit < coverageBits; bit++) {
            assert_int_equal(coverage[bit], bit < headerBits ? 1 : 0);
        }
    }
}

static void cvf_common_field_consistency(void **state)
{
    (void)state;

    assert_int_equal(AVTP_CVF_FIELD_STREAM_DATA_LENGTH, AVTPDU_CSH_FIELD_STREAM_DATA_LENGTH);

    for (uint8_t version = 0; version <= 1; version++) {
        const Avtp_FieldDescriptor_t *cvfDesc =
            version == AVTP_VERSION_1 ? Avtp_CvfFieldDescV1 : Avtp_CvfFieldDescV0;
        const Avtp_FieldDescriptor_t *cshDesc =
            version == AVTP_VERSION_1 ? Avtp_CshFieldDescV1 : Avtp_CshFieldDescV0;

        for (uint8_t i = 0; i < AVTPDU_CSH_FIELD_MAX; i++) {
            assert_int_equal(cvfDesc[i].quadlet, cshDesc[i].quadlet);
            assert_int_equal(cvfDesc[i].offset, cshDesc[i].offset);
            assert_int_equal(cvfDesc[i].bits, cshDesc[i].bits);
        }
    }
}

static void cvf_flag_fields(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Cvf_t *cvf = (Avtp_Cvf_t *)pdu;

    Avtp_Cvf_Init(cvf);
    assert_true(Avtp_Cvf_IsSv(cvf));

    Avtp_Cvf_SetSv(cvf, false);
    assert_false(Avtp_Cvf_IsSv(cvf));

    Avtp_Cvf_SetMr(cvf, true);
    assert_true(Avtp_Cvf_IsMr(cvf));
    Avtp_Cvf_SetMr(cvf, false);
    assert_false(Avtp_Cvf_IsMr(cvf));

    Avtp_Cvf_SetTv(cvf, true);
    assert_true(Avtp_Cvf_IsTv(cvf));
    Avtp_Cvf_SetTv(cvf, false);
    assert_false(Avtp_Cvf_IsTv(cvf));

    Avtp_Cvf_SetTu(cvf, true);
    assert_true(Avtp_Cvf_IsTu(cvf));
    Avtp_Cvf_SetTu(cvf, false);
    assert_false(Avtp_Cvf_IsTu(cvf));

    Avtp_Cvf_SetPtv(cvf, true);
    assert_true(Avtp_Cvf_IsPtv(cvf));
    Avtp_Cvf_SetPtv(cvf, false);
    assert_false(Avtp_Cvf_IsPtv(cvf));

    Avtp_Cvf_SetM(cvf, true);
    assert_true(Avtp_Cvf_IsM(cvf));
    Avtp_Cvf_SetM(cvf, false);
    assert_false(Avtp_Cvf_IsM(cvf));
}

static void cvf_field_layout(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Cvf_t *cvf = (Avtp_Cvf_t *)pdu;

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Cvf_SetSequenceNum(cvf, 0x55);
    assert_int_equal(Avtp_Cvf_GetSequenceNum(cvf), 0x55);
    assert_int_equal(read_quadlet(pdu, 0), 0x00005500);

    Avtp_Cvf_SetTu(cvf, true);
    assert_true(Avtp_Cvf_IsTu(cvf));
    assert_int_equal(read_quadlet(pdu, 0), 0x00005501);

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Cvf_SetStreamId(cvf, 0xAABBCCDDEEFF0001);
    assert_int_equal(Avtp_Cvf_GetStreamId(cvf), 0xAABBCCDDEEFF0001);

    Avtp_Cvf_SetAvtpTimestamp(cvf, 0x80C0FFEE);
    assert_int_equal(Avtp_Cvf_GetAvtpTimestamp(cvf), 0x80C0FFEE);
    assert_int_equal(read_quadlet(pdu, 3), 0x80C0FFEE);

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Cvf_SetFormat(cvf, AVTP_CVF_FORMAT_RFC);
    assert_int_equal(Avtp_Cvf_GetFormat(cvf), AVTP_CVF_FORMAT_RFC);
    assert_int_equal(read_quadlet(pdu, 4), 0x02000000);

    Avtp_Cvf_SetFormatSubtype(cvf, AVTP_CVF_FORMAT_SUBTYPE_H264);
    assert_int_equal(Avtp_Cvf_GetFormatSubtype(cvf), AVTP_CVF_FORMAT_SUBTYPE_H264);
    assert_int_equal(read_quadlet(pdu, 4), 0x02010000);

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Cvf_SetStreamDataLength(cvf, 0xAAAA);
    assert_int_equal(Avtp_Cvf_GetStreamDataLength(cvf), 0xAAAA);
    assert_int_equal(read_quadlet(pdu, 5), 0xAAAA0000);

    Avtp_Cvf_SetPtv(cvf, true);
    assert_true(Avtp_Cvf_IsPtv(cvf));
    assert_int_equal(read_quadlet(pdu, 5), 0xAAAA2000);

    Avtp_Cvf_SetM(cvf, true);
    assert_true(Avtp_Cvf_IsM(cvf));
    assert_int_equal(read_quadlet(pdu, 5), 0xAAAA3000);

    Avtp_Cvf_SetEvt(cvf, 0xA);
    assert_int_equal(Avtp_Cvf_GetEvt(cvf), 0xA);
    assert_int_equal(read_quadlet(pdu, 5), 0xAAAA3A00);

    /* ptp_grandmaster_identity does not exist in version 0. */
    assert_int_equal(Avtp_Cvf_GetPtpGrandmasterIdentity(cvf), 0);
}

static void cvf_v1_layout(void **state)
{
    (void)state;
    uint8_t pdu[AVTP_CVF_HEADER_LEN_V1];
    Avtp_Cvf_t *cvf = (Avtp_Cvf_t *)pdu;

    Avtp_Cvf_InitV1((Avtp_CvfV1_t *)pdu);

    Avtp_Cvf_SetSequenceNum(cvf, 0x12345678);
    assert_int_equal(Avtp_Cvf_GetSequenceNum(cvf), 0x12345678);
    assert_int_equal(read_quadlet(pdu, 3), 0x12345678);

    Avtp_Cvf_SetAvtpTimestamp(cvf, 0x1122334455667788ULL);
    assert_int_equal(Avtp_Cvf_GetAvtpTimestamp(cvf), 0x1122334455667788ULL);
    assert_int_equal(read_quadlet(pdu, 4), 0x11223344);
    assert_int_equal(read_quadlet(pdu, 5), 0x55667788);

    Avtp_Cvf_SetPtpGrandmasterIdentity(cvf, 0x99AABBCCDDEEFF00ULL);
    assert_int_equal(Avtp_Cvf_GetPtpGrandmasterIdentity(cvf), 0x99AABBCCDDEEFF00ULL);
    assert_int_equal(read_quadlet(pdu, 6), 0x99AABBCC);
    assert_int_equal(read_quadlet(pdu, 7), 0xDDEEFF00);

    Avtp_Cvf_SetFormat(cvf, AVTP_CVF_FORMAT_RFC);
    Avtp_Cvf_SetFormatSubtype(cvf, AVTP_CVF_FORMAT_SUBTYPE_H264);
    assert_int_equal(read_quadlet(pdu, 8), 0x02010000);

    Avtp_Cvf_SetStreamDataLength(cvf, 0xAAAA);
    Avtp_Cvf_SetPtv(cvf, true);
    Avtp_Cvf_SetM(cvf, true);
    Avtp_Cvf_SetEvt(cvf, 0xA);
    assert_int_equal(read_quadlet(pdu, 9), 0xAAAA3A00);
}

static void cvf_payload(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t payload[8] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
    uint8_t payload_out[8] = {0};
    Avtp_Cvf_t *cvf = (Avtp_Cvf_t *)pdu;

    Avtp_Cvf_Init(cvf);
    Avtp_Cvf_SetPayload(cvf, payload, sizeof(payload));

    assert_ptr_equal(Avtp_Cvf_GetPayload(cvf), pdu + AVTP_CVF_HEADER_LEN_V0);
    assert_memory_equal(pdu + AVTP_CVF_HEADER_LEN_V0, payload, sizeof(payload));

    memcpy(payload_out, Avtp_Cvf_GetPayload(cvf), sizeof(payload_out));
    assert_memory_equal(payload_out, payload, sizeof(payload_out));

    /* Version 1 payload starts after the 40-octet header. */
    Avtp_Cvf_InitV1((Avtp_CvfV1_t *)pdu);
    Avtp_Cvf_SetPayload((Avtp_Cvf_t *)pdu, payload, sizeof(payload));
    assert_ptr_equal(Avtp_Cvf_GetPayload((Avtp_Cvf_t *)pdu), pdu + AVTP_CVF_HEADER_LEN_V1);
    assert_memory_equal(pdu + AVTP_CVF_HEADER_LEN_V1, payload, sizeof(payload));
}

static void cvf_get_set_field(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Cvf_t *cvf = (Avtp_Cvf_t *)pdu;

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Cvf_SetField(cvf, AVTP_CVF_FIELD_EVT, 0xA);
    assert_int_equal(Avtp_Cvf_GetField(cvf, AVTP_CVF_FIELD_EVT), 0xA);

    /* Reserved fields are reachable through the generic access engine. */
    Avtp_Cvf_SetField(cvf, AVTP_CVF_FIELD_FSD, 0x3);
    assert_int_equal(Avtp_Cvf_GetField(cvf, AVTP_CVF_FIELD_FSD), 0x3);

    Avtp_Cvf_SetField(cvf, AVTP_CVF_FIELD_FSD1, 0x7F);
    assert_int_equal(Avtp_Cvf_GetField(cvf, AVTP_CVF_FIELD_FSD1), 0x7F);
}

/******************************************************************************
 * MJPEG tests
 *****************************************************************************/

static void mjpeg_init(void **state)
{
    (void)state;
    uint8_t pdu[AVTP_MJPEG_HEADER_LEN];
    uint8_t zero[AVTP_MJPEG_HEADER_LEN] = {0};

    assert_int_equal(sizeof(Avtp_Mjpeg_t), AVTP_MJPEG_HEADER_LEN);

    /* Passing a NULL pointer must be a no-op. */
    Avtp_Mjpeg_Init(NULL);

    memset(pdu, 0xFF, AVTP_MJPEG_HEADER_LEN);
    Avtp_Mjpeg_Init((Avtp_Mjpeg_t *)pdu);
    assert_memory_equal(pdu, zero, AVTP_MJPEG_HEADER_LEN);
}

static void mjpeg_is_valid(void **state)
{
    (void)state;
    uint8_t pdu[AVTP_MJPEG_HEADER_LEN];

    assert_true(Avtp_Mjpeg_IsValid((Avtp_Mjpeg_t *)pdu, AVTP_MJPEG_HEADER_LEN));
    assert_false(Avtp_Mjpeg_IsValid(NULL, AVTP_MJPEG_HEADER_LEN));
    assert_false(Avtp_Mjpeg_IsValid((Avtp_Mjpeg_t *)pdu, AVTP_MJPEG_HEADER_LEN - 1));
}

static void mjpeg_field_descriptors_cover_header(void **state)
{
    (void)state;
    uint8_t coverage[AVTP_MJPEG_HEADER_LEN * 8] = {0};

    for (uint8_t i = 0; i < AVTP_MJPEG_FIELD_MAX; i++) {
        uint8_t quadlet = Avtp_MjpegFieldDesc[i].quadlet;
        uint8_t offset = Avtp_MjpegFieldDesc[i].offset;
        uint8_t bits = Avtp_MjpegFieldDesc[i].bits;

        for (uint8_t b = 0; b < bits; b++) {
            size_t bit = ((size_t)quadlet * 32) + offset + b;

            assert_true(bit < sizeof(coverage));
            assert_int_equal(coverage[bit], 0);
            coverage[bit] = 1;
        }
    }

    for (size_t bit = 0; bit < sizeof(coverage); bit++) {
        assert_int_equal(coverage[bit], 1);
    }
}

static void mjpeg_field_layout(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Mjpeg_t *mjpeg = (Avtp_Mjpeg_t *)pdu;

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Mjpeg_SetTypeSpecific(mjpeg, 0xAB);
    assert_int_equal(Avtp_Mjpeg_GetTypeSpecific(mjpeg), 0xAB);
    assert_int_equal(read_quadlet(pdu, 0), 0xAB000000);

    Avtp_Mjpeg_SetFragmentOffset(mjpeg, 0x123456);
    assert_int_equal(Avtp_Mjpeg_GetFragmentOffset(mjpeg), 0x123456);
    assert_int_equal(read_quadlet(pdu, 0), 0xAB123456);

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Mjpeg_SetType(mjpeg, 0x11);
    assert_int_equal(Avtp_Mjpeg_GetType(mjpeg), 0x11);
    assert_int_equal(read_quadlet(pdu, 1), 0x11000000);

    Avtp_Mjpeg_SetQ(mjpeg, 0x22);
    assert_int_equal(Avtp_Mjpeg_GetQ(mjpeg), 0x22);
    assert_int_equal(read_quadlet(pdu, 1), 0x11220000);

    Avtp_Mjpeg_SetWidth(mjpeg, 0x33);
    assert_int_equal(Avtp_Mjpeg_GetWidth(mjpeg), 0x33);
    assert_int_equal(read_quadlet(pdu, 1), 0x11223300);

    Avtp_Mjpeg_SetHeight(mjpeg, 0x44);
    assert_int_equal(Avtp_Mjpeg_GetHeight(mjpeg), 0x44);
    assert_int_equal(read_quadlet(pdu, 1), 0x11223344);
}

static void mjpeg_payload(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t payload[8] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
    Avtp_Mjpeg_t *mjpeg = (Avtp_Mjpeg_t *)pdu;

    Avtp_Mjpeg_Init(mjpeg);
    Avtp_Mjpeg_SetPayload(mjpeg, payload, sizeof(payload));

    assert_memory_equal(Avtp_Mjpeg_GetPayload(mjpeg), payload, sizeof(payload));
    assert_memory_equal(mjpeg->payload, payload, sizeof(payload));
}

/******************************************************************************
 * H.264 tests
 *****************************************************************************/

static void h264_init(void **state)
{
    (void)state;
    uint8_t pdu[AVTP_H264_HEADER_LEN];
    uint8_t zero[AVTP_H264_HEADER_LEN] = {0};

    assert_int_equal(sizeof(Avtp_H264_t), AVTP_H264_HEADER_LEN);

    /* Passing a NULL pointer must be a no-op. */
    Avtp_H264_Init(NULL);

    memset(pdu, 0xFF, AVTP_H264_HEADER_LEN);
    Avtp_H264_Init((Avtp_H264_t *)pdu);
    assert_memory_equal(pdu, zero, AVTP_H264_HEADER_LEN);
}

static void h264_is_valid(void **state)
{
    (void)state;
    uint8_t pdu[AVTP_H264_HEADER_LEN];

    assert_true(Avtp_H264_IsValid((Avtp_H264_t *)pdu, AVTP_H264_HEADER_LEN));
    assert_false(Avtp_H264_IsValid(NULL, AVTP_H264_HEADER_LEN));
    assert_false(Avtp_H264_IsValid((Avtp_H264_t *)pdu, AVTP_H264_HEADER_LEN - 1));
}

static void h264_field_descriptors_cover_header(void **state)
{
    (void)state;
    uint8_t coverage[AVTP_H264_HEADER_LEN * 8] = {0};

    for (uint8_t i = 0; i < AVTP_H264_FIELD_MAX; i++) {
        uint8_t quadlet = Avtp_H264FieldDesc[i].quadlet;
        uint8_t offset = Avtp_H264FieldDesc[i].offset;
        uint8_t bits = Avtp_H264FieldDesc[i].bits;

        for (uint8_t b = 0; b < bits; b++) {
            size_t bit = ((size_t)quadlet * 32) + offset + b;

            assert_true(bit < sizeof(coverage));
            assert_int_equal(coverage[bit], 0);
            coverage[bit] = 1;
        }
    }

    for (size_t bit = 0; bit < sizeof(coverage); bit++) {
        assert_int_equal(coverage[bit], 1);
    }
}

static void h264_field_layout(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_H264_t *h264 = (Avtp_H264_t *)pdu;

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_H264_SetTimestamp(h264, 0x80C0FFEE);
    assert_int_equal(Avtp_H264_GetTimestamp(h264), 0x80C0FFEE);
    assert_int_equal(read_quadlet(pdu, 0), 0x80C0FFEE);
}

static void h264_payload(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t payload[8] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
    Avtp_H264_t *h264 = (Avtp_H264_t *)pdu;

    Avtp_H264_Init(h264);
    Avtp_H264_SetPayload(h264, payload, sizeof(payload));

    assert_memory_equal(Avtp_H264_GetPayload(h264), payload, sizeof(payload));
    assert_memory_equal(h264->payload, payload, sizeof(payload));
}

/******************************************************************************
 * JPEG 2000 tests
 *****************************************************************************/

static void jpeg2000_init(void **state)
{
    (void)state;
    uint8_t pdu[AVTP_JPEG2000_HEADER_LEN];
    uint8_t zero[AVTP_JPEG2000_HEADER_LEN] = {0};

    assert_int_equal(sizeof(Avtp_Jpeg2000_t), AVTP_JPEG2000_HEADER_LEN);

    /* Passing a NULL pointer must be a no-op. */
    Avtp_Jpeg2000_Init(NULL);

    memset(pdu, 0xFF, AVTP_JPEG2000_HEADER_LEN);
    Avtp_Jpeg2000_Init((Avtp_Jpeg2000_t *)pdu);
    assert_memory_equal(pdu, zero, AVTP_JPEG2000_HEADER_LEN);
}

static void jpeg2000_is_valid(void **state)
{
    (void)state;
    uint8_t pdu[AVTP_JPEG2000_HEADER_LEN];

    assert_true(Avtp_Jpeg2000_IsValid((Avtp_Jpeg2000_t *)pdu, AVTP_JPEG2000_HEADER_LEN));
    assert_false(Avtp_Jpeg2000_IsValid(NULL, AVTP_JPEG2000_HEADER_LEN));
    assert_false(Avtp_Jpeg2000_IsValid((Avtp_Jpeg2000_t *)pdu, AVTP_JPEG2000_HEADER_LEN - 1));
}

static void jpeg2000_field_descriptors_cover_header(void **state)
{
    (void)state;
    uint8_t coverage[AVTP_JPEG2000_HEADER_LEN * 8] = {0};

    for (uint8_t i = 0; i < AVTP_JPEG2000_FIELD_MAX; i++) {
        uint8_t quadlet = Avtp_Jpeg2000FieldDesc[i].quadlet;
        uint8_t offset = Avtp_Jpeg2000FieldDesc[i].offset;
        uint8_t bits = Avtp_Jpeg2000FieldDesc[i].bits;

        for (uint8_t b = 0; b < bits; b++) {
            size_t bit = ((size_t)quadlet * 32) + offset + b;

            assert_true(bit < sizeof(coverage));
            assert_int_equal(coverage[bit], 0);
            coverage[bit] = 1;
        }
    }

    for (size_t bit = 0; bit < sizeof(coverage); bit++) {
        assert_int_equal(coverage[bit], 1);
    }
}

static void jpeg2000_flag_fields(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Jpeg2000_t *jpeg2000 = (Avtp_Jpeg2000_t *)pdu;

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Jpeg2000_SetT(jpeg2000, true);
    assert_true(Avtp_Jpeg2000_IsT(jpeg2000));
    Avtp_Jpeg2000_SetT(jpeg2000, false);
    assert_false(Avtp_Jpeg2000_IsT(jpeg2000));
}

static void jpeg2000_field_layout(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Jpeg2000_t *jpeg2000 = (Avtp_Jpeg2000_t *)pdu;

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Jpeg2000_SetTp(jpeg2000, 0x3);
    assert_int_equal(Avtp_Jpeg2000_GetTp(jpeg2000), 0x3);
    assert_int_equal(read_quadlet(pdu, 0), 0xC0000000);

    Avtp_Jpeg2000_SetMhf(jpeg2000, 0x2);
    assert_int_equal(Avtp_Jpeg2000_GetMhf(jpeg2000), 0x2);
    assert_int_equal(read_quadlet(pdu, 0), 0xE0000000);

    Avtp_Jpeg2000_SetMhId(jpeg2000, 0x5);
    assert_int_equal(Avtp_Jpeg2000_GetMhId(jpeg2000), 0x5);
    assert_int_equal(read_quadlet(pdu, 0), 0xEA000000);

    Avtp_Jpeg2000_SetT(jpeg2000, true);
    assert_true(Avtp_Jpeg2000_IsT(jpeg2000));
    assert_int_equal(read_quadlet(pdu, 0), 0xEB000000);

    Avtp_Jpeg2000_SetPriority(jpeg2000, 0x11);
    assert_int_equal(Avtp_Jpeg2000_GetPriority(jpeg2000), 0x11);
    assert_int_equal(read_quadlet(pdu, 0), 0xEB110000);

    Avtp_Jpeg2000_SetTileNumber(jpeg2000, 0x2233);
    assert_int_equal(Avtp_Jpeg2000_GetTileNumber(jpeg2000), 0x2233);
    assert_int_equal(read_quadlet(pdu, 0), 0xEB112233);

    Avtp_Jpeg2000_SetFragmentOffset(jpeg2000, 0x123456);
    assert_int_equal(Avtp_Jpeg2000_GetFragmentOffset(jpeg2000), 0x123456);
    assert_int_equal(read_quadlet(pdu, 1), 0x00123456);
}

static void jpeg2000_payload(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t payload[8] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
    Avtp_Jpeg2000_t *jpeg2000 = (Avtp_Jpeg2000_t *)pdu;

    Avtp_Jpeg2000_Init(jpeg2000);
    Avtp_Jpeg2000_SetPayload(jpeg2000, payload, sizeof(payload));

    assert_memory_equal(Avtp_Jpeg2000_GetPayload(jpeg2000), payload, sizeof(payload));
    assert_memory_equal(jpeg2000->payload, payload, sizeof(payload));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(cvf_init),
        cmocka_unit_test(cvf_init_v1),
        cmocka_unit_test(cvf_is_valid),
        cmocka_unit_test(cvf_field_descriptors_cover_header),
        cmocka_unit_test(cvf_common_field_consistency),
        cmocka_unit_test(cvf_flag_fields),
        cmocka_unit_test(cvf_field_layout),
        cmocka_unit_test(cvf_v1_layout),
        cmocka_unit_test(cvf_payload),
        cmocka_unit_test(cvf_get_set_field),
        cmocka_unit_test(mjpeg_init),
        cmocka_unit_test(mjpeg_is_valid),
        cmocka_unit_test(mjpeg_field_descriptors_cover_header),
        cmocka_unit_test(mjpeg_field_layout),
        cmocka_unit_test(mjpeg_payload),
        cmocka_unit_test(h264_init),
        cmocka_unit_test(h264_is_valid),
        cmocka_unit_test(h264_field_descriptors_cover_header),
        cmocka_unit_test(h264_field_layout),
        cmocka_unit_test(h264_payload),
        cmocka_unit_test(jpeg2000_init),
        cmocka_unit_test(jpeg2000_is_valid),
        cmocka_unit_test(jpeg2000_field_descriptors_cover_header),
        cmocka_unit_test(jpeg2000_flag_fields),
        cmocka_unit_test(jpeg2000_field_layout),
        cmocka_unit_test(jpeg2000_payload),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
