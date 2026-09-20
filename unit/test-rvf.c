/*
 *
 * Copyright (c) 2021, Fastree3D
 * Adrian Fiergolski <Adrian.Fiergolski@fastree3d.com>
 * Copyright (c) 2026, COVESA
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
#include "avtp/Rvf.h"

#define MAX_PDU_SIZE 1500

static uint32_t read_quadlet(const uint8_t *pdu, size_t quadlet)
{
    uint32_t word;

    memcpy(&word, pdu + (quadlet * 4), sizeof(word));
    return ntohl(word);
}

static uint64_t mask_field_value(uint8_t bits, uint64_t value)
{
    if (bits == 0) {
        return 0;
    }
    if (bits >= 64) {
        return value;
    }
    return value & ((((uint64_t)1) << bits) - 1);
}

/* Initializes a minimal but valid RVF frame. */
static void init_valid_rvf(Avtp_Rvf_t *pdu)
{
    Avtp_Rvf_Init(pdu);
    Avtp_Rvf_SetStreamDataLength(pdu, AVTP_RVF_RAW_HEADER_LEN);
}

static void rvf_init(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t init_pdu[AVTP_RVF_HEADER_LEN_V0];

    assert_int_equal(sizeof(Avtp_Rvf_t), AVTP_RVF_HEADER_LEN_V0);

    /* Passing a NULL pointer must be a no-op. */
    Avtp_Rvf_Init(NULL);

    Avtp_Rvf_Init((Avtp_Rvf_t *)pdu);
    memset(init_pdu, 0, AVTP_RVF_HEADER_LEN_V0);
    init_pdu[0] = AVTP_SUBTYPE_RVF; /* subtype = RVF */
    init_pdu[1] = 0x80;             /* sv = 1, version = 0 */
    assert_memory_equal(init_pdu, pdu, AVTP_RVF_HEADER_LEN_V0);
}

static void rvf_init_v1(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t init_pdu[AVTP_RVF_HEADER_LEN_V1];

    assert_int_equal(sizeof(Avtp_RvfV1_t), AVTP_RVF_HEADER_LEN_V1);

    /* Passing a NULL pointer must be a no-op. */
    Avtp_Rvf_InitV1(NULL);

    Avtp_Rvf_InitV1((Avtp_RvfV1_t *)pdu);
    memset(init_pdu, 0, AVTP_RVF_HEADER_LEN_V1);
    init_pdu[0] = AVTP_SUBTYPE_RVF; /* subtype = RVF */
    init_pdu[1] = 0x90;             /* sv = 1, version = 1 */
    assert_memory_equal(init_pdu, pdu, AVTP_RVF_HEADER_LEN_V1);

    assert_int_equal(Avtp_Rvf_GetHeaderLen((Avtp_Rvf_t *)pdu), AVTP_RVF_HEADER_LEN_V1);
}

static void rvf_is_valid(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Rvf_t *rvf = (Avtp_Rvf_t *)pdu;

    init_valid_rvf(rvf);
    assert_true(Avtp_Rvf_IsValid(rvf, AVTP_RVF_HEADER_LEN_V0 + AVTP_RVF_RAW_HEADER_LEN));

    /* NULL pdu. */
    assert_false(Avtp_Rvf_IsValid(NULL, MAX_PDU_SIZE));

    /* Not an RVF frame. */
    memset(pdu, 0, MAX_PDU_SIZE);
    assert_false(Avtp_Rvf_IsValid(rvf, MAX_PDU_SIZE));

    /* Buffer smaller than the RVF header. */
    init_valid_rvf(rvf);
    assert_false(Avtp_Rvf_IsValid(rvf, AVTP_RVF_HEADER_LEN_V0 - 1));

    /* The stream data always contains at least the raw header. */
    init_valid_rvf(rvf);
    Avtp_Rvf_SetStreamDataLength(rvf, AVTP_RVF_RAW_HEADER_LEN - 1);
    assert_false(Avtp_Rvf_IsValid(rvf, MAX_PDU_SIZE));

    /* stream_data_length does not fit into the buffer. */
    init_valid_rvf(rvf);
    Avtp_Rvf_SetStreamDataLength(rvf, 16);
    assert_false(Avtp_Rvf_IsValid(rvf, AVTP_RVF_HEADER_LEN_V0 + 15));
    assert_true(Avtp_Rvf_IsValid(rvf, AVTP_RVF_HEADER_LEN_V0 + 16));

    /* Valid version 1 frame. */
    Avtp_Rvf_InitV1((Avtp_RvfV1_t *)pdu);
    Avtp_Rvf_SetStreamDataLength((Avtp_Rvf_t *)pdu, AVTP_RVF_RAW_HEADER_LEN);
    assert_true(
        Avtp_Rvf_IsValid((Avtp_Rvf_t *)pdu, AVTP_RVF_HEADER_LEN_V1 + AVTP_RVF_RAW_HEADER_LEN));
    assert_false(Avtp_Rvf_IsValid((Avtp_Rvf_t *)pdu, AVTP_RVF_HEADER_LEN_V1 - 1));

    /* Unsupported version is rejected. */
    init_valid_rvf(rvf);
    Avtp_CommonHeader_SetVersion((Avtp_CommonHeader_t *)pdu, 2);
    assert_false(Avtp_Rvf_IsValid(rvf, MAX_PDU_SIZE));
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

static void rvf_field_descriptors_cover_header(void **state)
{
    (void)state;

    for (uint8_t version = 0; version <= 1; version++) {
        uint8_t coverage[AVTP_RVF_HEADER_LEN_V1 * 8] = {0};
        size_t coverageBits = sizeof(coverage);
        const Avtp_FieldDescriptor_t *rvfDesc =
            version == AVTP_VERSION_1 ? Avtp_RvfFieldDescV1 : Avtp_RvfFieldDescV0;
        size_t headerBits = (version == AVTP_VERSION_1 ? (size_t)AVTP_RVF_HEADER_LEN_V1
                                                       : (size_t)AVTP_RVF_HEADER_LEN_V0) *
                            8;

        mark_descriptors(coverage, coverageBits,
                         &Avtp_CommonHeaderFieldDesc[AVTPDU_COMMON_FIELD_SUBTYPE], 1);
        mark_descriptors(coverage, coverageBits,
                         &Avtp_CommonHeaderFieldDesc[AVTPDU_COMMON_FIELD_VERSION], 1);
        mark_descriptors(coverage, coverageBits, rvfDesc, AVTP_RVF_FIELD_MAX);

        for (size_t bit = 0; bit < coverageBits; bit++) {
            assert_int_equal(coverage[bit], bit < headerBits ? 1 : 0);
        }
    }
}

static void rvf_common_field_consistency(void **state)
{
    (void)state;

    assert_int_equal(AVTP_RVF_FIELD_STREAM_DATA_LENGTH, AVTPDU_CSH_FIELD_STREAM_DATA_LENGTH);

    for (uint8_t version = 0; version <= 1; version++) {
        const Avtp_FieldDescriptor_t *rvfDesc =
            version == AVTP_VERSION_1 ? Avtp_RvfFieldDescV1 : Avtp_RvfFieldDescV0;
        const Avtp_FieldDescriptor_t *cshDesc =
            version == AVTP_VERSION_1 ? Avtp_CshFieldDescV1 : Avtp_CshFieldDescV0;

        for (uint8_t i = 0; i < AVTPDU_CSH_FIELD_MAX; i++) {
            assert_int_equal(rvfDesc[i].quadlet, cshDesc[i].quadlet);
            assert_int_equal(rvfDesc[i].offset, cshDesc[i].offset);
            assert_int_equal(rvfDesc[i].bits, cshDesc[i].bits);
        }
    }
}

static void rvf_flag_fields(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Rvf_t *rvf = (Avtp_Rvf_t *)pdu;

    Avtp_Rvf_Init(rvf);
    assert_true(Avtp_Rvf_IsSv(rvf));

    Avtp_Rvf_SetSv(rvf, false);
    assert_false(Avtp_Rvf_IsSv(rvf));

    Avtp_Rvf_SetMr(rvf, true);
    assert_true(Avtp_Rvf_IsMr(rvf));
    Avtp_Rvf_SetMr(rvf, false);
    assert_false(Avtp_Rvf_IsMr(rvf));

    Avtp_Rvf_SetTv(rvf, true);
    assert_true(Avtp_Rvf_IsTv(rvf));
    Avtp_Rvf_SetTv(rvf, false);
    assert_false(Avtp_Rvf_IsTv(rvf));

    Avtp_Rvf_SetTu(rvf, true);
    assert_true(Avtp_Rvf_IsTu(rvf));
    Avtp_Rvf_SetTu(rvf, false);
    assert_false(Avtp_Rvf_IsTu(rvf));

    Avtp_Rvf_SetAp(rvf, true);
    assert_true(Avtp_Rvf_IsAp(rvf));
    Avtp_Rvf_SetAp(rvf, false);
    assert_false(Avtp_Rvf_IsAp(rvf));

    Avtp_Rvf_SetF(rvf, true);
    assert_true(Avtp_Rvf_IsF(rvf));
    Avtp_Rvf_SetF(rvf, false);
    assert_false(Avtp_Rvf_IsF(rvf));

    Avtp_Rvf_SetEf(rvf, true);
    assert_true(Avtp_Rvf_IsEf(rvf));
    Avtp_Rvf_SetEf(rvf, false);
    assert_false(Avtp_Rvf_IsEf(rvf));

    Avtp_Rvf_SetPd(rvf, true);
    assert_true(Avtp_Rvf_IsPd(rvf));
    Avtp_Rvf_SetPd(rvf, false);
    assert_false(Avtp_Rvf_IsPd(rvf));

    Avtp_Rvf_SetI(rvf, true);
    assert_true(Avtp_Rvf_IsI(rvf));
    Avtp_Rvf_SetI(rvf, false);
    assert_false(Avtp_Rvf_IsI(rvf));
}

static void rvf_field_layout(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Rvf_t *rvf = (Avtp_Rvf_t *)pdu;

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Rvf_SetSequenceNum(rvf, 0x55);
    assert_int_equal(Avtp_Rvf_GetSequenceNum(rvf), 0x55);
    assert_int_equal(read_quadlet(pdu, 0), 0x00005500);

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Rvf_SetStreamId(rvf, 0xAABBCCDDEEFF0001);
    assert_int_equal(Avtp_Rvf_GetStreamId(rvf), 0xAABBCCDDEEFF0001);

    Avtp_Rvf_SetAvtpTimestamp(rvf, 0x80C0FFEE);
    assert_int_equal(Avtp_Rvf_GetAvtpTimestamp(rvf), 0x80C0FFEE);
    assert_int_equal(read_quadlet(pdu, 3), 0x80C0FFEE);

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Rvf_SetActivePixels(rvf, 0x20);
    assert_int_equal(Avtp_Rvf_GetActivePixels(rvf), 0x20);
    assert_int_equal(read_quadlet(pdu, 4), 0x00200000);

    Avtp_Rvf_SetTotalLines(rvf, 0x3C);
    assert_int_equal(Avtp_Rvf_GetTotalLines(rvf), 0x3C);
    assert_int_equal(read_quadlet(pdu, 4), 0x0020003C);

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Rvf_SetStreamDataLength(rvf, 0xAAAA);
    assert_int_equal(Avtp_Rvf_GetStreamDataLength(rvf), 0xAAAA);
    assert_int_equal(read_quadlet(pdu, 5), 0xAAAA0000);

    Avtp_Rvf_SetAp(rvf, true);
    assert_true(Avtp_Rvf_IsAp(rvf));
    assert_int_equal(read_quadlet(pdu, 5), 0xAAAA8000);

    Avtp_Rvf_SetF(rvf, true);
    assert_true(Avtp_Rvf_IsF(rvf));
    assert_int_equal(read_quadlet(pdu, 5), 0xAAAAA000);

    Avtp_Rvf_SetEf(rvf, true);
    assert_true(Avtp_Rvf_IsEf(rvf));
    assert_int_equal(read_quadlet(pdu, 5), 0xAAAAB000);

    Avtp_Rvf_SetEvt(rvf, 0xA);
    assert_int_equal(Avtp_Rvf_GetEvt(rvf), 0xA);
    assert_int_equal(read_quadlet(pdu, 5), 0xAAAABA00);

    Avtp_Rvf_SetPd(rvf, true);
    assert_true(Avtp_Rvf_IsPd(rvf));
    assert_int_equal(read_quadlet(pdu, 5), 0xAAAABA80);

    Avtp_Rvf_SetI(rvf, true);
    assert_true(Avtp_Rvf_IsI(rvf));
    assert_int_equal(read_quadlet(pdu, 5), 0xAAAABAC0);

    /* ptp_grandmaster_identity does not exist in version 0. */
    assert_int_equal(Avtp_Rvf_GetPtpGrandmasterIdentity(rvf), 0);
}

static void rvf_v1_layout(void **state)
{
    (void)state;
    uint8_t pdu[AVTP_RVF_HEADER_LEN_V1];
    Avtp_Rvf_t *rvf = (Avtp_Rvf_t *)pdu;

    Avtp_Rvf_InitV1((Avtp_RvfV1_t *)pdu);

    Avtp_Rvf_SetSequenceNum(rvf, 0x12345678);
    assert_int_equal(Avtp_Rvf_GetSequenceNum(rvf), 0x12345678);
    assert_int_equal(read_quadlet(pdu, 3), 0x12345678);

    Avtp_Rvf_SetAvtpTimestamp(rvf, 0x1122334455667788ULL);
    assert_int_equal(Avtp_Rvf_GetAvtpTimestamp(rvf), 0x1122334455667788ULL);
    assert_int_equal(read_quadlet(pdu, 4), 0x11223344);
    assert_int_equal(read_quadlet(pdu, 5), 0x55667788);

    Avtp_Rvf_SetPtpGrandmasterIdentity(rvf, 0x99AABBCCDDEEFF00ULL);
    assert_int_equal(Avtp_Rvf_GetPtpGrandmasterIdentity(rvf), 0x99AABBCCDDEEFF00ULL);
    assert_int_equal(read_quadlet(pdu, 6), 0x99AABBCC);
    assert_int_equal(read_quadlet(pdu, 7), 0xDDEEFF00);

    Avtp_Rvf_SetActivePixels(rvf, 0x20);
    Avtp_Rvf_SetTotalLines(rvf, 0x3C);
    assert_int_equal(read_quadlet(pdu, 8), 0x0020003C);

    Avtp_Rvf_SetStreamDataLength(rvf, 0xAAAA);
    Avtp_Rvf_SetAp(rvf, true);
    Avtp_Rvf_SetF(rvf, true);
    Avtp_Rvf_SetEf(rvf, true);
    Avtp_Rvf_SetEvt(rvf, 0xA);
    Avtp_Rvf_SetPd(rvf, true);
    Avtp_Rvf_SetI(rvf, true);
    assert_int_equal(read_quadlet(pdu, 9), 0xAAAABAC0);
}

static void rvf_payload(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t payload[12] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
    uint8_t payload_out[12] = {0};
    Avtp_Rvf_t *rvf = (Avtp_Rvf_t *)pdu;

    Avtp_Rvf_Init(rvf);
    Avtp_Rvf_SetPayload(rvf, payload, sizeof(payload));

    assert_ptr_equal(Avtp_Rvf_GetPayload(rvf), pdu + AVTP_RVF_HEADER_LEN_V0);
    assert_memory_equal(pdu + AVTP_RVF_HEADER_LEN_V0, payload, sizeof(payload));

    memcpy(payload_out, Avtp_Rvf_GetPayload(rvf), sizeof(payload_out));
    assert_memory_equal(payload_out, payload, sizeof(payload_out));

    /* Version 1 payload starts after the 40-octet header. */
    Avtp_Rvf_InitV1((Avtp_RvfV1_t *)pdu);
    Avtp_Rvf_SetPayload((Avtp_Rvf_t *)pdu, payload, sizeof(payload));
    assert_ptr_equal(Avtp_Rvf_GetPayload((Avtp_Rvf_t *)pdu), pdu + AVTP_RVF_HEADER_LEN_V1);
    assert_memory_equal(pdu + AVTP_RVF_HEADER_LEN_V1, payload, sizeof(payload));
}

static void rvf_get_set_field(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Rvf_t *rvf = (Avtp_Rvf_t *)pdu;

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Rvf_SetField(rvf, AVTP_RVF_FIELD_SEQUENCE_NUM, 0xAA);
    assert_int_equal(Avtp_Rvf_GetField(rvf, AVTP_RVF_FIELD_SEQUENCE_NUM), 0xAA);

    /* Reserved fields are reachable through the generic access engine. */
    Avtp_Rvf_SetField(rvf, AVTP_RVF_FIELD_FSD, 0x3);
    assert_int_equal(Avtp_Rvf_GetField(rvf, AVTP_RVF_FIELD_FSD), 0x3);

    Avtp_Rvf_SetField(rvf, AVTP_RVF_FIELD_FSD1, 0x5A);
    assert_int_equal(Avtp_Rvf_GetField(rvf, AVTP_RVF_FIELD_FSD1), 0x5A);
}

static void rvf_raw_header_init(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t init_pdu[AVTP_RVF_RAW_HEADER_LEN];

    assert_int_equal(sizeof(Avtp_RvfRawHeader_t), AVTP_RVF_RAW_HEADER_LEN);

    /* Passing a NULL pointer must be a no-op. */
    Avtp_RvfRawHeader_Init(NULL);

    memset(pdu, 0xFF, MAX_PDU_SIZE);
    Avtp_RvfRawHeader_Init((Avtp_RvfRawHeader_t *)pdu);
    memset(init_pdu, 0, AVTP_RVF_RAW_HEADER_LEN);
    assert_memory_equal(init_pdu, pdu, AVTP_RVF_RAW_HEADER_LEN);
}

static void rvf_raw_header_is_valid(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_RvfRawHeader_t *raw = (Avtp_RvfRawHeader_t *)pdu;

    memset(pdu, 0, MAX_PDU_SIZE);

    assert_true(Avtp_RvfRawHeader_IsValid(raw, AVTP_RVF_RAW_HEADER_LEN));
    assert_true(Avtp_RvfRawHeader_IsValid(raw, MAX_PDU_SIZE));
    assert_false(Avtp_RvfRawHeader_IsValid(raw, AVTP_RVF_RAW_HEADER_LEN - 1));
    assert_false(Avtp_RvfRawHeader_IsValid(NULL, MAX_PDU_SIZE));
}

static void rvf_raw_header_field_descriptors_cover_header(void **state)
{
    (void)state;
    uint8_t coverage[AVTP_RVF_RAW_HEADER_LEN * 8] = {0};

    /* Every bit of the raw header must be described exactly once. */
    for (uint8_t i = 0; i < AVTP_RVF_RAW_HEADER_FIELD_MAX; i++) {
        uint8_t quadlet = Avtp_RvfRawHeaderFieldDesc[i].quadlet;
        uint8_t offset = Avtp_RvfRawHeaderFieldDesc[i].offset;
        uint8_t bits = Avtp_RvfRawHeaderFieldDesc[i].bits;

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

static void rvf_raw_header_field_layout(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_RvfRawHeader_t *raw = (Avtp_RvfRawHeader_t *)pdu;

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_RvfRawHeader_SetPixelDepth(raw, AVTP_RVF_PIXEL_DEPTH_16);
    assert_int_equal(Avtp_RvfRawHeader_GetPixelDepth(raw), AVTP_RVF_PIXEL_DEPTH_16);
    assert_int_equal(read_quadlet(pdu, 0), 0x00400000);

    Avtp_RvfRawHeader_SetPixelFormat(raw, AVTP_RVF_PIXEL_FORMAT_422);
    assert_int_equal(Avtp_RvfRawHeader_GetPixelFormat(raw), AVTP_RVF_PIXEL_FORMAT_422);
    assert_int_equal(read_quadlet(pdu, 0), 0x00430000);

    Avtp_RvfRawHeader_SetFrameRate(raw, AVTP_RVF_FRAME_RATE_30);
    assert_int_equal(Avtp_RvfRawHeader_GetFrameRate(raw), AVTP_RVF_FRAME_RATE_30);
    assert_int_equal(read_quadlet(pdu, 0), 0x00431500);

    Avtp_RvfRawHeader_SetColorspace(raw, AVTP_RVF_COLORSPACE_GRAY);
    assert_int_equal(Avtp_RvfRawHeader_GetColorspace(raw), AVTP_RVF_COLORSPACE_GRAY);
    assert_int_equal(read_quadlet(pdu, 0), 0x00431540);

    Avtp_RvfRawHeader_SetNumLines(raw, 0x05);
    assert_int_equal(Avtp_RvfRawHeader_GetNumLines(raw), 0x05);
    assert_int_equal(read_quadlet(pdu, 0), 0x00431545);

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_RvfRawHeader_SetISeqNum(raw, 0x03);
    assert_int_equal(Avtp_RvfRawHeader_GetISeqNum(raw), 0x03);
    assert_int_equal(read_quadlet(pdu, 1), 0x00030000);

    Avtp_RvfRawHeader_SetLineNumber(raw, 0x0123);
    assert_int_equal(Avtp_RvfRawHeader_GetLineNumber(raw), 0x0123);
    assert_int_equal(read_quadlet(pdu, 1), 0x00030123);
}

static void rvf_raw_header_payload(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t payload[8] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
    uint8_t payload_out[8] = {0};
    Avtp_RvfRawHeader_t *raw = (Avtp_RvfRawHeader_t *)pdu;

    Avtp_RvfRawHeader_Init(raw);
    Avtp_RvfRawHeader_SetPayload(raw, payload, sizeof(payload));

    assert_memory_equal(Avtp_RvfRawHeader_GetPayload(raw), payload, sizeof(payload));
    assert_memory_equal(raw->payload, payload, sizeof(payload));

    memcpy(payload_out, Avtp_RvfRawHeader_GetPayload(raw), sizeof(payload_out));
    assert_memory_equal(payload_out, payload, sizeof(payload_out));
}

static void rvf_raw_header_get_set_field(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_RvfRawHeader_t *raw = (Avtp_RvfRawHeader_t *)pdu;

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_RvfRawHeader_SetField(raw, AVTP_RVF_RAW_HEADER_FIELD_PIXEL_DEPTH, 0x4);
    assert_int_equal(Avtp_RvfRawHeader_GetField(raw, AVTP_RVF_RAW_HEADER_FIELD_PIXEL_DEPTH), 0x4);

    /* Reserved fields are reachable through the generic access engine. */
    Avtp_RvfRawHeader_SetField(raw, AVTP_RVF_RAW_HEADER_FIELD_RESERVED1, 0xAB);
    assert_int_equal(Avtp_RvfRawHeader_GetField(raw, AVTP_RVF_RAW_HEADER_FIELD_RESERVED1), 0xAB);

    Avtp_RvfRawHeader_SetField(raw, AVTP_RVF_RAW_HEADER_FIELD_RESERVED2, 0xCD);
    assert_int_equal(Avtp_RvfRawHeader_GetField(raw, AVTP_RVF_RAW_HEADER_FIELD_RESERVED2), 0xCD);
}

/* The raw header lives in the stream data of the enclosing RVF PDU. */
static void rvf_raw_header_overlay(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Rvf_t *rvf = (Avtp_Rvf_t *)pdu;
    Avtp_RvfRawHeader_t *raw = (Avtp_RvfRawHeader_t *)rvf->payload;

    Avtp_Rvf_Init(rvf);
    Avtp_Rvf_SetStreamDataLength(rvf, AVTP_RVF_RAW_HEADER_LEN);
    Avtp_RvfRawHeader_Init(raw);

    Avtp_RvfRawHeader_SetPixelDepth(raw, AVTP_RVF_PIXEL_DEPTH_8);
    assert_int_equal(Avtp_RvfRawHeader_GetPixelDepth(raw), AVTP_RVF_PIXEL_DEPTH_8);

    assert_true(Avtp_Rvf_IsValid(rvf, AVTP_RVF_HEADER_LEN_V0 + AVTP_RVF_RAW_HEADER_LEN));
}

static void rvf_typed_fields_v0(void **state)
{
    (void)state;
    uint8_t pdu[AVTP_RVF_HEADER_LEN_V1];
    Avtp_Rvf_t *rvf = (Avtp_Rvf_t *)pdu;

    Avtp_Rvf_Init(rvf);

    for (uint8_t f = 0; f < AVTP_RVF_FIELD_MAX; f++) {
        uint8_t bits = Avtp_RvfFieldDescV0[f].bits;
        uint64_t value = 0xA5A5A5A5A5A5A5A5ULL ^ (uint64_t)f;
        uint64_t expected = mask_field_value(bits, value);
        Avtp_RvfFields_t field = (Avtp_RvfFields_t)f;

        Avtp_Rvf_SetField_V0(rvf, field, value);
        assert_int_equal(Avtp_Rvf_GetField_V0(rvf, field), expected);
        assert_int_equal(Avtp_Rvf_GetField(rvf, field), expected);
        assert_int_equal(Avtp_GetField(Avtp_RvfFieldDescV0, AVTP_RVF_FIELD_MAX, pdu, f), expected);
    }
}

static void rvf_typed_fields_v1(void **state)
{
    (void)state;
    uint8_t pdu[AVTP_RVF_HEADER_LEN_V1];
    Avtp_RvfV1_t *rvf = (Avtp_RvfV1_t *)pdu;

    Avtp_Rvf_InitV1(rvf);

    for (uint8_t f = 0; f < AVTP_RVF_FIELD_MAX; f++) {
        uint8_t bits = Avtp_RvfFieldDescV1[f].bits;
        uint64_t value = 0x5A5A5A5A5A5A5A5AULL ^ (uint64_t)f;
        uint64_t expected = mask_field_value(bits, value);
        Avtp_RvfFields_t field = (Avtp_RvfFields_t)f;

        Avtp_Rvf_SetField_V1(rvf, field, value);
        assert_int_equal(Avtp_Rvf_GetField_V1(rvf, field), expected);
        assert_int_equal(Avtp_Rvf_GetField((Avtp_Rvf_t *)rvf, field), expected);
        assert_int_equal(Avtp_GetField(Avtp_RvfFieldDescV1, AVTP_RVF_FIELD_MAX, pdu, f), expected);
    }
}

static void rvf_typed_named(void **state)
{
    (void)state;
    uint8_t pdu[AVTP_RVF_HEADER_LEN_V1];
    Avtp_Rvf_t *v0 = (Avtp_Rvf_t *)pdu;
    Avtp_RvfV1_t *v1 = (Avtp_RvfV1_t *)pdu;

    /* Version 0. */
    Avtp_Rvf_Init(v0);
    Avtp_Rvf_SetSv_V0(v0, true);
    Avtp_Rvf_SetSequenceNum_V0(v0, 0x55);
    Avtp_Rvf_SetStreamId_V0(v0, 0xAABBCCDDEEFF0001ULL);
    Avtp_Rvf_SetAvtpTimestamp_V0(v0, 0x80C0FFEE);
    Avtp_Rvf_SetStreamDataLength_V0(v0, 0xAAAA);
    Avtp_Rvf_SetActivePixels_V0(v0, 1920);
    Avtp_Rvf_SetTotalLines_V0(v0, 1080);
    Avtp_Rvf_SetAp_V0(v0, true);
    Avtp_Rvf_SetF_V0(v0, true);
    Avtp_Rvf_SetEf_V0(v0, true);
    Avtp_Rvf_SetEvt_V0(v0, 0xA);
    Avtp_Rvf_SetPd_V0(v0, true);
    Avtp_Rvf_SetI_V0(v0, true);

    assert_true(Avtp_Rvf_IsSv_V0(v0));
    assert_int_equal(Avtp_Rvf_GetSequenceNum_V0(v0), 0x55);
    assert_int_equal(Avtp_Rvf_GetStreamId_V0(v0), 0xAABBCCDDEEFF0001ULL);
    assert_int_equal(Avtp_Rvf_GetAvtpTimestamp_V0(v0), 0x80C0FFEE);
    assert_int_equal(Avtp_Rvf_GetStreamDataLength_V0(v0), 0xAAAA);
    assert_int_equal(Avtp_Rvf_GetActivePixels_V0(v0), 1920);
    assert_int_equal(Avtp_Rvf_GetTotalLines_V0(v0), 1080);
    assert_true(Avtp_Rvf_IsAp_V0(v0));
    assert_true(Avtp_Rvf_IsF_V0(v0));
    assert_true(Avtp_Rvf_IsEf_V0(v0));
    assert_int_equal(Avtp_Rvf_GetEvt_V0(v0), 0xA);
    assert_true(Avtp_Rvf_IsPd_V0(v0));
    assert_true(Avtp_Rvf_IsI_V0(v0));
    assert_int_equal(Avtp_Rvf_GetPtpGrandmasterIdentity_V0(v0), 0);

    /* The version-dispatched accessors agree with the version 0 variants. */
    assert_int_equal(Avtp_Rvf_GetSequenceNum(v0), Avtp_Rvf_GetSequenceNum_V0(v0));
    assert_int_equal(Avtp_Rvf_GetStreamId(v0), Avtp_Rvf_GetStreamId_V0(v0));
    assert_int_equal(Avtp_Rvf_GetAvtpTimestamp(v0), Avtp_Rvf_GetAvtpTimestamp_V0(v0));
    assert_int_equal(Avtp_Rvf_GetStreamDataLength(v0), Avtp_Rvf_GetStreamDataLength_V0(v0));
    assert_int_equal(Avtp_Rvf_GetActivePixels(v0), Avtp_Rvf_GetActivePixels_V0(v0));
    assert_int_equal(Avtp_Rvf_GetTotalLines(v0), Avtp_Rvf_GetTotalLines_V0(v0));
    assert_int_equal(Avtp_Rvf_GetEvt(v0), Avtp_Rvf_GetEvt_V0(v0));

    /* Version 1. */
    Avtp_Rvf_InitV1(v1);
    Avtp_Rvf_SetSv_V1(v1, true);
    Avtp_Rvf_SetSequenceNum_V1(v1, 0x12345678);
    Avtp_Rvf_SetStreamId_V1(v1, 0x0102030405060708ULL);
    Avtp_Rvf_SetAvtpTimestamp_V1(v1, 0x1122334455667788ULL);
    Avtp_Rvf_SetPtpGrandmasterIdentity_V1(v1, 0x99AABBCCDDEEFF00ULL);
    Avtp_Rvf_SetStreamDataLength_V1(v1, 0xBBBB);
    Avtp_Rvf_SetActivePixels_V1(v1, 1280);
    Avtp_Rvf_SetTotalLines_V1(v1, 720);
    Avtp_Rvf_SetAp_V1(v1, true);
    Avtp_Rvf_SetF_V1(v1, true);
    Avtp_Rvf_SetEf_V1(v1, true);
    Avtp_Rvf_SetEvt_V1(v1, 0xB);
    Avtp_Rvf_SetPd_V1(v1, true);
    Avtp_Rvf_SetI_V1(v1, true);

    assert_true(Avtp_Rvf_IsSv_V1(v1));
    assert_int_equal(Avtp_Rvf_GetSequenceNum_V1(v1), 0x12345678);
    assert_int_equal(Avtp_Rvf_GetStreamId_V1(v1), 0x0102030405060708ULL);
    assert_int_equal(Avtp_Rvf_GetAvtpTimestamp_V1(v1), 0x1122334455667788ULL);
    assert_int_equal(Avtp_Rvf_GetPtpGrandmasterIdentity_V1(v1), 0x99AABBCCDDEEFF00ULL);
    assert_int_equal(Avtp_Rvf_GetStreamDataLength_V1(v1), 0xBBBB);
    assert_int_equal(Avtp_Rvf_GetActivePixels_V1(v1), 1280);
    assert_int_equal(Avtp_Rvf_GetTotalLines_V1(v1), 720);
    assert_true(Avtp_Rvf_IsAp_V1(v1));
    assert_true(Avtp_Rvf_IsF_V1(v1));
    assert_true(Avtp_Rvf_IsEf_V1(v1));
    assert_int_equal(Avtp_Rvf_GetEvt_V1(v1), 0xB);
    assert_true(Avtp_Rvf_IsPd_V1(v1));
    assert_true(Avtp_Rvf_IsI_V1(v1));

    /* The version-dispatched accessors agree with the version 1 variants. */
    assert_int_equal(Avtp_Rvf_GetSequenceNum(v0), Avtp_Rvf_GetSequenceNum_V1(v1));
    assert_int_equal(Avtp_Rvf_GetStreamId(v0), Avtp_Rvf_GetStreamId_V1(v1));
    assert_int_equal(Avtp_Rvf_GetAvtpTimestamp(v0), Avtp_Rvf_GetAvtpTimestamp_V1(v1));
    assert_int_equal(Avtp_Rvf_GetPtpGrandmasterIdentity(v0),
                     Avtp_Rvf_GetPtpGrandmasterIdentity_V1(v1));
    assert_int_equal(Avtp_Rvf_GetStreamDataLength(v0), Avtp_Rvf_GetStreamDataLength_V1(v1));
    assert_int_equal(Avtp_Rvf_GetActivePixels(v0), Avtp_Rvf_GetActivePixels_V1(v1));
    assert_int_equal(Avtp_Rvf_GetTotalLines(v0), Avtp_Rvf_GetTotalLines_V1(v1));
    assert_int_equal(Avtp_Rvf_GetEvt(v0), Avtp_Rvf_GetEvt_V1(v1));
}

static void rvf_typed_helpers(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t payload[8] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};

    Avtp_Rvf_Init((Avtp_Rvf_t *)pdu);
    assert_int_equal(Avtp_Rvf_GetHeaderLen_V0((Avtp_Rvf_t *)pdu), AVTP_RVF_HEADER_LEN_V0);
    assert_ptr_equal(Avtp_Rvf_GetPayload_V0((Avtp_Rvf_t *)pdu), pdu + AVTP_RVF_HEADER_LEN_V0);
    Avtp_Rvf_SetPayload_V0((Avtp_Rvf_t *)pdu, payload, sizeof(payload));
    assert_memory_equal(pdu + AVTP_RVF_HEADER_LEN_V0, payload, sizeof(payload));

    Avtp_Rvf_InitV1((Avtp_RvfV1_t *)pdu);
    assert_int_equal(Avtp_Rvf_GetHeaderLen_V1((Avtp_RvfV1_t *)pdu), AVTP_RVF_HEADER_LEN_V1);
    assert_ptr_equal(Avtp_Rvf_GetPayload_V1((Avtp_RvfV1_t *)pdu), pdu + AVTP_RVF_HEADER_LEN_V1);
    Avtp_Rvf_SetPayload_V1((Avtp_RvfV1_t *)pdu, payload, sizeof(payload));
    assert_memory_equal(pdu + AVTP_RVF_HEADER_LEN_V1, payload, sizeof(payload));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(rvf_init),
        cmocka_unit_test(rvf_init_v1),
        cmocka_unit_test(rvf_is_valid),
        cmocka_unit_test(rvf_field_descriptors_cover_header),
        cmocka_unit_test(rvf_common_field_consistency),
        cmocka_unit_test(rvf_flag_fields),
        cmocka_unit_test(rvf_field_layout),
        cmocka_unit_test(rvf_v1_layout),
        cmocka_unit_test(rvf_payload),
        cmocka_unit_test(rvf_get_set_field),
        cmocka_unit_test(rvf_raw_header_init),
        cmocka_unit_test(rvf_raw_header_is_valid),
        cmocka_unit_test(rvf_raw_header_field_descriptors_cover_header),
        cmocka_unit_test(rvf_raw_header_field_layout),
        cmocka_unit_test(rvf_raw_header_payload),
        cmocka_unit_test(rvf_raw_header_get_set_field),
        cmocka_unit_test(rvf_typed_fields_v0),
        cmocka_unit_test(rvf_typed_fields_v1),
        cmocka_unit_test(rvf_typed_named),
        cmocka_unit_test(rvf_typed_helpers),
        cmocka_unit_test(rvf_raw_header_overlay),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
