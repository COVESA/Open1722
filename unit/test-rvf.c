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
#include "avtp/Rvf.h"

#define MAX_PDU_SIZE 1500

static uint32_t read_quadlet(const uint8_t *pdu, size_t quadlet)
{
    uint32_t word;

    memcpy(&word, pdu + (quadlet * 4), sizeof(word));
    return ntohl(word);
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
    uint8_t init_pdu[AVTP_RVF_HEADER_LEN];

    assert_int_equal(sizeof(Avtp_Rvf_t), AVTP_RVF_HEADER_LEN);

    /* Passing a NULL pointer must be a no-op. */
    Avtp_Rvf_Init(NULL);

    Avtp_Rvf_Init((Avtp_Rvf_t *)pdu);
    memset(init_pdu, 0, AVTP_RVF_HEADER_LEN);
    init_pdu[0] = AVTP_SUBTYPE_RVF; /* subtype = RVF */
    init_pdu[1] = 0x80;             /* sv = 1 */
    assert_memory_equal(init_pdu, pdu, AVTP_RVF_HEADER_LEN);
}

static void rvf_is_valid(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Rvf_t *rvf = (Avtp_Rvf_t *)pdu;

    init_valid_rvf(rvf);
    assert_true(Avtp_Rvf_IsValid(rvf, AVTP_RVF_HEADER_LEN + AVTP_RVF_RAW_HEADER_LEN));

    /* NULL pdu. */
    assert_false(Avtp_Rvf_IsValid(NULL, MAX_PDU_SIZE));

    /* Not an RVF frame. */
    memset(pdu, 0, MAX_PDU_SIZE);
    assert_false(Avtp_Rvf_IsValid(rvf, MAX_PDU_SIZE));

    /* Buffer smaller than the RVF header. */
    init_valid_rvf(rvf);
    assert_false(Avtp_Rvf_IsValid(rvf, AVTP_RVF_HEADER_LEN - 1));

    /* The stream data always contains at least the raw header. */
    init_valid_rvf(rvf);
    Avtp_Rvf_SetStreamDataLength(rvf, AVTP_RVF_RAW_HEADER_LEN - 1);
    assert_false(Avtp_Rvf_IsValid(rvf, MAX_PDU_SIZE));

    /* stream_data_length does not fit into the buffer. */
    init_valid_rvf(rvf);
    Avtp_Rvf_SetStreamDataLength(rvf, 16);
    assert_false(Avtp_Rvf_IsValid(rvf, AVTP_RVF_HEADER_LEN + 15));
    assert_true(Avtp_Rvf_IsValid(rvf, AVTP_RVF_HEADER_LEN + 16));
}

static void rvf_field_descriptors_cover_header(void **state)
{
    (void)state;
    uint8_t coverage[AVTP_RVF_HEADER_LEN * 8] = {0};

    /* Every bit of the header must be described exactly once. */
    for (uint8_t i = 0; i < AVTP_RVF_FIELD_MAX; i++) {
        uint8_t quadlet = Avtp_RvfFieldDesc[i].quadlet;
        uint8_t offset = Avtp_RvfFieldDesc[i].offset;
        uint8_t bits = Avtp_RvfFieldDesc[i].bits;

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

    assert_memory_equal(Avtp_Rvf_GetPayload(rvf), payload, sizeof(payload));
    assert_memory_equal(rvf->payload, payload, sizeof(payload));

    memcpy(payload_out, Avtp_Rvf_GetPayload(rvf), sizeof(payload_out));
    assert_memory_equal(payload_out, payload, sizeof(payload_out));
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
    Avtp_Rvf_SetField(rvf, AVTP_RVF_FIELD_RSV, 0x3);
    assert_int_equal(Avtp_Rvf_GetField(rvf, AVTP_RVF_FIELD_RSV), 0x3);

    Avtp_Rvf_SetField(rvf, AVTP_RVF_FIELD_RESERVED1, 0x5A);
    assert_int_equal(Avtp_Rvf_GetField(rvf, AVTP_RVF_FIELD_RESERVED1), 0x5A);
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

    assert_true(Avtp_Rvf_IsValid(rvf, AVTP_RVF_HEADER_LEN + AVTP_RVF_RAW_HEADER_LEN));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(rvf_init),
        cmocka_unit_test(rvf_is_valid),
        cmocka_unit_test(rvf_field_descriptors_cover_header),
        cmocka_unit_test(rvf_flag_fields),
        cmocka_unit_test(rvf_field_layout),
        cmocka_unit_test(rvf_payload),
        cmocka_unit_test(rvf_get_set_field),
        cmocka_unit_test(rvf_raw_header_init),
        cmocka_unit_test(rvf_raw_header_is_valid),
        cmocka_unit_test(rvf_raw_header_field_descriptors_cover_header),
        cmocka_unit_test(rvf_raw_header_field_layout),
        cmocka_unit_test(rvf_raw_header_payload),
        cmocka_unit_test(rvf_raw_header_get_set_field),
        cmocka_unit_test(rvf_raw_header_overlay),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
