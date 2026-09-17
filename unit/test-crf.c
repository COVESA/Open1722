/*
 * Copyright (c) 2018, Intel Corporation
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
#include "avtp/Crf.h"

#define MAX_PDU_SIZE 1500

static uint32_t read_quadlet(const uint8_t *pdu, size_t quadlet)
{
    uint32_t word;

    memcpy(&word, pdu + (quadlet * 4), sizeof(word));
    return ntohl(word);
}

/* Initializes a minimal but valid CRF frame. */
static void init_valid_crf(Avtp_Crf_t *pdu)
{
    Avtp_Crf_Init(pdu);
    Avtp_Crf_SetCrfDataLength(pdu, 8);
    Avtp_Crf_SetTimestampInterval(pdu, 1);
}

static void crf_init(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t init_pdu[AVTP_CRF_HEADER_LEN];

    assert_int_equal(sizeof(Avtp_Crf_t), AVTP_CRF_HEADER_LEN);

    /* Passing a NULL pointer must be a no-op. */
    Avtp_Crf_Init(NULL);

    Avtp_Crf_Init((Avtp_Crf_t *)pdu);
    memset(init_pdu, 0, AVTP_CRF_HEADER_LEN);
    init_pdu[0] = AVTP_SUBTYPE_CRF; /* subtype = CRF */
    init_pdu[1] = 0x80;             /* sv = 1 */
    assert_memory_equal(init_pdu, pdu, AVTP_CRF_HEADER_LEN);
}

static void crf_is_valid(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Crf_t *crf = (Avtp_Crf_t *)pdu;

    init_valid_crf(crf);
    assert_true(Avtp_Crf_IsValid(crf, AVTP_CRF_HEADER_LEN + 8));

    /* NULL pdu. */
    assert_false(Avtp_Crf_IsValid(NULL, MAX_PDU_SIZE));

    /* Not a CRF frame. */
    memset(pdu, 0, MAX_PDU_SIZE);
    assert_false(Avtp_Crf_IsValid(crf, MAX_PDU_SIZE));

    /* Buffer smaller than the CRF header. */
    init_valid_crf(crf);
    assert_false(Avtp_Crf_IsValid(crf, AVTP_CRF_HEADER_LEN - 1));

    /* crf_data_length shall be a non-zero multiple of 8. */
    init_valid_crf(crf);
    Avtp_Crf_SetCrfDataLength(crf, 0);
    assert_false(Avtp_Crf_IsValid(crf, AVTP_CRF_HEADER_LEN));
    Avtp_Crf_SetCrfDataLength(crf, 7);
    assert_false(Avtp_Crf_IsValid(crf, AVTP_CRF_HEADER_LEN + 8));

    /* crf_data_length does not fit into the buffer. */
    init_valid_crf(crf);
    Avtp_Crf_SetCrfDataLength(crf, 16);
    assert_false(Avtp_Crf_IsValid(crf, AVTP_CRF_HEADER_LEN + 15));
    assert_true(Avtp_Crf_IsValid(crf, AVTP_CRF_HEADER_LEN + 16));
}

static void crf_field_descriptors_cover_header(void **state)
{
    (void)state;
    uint8_t coverage[AVTP_CRF_HEADER_LEN * 8] = {0};

    /* Every bit of the header must be described exactly once. */
    for (uint8_t i = 0; i < AVTP_CRF_FIELD_MAX; i++) {
        uint8_t quadlet = Avtp_CrfFieldDesc[i].quadlet;
        uint8_t offset = Avtp_CrfFieldDesc[i].offset;
        uint8_t bits = Avtp_CrfFieldDesc[i].bits;

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

static void crf_flag_fields(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Crf_t *crf = (Avtp_Crf_t *)pdu;

    Avtp_Crf_Init(crf);
    assert_true(Avtp_Crf_IsSv(crf));

    Avtp_Crf_SetSv(crf, false);
    assert_false(Avtp_Crf_IsSv(crf));

    Avtp_Crf_SetMr(crf, true);
    assert_true(Avtp_Crf_IsMr(crf));
    Avtp_Crf_SetMr(crf, false);
    assert_false(Avtp_Crf_IsMr(crf));

    Avtp_Crf_SetFs(crf, true);
    assert_true(Avtp_Crf_IsFs(crf));
    Avtp_Crf_SetFs(crf, false);
    assert_false(Avtp_Crf_IsFs(crf));

    Avtp_Crf_SetTu(crf, true);
    assert_true(Avtp_Crf_IsTu(crf));
    Avtp_Crf_SetTu(crf, false);
    assert_false(Avtp_Crf_IsTu(crf));
}

static void crf_field_layout(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Crf_t *crf = (Avtp_Crf_t *)pdu;

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Crf_SetSequenceNum(crf, 0xBB);
    assert_int_equal(Avtp_Crf_GetSequenceNum(crf), 0xBB);
    assert_int_equal(read_quadlet(pdu, 0), 0x0000BB00);

    Avtp_Crf_SetType(crf, AVTP_CRF_TYPE_VIDEO_LINE);
    assert_int_equal(Avtp_Crf_GetType(crf), AVTP_CRF_TYPE_VIDEO_LINE);
    assert_int_equal(read_quadlet(pdu, 0), 0x0000BB03);

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Crf_SetStreamId(crf, 0xAABBCCDDEEFF0002);
    assert_int_equal(Avtp_Crf_GetStreamId(crf), 0xAABBCCDDEEFF0002);

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Crf_SetPull(crf, AVTP_CRF_PULL_MULT_BY_1_001);
    assert_int_equal(Avtp_Crf_GetPull(crf), AVTP_CRF_PULL_MULT_BY_1_001);
    assert_int_equal(read_quadlet(pdu, 3), 0x40000000);

    Avtp_Crf_SetBaseFrequency(crf, 0x1FFFFFFF);
    assert_int_equal(Avtp_Crf_GetBaseFrequency(crf), 0x1FFFFFFF);
    assert_int_equal(read_quadlet(pdu, 3), 0x5FFFFFFF);

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Crf_SetCrfDataLength(crf, 0xABCD);
    assert_int_equal(Avtp_Crf_GetCrfDataLength(crf), 0xABCD);
    assert_int_equal(read_quadlet(pdu, 4), 0xABCD0000);

    Avtp_Crf_SetTimestampInterval(crf, 0x1234);
    assert_int_equal(Avtp_Crf_GetTimestampInterval(crf), 0x1234);
    assert_int_equal(read_quadlet(pdu, 4), 0xABCD1234);
}

static void crf_payload(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t payload[8] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
    uint8_t payload_out[8] = {0};
    Avtp_Crf_t *crf = (Avtp_Crf_t *)pdu;

    Avtp_Crf_Init(crf);
    Avtp_Crf_SetPayload(crf, payload, sizeof(payload));

    assert_memory_equal(Avtp_Crf_GetPayload(crf), payload, sizeof(payload));
    assert_memory_equal(crf->payload, payload, sizeof(payload));

    memcpy(payload_out, Avtp_Crf_GetPayload(crf), sizeof(payload_out));
    assert_memory_equal(payload_out, payload, sizeof(payload_out));
}

static void crf_get_set_field(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Crf_t *crf = (Avtp_Crf_t *)pdu;

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Crf_SetField(crf, AVTP_CRF_FIELD_SEQUENCE_NUM, 0xAA);
    assert_int_equal(Avtp_Crf_GetField(crf, AVTP_CRF_FIELD_SEQUENCE_NUM), 0xAA);

    /* Reserved fields are reachable through the generic access engine. */
    Avtp_Crf_SetField(crf, AVTP_CRF_FIELD_R, 0x1);
    assert_int_equal(Avtp_Crf_GetField(crf, AVTP_CRF_FIELD_R), 0x1);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(crf_init),
        cmocka_unit_test(crf_is_valid),
        cmocka_unit_test(crf_field_descriptors_cover_header),
        cmocka_unit_test(crf_flag_fields),
        cmocka_unit_test(crf_field_layout),
        cmocka_unit_test(crf_payload),
        cmocka_unit_test(crf_get_set_field),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
