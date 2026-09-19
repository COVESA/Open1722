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
#include "avtp/AlternativeHeader.h"
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
    uint8_t init_pdu[AVTP_CRF_HEADER_LEN_V0];

    assert_int_equal(sizeof(Avtp_Crf_t), AVTP_CRF_HEADER_LEN_V0);

    /* Passing a NULL pointer must be a no-op. */
    Avtp_Crf_Init(NULL);

    Avtp_Crf_Init((Avtp_Crf_t *)pdu);
    memset(init_pdu, 0, AVTP_CRF_HEADER_LEN_V0);
    init_pdu[0] = AVTP_SUBTYPE_CRF; /* subtype = CRF */
    init_pdu[1] = 0x80;             /* sv = 1, version = 0 */
    assert_memory_equal(init_pdu, pdu, AVTP_CRF_HEADER_LEN_V0);
}

static void crf_init_v1(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t init_pdu[AVTP_CRF_HEADER_LEN_V1];

    assert_int_equal(sizeof(Avtp_CrfV1_t), AVTP_CRF_HEADER_LEN_V1);

    /* Passing a NULL pointer must be a no-op. */
    Avtp_Crf_InitV1(NULL);

    Avtp_Crf_InitV1((Avtp_CrfV1_t *)pdu);
    memset(init_pdu, 0, AVTP_CRF_HEADER_LEN_V1);
    init_pdu[0] = AVTP_SUBTYPE_CRF; /* subtype = CRF */
    init_pdu[1] = 0x90;             /* sv = 1, version = 1 */
    assert_memory_equal(init_pdu, pdu, AVTP_CRF_HEADER_LEN_V1);

    assert_int_equal(Avtp_Crf_GetHeaderLen((Avtp_Crf_t *)pdu), AVTP_CRF_HEADER_LEN_V1);
}

static void crf_is_valid(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Crf_t *crf = (Avtp_Crf_t *)pdu;

    init_valid_crf(crf);
    assert_true(Avtp_Crf_IsValid(crf, AVTP_CRF_HEADER_LEN_V0 + 8));

    /* NULL pdu. */
    assert_false(Avtp_Crf_IsValid(NULL, MAX_PDU_SIZE));

    /* Not a CRF frame. */
    memset(pdu, 0, MAX_PDU_SIZE);
    assert_false(Avtp_Crf_IsValid(crf, MAX_PDU_SIZE));

    /* Buffer smaller than the CRF header. */
    init_valid_crf(crf);
    assert_false(Avtp_Crf_IsValid(crf, AVTP_CRF_HEADER_LEN_V0 - 1));

    /* crf_data_length shall be a non-zero multiple of 8. */
    init_valid_crf(crf);
    Avtp_Crf_SetCrfDataLength(crf, 0);
    assert_false(Avtp_Crf_IsValid(crf, AVTP_CRF_HEADER_LEN_V0));
    Avtp_Crf_SetCrfDataLength(crf, 7);
    assert_false(Avtp_Crf_IsValid(crf, AVTP_CRF_HEADER_LEN_V0 + 8));

    /* crf_data_length does not fit into the buffer. */
    init_valid_crf(crf);
    Avtp_Crf_SetCrfDataLength(crf, 16);
    assert_false(Avtp_Crf_IsValid(crf, AVTP_CRF_HEADER_LEN_V0 + 15));
    assert_true(Avtp_Crf_IsValid(crf, AVTP_CRF_HEADER_LEN_V0 + 16));

    /* Valid version 1 frame. */
    Avtp_Crf_InitV1((Avtp_CrfV1_t *)pdu);
    Avtp_Crf_SetCrfDataLength((Avtp_Crf_t *)pdu, 8);
    assert_true(Avtp_Crf_IsValid((Avtp_Crf_t *)pdu, AVTP_CRF_HEADER_LEN_V1 + 8));
    assert_false(Avtp_Crf_IsValid((Avtp_Crf_t *)pdu, AVTP_CRF_HEADER_LEN_V1 + 7));
    assert_false(Avtp_Crf_IsValid((Avtp_Crf_t *)pdu, AVTP_CRF_HEADER_LEN_V1 - 1));

    /* Unsupported version is rejected. */
    init_valid_crf(crf);
    Avtp_CommonHeader_SetVersion((Avtp_CommonHeader_t *)pdu, 2);
    assert_false(Avtp_Crf_IsValid(crf, MAX_PDU_SIZE));
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

static void crf_field_descriptors_cover_header(void **state)
{
    (void)state;

    for (uint8_t version = 0; version <= 1; version++) {
        uint8_t coverage[AVTP_CRF_HEADER_LEN_V1 * 8] = {0};
        size_t coverageBits = sizeof(coverage);
        const Avtp_FieldDescriptor_t *crfDesc =
            version == AVTP_VERSION_1 ? Avtp_CrfFieldDescV1 : Avtp_CrfFieldDescV0;
        size_t headerBits = (version == AVTP_VERSION_1 ? (size_t)AVTP_CRF_HEADER_LEN_V1
                                                       : (size_t)AVTP_CRF_HEADER_LEN_V0) *
                            8;

        /* subtype and version are owned by the common header; h/sv is covered
         * by the format table. */
        mark_descriptors(coverage, coverageBits,
                         &Avtp_CommonHeaderFieldDesc[AVTPDU_COMMON_FIELD_SUBTYPE], 1);
        mark_descriptors(coverage, coverageBits,
                         &Avtp_CommonHeaderFieldDesc[AVTPDU_COMMON_FIELD_VERSION], 1);
        mark_descriptors(coverage, coverageBits, crfDesc, AVTP_CRF_FIELD_MAX);

        for (size_t bit = 0; bit < coverageBits; bit++) {
            assert_int_equal(coverage[bit], bit < headerBits ? 1 : 0);
        }
    }
}

static void crf_ah_field_consistency(void **state)
{
    (void)state;

    /* The alternative header fields must be declared first and in the same
     * order as in the alternative header module. */
    assert_int_equal(AVTP_CRF_FIELD_PTP_GRANDMASTER_IDENTITY,
                     AVTPDU_AH_FIELD_PTP_GRANDMASTER_IDENTITY);

    for (uint8_t version = 0; version <= 1; version++) {
        const Avtp_FieldDescriptor_t *crfDesc =
            version == AVTP_VERSION_1 ? Avtp_CrfFieldDescV1 : Avtp_CrfFieldDescV0;
        const Avtp_FieldDescriptor_t *ahDesc =
            version == AVTP_VERSION_1 ? Avtp_AhFieldDescV1 : Avtp_AhFieldDescV0;

        for (uint8_t i = 0; i < AVTPDU_AH_FIELD_MAX; i++) {
            assert_int_equal(crfDesc[i].quadlet, ahDesc[i].quadlet);
            assert_int_equal(crfDesc[i].offset, ahDesc[i].offset);
            assert_int_equal(crfDesc[i].bits, ahDesc[i].bits);
        }
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
    assert_int_equal(Avtp_Crf_GetSequenceNumLsb(crf), 0xBB);
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

    /* ptp_grandmaster_identity does not exist in version 0. */
    assert_int_equal(Avtp_Crf_GetPtpGrandmasterIdentity(crf), 0);
}

static void crf_v1_layout(void **state)
{
    (void)state;
    uint8_t pdu[AVTP_CRF_HEADER_LEN_V1];
    Avtp_Crf_t *crf = (Avtp_Crf_t *)pdu;

    Avtp_Crf_InitV1((Avtp_CrfV1_t *)pdu);

    Avtp_Crf_SetSequenceNum(crf, 0x12345678);
    assert_int_equal(Avtp_Crf_GetSequenceNum(crf), 0x12345678);
    assert_int_equal(Avtp_Crf_GetSequenceNumLsb(crf), 0x78);
    assert_int_equal(read_quadlet(pdu, 1), 0x12345678);
    assert_int_equal(pdu[18], 0x78); /* sequence_num_lsb at q4@16 */

    Avtp_Crf_SetPtpGrandmasterIdentity(crf, 0x99AABBCCDDEEFF00ULL);
    assert_int_equal(Avtp_Crf_GetPtpGrandmasterIdentity(crf), 0x99AABBCCDDEEFF00ULL);
    assert_int_equal(read_quadlet(pdu, 2), 0x99AABBCC);
    assert_int_equal(read_quadlet(pdu, 3), 0xDDEEFF00);

    Avtp_Crf_SetType(crf, AVTP_CRF_TYPE_VIDEO_LINE);
    assert_int_equal(Avtp_Crf_GetType(crf), AVTP_CRF_TYPE_VIDEO_LINE);
    assert_int_equal(read_quadlet(pdu, 4), 0x00007803); /* type plus seq_lsb copy */

    Avtp_Crf_SetStreamId(crf, 0x0102030405060708ULL);
    assert_int_equal(Avtp_Crf_GetStreamId(crf), 0x0102030405060708ULL);
    assert_int_equal(read_quadlet(pdu, 5), 0x01020304);
    assert_int_equal(read_quadlet(pdu, 6), 0x05060708);

    Avtp_Crf_SetPull(crf, AVTP_CRF_PULL_MULT_BY_1_001);
    Avtp_Crf_SetBaseFrequency(crf, 0x1FFFFFFF);
    assert_int_equal(read_quadlet(pdu, 7), 0x5FFFFFFF);

    Avtp_Crf_SetCrfDataLength(crf, 0xABCD);
    Avtp_Crf_SetTimestampInterval(crf, 0x1234);
    assert_int_equal(read_quadlet(pdu, 8), 0xABCD1234);
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

    assert_ptr_equal(Avtp_Crf_GetPayload(crf), pdu + AVTP_CRF_HEADER_LEN_V0);
    assert_memory_equal(pdu + AVTP_CRF_HEADER_LEN_V0, payload, sizeof(payload));

    memcpy(payload_out, Avtp_Crf_GetPayload(crf), sizeof(payload_out));
    assert_memory_equal(payload_out, payload, sizeof(payload_out));

    /* Version 1 payload starts after the 36-octet header. */
    Avtp_Crf_InitV1((Avtp_CrfV1_t *)pdu);
    Avtp_Crf_SetPayload((Avtp_Crf_t *)pdu, payload, sizeof(payload));

    assert_ptr_equal(Avtp_Crf_GetPayload((Avtp_Crf_t *)pdu), pdu + AVTP_CRF_HEADER_LEN_V1);
    assert_memory_equal(pdu + AVTP_CRF_HEADER_LEN_V1, payload, sizeof(payload));
}

static void crf_get_set_field(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Crf_t *crf = (Avtp_Crf_t *)pdu;

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Crf_SetField(crf, AVTP_CRF_FIELD_SEQUENCE_NUM_LSB, 0xAA);
    assert_int_equal(Avtp_Crf_GetField(crf, AVTP_CRF_FIELD_SEQUENCE_NUM_LSB), 0xAA);

    /* Reserved fields are reachable through the generic access engine. */
    Avtp_Crf_SetField(crf, AVTP_CRF_FIELD_R, 0x1);
    assert_int_equal(Avtp_Crf_GetField(crf, AVTP_CRF_FIELD_R), 0x1);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(crf_init),
        cmocka_unit_test(crf_init_v1),
        cmocka_unit_test(crf_is_valid),
        cmocka_unit_test(crf_field_descriptors_cover_header),
        cmocka_unit_test(crf_ah_field_consistency),
        cmocka_unit_test(crf_flag_fields),
        cmocka_unit_test(crf_field_layout),
        cmocka_unit_test(crf_v1_layout),
        cmocka_unit_test(crf_payload),
        cmocka_unit_test(crf_get_set_field),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
