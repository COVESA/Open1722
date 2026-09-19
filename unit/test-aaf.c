/*
 * Copyright (c) 2017, Intel Corporation
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
#include "avtp/aaf/Aaf.h"

#define MAX_PDU_SIZE 1500

static uint32_t read_quadlet(const uint8_t *pdu, size_t quadlet)
{
    uint32_t word;

    memcpy(&word, pdu + (quadlet * 4), sizeof(word));
    return ntohl(word);
}

static void aaf_init(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t init_pdu[AVTP_AAF_HEADER_LEN_V0];

    assert_int_equal(sizeof(Avtp_Aaf_t), AVTP_AAF_HEADER_LEN_V0);

    /* Passing a NULL pointer must be a no-op. */
    Avtp_Aaf_Init(NULL);

    Avtp_Aaf_Init((Avtp_Aaf_t *)pdu);
    memset(init_pdu, 0, AVTP_AAF_HEADER_LEN_V0);
    init_pdu[0] = AVTP_SUBTYPE_AAF; /* subtype = AAF */
    init_pdu[1] = 0x80;             /* sv = 1, version = 0 */
    assert_memory_equal(init_pdu, pdu, AVTP_AAF_HEADER_LEN_V0);
}

static void aaf_init_v1(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t init_pdu[AVTP_AAF_HEADER_LEN_V1];

    assert_int_equal(sizeof(Avtp_AafV1_t), AVTP_AAF_HEADER_LEN_V1);

    /* Passing a NULL pointer must be a no-op. */
    Avtp_Aaf_InitV1(NULL);

    Avtp_Aaf_InitV1((Avtp_AafV1_t *)pdu);
    memset(init_pdu, 0, AVTP_AAF_HEADER_LEN_V1);
    init_pdu[0] = AVTP_SUBTYPE_AAF; /* subtype = AAF */
    init_pdu[1] = 0x90;             /* sv = 1, version = 1 */
    assert_memory_equal(init_pdu, pdu, AVTP_AAF_HEADER_LEN_V1);

    assert_int_equal(Avtp_Aaf_GetHeaderLen((Avtp_Aaf_t *)pdu), AVTP_AAF_HEADER_LEN_V1);
}

static void aaf_is_valid(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Aaf_t *aaf = (Avtp_Aaf_t *)pdu;

    Avtp_Aaf_Init(aaf);
    assert_true(Avtp_Aaf_IsValid(aaf, AVTP_AAF_HEADER_LEN_V0));

    /* NULL pdu. */
    assert_false(Avtp_Aaf_IsValid(NULL, MAX_PDU_SIZE));

    /* Not an AAF frame. */
    memset(pdu, 0, MAX_PDU_SIZE);
    assert_false(Avtp_Aaf_IsValid(aaf, MAX_PDU_SIZE));

    /* Buffer smaller than the AAF header. */
    Avtp_Aaf_Init(aaf);
    assert_false(Avtp_Aaf_IsValid(aaf, AVTP_AAF_HEADER_LEN_V0 - 1));

    /* stream_data_length does not fit into the buffer. */
    Avtp_Aaf_Init(aaf);
    Avtp_Aaf_SetStreamDataLength(aaf, 10);
    assert_false(Avtp_Aaf_IsValid(aaf, AVTP_AAF_HEADER_LEN_V0 + 9));
    assert_true(Avtp_Aaf_IsValid(aaf, AVTP_AAF_HEADER_LEN_V0 + 10));

    /* Valid version 1 frame. */
    Avtp_Aaf_InitV1((Avtp_AafV1_t *)pdu);
    Avtp_Aaf_SetStreamDataLength((Avtp_Aaf_t *)pdu, 10);
    assert_true(Avtp_Aaf_IsValid((Avtp_Aaf_t *)pdu, AVTP_AAF_HEADER_LEN_V1 + 10));
    assert_false(Avtp_Aaf_IsValid((Avtp_Aaf_t *)pdu, AVTP_AAF_HEADER_LEN_V1 + 9));
    assert_false(Avtp_Aaf_IsValid((Avtp_Aaf_t *)pdu, AVTP_AAF_HEADER_LEN_V1 - 1));

    /* Unsupported version is rejected. */
    Avtp_Aaf_Init(aaf);
    Avtp_CommonHeader_SetVersion((Avtp_CommonHeader_t *)pdu, 2);
    assert_false(Avtp_Aaf_IsValid(aaf, MAX_PDU_SIZE));
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

static void aaf_field_descriptors_cover_header(void **state)
{
    (void)state;

    for (uint8_t version = 0; version <= 1; version++) {
        uint8_t coverage[AVTP_AAF_HEADER_LEN_V1 * 8] = {0};
        size_t coverageBits = sizeof(coverage);
        const Avtp_FieldDescriptor_t *aafDesc =
            version == AVTP_VERSION_1 ? Avtp_AafFieldDescV1 : Avtp_AafFieldDescV0;
        size_t headerBits = (version == AVTP_VERSION_1 ? (size_t)AVTP_AAF_HEADER_LEN_V1
                                                       : (size_t)AVTP_AAF_HEADER_LEN_V0) *
                            8;

        /* subtype and version are owned by the common header; h/sv is covered
         * by the format table. */
        mark_descriptors(coverage, coverageBits,
                         &Avtp_CommonHeaderFieldDesc[AVTPDU_COMMON_FIELD_SUBTYPE], 1);
        mark_descriptors(coverage, coverageBits,
                         &Avtp_CommonHeaderFieldDesc[AVTPDU_COMMON_FIELD_VERSION], 1);
        mark_descriptors(coverage, coverageBits, aafDesc, AVTP_AAF_FIELD_MAX);

        for (size_t bit = 0; bit < coverageBits; bit++) {
            assert_int_equal(coverage[bit], bit < headerBits ? 1 : 0);
        }
    }
}

static void aaf_common_field_consistency(void **state)
{
    (void)state;

    /* The common fields must be declared in the same order as in the common
     * stream header module, so the tables can be compared index by index. */
    assert_int_equal(AVTP_AAF_FIELD_STREAM_DATA_LENGTH, AVTPDU_CSH_FIELD_STREAM_DATA_LENGTH);

    for (uint8_t version = 0; version <= 1; version++) {
        const Avtp_FieldDescriptor_t *aafDesc =
            version == AVTP_VERSION_1 ? Avtp_AafFieldDescV1 : Avtp_AafFieldDescV0;
        const Avtp_FieldDescriptor_t *cshDesc =
            version == AVTP_VERSION_1 ? Avtp_CshFieldDescV1 : Avtp_CshFieldDescV0;

        for (uint8_t i = 0; i < AVTPDU_CSH_FIELD_MAX; i++) {
            assert_int_equal(aafDesc[i].quadlet, cshDesc[i].quadlet);
            assert_int_equal(aafDesc[i].offset, cshDesc[i].offset);
            assert_int_equal(aafDesc[i].bits, cshDesc[i].bits);
        }
    }
}

static void aaf_flag_fields(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Aaf_t *aaf = (Avtp_Aaf_t *)pdu;

    Avtp_Aaf_Init(aaf);
    assert_true(Avtp_Aaf_IsSv(aaf));

    Avtp_Aaf_SetSv(aaf, false);
    assert_false(Avtp_Aaf_IsSv(aaf));

    Avtp_Aaf_SetMr(aaf, true);
    assert_true(Avtp_Aaf_IsMr(aaf));
    Avtp_Aaf_SetMr(aaf, false);
    assert_false(Avtp_Aaf_IsMr(aaf));

    Avtp_Aaf_SetTv(aaf, true);
    assert_true(Avtp_Aaf_IsTv(aaf));
    Avtp_Aaf_SetTv(aaf, false);
    assert_false(Avtp_Aaf_IsTv(aaf));

    Avtp_Aaf_SetTu(aaf, true);
    assert_true(Avtp_Aaf_IsTu(aaf));
    Avtp_Aaf_SetTu(aaf, false);
    assert_false(Avtp_Aaf_IsTu(aaf));

    Avtp_Aaf_SetSp(aaf, true);
    assert_true(Avtp_Aaf_IsSp(aaf));
    Avtp_Aaf_SetSp(aaf, false);
    assert_false(Avtp_Aaf_IsSp(aaf));
}

static void aaf_field_layout(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Aaf_t *aaf = (Avtp_Aaf_t *)pdu;

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Aaf_SetSequenceNum(aaf, 0x55);
    assert_int_equal(Avtp_Aaf_GetSequenceNum(aaf), 0x55);
    assert_int_equal(read_quadlet(pdu, 0), 0x00005500);

    Avtp_Aaf_SetTu(aaf, true);
    assert_true(Avtp_Aaf_IsTu(aaf));
    assert_int_equal(read_quadlet(pdu, 0), 0x00005501);

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Aaf_SetStreamId(aaf, 0xAABBCCDDEEFF0001);
    assert_int_equal(Avtp_Aaf_GetStreamId(aaf), 0xAABBCCDDEEFF0001);

    Avtp_Aaf_SetAvtpTimestamp(aaf, 0x80C0FFEE);
    assert_int_equal(Avtp_Aaf_GetAvtpTimestamp(aaf), 0x80C0FFEE);
    assert_int_equal(read_quadlet(pdu, 3), 0x80C0FFEE);

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Aaf_SetFormat(aaf, AVTP_AAF_FORMAT_INT_16BIT);
    assert_int_equal(Avtp_Aaf_GetFormat(aaf), AVTP_AAF_FORMAT_INT_16BIT);
    assert_int_equal(read_quadlet(pdu, 4), 0x04000000);

    Avtp_Aaf_SetAafFormatSpecificData1(aaf, 0x123456);
    assert_int_equal(Avtp_Aaf_GetAafFormatSpecificData1(aaf), 0x123456);
    assert_int_equal(read_quadlet(pdu, 4), 0x04123456);

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Aaf_SetStreamDataLength(aaf, 0xAAAA);
    assert_int_equal(Avtp_Aaf_GetStreamDataLength(aaf), 0xAAAA);
    assert_int_equal(read_quadlet(pdu, 5), 0xAAAA0000);

    Avtp_Aaf_SetAfsd(aaf, 0x5);
    assert_int_equal(Avtp_Aaf_GetAfsd(aaf), 0x5);
    assert_int_equal(read_quadlet(pdu, 5), 0xAAAAA000);

    Avtp_Aaf_SetSp(aaf, true);
    assert_true(Avtp_Aaf_IsSp(aaf));
    assert_int_equal(read_quadlet(pdu, 5), 0xAAAAB000);

    Avtp_Aaf_SetEvt(aaf, 0xA);
    assert_int_equal(Avtp_Aaf_GetEvt(aaf), 0xA);
    assert_int_equal(read_quadlet(pdu, 5), 0xAAAABA00);

    Avtp_Aaf_SetAafFormatSpecificData2(aaf, 0xAB);
    assert_int_equal(Avtp_Aaf_GetAafFormatSpecificData2(aaf), 0xAB);
    assert_int_equal(read_quadlet(pdu, 5), 0xAAAABAAB);

    /* ptp_grandmaster_identity does not exist in version 0. */
    assert_int_equal(Avtp_Aaf_GetPtpGrandmasterIdentity(aaf), 0);
}

static void aaf_v1_layout(void **state)
{
    (void)state;
    uint8_t pdu[AVTP_AAF_HEADER_LEN_V1];
    Avtp_Aaf_t *aaf = (Avtp_Aaf_t *)pdu;

    Avtp_Aaf_InitV1((Avtp_AafV1_t *)pdu);

    Avtp_Aaf_SetSequenceNum(aaf, 0x12345678);
    assert_int_equal(Avtp_Aaf_GetSequenceNum(aaf), 0x12345678);
    assert_int_equal(read_quadlet(pdu, 3), 0x12345678);

    Avtp_Aaf_SetAvtpTimestamp(aaf, 0x1122334455667788ULL);
    assert_int_equal(Avtp_Aaf_GetAvtpTimestamp(aaf), 0x1122334455667788ULL);
    assert_int_equal(read_quadlet(pdu, 4), 0x11223344);
    assert_int_equal(read_quadlet(pdu, 5), 0x55667788);

    Avtp_Aaf_SetPtpGrandmasterIdentity(aaf, 0x99AABBCCDDEEFF00ULL);
    assert_int_equal(Avtp_Aaf_GetPtpGrandmasterIdentity(aaf), 0x99AABBCCDDEEFF00ULL);
    assert_int_equal(read_quadlet(pdu, 6), 0x99AABBCC);
    assert_int_equal(read_quadlet(pdu, 7), 0xDDEEFF00);

    Avtp_Aaf_SetFormat(aaf, AVTP_AAF_FORMAT_INT_16BIT);
    Avtp_Aaf_SetAafFormatSpecificData1(aaf, 0x123456);
    assert_int_equal(read_quadlet(pdu, 8), 0x04123456);

    Avtp_Aaf_SetStreamDataLength(aaf, 0xAAAA);
    Avtp_Aaf_SetAfsd(aaf, 0x5);
    Avtp_Aaf_SetSp(aaf, true);
    Avtp_Aaf_SetEvt(aaf, 0xA);
    Avtp_Aaf_SetAafFormatSpecificData2(aaf, 0xAB);
    assert_int_equal(read_quadlet(pdu, 9), 0xAAAABAAB);
}

static void aaf_payload(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t payload[8] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
    uint8_t payload_out[8] = {0};
    Avtp_Aaf_t *aaf = (Avtp_Aaf_t *)pdu;

    Avtp_Aaf_Init(aaf);
    Avtp_Aaf_SetPayload(aaf, payload, sizeof(payload));

    assert_ptr_equal(Avtp_Aaf_GetPayload(aaf), pdu + AVTP_AAF_HEADER_LEN_V0);
    assert_memory_equal(pdu + AVTP_AAF_HEADER_LEN_V0, payload, sizeof(payload));

    memcpy(payload_out, Avtp_Aaf_GetPayload(aaf), sizeof(payload_out));
    assert_memory_equal(payload_out, payload, sizeof(payload_out));

    /* Version 1 payload starts after the 40-octet header. */
    Avtp_Aaf_InitV1((Avtp_AafV1_t *)pdu);
    Avtp_Aaf_SetPayload((Avtp_Aaf_t *)pdu, payload, sizeof(payload));
    assert_ptr_equal(Avtp_Aaf_GetPayload((Avtp_Aaf_t *)pdu), pdu + AVTP_AAF_HEADER_LEN_V1);
    assert_memory_equal(pdu + AVTP_AAF_HEADER_LEN_V1, payload, sizeof(payload));
}

static void aaf_get_set_field(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Aaf_t *aaf = (Avtp_Aaf_t *)pdu;

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Aaf_SetField(aaf, AVTP_AAF_FIELD_EVT, 0xA);
    assert_int_equal(Avtp_Aaf_GetField(aaf, AVTP_AAF_FIELD_EVT), 0xA);

    /* Reserved fields are reachable through the generic access engine. */
    Avtp_Aaf_SetField(aaf, AVTP_AAF_FIELD_FSD, 0x3);
    assert_int_equal(Avtp_Aaf_GetField(aaf, AVTP_AAF_FIELD_FSD), 0x3);

    Avtp_Aaf_SetField(aaf, AVTP_AAF_FIELD_FSD1, 0x7F);
    assert_int_equal(Avtp_Aaf_GetField(aaf, AVTP_AAF_FIELD_FSD1), 0x7F);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(aaf_init),
        cmocka_unit_test(aaf_init_v1),
        cmocka_unit_test(aaf_is_valid),
        cmocka_unit_test(aaf_field_descriptors_cover_header),
        cmocka_unit_test(aaf_common_field_consistency),
        cmocka_unit_test(aaf_flag_fields),
        cmocka_unit_test(aaf_field_layout),
        cmocka_unit_test(aaf_v1_layout),
        cmocka_unit_test(aaf_payload),
        cmocka_unit_test(aaf_get_set_field),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
