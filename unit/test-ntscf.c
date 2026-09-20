/*
 * Copyright (c) 2025, COVESA
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
#include "avtp/acf/Ntscf.h"

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

static void ntscf_init(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t init_pdu[AVTP_NTSCF_HEADER_LEN_V0];

    assert_int_equal(sizeof(Avtp_Ntscf_t), AVTP_NTSCF_HEADER_LEN_V0);

    /* Passing a NULL pointer must be a no-op. */
    Avtp_Ntscf_Init(NULL);

    Avtp_Ntscf_Init((Avtp_Ntscf_t *)pdu);
    memset(init_pdu, 0, AVTP_NTSCF_HEADER_LEN_V0);
    init_pdu[0] = AVTP_SUBTYPE_NTSCF; /* subtype = NTSCF */
    init_pdu[1] = 0x80;               /* sv = 1, version = 0 */
    assert_memory_equal(init_pdu, pdu, AVTP_NTSCF_HEADER_LEN_V0);
}

static void ntscf_init_v1(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t init_pdu[AVTP_NTSCF_HEADER_LEN_V1];

    assert_int_equal(sizeof(Avtp_NtscfV1_t), AVTP_NTSCF_HEADER_LEN_V1);

    /* Passing a NULL pointer must be a no-op. */
    Avtp_Ntscf_InitV1(NULL);

    Avtp_Ntscf_InitV1((Avtp_NtscfV1_t *)pdu);
    memset(init_pdu, 0, AVTP_NTSCF_HEADER_LEN_V1);
    init_pdu[0] = AVTP_SUBTYPE_NTSCF; /* subtype = NTSCF */
    init_pdu[1] = 0x90;               /* sv = 1, version = 1 */
    assert_memory_equal(init_pdu, pdu, AVTP_NTSCF_HEADER_LEN_V1);

    assert_int_equal(Avtp_Ntscf_GetHeaderLen((Avtp_Ntscf_t *)pdu), AVTP_NTSCF_HEADER_LEN_V1);
}

static void ntscf_is_valid(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];

    /* Valid version 0 frame with no payload. */
    Avtp_Ntscf_Init((Avtp_Ntscf_t *)pdu);
    assert_true(Avtp_Ntscf_IsValid((Avtp_Ntscf_t *)pdu, AVTP_NTSCF_HEADER_LEN_V0));

    /* Not an NTSCF frame. */
    memset(pdu, 0, MAX_PDU_SIZE);
    assert_false(Avtp_Ntscf_IsValid((Avtp_Ntscf_t *)pdu, MAX_PDU_SIZE));

    /* Buffer smaller than the version 0 header. */
    Avtp_Ntscf_Init((Avtp_Ntscf_t *)pdu);
    assert_false(Avtp_Ntscf_IsValid((Avtp_Ntscf_t *)pdu, AVTP_NTSCF_HEADER_LEN_V0 - 1));

    /* ntscf_data_length must fit after the header. */
    Avtp_Ntscf_Init((Avtp_Ntscf_t *)pdu);
    Avtp_Ntscf_SetNtscfDataLength((Avtp_Ntscf_t *)pdu, 28);
    assert_false(Avtp_Ntscf_IsValid((Avtp_Ntscf_t *)pdu, AVTP_NTSCF_HEADER_LEN_V0 + 27));
    assert_true(Avtp_Ntscf_IsValid((Avtp_Ntscf_t *)pdu, AVTP_NTSCF_HEADER_LEN_V0 + 28));

    /* Valid version 1 frame. */
    Avtp_Ntscf_InitV1((Avtp_NtscfV1_t *)pdu);
    assert_true(Avtp_Ntscf_IsValid((Avtp_Ntscf_t *)pdu, AVTP_NTSCF_HEADER_LEN_V1));
    assert_false(Avtp_Ntscf_IsValid((Avtp_Ntscf_t *)pdu, AVTP_NTSCF_HEADER_LEN_V1 - 1));

    /* Unsupported version is rejected. */
    Avtp_Ntscf_Init((Avtp_Ntscf_t *)pdu);
    Avtp_CommonHeader_SetVersion((Avtp_CommonHeader_t *)pdu, 2);
    assert_false(Avtp_Ntscf_IsValid((Avtp_Ntscf_t *)pdu, MAX_PDU_SIZE));
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

static void ntscf_field_descriptors_cover_header(void **state)
{
    (void)state;

    for (uint8_t version = 0; version <= 1; version++) {
        uint8_t coverage[AVTP_NTSCF_HEADER_LEN_V1 * 8] = {0};
        size_t coverageBits = sizeof(coverage);
        const Avtp_FieldDescriptor_t *ntscfDesc =
            version == AVTP_VERSION_1 ? Avtp_NtscfFieldDescV1 : Avtp_NtscfFieldDescV0;
        size_t headerBits = (version == AVTP_VERSION_1 ? (size_t)AVTP_NTSCF_HEADER_LEN_V1
                                                       : (size_t)AVTP_NTSCF_HEADER_LEN_V0) *
                            8;

        /* subtype and version are owned by the common header; h/sv is covered
         * by the format table. */
        mark_descriptors(coverage, coverageBits,
                         &Avtp_CommonHeaderFieldDesc[AVTPDU_COMMON_FIELD_SUBTYPE], 1);
        mark_descriptors(coverage, coverageBits,
                         &Avtp_CommonHeaderFieldDesc[AVTPDU_COMMON_FIELD_VERSION], 1);
        mark_descriptors(coverage, coverageBits, ntscfDesc, AVTP_NTSCF_FIELD_MAX);

        for (size_t bit = 0; bit < coverageBits; bit++) {
            assert_int_equal(coverage[bit], bit < headerBits ? 1 : 0);
        }
    }
}

static void ntscf_ah_field_consistency(void **state)
{
    (void)state;

    /* The alternative header fields must be declared first and in the same
     * order as in the alternative header module. */
    assert_int_equal(AVTP_NTSCF_FIELD_PTP_GRANDMASTER_IDENTITY,
                     AVTPDU_AH_FIELD_PTP_GRANDMASTER_IDENTITY);

    for (uint8_t version = 0; version <= 1; version++) {
        const Avtp_FieldDescriptor_t *ntscfDesc =
            version == AVTP_VERSION_1 ? Avtp_NtscfFieldDescV1 : Avtp_NtscfFieldDescV0;
        const Avtp_FieldDescriptor_t *ahDesc =
            version == AVTP_VERSION_1 ? Avtp_AhFieldDescV1 : Avtp_AhFieldDescV0;

        for (uint8_t i = 0; i < AVTPDU_AH_FIELD_MAX; i++) {
            assert_int_equal(ntscfDesc[i].quadlet, ahDesc[i].quadlet);
            assert_int_equal(ntscfDesc[i].offset, ahDesc[i].offset);
            assert_int_equal(ntscfDesc[i].bits, ahDesc[i].bits);
        }
    }
}

static void ntscf_field_layout(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Ntscf_t *ntscf = (Avtp_Ntscf_t *)pdu;

    memset(pdu, 0, MAX_PDU_SIZE);
    Avtp_CommonHeader_SetSubtype((Avtp_CommonHeader_t *)ntscf, AVTP_SUBTYPE_NTSCF);

    Avtp_Ntscf_SetSequenceNum(ntscf, 0xAB);
    assert_int_equal(Avtp_Ntscf_GetSequenceNum(ntscf), 0xAB);
    assert_int_equal(Avtp_Ntscf_GetSequenceNumLsb(ntscf), 0xAB);
    assert_int_equal(read_quadlet(pdu, 0), 0x820000AB);

    Avtp_Ntscf_SetNtscfDataLength(ntscf, 0x123);
    assert_int_equal(Avtp_Ntscf_GetNtscfDataLength(ntscf), 0x123);
    assert_int_equal(read_quadlet(pdu, 0), 0x820123AB);

    Avtp_Ntscf_SetStreamId(ntscf, 0xAABBCCDDEEFF0001ULL);
    assert_int_equal(Avtp_Ntscf_GetStreamId(ntscf), 0xAABBCCDDEEFF0001ULL);
    assert_int_equal(read_quadlet(pdu, 1), 0xAABBCCDD);
    assert_int_equal(read_quadlet(pdu, 2), 0xEEFF0001);

    /* ptp_grandmaster_identity does not exist in version 0. */
    assert_int_equal(Avtp_Ntscf_GetPtpGrandmasterIdentity(ntscf), 0);
}

static void ntscf_v1_layout(void **state)
{
    (void)state;
    uint8_t pdu[AVTP_NTSCF_HEADER_LEN_V1];
    Avtp_Ntscf_t *ntscf = (Avtp_Ntscf_t *)pdu;

    Avtp_Ntscf_InitV1((Avtp_NtscfV1_t *)pdu);

    Avtp_Ntscf_SetSequenceNum(ntscf, 0x12345678);
    assert_int_equal(Avtp_Ntscf_GetSequenceNum(ntscf), 0x12345678);
    assert_int_equal(Avtp_Ntscf_GetSequenceNumLsb(ntscf), 0x78);
    assert_int_equal(read_quadlet(pdu, 1), 0x12345678);
    assert_int_equal(pdu[19], 0x78); /* sequence_num_lsb at q4@24 */

    Avtp_Ntscf_SetPtpGrandmasterIdentity(ntscf, 0x99AABBCCDDEEFF00ULL);
    assert_int_equal(Avtp_Ntscf_GetPtpGrandmasterIdentity(ntscf), 0x99AABBCCDDEEFF00ULL);
    assert_int_equal(read_quadlet(pdu, 2), 0x99AABBCC);
    assert_int_equal(read_quadlet(pdu, 3), 0xDDEEFF00);

    Avtp_Ntscf_SetNtscfDataLength(ntscf, 0x123);
    assert_int_equal(Avtp_Ntscf_GetNtscfDataLength(ntscf), 0x123);
    assert_int_equal(read_quadlet(pdu, 4), 0x00012378);

    Avtp_Ntscf_SetStreamId(ntscf, 0x0102030405060708ULL);
    assert_int_equal(Avtp_Ntscf_GetStreamId(ntscf), 0x0102030405060708ULL);
    assert_int_equal(read_quadlet(pdu, 5), 0x01020304);
    assert_int_equal(read_quadlet(pdu, 6), 0x05060708);
}

static void ntscf_payload(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t payload[4] = {0xDE, 0xAD, 0xBE, 0xEF};

    Avtp_Ntscf_Init((Avtp_Ntscf_t *)pdu);
    assert_ptr_equal(Avtp_Ntscf_GetPayload((Avtp_Ntscf_t *)pdu), pdu + AVTP_NTSCF_HEADER_LEN_V0);
    Avtp_Ntscf_SetPayload((Avtp_Ntscf_t *)pdu, payload, sizeof(payload));
    assert_memory_equal(pdu + AVTP_NTSCF_HEADER_LEN_V0, payload, sizeof(payload));

    Avtp_Ntscf_InitV1((Avtp_NtscfV1_t *)pdu);
    assert_ptr_equal(Avtp_Ntscf_GetPayload((Avtp_Ntscf_t *)pdu), pdu + AVTP_NTSCF_HEADER_LEN_V1);
    Avtp_Ntscf_SetPayload((Avtp_Ntscf_t *)pdu, payload, sizeof(payload));
    assert_memory_equal(pdu + AVTP_NTSCF_HEADER_LEN_V1, payload, sizeof(payload));
}

static void ntscf_get_set_field(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Ntscf_t *ntscf = (Avtp_Ntscf_t *)pdu;

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Ntscf_SetField(ntscf, AVTP_NTSCF_FIELD_SEQUENCE_NUM_LSB, 0xAA);
    assert_int_equal(Avtp_Ntscf_GetField(ntscf, AVTP_NTSCF_FIELD_SEQUENCE_NUM_LSB), 0xAA);

    /* Reserved fields are reachable through the generic access engine. */
    Avtp_Ntscf_SetField(ntscf, AVTP_NTSCF_FIELD_R, 0x1);
    assert_int_equal(Avtp_Ntscf_GetField(ntscf, AVTP_NTSCF_FIELD_R), 0x1);
}

static void ntscf_typed_fields_v0(void **state)
{
    (void)state;
    uint8_t pdu[AVTP_NTSCF_HEADER_LEN_V1];
    Avtp_Ntscf_t *ntscf = (Avtp_Ntscf_t *)pdu;

    Avtp_Ntscf_Init(ntscf);

    for (uint8_t f = 0; f < AVTP_NTSCF_FIELD_MAX; f++) {
        uint8_t bits = Avtp_NtscfFieldDescV0[f].bits;
        uint64_t value = 0xA5A5A5A5A5A5A5A5ULL ^ (uint64_t)f;
        uint64_t expected = mask_field_value(bits, value);
        Avtp_NtscfFields_t field = (Avtp_NtscfFields_t)f;

        Avtp_Ntscf_SetField_V0(ntscf, field, value);
        assert_int_equal(Avtp_Ntscf_GetField_V0(ntscf, field), expected);
        assert_int_equal(Avtp_Ntscf_GetField(ntscf, field), expected);
        assert_int_equal(Avtp_GetField(Avtp_NtscfFieldDescV0, AVTP_NTSCF_FIELD_MAX, pdu, f),
                         expected);
    }
}

static void ntscf_typed_fields_v1(void **state)
{
    (void)state;
    uint8_t pdu[AVTP_NTSCF_HEADER_LEN_V1];
    Avtp_NtscfV1_t *ntscf = (Avtp_NtscfV1_t *)pdu;

    Avtp_Ntscf_InitV1(ntscf);

    for (uint8_t f = 0; f < AVTP_NTSCF_FIELD_MAX; f++) {
        uint8_t bits = Avtp_NtscfFieldDescV1[f].bits;
        uint64_t value = 0x5A5A5A5A5A5A5A5AULL ^ (uint64_t)f;
        uint64_t expected = mask_field_value(bits, value);
        Avtp_NtscfFields_t field = (Avtp_NtscfFields_t)f;

        Avtp_Ntscf_SetField_V1(ntscf, field, value);
        assert_int_equal(Avtp_Ntscf_GetField_V1(ntscf, field), expected);
        assert_int_equal(Avtp_Ntscf_GetField((Avtp_Ntscf_t *)ntscf, field), expected);
        assert_int_equal(Avtp_GetField(Avtp_NtscfFieldDescV1, AVTP_NTSCF_FIELD_MAX, pdu, f),
                         expected);
    }
}

static void ntscf_typed_named(void **state)
{
    (void)state;
    uint8_t pdu[AVTP_NTSCF_HEADER_LEN_V1];
    Avtp_Ntscf_t *v0 = (Avtp_Ntscf_t *)pdu;
    Avtp_NtscfV1_t *v1 = (Avtp_NtscfV1_t *)pdu;

    /* Version 0. */
    Avtp_Ntscf_Init(v0);
    Avtp_Ntscf_SetSv_V0(v0, true);
    Avtp_Ntscf_SetSequenceNum_V0(v0, 0xAB);
    Avtp_Ntscf_SetNtscfDataLength_V0(v0, 0x123);
    Avtp_Ntscf_SetStreamId_V0(v0, 0xAABBCCDDEEFF0001ULL);

    assert_true(Avtp_Ntscf_IsSv_V0(v0));
    assert_int_equal(Avtp_Ntscf_GetSequenceNum_V0(v0), 0xAB);
    assert_int_equal(Avtp_Ntscf_GetSequenceNumLsb_V0(v0), 0xAB);
    assert_int_equal(Avtp_Ntscf_GetNtscfDataLength_V0(v0), 0x123);
    assert_int_equal(Avtp_Ntscf_GetStreamId_V0(v0), 0xAABBCCDDEEFF0001ULL);
    assert_int_equal(Avtp_Ntscf_GetPtpGrandmasterIdentity_V0(v0), 0);

    /* The version-dispatched accessors agree with the version 0 variants. */
    assert_int_equal(Avtp_Ntscf_GetSequenceNum(v0), Avtp_Ntscf_GetSequenceNum_V0(v0));
    assert_int_equal(Avtp_Ntscf_GetSequenceNumLsb(v0), Avtp_Ntscf_GetSequenceNumLsb_V0(v0));
    assert_int_equal(Avtp_Ntscf_GetNtscfDataLength(v0), Avtp_Ntscf_GetNtscfDataLength_V0(v0));
    assert_int_equal(Avtp_Ntscf_GetStreamId(v0), Avtp_Ntscf_GetStreamId_V0(v0));

    /* Version 1. */
    Avtp_Ntscf_InitV1(v1);
    Avtp_Ntscf_SetSv_V1(v1, true);
    Avtp_Ntscf_SetSequenceNum_V1(v1, 0x12345678);
    Avtp_Ntscf_SetNtscfDataLength_V1(v1, 0x456);
    Avtp_Ntscf_SetPtpGrandmasterIdentity_V1(v1, 0x99AABBCCDDEEFF00ULL);
    Avtp_Ntscf_SetStreamId_V1(v1, 0x0102030405060708ULL);

    assert_true(Avtp_Ntscf_IsSv_V1(v1));
    assert_int_equal(Avtp_Ntscf_GetSequenceNum_V1(v1), 0x12345678);
    assert_int_equal(Avtp_Ntscf_GetSequenceNumLsb_V1(v1), 0x78);
    assert_int_equal(Avtp_Ntscf_GetNtscfDataLength_V1(v1), 0x456);
    assert_int_equal(Avtp_Ntscf_GetPtpGrandmasterIdentity_V1(v1), 0x99AABBCCDDEEFF00ULL);
    assert_int_equal(Avtp_Ntscf_GetStreamId_V1(v1), 0x0102030405060708ULL);

    /* The version-dispatched accessors agree with the version 1 variants. */
    assert_int_equal(Avtp_Ntscf_GetSequenceNum(v0), Avtp_Ntscf_GetSequenceNum_V1(v1));
    assert_int_equal(Avtp_Ntscf_GetSequenceNumLsb(v0), Avtp_Ntscf_GetSequenceNumLsb_V1(v1));
    assert_int_equal(Avtp_Ntscf_GetNtscfDataLength(v0), Avtp_Ntscf_GetNtscfDataLength_V1(v1));
    assert_int_equal(Avtp_Ntscf_GetPtpGrandmasterIdentity(v0),
                     Avtp_Ntscf_GetPtpGrandmasterIdentity_V1(v1));
    assert_int_equal(Avtp_Ntscf_GetStreamId(v0), Avtp_Ntscf_GetStreamId_V1(v1));
}

static void ntscf_typed_helpers(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t payload[4] = {0xDE, 0xAD, 0xBE, 0xEF};

    Avtp_Ntscf_Init((Avtp_Ntscf_t *)pdu);
    assert_int_equal(Avtp_Ntscf_GetHeaderLen_V0((Avtp_Ntscf_t *)pdu), AVTP_NTSCF_HEADER_LEN_V0);
    assert_ptr_equal(Avtp_Ntscf_GetPayload_V0((Avtp_Ntscf_t *)pdu), pdu + AVTP_NTSCF_HEADER_LEN_V0);
    Avtp_Ntscf_SetPayload_V0((Avtp_Ntscf_t *)pdu, payload, sizeof(payload));
    assert_memory_equal(pdu + AVTP_NTSCF_HEADER_LEN_V0, payload, sizeof(payload));

    Avtp_Ntscf_InitV1((Avtp_NtscfV1_t *)pdu);
    assert_int_equal(Avtp_Ntscf_GetHeaderLen_V1((Avtp_NtscfV1_t *)pdu), AVTP_NTSCF_HEADER_LEN_V1);
    assert_ptr_equal(Avtp_Ntscf_GetPayload_V1((Avtp_NtscfV1_t *)pdu),
                     pdu + AVTP_NTSCF_HEADER_LEN_V1);
    Avtp_Ntscf_SetPayload_V1((Avtp_NtscfV1_t *)pdu, payload, sizeof(payload));
    assert_memory_equal(pdu + AVTP_NTSCF_HEADER_LEN_V1, payload, sizeof(payload));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(ntscf_init),
        cmocka_unit_test(ntscf_init_v1),
        cmocka_unit_test(ntscf_is_valid),
        cmocka_unit_test(ntscf_field_descriptors_cover_header),
        cmocka_unit_test(ntscf_ah_field_consistency),
        cmocka_unit_test(ntscf_field_layout),
        cmocka_unit_test(ntscf_v1_layout),
        cmocka_unit_test(ntscf_payload),
        cmocka_unit_test(ntscf_get_set_field),
        cmocka_unit_test(ntscf_typed_fields_v0),
        cmocka_unit_test(ntscf_typed_fields_v1),
        cmocka_unit_test(ntscf_typed_named),
        cmocka_unit_test(ntscf_typed_helpers),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
