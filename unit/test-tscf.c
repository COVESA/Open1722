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

#include "avtp/acf/Tscf.h"
#include "avtp/CommonHeader.h"
#include "avtp/CommonStreamHeader.h"

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

static void tscf_init(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t init_pdu[AVTP_TSCF_HEADER_LEN_V0];

    assert_int_equal(sizeof(Avtp_Tscf_t), AVTP_TSCF_HEADER_LEN_V0);
    assert_int_equal(sizeof(Avtp_TscfV1_t), AVTP_TSCF_HEADER_LEN_V1);

    /* Passing a NULL pointer must be a no-op. */
    Avtp_Tscf_Init(NULL);

    Avtp_Tscf_Init((Avtp_Tscf_t *)pdu);
    memset(init_pdu, 0, AVTP_TSCF_HEADER_LEN_V0);
    init_pdu[0] = AVTP_SUBTYPE_TSCF; /* subtype = TSCF */
    init_pdu[1] = 0x80;              /* sv = 1, version = 0 */
    assert_memory_equal(init_pdu, pdu, AVTP_TSCF_HEADER_LEN_V0);
}

static void tscf_init_v1(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t init_pdu[AVTP_TSCF_HEADER_LEN_V1];

    /* Passing a NULL pointer must be a no-op. */
    Avtp_Tscf_InitV1(NULL);

    Avtp_Tscf_InitV1((Avtp_TscfV1_t *)pdu);
    memset(init_pdu, 0, AVTP_TSCF_HEADER_LEN_V1);
    init_pdu[0] = AVTP_SUBTYPE_TSCF; /* subtype = TSCF */
    init_pdu[1] = 0x90;              /* sv = 1, version = 1 */
    assert_memory_equal(init_pdu, pdu, AVTP_TSCF_HEADER_LEN_V1);

    assert_int_equal(Avtp_CommonStreamHeader_GetVersion((Avtp_CommonStreamHeader_t *)pdu),
                     AVTP_VERSION_1);
    assert_int_equal(Avtp_CommonStreamHeader_GetHeaderLen((Avtp_CommonStreamHeader_t *)pdu),
                     AVTP_TSCF_HEADER_LEN_V1);
}

static void tscf_v0_layout(void **state)
{
    (void)state;
    uint8_t pdu[AVTP_TSCF_HEADER_LEN_V0];
    uint8_t snapshot[AVTP_TSCF_HEADER_LEN_V0];
    Avtp_Tscf_t *tscf = (Avtp_Tscf_t *)pdu;

    Avtp_Tscf_Init(tscf);

    Avtp_Tscf_SetSequenceNum(tscf, 0xAB);
    assert_int_equal(Avtp_Tscf_GetSequenceNum(tscf), 0xAB);
    assert_int_equal(Avtp_Tscf_GetSequenceNumLsb(tscf), 0xAB);
    assert_int_equal(read_quadlet(pdu, 0), 0x0580AB00);

    Avtp_Tscf_SetAvtpTimestamp(tscf, 0x80C0FFEE);
    assert_int_equal(Avtp_Tscf_GetAvtpTimestamp(tscf), 0x80C0FFEE);
    assert_int_equal(read_quadlet(pdu, 3), 0x80C0FFEE);

    /* ptp_grandmaster_identity does not exist in version 0: the setter is a
     * no-op and the getter returns 0. */
    assert_int_equal(Avtp_Tscf_GetPtpGrandmasterIdentity(tscf), 0);
    memcpy(snapshot, pdu, sizeof(snapshot));
    Avtp_Tscf_SetPtpGrandmasterIdentity(tscf, 0xFFFFFFFFFFFFFFFFULL);
    assert_memory_equal(snapshot, pdu, sizeof(snapshot));
}

static void tscf_v1_layout(void **state)
{
    (void)state;
    uint8_t pdu[AVTP_TSCF_HEADER_LEN_V1];
    Avtp_Tscf_t *tscf = (Avtp_Tscf_t *)pdu;

    Avtp_Tscf_InitV1((Avtp_TscfV1_t *)pdu);

    Avtp_Tscf_SetStreamId(tscf, 0x0102030405060708ULL);
    assert_int_equal(Avtp_Tscf_GetStreamId(tscf), 0x0102030405060708ULL);
    assert_int_equal(read_quadlet(pdu, 1), 0x01020304);
    assert_int_equal(read_quadlet(pdu, 2), 0x05060708);

    Avtp_Tscf_SetSequenceNum(tscf, 0x12345678);
    assert_int_equal(Avtp_Tscf_GetSequenceNum(tscf), 0x12345678);
    assert_int_equal(read_quadlet(pdu, 3), 0x12345678);
    /* sequence_num_lsb copy in format_specific_data_0 (byte 2 of quadlet 0). */
    assert_int_equal(pdu[2], 0x78);
    assert_int_equal(Avtp_Tscf_GetSequenceNumLsb(tscf), 0x78);

    Avtp_Tscf_SetAvtpTimestamp(tscf, 0x1122334455667788ULL);
    assert_int_equal(Avtp_Tscf_GetAvtpTimestamp(tscf), 0x1122334455667788ULL);
    assert_int_equal(read_quadlet(pdu, 4), 0x11223344);
    assert_int_equal(read_quadlet(pdu, 5), 0x55667788);

    Avtp_Tscf_SetPtpGrandmasterIdentity(tscf, 0x99AABBCCDDEEFF00ULL);
    assert_int_equal(Avtp_Tscf_GetPtpGrandmasterIdentity(tscf), 0x99AABBCCDDEEFF00ULL);
    assert_int_equal(read_quadlet(pdu, 6), 0x99AABBCC);
    assert_int_equal(read_quadlet(pdu, 7), 0xDDEEFF00);

    Avtp_Tscf_SetStreamDataLength(tscf, 0x0ABC);
    assert_int_equal(Avtp_Tscf_GetStreamDataLength(tscf), 0x0ABC);
    assert_int_equal(read_quadlet(pdu, 9), 0x0ABC0000);
}

static void tscf_is_valid(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];

    /* Valid version 0 frame with no payload. */
    Avtp_Tscf_Init((Avtp_Tscf_t *)pdu);
    assert_true(Avtp_Tscf_IsValid((Avtp_Tscf_t *)pdu, AVTP_TSCF_HEADER_LEN_V0));

    /* Not a TSCF frame. */
    memset(pdu, 0, MAX_PDU_SIZE);
    assert_false(Avtp_Tscf_IsValid((Avtp_Tscf_t *)pdu, MAX_PDU_SIZE));

    /* Buffer smaller than the version 0 header. */
    Avtp_Tscf_Init((Avtp_Tscf_t *)pdu);
    assert_false(Avtp_Tscf_IsValid((Avtp_Tscf_t *)pdu, AVTP_TSCF_HEADER_LEN_V0 - 1));

    /* stream_data_length must fit after the header. */
    Avtp_Tscf_Init((Avtp_Tscf_t *)pdu);
    Avtp_Tscf_SetStreamDataLength((Avtp_Tscf_t *)pdu, 10);
    assert_false(Avtp_Tscf_IsValid((Avtp_Tscf_t *)pdu, AVTP_TSCF_HEADER_LEN_V0 + 9));
    assert_true(Avtp_Tscf_IsValid((Avtp_Tscf_t *)pdu, AVTP_TSCF_HEADER_LEN_V0 + 10));

    /* Valid version 1 frame with no payload. */
    Avtp_Tscf_InitV1((Avtp_TscfV1_t *)pdu);
    assert_true(Avtp_Tscf_IsValid((Avtp_Tscf_t *)pdu, AVTP_TSCF_HEADER_LEN_V1));
    assert_false(Avtp_Tscf_IsValid((Avtp_Tscf_t *)pdu, AVTP_TSCF_HEADER_LEN_V1 - 1));

    /* Unsupported version is rejected. */
    Avtp_Tscf_Init((Avtp_Tscf_t *)pdu);
    Avtp_CommonHeader_SetVersion((Avtp_CommonHeader_t *)pdu, 2);
    assert_false(Avtp_Tscf_IsValid((Avtp_Tscf_t *)pdu, MAX_PDU_SIZE));
}

static void tscf_payload(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t payload[4] = {0xDE, 0xAD, 0xBE, 0xEF};

    Avtp_Tscf_Init((Avtp_Tscf_t *)pdu);
    assert_ptr_equal(Avtp_Tscf_GetPayload((Avtp_Tscf_t *)pdu), pdu + AVTP_TSCF_HEADER_LEN_V0);
    Avtp_Tscf_SetPayload((Avtp_Tscf_t *)pdu, payload, sizeof(payload));
    assert_memory_equal(pdu + AVTP_TSCF_HEADER_LEN_V0, payload, sizeof(payload));

    Avtp_Tscf_InitV1((Avtp_TscfV1_t *)pdu);
    assert_ptr_equal(Avtp_Tscf_GetPayload((Avtp_Tscf_t *)pdu), pdu + AVTP_TSCF_HEADER_LEN_V1);
    Avtp_Tscf_SetPayload((Avtp_Tscf_t *)pdu, payload, sizeof(payload));
    assert_memory_equal(pdu + AVTP_TSCF_HEADER_LEN_V1, payload, sizeof(payload));
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

static void tscf_header_coverage(void **state)
{
    (void)state;

    for (uint8_t version = 0; version <= 1; version++) {
        uint8_t coverage[AVTP_TSCF_HEADER_LEN_V1 * 8] = {0};
        size_t coverageBits = sizeof(coverage);
        const Avtp_FieldDescriptor_t *tscfDesc =
            version == AVTP_VERSION_1 ? Avtp_TscfFieldDescV1 : Avtp_TscfFieldDescV0;
        size_t headerBits = (version == AVTP_VERSION_1 ? (size_t)AVTP_TSCF_HEADER_LEN_V1
                                                       : (size_t)AVTP_TSCF_HEADER_LEN_V0) *
                            8;

        /* subtype and version are owned by the common header; h/sv is covered
         * by the format table. */
        mark_descriptors(coverage, coverageBits,
                         &Avtp_CommonHeaderFieldDesc[AVTPDU_COMMON_FIELD_SUBTYPE], 1);
        mark_descriptors(coverage, coverageBits,
                         &Avtp_CommonHeaderFieldDesc[AVTPDU_COMMON_FIELD_VERSION], 1);
        mark_descriptors(coverage, coverageBits, tscfDesc, AVTP_TSCF_FIELD_MAX);

        for (size_t bit = 0; bit < coverageBits; bit++) {
            assert_int_equal(coverage[bit], bit < headerBits ? 1 : 0);
        }
    }
}

static void tscf_common_field_consistency(void **state)
{
    (void)state;

    /* The common fields must be declared in the same order as in the common
     * stream header module, so the tables can be compared index by index. */
    assert_int_equal(AVTP_TSCF_FIELD_STREAM_DATA_LENGTH, AVTPDU_CSH_FIELD_STREAM_DATA_LENGTH);

    for (uint8_t version = 0; version <= 1; version++) {
        const Avtp_FieldDescriptor_t *tscfDesc =
            version == AVTP_VERSION_1 ? Avtp_TscfFieldDescV1 : Avtp_TscfFieldDescV0;
        const Avtp_FieldDescriptor_t *cshDesc =
            version == AVTP_VERSION_1 ? Avtp_CshFieldDescV1 : Avtp_CshFieldDescV0;

        for (uint8_t i = 0; i < AVTPDU_CSH_FIELD_MAX; i++) {
            assert_int_equal(tscfDesc[i].quadlet, cshDesc[i].quadlet);
            assert_int_equal(tscfDesc[i].offset, cshDesc[i].offset);
            assert_int_equal(tscfDesc[i].bits, cshDesc[i].bits);
        }
    }
}

static void tscf_typed_fields_v0(void **state)
{
    (void)state;
    uint8_t pdu[AVTP_TSCF_HEADER_LEN_V1];
    Avtp_Tscf_t *tscf = (Avtp_Tscf_t *)pdu;

    Avtp_Tscf_Init(tscf);

    for (uint8_t f = 0; f < AVTP_TSCF_FIELD_MAX; f++) {
        uint8_t bits = Avtp_TscfFieldDescV0[f].bits;
        uint64_t value = 0xA5A5A5A5A5A5A5A5ULL ^ (uint64_t)f;
        uint64_t expected = mask_field_value(bits, value);
        Avtp_TscfFields_t field = (Avtp_TscfFields_t)f;

        Avtp_Tscf_SetField_V0(tscf, field, value);
        assert_int_equal(Avtp_Tscf_GetField_V0(tscf, field), expected);
        assert_int_equal(Avtp_Tscf_GetField(tscf, field), expected);
        assert_int_equal(Avtp_GetField(Avtp_TscfFieldDescV0, AVTP_TSCF_FIELD_MAX, pdu, f),
                         expected);
    }
}

static void tscf_typed_fields_v1(void **state)
{
    (void)state;
    uint8_t pdu[AVTP_TSCF_HEADER_LEN_V1];
    Avtp_TscfV1_t *tscf = (Avtp_TscfV1_t *)pdu;

    Avtp_Tscf_InitV1(tscf);

    for (uint8_t f = 0; f < AVTP_TSCF_FIELD_MAX; f++) {
        uint8_t bits = Avtp_TscfFieldDescV1[f].bits;
        uint64_t value = 0x5A5A5A5A5A5A5A5AULL ^ (uint64_t)f;
        uint64_t expected = mask_field_value(bits, value);
        Avtp_TscfFields_t field = (Avtp_TscfFields_t)f;

        Avtp_Tscf_SetField_V1(tscf, field, value);
        assert_int_equal(Avtp_Tscf_GetField_V1(tscf, field), expected);
        assert_int_equal(Avtp_Tscf_GetField((Avtp_Tscf_t *)tscf, field), expected);
        assert_int_equal(Avtp_GetField(Avtp_TscfFieldDescV1, AVTP_TSCF_FIELD_MAX, pdu, f),
                         expected);
    }
}

static void tscf_typed_named(void **state)
{
    (void)state;
    uint8_t pdu[AVTP_TSCF_HEADER_LEN_V1];
    Avtp_Tscf_t *v0 = (Avtp_Tscf_t *)pdu;
    Avtp_TscfV1_t *v1 = (Avtp_TscfV1_t *)pdu;

    /* Version 0. */
    Avtp_Tscf_Init(v0);
    Avtp_Tscf_SetSv_V0(v0, true);
    Avtp_Tscf_SetSequenceNum_V0(v0, 0xAB);
    Avtp_Tscf_SetStreamId_V0(v0, 0x0102030405060708ULL);
    Avtp_Tscf_SetAvtpTimestamp_V0(v0, 0x80C0FFEE);
    Avtp_Tscf_SetStreamDataLength_V0(v0, 0x0ABC);

    assert_true(Avtp_Tscf_IsSv_V0(v0));
    assert_int_equal(Avtp_Tscf_GetSequenceNum_V0(v0), 0xAB);
    assert_int_equal(Avtp_Tscf_GetSequenceNumLsb_V0(v0), 0xAB);
    assert_int_equal(Avtp_Tscf_GetStreamId_V0(v0), 0x0102030405060708ULL);
    assert_int_equal(Avtp_Tscf_GetAvtpTimestamp_V0(v0), 0x80C0FFEE);
    assert_int_equal(Avtp_Tscf_GetStreamDataLength_V0(v0), 0x0ABC);
    assert_int_equal(Avtp_Tscf_GetPtpGrandmasterIdentity_V0(v0), 0);

    /* The version-dispatched accessors agree with the version 0 variants. */
    assert_int_equal(Avtp_Tscf_GetSequenceNum(v0), Avtp_Tscf_GetSequenceNum_V0(v0));
    assert_int_equal(Avtp_Tscf_GetSequenceNumLsb(v0), Avtp_Tscf_GetSequenceNumLsb_V0(v0));
    assert_int_equal(Avtp_Tscf_GetStreamId(v0), Avtp_Tscf_GetStreamId_V0(v0));
    assert_int_equal(Avtp_Tscf_GetAvtpTimestamp(v0), Avtp_Tscf_GetAvtpTimestamp_V0(v0));
    assert_int_equal(Avtp_Tscf_GetStreamDataLength(v0), Avtp_Tscf_GetStreamDataLength_V0(v0));

    /* Version 1. */
    Avtp_Tscf_InitV1(v1);
    Avtp_Tscf_SetSv_V1(v1, true);
    Avtp_Tscf_SetSequenceNum_V1(v1, 0x12345678);
    Avtp_Tscf_SetStreamId_V1(v1, 0x1122334455667788ULL);
    Avtp_Tscf_SetAvtpTimestamp_V1(v1, 0x99AABBCCDDEEFF00ULL);
    Avtp_Tscf_SetPtpGrandmasterIdentity_V1(v1, 0x0F1E2D3C4B5A6978ULL);
    Avtp_Tscf_SetStreamDataLength_V1(v1, 0x0DEF);

    assert_true(Avtp_Tscf_IsSv_V1(v1));
    assert_int_equal(Avtp_Tscf_GetSequenceNum_V1(v1), 0x12345678);
    /* sequence_num_lsb copy in format_specific_data_0 (byte 2 of quadlet 0). */
    assert_int_equal(Avtp_Tscf_GetSequenceNumLsb_V1(v1), 0x78);
    assert_int_equal(pdu[2], 0x78);
    assert_int_equal(Avtp_Tscf_GetStreamId_V1(v1), 0x1122334455667788ULL);
    assert_int_equal(Avtp_Tscf_GetAvtpTimestamp_V1(v1), 0x99AABBCCDDEEFF00ULL);
    assert_int_equal(Avtp_Tscf_GetPtpGrandmasterIdentity_V1(v1), 0x0F1E2D3C4B5A6978ULL);
    assert_int_equal(Avtp_Tscf_GetStreamDataLength_V1(v1), 0x0DEF);

    /* The version-dispatched accessors agree with the version 1 variants. */
    assert_int_equal(Avtp_Tscf_GetSequenceNum(v0), Avtp_Tscf_GetSequenceNum_V1(v1));
    assert_int_equal(Avtp_Tscf_GetSequenceNumLsb(v0), Avtp_Tscf_GetSequenceNumLsb_V1(v1));
    assert_int_equal(Avtp_Tscf_GetStreamId(v0), Avtp_Tscf_GetStreamId_V1(v1));
    assert_int_equal(Avtp_Tscf_GetAvtpTimestamp(v0), Avtp_Tscf_GetAvtpTimestamp_V1(v1));
    assert_int_equal(Avtp_Tscf_GetPtpGrandmasterIdentity(v0),
                     Avtp_Tscf_GetPtpGrandmasterIdentity_V1(v1));
    assert_int_equal(Avtp_Tscf_GetStreamDataLength(v0), Avtp_Tscf_GetStreamDataLength_V1(v1));
}

static void tscf_typed_helpers(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t payload[4] = {0xDE, 0xAD, 0xBE, 0xEF};

    Avtp_Tscf_Init((Avtp_Tscf_t *)pdu);
    assert_int_equal(Avtp_Tscf_GetHeaderLen_V0((Avtp_Tscf_t *)pdu), AVTP_TSCF_HEADER_LEN_V0);
    assert_ptr_equal(Avtp_Tscf_GetPayload_V0((Avtp_Tscf_t *)pdu), pdu + AVTP_TSCF_HEADER_LEN_V0);
    Avtp_Tscf_SetPayload_V0((Avtp_Tscf_t *)pdu, payload, sizeof(payload));
    assert_memory_equal(pdu + AVTP_TSCF_HEADER_LEN_V0, payload, sizeof(payload));

    Avtp_Tscf_InitV1((Avtp_TscfV1_t *)pdu);
    assert_int_equal(Avtp_Tscf_GetHeaderLen_V1((Avtp_TscfV1_t *)pdu), AVTP_TSCF_HEADER_LEN_V1);
    assert_ptr_equal(Avtp_Tscf_GetPayload_V1((Avtp_TscfV1_t *)pdu), pdu + AVTP_TSCF_HEADER_LEN_V1);
    Avtp_Tscf_SetPayload_V1((Avtp_TscfV1_t *)pdu, payload, sizeof(payload));
    assert_memory_equal(pdu + AVTP_TSCF_HEADER_LEN_V1, payload, sizeof(payload));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(tscf_init),
        cmocka_unit_test(tscf_init_v1),
        cmocka_unit_test(tscf_v0_layout),
        cmocka_unit_test(tscf_v1_layout),
        cmocka_unit_test(tscf_is_valid),
        cmocka_unit_test(tscf_payload),
        cmocka_unit_test(tscf_header_coverage),
        cmocka_unit_test(tscf_common_field_consistency),
        cmocka_unit_test(tscf_typed_fields_v0),
        cmocka_unit_test(tscf_typed_fields_v1),
        cmocka_unit_test(tscf_typed_named),
        cmocka_unit_test(tscf_typed_helpers),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
