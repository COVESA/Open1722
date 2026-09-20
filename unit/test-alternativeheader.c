/*
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

#include "avtp/AlternativeHeader.h"

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

static void alternative_header_lengths(void **state)
{
    (void)state;

    assert_int_equal(AVTPDU_AH_LEN_V0, 4);
    assert_int_equal(AVTPDU_AH_LEN_V1, 16);
    assert_int_equal(sizeof(Avtp_AlternativeHeader_t), AVTPDU_AH_LEN_V1);
}

static void alternative_header_typed_fields_v0(void **state)
{
    (void)state;
    uint8_t pdu[AVTPDU_AH_LEN_V1];
    Avtp_AlternativeHeader_t *ah = (Avtp_AlternativeHeader_t *)pdu;

    memset(pdu, 0, sizeof(pdu));
    Avtp_CommonHeader_SetVersion((Avtp_CommonHeader_t *)ah, AVTP_VERSION_0);

    for (uint8_t f = 0; f < AVTPDU_AH_FIELD_MAX; f++) {
        uint8_t bits = Avtp_AhFieldDescV0[f].bits;
        uint64_t value = 0xA5A5A5A5A5A5A5A5ULL ^ (uint64_t)f;
        uint64_t expected = mask_field_value(bits, value);
        Avtp_AlternativeHeaderField_t field = (Avtp_AlternativeHeaderField_t)f;

        Avtp_AlternativeHeader_SetField_V0(ah, field, value);
        assert_int_equal(Avtp_AlternativeHeader_GetField_V0(ah, field), expected);
        assert_int_equal(Avtp_AlternativeHeader_GetField(ah, field), expected);
        assert_int_equal(Avtp_GetField(Avtp_AhFieldDescV0, AVTPDU_AH_FIELD_MAX, pdu, f), expected);
    }
}

static void alternative_header_typed_fields_v1(void **state)
{
    (void)state;
    uint8_t pdu[AVTPDU_AH_LEN_V1];
    Avtp_AlternativeHeader_t *ah = (Avtp_AlternativeHeader_t *)pdu;

    memset(pdu, 0, sizeof(pdu));
    Avtp_CommonHeader_SetVersion((Avtp_CommonHeader_t *)ah, AVTP_VERSION_1);

    for (uint8_t f = 0; f < AVTPDU_AH_FIELD_MAX; f++) {
        uint8_t bits = Avtp_AhFieldDescV1[f].bits;
        uint64_t value = 0x5A5A5A5A5A5A5A5AULL ^ (uint64_t)f;
        uint64_t expected = mask_field_value(bits, value);
        Avtp_AlternativeHeaderField_t field = (Avtp_AlternativeHeaderField_t)f;

        Avtp_AlternativeHeader_SetField_V1(ah, field, value);
        assert_int_equal(Avtp_AlternativeHeader_GetField_V1(ah, field), expected);
        assert_int_equal(Avtp_AlternativeHeader_GetField(ah, field), expected);
        assert_int_equal(Avtp_GetField(Avtp_AhFieldDescV1, AVTPDU_AH_FIELD_MAX, pdu, f), expected);
    }
}

static void alternative_header_typed_named_v1(void **state)
{
    (void)state;
    uint8_t pdu[AVTPDU_AH_LEN_V1];
    Avtp_AlternativeHeader_t *ah = (Avtp_AlternativeHeader_t *)pdu;

    memset(pdu, 0, sizeof(pdu));
    Avtp_CommonHeader_SetVersion((Avtp_CommonHeader_t *)ah, AVTP_VERSION_1);

    Avtp_AlternativeHeader_SetSequenceNum_V1(ah, 0x12345678);
    Avtp_AlternativeHeader_SetPtpGrandmasterIdentity_V1(ah, 0x99AABBCCDDEEFF00ULL);

    assert_int_equal(Avtp_AlternativeHeader_GetSequenceNum_V1(ah), 0x12345678);
    assert_int_equal(Avtp_AlternativeHeader_GetPtpGrandmasterIdentity_V1(ah),
                     0x99AABBCCDDEEFF00ULL);

    /* The version-dispatched accessors agree with the version 1 variants. */
    assert_int_equal(Avtp_AlternativeHeader_GetSequenceNum(ah),
                     Avtp_AlternativeHeader_GetSequenceNum_V1(ah));
    assert_int_equal(Avtp_AlternativeHeader_GetPtpGrandmasterIdentity(ah),
                     Avtp_AlternativeHeader_GetPtpGrandmasterIdentity_V1(ah));
}

static void alternative_header_typed_absent_fields(void **state)
{
    (void)state;
    uint8_t pdu[AVTPDU_AH_LEN_V1];
    uint8_t snapshot[AVTPDU_AH_LEN_V1];
    Avtp_AlternativeHeader_t *ah = (Avtp_AlternativeHeader_t *)pdu;

    memset(pdu, 0, sizeof(pdu));
    Avtp_CommonHeader_SetVersion((Avtp_CommonHeader_t *)ah, AVTP_VERSION_0);

    /* sequence_num and ptp_grandmaster_identity do not exist in v0. */
    assert_int_equal(Avtp_AlternativeHeader_GetSequenceNum_V0(ah), 0);
    assert_int_equal(Avtp_AlternativeHeader_GetPtpGrandmasterIdentity_V0(ah), 0);

    memcpy(snapshot, pdu, sizeof(snapshot));
    Avtp_AlternativeHeader_SetSequenceNum_V0(ah, 0xFFFFFFFF);
    Avtp_AlternativeHeader_SetPtpGrandmasterIdentity_V0(ah, 0xFFFFFFFFFFFFFFFFULL);
    assert_memory_equal(snapshot, pdu, sizeof(snapshot));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(alternative_header_lengths),
        cmocka_unit_test(alternative_header_typed_fields_v0),
        cmocka_unit_test(alternative_header_typed_fields_v1),
        cmocka_unit_test(alternative_header_typed_named_v1),
        cmocka_unit_test(alternative_header_typed_absent_fields),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
