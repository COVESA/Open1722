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

#include "avtp/CommonStreamHeader.h"

static uint32_t read_quadlet(const uint8_t *pdu, size_t quadlet)
{
    uint32_t word;

    memcpy(&word, pdu + (quadlet * 4), sizeof(word));
    return ntohl(word);
}

static void common_stream_header_lengths(void **state)
{
    (void)state;

    assert_int_equal(AVTPDU_CSH_LEN_V0, 24);
    assert_int_equal(AVTPDU_CSH_LEN_V1, 40);
    assert_int_equal(sizeof(Avtp_CommonStreamHeader_t), AVTPDU_CSH_LEN_V1);
}

static void common_stream_header_v0_layout(void **state)
{
    (void)state;
    uint8_t pdu[AVTPDU_CSH_LEN_V0];
    Avtp_CommonStreamHeader_t *csh = (Avtp_CommonStreamHeader_t *)pdu;

    memset(pdu, 0, sizeof(pdu));
    Avtp_CommonHeader_SetVersion((Avtp_CommonHeader_t *)csh, AVTP_VERSION_0);

    assert_int_equal(Avtp_CommonStreamHeader_GetVersion(csh), AVTP_VERSION_0);
    assert_int_equal(Avtp_CommonStreamHeader_GetHeaderLen(csh), AVTPDU_CSH_LEN_V0);
    assert_int_equal(Avtp_CommonStreamHeader_GetFormatOffset(csh), 0);

    Avtp_CommonStreamHeader_SetSv(csh, true);
    Avtp_CommonStreamHeader_SetMr(csh, true);
    Avtp_CommonStreamHeader_SetFsd(csh, 0x3);
    Avtp_CommonStreamHeader_SetTv(csh, true);
    Avtp_CommonStreamHeader_SetTu(csh, true);

    assert_true(Avtp_CommonStreamHeader_IsSv(csh));
    assert_true(Avtp_CommonStreamHeader_IsMr(csh));
    assert_int_equal(Avtp_CommonStreamHeader_GetFsd(csh), 0x3);
    assert_true(Avtp_CommonStreamHeader_IsTv(csh));
    assert_true(Avtp_CommonStreamHeader_IsTu(csh));
    assert_int_equal(read_quadlet(pdu, 0), 0x008F0001);

    Avtp_CommonStreamHeader_SetFormatSpecificData1(csh, 0x5A);
    assert_int_equal(Avtp_CommonStreamHeader_GetFormatSpecificData1(csh), 0x5A);
    assert_int_equal(read_quadlet(pdu, 0), 0x008F00B5);

    Avtp_CommonStreamHeader_SetSequenceNum(csh, 0xAB);
    assert_int_equal(Avtp_CommonStreamHeader_GetSequenceNum(csh), 0xAB);
    assert_int_equal(read_quadlet(pdu, 0), 0x008FABB5);

    Avtp_CommonStreamHeader_SetStreamId(csh, 0xAABBCCDDEEFF0011ULL);
    assert_int_equal(Avtp_CommonStreamHeader_GetStreamId(csh), 0xAABBCCDDEEFF0011ULL);
    assert_int_equal(read_quadlet(pdu, 1), 0xAABBCCDD);
    assert_int_equal(read_quadlet(pdu, 2), 0xEEFF0011);

    Avtp_CommonStreamHeader_SetAvtpTimestamp(csh, 0x80C0FFEE);
    assert_int_equal(Avtp_CommonStreamHeader_GetAvtpTimestamp(csh), 0x80C0FFEE);
    assert_int_equal(read_quadlet(pdu, 3), 0x80C0FFEE);

    Avtp_CommonStreamHeader_SetStreamDataLength(csh, 0x1234);
    assert_int_equal(Avtp_CommonStreamHeader_GetStreamDataLength(csh), 0x1234);
    assert_int_equal(read_quadlet(pdu, 5), 0x12340000);
}

static void common_stream_header_v1_layout(void **state)
{
    (void)state;
    uint8_t pdu[AVTPDU_CSH_LEN_V1];
    Avtp_CommonStreamHeader_t *csh = (Avtp_CommonStreamHeader_t *)pdu;

    memset(pdu, 0, sizeof(pdu));
    Avtp_CommonHeader_SetVersion((Avtp_CommonHeader_t *)csh, AVTP_VERSION_1);

    assert_int_equal(Avtp_CommonStreamHeader_GetVersion(csh), AVTP_VERSION_1);
    assert_int_equal(Avtp_CommonStreamHeader_GetHeaderLen(csh), AVTPDU_CSH_LEN_V1);
    assert_int_equal(Avtp_CommonStreamHeader_GetFormatOffset(csh), 16);

    Avtp_CommonStreamHeader_SetSv(csh, true);
    Avtp_CommonStreamHeader_SetMr(csh, true);
    Avtp_CommonStreamHeader_SetFsd(csh, 0x1);
    Avtp_CommonStreamHeader_SetTv(csh, true);
    Avtp_CommonStreamHeader_SetFormatSpecificData0(csh, 0x42);
    Avtp_CommonStreamHeader_SetFormatSpecificData1(csh, 0x5A);
    Avtp_CommonStreamHeader_SetTu(csh, true);

    assert_true(Avtp_CommonStreamHeader_IsSv(csh));
    assert_true(Avtp_CommonStreamHeader_IsMr(csh));
    assert_int_equal(Avtp_CommonStreamHeader_GetFsd(csh), 0x1);
    assert_true(Avtp_CommonStreamHeader_IsTv(csh));
    assert_int_equal(Avtp_CommonStreamHeader_GetFormatSpecificData0(csh), 0x42);
    assert_int_equal(Avtp_CommonStreamHeader_GetFormatSpecificData1(csh), 0x5A);
    assert_true(Avtp_CommonStreamHeader_IsTu(csh));
    assert_int_equal(read_quadlet(pdu, 0), 0x9B42B5);

    Avtp_CommonStreamHeader_SetSequenceNum(csh, 0x12345678);
    assert_int_equal(Avtp_CommonStreamHeader_GetSequenceNum(csh), 0x12345678);
    assert_int_equal(read_quadlet(pdu, 3), 0x12345678);

    Avtp_CommonStreamHeader_SetStreamId(csh, 0x0102030405060708ULL);
    assert_int_equal(Avtp_CommonStreamHeader_GetStreamId(csh), 0x0102030405060708ULL);
    assert_int_equal(read_quadlet(pdu, 1), 0x01020304);
    assert_int_equal(read_quadlet(pdu, 2), 0x05060708);

    Avtp_CommonStreamHeader_SetAvtpTimestamp(csh, 0x1122334455667788ULL);
    assert_int_equal(Avtp_CommonStreamHeader_GetAvtpTimestamp(csh), 0x1122334455667788ULL);
    assert_int_equal(read_quadlet(pdu, 4), 0x11223344);
    assert_int_equal(read_quadlet(pdu, 5), 0x55667788);

    Avtp_CommonStreamHeader_SetPtpGrandmasterIdentity(csh, 0x99AABBCCDDEEFF00ULL);
    assert_int_equal(Avtp_CommonStreamHeader_GetPtpGrandmasterIdentity(csh), 0x99AABBCCDDEEFF00ULL);
    assert_int_equal(read_quadlet(pdu, 6), 0x99AABBCC);
    assert_int_equal(read_quadlet(pdu, 7), 0xDDEEFF00);

    Avtp_CommonStreamHeader_SetStreamDataLength(csh, 0x0ABC);
    assert_int_equal(Avtp_CommonStreamHeader_GetStreamDataLength(csh), 0x0ABC);
    assert_int_equal(read_quadlet(pdu, 9), 0x0ABC0000);
}

static void common_stream_header_absent_fields(void **state)
{
    (void)state;
    uint8_t pdu[AVTPDU_CSH_LEN_V0];
    uint8_t snapshot[AVTPDU_CSH_LEN_V0];
    Avtp_CommonStreamHeader_t *csh = (Avtp_CommonStreamHeader_t *)pdu;

    memset(pdu, 0, sizeof(pdu));
    Avtp_CommonHeader_SetVersion((Avtp_CommonHeader_t *)csh, AVTP_VERSION_0);

    /* format_specific_data_0 and ptp_grandmaster_identity do not exist in v0. */
    assert_int_equal(Avtp_CommonStreamHeader_GetFormatSpecificData0(csh), 0);
    assert_int_equal(Avtp_CommonStreamHeader_GetPtpGrandmasterIdentity(csh), 0);

    memcpy(snapshot, pdu, sizeof(snapshot));
    Avtp_CommonStreamHeader_SetFormatSpecificData0(csh, 0x42);
    Avtp_CommonStreamHeader_SetPtpGrandmasterIdentity(csh, 0xFFFFFFFFFFFFFFFFULL);
    assert_memory_equal(snapshot, pdu, sizeof(snapshot));
}

static void common_stream_header_no_overlap(void **state)
{
    (void)state;

    for (uint8_t version = 0; version <= 1; version++) {
        uint8_t coverage[AVTPDU_CSH_LEN_V1 * 8] = {0};
        const Avtp_FieldDescriptor_t *desc =
            version == AVTP_VERSION_1 ? Avtp_CshFieldDescV1 : Avtp_CshFieldDescV0;

        for (uint8_t i = 0; i < AVTPDU_CSH_FIELD_MAX; i++) {
            uint8_t quadlet = desc[i].quadlet;
            uint8_t offset = desc[i].offset;
            uint8_t bits = desc[i].bits;

            for (uint8_t b = 0; b < bits; b++) {
                size_t bit = ((size_t)quadlet * 32) + offset + b;

                assert_true(bit < sizeof(coverage));
                assert_int_equal(coverage[bit], 0);
                coverage[bit] = 1;
            }
        }
    }
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(common_stream_header_lengths),
        cmocka_unit_test(common_stream_header_v0_layout),
        cmocka_unit_test(common_stream_header_v1_layout),
        cmocka_unit_test(common_stream_header_absent_fields),
        cmocka_unit_test(common_stream_header_no_overlap),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
