/*
 * Copyright (c) 2018, Intel Corporation
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
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
extern "C" {
#include <cmocka.h>
}
#include <arpa/inet.h>
#include <stdio.h>
#include <errno.h>

#include "avtp/CommonHeader.h"
#include "avtp/Crf.h"

static void crf_get_field_null_pdu(void **state)
{
    int res;
    uint64_t val;

    res = avtp_crf_pdu_get(NULL, AVTP_CRF_FIELD_SV, &val);

    assert_int_equal(res, -EINVAL);
}

static void crf_get_field_null_val(void **state)
{
    int res;
    struct avtp_crf_pdu pdu = { 0 };

    res = avtp_crf_pdu_get(&pdu, AVTP_CRF_FIELD_SV, NULL);

    assert_int_equal(res, -EINVAL);
}

static void crf_get_field_invalid_field(void **state)
{
    int res;
    uint64_t val;
    struct avtp_crf_pdu pdu = { 0 };

    res = avtp_crf_pdu_get(&pdu, AVTP_CRF_FIELD_MAX, &val);

    assert_int_equal(res, -EINVAL);
}

static void crf_get_field_sv(void **state)
{
    int res;
    uint64_t val;
    struct avtp_crf_pdu pdu = { 0 };

    /* Set the 'sv' field to 1 */
    pdu.subtype_data = htonl(0x00800000);

    res = avtp_crf_pdu_get(&pdu, AVTP_CRF_FIELD_SV, &val);

    assert_int_equal(res, 0);
    assert_true(val == 1);
}

static void crf_get_field_mr(void **state)
{
    int res;
    uint64_t val;
    struct avtp_crf_pdu pdu = { 0 };

    /* Set the 'mr' field to 1 */
    pdu.subtype_data = htonl(0x00080000);

    res = avtp_crf_pdu_get(&pdu, AVTP_CRF_FIELD_MR, &val);

    assert_int_equal(res, 0);
    assert_true(val == 1);
}

static void ctf_get_field_fs(void **state)
{
    int res;
    uint64_t val;
    struct avtp_crf_pdu pdu = { 0 };

    /* Set the 'fs' field to 1 */
    pdu.subtype_data = htonl(0x00020000);

    res = avtp_crf_pdu_get(&pdu, AVTP_CRF_FIELD_FS, &val);

    assert_int_equal(res, 0);
    assert_true(val == 1);
}

static void crf_get_field_tu(void **state)
{
    int res;
    uint64_t val;
    struct avtp_crf_pdu pdu = { 0 };

    /* Set the 'tu' field to 1 */
    pdu.subtype_data = htonl(0x00010000);

    res = avtp_crf_pdu_get(&pdu, AVTP_CRF_FIELD_TU, &val);

    assert_int_equal(res, 0);
    assert_true(val == 1);
}

static void crf_get_field_seq_num(void **state)
{
    int res;
    uint64_t val;
    struct avtp_crf_pdu pdu = { 0 };

    /* Set the 'seq_num' field to 0xBB */
    pdu.subtype_data = htonl(0x0000BB00);

    res = avtp_crf_pdu_get(&pdu, AVTP_CRF_FIELD_SEQ_NUM, &val);

    assert_int_equal(res, 0);
    assert_true(val == 0xBB);
}

static void crf_get_field_type(void **state)
{
    int res;
    uint64_t val;
    struct avtp_crf_pdu pdu = { 0 };

    /* Set the 'type' field to AVTP_CRF_TYPE_VIDEO_LINE */
    pdu.subtype_data = htonl(0x00000003);

    res = avtp_crf_pdu_get(&pdu, AVTP_CRF_FIELD_TYPE, &val);

    assert_int_equal(res, 0);
    assert_true(val == AVTP_CRF_TYPE_VIDEO_LINE);
}

static void crf_get_field_stream_id(void **state)
{
    int res;
    uint64_t val;
    struct avtp_crf_pdu pdu = { 0 };

    /* Set the 'stream_id' field to 0xAABBCCDDEEFF0002 */
    pdu.stream_id = htobe64(0xAABBCCDDEEFF0002);

    res = avtp_crf_pdu_get(&pdu, AVTP_CRF_FIELD_STREAM_ID, &val);

    assert_int_equal(res, 0);
    assert_true(val == 0xAABBCCDDEEFF0002);
}

static void crf_get_field_pull(void **state)
{
    int res;
    uint64_t val;
    struct avtp_crf_pdu pdu = { 0 };

    /* Set the 'pull' field to AVTP_CRF_PULL_MULT_BY_1_001 */
    pdu.packet_info = htobe64(0x4000000000000000);

    res = avtp_crf_pdu_get(&pdu, AVTP_CRF_FIELD_PULL, &val);

    assert_int_equal(res, 0);
    assert_true(val == AVTP_CRF_PULL_MULT_BY_1_001);
}

static void crf_get_field_base_freq(void **state)
{
    int res;
    uint64_t val;
    struct avtp_crf_pdu pdu = { 0 };

    /* Set the 'base_freq' field to 0x1FFFFFFF */
    pdu.packet_info = htobe64(0x1FFFFFFF00000000);

    res = avtp_crf_pdu_get(&pdu, AVTP_CRF_FIELD_BASE_FREQ, &val);

    assert_int_equal(res, 0);
    assert_true(val == 0x1FFFFFFF);
}

static void crf_get_field_crf_data_len(void **state)
{
    int res;
    uint64_t val;
    struct avtp_crf_pdu pdu = { 0 };

    /* Set the 'crf_data_len' field to 0xABCD */
    pdu.packet_info = htobe64(0x00000000ABCD0000);

    res = avtp_crf_pdu_get(&pdu, AVTP_CRF_FIELD_CRF_DATA_LEN, &val);

    assert_int_equal(res, 0);
    assert_true(val == 0xABCD);
}

static void crf_get_field_timestamp_interval(void **state)
{
    int res;
    uint64_t val;
    struct avtp_crf_pdu pdu = { 0 };

    /* Set the 'timestamp_interval' field to 0xABCD */
    pdu.packet_info = htobe64(0x000000000000ABCD);

    res = avtp_crf_pdu_get(&pdu, AVTP_CRF_FIELD_TIMESTAMP_INTERVAL, &val);

    assert_int_equal(res, 0);
    assert_true(val == 0xABCD);
}

static void crf_set_field_null_pdu(void **state)
{
    int res;

    res = avtp_crf_pdu_set(NULL, AVTP_CRF_FIELD_SV, 1);

    assert_int_equal(res, -EINVAL);
}

static void crf_set_field_invalid_field(void **state)
{
    int res;
    struct avtp_crf_pdu pdu = { 0 };

    res = avtp_crf_pdu_set(&pdu, AVTP_CRF_FIELD_MAX, 1);

    assert_int_equal(res, -EINVAL);
}

static void crf_set_field_sv(void **state)
{
    int res;
    struct avtp_crf_pdu pdu = { 0 };

    res = avtp_crf_pdu_set(&pdu, AVTP_CRF_FIELD_SV, 1);

    assert_int_equal(res, 0);
    assert_true(ntohl(pdu.subtype_data) == 0x00800000);
    assert_true(pdu.stream_id == 0);
    assert_true(pdu.packet_info == 0);
}

static void crf_set_field_mr(void **state)
{
    int res;
    struct avtp_crf_pdu pdu = { 0 };

    res = avtp_crf_pdu_set(&pdu, AVTP_CRF_FIELD_MR, 1);

    assert_int_equal(res, 0);
    assert_true(ntohl(pdu.subtype_data) == 0x00080000);
    assert_true(pdu.stream_id == 0);
    assert_true(pdu.packet_info == 0);
}

static void crf_set_field_fs(void **state)
{
    int res;
    struct avtp_crf_pdu pdu = { 0 };

    res = avtp_crf_pdu_set(&pdu, AVTP_CRF_FIELD_FS, 1);

    assert_int_equal(res, 0);
    assert_true(ntohl(pdu.subtype_data) == 0x00020000);
    assert_true(pdu.stream_id == 0);
    assert_true(pdu.packet_info == 0);
}

static void crf_set_field_tu(void **state)
{
    int res;
    struct avtp_crf_pdu pdu = { 0 };

    res = avtp_crf_pdu_set(&pdu, AVTP_CRF_FIELD_TU, 1);

    assert_int_equal(res, 0);
    assert_true(ntohl(pdu.subtype_data) == 0x00010000);
    assert_true(pdu.stream_id == 0);
    assert_true(pdu.packet_info == 0);
}

static void crf_set_field_seq_num(void **state)
{
    int res;
    struct avtp_crf_pdu pdu = { 0 };

    res = avtp_crf_pdu_set(&pdu, AVTP_CRF_FIELD_SEQ_NUM, 0xAA);

    assert_int_equal(res, 0);
    assert_true(ntohl(pdu.subtype_data) == 0x0000AA00);
    assert_true(pdu.stream_id == 0);
    assert_true(pdu.packet_info == 0);
}

static void crf_set_field_type(void **state)
{
    int res;
    struct avtp_crf_pdu pdu = { 0 };

    res = avtp_crf_pdu_set(&pdu, AVTP_CRF_FIELD_TYPE,
                          AVTP_CRF_TYPE_AUDIO_SAMPLE);

    assert_int_equal(res, 0);
    assert_true(ntohl(pdu.subtype_data) == 0x00000001);
    assert_true(pdu.stream_id == 0);
    assert_true(pdu.packet_info == 0);
}

static void crf_set_field_stream_id(void **state)
{
    int res;
    struct avtp_crf_pdu pdu = { 0 };

    res = avtp_crf_pdu_set(&pdu, AVTP_CRF_FIELD_STREAM_ID,
                              0xAABBCCDDEEFF0002);

    assert_int_equal(res, 0);
    assert_true(be64toh(pdu.stream_id) == 0xAABBCCDDEEFF0002);
    assert_true(pdu.subtype_data == 0);
    assert_true(pdu.packet_info == 0);
}

static void crf_set_field_pull(void **state)
{
    int res;
    struct avtp_crf_pdu pdu = { 0 };

    res = avtp_crf_pdu_set(&pdu, AVTP_CRF_FIELD_PULL,
                          AVTP_CRF_PULL_MULT_BY_1_001);

    assert_int_equal(res, 0);
    assert_true(pdu.subtype_data == 0);
    assert_true(pdu.stream_id == 0);
    assert_true(be64toh(pdu.packet_info) == 0x4000000000000000);
}

static void crf_set_field_base_freq(void **state)
{
    int res;
    struct avtp_crf_pdu pdu = { 0 };

    res = avtp_crf_pdu_set(&pdu, AVTP_CRF_FIELD_BASE_FREQ, 0x1FFFFFFF);

    assert_int_equal(res, 0);
    assert_true(pdu.subtype_data == 0);
    assert_true(pdu.stream_id == 0);
    assert_true(be64toh(pdu.packet_info) == 0x1FFFFFFF00000000);
}

static void crf_set_field_crf_data_len(void **state)
{
    int res;
    struct avtp_crf_pdu pdu = { 0 };

    res = avtp_crf_pdu_set(&pdu, AVTP_CRF_FIELD_CRF_DATA_LEN, 0xABCD);

    assert_int_equal(res, 0);
    assert_true(be64toh(pdu.packet_info) == 0x00000000ABCD0000);
    assert_true(pdu.subtype_data == 0);
    assert_true(pdu.stream_id == 0);
}

static void crf_set_field_timestamp_interval(void **state)
{
    int res;
    struct avtp_crf_pdu pdu = { 0 };

    res = avtp_crf_pdu_set(&pdu, AVTP_CRF_FIELD_TIMESTAMP_INTERVAL, 0xABCD);

    assert_int_equal(res, 0);
    assert_true(be64toh(pdu.packet_info) == 0x000000000000ABCD);
    assert_true(pdu.subtype_data == 0);
    assert_true(pdu.stream_id == 0);
}

static void crf_pdu_init_null_pdu(void **state)
{
    int res;

    res = avtp_crf_pdu_init(NULL);

    assert_int_equal(res, -EINVAL);
}

static void crf_pdu_init(void **state)
{
    int res;
    struct avtp_crf_pdu pdu;

    res = avtp_crf_pdu_init(&pdu);

    assert_int_equal(res, 0);
    assert_true(ntohl(pdu.subtype_data) == 0x04800000);
    assert_true(pdu.stream_id == 0);
    assert_true(pdu.packet_info == 0);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(crf_get_field_null_pdu),
        cmocka_unit_test(crf_get_field_null_val),
        cmocka_unit_test(crf_get_field_invalid_field),
        cmocka_unit_test(crf_get_field_sv),
        cmocka_unit_test(crf_get_field_mr),
        cmocka_unit_test(ctf_get_field_fs),
        cmocka_unit_test(crf_get_field_tu),
        cmocka_unit_test(crf_get_field_seq_num),
        cmocka_unit_test(crf_get_field_type),
        cmocka_unit_test(crf_get_field_stream_id),
        cmocka_unit_test(crf_get_field_pull),
        cmocka_unit_test(crf_get_field_base_freq),
        cmocka_unit_test(crf_get_field_crf_data_len),
        cmocka_unit_test(crf_get_field_timestamp_interval),
        cmocka_unit_test(crf_set_field_null_pdu),
        cmocka_unit_test(crf_set_field_invalid_field),
        cmocka_unit_test(crf_set_field_sv),
        cmocka_unit_test(crf_set_field_mr),
        cmocka_unit_test(crf_set_field_fs),
        cmocka_unit_test(crf_set_field_tu),
        cmocka_unit_test(crf_set_field_seq_num),
        cmocka_unit_test(crf_set_field_type),
        cmocka_unit_test(crf_set_field_stream_id),
        cmocka_unit_test(crf_set_field_pull),
        cmocka_unit_test(crf_set_field_base_freq),
        cmocka_unit_test(crf_set_field_crf_data_len),
        cmocka_unit_test(crf_set_field_timestamp_interval),
        cmocka_unit_test(crf_pdu_init_null_pdu),
        cmocka_unit_test(crf_pdu_init),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
