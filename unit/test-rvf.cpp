/*
 * Copyright (c) 2021, Fastree3D
 * Adrian Fiergolski <Adrian.Fiergolski@fastree3d.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of Fastree3D nor the names of its contributors
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

#include <alloca.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <setjmp.h>
extern "C" {
#include <cmocka.h>
}
#include <arpa/inet.h>
#include <stdio.h>
#include <errno.h>

#include "avtp/CommonHeader.h"
#include "avtp/Rvf.h"

static void rvf_get_field_null_pdu(void **state)
{
    int res;
    uint64_t val = 1;

    res = avtp_rvf_pdu_get(NULL, AVTP_RVF_FIELD_SV, &val);

    assert_int_equal(res, -EINVAL);
}

static void rvf_get_field_null_val(void **state)
{
    int res;
    struct avtp_stream_pdu pdu = { 0 };

    res = avtp_rvf_pdu_get(&pdu, AVTP_RVF_FIELD_SV, NULL);

    assert_int_equal(res, -EINVAL);
}

static void rvf_get_field_invalid_field(void **state)
{
    int res;
    uint64_t val = 1;
    struct avtp_stream_pdu pdu = { 0 };

    res = avtp_rvf_pdu_get(&pdu, AVTP_RVF_FIELD_MAX, &val);

    assert_int_equal(res, -EINVAL);
}

static void rvf_get_field_sv(void **state)
{
    int res;
    uint64_t val;
    struct avtp_stream_pdu pdu = { 0 };

    /* Set 'sv' field to 1. */
    pdu.subtype_data = htonl(0x00800000);
    // pdu.subtype_data = htonl(0x00000100);

    res = avtp_rvf_pdu_get(&pdu, AVTP_RVF_FIELD_SV, &val);


    assert_int_equal(res, 0);
    assert_true(val == 1);
}

static void rvf_get_field_mr(void **state)
{
    int res;
    uint64_t val;
    struct avtp_stream_pdu pdu = { 0 };

    /* Set 'mr' field to 1. */
    pdu.subtype_data = htonl(0x00080000);

    res = avtp_rvf_pdu_get(&pdu, AVTP_RVF_FIELD_MR, &val);

    assert_int_equal(res, 0);
    assert_true(val == 1);
}

static void rvf_get_field_tv(void **state)
{
    int res;
    uint64_t val;
    struct avtp_stream_pdu pdu = { 0 };

    /* Set 'tv' field to 1. */
    pdu.subtype_data = htonl(0x00010000);

    res = avtp_rvf_pdu_get(&pdu, AVTP_RVF_FIELD_TV, &val);

    assert_int_equal(res, 0);
    assert_true(val == 1);
}

static void rvf_get_field_seq_num(void **state)
{
    int res;
    uint64_t val;
    struct avtp_stream_pdu pdu = { 0 };

    /* Set 'sequence_num' field to 0x55. */
    pdu.subtype_data = htonl(0x00005500);

    res = avtp_rvf_pdu_get(&pdu, AVTP_RVF_FIELD_SEQ_NUM, &val);

    assert_int_equal(res, 0);
    assert_true(val == 0x55);
}

static void rvf_get_field_tu(void **state)
{
    int res;
    uint64_t val;
    struct avtp_stream_pdu pdu = { 0 };

    /* Set 'tu' field to 1. */
    pdu.subtype_data = htonl(0x00000001);

    res = avtp_rvf_pdu_get(&pdu, AVTP_RVF_FIELD_TU, &val);

    assert_int_equal(res, 0);
    assert_true(val == 1);
}

static void rvf_get_field_stream_id(void **state)
{
    int res;
    uint64_t val;
    struct avtp_stream_pdu pdu = { 0 };

    /* Set 'stream_id' field to 0xAABBCCDDEEFF0001. */
    pdu.stream_id = htobe64(0xAABBCCDDEEFF0001);

    res = avtp_rvf_pdu_get(&pdu, AVTP_RVF_FIELD_STREAM_ID, &val);

    assert_int_equal(res, 0);
    assert_true(val == 0xAABBCCDDEEFF0001);
}

static void rvf_get_field_timestamp(void **state)
{
    int res;
    uint64_t val;
    struct avtp_stream_pdu pdu = { 0 };

    /* Set 'avtp_timestamp' field to 0x80C0FFEE. */
    pdu.avtp_time = htonl(0x80C0FFEE);

    res = avtp_rvf_pdu_get(&pdu, AVTP_RVF_FIELD_TIMESTAMP, &val);

    assert_int_equal(res, 0);
    assert_true(val == 0x80C0FFEE);
}

static void rvf_get_field_active_pixels(void **state)
{
    int res;
    uint64_t val;
    struct avtp_stream_pdu pdu = { 0 };

    /* Set 'active_pixels' field to 0x20. */
    pdu.format_specific = htonl(0x00200000);

    res = avtp_rvf_pdu_get(&pdu, AVTP_RVF_FIELD_ACTIVE_PIXELS, &val);

    assert_int_equal(res, 0);
    assert_true(val == 0x20);
}

static void rvf_get_field_format_total_lines(void **state)
{
    int res;
    uint64_t val;
    struct avtp_stream_pdu pdu = { 0 };

    /* Set 'total_lines' field to 0x3C. */
    pdu.format_specific = htonl(0x0000003C);

    res = avtp_rvf_pdu_get(&pdu, AVTP_RVF_FIELD_TOTAL_LINES, &val);

    assert_int_equal(res, 0);
    assert_true(val == 0x3C);
}

static void rvf_get_field_data_len(void **state)
{
    int res;
    uint64_t val;
    struct avtp_stream_pdu pdu = { 0 };

    /* Set 'stream_data_length' field to 0xAAAA. */
    pdu.packet_info = htonl(0xAAAA0000);

    res = avtp_rvf_pdu_get(&pdu, AVTP_RVF_FIELD_STREAM_DATA_LEN, &val);

    assert_int_equal(res, 0);
    assert_true(val == 0xAAAA);
}

static void rvf_get_field_ap(void **state)
{
    int res;
    uint64_t val;
    struct avtp_stream_pdu pdu = { 0 };

    /* Set 'AP' field to 0x1. */
    pdu.packet_info = htonl(0x00008000);

    res = avtp_rvf_pdu_get(&pdu, AVTP_RVF_FIELD_AP, &val);

    assert_int_equal(res, 0);
    assert_true(val == 0x1);
}

static void rvf_get_field_f(void **state)
{
    int res;
    uint64_t val;
    struct avtp_stream_pdu pdu = { 0 };

    /* Set 'F' field to 0x1. */
    pdu.packet_info = htonl(0x00002000);

    res = avtp_rvf_pdu_get(&pdu, AVTP_RVF_FIELD_F, &val);

    assert_int_equal(res, 0);
    assert_true(val == 0x1);
}

static void rvf_get_field_ef(void **state)
{
    int res;
    uint64_t val;
    struct avtp_stream_pdu pdu = { 0 };

    /* Set 'EF' field to 0x1. */
    pdu.packet_info = htonl(0x00001000);

    res = avtp_rvf_pdu_get(&pdu, AVTP_RVF_FIELD_EF, &val);

    assert_int_equal(res, 0);
    assert_true(val == 0x1);
}

static void rvf_get_field_evt(void **state)
{
    int res;
    uint64_t val;
    struct avtp_stream_pdu pdu = { 0 };

    /* Set 'evt' field to 0xA. */
    pdu.packet_info = htonl(0x00000A00);

    res = avtp_rvf_pdu_get(&pdu, AVTP_RVF_FIELD_EVT, &val);

    assert_int_equal(res, 0);
    assert_true(val == 0xA);
}

static void rvf_get_field_pd(void **state)
{
    int res;
    uint64_t val;
    struct avtp_stream_pdu pdu = { 0 };

    /* Set 'PD' field to 0x1. */
    pdu.packet_info = htonl(0x00000080);

    res = avtp_rvf_pdu_get(&pdu, AVTP_RVF_FIELD_PD, &val);

    assert_int_equal(res, 0);
    assert_true(val == 0x1);
}

static void rvf_get_field_i(void **state)
{
    int res;
    uint64_t val;
    struct avtp_stream_pdu pdu = { 0 };

    /* Set 'I' field to 0x1. */
    pdu.packet_info = htonl(0x00000040);

    res = avtp_rvf_pdu_get(&pdu, AVTP_RVF_FIELD_I, &val);

    assert_int_equal(res, 0);
    assert_true(val == 0x1);
}

static void rvf_set_field_null_pdu(void **state)
{
    int res;

    res = avtp_rvf_pdu_set(NULL, AVTP_RVF_FIELD_SV, 1);

    assert_int_equal(res, -EINVAL);
}

static void rvf_set_field_invalid_field(void **state)
{
    int res;
    struct avtp_stream_pdu pdu = { 0 };

    res = avtp_rvf_pdu_set(&pdu, AVTP_RVF_FIELD_MAX, 1);

    assert_int_equal(res, -EINVAL);
}

static void rvf_set_field_sv(void **state)
{
    int res;
    struct avtp_stream_pdu pdu = { 0 };

    res = avtp_rvf_pdu_set(&pdu, AVTP_RVF_FIELD_SV, 1);

    assert_int_equal(res, 0);
    assert_true(ntohl(pdu.subtype_data) == 0x00800000);
    assert_true(pdu.stream_id == 0);
    assert_true(pdu.avtp_time == 0);
    assert_true(pdu.format_specific == 0);
    assert_true(pdu.packet_info == 0);
}

static void rvf_set_field_mr(void **state)
{
    int res;
    struct avtp_stream_pdu pdu = { 0 };

    res = avtp_rvf_pdu_set(&pdu, AVTP_RVF_FIELD_MR, 1);

    assert_int_equal(res, 0);
    assert_true(ntohl(pdu.subtype_data) == 0x00080000);
    assert_true(pdu.stream_id == 0);
    assert_true(pdu.avtp_time == 0);
    assert_true(pdu.format_specific == 0);
    assert_true(pdu.packet_info == 0);
}

static void rvf_set_field_tv(void **state)
{
    int res;
    struct avtp_stream_pdu pdu = { 0 };

    res = avtp_rvf_pdu_set(&pdu, AVTP_RVF_FIELD_TV, 1);

    assert_int_equal(res, 0);
    assert_true(ntohl(pdu.subtype_data) == 0x00010000);
    assert_true(pdu.stream_id == 0);
    assert_true(pdu.avtp_time == 0);
    assert_true(pdu.format_specific == 0);
    assert_true(pdu.packet_info == 0);
}

static void rvf_set_field_seq_num(void **state)
{
    int res;
    struct avtp_stream_pdu pdu = { 0 };

    res = avtp_rvf_pdu_set(&pdu, AVTP_RVF_FIELD_SEQ_NUM, 0x55);

    assert_int_equal(res, 0);
    assert_true(ntohl(pdu.subtype_data) == 0x00005500);
    assert_true(pdu.stream_id == 0);
    assert_true(pdu.avtp_time == 0);
    assert_true(pdu.format_specific == 0);
    assert_true(pdu.packet_info == 0);
}

static void rvf_set_field_tu(void **state)
{
    int res;
    struct avtp_stream_pdu pdu = { 0 };

    res = avtp_rvf_pdu_set(&pdu, AVTP_RVF_FIELD_TU, 1);

    assert_int_equal(res, 0);
    assert_true(ntohl(pdu.subtype_data) == 0x00000001);
    assert_true(pdu.stream_id == 0);
    assert_true(pdu.avtp_time == 0);
    assert_true(pdu.format_specific == 0);
    assert_true(pdu.packet_info == 0);
}

static void rvf_set_field_stream_id(void **state)
{
    int res;
    struct avtp_stream_pdu pdu = { 0 };

    res = avtp_rvf_pdu_set(&pdu, AVTP_RVF_FIELD_STREAM_ID,
                   0xAABBCCDDEEFF0001);

    assert_int_equal(res, 0);
    assert_true(be64toh(pdu.stream_id) == 0xAABBCCDDEEFF0001);
    assert_true(pdu.subtype_data == 0);
    assert_true(pdu.avtp_time == 0);
    assert_true(pdu.format_specific == 0);
    assert_true(pdu.packet_info == 0);
}

static void rvf_set_field_timestamp(void **state)
{
    int res;
    struct avtp_stream_pdu pdu = { 0 };

    res = avtp_rvf_pdu_set(&pdu, AVTP_RVF_FIELD_TIMESTAMP, 0x80C0FFEE);

    assert_int_equal(res, 0);
    assert_true(ntohl(pdu.avtp_time) == 0x80C0FFEE);
    assert_true(pdu.subtype_data == 0);
    assert_true(pdu.stream_id == 0);
    assert_true(pdu.format_specific == 0);
    assert_true(pdu.packet_info == 0);
}

static void rvf_set_field_active_pixels(void **state)
{
    int res;
    struct avtp_stream_pdu pdu = { 0 };

    res = avtp_rvf_pdu_set(&pdu, AVTP_RVF_FIELD_ACTIVE_PIXELS,
                   AVTP_RVF_PIXEL_DEPTH_16);

    assert_int_equal(res, 0);
    assert_true(ntohl(pdu.format_specific) == 0x00040000);
    assert_true(pdu.subtype_data == 0);
    assert_true(pdu.stream_id == 0);
    assert_true(pdu.avtp_time == 0);
    assert_true(pdu.packet_info == 0);
}

static void rvf_set_field_total_lines(void **state)
{
    int res;
    struct avtp_stream_pdu pdu = { 0 };

    res = avtp_rvf_pdu_set(&pdu, AVTP_RVF_FIELD_TOTAL_LINES, 0x3C);

    assert_int_equal(res, 0);
    assert_true(ntohl(pdu.format_specific) == 0x3C);
    assert_true(pdu.subtype_data == 0);
    assert_true(pdu.stream_id == 0);
    assert_true(pdu.avtp_time == 0);
    assert_true(pdu.packet_info == 0);
}

static void rvf_set_field_data_len(void **state)
{
    int res;
    struct avtp_stream_pdu pdu = { 0 };

    res = avtp_rvf_pdu_set(&pdu, AVTP_RVF_FIELD_STREAM_DATA_LEN, 0xAAAA);

    assert_int_equal(res, 0);
    assert_true(ntohl(pdu.packet_info) == 0xAAAA0000);
    assert_true(pdu.subtype_data == 0);
    assert_true(pdu.stream_id == 0);
    assert_true(pdu.avtp_time == 0);
    assert_true(pdu.format_specific == 0);
}

static void rvf_set_field_ap(void **state)
{
    int res;
    struct avtp_stream_pdu pdu = { 0 };

    res = avtp_rvf_pdu_set(&pdu, AVTP_RVF_FIELD_AP, 1);

    assert_int_equal(res, 0);
    assert_true(ntohl(pdu.packet_info) == 0x00008000);
    assert_true(pdu.subtype_data == 0);
    assert_true(pdu.stream_id == 0);
    assert_true(pdu.avtp_time == 0);
    assert_true(pdu.format_specific == 0);
}

static void rvf_set_field_f(void **state)
{
    int res;
    struct avtp_stream_pdu pdu = { 0 };

    res = avtp_rvf_pdu_set(&pdu, AVTP_RVF_FIELD_F, 1);

    assert_int_equal(res, 0);
    assert_true(ntohl(pdu.packet_info) == 0x00002000);
    assert_true(pdu.subtype_data == 0);
    assert_true(pdu.stream_id == 0);
    assert_true(pdu.avtp_time == 0);
    assert_true(pdu.format_specific == 0);
}

static void rvf_set_field_ef(void **state)
{
    int res;
    struct avtp_stream_pdu pdu = { 0 };

    res = avtp_rvf_pdu_set(&pdu, AVTP_RVF_FIELD_EF, 1);

    assert_int_equal(res, 0);
    assert_true(ntohl(pdu.packet_info) == 0x00001000);
    assert_true(pdu.subtype_data == 0);
    assert_true(pdu.stream_id == 0);
    assert_true(pdu.avtp_time == 0);
    assert_true(pdu.format_specific == 0);
}

static void rvf_set_field_evt(void **state)
{
    int res;
    struct avtp_stream_pdu pdu = { 0 };

    res = avtp_rvf_pdu_set(&pdu, AVTP_RVF_FIELD_EVT, 0xA);

    assert_int_equal(res, 0);
    assert_true(ntohl(pdu.packet_info) == 0x00000A00);
    assert_true(pdu.subtype_data == 0);
    assert_true(pdu.stream_id == 0);
    assert_true(pdu.avtp_time == 0);
    assert_true(pdu.format_specific == 0);
}

static void rvf_set_field_pd(void **state)
{
    int res;
    struct avtp_stream_pdu pdu = { 0 };

    res = avtp_rvf_pdu_set(&pdu, AVTP_RVF_FIELD_PD, 1);

    assert_int_equal(res, 0);
    assert_true(ntohl(pdu.packet_info) == 0x00000080);
    assert_true(pdu.subtype_data == 0);
    assert_true(pdu.stream_id == 0);
    assert_true(pdu.avtp_time == 0);
    assert_true(pdu.format_specific == 0);
}

static void rvf_set_field_i(void **state)
{
    int res;
    struct avtp_stream_pdu pdu = { 0 };

    res = avtp_rvf_pdu_set(&pdu, AVTP_RVF_FIELD_I, 1);

    assert_int_equal(res, 0);
    assert_true(ntohl(pdu.packet_info) == 0x00000040);
    assert_true(pdu.subtype_data == 0);
    assert_true(pdu.stream_id == 0);
    assert_true(pdu.avtp_time == 0);
    assert_true(pdu.format_specific == 0);
}

static void rvf_pdu_init_null_pdu(void **state)
{
    int res;

    res = avtp_rvf_pdu_init(NULL);
    assert_int_equal(res, -EINVAL);
}

static void rvf_pdu_init(void **state)
{
    int res;
    struct avtp_stream_pdu *pdu =
        (struct avtp_stream_pdu *) alloca(sizeof(struct avtp_stream_pdu) + sizeof(uint64_t));

    res = avtp_rvf_pdu_init(pdu);

    assert_int_equal(res, 0);
    assert_true(ntohl(pdu->subtype_data) == 0x07800000);
    assert_true(pdu->stream_id == 0);
    assert_true(pdu->avtp_time == 0);
    assert_true(ntohl(pdu->format_specific) == 0x0000000);
    assert_true(pdu->packet_info == 0);
}

/**** Tests for RAW fields ****/

static void rvf_get_field_raw_pixel_depth(void **state)
{
    int res;
    uint64_t val;
    struct avtp_stream_pdu *pdu =
        (struct avtp_stream_pdu *) alloca(sizeof(struct avtp_stream_pdu) + sizeof(uint64_t));
    struct avtp_rvf_payload *pay =
        (struct avtp_rvf_payload *)pdu->avtp_payload;

    /* Set 'pixel_depth' field to AVTP_RVF_PIXEL_DEPTH_16 */
    pay->raw_header = htobe64(0x0040000000000000);

    res = avtp_rvf_pdu_get(pdu, AVTP_RVF_FIELD_RAW_PIXEL_DEPTH, &val);

    assert_int_equal(res, 0);
    assert_true(val == AVTP_RVF_PIXEL_DEPTH_16);
}

static void rvf_get_field_raw_pixel_format(void **state)
{
    int res;
    uint64_t val;
    struct avtp_stream_pdu *pdu =
        (struct avtp_stream_pdu *) alloca(sizeof(struct avtp_stream_pdu) + sizeof(uint64_t));
    struct avtp_rvf_payload *pay =
        (struct avtp_rvf_payload *)pdu->avtp_payload;

    /* Set 'pixel_format' field to AVTP_RVF_PIXEL_DEPTH_16 */
    pay->raw_header = htobe64(0x0003000000000000);

    res = avtp_rvf_pdu_get(pdu, AVTP_RVF_FIELD_RAW_PIXEL_FORMAT, &val);

    assert_int_equal(res, 0);
    assert_true(val == AVTP_RVF_PIXEL_FORMAT_422);
}

static void rvf_get_field_raw_frame_rate(void **state)
{
    int res;
    uint64_t val;
    struct avtp_stream_pdu *pdu =
        (struct avtp_stream_pdu *) alloca(sizeof(struct avtp_stream_pdu) + sizeof(uint64_t));
    struct avtp_rvf_payload *pay =
        (struct avtp_rvf_payload *)pdu->avtp_payload;

    /* Set 'frame rate' field to AVTP_RVF_FRAME_RATE_30 */
    pay->raw_header = htobe64(0x0000150000000000);

    res = avtp_rvf_pdu_get(pdu, AVTP_RVF_FIELD_RAW_FRAME_RATE, &val);

    assert_int_equal(res, 0);
    assert_true(val == AVTP_RVF_FRAME_RATE_30);
}

static void rvf_get_field_raw_colorspace(void **state)
{
    int res;
    uint64_t val;
    struct avtp_stream_pdu *pdu =
        (struct avtp_stream_pdu *) alloca(sizeof(struct avtp_stream_pdu) + sizeof(uint64_t));
    struct avtp_rvf_payload *pay =
        (struct avtp_rvf_payload *)pdu->avtp_payload;

    /* Set 'colorspace' field to AVTP_RVF_COLORSPACE_GRAY */
    pay->raw_header = htobe64(0x0000004000000000);

    res = avtp_rvf_pdu_get(pdu, AVTP_RVF_FIELD_RAW_COLORSPACE, &val);

    assert_int_equal(res, 0);
    assert_true(val == AVTP_RVF_COLORSPACE_GRAY);
}

static void rvf_get_field_raw_num_lines(void **state)
{
    int res;
    uint64_t val;
    struct avtp_stream_pdu *pdu =
        (struct avtp_stream_pdu *) alloca(sizeof(struct avtp_stream_pdu) + sizeof(uint64_t));
    struct avtp_rvf_payload *pay =
        (struct avtp_rvf_payload *)pdu->avtp_payload;

    /* Set 'num_lines' field to 0x05 */
    pay->raw_header = htobe64(0x0000000500000000);

    res = avtp_rvf_pdu_get(pdu, AVTP_RVF_FIELD_RAW_NUM_LINES, &val);

    assert_int_equal(res, 0);
    assert_true(val == 0x5);
}

static void rvf_get_field_raw_i_seq_num(void **state)
{
    int res;
    uint64_t val;
    struct avtp_stream_pdu *pdu =
        (struct avtp_stream_pdu *) alloca(sizeof(struct avtp_stream_pdu) + sizeof(uint64_t));
    struct avtp_rvf_payload *pay =
        (struct avtp_rvf_payload *)pdu->avtp_payload;

    /* Set 'i_seq_num' field to 0x03 */
    pay->raw_header = htobe64(0x0000000000030000);

    res = avtp_rvf_pdu_get(pdu, AVTP_RVF_FIELD_RAW_I_SEQ_NUM, &val);

    assert_int_equal(res, 0);
    assert_true(val == 0x3);
}

static void rvf_get_field_raw_line_number(void **state)
{
    int res;
    uint64_t val;
    struct avtp_stream_pdu *pdu =
        (struct avtp_stream_pdu *) alloca(sizeof(struct avtp_stream_pdu) + sizeof(uint64_t));
    struct avtp_rvf_payload *pay =
        (struct avtp_rvf_payload *)pdu->avtp_payload;

    /* Set 'i_seq_num' field to 0x123 */
    pay->raw_header = htobe64(0x0000000000000123);

    res = avtp_rvf_pdu_get(pdu, AVTP_RVF_FIELD_RAW_LINE_NUMBER, &val);

    assert_int_equal(res, 0);
    assert_true(val == 0x123);
}

static void rvf_set_field_raw_pixel_depth(void **state)
{
    int res;
    struct avtp_stream_pdu *pdu =
        (struct avtp_stream_pdu *) alloca(sizeof(struct avtp_stream_pdu) + sizeof(uint64_t));
    struct avtp_rvf_payload *pay =
        (struct avtp_rvf_payload *)pdu->avtp_payload;
    memset(pdu, 0, sizeof(struct avtp_stream_pdu) + sizeof(uint64_t));

    res = avtp_rvf_pdu_set(pdu, AVTP_RVF_FIELD_RAW_PIXEL_DEPTH,
                   AVTP_RVF_PIXEL_DEPTH_16);

    assert_int_equal(res, 0);
    assert_true(pdu->avtp_time == 0);
    assert_true(pdu->subtype_data == 0);
    assert_true(pdu->stream_id == 0);
    assert_true(pdu->format_specific == 0);
    assert_true(pdu->packet_info == 0);
    assert_true(be64toh(pay->raw_header) == 0x0040000000000000);
}

static void rvf_set_field_raw_pixel_format(void **state)
{
    int res;
    struct avtp_stream_pdu *pdu =
        (struct avtp_stream_pdu *) alloca(sizeof(struct avtp_stream_pdu) + sizeof(uint64_t));
    struct avtp_rvf_payload *pay =
        (struct avtp_rvf_payload *)pdu->avtp_payload;
    memset(pdu, 0, sizeof(struct avtp_stream_pdu) + sizeof(uint64_t));

    res = avtp_rvf_pdu_set(pdu, AVTP_RVF_FIELD_RAW_PIXEL_FORMAT,
                   AVTP_RVF_PIXEL_FORMAT_422);

    assert_int_equal(res, 0);
    assert_true(pdu->avtp_time == 0);
    assert_true(pdu->subtype_data == 0);
    assert_true(pdu->stream_id == 0);
    assert_true(pdu->format_specific == 0);
    assert_true(pdu->packet_info == 0);
    assert_true(be64toh(pay->raw_header) == 0x0003000000000000);
}

static void rvf_set_field_raw_frame_rate(void **state)
{
    int res;
    struct avtp_stream_pdu *pdu =
        (struct avtp_stream_pdu *) alloca(sizeof(struct avtp_stream_pdu) + sizeof(uint64_t));
    struct avtp_rvf_payload *pay =
        (struct avtp_rvf_payload *)pdu->avtp_payload;
    memset(pdu, 0, sizeof(struct avtp_stream_pdu) + sizeof(uint64_t));

    res = avtp_rvf_pdu_set(pdu, AVTP_RVF_FIELD_RAW_FRAME_RATE,
                   AVTP_RVF_FRAME_RATE_30);

    assert_int_equal(res, 0);
    assert_true(pdu->avtp_time == 0);
    assert_true(pdu->subtype_data == 0);
    assert_true(pdu->stream_id == 0);
    assert_true(pdu->format_specific == 0);
    assert_true(pdu->packet_info == 0);
    assert_true(be64toh(pay->raw_header) == 0x0000150000000000);
}

static void rvf_set_field_raw_colorspace(void **state)
{
    int res;
    struct avtp_stream_pdu *pdu =
        (struct avtp_stream_pdu *) alloca(sizeof(struct avtp_stream_pdu) + sizeof(uint64_t));
    struct avtp_rvf_payload *pay =
        (struct avtp_rvf_payload *)pdu->avtp_payload;
    memset(pdu, 0, sizeof(struct avtp_stream_pdu) + sizeof(uint64_t));

    res = avtp_rvf_pdu_set(pdu, AVTP_RVF_FIELD_RAW_COLORSPACE,
                   AVTP_RVF_COLORSPACE_GRAY);

    assert_int_equal(res, 0);
    assert_true(pdu->avtp_time == 0);
    assert_true(pdu->subtype_data == 0);
    assert_true(pdu->stream_id == 0);
    assert_true(pdu->format_specific == 0);
    assert_true(pdu->packet_info == 0);
    assert_true(be64toh(pay->raw_header) == 0x0000004000000000);
}

static void rvf_set_field_raw_num_lines(void **state)
{
    int res;
    struct avtp_stream_pdu *pdu =
        (struct avtp_stream_pdu *) alloca(sizeof(struct avtp_stream_pdu) + sizeof(uint64_t));
    struct avtp_rvf_payload *pay =
        (struct avtp_rvf_payload *)pdu->avtp_payload;
    memset(pdu, 0, sizeof(struct avtp_stream_pdu) + sizeof(uint64_t));

    res = avtp_rvf_pdu_set(pdu, AVTP_RVF_FIELD_RAW_NUM_LINES, 0x05);

    assert_int_equal(res, 0);
    assert_true(pdu->avtp_time == 0);
    assert_true(pdu->subtype_data == 0);
    assert_true(pdu->stream_id == 0);
    assert_true(pdu->format_specific == 0);
    assert_true(pdu->packet_info == 0);
    assert_true(be64toh(pay->raw_header) == 0x0000000500000000);
}

static void rvf_set_field_raw_i_seq_num(void **state)
{
    int res;
    struct avtp_stream_pdu *pdu =
        (struct avtp_stream_pdu *) alloca(sizeof(struct avtp_stream_pdu) + sizeof(uint64_t));
    struct avtp_rvf_payload *pay =
        (struct avtp_rvf_payload *)pdu->avtp_payload;
    memset(pdu, 0, sizeof(struct avtp_stream_pdu) + sizeof(uint64_t));

    res = avtp_rvf_pdu_set(pdu, AVTP_RVF_FIELD_RAW_I_SEQ_NUM, 0x03);

    assert_int_equal(res, 0);
    assert_true(pdu->avtp_time == 0);
    assert_true(pdu->subtype_data == 0);
    assert_true(pdu->stream_id == 0);
    assert_true(pdu->format_specific == 0);
    assert_true(pdu->packet_info == 0);
    assert_true(be64toh(pay->raw_header) == 0x0000000000030000);
}

static void rvf_set_field_raw_line_number(void **state)
{
    int res;
    struct avtp_stream_pdu *pdu =
        (struct avtp_stream_pdu *) alloca(sizeof(struct avtp_stream_pdu) + sizeof(uint64_t));
    struct avtp_rvf_payload *pay =
        (struct avtp_rvf_payload *)pdu->avtp_payload;
    memset(pdu, 0, sizeof(struct avtp_stream_pdu) + sizeof(uint64_t));

    res = avtp_rvf_pdu_set(pdu, AVTP_RVF_FIELD_RAW_LINE_NUMBER, 0x123);

    assert_int_equal(res, 0);
    assert_true(pdu->avtp_time == 0);
    assert_true(pdu->subtype_data == 0);
    assert_true(pdu->stream_id == 0);
    assert_true(pdu->format_specific == 0);
    assert_true(pdu->packet_info == 0);
    assert_true(be64toh(pay->raw_header) == 0x0000000000000123);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(rvf_get_field_null_pdu),
        cmocka_unit_test(rvf_get_field_null_val),
        cmocka_unit_test(rvf_get_field_invalid_field),
        cmocka_unit_test(rvf_get_field_sv),
        cmocka_unit_test(rvf_get_field_mr),
        cmocka_unit_test(rvf_get_field_tv),
        cmocka_unit_test(rvf_get_field_seq_num),
        cmocka_unit_test(rvf_get_field_tu),
        cmocka_unit_test(rvf_get_field_stream_id),
        cmocka_unit_test(rvf_get_field_timestamp),
        cmocka_unit_test(rvf_get_field_active_pixels),
        cmocka_unit_test(rvf_get_field_format_total_lines),
        cmocka_unit_test(rvf_get_field_data_len),
        cmocka_unit_test(rvf_get_field_ap),
        cmocka_unit_test(rvf_get_field_f),
        cmocka_unit_test(rvf_get_field_ef),
        cmocka_unit_test(rvf_get_field_evt),
        cmocka_unit_test(rvf_get_field_pd),
        cmocka_unit_test(rvf_get_field_i),
        cmocka_unit_test(rvf_get_field_raw_pixel_depth),
        cmocka_unit_test(rvf_get_field_raw_pixel_format),
        cmocka_unit_test(rvf_get_field_raw_frame_rate),
        cmocka_unit_test(rvf_get_field_raw_colorspace),
        cmocka_unit_test(rvf_get_field_raw_num_lines),
        cmocka_unit_test(rvf_get_field_raw_i_seq_num),
        cmocka_unit_test(rvf_get_field_raw_line_number),
        cmocka_unit_test(rvf_set_field_null_pdu),
        cmocka_unit_test(rvf_set_field_invalid_field),
        cmocka_unit_test(rvf_set_field_sv),
        cmocka_unit_test(rvf_set_field_mr),
        cmocka_unit_test(rvf_set_field_tv),
        cmocka_unit_test(rvf_set_field_seq_num),
        cmocka_unit_test(rvf_set_field_tu),
        cmocka_unit_test(rvf_set_field_stream_id),
        cmocka_unit_test(rvf_set_field_timestamp),
        cmocka_unit_test(rvf_set_field_active_pixels),
        cmocka_unit_test(rvf_set_field_total_lines),
        cmocka_unit_test(rvf_set_field_data_len),
        cmocka_unit_test(rvf_set_field_ap),
        cmocka_unit_test(rvf_set_field_f),
        cmocka_unit_test(rvf_set_field_ef),
        cmocka_unit_test(rvf_set_field_evt),
        cmocka_unit_test(rvf_set_field_pd),
        cmocka_unit_test(rvf_set_field_i),
        cmocka_unit_test(rvf_set_field_raw_pixel_depth),
        cmocka_unit_test(rvf_set_field_raw_pixel_format),
        cmocka_unit_test(rvf_set_field_raw_frame_rate),
        cmocka_unit_test(rvf_set_field_raw_colorspace),
        cmocka_unit_test(rvf_set_field_raw_num_lines),
        cmocka_unit_test(rvf_set_field_raw_i_seq_num),
        cmocka_unit_test(rvf_set_field_raw_line_number),
        cmocka_unit_test(rvf_pdu_init_null_pdu),
        cmocka_unit_test(rvf_pdu_init),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
