/*
 * Copyright (c) 2019, Intel Corporation
 * Copyright (c) 2024, COVESA
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

#include <alloca.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>
#include <arpa/inet.h>

#include "avtp.h"
#include "avtp/cvf/Cvf.h"
#include "avtp/cvf/H264.h"

static void cvf_get_field_null_pdu(void **state)
{
	int res;
	uint64_t val = 1;

	res = avtp_cvf_pdu_get(NULL, AVTP_CVF_FIELD_SV, &val);

	assert_int_equal(res, -EINVAL);
}

static void cvf_get_field_null_val(void **state)
{
	int res;
	struct avtp_stream_pdu pdu = { 0 };

	res = avtp_cvf_pdu_get(&pdu, AVTP_CVF_FIELD_SV, NULL);

	assert_int_equal(res, -EINVAL);
}

static void cvf_get_field_invalid_field(void **state)
{
	int res;
	uint64_t val = 1;
	struct avtp_stream_pdu pdu = { 0 };

	res = avtp_cvf_pdu_get(&pdu, AVTP_CVF_FIELD_MAX, &val);

	assert_int_equal(res, -EINVAL);
}

static void cvf_get_field_sv(void **state)
{
	int res;
	uint64_t val;
	struct avtp_stream_pdu pdu = { 0 };

	/* Set 'sv' field to 1. */
	pdu.subtype_data = htonl(0x00800000);

	res = avtp_cvf_pdu_get(&pdu, AVTP_CVF_FIELD_SV, &val);

	assert_int_equal(res, 0);
	assert_true(val == 1);
}

static void cvf_get_field_mr(void **state)
{
	int res;
	uint64_t val;
	struct avtp_stream_pdu pdu = { 0 };

	/* Set 'mr' field to 1. */
	pdu.subtype_data = htonl(0x00080000);

	res = avtp_cvf_pdu_get(&pdu, AVTP_CVF_FIELD_MR, &val);

	assert_int_equal(res, 0);
	assert_true(val == 1);
}

static void cvf_get_field_tv(void **state)
{
	int res;
	uint64_t val;
	struct avtp_stream_pdu pdu = { 0 };

	/* Set 'tv' field to 1. */
	pdu.subtype_data = htonl(0x00010000);

	res = avtp_cvf_pdu_get(&pdu, AVTP_CVF_FIELD_TV, &val);

	assert_int_equal(res, 0);
	assert_true(val == 1);
}

static void cvf_get_field_seq_num(void **state)
{
	int res;
	uint64_t val;
	struct avtp_stream_pdu pdu = { 0 };

	/* Set 'sequence_num' field to 0x55. */
	pdu.subtype_data = htonl(0x00005500);

	res = avtp_cvf_pdu_get(&pdu, AVTP_CVF_FIELD_SEQUENCE_NUM, &val);

	assert_int_equal(res, 0);
	assert_true(val == 0x55);
}

static void cvf_get_field_tu(void **state)
{
	int res;
	uint64_t val;
	struct avtp_stream_pdu pdu = { 0 };

	/* Set 'tu' field to 1. */
	pdu.subtype_data = htonl(0x00000001);

	res = avtp_cvf_pdu_get(&pdu, AVTP_CVF_FIELD_TU, &val);

	assert_int_equal(res, 0);
	assert_true(val == 1);
}

static void cvf_get_field_stream_id(void **state)
{
	int res;
	uint64_t val;
	struct avtp_stream_pdu pdu = { 0 };

	/* Set 'stream_id' field to 0xAABBCCDDEEFF0001. */
	pdu.stream_id = htobe64(0xAABBCCDDEEFF0001);

	res = avtp_cvf_pdu_get(&pdu, AVTP_CVF_FIELD_STREAM_ID, &val);

	assert_int_equal(res, 0);
	assert_true(val == 0xAABBCCDDEEFF0001);
}

static void cvf_get_field_timestamp(void **state)
{
	int res;
	uint64_t val;
	struct avtp_stream_pdu pdu = { 0 };

	/* Set 'avtp_timestamp' field to 0x80C0FFEE. */
	pdu.avtp_time = htonl(0x80C0FFEE);

	res = avtp_cvf_pdu_get(&pdu, AVTP_CVF_FIELD_AVTP_TIMESTAMP, &val);

	assert_int_equal(res, 0);
	assert_true(val == 0x80C0FFEE);
}

static void cvf_get_field_format(void **state)
{
	int res;
	uint64_t val;
	struct avtp_stream_pdu pdu = { 0 };

	/* Set 'format' field to AVTP_CVF_FORMAT_RFC. */
	pdu.format_specific = htonl(0x02000000);

	res = avtp_cvf_pdu_get(&pdu, AVTP_CVF_FIELD_FORMAT, &val);

	assert_int_equal(res, 0);
	assert_true(val == AVTP_CVF_FORMAT_RFC);
}

static void cvf_get_field_format_subtype(void **state)
{
	int res;
	uint64_t val;
	struct avtp_stream_pdu pdu = { 0 };

	/* Set 'format_subtype' field to AVTP_CVF_FORMAT_SUBTYPE_H264. */
	pdu.format_specific = htonl(0x00010000);

	res = avtp_cvf_pdu_get(&pdu, AVTP_CVF_FIELD_FORMAT_SUBTYPE, &val);

	assert_int_equal(res, 0);
	assert_true(val == AVTP_CVF_FORMAT_SUBTYPE_H264);
}

static void cvf_get_field_data_len(void **state)
{
	int res;
	uint64_t val;
	struct avtp_stream_pdu pdu = { 0 };

	/* Set 'stream_data_length' field to 0xAAAA. */
	pdu.packet_info = htonl(0xAAAA0000);

	res = avtp_cvf_pdu_get(&pdu, AVTP_CVF_FIELD_STREAM_DATA_LENGTH, &val);

	assert_int_equal(res, 0);
	assert_true(val == 0xAAAA);
}

static void cvf_get_field_m(void **state)
{
	int res;
	uint64_t val;
	struct avtp_stream_pdu pdu = { 0 };

	/* Set 'M' field to 0x1. */
	pdu.packet_info = htonl(0x00001000);

	res = avtp_cvf_pdu_get(&pdu, AVTP_CVF_FIELD_M, &val);

	assert_int_equal(res, 0);
	assert_true(val == 0x1);
}

static void cvf_get_field_evt(void **state)
{
	int res;
	uint64_t val;
	struct avtp_stream_pdu pdu = { 0 };

	/* Set 'evt' field to 0xA. */
	pdu.packet_info = htonl(0x00000A00);

	res = avtp_cvf_pdu_get(&pdu, AVTP_CVF_FIELD_EVT, &val);

	assert_int_equal(res, 0);
	assert_true(val == 0xA);
}

static void cvf_set_field_null_pdu(void **state)
{
	int res;

	res = avtp_cvf_pdu_set(NULL, AVTP_CVF_FIELD_SV, 1);

	assert_int_equal(res, -EINVAL);
}

static void cvf_set_field_invalid_field(void **state)
{
	int res;
	struct avtp_stream_pdu pdu = { 0 };

	res = avtp_cvf_pdu_set(&pdu, AVTP_CVF_FIELD_MAX, 1);

	assert_int_equal(res, -EINVAL);
}

static void cvf_set_field_sv(void **state)
{
	int res;
	struct avtp_stream_pdu pdu = { 0 };

	res = avtp_cvf_pdu_set(&pdu, AVTP_CVF_FIELD_SV, 1);

	assert_int_equal(res, 0);
	assert_true(ntohl(pdu.subtype_data) == 0x00800000);
	assert_true(pdu.stream_id == 0);
	assert_true(pdu.avtp_time == 0);
	assert_true(pdu.format_specific == 0);
	assert_true(pdu.packet_info == 0);
}

static void cvf_set_field_mr(void **state)
{
	int res;
	struct avtp_stream_pdu pdu = { 0 };

	res = avtp_cvf_pdu_set(&pdu, AVTP_CVF_FIELD_MR, 1);

	assert_int_equal(res, 0);
	assert_true(ntohl(pdu.subtype_data) == 0x00080000);
	assert_true(pdu.stream_id == 0);
	assert_true(pdu.avtp_time == 0);
	assert_true(pdu.format_specific == 0);
	assert_true(pdu.packet_info == 0);
}

static void cvf_set_field_tv(void **state)
{
	int res;
	struct avtp_stream_pdu pdu = { 0 };

	res = avtp_cvf_pdu_set(&pdu, AVTP_CVF_FIELD_TV, 1);

	assert_int_equal(res, 0);
	assert_true(ntohl(pdu.subtype_data) == 0x00010000);
	assert_true(pdu.stream_id == 0);
	assert_true(pdu.avtp_time == 0);
	assert_true(pdu.format_specific == 0);
	assert_true(pdu.packet_info == 0);
}

static void cvf_set_field_seq_num(void **state)
{
	int res;
	struct avtp_stream_pdu pdu = { 0 };

	res = avtp_cvf_pdu_set(&pdu, AVTP_CVF_FIELD_SEQUENCE_NUM, 0x55);

	assert_int_equal(res, 0);
	assert_true(ntohl(pdu.subtype_data) == 0x00005500);
	assert_true(pdu.stream_id == 0);
	assert_true(pdu.avtp_time == 0);
	assert_true(pdu.format_specific == 0);
	assert_true(pdu.packet_info == 0);
}

static void cvf_set_field_tu(void **state)
{
	int res;
	struct avtp_stream_pdu pdu = { 0 };

	res = avtp_cvf_pdu_set(&pdu, AVTP_CVF_FIELD_TU, 1);

	assert_int_equal(res, 0);
	assert_true(ntohl(pdu.subtype_data) == 0x00000001);
	assert_true(pdu.stream_id == 0);
	assert_true(pdu.avtp_time == 0);
	assert_true(pdu.format_specific == 0);
	assert_true(pdu.packet_info == 0);
}

static void cvf_set_field_stream_id(void **state)
{
	int res;
	struct avtp_stream_pdu pdu = { 0 };

	res = avtp_cvf_pdu_set(&pdu, AVTP_CVF_FIELD_STREAM_ID,
							0xAABBCCDDEEFF0001);

	assert_int_equal(res, 0);
	assert_true(be64toh(pdu.stream_id) == 0xAABBCCDDEEFF0001);
	assert_true(pdu.subtype_data == 0);
	assert_true(pdu.avtp_time == 0);
	assert_true(pdu.format_specific == 0);
	assert_true(pdu.packet_info == 0);
}

static void cvf_set_field_timestamp(void **state)
{
	int res;
	struct avtp_stream_pdu pdu = { 0 };

	res = avtp_cvf_pdu_set(&pdu, AVTP_CVF_FIELD_AVTP_TIMESTAMP, 0x80C0FFEE);

	assert_int_equal(res, 0);
	assert_true(ntohl(pdu.avtp_time) == 0x80C0FFEE);
	assert_true(pdu.subtype_data == 0);
	assert_true(pdu.stream_id == 0);
	assert_true(pdu.format_specific == 0);
	assert_true(pdu.packet_info == 0);
}

static void cvf_set_field_format(void **state)
{
	int res;
	struct avtp_stream_pdu pdu = { 0 };

	res = avtp_cvf_pdu_set(&pdu, AVTP_CVF_FIELD_FORMAT,
						AVTP_CVF_FORMAT_RFC);

	assert_int_equal(res, 0);
	assert_true(ntohl(pdu.format_specific) == 0x02000000);
	assert_true(pdu.subtype_data == 0);
	assert_true(pdu.stream_id == 0);
	assert_true(pdu.avtp_time == 0);
	assert_true(pdu.packet_info == 0);
}

static void cvf_set_field_format_subtype(void **state)
{
	int res;
	struct avtp_stream_pdu pdu = { 0 };

	res = avtp_cvf_pdu_set(&pdu, AVTP_CVF_FIELD_FORMAT_SUBTYPE,
						AVTP_CVF_FORMAT_SUBTYPE_H264);

	assert_int_equal(res, 0);
	assert_true(ntohl(pdu.format_specific) == 0x10000);
	assert_true(pdu.subtype_data == 0);
	assert_true(pdu.stream_id == 0);
	assert_true(pdu.avtp_time == 0);
	assert_true(pdu.packet_info == 0);
}

static void cvf_set_field_data_len(void **state)
{
	int res;
	struct avtp_stream_pdu pdu = { 0 };

	res = avtp_cvf_pdu_set(&pdu, AVTP_CVF_FIELD_STREAM_DATA_LENGTH, 0xAAAA);

	assert_int_equal(res, 0);
	assert_true(ntohl(pdu.packet_info) == 0xAAAA0000);
	assert_true(pdu.subtype_data == 0);
	assert_true(pdu.stream_id == 0);
	assert_true(pdu.avtp_time == 0);
	assert_true(pdu.format_specific == 0);
}

static void cvf_set_field_m(void **state)
{
	int res;
	struct avtp_stream_pdu pdu = { 0 };

	res = avtp_cvf_pdu_set(&pdu, AVTP_CVF_FIELD_M, 1);

	assert_int_equal(res, 0);
	assert_true(ntohl(pdu.packet_info) == 0x00001000);
	assert_true(pdu.subtype_data == 0);
	assert_true(pdu.stream_id == 0);
	assert_true(pdu.avtp_time == 0);
	assert_true(pdu.format_specific == 0);
}

static void cvf_set_field_evt(void **state)
{
	int res;
	struct avtp_stream_pdu pdu = { 0 };

	res = avtp_cvf_pdu_set(&pdu, AVTP_CVF_FIELD_EVT, 0xA);

	assert_int_equal(res, 0);
	assert_true(ntohl(pdu.packet_info) == 0x00000A00);
	assert_true(pdu.subtype_data == 0);
	assert_true(pdu.stream_id == 0);
	assert_true(pdu.avtp_time == 0);
	assert_true(pdu.format_specific == 0);
}

static void cvf_pdu_init_null_pdu(void **state)
{
	int res;

	res = avtp_cvf_pdu_init(NULL, AVTP_CVF_FORMAT_SUBTYPE_H264);
	assert_int_equal(res, -EINVAL);
}

static void cvf_pdu_init(void **state)
{
	int res;
	struct avtp_stream_pdu pdu;

	res = avtp_cvf_pdu_init(&pdu, AVTP_CVF_FORMAT_SUBTYPE_H264);

	assert_int_equal(res, 0);
	assert_true(ntohl(pdu.subtype_data) == 0x03800000);
	assert_true(pdu.stream_id == 0);
	assert_true(pdu.avtp_time == 0);
	assert_true(ntohl(pdu.format_specific) == 0x2010000);
	assert_true(pdu.packet_info == 0);
}

static void cvf_get_field_ptv(void **state)
{
	int res;
	uint64_t val;
	struct avtp_stream_pdu pdu = { 0 };

	/* Set 'ptv' field to 1. */
	pdu.packet_info = htonl(0x00002000);

	res = avtp_cvf_pdu_get(&pdu, AVTP_CVF_FIELD_PTV, &val);

	assert_int_equal(res, 0);
	assert_true(val == 1);
}

static void cvf_set_field_ptv(void **state)
{
	int res;
	struct avtp_stream_pdu pdu = { 0 };

	res = avtp_cvf_pdu_set(&pdu, AVTP_CVF_FIELD_PTV, 1);

	assert_int_equal(res, 0);
	assert_true(pdu.subtype_data == 0);
	assert_true(pdu.stream_id == 0);
	assert_true(pdu.avtp_time == 0);
	assert_true(pdu.format_specific == 0);
	assert_true(ntohl(pdu.packet_info) == 0x00002000);
}

/**** Tests for H.264 fields ****/

static void cvf_get_field_h264_timestamp(void **state)
{
	int res;
	uint64_t val;
	Avtp_H264_t pdu;

	/* Set 'h264_timestamp' field (which lives in h264_header) to
	 * 0x80C0FFEE. */
	uint32_t value = htonl(0x80C0FFEE);
	memcpy(&pdu.header, &value, 4);

	res = Avtp_H264_GetField(&pdu, AVTP_H264_FIELD_TIMESTAMP, &val);

	assert_int_equal(res, 0);
	assert_true(val == 0x80C0FFEE);
}

static void cvf_set_field_h264_timestamp(void **state)
{
	int res;
	Avtp_H264_t pdu;

	res = Avtp_H264_SetField(&pdu, AVTP_H264_FIELD_TIMESTAMP, 0x80C0FFEE);

	assert_int_equal(res, 0);
	assert_true(ntohl(*(uint32_t*)(&pdu.header)) == 0x80C0FFEE);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(cvf_get_field_null_pdu),
		cmocka_unit_test(cvf_get_field_null_val),
		cmocka_unit_test(cvf_get_field_invalid_field),
		cmocka_unit_test(cvf_get_field_sv),
		cmocka_unit_test(cvf_get_field_mr),
		cmocka_unit_test(cvf_get_field_tv),
		cmocka_unit_test(cvf_get_field_seq_num),
		cmocka_unit_test(cvf_get_field_tu),
		cmocka_unit_test(cvf_get_field_stream_id),
		cmocka_unit_test(cvf_get_field_timestamp),
		cmocka_unit_test(cvf_get_field_format),
		cmocka_unit_test(cvf_get_field_format_subtype),
		cmocka_unit_test(cvf_get_field_data_len),
		cmocka_unit_test(cvf_get_field_m),
		cmocka_unit_test(cvf_get_field_evt),
		cmocka_unit_test(cvf_get_field_ptv),
		cmocka_unit_test(cvf_get_field_h264_timestamp),
		cmocka_unit_test(cvf_set_field_null_pdu),
		cmocka_unit_test(cvf_set_field_invalid_field),
		cmocka_unit_test(cvf_set_field_sv),
		cmocka_unit_test(cvf_set_field_mr),
		cmocka_unit_test(cvf_set_field_tv),
		cmocka_unit_test(cvf_set_field_seq_num),
		cmocka_unit_test(cvf_set_field_tu),
		cmocka_unit_test(cvf_set_field_stream_id),
		cmocka_unit_test(cvf_set_field_timestamp),
		cmocka_unit_test(cvf_set_field_format),
		cmocka_unit_test(cvf_set_field_format_subtype),
		cmocka_unit_test(cvf_set_field_data_len),
		cmocka_unit_test(cvf_set_field_m),
		cmocka_unit_test(cvf_set_field_evt),
		cmocka_unit_test(cvf_set_field_ptv),
		cmocka_unit_test(cvf_set_field_h264_timestamp),
		cmocka_unit_test(cvf_pdu_init_null_pdu),
		cmocka_unit_test(cvf_pdu_init),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
