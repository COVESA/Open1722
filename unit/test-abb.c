/*
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

#ifdef __cplusplus
extern "C" {
#endif

#include "avtp/acf/Abb.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>

static void Test_Abb_Init(void** state)
{
    const size_t buffer_len = AVTP_ABB_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {0};
    Avtp_Abb_t* abb = (Avtp_Abb_t*)buffer;
    Avtp_Abb_Init(abb);

    uint8_t expected_buf[buffer_len] = {
        0x1C, 0x02, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };

    assert_memory_equal(buffer, expected_buf, buffer_len);
}

static void Test_Abb_GetPad(void** state)
{
    const size_t buffer_len = AVTP_ABB_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {
        0x1C, 0x02, 0xC0, 0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_Abb_t* abb = (Avtp_Abb_t*)buffer;
    assert_int_equal(Avtp_Abb_GetPad(abb), 3);
}

static void Test_Abb_IsMtv(void** state)
{
    const size_t buffer_len = AVTP_ABB_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {
        0x1C, 0x02, 0x20, 0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_Abb_t* abb = (Avtp_Abb_t*)buffer;
    assert_int_equal(Avtp_Abb_IsMtv(abb), true);
}

static void Test_Abb_GetByteBusId(void** state)
{
    const size_t buffer_len = AVTP_ABB_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {
        0x1C, 0x02, 0x05, 0xFF,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_Abb_t* abb = (Avtp_Abb_t*)buffer;
    assert_int_equal(Avtp_Abb_GetByteBusId(abb), 0x5FF);
}

static void Test_Abb_GetEvt(void** state)
{
    const size_t buffer_len = AVTP_ABB_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {
        0x1C, 0x02, 0x0,  0x0,
        0xB0, 0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_Abb_t* abb = (Avtp_Abb_t*)buffer;
    assert_int_equal(Avtp_Abb_GetEvt(abb), 0xB);
}

static void Test_Abb_IsHs(void** state)
{
    const size_t buffer_len = AVTP_ABB_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {
        0x1C, 0x02, 0x0,  0x0,
        0x2,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_Abb_t* abb = (Avtp_Abb_t*)buffer;
    assert_int_equal(Avtp_Abb_IsHs(abb), true);
}

static void Test_Abb_IsCs(void** state)
{
    const size_t buffer_len = AVTP_ABB_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {
        0x1C, 0x02, 0x0,  0x0,
        0x1,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_Abb_t* abb = (Avtp_Abb_t*)buffer;
    assert_int_equal(Avtp_Abb_IsCs(abb), true);
}

static void Test_Abb_GetTransactionNum(void** state)
{
    const size_t buffer_len = AVTP_ABB_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {
        0x1C, 0x02, 0x0,  0x0,
        0x0,  0xBF, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_Abb_t* abb = (Avtp_Abb_t*)buffer;
    assert_int_equal(Avtp_Abb_GetTransactionNum(abb), 0xBF);
}

static void Test_Abb_IsOp(void** state)
{
    const size_t buffer_len = AVTP_ABB_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {
        0x1C, 0x02, 0x0,  0x0,
        0x0,  0x0,  0x80, 0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_Abb_t* abb = (Avtp_Abb_t*)buffer;
    assert_int_equal(Avtp_Abb_IsOp(abb), true);
}

static void Test_Abb_IsRsp(void** state)
{
    const size_t buffer_len = AVTP_ABB_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {
        0x1C, 0x02, 0x0,  0x0,
        0x0,  0x0,  0x40, 0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_Abb_t* abb = (Avtp_Abb_t*)buffer;
    assert_int_equal(Avtp_Abb_IsRsp(abb), true);
}

static void Test_Abb_IsErr(void** state)
{
    const size_t buffer_len = AVTP_ABB_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {
        0x1C, 0x02, 0x0,  0x0,
        0x0,  0x0,  0x20, 0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_Abb_t* abb = (Avtp_Abb_t*)buffer;
    assert_int_equal(Avtp_Abb_IsErr(abb), true);
}

static void Test_Abb_IsMs(void** state)
{
    const size_t buffer_len = AVTP_ABB_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {
        0x1C, 0x02, 0x0,  0x0,
        0x0,  0x0,  0x10, 0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_Abb_t* abb = (Avtp_Abb_t*)buffer;
    assert_int_equal(Avtp_Abb_IsMs(abb), true);
}

static void Test_Abb_GetReadSize(void** state)
{
    const size_t buffer_len = AVTP_ABB_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {
        0x1C, 0x02, 0x0,  0x0,
        0x0,  0x0,  0x0B, 0xFF,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_Abb_t* abb = (Avtp_Abb_t*)buffer;
    assert_int_equal(Avtp_Abb_GetReadSize(abb), 0xBFF);
}

static void Test_Abb_GetSegmentNum(void** state)
{
    const size_t buffer_len = AVTP_ABB_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {
        0x1C, 0x02, 0x0,  0x0,
        0x0,  0x0,  0x0B, 0xFF,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_Abb_t* abb = (Avtp_Abb_t*)buffer;
    assert_int_equal(Avtp_Abb_GetSegmentNum(abb), 0xBFF);
}

static void Test_Abb_GetPayloadLen(void** state)
{
    const size_t buffer_len = AVTP_ABB_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {
        0x1C, 0x03, 0xC0, 0x0,
        0x0,  0x0,  0x0B, 0xFF,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_Abb_t* abb = (Avtp_Abb_t*)buffer;
    assert_int_equal(Avtp_Abb_GetPayloadLen(abb), 1);
}

static void Test_Abb_GetPayloadLen_NoPadding(void** state)
{
    const size_t buffer_len = AVTP_ABB_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {
        0x1C, 0x03, 0x0,  0x0,
        0x0,  0x0,  0x0B, 0xFF,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_Abb_t* abb = (Avtp_Abb_t*)buffer;
    assert_int_equal(Avtp_Abb_GetPayloadLen(abb), 4);
}

static void Test_Abb_GetLen(void** state)
{
    const size_t buffer_len = AVTP_ABB_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {
        0x1C, 0x03, 0x0,  0x0,
        0x0,  0x0,  0x0B, 0xFF,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_Abb_t* abb = (Avtp_Abb_t*)buffer;
    assert_int_equal(Avtp_Abb_GetLen(abb), 3 * 4);
}

// TODO add more tests

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(Test_Abb_Init),
        cmocka_unit_test(Test_Abb_GetPad),
        cmocka_unit_test(Test_Abb_IsMtv),
        cmocka_unit_test(Test_Abb_GetByteBusId),
        cmocka_unit_test(Test_Abb_GetEvt),
        cmocka_unit_test(Test_Abb_IsHs),
        cmocka_unit_test(Test_Abb_IsCs),
        cmocka_unit_test(Test_Abb_GetTransactionNum),
        cmocka_unit_test(Test_Abb_IsOp),
        cmocka_unit_test(Test_Abb_IsRsp),
        cmocka_unit_test(Test_Abb_IsErr),
        cmocka_unit_test(Test_Abb_IsMs),
        cmocka_unit_test(Test_Abb_GetReadSize),
        cmocka_unit_test(Test_Abb_GetSegmentNum),
        cmocka_unit_test(Test_Abb_GetPayloadLen),
        cmocka_unit_test(Test_Abb_GetPayloadLen_NoPadding),
        cmocka_unit_test(Test_Abb_GetLen),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

#ifdef __cplusplus
}
#endif
