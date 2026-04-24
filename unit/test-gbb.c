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

#include "avtp/acf/Gbb.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>

static void Test_Gbb_Init(void** state)
{
    const size_t msg_len = AVTP_GBB_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_Gbb_t* gbb = (Avtp_Gbb_t*)msg;
    Avtp_Gbb_Init(gbb);

    uint8_t expected_msg[msg_len] = {
        0x1A, 0x04, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };

    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_Gbb_GetPad(void** state)
{
    const size_t msg_len = AVTP_GBB_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {
        0x1A, 0x04, 0xC0, 0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_Gbb_t* gbb = (Avtp_Gbb_t*)msg;
    assert_int_equal(Avtp_Gbb_GetPad(gbb), 3);
}

static void Test_Gbb_IsMtv(void** state)
{
    const size_t msg_len = AVTP_GBB_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {
        0x1A, 0x04, 0x20, 0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_Gbb_t* gbb = (Avtp_Gbb_t*)msg;
    assert_int_equal(Avtp_Gbb_IsMtv(gbb), true);
}

static void Test_Gbb_GetByteBusId(void** state)
{
    const size_t msg_len = AVTP_GBB_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {
        0x1A, 0x04, 0x05, 0xFF,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_Gbb_t* gbb = (Avtp_Gbb_t*)msg;
    assert_int_equal(Avtp_Gbb_GetByteBusId(gbb), 0x5FF);
}

static void Test_Gbb_GetMessageTimestamp(void** state)
{
    const size_t msg_len = AVTP_GBB_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {
        0x1A, 0x04, 0x0,  0x0,
        0xBF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_Gbb_t* gbb = (Avtp_Gbb_t*)msg;
    assert_int_equal(Avtp_Gbb_GetMessageTimestamp(gbb), 0xBFFFFFFFFFFFFFFFull);
}

static void Test_Gbb_GetEvt(void** state)
{
    const size_t msg_len = AVTP_GBB_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {
        0x1A, 0x04, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0xB0, 0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_Gbb_t* gbb = (Avtp_Gbb_t*)msg;
    assert_int_equal(Avtp_Gbb_GetEvt(gbb), 0xB);
}

static void Test_Gbb_IsHs(void** state)
{
    const size_t msg_len = AVTP_GBB_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {
        0x1A, 0x04, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x2,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_Gbb_t* gbb = (Avtp_Gbb_t*)msg;
    assert_int_equal(Avtp_Gbb_IsHs(gbb), true);
}

static void Test_Gbb_IsCs(void** state)
{
    const size_t msg_len = AVTP_GBB_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {
        0x1A, 0x04, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x1,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_Gbb_t* gbb = (Avtp_Gbb_t*)msg;
    assert_int_equal(Avtp_Gbb_IsCs(gbb), true);
}

static void Test_Gbb_GetTransactionNum(void** state)
{
    const size_t msg_len = AVTP_GBB_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {
        0x1A, 0x04, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0xBF, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_Gbb_t* gbb = (Avtp_Gbb_t*)msg;
    assert_int_equal(Avtp_Gbb_GetTransactionNum(gbb), 0xBF);
}

static void Test_Gbb_IsOp(void** state)
{
    const size_t msg_len = AVTP_GBB_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {
        0x1A, 0x04, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x80, 0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_Gbb_t* gbb = (Avtp_Gbb_t*)msg;
    assert_int_equal(Avtp_Gbb_IsOp(gbb), true);
}

static void Test_Gbb_IsRsp(void** state)
{
    const size_t msg_len = AVTP_GBB_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {
        0x1A, 0x04, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x40, 0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_Gbb_t* gbb = (Avtp_Gbb_t*)msg;
    assert_int_equal(Avtp_Gbb_IsRsp(gbb), true);
}

static void Test_Gbb_IsErr(void** state)
{
    const size_t msg_len = AVTP_GBB_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {
        0x1A, 0x04, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x20, 0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_Gbb_t* gbb = (Avtp_Gbb_t*)msg;
    assert_int_equal(Avtp_Gbb_IsErr(gbb), true);
}

static void Test_Gbb_IsMs(void** state)
{
    const size_t msg_len = AVTP_GBB_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {
        0x1A, 0x04, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x10, 0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_Gbb_t* gbb = (Avtp_Gbb_t*)msg;
    assert_int_equal(Avtp_Gbb_IsMs(gbb), true);
}

static void Test_Gbb_GetReadSize(void** state)
{
    const size_t msg_len = AVTP_GBB_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {
        0x1A, 0x04, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0B, 0xFF,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_Gbb_t* gbb = (Avtp_Gbb_t*)msg;
    assert_int_equal(Avtp_Gbb_GetReadSize(gbb), 0xBFF);
}

static void Test_Gbb_GetSegmentNum(void** state)
{
    const size_t msg_len = AVTP_GBB_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {
        0x1A, 0x04, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0B, 0xFF,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_Gbb_t* gbb = (Avtp_Gbb_t*)msg;
    assert_int_equal(Avtp_Gbb_GetSegmentNum(gbb), 0xBFF);
}

static void Test_Gbb_GetPayloadLen(void** state)
{
    const size_t msg_len = AVTP_GBB_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {
        0x1A, 0x05, 0xC0, 0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0B, 0xFF,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_Gbb_t* gbb = (Avtp_Gbb_t*)msg;
    assert_int_equal(Avtp_Gbb_GetPayloadLen(gbb), 1);
}

static void Test_Gbb_GetPayloadLen_NoPadding(void** state)
{
    const size_t msg_len = AVTP_GBB_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {
        0x1A, 0x05, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0B, 0xFF,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_Gbb_t* gbb = (Avtp_Gbb_t*)msg;
    assert_int_equal(Avtp_Gbb_GetPayloadLen(gbb), 4);
}

static void Test_Gbb_GetLen(void** state)
{
    const size_t msg_len = AVTP_GBB_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {
        0x1A, 0x05, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0B, 0xFF,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_Gbb_t* gbb = (Avtp_Gbb_t*)msg;
    assert_int_equal(Avtp_Gbb_GetLen(gbb), 5 * 4);
}

static void Test_Gbb_SetMtv(void** state)
{
    const size_t msg_len = AVTP_GBB_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_Gbb_t* gbb = (Avtp_Gbb_t*)msg;
    Avtp_Gbb_Init(gbb);
    Avtp_Gbb_SetMtv(gbb, true);

    uint8_t expected_msg[msg_len] = {
        0x1A, 0x04, 0x20, 0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_Gbb_SetByteBusId(void** state)
{
    const size_t msg_len = AVTP_GBB_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_Gbb_t* gbb = (Avtp_Gbb_t*)msg;
    Avtp_Gbb_Init(gbb);
    Avtp_Gbb_SetByteBusId(gbb, 0x5FF);

    uint8_t expected_msg[msg_len] = {
        0x1A, 0x04, 0x5,  0xFF,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_Gbb_SetMessageTimestamp(void** state)
{
    const size_t msg_len = AVTP_GBB_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_Gbb_t* gbb = (Avtp_Gbb_t*)msg;
    Avtp_Gbb_Init(gbb);
    Avtp_Gbb_SetMessageTimestamp(gbb, 0xBFFFFFFFFFFFFFFFull);

    uint8_t expected_msg[msg_len] = {
        0x1A, 0x04, 0x0,  0x0,
        0xBF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_Gbb_SetEvt(void** state)
{
    const size_t msg_len = AVTP_GBB_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_Gbb_t* gbb = (Avtp_Gbb_t*)msg;
    Avtp_Gbb_Init(gbb);
    Avtp_Gbb_SetEvt(gbb, 0xB);

    uint8_t expected_msg[msg_len] = {
        0x1A, 0x04, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0xB0, 0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_Gbb_SetHs(void** state)
{
    const size_t msg_len = AVTP_GBB_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_Gbb_t* gbb = (Avtp_Gbb_t*)msg;
    Avtp_Gbb_Init(gbb);
    Avtp_Gbb_SetHs(gbb, true);

    uint8_t expected_msg[msg_len] = {
        0x1A, 0x04, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x2,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_Gbb_SetCs(void** state)
{
    const size_t msg_len = AVTP_GBB_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_Gbb_t* gbb = (Avtp_Gbb_t*)msg;
    Avtp_Gbb_Init(gbb);
    Avtp_Gbb_SetCs(gbb, true);

    uint8_t expected_msg[msg_len] = {
        0x1A, 0x04, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x1,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_Gbb_SetTransactionNum(void** state)
{
    const size_t msg_len = AVTP_GBB_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_Gbb_t* gbb = (Avtp_Gbb_t*)msg;
    Avtp_Gbb_Init(gbb);
    Avtp_Gbb_SetTransactionNum(gbb, 0xBF);

    uint8_t expected_msg[msg_len] = {
        0x1A, 0x04, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0xBF, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_Gbb_SetOp(void** state)
{
    const size_t msg_len = AVTP_GBB_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_Gbb_t* gbb = (Avtp_Gbb_t*)msg;
    Avtp_Gbb_Init(gbb);
    Avtp_Gbb_SetOp(gbb, true);

    uint8_t expected_msg[msg_len] = {
        0x1A, 0x04, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x80, 0x0,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_Gbb_SetRsp(void** state)
{
    const size_t msg_len = AVTP_GBB_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_Gbb_t* gbb = (Avtp_Gbb_t*)msg;
    Avtp_Gbb_Init(gbb);
    Avtp_Gbb_SetRsp(gbb, true);

    uint8_t expected_msg[msg_len] = {
        0x1A, 0x04, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x40, 0x0,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_Gbb_SetErr(void** state)
{
    const size_t msg_len = AVTP_GBB_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_Gbb_t* gbb = (Avtp_Gbb_t*)msg;
    Avtp_Gbb_Init(gbb);
    Avtp_Gbb_SetErr(gbb, true);

    uint8_t expected_msg[msg_len] = {
        0x1A, 0x04, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x20, 0x0,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_Gbb_SetMs(void** state)
{
    const size_t msg_len = AVTP_GBB_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_Gbb_t* gbb = (Avtp_Gbb_t*)msg;
    Avtp_Gbb_Init(gbb);
    Avtp_Gbb_SetMs(gbb, true);

    uint8_t expected_msg[msg_len] = {
        0x1A, 0x04, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x10, 0x0,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_Gbb_SetReadSize(void** state)
{
    const size_t msg_len = AVTP_GBB_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_Gbb_t* gbb = (Avtp_Gbb_t*)msg;
    Avtp_Gbb_Init(gbb);
    Avtp_Gbb_SetReadSize(gbb, 0xBFF);

    uint8_t expected_msg[msg_len] = {
        0x1A, 0x04, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0xB,  0xFF,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_Gbb_SetSegmentNum(void** state)
{
    const size_t msg_len = AVTP_GBB_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_Gbb_t* gbb = (Avtp_Gbb_t*)msg;
    Avtp_Gbb_Init(gbb);
    Avtp_Gbb_SetSegmentNum(gbb, 0xBFF);

    uint8_t expected_msg[msg_len] = {
        0x1A, 0x04, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0xB,  0xFF,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_Gbb_SetPayloadLen(void** state)
{
    const size_t msg_len = AVTP_GBB_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_Gbb_t* gbb = (Avtp_Gbb_t*)msg;
    Avtp_Gbb_Init(gbb);
    Avtp_Gbb_SetPayloadLen(gbb, 3);

    uint8_t expected_msg[msg_len] = {
        0x1A, 0x05, 0x40, 0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_Gbb_SetPayloadLen_NoPadding(void** state)
{
    const size_t msg_len = AVTP_GBB_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_Gbb_t* gbb = (Avtp_Gbb_t*)msg;
    Avtp_Gbb_Init(gbb);
    Avtp_Gbb_SetPayloadLen(gbb, 4);

    uint8_t expected_msg[msg_len] = {
        0x1A, 0x05, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(msg, expected_msg, msg_len);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(Test_Gbb_Init),
        cmocka_unit_test(Test_Gbb_GetPad),
        cmocka_unit_test(Test_Gbb_IsMtv),
        cmocka_unit_test(Test_Gbb_GetByteBusId),
        cmocka_unit_test(Test_Gbb_GetMessageTimestamp),
        cmocka_unit_test(Test_Gbb_GetEvt),
        cmocka_unit_test(Test_Gbb_IsHs),
        cmocka_unit_test(Test_Gbb_IsCs),
        cmocka_unit_test(Test_Gbb_GetTransactionNum),
        cmocka_unit_test(Test_Gbb_IsOp),
        cmocka_unit_test(Test_Gbb_IsRsp),
        cmocka_unit_test(Test_Gbb_IsErr),
        cmocka_unit_test(Test_Gbb_IsMs),
        cmocka_unit_test(Test_Gbb_GetReadSize),
        cmocka_unit_test(Test_Gbb_GetSegmentNum),
        cmocka_unit_test(Test_Gbb_GetPayloadLen),
        cmocka_unit_test(Test_Gbb_GetPayloadLen_NoPadding),
        cmocka_unit_test(Test_Gbb_GetLen),
        cmocka_unit_test(Test_Gbb_SetMtv),
        cmocka_unit_test(Test_Gbb_SetByteBusId),
        cmocka_unit_test(Test_Gbb_SetMessageTimestamp),
        cmocka_unit_test(Test_Gbb_SetEvt),
        cmocka_unit_test(Test_Gbb_SetHs),
        cmocka_unit_test(Test_Gbb_SetCs),
        cmocka_unit_test(Test_Gbb_SetTransactionNum),
        cmocka_unit_test(Test_Gbb_SetOp),
        cmocka_unit_test(Test_Gbb_SetRsp),
        cmocka_unit_test(Test_Gbb_SetErr),
        cmocka_unit_test(Test_Gbb_SetMs),
        cmocka_unit_test(Test_Gbb_SetReadSize),
        cmocka_unit_test(Test_Gbb_SetSegmentNum),
        cmocka_unit_test(Test_Gbb_SetPayloadLen),
        cmocka_unit_test(Test_Gbb_SetPayloadLen_NoPadding),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

#ifdef __cplusplus
}
#endif
