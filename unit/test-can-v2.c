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

#ifdef __cplusplus
extern "C" {
#endif

#include "avtp/acf/CanV2.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>

static void Test_CanV2_Init(void** state)
{
    const size_t msg_len = AVTP_CAN_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanV2_t* canV2 = (Avtp_CanV2_t*)msg;
    Avtp_CanV2_Init(canV2);

    uint8_t expected_msg[msg_len] = {
        0x42, 0x04, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };

    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanV2_GetPad(void** state)
{
    const size_t msg_len = AVTP_CAN_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {
        0x42, 0x04, 0xC0, 0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_CanV2_t* canV2 = (Avtp_CanV2_t*)msg;
    assert_int_equal(Avtp_CanV2_GetPad(canV2), 3);
}

static void Test_CanV2_IsMtv(void** state)
{
    const size_t msg_len = AVTP_CAN_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {
        0x42, 0x04, 0x20, 0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_CanV2_t* canV2 = (Avtp_CanV2_t*)msg;
    assert_int_equal(Avtp_CanV2_IsMtv(canV2), true);
}

static void Test_CanV2_IsRtr(void** state)
{
    const size_t msg_len = AVTP_CAN_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {
        0x42, 0x04, 0x10, 0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_CanV2_t* canV2 = (Avtp_CanV2_t*)msg;
    assert_int_equal(Avtp_CanV2_IsRtr(canV2), true);
}

static void Test_CanV2_IsEff(void** state)
{
    const size_t msg_len = AVTP_CAN_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {
        0x42, 0x04, 0x08, 0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_CanV2_t* canV2 = (Avtp_CanV2_t*)msg;
    assert_int_equal(Avtp_CanV2_IsEff(canV2), true);
}

static void Test_CanV2_GetCanBusId(void** state)
{
    const size_t msg_len = AVTP_CAN_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {
        0x42, 0x04, 0x05, 0xFF,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_CanV2_t* canV2 = (Avtp_CanV2_t*)msg;
    assert_int_equal(Avtp_CanV2_GetCanBusId(canV2), 0x5FF);
}

static void Test_CanV2_GetMessageTimestamp(void** state)
{
    const size_t msg_len = AVTP_CAN_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {
        0x42, 0x04, 0x0,  0x0,
        0xBF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_CanV2_t* canV2 = (Avtp_CanV2_t*)msg;
    assert_int_equal(Avtp_CanV2_GetMessageTimestamp(canV2), 0xBFFFFFFFFFFFFFFFull);
}

static void Test_CanV2_IsBrs(void** state)
{
    const size_t msg_len = AVTP_CAN_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {
        0x42, 0x04, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x80, 0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_CanV2_t* canV2 = (Avtp_CanV2_t*)msg;
    assert_int_equal(Avtp_CanV2_IsBrs(canV2), true);
}

static void Test_CanV2_IsFdf(void** state)
{
    const size_t msg_len = AVTP_CAN_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {
        0x42, 0x04, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x40, 0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_CanV2_t* canV2 = (Avtp_CanV2_t*)msg;
    assert_int_equal(Avtp_CanV2_IsFdf(canV2), true);
}

static void Test_CanV2_IsEsi(void** state)
{
    const size_t msg_len = AVTP_CAN_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {
        0x42, 0x04, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x20, 0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_CanV2_t* canV2 = (Avtp_CanV2_t*)msg;
    assert_int_equal(Avtp_CanV2_IsEsi(canV2), true);
}

static void Test_CanV2_GetCanIdentifier(void** state)
{
    const size_t msg_len = AVTP_CAN_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {
        0x42, 0x04, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x17, 0xFF, 0xFF, 0xFF,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_CanV2_t* canV2 = (Avtp_CanV2_t*)msg;
    assert_int_equal(Avtp_CanV2_GetCanIdentifier(canV2), 0x17FFFFFFul);
}

static void Test_CanV2_GetPayloadLen(void** state)
{
    const size_t msg_len = AVTP_CAN_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {
        0x42, 0x05, 0xC0, 0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_CanV2_t* canV2 = (Avtp_CanV2_t*)msg;
    assert_int_equal(Avtp_CanV2_GetPayloadLen(canV2), 1);
}

static void Test_CanV2_GetPayloadLen_NoPadding(void** state)
{
    const size_t msg_len = AVTP_CAN_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {
        0x42, 0x05, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_CanV2_t* canV2 = (Avtp_CanV2_t*)msg;
    assert_int_equal(Avtp_CanV2_GetPayloadLen(canV2), 4);
}

static void Test_CanV2_GetLen(void** state)
{
    const size_t msg_len = AVTP_CAN_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {
        0x42, 0x05, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    Avtp_CanV2_t* canV2 = (Avtp_CanV2_t*)msg;
    assert_int_equal(Avtp_CanV2_GetLen(canV2), 5 * 4);
}

static void Test_CanV2_SetMtv(void** state)
{
    const size_t msg_len = AVTP_CAN_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanV2_t* canV2 = (Avtp_CanV2_t*)msg;
    Avtp_CanV2_Init(canV2);
    Avtp_CanV2_SetMtv(canV2, true);

    uint8_t expected_msg[msg_len] = {
        0x42, 0x04, 0x20, 0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanV2_SetRtr(void** state)
{
    const size_t msg_len = AVTP_CAN_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanV2_t* canV2 = (Avtp_CanV2_t*)msg;
    Avtp_CanV2_Init(canV2);
    Avtp_CanV2_SetRtr(canV2, true);

    uint8_t expected_msg[msg_len] = {
        0x42, 0x04, 0x10, 0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanV2_SetEff(void** state)
{
    const size_t msg_len = AVTP_CAN_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanV2_t* canV2 = (Avtp_CanV2_t*)msg;
    Avtp_CanV2_Init(canV2);
    Avtp_CanV2_SetEff(canV2, true);

    uint8_t expected_msg[msg_len] = {
        0x42, 0x04, 0x08, 0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanV2_SetCanBusId(void** state)
{
    const size_t msg_len = AVTP_CAN_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanV2_t* canV2 = (Avtp_CanV2_t*)msg;
    Avtp_CanV2_Init(canV2);
    Avtp_CanV2_SetCanBusId(canV2, 0x5FF);

    uint8_t expected_msg[msg_len] = {
        0x42, 0x04, 0x05, 0xFF,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanV2_SetMessageTimestamp(void** state)
{
    const size_t msg_len = AVTP_CAN_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanV2_t* canV2 = (Avtp_CanV2_t*)msg;
    Avtp_CanV2_Init(canV2);
    Avtp_CanV2_SetMessageTimestamp(canV2, 0xBFFFFFFFFFFFFFFFull);

    uint8_t expected_msg[msg_len] = {
        0x42, 0x04, 0x0,  0x0,
        0xBF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanV2_SetBrs(void** state)
{
    const size_t msg_len = AVTP_CAN_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanV2_t* canV2 = (Avtp_CanV2_t*)msg;
    Avtp_CanV2_Init(canV2);
    Avtp_CanV2_SetBrs(canV2, true);

    uint8_t expected_msg[msg_len] = {
        0x42, 0x04, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x80, 0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanV2_SetFdf(void** state)
{
    const size_t msg_len = AVTP_CAN_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanV2_t* canV2 = (Avtp_CanV2_t*)msg;
    Avtp_CanV2_Init(canV2);
    Avtp_CanV2_SetFdf(canV2, true);

    uint8_t expected_msg[msg_len] = {
        0x42, 0x04, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x40, 0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanV2_SetEsi(void** state)
{
    const size_t msg_len = AVTP_CAN_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanV2_t* canV2 = (Avtp_CanV2_t*)msg;
    Avtp_CanV2_Init(canV2);
    Avtp_CanV2_SetEsi(canV2, true);

    uint8_t expected_msg[msg_len] = {
        0x42, 0x04, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x20, 0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanV2_SetCanIdentifier(void** state)
{
    const size_t msg_len = AVTP_CAN_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanV2_t* canV2 = (Avtp_CanV2_t*)msg;
    Avtp_CanV2_Init(canV2);
    Avtp_CanV2_SetCanIdentifier(canV2, 0x17FFFFFFul);

    uint8_t expected_msg[msg_len] = {
        0x42, 0x04, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x17, 0xFF, 0xFF, 0xFF,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanV2_SetPayloadLen(void** state)
{
    const size_t msg_len = AVTP_CAN_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanV2_t* canV2 = (Avtp_CanV2_t*)msg;
    Avtp_CanV2_Init(canV2);
    Avtp_CanV2_SetPayloadLen(canV2, 3);

    uint8_t expected_msg[msg_len] = {
        0x42, 0x05, 0x40, 0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanV2_SetPayloadLen_NoPadding(void** state)
{
    const size_t msg_len = AVTP_CAN_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanV2_t* canV2 = (Avtp_CanV2_t*)msg;
    Avtp_CanV2_Init(canV2);
    Avtp_CanV2_SetPayloadLen(canV2, 4);

    uint8_t expected_msg[msg_len] = {
        0x42, 0x05, 0x0,  0x0,
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
        cmocka_unit_test(Test_CanV2_Init),
        cmocka_unit_test(Test_CanV2_GetPad),
        cmocka_unit_test(Test_CanV2_IsMtv),
        cmocka_unit_test(Test_CanV2_IsRtr),
        cmocka_unit_test(Test_CanV2_IsEff),
        cmocka_unit_test(Test_CanV2_GetCanBusId),
        cmocka_unit_test(Test_CanV2_GetMessageTimestamp),
        cmocka_unit_test(Test_CanV2_IsBrs),
        cmocka_unit_test(Test_CanV2_IsFdf),
        cmocka_unit_test(Test_CanV2_IsEsi),
        cmocka_unit_test(Test_CanV2_GetCanIdentifier),
        cmocka_unit_test(Test_CanV2_GetPayloadLen),
        cmocka_unit_test(Test_CanV2_GetPayloadLen_NoPadding),
        cmocka_unit_test(Test_CanV2_GetLen),
        cmocka_unit_test(Test_CanV2_SetMtv),
        cmocka_unit_test(Test_CanV2_SetRtr),
        cmocka_unit_test(Test_CanV2_SetEff),
        cmocka_unit_test(Test_CanV2_SetCanBusId),
        cmocka_unit_test(Test_CanV2_SetMessageTimestamp),
        cmocka_unit_test(Test_CanV2_SetBrs),
        cmocka_unit_test(Test_CanV2_SetFdf),
        cmocka_unit_test(Test_CanV2_SetEsi),
        cmocka_unit_test(Test_CanV2_SetCanIdentifier),
        cmocka_unit_test(Test_CanV2_SetPayloadLen),
        cmocka_unit_test(Test_CanV2_SetPayloadLen_NoPadding)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

#ifdef __cplusplus
}
#endif
