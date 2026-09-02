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

#include "avtp/acf/CanXl.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>

static void Test_CanXl_Init(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;

    // Check init function while passing in a null pointer
    Avtp_CanXl_Init(NULL);

    Avtp_CanXl_Init(canxl);

    uint8_t expected_msg[msg_len] = {0x22, 0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanXl_GetAcfMsgLength(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x22, 0x06, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    assert_int_equal(Avtp_CanXl_GetAcfMsgLength(canxl), 6);
}

static void Test_CanXl_GetPad(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x22, 0x06, 0xC0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0,  0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0,  0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    assert_int_equal(Avtp_CanXl_GetPad(canxl), 3);
}

static void Test_CanXl_IsMtv(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x22, 0x06, 0x20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0,  0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0,  0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    assert_int_equal(Avtp_CanXl_IsMtv(canxl), true);
}

static void Test_CanXl_GetCanBusId(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x22, 0x06, 0x05, 0xFF, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0,  0x0,  0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0,  0x0,  0x0,  0x0,  0x0, 0x0, 0x0, 0x0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    assert_int_equal(Avtp_CanXl_GetCanBusId(canxl), 0x5FF);
}

static void Test_CanXl_GetMessageTimestamp(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x22, 0x06, 0x0, 0x0, 0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                            0xFF, 0xFF, 0x0, 0x0, 0x0,  0x0,  0x0,  0x0,  0x0,  0x0,
                            0x0,  0x0,  0x0, 0x0, 0x0,  0x0,  0x0,  0x0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    assert_int_equal(Avtp_CanXl_GetMessageTimestamp(canxl), 0xBFFFFFFFFFFFFFFFull);
}

static void Test_CanXl_GetVcid(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x22, 0x06, 0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0,  0x0,  0xBF, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0,  0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    assert_int_equal(Avtp_CanXl_GetVcid(canxl), 0xBF);
}

static void Test_CanXl_GetSdt(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x22, 0x06, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xBF,
                            0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    assert_int_equal(Avtp_CanXl_GetSdt(canxl), 0xBF);
}

static void Test_CanXl_IsRrs(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x22, 0x06, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x10, 0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    assert_int_equal(Avtp_CanXl_IsRrs(canxl), true);
}

static void Test_CanXl_IsSec(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x22, 0x06, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x08, 0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    assert_int_equal(Avtp_CanXl_IsSec(canxl), true);
}

static void Test_CanXl_GetPriorityId(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x22, 0x06, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x05, 0xFF, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    assert_int_equal(Avtp_CanXl_GetPriorityId(canxl), 0x5FF);
}

static void Test_CanXl_GetAcceptanceField(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x22, 0x06, 0x0, 0x0, 0x0, 0x0, 0x0,  0x0,  0x0,  0x0,
                            0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0xBF, 0xFF, 0xFF, 0xFF,
                            0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0,  0x0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    assert_int_equal(Avtp_CanXl_GetAcceptanceField(canxl), 0xBFFFFFFFul);
}

static void Test_CanXl_GetTransactionNum(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x22, 0x06, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0,  0xBF, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    assert_int_equal(Avtp_CanXl_GetTransactionNum(canxl), 0xBF);
}

static void Test_CanXl_IsMs(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x22, 0x06, 0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0,  0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0,  0x0,  0x10, 0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    assert_int_equal(Avtp_CanXl_IsMs(canxl), true);
}

static void Test_CanXl_GetSegmentNum(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x22, 0x06, 0x0, 0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0,  0x0,  0x0, 0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0,  0x0,  0xB, 0xFF, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    assert_int_equal(Avtp_CanXl_GetSegmentNum(canxl), 0xBFF);
}

static void Test_CanXl_GetPayloadLength(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x22, 0x07, 0xC0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0,  0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0,  0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    assert_int_equal(Avtp_CanXl_GetPayloadLength(canxl), 1);
}

static void Test_CanXl_GetPayloadLength_NoPadding(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x22, 0x07, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    assert_int_equal(Avtp_CanXl_GetPayloadLength(canxl), 4);
}

static void Test_CanXl_GetAcfMsgLengthInBytes(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x22, 0x07, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    assert_int_equal(Avtp_CanXl_GetAcfMsgLengthInBytes(canxl), 7 * 4);
}

static void Test_CanXl_SetAcfMsgLength(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    Avtp_CanXl_Init(canxl);
    Avtp_CanXl_SetAcfMsgLength(canxl, 5);
    assert_int_equal(Avtp_CanXl_GetAcfMsgLength(canxl), 5);
    assert_int_equal(Avtp_CanXl_GetAcfMsgLengthInBytes(canxl), 20);
}

static void Test_CanXl_SetMtv(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    Avtp_CanXl_Init(canxl);
    Avtp_CanXl_SetMtv(canxl, true);

    uint8_t expected_msg[msg_len] = {0x22, 0x00, 0x20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanXl_SetCanBusId(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    Avtp_CanXl_Init(canxl);
    Avtp_CanXl_SetCanBusId(canxl, 0x5FF);

    uint8_t expected_msg[msg_len] = {0x22, 0x00, 0x05, 0xFF, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0,  0x0,  0x0, 0x0, 0x0, 0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanXl_SetMessageTimestamp(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    Avtp_CanXl_Init(canxl);
    Avtp_CanXl_SetMessageTimestamp(canxl, 0xBFFFFFFFFFFFFFFFull);

    uint8_t expected_msg[msg_len] = {0x22, 0x00, 0x0, 0x0, 0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                     0xFF, 0xFF, 0x0, 0x0, 0x0,  0x0,  0x0,  0x0,  0x0,  0x0,
                                     0x0,  0x0,  0x0, 0x0, 0x0,  0x0,  0x0,  0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanXl_SetVcid(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    Avtp_CanXl_Init(canxl);
    Avtp_CanXl_SetVcid(canxl, 0xBF);

    uint8_t expected_msg[msg_len] = {0x22, 0x00, 0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0xBF, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanXl_SetSdt(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    Avtp_CanXl_Init(canxl);
    Avtp_CanXl_SetSdt(canxl, 0xBF);

    uint8_t expected_msg[msg_len] = {0x22, 0x00, 0x0, 0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0, 0xBF, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0, 0x0,  0x0, 0x0, 0x0, 0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanXl_SetRrs(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    Avtp_CanXl_Init(canxl);
    Avtp_CanXl_SetRrs(canxl, true);

    uint8_t expected_msg[msg_len] = {0x22, 0x00, 0x0, 0x0, 0x0,  0x0, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0, 0x0, 0x10, 0x0, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0, 0x0, 0x0,  0x0, 0x0, 0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanXl_SetSec(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    Avtp_CanXl_Init(canxl);
    Avtp_CanXl_SetSec(canxl, true);

    uint8_t expected_msg[msg_len] = {0x22, 0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0, 0x0, 0x8, 0x0, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanXl_SetPriorityId(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    Avtp_CanXl_Init(canxl);
    Avtp_CanXl_SetPriorityId(canxl, 0x5FF);

    uint8_t expected_msg[msg_len] = {0x22, 0x00, 0x0, 0x0, 0x0,  0x0,  0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0, 0x0, 0x05, 0xFF, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0, 0x0, 0x0,  0x0,  0x0, 0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanXl_SetAcceptanceField(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    Avtp_CanXl_Init(canxl);
    Avtp_CanXl_SetAcceptanceField(canxl, 0xBFFFFFFFul);

    uint8_t expected_msg[msg_len] = {0x22, 0x00, 0x0, 0x0, 0x0, 0x0, 0x0,  0x0,  0x0,  0x0,
                                     0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0xBF, 0xFF, 0xFF, 0xFF,
                                     0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0,  0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanXl_SetTransactionNum(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    Avtp_CanXl_Init(canxl);
    Avtp_CanXl_SetTransactionNum(canxl, 0xBF);

    uint8_t expected_msg[msg_len] = {0x22, 0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0xBF, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanXl_SetMs(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    Avtp_CanXl_Init(canxl);
    Avtp_CanXl_SetMs(canxl, true);

    uint8_t expected_msg[msg_len] = {0x22, 0x00, 0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x10, 0x0, 0x0, 0x0, 0x0, 0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanXl_SetSegmentNum(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    Avtp_CanXl_Init(canxl);
    Avtp_CanXl_SetSegmentNum(canxl, 0xBFF);

    uint8_t expected_msg[msg_len] = {0x22, 0x00, 0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0B, 0xFF, 0x0, 0x0, 0x0, 0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanXl_SetPayloadLength(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    Avtp_CanXl_Init(canxl);
    Avtp_CanXl_SetPayloadLength(canxl, 3);

    uint8_t expected_msg[msg_len] = {0x22, 0x07, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanXl_SetPayloadLength_NoPadding(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    Avtp_CanXl_Init(canxl);
    Avtp_CanXl_SetPayloadLength(canxl, 4);

    uint8_t expected_msg[msg_len] = {0x22, 0x07, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanXl_Payload(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 8;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    uint8_t payload[8] = {0, 1, 2, 3, 4, 5, 6, 7};

    Avtp_CanXl_Init(canxl);
    Avtp_CanXl_SetPayload(canxl, payload, sizeof(payload));

    assert_ptr_equal(Avtp_CanXl_GetPayload(canxl), msg + AVTP_CANXL_HEADER_LEN);
    assert_memory_equal(payload, Avtp_CanXl_GetPayload(canxl), sizeof(payload));
}

static void Test_CanXl_CreateAcfMessage(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 8;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    uint8_t payload[8] = {0, 1, 2, 3, 4, 5, 6, 7};

    Avtp_CanXl_CreateAcfMessage(canxl, 0x5FF, 0xBFFFFFFFul, 0xBF, payload, sizeof(payload));

    assert_int_equal(Avtp_AcfCommon_GetAcfMsgType((Avtp_AcfCommon_t *)canxl), AVTP_ACF_TYPE_CAN_XL);
    assert_int_equal(Avtp_CanXl_GetPriorityId(canxl), 0x5FF);
    assert_int_equal(Avtp_CanXl_GetAcceptanceField(canxl), 0xBFFFFFFFul);
    assert_int_equal(Avtp_CanXl_GetSdt(canxl), 0xBF);
    assert_memory_equal(payload, msg + AVTP_CANXL_HEADER_LEN, sizeof(payload));
    assert_int_equal(Avtp_CanXl_GetPayloadLength(canxl), 8);

    // can_bus_id, vcid and message_timestamp are set by the caller afterwards
    Avtp_CanXl_SetCanBusId(canxl, 0x5FF);
    Avtp_CanXl_SetVcid(canxl, 0xBF);
    Avtp_CanXl_SetMessageTimestamp(canxl, 0x123456789ABCDEF0ULL);
    assert_int_equal(Avtp_CanXl_GetCanBusId(canxl), 0x5FF);
    assert_int_equal(Avtp_CanXl_GetVcid(canxl), 0xBF);
    assert_int_equal(Avtp_CanXl_GetMessageTimestamp(canxl), 0x123456789ABCDEF0ULL);
}

static void Test_CanXl_CreateFromGarbage(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 8;
    uint8_t msg[msg_len];
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    uint8_t payload[8] = {0, 1, 2, 3, 4, 5, 6, 7};

    // CreateAcfMessage must fully initialize the header even on garbage input.
    memset(msg, 0xAA, msg_len);
    Avtp_CanXl_CreateAcfMessage(canxl, 0x5FF, 0x0, 0x0, payload, sizeof(payload));

    assert_int_equal(Avtp_AcfCommon_GetAcfMsgType((Avtp_AcfCommon_t *)canxl), AVTP_ACF_TYPE_CAN_XL);
    assert_int_equal(Avtp_CanXl_IsMtv(canxl), false);
    assert_int_equal(Avtp_CanXl_IsRrs(canxl), false);
    assert_int_equal(Avtp_CanXl_IsSec(canxl), false);
    assert_int_equal(Avtp_CanXl_IsMs(canxl), false);
    assert_int_equal(Avtp_CanXl_GetCanBusId(canxl), 0);
    assert_int_equal(Avtp_CanXl_GetMessageTimestamp(canxl), 0);
    assert_memory_equal(payload, msg + AVTP_CANXL_HEADER_LEN, sizeof(payload));
    assert_int_equal(Avtp_CanXl_IsValid(canxl, msg_len), 1);
}

static void Test_CanXl_IsValid(void **state)
{
    const size_t msg_len = AVTP_CANXL_HEADER_LEN + 32;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXl_t *canxl = (Avtp_CanXl_t *)msg;
    uint8_t payload[8] = {0, 1, 2, 3, 4, 5, 6, 7};

    // An Init-only PDU has AcfMsgLength == 0, so IsValid must reject it.
    Avtp_CanXl_Init(canxl);
    assert_int_equal(Avtp_CanXl_IsValid(canxl, msg_len), 0);

    // A properly-formed frame with an 8-byte payload is valid.
    Avtp_CanXl_CreateAcfMessage(canxl, 0x5FF, 0x0, 0x0, payload, sizeof(payload));
    assert_int_equal(Avtp_CanXl_IsValid(canxl, msg_len), 1);

    // Not a CAN XL message (zero buffer, AcfMsgType != CAN_XL).
    memset(msg, 0, msg_len);
    assert_int_equal(Avtp_CanXl_IsValid(canxl, msg_len), 0);

    // Declared length larger than the buffer is invalid.
    Avtp_CanXl_CreateAcfMessage(canxl, 0x5FF, 0x0, 0x0, payload, sizeof(payload));
    assert_int_equal(Avtp_CanXl_IsValid(canxl, AVTP_CANXL_HEADER_LEN + 1), 0);
}

int main(void)
{
    const struct CMUnitTest tests[] = {cmocka_unit_test(Test_CanXl_Init),
                                       cmocka_unit_test(Test_CanXl_GetAcfMsgLength),
                                       cmocka_unit_test(Test_CanXl_GetPad),
                                       cmocka_unit_test(Test_CanXl_IsMtv),
                                       cmocka_unit_test(Test_CanXl_GetCanBusId),
                                       cmocka_unit_test(Test_CanXl_GetMessageTimestamp),
                                       cmocka_unit_test(Test_CanXl_GetVcid),
                                       cmocka_unit_test(Test_CanXl_GetSdt),
                                       cmocka_unit_test(Test_CanXl_IsRrs),
                                       cmocka_unit_test(Test_CanXl_IsSec),
                                       cmocka_unit_test(Test_CanXl_GetPriorityId),
                                       cmocka_unit_test(Test_CanXl_GetAcceptanceField),
                                       cmocka_unit_test(Test_CanXl_GetTransactionNum),
                                       cmocka_unit_test(Test_CanXl_IsMs),
                                       cmocka_unit_test(Test_CanXl_GetSegmentNum),
                                       cmocka_unit_test(Test_CanXl_GetPayloadLength),
                                       cmocka_unit_test(Test_CanXl_GetPayloadLength_NoPadding),
                                       cmocka_unit_test(Test_CanXl_GetAcfMsgLengthInBytes),
                                       cmocka_unit_test(Test_CanXl_SetAcfMsgLength),
                                       cmocka_unit_test(Test_CanXl_SetMtv),
                                       cmocka_unit_test(Test_CanXl_SetCanBusId),
                                       cmocka_unit_test(Test_CanXl_SetMessageTimestamp),
                                       cmocka_unit_test(Test_CanXl_SetVcid),
                                       cmocka_unit_test(Test_CanXl_SetSdt),
                                       cmocka_unit_test(Test_CanXl_SetRrs),
                                       cmocka_unit_test(Test_CanXl_SetSec),
                                       cmocka_unit_test(Test_CanXl_SetPriorityId),
                                       cmocka_unit_test(Test_CanXl_SetAcceptanceField),
                                       cmocka_unit_test(Test_CanXl_SetTransactionNum),
                                       cmocka_unit_test(Test_CanXl_SetMs),
                                       cmocka_unit_test(Test_CanXl_SetSegmentNum),
                                       cmocka_unit_test(Test_CanXl_SetPayloadLength),
                                       cmocka_unit_test(Test_CanXl_SetPayloadLength_NoPadding),
                                       cmocka_unit_test(Test_CanXl_Payload),
                                       cmocka_unit_test(Test_CanXl_CreateAcfMessage),
                                       cmocka_unit_test(Test_CanXl_CreateFromGarbage),
                                       cmocka_unit_test(Test_CanXl_IsValid)};

    return cmocka_run_group_tests(tests, NULL, NULL);
}

#ifdef __cplusplus
}
#endif
