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

#include "avtp/acf/CanXlBrief.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>

static void Test_CanXlBrief_Init(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;

    // Check init function while passing in a null pointer
    Avtp_CanXlBrief_Init(NULL);

    Avtp_CanXlBrief_Init(canxl);

    uint8_t expected_msg[msg_len] = {0x24, 0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanXlBrief_GetAcfMsgType(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x24, 0x04, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    assert_int_equal(Avtp_CanXlBrief_GetAcfMsgType(canxl), AVTP_ACF_TYPE_CAN_XL_BRIEF);
}

static void Test_CanXlBrief_GetAcfMsgLength(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x24, 0x04, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    assert_int_equal(Avtp_CanXlBrief_GetAcfMsgLength(canxl), 4);
}

static void Test_CanXlBrief_GetPad(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x24, 0x04, 0xC0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0,  0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    assert_int_equal(Avtp_CanXlBrief_GetPad(canxl), 3);
}

static void Test_CanXlBrief_IsMtv(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x24, 0x04, 0x20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0,  0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    assert_int_equal(Avtp_CanXlBrief_IsMtv(canxl), true);
}

static void Test_CanXlBrief_GetCanBusId(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x24, 0x04, 0x05, 0xFF, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0,  0x0,  0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    assert_int_equal(Avtp_CanXlBrief_GetCanBusId(canxl), 0x5FF);
}

static void Test_CanXlBrief_GetVcid(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x24, 0x04, 0x0, 0x0, 0xBF, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0,  0x0,  0x0, 0x0, 0x0,  0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    assert_int_equal(Avtp_CanXlBrief_GetVcid(canxl), 0xBF);
}

static void Test_CanXlBrief_GetSdt(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x24, 0x04, 0x0, 0x0, 0x0, 0xBF, 0x0, 0x0, 0x0, 0x0,
                            0x0,  0x0,  0x0, 0x0, 0x0, 0x0,  0x0, 0x0, 0x0, 0x0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    assert_int_equal(Avtp_CanXlBrief_GetSdt(canxl), 0xBF);
}

static void Test_CanXlBrief_IsRrs(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x24, 0x04, 0x0, 0x0, 0x0, 0x0, 0x10, 0x0, 0x0, 0x0,
                            0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0,  0x0, 0x0, 0x0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    assert_int_equal(Avtp_CanXlBrief_IsRrs(canxl), true);
}

static void Test_CanXlBrief_IsSec(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x24, 0x04, 0x0, 0x0, 0x0, 0x0, 0x08, 0x0, 0x0, 0x0,
                            0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0,  0x0, 0x0, 0x0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    assert_int_equal(Avtp_CanXlBrief_IsSec(canxl), true);
}

static void Test_CanXlBrief_GetPriorityId(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x24, 0x04, 0x0, 0x0, 0x0, 0x0, 0x05, 0xFF, 0x0, 0x0,
                            0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0,  0x0,  0x0, 0x0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    assert_int_equal(Avtp_CanXlBrief_GetPriorityId(canxl), 0x5FF);
}

static void Test_CanXlBrief_GetAcceptanceField(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x24, 0x04, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xBF, 0xFF,
                            0xFF, 0xFF, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  0x0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    assert_int_equal(Avtp_CanXlBrief_GetAcceptanceField(canxl), 0xBFFFFFFFul);
}

static void Test_CanXlBrief_GetTransactionNum(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x24, 0x04, 0x0, 0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0,  0x0,  0x0, 0xBF, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    assert_int_equal(Avtp_CanXlBrief_GetTransactionNum(canxl), 0xBF);
}

static void Test_CanXlBrief_IsMs(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x24, 0x04, 0x0, 0x0, 0x0,  0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0,  0x0,  0x0, 0x0, 0x10, 0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    assert_int_equal(Avtp_CanXlBrief_IsMs(canxl), true);
}

static void Test_CanXlBrief_GetSegmentNum(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x24, 0x04, 0x0, 0x0, 0x0, 0x0,  0x0, 0x0, 0x0, 0x0,
                            0x0,  0x0,  0x0, 0x0, 0xB, 0xFF, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    assert_int_equal(Avtp_CanXlBrief_GetSegmentNum(canxl), 0xBFF);
}

static void Test_CanXlBrief_GetPayloadLength(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x24, 0x05, 0xC0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0,  0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    assert_int_equal(Avtp_CanXlBrief_GetPayloadLength(canxl), 1);
}

static void Test_CanXlBrief_GetPayloadLength_NoPadding(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x24, 0x05, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    assert_int_equal(Avtp_CanXlBrief_GetPayloadLength(canxl), 4);
}

static void Test_CanXlBrief_GetAcfMsgLengthInBytes(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x24, 0x05, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    assert_int_equal(Avtp_CanXlBrief_GetAcfMsgLengthInBytes(canxl), 5 * 4);
}

static void Test_CanXlBrief_SetAcfMsgType(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    Avtp_CanXlBrief_Init(canxl);
    Avtp_CanXlBrief_SetAcfMsgType(canxl, AVTP_ACF_TYPE_CAN_XL_BRIEF);
    assert_int_equal(Avtp_CanXlBrief_GetAcfMsgType(canxl), AVTP_ACF_TYPE_CAN_XL_BRIEF);
}

static void Test_CanXlBrief_SetAcfMsgLength(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    Avtp_CanXlBrief_Init(canxl);
    Avtp_CanXlBrief_SetAcfMsgLength(canxl, 5);
    assert_int_equal(Avtp_CanXlBrief_GetAcfMsgLength(canxl), 5);
    assert_int_equal(Avtp_CanXlBrief_GetAcfMsgLengthInBytes(canxl), 20);
}

static void Test_CanXlBrief_SetMtv(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    Avtp_CanXlBrief_Init(canxl);
    Avtp_CanXlBrief_SetMtv(canxl, true);

    uint8_t expected_msg[msg_len] = {0x24, 0x00, 0x20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanXlBrief_SetCanBusId(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    Avtp_CanXlBrief_Init(canxl);
    Avtp_CanXlBrief_SetCanBusId(canxl, 0x5FF);

    uint8_t expected_msg[msg_len] = {0x24, 0x00, 0x05, 0xFF, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanXlBrief_SetVcid(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    Avtp_CanXlBrief_Init(canxl);
    Avtp_CanXlBrief_SetVcid(canxl, 0xBF);

    uint8_t expected_msg[msg_len] = {0x24, 0x00, 0x0, 0x0, 0xBF, 0x0, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0, 0x0, 0x0,  0x0, 0x0, 0x0, 0x0, 0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanXlBrief_SetSdt(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    Avtp_CanXlBrief_Init(canxl);
    Avtp_CanXlBrief_SetSdt(canxl, 0xBF);

    uint8_t expected_msg[msg_len] = {0x24, 0x00, 0x0, 0x0, 0x0, 0xBF, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0, 0x0, 0x0, 0x0,  0x0, 0x0, 0x0, 0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanXlBrief_SetRrs(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    Avtp_CanXlBrief_Init(canxl);
    Avtp_CanXlBrief_SetRrs(canxl, true);

    uint8_t expected_msg[msg_len] = {0x24, 0x00, 0x0, 0x0, 0x0, 0x0, 0x10, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0,  0x0, 0x0, 0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanXlBrief_SetSec(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    Avtp_CanXlBrief_Init(canxl);
    Avtp_CanXlBrief_SetSec(canxl, true);

    uint8_t expected_msg[msg_len] = {0x24, 0x00, 0x0, 0x0, 0x0, 0x0, 0x8, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanXlBrief_SetPriorityId(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    Avtp_CanXlBrief_Init(canxl);
    Avtp_CanXlBrief_SetPriorityId(canxl, 0x5FF);

    uint8_t expected_msg[msg_len] = {0x24, 0x00, 0x0, 0x0, 0x0, 0x0, 0x05, 0xFF, 0x0, 0x0,
                                     0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0,  0x0,  0x0, 0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanXlBrief_SetAcceptanceField(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    Avtp_CanXlBrief_Init(canxl);
    Avtp_CanXlBrief_SetAcceptanceField(canxl, 0xBFFFFFFFul);

    uint8_t expected_msg[msg_len] = {0x24, 0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xBF, 0xFF,
                                     0xFF, 0xFF, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanXlBrief_SetTransactionNum(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    Avtp_CanXlBrief_Init(canxl);
    Avtp_CanXlBrief_SetTransactionNum(canxl, 0xBF);

    uint8_t expected_msg[msg_len] = {0x24, 0x00, 0x0, 0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0, 0xBF, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanXlBrief_SetMs(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    Avtp_CanXlBrief_Init(canxl);
    Avtp_CanXlBrief_SetMs(canxl, true);

    uint8_t expected_msg[msg_len] = {0x24, 0x00, 0x0, 0x0, 0x0,  0x0, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0, 0x0, 0x10, 0x0, 0x0, 0x0, 0x0, 0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanXlBrief_SetSegmentNum(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    Avtp_CanXlBrief_Init(canxl);
    Avtp_CanXlBrief_SetSegmentNum(canxl, 0xBFF);

    uint8_t expected_msg[msg_len] = {0x24, 0x00, 0x0, 0x0, 0x0,  0x0,  0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0, 0x0, 0x0B, 0xFF, 0x0, 0x0, 0x0, 0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanXlBrief_SetPayloadLength(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    Avtp_CanXlBrief_Init(canxl);
    Avtp_CanXlBrief_SetPayloadLength(canxl, 3);

    uint8_t expected_msg[msg_len] = {0x24, 0x05, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanXlBrief_SetPayloadLength_NoPadding(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    Avtp_CanXlBrief_Init(canxl);
    Avtp_CanXlBrief_SetPayloadLength(canxl, 4);

    uint8_t expected_msg[msg_len] = {0x24, 0x05, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                     0x0,  0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanXlBrief_Payload(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 8;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    uint8_t payload[8] = {0, 1, 2, 3, 4, 5, 6, 7};

    Avtp_CanXlBrief_Init(canxl);
    Avtp_CanXlBrief_SetPayload(canxl, payload, sizeof(payload));

    assert_ptr_equal(Avtp_CanXlBrief_GetPayload(canxl), msg + AVTP_CANXL_BRIEF_HEADER_LEN);
    assert_memory_equal(payload, Avtp_CanXlBrief_GetPayload(canxl), sizeof(payload));
}

static void Test_CanXlBrief_CreateAcfMessage(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 8;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    uint8_t payload[8] = {0, 1, 2, 3, 4, 5, 6, 7};

    Avtp_CanXlBrief_CreateAcfMessage(canxl, 0x5FF, 0xBFFFFFFFul, 0xBF, payload, sizeof(payload));

    assert_int_equal(Avtp_CanXlBrief_GetAcfMsgType(canxl), AVTP_ACF_TYPE_CAN_XL_BRIEF);
    assert_int_equal(Avtp_CanXlBrief_GetPriorityId(canxl), 0x5FF);
    assert_int_equal(Avtp_CanXlBrief_GetAcceptanceField(canxl), 0xBFFFFFFFul);
    assert_int_equal(Avtp_CanXlBrief_GetSdt(canxl), 0xBF);
    assert_memory_equal(payload, msg + AVTP_CANXL_BRIEF_HEADER_LEN, sizeof(payload));
    assert_int_equal(Avtp_CanXlBrief_GetPayloadLength(canxl), 8);

    // can_bus_id and vcid are set by the caller afterwards
    Avtp_CanXlBrief_SetCanBusId(canxl, 0x5FF);
    Avtp_CanXlBrief_SetVcid(canxl, 0xBF);
    assert_int_equal(Avtp_CanXlBrief_GetCanBusId(canxl), 0x5FF);
    assert_int_equal(Avtp_CanXlBrief_GetVcid(canxl), 0xBF);
}

static void Test_CanXlBrief_CreateFromGarbage(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 8;
    uint8_t msg[msg_len];
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    uint8_t payload[8] = {0, 1, 2, 3, 4, 5, 6, 7};

    // CreateAcfMessage must fully initialize the header even on garbage input.
    memset(msg, 0xAA, msg_len);
    Avtp_CanXlBrief_CreateAcfMessage(canxl, 0x5FF, 0x0, 0x0, payload, sizeof(payload));

    assert_int_equal(Avtp_CanXlBrief_GetAcfMsgType(canxl), AVTP_ACF_TYPE_CAN_XL_BRIEF);
    assert_int_equal(Avtp_CanXlBrief_IsMtv(canxl), false);
    assert_int_equal(Avtp_CanXlBrief_IsRrs(canxl), false);
    assert_int_equal(Avtp_CanXlBrief_IsSec(canxl), false);
    assert_int_equal(Avtp_CanXlBrief_IsMs(canxl), false);
    assert_int_equal(Avtp_CanXlBrief_GetCanBusId(canxl), 0);
    assert_memory_equal(payload, msg + AVTP_CANXL_BRIEF_HEADER_LEN, sizeof(payload));
    assert_int_equal(Avtp_CanXlBrief_IsValid(canxl, msg_len), 1);
}

static void Test_CanXlBrief_IsValid(void **state)
{
    const size_t msg_len = AVTP_CANXL_BRIEF_HEADER_LEN + 32;
    uint8_t msg[msg_len] = {0};
    Avtp_CanXlBrief_t *canxl = (Avtp_CanXlBrief_t *)msg;
    uint8_t payload[8] = {0, 1, 2, 3, 4, 5, 6, 7};

    // An Init-only PDU has AcfMsgLength == 0, so IsValid must reject it.
    Avtp_CanXlBrief_Init(canxl);
    assert_int_equal(Avtp_CanXlBrief_IsValid(canxl, msg_len), 0);

    // A properly-formed frame with an 8-byte payload is valid.
    Avtp_CanXlBrief_CreateAcfMessage(canxl, 0x5FF, 0x0, 0x0, payload, sizeof(payload));
    assert_int_equal(Avtp_CanXlBrief_IsValid(canxl, msg_len), 1);

    // Not a CAN XL Brief message (zero buffer, AcfMsgType != CAN_XL_BRIEF).
    memset(msg, 0, msg_len);
    assert_int_equal(Avtp_CanXlBrief_IsValid(canxl, msg_len), 0);

    // Declared length larger than the buffer is invalid.
    Avtp_CanXlBrief_CreateAcfMessage(canxl, 0x5FF, 0x0, 0x0, payload, sizeof(payload));
    assert_int_equal(Avtp_CanXlBrief_IsValid(canxl, AVTP_CANXL_BRIEF_HEADER_LEN + 1), 0);
}

int main(void)
{
    const struct CMUnitTest tests[] = {cmocka_unit_test(Test_CanXlBrief_Init),
                                       cmocka_unit_test(Test_CanXlBrief_GetAcfMsgType),
                                       cmocka_unit_test(Test_CanXlBrief_GetAcfMsgLength),
                                       cmocka_unit_test(Test_CanXlBrief_GetPad),
                                       cmocka_unit_test(Test_CanXlBrief_IsMtv),
                                       cmocka_unit_test(Test_CanXlBrief_GetCanBusId),
                                       cmocka_unit_test(Test_CanXlBrief_GetVcid),
                                       cmocka_unit_test(Test_CanXlBrief_GetSdt),
                                       cmocka_unit_test(Test_CanXlBrief_IsRrs),
                                       cmocka_unit_test(Test_CanXlBrief_IsSec),
                                       cmocka_unit_test(Test_CanXlBrief_GetPriorityId),
                                       cmocka_unit_test(Test_CanXlBrief_GetAcceptanceField),
                                       cmocka_unit_test(Test_CanXlBrief_GetTransactionNum),
                                       cmocka_unit_test(Test_CanXlBrief_IsMs),
                                       cmocka_unit_test(Test_CanXlBrief_GetSegmentNum),
                                       cmocka_unit_test(Test_CanXlBrief_GetPayloadLength),
                                       cmocka_unit_test(Test_CanXlBrief_GetPayloadLength_NoPadding),
                                       cmocka_unit_test(Test_CanXlBrief_GetAcfMsgLengthInBytes),
                                       cmocka_unit_test(Test_CanXlBrief_SetAcfMsgType),
                                       cmocka_unit_test(Test_CanXlBrief_SetAcfMsgLength),
                                       cmocka_unit_test(Test_CanXlBrief_SetMtv),
                                       cmocka_unit_test(Test_CanXlBrief_SetCanBusId),
                                       cmocka_unit_test(Test_CanXlBrief_SetVcid),
                                       cmocka_unit_test(Test_CanXlBrief_SetSdt),
                                       cmocka_unit_test(Test_CanXlBrief_SetRrs),
                                       cmocka_unit_test(Test_CanXlBrief_SetSec),
                                       cmocka_unit_test(Test_CanXlBrief_SetPriorityId),
                                       cmocka_unit_test(Test_CanXlBrief_SetAcceptanceField),
                                       cmocka_unit_test(Test_CanXlBrief_SetTransactionNum),
                                       cmocka_unit_test(Test_CanXlBrief_SetMs),
                                       cmocka_unit_test(Test_CanXlBrief_SetSegmentNum),
                                       cmocka_unit_test(Test_CanXlBrief_SetPayloadLength),
                                       cmocka_unit_test(Test_CanXlBrief_SetPayloadLength_NoPadding),
                                       cmocka_unit_test(Test_CanXlBrief_Payload),
                                       cmocka_unit_test(Test_CanXlBrief_CreateAcfMessage),
                                       cmocka_unit_test(Test_CanXlBrief_CreateFromGarbage),
                                       cmocka_unit_test(Test_CanXlBrief_IsValid)};

    return cmocka_run_group_tests(tests, NULL, NULL);
}

#ifdef __cplusplus
}
#endif
