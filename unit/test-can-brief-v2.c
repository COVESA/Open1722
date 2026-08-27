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

#include "avtp/acf/CanBriefV2.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>

static void Test_CanBriefV2_Init(void **state)
{
    const size_t msg_len = AVTP_CAN_BRIEF_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanBriefV2_t *canV2 = (Avtp_CanBriefV2_t *)msg;

    // Check init function while passing in a null pointer
    Avtp_CanBriefV2_Init(NULL);

    Avtp_CanBriefV2_Init(canV2);

    uint8_t expected_msg[msg_len] = {0x44, 0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanBriefV2_GetAcfMsgType(void **state)
{
    const size_t msg_len = AVTP_CAN_BRIEF_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x44, 0x02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanBriefV2_t *canV2 = (Avtp_CanBriefV2_t *)msg;
    assert_int_equal(Avtp_CanBriefV2_GetAcfMsgType(canV2), AVTP_ACF_TYPE_CAN_BRIEF_V2);
}

static void Test_CanBriefV2_GetAcfMsgLength(void **state)
{
    const size_t msg_len = AVTP_CAN_BRIEF_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x44, 0x02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanBriefV2_t *canV2 = (Avtp_CanBriefV2_t *)msg;
    assert_int_equal(Avtp_CanBriefV2_GetAcfMsgLength(canV2), 2);
}

static void Test_CanBriefV2_GetPad(void **state)
{
    const size_t msg_len = AVTP_CAN_BRIEF_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x44, 0x02, 0xC0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanBriefV2_t *canV2 = (Avtp_CanBriefV2_t *)msg;
    assert_int_equal(Avtp_CanBriefV2_GetPad(canV2), 3);
}

static void Test_CanBriefV2_IsMtv(void **state)
{
    const size_t msg_len = AVTP_CAN_BRIEF_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x44, 0x02, 0x20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanBriefV2_t *canV2 = (Avtp_CanBriefV2_t *)msg;
    assert_int_equal(Avtp_CanBriefV2_IsMtv(canV2), true);
}

static void Test_CanBriefV2_IsRtr(void **state)
{
    const size_t msg_len = AVTP_CAN_BRIEF_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x44, 0x02, 0x10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanBriefV2_t *canV2 = (Avtp_CanBriefV2_t *)msg;
    assert_int_equal(Avtp_CanBriefV2_IsRtr(canV2), true);
}

static void Test_CanBriefV2_IsEff(void **state)
{
    const size_t msg_len = AVTP_CAN_BRIEF_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x44, 0x02, 0x08, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanBriefV2_t *canV2 = (Avtp_CanBriefV2_t *)msg;
    assert_int_equal(Avtp_CanBriefV2_IsEff(canV2), true);
}

static void Test_CanBriefV2_GetCanBusId(void **state)
{
    const size_t msg_len = AVTP_CAN_BRIEF_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x44, 0x02, 0x05, 0xFF, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanBriefV2_t *canV2 = (Avtp_CanBriefV2_t *)msg;
    assert_int_equal(Avtp_CanBriefV2_GetCanBusId(canV2), 0x5FF);
}

static void Test_CanBriefV2_IsBrs(void **state)
{
    const size_t msg_len = AVTP_CAN_BRIEF_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x44, 0x02, 0x0, 0x0, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanBriefV2_t *canV2 = (Avtp_CanBriefV2_t *)msg;
    assert_int_equal(Avtp_CanBriefV2_IsBrs(canV2), true);
}

static void Test_CanBriefV2_IsFdf(void **state)
{
    const size_t msg_len = AVTP_CAN_BRIEF_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x44, 0x02, 0x0, 0x0, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanBriefV2_t *canV2 = (Avtp_CanBriefV2_t *)msg;
    assert_int_equal(Avtp_CanBriefV2_IsFdf(canV2), true);
}

static void Test_CanBriefV2_IsEsi(void **state)
{
    const size_t msg_len = AVTP_CAN_BRIEF_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x44, 0x02, 0x0, 0x0, 0x20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanBriefV2_t *canV2 = (Avtp_CanBriefV2_t *)msg;
    assert_int_equal(Avtp_CanBriefV2_IsEsi(canV2), true);
}

static void Test_CanBriefV2_GetCanIdentifier(void **state)
{
    const size_t msg_len = AVTP_CAN_BRIEF_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x44, 0x02, 0x0, 0x0, 0x17, 0xFF, 0xFF, 0xFF, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanBriefV2_t *canV2 = (Avtp_CanBriefV2_t *)msg;
    assert_int_equal(Avtp_CanBriefV2_GetCanIdentifier(canV2), 0x17FFFFFFul);
}

static void Test_CanBriefV2_GetPayloadLength(void **state)
{
    const size_t msg_len = AVTP_CAN_BRIEF_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x44, 0x03, 0xC0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanBriefV2_t *canV2 = (Avtp_CanBriefV2_t *)msg;
    assert_int_equal(Avtp_CanBriefV2_GetPayloadLength(canV2), 1);
}

static void Test_CanBriefV2_GetPayloadLength_NoPadding(void **state)
{
    const size_t msg_len = AVTP_CAN_BRIEF_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x44, 0x03, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanBriefV2_t *canV2 = (Avtp_CanBriefV2_t *)msg;
    assert_int_equal(Avtp_CanBriefV2_GetPayloadLength(canV2), 4);
}

static void Test_CanBriefV2_GetAcfMsgLengthInBytes(void **state)
{
    const size_t msg_len = AVTP_CAN_BRIEF_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0x44, 0x03, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    Avtp_CanBriefV2_t *canV2 = (Avtp_CanBriefV2_t *)msg;
    assert_int_equal(Avtp_CanBriefV2_GetAcfMsgLengthInBytes(canV2), 3 * 4);
}

static void Test_CanBriefV2_SetAcfMsgType(void **state)
{
    const size_t msg_len = AVTP_CAN_BRIEF_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanBriefV2_t *canV2 = (Avtp_CanBriefV2_t *)msg;
    Avtp_CanBriefV2_Init(canV2);
    Avtp_CanBriefV2_SetAcfMsgType(canV2, AVTP_ACF_TYPE_CAN_BRIEF_V2);
    assert_int_equal(Avtp_CanBriefV2_GetAcfMsgType(canV2), AVTP_ACF_TYPE_CAN_BRIEF_V2);
}

static void Test_CanBriefV2_SetAcfMsgLength(void **state)
{
    const size_t msg_len = AVTP_CAN_BRIEF_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanBriefV2_t *canV2 = (Avtp_CanBriefV2_t *)msg;
    Avtp_CanBriefV2_Init(canV2);
    Avtp_CanBriefV2_SetAcfMsgLength(canV2, 5);
    assert_int_equal(Avtp_CanBriefV2_GetAcfMsgLength(canV2), 5);
    assert_int_equal(Avtp_CanBriefV2_GetAcfMsgLengthInBytes(canV2), 20);
}

static void Test_CanBriefV2_SetMtv(void **state)
{
    const size_t msg_len = AVTP_CAN_BRIEF_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanBriefV2_t *canV2 = (Avtp_CanBriefV2_t *)msg;
    Avtp_CanBriefV2_Init(canV2);
    Avtp_CanBriefV2_SetMtv(canV2, true);

    uint8_t expected_msg[msg_len] = {0x44, 0x00, 0x20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanBriefV2_SetRtr(void **state)
{
    const size_t msg_len = AVTP_CAN_BRIEF_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanBriefV2_t *canV2 = (Avtp_CanBriefV2_t *)msg;
    Avtp_CanBriefV2_Init(canV2);
    Avtp_CanBriefV2_SetRtr(canV2, true);

    uint8_t expected_msg[msg_len] = {0x44, 0x00, 0x10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanBriefV2_SetEff(void **state)
{
    const size_t msg_len = AVTP_CAN_BRIEF_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanBriefV2_t *canV2 = (Avtp_CanBriefV2_t *)msg;
    Avtp_CanBriefV2_Init(canV2);
    Avtp_CanBriefV2_SetEff(canV2, true);

    uint8_t expected_msg[msg_len] = {0x44, 0x00, 0x08, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanBriefV2_SetCanBusId(void **state)
{
    const size_t msg_len = AVTP_CAN_BRIEF_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanBriefV2_t *canV2 = (Avtp_CanBriefV2_t *)msg;
    Avtp_CanBriefV2_Init(canV2);
    Avtp_CanBriefV2_SetCanBusId(canV2, 0x5FF);

    uint8_t expected_msg[msg_len] = {0x44, 0x00, 0x05, 0xFF, 0x0, 0x0,
                                     0x0,  0x0,  0x0,  0x0,  0x0, 0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanBriefV2_SetBrs(void **state)
{
    const size_t msg_len = AVTP_CAN_BRIEF_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanBriefV2_t *canV2 = (Avtp_CanBriefV2_t *)msg;
    Avtp_CanBriefV2_Init(canV2);
    Avtp_CanBriefV2_SetBrs(canV2, true);

    uint8_t expected_msg[msg_len] = {0x44, 0x00, 0x0, 0x0, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanBriefV2_SetFdf(void **state)
{
    const size_t msg_len = AVTP_CAN_BRIEF_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanBriefV2_t *canV2 = (Avtp_CanBriefV2_t *)msg;
    Avtp_CanBriefV2_Init(canV2);
    Avtp_CanBriefV2_SetFdf(canV2, true);

    uint8_t expected_msg[msg_len] = {0x44, 0x00, 0x0, 0x0, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanBriefV2_SetEsi(void **state)
{
    const size_t msg_len = AVTP_CAN_BRIEF_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanBriefV2_t *canV2 = (Avtp_CanBriefV2_t *)msg;
    Avtp_CanBriefV2_Init(canV2);
    Avtp_CanBriefV2_SetEsi(canV2, true);

    uint8_t expected_msg[msg_len] = {0x44, 0x00, 0x0, 0x0, 0x20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanBriefV2_SetCanIdentifier(void **state)
{
    const size_t msg_len = AVTP_CAN_BRIEF_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanBriefV2_t *canV2 = (Avtp_CanBriefV2_t *)msg;
    Avtp_CanBriefV2_Init(canV2);
    Avtp_CanBriefV2_SetCanIdentifier(canV2, 0x17FFFFFFul);

    uint8_t expected_msg[msg_len] = {0x44, 0x00, 0x0, 0x0, 0x17, 0xFF,
                                     0xFF, 0xFF, 0x0, 0x0, 0x0,  0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanBriefV2_SetPayloadLength(void **state)
{
    const size_t msg_len = AVTP_CAN_BRIEF_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanBriefV2_t *canV2 = (Avtp_CanBriefV2_t *)msg;
    Avtp_CanBriefV2_Init(canV2);
    Avtp_CanBriefV2_SetPayloadLength(canV2, 3);

    uint8_t expected_msg[msg_len] = {0x44, 0x03, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanBriefV2_SetPayloadLength_NoPadding(void **state)
{
    const size_t msg_len = AVTP_CAN_BRIEF_V2_HEADER_LEN + 4;
    uint8_t msg[msg_len] = {0};
    Avtp_CanBriefV2_t *canV2 = (Avtp_CanBriefV2_t *)msg;
    Avtp_CanBriefV2_Init(canV2);
    Avtp_CanBriefV2_SetPayloadLength(canV2, 4);

    uint8_t expected_msg[msg_len] = {0x44, 0x03, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    assert_memory_equal(msg, expected_msg, msg_len);
}

static void Test_CanBriefV2_Payload(void **state)
{
    const size_t msg_len = AVTP_CAN_BRIEF_V2_HEADER_LEN + 8;
    uint8_t msg[msg_len] = {0};
    Avtp_CanBriefV2_t *canV2 = (Avtp_CanBriefV2_t *)msg;
    uint8_t payload[8] = {0, 1, 2, 3, 4, 5, 6, 7};

    Avtp_CanBriefV2_Init(canV2);
    Avtp_CanBriefV2_SetPayload(canV2, payload, sizeof(payload));

    assert_ptr_equal(Avtp_CanBriefV2_GetPayload(canV2), msg + AVTP_CAN_BRIEF_V2_HEADER_LEN);
    assert_memory_equal(payload, Avtp_CanBriefV2_GetPayload(canV2), sizeof(payload));
}

static void Test_CanBriefV2_CreateAcfMessage(void **state)
{
    const size_t msg_len = AVTP_CAN_BRIEF_V2_HEADER_LEN + 8;
    uint8_t msg[msg_len] = {0};
    Avtp_CanBriefV2_t *canV2 = (Avtp_CanBriefV2_t *)msg;
    uint8_t payload[8] = {0, 1, 2, 3, 4, 5, 6, 7};

    Avtp_CanBriefV2_Init(canV2);
    Avtp_CanBriefV2_CreateAcfMessage(canV2, 0x7ff, 0x5FF, payload, sizeof(payload),
                                     AVTP_CAN_CLASSIC);

    assert_int_equal(Avtp_CanBriefV2_GetCanIdentifier(canV2), 0x7ff);
    assert_int_equal(Avtp_CanBriefV2_GetCanBusId(canV2), 0x5FF);
    assert_int_equal(Avtp_CanBriefV2_IsEff(canV2), false);
    assert_memory_equal(payload, msg + AVTP_CAN_BRIEF_V2_HEADER_LEN, sizeof(payload));
    assert_int_equal(Avtp_CanBriefV2_GetPayloadLength(canV2), 8);

    // Extended Frame IDs set the EFF flag
    Avtp_CanBriefV2_CreateAcfMessage(canV2, 0x800, 0x5FF, payload, sizeof(payload),
                                     AVTP_CAN_CLASSIC);
    assert_int_equal(Avtp_CanBriefV2_GetCanIdentifier(canV2), 0x800);
    assert_int_equal(Avtp_CanBriefV2_IsEff(canV2), true);
}

static void Test_CanBriefV2_IsValid(void **state)
{
    const size_t msg_len = AVTP_CAN_BRIEF_V2_HEADER_LEN + 68;
    uint8_t msg[msg_len] = {0};
    Avtp_CanBriefV2_t *canV2 = (Avtp_CanBriefV2_t *)msg;
    uint32_t frame_id = 0x123;

    // An Init-only PDU has AcfMsgLength == 0, so IsValid must reject it.
    Avtp_CanBriefV2_Init(canV2);
    assert_int_equal(Avtp_CanBriefV2_IsValid(canV2, msg_len), 0);

    // A properly-formed classic CAN frame with an 8-byte payload is valid.
    {
        uint8_t payload[8] = {0, 1, 2, 3, 4, 5, 6, 7};
        Avtp_CanBriefV2_Init(canV2);
        Avtp_CanBriefV2_CreateAcfMessage(canV2, frame_id, 0x0, payload, sizeof(payload),
                                         AVTP_CAN_CLASSIC);
        assert_int_equal(Avtp_CanBriefV2_IsValid(canV2, msg_len), 1);
    }

    // Not a CAN Brief V2 message (zero buffer, AcfMsgType != CAN_BRIEF_V2).
    memset(msg, 0, msg_len);
    assert_int_equal(Avtp_CanBriefV2_IsValid(canV2, msg_len), 0);

    // Classic CAN payload bound: a 12-byte payload as classic CAN is invalid.
    {
        uint8_t too_big[12] = {0};
        Avtp_CanBriefV2_Init(canV2);
        Avtp_CanBriefV2_CreateAcfMessage(canV2, frame_id, 0x0, too_big, sizeof(too_big),
                                         AVTP_CAN_CLASSIC);
        assert_int_equal(Avtp_CanBriefV2_IsValid(canV2, msg_len), 0);
    }

    // CAN-FD payload bound: 64 bytes valid, 68 bytes invalid.
    {
        uint8_t fd_max[64] = {0};
        Avtp_CanBriefV2_Init(canV2);
        Avtp_CanBriefV2_CreateAcfMessage(canV2, frame_id, 0x0, fd_max, sizeof(fd_max), AVTP_CAN_FD);
        assert_int_equal(Avtp_CanBriefV2_IsValid(canV2, msg_len), 1);
    }
    {
        uint8_t fd_too_big[68] = {0};
        Avtp_CanBriefV2_Init(canV2);
        Avtp_CanBriefV2_CreateAcfMessage(canV2, frame_id, 0x0, fd_too_big, sizeof(fd_too_big),
                                         AVTP_CAN_FD);
        assert_int_equal(Avtp_CanBriefV2_IsValid(canV2, msg_len), 0);
    }
}

int main(void)
{
    const struct CMUnitTest tests[] = {cmocka_unit_test(Test_CanBriefV2_Init),
                                       cmocka_unit_test(Test_CanBriefV2_GetAcfMsgType),
                                       cmocka_unit_test(Test_CanBriefV2_GetAcfMsgLength),
                                       cmocka_unit_test(Test_CanBriefV2_GetPad),
                                       cmocka_unit_test(Test_CanBriefV2_IsMtv),
                                       cmocka_unit_test(Test_CanBriefV2_IsRtr),
                                       cmocka_unit_test(Test_CanBriefV2_IsEff),
                                       cmocka_unit_test(Test_CanBriefV2_GetCanBusId),
                                       cmocka_unit_test(Test_CanBriefV2_IsBrs),
                                       cmocka_unit_test(Test_CanBriefV2_IsFdf),
                                       cmocka_unit_test(Test_CanBriefV2_IsEsi),
                                       cmocka_unit_test(Test_CanBriefV2_GetCanIdentifier),
                                       cmocka_unit_test(Test_CanBriefV2_GetPayloadLength),
                                       cmocka_unit_test(Test_CanBriefV2_GetPayloadLength_NoPadding),
                                       cmocka_unit_test(Test_CanBriefV2_GetAcfMsgLengthInBytes),
                                       cmocka_unit_test(Test_CanBriefV2_SetAcfMsgType),
                                       cmocka_unit_test(Test_CanBriefV2_SetAcfMsgLength),
                                       cmocka_unit_test(Test_CanBriefV2_SetMtv),
                                       cmocka_unit_test(Test_CanBriefV2_SetRtr),
                                       cmocka_unit_test(Test_CanBriefV2_SetEff),
                                       cmocka_unit_test(Test_CanBriefV2_SetCanBusId),
                                       cmocka_unit_test(Test_CanBriefV2_SetBrs),
                                       cmocka_unit_test(Test_CanBriefV2_SetFdf),
                                       cmocka_unit_test(Test_CanBriefV2_SetEsi),
                                       cmocka_unit_test(Test_CanBriefV2_SetCanIdentifier),
                                       cmocka_unit_test(Test_CanBriefV2_SetPayloadLength),
                                       cmocka_unit_test(Test_CanBriefV2_SetPayloadLength_NoPadding),
                                       cmocka_unit_test(Test_CanBriefV2_Payload),
                                       cmocka_unit_test(Test_CanBriefV2_CreateAcfMessage),
                                       cmocka_unit_test(Test_CanBriefV2_IsValid)};

    return cmocka_run_group_tests(tests, NULL, NULL);
}

#ifdef __cplusplus
}
#endif
