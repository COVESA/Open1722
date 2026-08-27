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
#include <errno.h>
#include <string.h>
#include <math.h>
#include <stdio.h>

#include "avtp/acf/Can.h"
#include "avtp/acf/CanBrief.h"

#define MAX_PDU_SIZE 1500
#define CAN_PAYLOAD_SIZE 8

static void can_init(void **state)
{

    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t init_pdu[AVTP_CAN_HEADER_LEN];

    // Check init function while passing in a null pointer
    Avtp_Can_Init(NULL);

    // Check if the function is initializing properly
    Avtp_Can_Init((Avtp_Can_t *)pdu);
    memset(init_pdu, 0, AVTP_CAN_HEADER_LEN);
    init_pdu[0] = AVTP_ACF_TYPE_CAN << 1; // Setting ACF type as ACF_CAN
    assert_memory_equal(init_pdu, pdu, AVTP_CAN_HEADER_LEN);
}

static void can_brief_init(void **state)
{

    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t init_pdu[AVTP_CAN_BRIEF_HEADER_LEN];

    // Check init function while passing in a null pointer
    Avtp_CanBrief_Init(NULL);

    // Check if the function is initializing properly
    Avtp_CanBrief_Init((Avtp_CanBrief_t *)pdu);
    memset(init_pdu, 0, AVTP_CAN_BRIEF_HEADER_LEN);
    init_pdu[0] = 0x04; // Setting ACF type as ACF_CAN
    assert_memory_equal(init_pdu, pdu, AVTP_CAN_BRIEF_HEADER_LEN);
}

static void can_set_payload(void **state)
{

    uint8_t pdu[MAX_PDU_SIZE];
    uint32_t set_frame_id = 0x7ff;
    uint8_t set_payload[CAN_PAYLOAD_SIZE] = {0, 1, 2, 3, 4, 5, 6, 7};

    // Initialize PDU
    Avtp_Can_Init((Avtp_Can_t *)pdu);

    // Set payload and check for EFF
    Avtp_Can_CreateAcfMessage((Avtp_Can_t *)pdu, set_frame_id, set_payload, CAN_PAYLOAD_SIZE,
                              AVTP_CAN_CLASSIC);
    assert_int_equal(htonl(set_frame_id), (uint32_t) * ((int *)pdu + 3));
    assert_memory_equal(set_payload, pdu + 16, CAN_PAYLOAD_SIZE);
    assert_int_equal(0x0, *(pdu + 2) & 0x08); // Check EFF

    // Check EFF for extended Frame IDs
    set_frame_id = 0x800;
    Avtp_Can_CreateAcfMessage((Avtp_Can_t *)pdu, set_frame_id, set_payload, CAN_PAYLOAD_SIZE,
                              AVTP_CAN_CLASSIC);
    assert_int_equal(htonl(set_frame_id), (uint32_t) * ((int *)pdu + 3));
    assert_int_equal(0x8, *(pdu + 2) & 0x08); // Check EFF

    // Check padding bytes and length field
    uint8_t zero_array[CAN_PAYLOAD_SIZE] = {0, 0, 0, 0, 0, 0, 0, 0};
    for (int i = 0; i < CAN_PAYLOAD_SIZE; i++) {
        memset(pdu, 0, MAX_PDU_SIZE);
        Avtp_Can_Init((Avtp_Can_t *)pdu);
        Avtp_Can_CreateAcfMessage((Avtp_Can_t *)pdu, set_frame_id, set_payload, i,
                                  AVTP_CAN_CLASSIC);
        assert_memory_equal(set_payload, pdu + 16, i);
        assert_memory_equal(zero_array, pdu + 16 + i, CAN_PAYLOAD_SIZE - i);

        // Padding tests
        uint8_t pad = *(pdu + 2) & 0xc0;
        assert_int_equal(pad >> 6, (4 - i % 4) & 0x3);

        // Length tests
        uint8_t length = *(pdu + 1);
        assert_int_equal(length, (4 + ceil(i / 4.0)));
    }
}

static void can_is_valid(void **state)
{

    uint8_t pdu[MAX_PDU_SIZE];
    uint32_t frame_id = 0x123;

    // An Init-only PDU has AcfMsgLength == 0 — i.e. it declares a frame
    // shorter than its own header. Per IEEE 1722 ACF wire format that is
    // not a valid frame, so IsValid must reject it.
    Avtp_Can_Init((Avtp_Can_t *)pdu);
    assert_int_equal(Avtp_Can_IsValid((Avtp_Can_t *)pdu, MAX_PDU_SIZE), 0);

    // A properly-formed classic CAN frame with an 8-byte payload (the
    // classic-CAN max) is valid.
    {
        uint8_t payload[8] = {0, 1, 2, 3, 4, 5, 6, 7};
        Avtp_Can_Init((Avtp_Can_t *)pdu);
        Avtp_Can_CreateAcfMessage((Avtp_Can_t *)pdu, frame_id, payload, sizeof(payload),
                                  AVTP_CAN_CLASSIC);
        assert_int_equal(Avtp_Can_IsValid((Avtp_Can_t *)pdu, MAX_PDU_SIZE), 1);
    }

    // Not an IEEE 1722 ACF-CAN message (zero buffer, AcfMsgType != CAN).
    memset(pdu, 0, MAX_PDU_SIZE);
    assert_int_equal(Avtp_Can_IsValid((Avtp_Can_t *)pdu, MAX_PDU_SIZE), 0);

    // Valid IEEE 1722 CAN Frame (Length 24, Buffer 25). AcfMsgLength=6
    // quadlets = 24 bytes; payload = 24 - 16 header = 8 bytes (classic max).
    Avtp_Can_Init((Avtp_Can_t *)pdu);
    Avtp_Can_SetAcfMsgLength((Avtp_Can_t *)pdu, 6);
    assert_int_equal(Avtp_Can_IsValid((Avtp_Can_t *)pdu, 25), 1);

    // Invalid IEEE 1722 CAN Frame (Length 24 but buffer only 9!).
    Avtp_Can_Init((Avtp_Can_t *)pdu);
    Avtp_Can_SetAcfMsgLength((Avtp_Can_t *)pdu, 6);
    assert_int_equal(Avtp_Can_IsValid((Avtp_Can_t *)pdu, 9), 0);

    // Classic CAN payload bound: a frame declaring a 12-byte payload as
    // classic CAN is invalid (classic tops out at 8). Constructed by
    // handing CreateAcfMessage an oversized payload while marking the
    // frame as classic — the wire encoding succeeds but IsValid rejects.
    {
        uint8_t too_big[12] = {0};
        Avtp_Can_Init((Avtp_Can_t *)pdu);
        Avtp_Can_CreateAcfMessage((Avtp_Can_t *)pdu, frame_id, too_big, sizeof(too_big),
                                  AVTP_CAN_CLASSIC);
        assert_int_equal(Avtp_Can_IsValid((Avtp_Can_t *)pdu, MAX_PDU_SIZE), 0);
    }

    // CAN-FD payload bound: 64 bytes is at the FD limit (valid); 68 bytes
    // exceeds it (invalid).
    {
        uint8_t fd_max[64] = {0};
        Avtp_Can_Init((Avtp_Can_t *)pdu);
        Avtp_Can_CreateAcfMessage((Avtp_Can_t *)pdu, frame_id, fd_max, sizeof(fd_max), AVTP_CAN_FD);
        assert_int_equal(Avtp_Can_IsValid((Avtp_Can_t *)pdu, MAX_PDU_SIZE), 1);
    }
    {
        uint8_t fd_too_big[68] = {0};
        Avtp_Can_Init((Avtp_Can_t *)pdu);
        Avtp_Can_CreateAcfMessage((Avtp_Can_t *)pdu, frame_id, fd_too_big, sizeof(fd_too_big),
                                  AVTP_CAN_FD);
        assert_int_equal(Avtp_Can_IsValid((Avtp_Can_t *)pdu, MAX_PDU_SIZE), 0);
    }
}

static void can_brief_set_payload(void **state)
{

    uint8_t pdu[MAX_PDU_SIZE];
    uint32_t set_frame_id = 0x7ff;
    uint8_t set_payload[CAN_PAYLOAD_SIZE] = {0, 1, 2, 3, 4, 5, 6, 7};

    // Initialize PDU
    Avtp_CanBrief_Init((Avtp_CanBrief_t *)pdu);

    // Set payload and check for EFF
    Avtp_CanBrief_CreateAcfMessage((Avtp_CanBrief_t *)pdu, set_frame_id, set_payload,
                                   CAN_PAYLOAD_SIZE, AVTP_CAN_CLASSIC);
    assert_int_equal(Avtp_CanBrief_GetCanIdentifier((Avtp_CanBrief_t *)pdu), set_frame_id);
    assert_int_equal(Avtp_CanBrief_IsEff((Avtp_CanBrief_t *)pdu), 0);
    assert_memory_equal(set_payload, pdu + AVTP_CAN_BRIEF_HEADER_LEN, CAN_PAYLOAD_SIZE);
    assert_int_equal(Avtp_CanBrief_GetPayloadLength((Avtp_CanBrief_t *)pdu), CAN_PAYLOAD_SIZE);

    // Check EFF for extended Frame IDs
    set_frame_id = 0x800;
    Avtp_CanBrief_CreateAcfMessage((Avtp_CanBrief_t *)pdu, set_frame_id, set_payload,
                                   CAN_PAYLOAD_SIZE, AVTP_CAN_CLASSIC);
    assert_int_equal(Avtp_CanBrief_GetCanIdentifier((Avtp_CanBrief_t *)pdu), set_frame_id);
    assert_int_equal(Avtp_CanBrief_IsEff((Avtp_CanBrief_t *)pdu), 1);

    // Check padding bytes and length field
    uint8_t zero_array[CAN_PAYLOAD_SIZE] = {0, 0, 0, 0, 0, 0, 0, 0};
    for (int i = 0; i < CAN_PAYLOAD_SIZE; i++) {
        memset(pdu, 0, MAX_PDU_SIZE);
        Avtp_CanBrief_Init((Avtp_CanBrief_t *)pdu);
        Avtp_CanBrief_CreateAcfMessage((Avtp_CanBrief_t *)pdu, set_frame_id, set_payload, i,
                                       AVTP_CAN_CLASSIC);
        assert_memory_equal(set_payload, pdu + AVTP_CAN_BRIEF_HEADER_LEN, i);
        assert_memory_equal(zero_array, pdu + AVTP_CAN_BRIEF_HEADER_LEN + i, CAN_PAYLOAD_SIZE - i);

        uint16_t msgLenBytes = AVTP_CAN_BRIEF_HEADER_LEN + i;
        uint8_t pad = (uint8_t)(4 - (msgLenBytes % 4)) % 4;
        assert_int_equal(Avtp_CanBrief_GetPad((Avtp_CanBrief_t *)pdu), pad);
        assert_int_equal(Avtp_CanBrief_GetAcfMsgLength((Avtp_CanBrief_t *)pdu),
                         (msgLenBytes + pad) / 4);
    }
}

static void can_brief_is_valid(void **state)
{

    uint8_t pdu[MAX_PDU_SIZE];
    uint32_t frame_id = 0x123;

    // An Init-only PDU has AcfMsgLength == 0 — i.e. it declares a frame
    // shorter than its own header. Per IEEE 1722 ACF wire format that is
    // not a valid frame, so IsValid must reject it.
    Avtp_CanBrief_Init((Avtp_CanBrief_t *)pdu);
    assert_int_equal(Avtp_CanBrief_IsValid((Avtp_CanBrief_t *)pdu, MAX_PDU_SIZE), 0);

    // A properly-formed classic CAN frame with an 8-byte payload (the
    // classic-CAN max) is valid.
    {
        uint8_t payload[8] = {0, 1, 2, 3, 4, 5, 6, 7};
        Avtp_CanBrief_Init((Avtp_CanBrief_t *)pdu);
        Avtp_CanBrief_CreateAcfMessage((Avtp_CanBrief_t *)pdu, frame_id, payload, sizeof(payload),
                                       AVTP_CAN_CLASSIC);
        assert_int_equal(Avtp_CanBrief_IsValid((Avtp_CanBrief_t *)pdu, MAX_PDU_SIZE), 1);
    }

    // Not an IEEE 1722 ACF-CAN Brief message (zero buffer, AcfMsgType != CAN_BRIEF).
    memset(pdu, 0, MAX_PDU_SIZE);
    assert_int_equal(Avtp_CanBrief_IsValid((Avtp_CanBrief_t *)pdu, MAX_PDU_SIZE), 0);

    // Valid IEEE 1722 CAN Brief Frame (Length 16, Buffer 17). AcfMsgLength=4
    // quadlets = 16 bytes; payload = 16 - 8 header = 8 bytes (classic max).
    Avtp_CanBrief_Init((Avtp_CanBrief_t *)pdu);
    Avtp_CanBrief_SetAcfMsgLength((Avtp_CanBrief_t *)pdu, 4);
    assert_int_equal(Avtp_CanBrief_IsValid((Avtp_CanBrief_t *)pdu, 17), 1);

    // Invalid IEEE 1722 CAN Brief Frame (Length 16 but buffer only 9!).
    Avtp_CanBrief_Init((Avtp_CanBrief_t *)pdu);
    Avtp_CanBrief_SetAcfMsgLength((Avtp_CanBrief_t *)pdu, 4);
    assert_int_equal(Avtp_CanBrief_IsValid((Avtp_CanBrief_t *)pdu, 9), 0);

    // Classic CAN payload bound: a frame declaring a 12-byte payload as
    // classic CAN is invalid (classic tops out at 8).
    {
        uint8_t too_big[12] = {0};
        Avtp_CanBrief_Init((Avtp_CanBrief_t *)pdu);
        Avtp_CanBrief_CreateAcfMessage((Avtp_CanBrief_t *)pdu, frame_id, too_big, sizeof(too_big),
                                       AVTP_CAN_CLASSIC);
        assert_int_equal(Avtp_CanBrief_IsValid((Avtp_CanBrief_t *)pdu, MAX_PDU_SIZE), 0);
    }

    // CAN-FD payload bound: 64 bytes is at the FD limit (valid); 68 bytes
    // exceeds it (invalid).
    {
        uint8_t fd_max[64] = {0};
        Avtp_CanBrief_Init((Avtp_CanBrief_t *)pdu);
        Avtp_CanBrief_CreateAcfMessage((Avtp_CanBrief_t *)pdu, frame_id, fd_max, sizeof(fd_max),
                                       AVTP_CAN_FD);
        assert_int_equal(Avtp_CanBrief_IsValid((Avtp_CanBrief_t *)pdu, MAX_PDU_SIZE), 1);
    }
    {
        uint8_t fd_too_big[68] = {0};
        Avtp_CanBrief_Init((Avtp_CanBrief_t *)pdu);
        Avtp_CanBrief_CreateAcfMessage((Avtp_CanBrief_t *)pdu, frame_id, fd_too_big,
                                       sizeof(fd_too_big), AVTP_CAN_FD);
        assert_int_equal(Avtp_CanBrief_IsValid((Avtp_CanBrief_t *)pdu, MAX_PDU_SIZE), 0);
    }
}

static void can_create_from_garbage(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    uint32_t frame_id = 0x123;
    uint8_t payload[8] = {0,1,2,3,4,5,6,7};

    // CreateAcfMessage must fully initialize the header even on garbage input.
    memset(pdu, 0xAA, MAX_PDU_SIZE);
    Avtp_Can_CreateAcfMessage((Avtp_Can_t*)pdu, frame_id, payload, sizeof(payload),
                              AVTP_CAN_CLASSIC);

    assert_int_equal(Avtp_Can_GetAcfMsgType((Avtp_Can_t*)pdu), AVTP_ACF_TYPE_CAN);
    assert_int_equal(Avtp_Can_IsMtv((Avtp_Can_t*)pdu), 0);
    assert_int_equal(Avtp_Can_IsRtr((Avtp_Can_t*)pdu), 0);
    assert_int_equal(Avtp_Can_IsBrs((Avtp_Can_t*)pdu), 0);
    assert_int_equal(Avtp_Can_IsFdf((Avtp_Can_t*)pdu), 0);
    assert_int_equal(Avtp_Can_IsEsi((Avtp_Can_t*)pdu), 0);
    assert_int_equal(Avtp_Can_GetCanBusId((Avtp_Can_t*)pdu), 0);
    assert_memory_equal(payload, pdu + AVTP_CAN_HEADER_LEN, sizeof(payload));
    assert_int_equal(Avtp_Can_IsValid((Avtp_Can_t*)pdu, MAX_PDU_SIZE), 1);
}

static void can_brief_create_from_garbage(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    uint32_t frame_id = 0x123;
    uint8_t payload[8] = {0,1,2,3,4,5,6,7};

    // CreateAcfMessage must fully initialize the header even on garbage input.
    memset(pdu, 0xAA, MAX_PDU_SIZE);
    Avtp_CanBrief_CreateAcfMessage((Avtp_CanBrief_t*)pdu, frame_id, payload, sizeof(payload),
                                   AVTP_CAN_CLASSIC);

    assert_int_equal(Avtp_CanBrief_GetAcfMsgType((Avtp_CanBrief_t*)pdu), AVTP_ACF_TYPE_CAN_BRIEF);
    assert_int_equal(Avtp_CanBrief_IsMtv((Avtp_CanBrief_t*)pdu), 0);
    assert_int_equal(Avtp_CanBrief_IsRtr((Avtp_CanBrief_t*)pdu), 0);
    assert_int_equal(Avtp_CanBrief_IsBrs((Avtp_CanBrief_t*)pdu), 0);
    assert_int_equal(Avtp_CanBrief_IsFdf((Avtp_CanBrief_t*)pdu), 0);
    assert_int_equal(Avtp_CanBrief_IsEsi((Avtp_CanBrief_t*)pdu), 0);
    assert_int_equal(Avtp_CanBrief_GetCanBusId((Avtp_CanBrief_t*)pdu), 0);
    assert_memory_equal(payload, pdu + AVTP_CAN_BRIEF_HEADER_LEN, sizeof(payload));
    assert_int_equal(Avtp_CanBrief_IsValid((Avtp_CanBrief_t*)pdu, MAX_PDU_SIZE), 1);
}

int main(void)
{
    const struct CMUnitTest tests[] = {cmocka_unit_test(can_init),
                                       cmocka_unit_test(can_brief_init),
                                       cmocka_unit_test(can_set_payload),
                                       cmocka_unit_test(can_is_valid),
                                       cmocka_unit_test(can_brief_set_payload),
                                       cmocka_unit_test(can_brief_is_valid),
                                       cmocka_unit_test(can_create_from_garbage),
                                       cmocka_unit_test(can_brief_create_from_garbage)};

    return cmocka_run_group_tests(tests, NULL, NULL);
}