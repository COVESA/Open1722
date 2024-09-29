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
#include <cmocka.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <math.h>
#include <stdio.h>

#include "avtp/acf/Can.h"
#include "avtp/acf/CanBrief.h"

#define MAX_PDU_SIZE        1500
#define CAN_PAYLOAD_SIZE    8

static void can_init(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t init_pdu[AVTP_CAN_HEADER_LEN];

    // Check init function while passing in a null pointer
    Avtp_Can_Init(NULL);

    // Check if the function is initializing properly
    Avtp_Can_Init((Avtp_Can_t*)pdu);
    memset(init_pdu, 0, AVTP_CAN_HEADER_LEN);
    init_pdu[0] = AVTP_ACF_TYPE_CAN << 1; // Setting ACF type as ACF_CAN
    assert_memory_equal(init_pdu, pdu, AVTP_CAN_HEADER_LEN);
}

static void can_brief_init(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t init_pdu[AVTP_CAN_BRIEF_HEADER_LEN];

    // Check init function while passing in a null pointer
    Avtp_CanBrief_Init(NULL);

    // Check if the function is initializing properly
    Avtp_CanBrief_Init((Avtp_CanBrief_t*)pdu);
    memset(init_pdu, 0, AVTP_CAN_BRIEF_HEADER_LEN);
    init_pdu[0] = 0x04; // Setting ACF type as ACF_CAN
    assert_memory_equal(init_pdu, pdu, AVTP_CAN_BRIEF_HEADER_LEN);
}

static void can_set_payload(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    uint32_t set_frame_id = 0x7ff;
    uint8_t set_payload[CAN_PAYLOAD_SIZE] = {0,1,2,3,4,5,6,7};

    // Initialize PDU
    Avtp_Can_Init((Avtp_Can_t*)pdu);

    // Set payload and check for EFF
    Avtp_Can_CreateAcfMessage((Avtp_Can_t*)pdu, set_frame_id, set_payload,
                        CAN_PAYLOAD_SIZE, AVTP_CAN_CLASSIC);
    assert_int_equal(htonl(set_frame_id), (uint32_t) *((int*)pdu+3));
    assert_memory_equal(set_payload, pdu+16, CAN_PAYLOAD_SIZE);
    assert_int_equal(0x0, *(pdu+2)&0x08);    // Check EFF

    // Check EFF for extended Frame IDs
    set_frame_id = 0x800;
    Avtp_Can_CreateAcfMessage((Avtp_Can_t*)pdu, set_frame_id, set_payload,
                        CAN_PAYLOAD_SIZE, AVTP_CAN_CLASSIC);
    assert_int_equal(htonl(set_frame_id), (uint32_t) *((int*)pdu+3));
    assert_int_equal(0x8, *(pdu+2)&0x08);    // Check EFF

    // Check padding bytes and length field
    uint8_t zero_array[CAN_PAYLOAD_SIZE] = {0, 0, 0, 0, 0, 0, 0, 0};
    for (int i=0; i<CAN_PAYLOAD_SIZE; i++) {
        memset(pdu, 0, MAX_PDU_SIZE);
        Avtp_Can_Init((Avtp_Can_t*)pdu);
        Avtp_Can_CreateAcfMessage((Avtp_Can_t*)pdu, set_frame_id, set_payload,
                        i, AVTP_CAN_CLASSIC);
        assert_memory_equal(set_payload, pdu+16, i);
        assert_memory_equal(zero_array, pdu+16+i, CAN_PAYLOAD_SIZE-i);

        // Padding tests
        uint8_t pad = *(pdu+2) & 0xc0;
        assert_int_equal(pad>>6, (4 - i%4)&0x3);

        // Length tests
        uint8_t length = *(pdu+1);
        assert_int_equal(length, (4+ceil(i/4.0)));
    }
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(can_init),
        cmocka_unit_test(can_brief_init),
        cmocka_unit_test(can_set_payload)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}