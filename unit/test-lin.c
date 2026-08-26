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
#include <string.h>

#include "avtp/acf/Lin.h"

#define MAX_PDU_SIZE 1500

static void lin_init(void **state) {
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t init_pdu[AVTP_LIN_HEADER_LEN];

    Avtp_Lin_Init(NULL);

    Avtp_Lin_Init((Avtp_Lin_t*)pdu);
    memset(init_pdu, 0, AVTP_LIN_HEADER_LEN);
    init_pdu[0] = AVTP_ACF_TYPE_LIN << 1;
    assert_memory_equal(init_pdu, pdu, AVTP_LIN_HEADER_LEN);
}

static void lin_get_set_fields(void **state) {
    uint8_t pdu[MAX_PDU_SIZE];
    
    Avtp_Lin_Init((Avtp_Lin_t*)pdu);

    Avtp_Lin_SetAcfMsgType((Avtp_Lin_t*)pdu, AVTP_ACF_TYPE_LIN);
    assert_int_equal(Avtp_Lin_GetAcfMsgType((Avtp_Lin_t*)pdu), AVTP_ACF_TYPE_LIN);

    Avtp_Lin_SetAcfMsgLength((Avtp_Lin_t*)pdu, 50);
    assert_int_equal(Avtp_Lin_GetAcfMsgLength((Avtp_Lin_t*)pdu), 50);

    Avtp_Lin_SetPad((Avtp_Lin_t*)pdu, 3);
    assert_int_equal(Avtp_Lin_GetPad((Avtp_Lin_t*)pdu), 3);

    Avtp_Lin_SetMtv((Avtp_Lin_t*)pdu, true);
    assert_int_equal(Avtp_Lin_IsMtv((Avtp_Lin_t*)pdu), 1);

    Avtp_Lin_SetMtv((Avtp_Lin_t*)pdu, false);
    assert_int_equal(Avtp_Lin_IsMtv((Avtp_Lin_t*)pdu), 0);

    Avtp_Lin_SetLinBusId((Avtp_Lin_t*)pdu, 7);
    assert_int_equal(Avtp_Lin_GetLinBusId((Avtp_Lin_t*)pdu), 7);

    Avtp_Lin_SetLinIdentifier((Avtp_Lin_t*)pdu, 0x3F);
    assert_int_equal(Avtp_Lin_GetLinIdentifier((Avtp_Lin_t*)pdu), 0x3F);

    Avtp_Lin_SetMessageTimestamp((Avtp_Lin_t*)pdu, 0x123456789ABCULL);
    assert_int_equal(Avtp_Lin_GetMessageTimestamp((Avtp_Lin_t*)pdu), 0x123456789ABCULL);
}

static void lin_is_valid(void **state) {
    uint8_t pdu[MAX_PDU_SIZE];

    // An Init-only PDU has AcfMsgLength == 0 - i.e. it declares a frame
    // shorter than its own header, so IsValid must reject it.
    Avtp_Lin_Init((Avtp_Lin_t*)pdu);
    assert_int_equal(Avtp_Lin_IsValid((Avtp_Lin_t*)pdu, MAX_PDU_SIZE), 0);

    // Not an IEEE 1722 ACF-LIN message (zero buffer, AcfMsgType != LIN).
    memset(pdu, 0, MAX_PDU_SIZE);
    assert_int_equal(Avtp_Lin_IsValid((Avtp_Lin_t*)pdu, MAX_PDU_SIZE), 0);

    // Valid IEEE 1722 LIN Frame (Length 20, Buffer 25). AcfMsgLength=5
    // quadlets = 20 bytes; payload = 20 - 12 header = 8 bytes (LIN max).
    Avtp_Lin_Init((Avtp_Lin_t*)pdu);
    Avtp_Lin_SetAcfMsgLength((Avtp_Lin_t*)pdu, 5);
    assert_int_equal(Avtp_Lin_IsValid((Avtp_Lin_t*)pdu, 25), 1);

    // Invalid IEEE 1722 LIN Frame (Length 20 but buffer only 9!).
    Avtp_Lin_Init((Avtp_Lin_t*)pdu);
    Avtp_Lin_SetAcfMsgLength((Avtp_Lin_t*)pdu, 5);
    assert_int_equal(Avtp_Lin_IsValid((Avtp_Lin_t*)pdu, 9), 0);

    // LIN payload bound: a frame declaring a 12-byte payload is invalid
    // (LIN tops out at 8 bytes). AcfMsgLength=6 quadlets = 24 bytes;
    // payload = 24 - 12 header = 12 bytes.
    Avtp_Lin_Init((Avtp_Lin_t*)pdu);
    Avtp_Lin_SetAcfMsgLength((Avtp_Lin_t*)pdu, 6);
    assert_int_equal(Avtp_Lin_IsValid((Avtp_Lin_t*)pdu, MAX_PDU_SIZE), 0);
}

static void lin_create_message(void **state) {
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t payload[8] = {0,1,2,3,4,5,6,7};

    Avtp_Lin_Init((Avtp_Lin_t*)pdu);
    Avtp_Lin_CreateAcfMessage((Avtp_Lin_t*)pdu, 7, 0x3F, 0x123456789ABCULL,
                              payload, sizeof(payload));

    assert_int_equal(Avtp_Lin_GetLinBusId((Avtp_Lin_t*)pdu), 7);
    assert_int_equal(Avtp_Lin_GetLinIdentifier((Avtp_Lin_t*)pdu), 0x3F);
    assert_int_equal(Avtp_Lin_GetMessageTimestamp((Avtp_Lin_t*)pdu), 0x123456789ABCULL);
    assert_memory_equal(payload, pdu+AVTP_LIN_HEADER_LEN, sizeof(payload));
    assert_int_equal(Avtp_Lin_GetPayloadLength((Avtp_Lin_t*)pdu), 8);
    assert_int_equal(Avtp_Lin_GetAcfMsgLength((Avtp_Lin_t*)pdu), 5);
    assert_int_equal(Avtp_Lin_IsValid((Avtp_Lin_t*)pdu, MAX_PDU_SIZE), 1);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(lin_init),
        cmocka_unit_test(lin_get_set_fields),
        cmocka_unit_test(lin_is_valid),
        cmocka_unit_test(lin_create_message),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
