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

#include "avtp/acf/Most.h"

#define MAX_PDU_SIZE 1500

static void most_init(void **state) {
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t init_pdu[AVTP_MOST_HEADER_LEN];

    Avtp_Most_Init(NULL);

    Avtp_Most_Init((Avtp_Most_t*)pdu);
    memset(init_pdu, 0, AVTP_MOST_HEADER_LEN);
    init_pdu[0] = AVTP_ACF_TYPE_MOST << 1;
    assert_memory_equal(init_pdu, pdu, AVTP_MOST_HEADER_LEN);
}

static void most_get_set_fields(void **state) {
    uint8_t pdu[MAX_PDU_SIZE];
    
    Avtp_Most_Init((Avtp_Most_t*)pdu);

    Avtp_Most_SetAcfMsgType((Avtp_Most_t*)pdu, AVTP_ACF_TYPE_MOST);
    assert_int_equal(Avtp_Most_GetAcfMsgType((Avtp_Most_t*)pdu), AVTP_ACF_TYPE_MOST);

    Avtp_Most_SetAcfMsgLength((Avtp_Most_t*)pdu, 120);
    assert_int_equal(Avtp_Most_GetAcfMsgLength((Avtp_Most_t*)pdu), 120);

    Avtp_Most_SetPad((Avtp_Most_t*)pdu, 1);
    assert_int_equal(Avtp_Most_GetPad((Avtp_Most_t*)pdu), 1);

    Avtp_Most_EnableMtv((Avtp_Most_t*)pdu);
    assert_int_equal(Avtp_Most_GetMtv((Avtp_Most_t*)pdu), 1);

    Avtp_Most_DisableMtv((Avtp_Most_t*)pdu);
    assert_int_equal(Avtp_Most_GetMtv((Avtp_Most_t*)pdu), 0);

    Avtp_Most_SetMostNetId((Avtp_Most_t*)pdu, 15);
    assert_int_equal(Avtp_Most_GetMostNetId((Avtp_Most_t*)pdu), 15);

    Avtp_Most_SetMessageTimestamp((Avtp_Most_t*)pdu, 0x123456789ABCULL);
    assert_int_equal(Avtp_Most_GetMessageTimestamp((Avtp_Most_t*)pdu), 0x123456789ABCULL);

    Avtp_Most_SetDeviceId((Avtp_Most_t*)pdu, 0x1234);
    assert_int_equal(Avtp_Most_GetDeviceId((Avtp_Most_t*)pdu), 0x1234);

    Avtp_Most_SetFblockId((Avtp_Most_t*)pdu, 0xAB);
    assert_int_equal(Avtp_Most_GetFblockId((Avtp_Most_t*)pdu), 0xAB);

    Avtp_Most_SetInstId((Avtp_Most_t*)pdu, 0x12);
    assert_int_equal(Avtp_Most_GetInstId((Avtp_Most_t*)pdu), 0x12);

    Avtp_Most_SetFuncId((Avtp_Most_t*)pdu, 0x456);
    assert_int_equal(Avtp_Most_GetFuncId((Avtp_Most_t*)pdu), 0x456);

    Avtp_Most_SetOpType((Avtp_Most_t*)pdu, 0x0F);
    assert_int_equal(Avtp_Most_GetOpType((Avtp_Most_t*)pdu), 0x0F);
}

static void most_is_valid(void **state) {
    uint8_t pdu[MAX_PDU_SIZE];

    Avtp_Most_Init((Avtp_Most_t*)pdu);
    assert_int_equal(Avtp_Most_IsValid((Avtp_Most_t*)pdu, MAX_PDU_SIZE), 1);

    memset(pdu, 0, MAX_PDU_SIZE);
    assert_int_equal(Avtp_Most_IsValid((Avtp_Most_t*)pdu, MAX_PDU_SIZE), 0);

    Avtp_Most_Init((Avtp_Most_t*)pdu);
    Avtp_Most_SetAcfMsgLength((Avtp_Most_t*)pdu, 8);
    assert_int_equal(Avtp_Most_IsValid((Avtp_Most_t*)pdu, 35), 1);

    Avtp_Most_Init((Avtp_Most_t*)pdu);
    Avtp_Most_SetAcfMsgLength((Avtp_Most_t*)pdu, 8);
    assert_int_equal(Avtp_Most_IsValid((Avtp_Most_t*)pdu, 9), 0);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(most_init),
        cmocka_unit_test(most_get_set_fields),
        cmocka_unit_test(most_is_valid),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
