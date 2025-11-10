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
#include <string.h>

#include "avtp/acf/FlexRay.h"

#define MAX_PDU_SIZE 1500

static void flexray_init(void **state) {
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t init_pdu[AVTP_FLEXRAY_HEADER_LEN];

    Avtp_FlexRay_Init(NULL);

    Avtp_FlexRay_Init((Avtp_FlexRay_t*)pdu);
    memset(init_pdu, 0, AVTP_FLEXRAY_HEADER_LEN);
    init_pdu[0] = AVTP_ACF_TYPE_FLEXRAY << 1;
    assert_memory_equal(init_pdu, pdu, AVTP_FLEXRAY_HEADER_LEN);
}

static void flexray_get_set_fields(void **state) {
    uint8_t pdu[MAX_PDU_SIZE];
    
    Avtp_FlexRay_Init((Avtp_FlexRay_t*)pdu);

    Avtp_FlexRay_SetAcfMsgType((Avtp_FlexRay_t*)pdu, AVTP_ACF_TYPE_FLEXRAY);
    assert_int_equal(Avtp_FlexRay_GetAcfMsgType((Avtp_FlexRay_t*)pdu), AVTP_ACF_TYPE_FLEXRAY);

    Avtp_FlexRay_SetAcfMsgLength((Avtp_FlexRay_t*)pdu, 100);
    assert_int_equal(Avtp_FlexRay_GetAcfMsgLength((Avtp_FlexRay_t*)pdu), 100);

    Avtp_FlexRay_SetPad((Avtp_FlexRay_t*)pdu, 2);
    assert_int_equal(Avtp_FlexRay_GetPad((Avtp_FlexRay_t*)pdu), 2);

    Avtp_FlexRay_EnableMtv((Avtp_FlexRay_t*)pdu);
    assert_int_equal(Avtp_FlexRay_GetMtv((Avtp_FlexRay_t*)pdu), 1);

    Avtp_FlexRay_DisableMtv((Avtp_FlexRay_t*)pdu);
    assert_int_equal(Avtp_FlexRay_GetMtv((Avtp_FlexRay_t*)pdu), 0);

    Avtp_FlexRay_SetFrBusId((Avtp_FlexRay_t*)pdu, 5);
    assert_int_equal(Avtp_FlexRay_GetFrBusId((Avtp_FlexRay_t*)pdu), 5);

    Avtp_FlexRay_SetChan((Avtp_FlexRay_t*)pdu, 1);
    assert_int_equal(Avtp_FlexRay_GetChan((Avtp_FlexRay_t*)pdu), 1);

    Avtp_FlexRay_EnableStr((Avtp_FlexRay_t*)pdu);
    assert_int_equal(Avtp_FlexRay_GetStr((Avtp_FlexRay_t*)pdu), 1);

    Avtp_FlexRay_DisableStr((Avtp_FlexRay_t*)pdu);
    assert_int_equal(Avtp_FlexRay_GetStr((Avtp_FlexRay_t*)pdu), 0);

    Avtp_FlexRay_EnableSyn((Avtp_FlexRay_t*)pdu);
    assert_int_equal(Avtp_FlexRay_GetSyn((Avtp_FlexRay_t*)pdu), 1);

    Avtp_FlexRay_DisableSyn((Avtp_FlexRay_t*)pdu);
    assert_int_equal(Avtp_FlexRay_GetSyn((Avtp_FlexRay_t*)pdu), 0);

    Avtp_FlexRay_EnablePre((Avtp_FlexRay_t*)pdu);
    assert_int_equal(Avtp_FlexRay_GetPre((Avtp_FlexRay_t*)pdu), 1);

    Avtp_FlexRay_DisablePre((Avtp_FlexRay_t*)pdu);
    assert_int_equal(Avtp_FlexRay_GetPre((Avtp_FlexRay_t*)pdu), 0);

    Avtp_FlexRay_EnableNfi((Avtp_FlexRay_t*)pdu);
    assert_int_equal(Avtp_FlexRay_GetNfi((Avtp_FlexRay_t*)pdu), 1);

    Avtp_FlexRay_DisableNfi((Avtp_FlexRay_t*)pdu);
    assert_int_equal(Avtp_FlexRay_GetNfi((Avtp_FlexRay_t*)pdu), 0);

    Avtp_FlexRay_SetMessageTimestamp((Avtp_FlexRay_t*)pdu, 0x123456789ABCULL);
    assert_int_equal(Avtp_FlexRay_GetMessageTimestamp((Avtp_FlexRay_t*)pdu), 0x123456789ABCULL);

    Avtp_FlexRay_SetFrFrameId((Avtp_FlexRay_t*)pdu, 0x7FF);
    assert_int_equal(Avtp_FlexRay_GetFrFrameId((Avtp_FlexRay_t*)pdu), 0x7FF);

    Avtp_FlexRay_SetCycle((Avtp_FlexRay_t*)pdu, 63);
    assert_int_equal(Avtp_FlexRay_GetCycle((Avtp_FlexRay_t*)pdu), 63);
}

static void flexray_is_valid(void **state) {
    uint8_t pdu[MAX_PDU_SIZE];

    Avtp_FlexRay_Init((Avtp_FlexRay_t*)pdu);
    Avtp_FlexRay_SetAcfMsgLength((Avtp_FlexRay_t*)pdu, 4);
    assert_int_equal(Avtp_FlexRay_IsValid((Avtp_FlexRay_t*)pdu, MAX_PDU_SIZE), 1);

    memset(pdu, 0xFF, MAX_PDU_SIZE);
    assert_int_equal(Avtp_FlexRay_IsValid((Avtp_FlexRay_t*)pdu, MAX_PDU_SIZE), 0);

    Avtp_FlexRay_Init((Avtp_FlexRay_t*)pdu);
    Avtp_FlexRay_SetAcfMsgLength((Avtp_FlexRay_t*)pdu, 6);
    assert_int_equal(Avtp_FlexRay_IsValid((Avtp_FlexRay_t*)pdu, 25), 1);

    Avtp_FlexRay_Init((Avtp_FlexRay_t*)pdu);
    Avtp_FlexRay_SetAcfMsgLength((Avtp_FlexRay_t*)pdu, 6);
    assert_int_equal(Avtp_FlexRay_IsValid((Avtp_FlexRay_t*)pdu, 9), 0);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(flexray_init),
        cmocka_unit_test(flexray_get_set_fields),
        cmocka_unit_test(flexray_is_valid),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
