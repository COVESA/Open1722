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

#include "avtp/acf/Gpc.h"

#define MAX_PDU_SIZE 1500

static void gpc_init(void **state)
{
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t init_pdu[AVTP_GPC_HEADER_LEN];

    Avtp_Gpc_Init(NULL);

    Avtp_Gpc_Init((Avtp_Gpc_t *)pdu);
    memset(init_pdu, 0, AVTP_GPC_HEADER_LEN);
    init_pdu[0] = AVTP_ACF_TYPE_GPC << 1;
    assert_memory_equal(init_pdu, pdu, AVTP_GPC_HEADER_LEN);
}

static void gpc_get_set_fields(void **state)
{
    uint8_t pdu[MAX_PDU_SIZE];

    Avtp_Gpc_Init((Avtp_Gpc_t *)pdu);

    assert_int_equal(Avtp_AcfCommon_GetAcfMsgType((Avtp_AcfCommon_t *)pdu), AVTP_ACF_TYPE_GPC);

    Avtp_Gpc_SetAcfMsgLength((Avtp_Gpc_t *)pdu, 200);
    assert_int_equal(Avtp_Gpc_GetAcfMsgLength((Avtp_Gpc_t *)pdu), 200);

    Avtp_Gpc_SetGpcMsgId((Avtp_Gpc_t *)pdu, 0x456789ABCDEFULL);
    assert_int_equal(Avtp_Gpc_GetGpcMsgId((Avtp_Gpc_t *)pdu), 0x456789ABCDEFULL);
}

static void gpc_is_valid(void **state)
{
    uint8_t pdu[MAX_PDU_SIZE];

    // An Init-only PDU has AcfMsgLength == 0, so IsValid must reject it.
    Avtp_Gpc_Init((Avtp_Gpc_t *)pdu);
    assert_int_equal(Avtp_Gpc_IsValid((Avtp_Gpc_t *)pdu, MAX_PDU_SIZE), 0);

    memset(pdu, 0, MAX_PDU_SIZE);
    assert_int_equal(Avtp_Gpc_IsValid((Avtp_Gpc_t *)pdu, MAX_PDU_SIZE), 0);

    Avtp_Gpc_Init((Avtp_Gpc_t *)pdu);
    Avtp_Gpc_SetAcfMsgLength((Avtp_Gpc_t *)pdu, 4);
    assert_int_equal(Avtp_Gpc_IsValid((Avtp_Gpc_t *)pdu, 20), 1);

    Avtp_Gpc_Init((Avtp_Gpc_t *)pdu);
    Avtp_Gpc_SetAcfMsgLength((Avtp_Gpc_t *)pdu, 4);
    assert_int_equal(Avtp_Gpc_IsValid((Avtp_Gpc_t *)pdu, 5), 0);
}

static void gpc_create_message(void **state)
{
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t payload[6] = {0, 1, 2, 3, 4, 5};

    Avtp_Gpc_CreateAcfMessage((Avtp_Gpc_t *)pdu, 0x456789ABCDEFULL, payload, sizeof(payload));

    assert_int_equal(Avtp_AcfCommon_GetAcfMsgType((Avtp_AcfCommon_t *)pdu), AVTP_ACF_TYPE_GPC);
    assert_int_equal(Avtp_Gpc_GetGpcMsgId((Avtp_Gpc_t *)pdu), 0x456789ABCDEFULL);
    assert_memory_equal(payload, pdu + AVTP_GPC_HEADER_LEN, sizeof(payload));
    assert_int_equal(Avtp_Gpc_GetAcfMsgLengthInBytes((Avtp_Gpc_t *)pdu), 16);
    assert_int_equal(Avtp_Gpc_IsValid((Avtp_Gpc_t *)pdu, MAX_PDU_SIZE), 1);
}

static void gpc_create_from_garbage(void **state)
{
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t payload[6] = {0, 1, 2, 3, 4, 5};

    // CreateAcfMessage must fully initialize the header even on garbage input.
    memset(pdu, 0xAA, MAX_PDU_SIZE);
    Avtp_Gpc_CreateAcfMessage((Avtp_Gpc_t *)pdu, 0x456789ABCDEFULL, payload, sizeof(payload));

    assert_int_equal(Avtp_AcfCommon_GetAcfMsgType((Avtp_AcfCommon_t *)pdu), AVTP_ACF_TYPE_GPC);
    assert_int_equal(Avtp_Gpc_GetGpcMsgId((Avtp_Gpc_t *)pdu), 0x456789ABCDEFULL);
    assert_memory_equal(payload, pdu + AVTP_GPC_HEADER_LEN, sizeof(payload));
    assert_int_equal(Avtp_Gpc_IsValid((Avtp_Gpc_t *)pdu, MAX_PDU_SIZE), 1);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(gpc_init),
        cmocka_unit_test(gpc_get_set_fields),
        cmocka_unit_test(gpc_is_valid),
        cmocka_unit_test(gpc_create_message),
        cmocka_unit_test(gpc_create_from_garbage),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
