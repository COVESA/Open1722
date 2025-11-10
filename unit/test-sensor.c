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

#include "avtp/acf/Sensor.h"

#define MAX_PDU_SIZE 1500

static void sensor_init(void **state) {
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t init_pdu[AVTP_SENSOR_HEADER_LEN];

    Avtp_Sensor_Init(NULL);

    Avtp_Sensor_Init((Avtp_Sensor_t*)pdu);
    memset(init_pdu, 0, AVTP_SENSOR_HEADER_LEN);
    init_pdu[0] = AVTP_ACF_TYPE_SENSOR << 1;
    assert_memory_equal(init_pdu, pdu, AVTP_SENSOR_HEADER_LEN);
}

static void sensor_get_set_fields(void **state) {
    uint8_t pdu[MAX_PDU_SIZE];
    
    Avtp_Sensor_Init((Avtp_Sensor_t*)pdu);

    Avtp_Sensor_SetAcfMsgType((Avtp_Sensor_t*)pdu, AVTP_ACF_TYPE_SENSOR);
    assert_int_equal(Avtp_Sensor_GetAcfMsgType((Avtp_Sensor_t*)pdu), AVTP_ACF_TYPE_SENSOR);

    Avtp_Sensor_SetAcfMsgLength((Avtp_Sensor_t*)pdu, 80);
    assert_int_equal(Avtp_Sensor_GetAcfMsgLength((Avtp_Sensor_t*)pdu), 80);

    Avtp_Sensor_EnableMtv((Avtp_Sensor_t*)pdu);
    assert_int_equal(Avtp_Sensor_GetMtv((Avtp_Sensor_t*)pdu), 1);

    Avtp_Sensor_DisableMtv((Avtp_Sensor_t*)pdu);
    assert_int_equal(Avtp_Sensor_GetMtv((Avtp_Sensor_t*)pdu), 0);

    Avtp_Sensor_SetNumSensor((Avtp_Sensor_t*)pdu, 10);
    assert_int_equal(Avtp_Sensor_GetNumSensor((Avtp_Sensor_t*)pdu), 10);

    Avtp_Sensor_SetSz((Avtp_Sensor_t*)pdu, 3);
    assert_int_equal(Avtp_Sensor_GetSz((Avtp_Sensor_t*)pdu), 3);

    Avtp_Sensor_SetSensorGroup((Avtp_Sensor_t*)pdu, 5);
    assert_int_equal(Avtp_Sensor_GetSensorGroup((Avtp_Sensor_t*)pdu), 5);

    Avtp_Sensor_SetMessageTimestamp((Avtp_Sensor_t*)pdu, 0x123456789ABCULL);
    assert_int_equal(Avtp_Sensor_GetMessageTimestamp((Avtp_Sensor_t*)pdu), 0x123456789ABCULL);
}

static void sensor_is_valid(void **state) {
    uint8_t pdu[MAX_PDU_SIZE];

    Avtp_Sensor_Init((Avtp_Sensor_t*)pdu);
    assert_int_equal(Avtp_Sensor_IsValid((Avtp_Sensor_t*)pdu, MAX_PDU_SIZE), 1);

    memset(pdu, 0, MAX_PDU_SIZE);
    assert_int_equal(Avtp_Sensor_IsValid((Avtp_Sensor_t*)pdu, MAX_PDU_SIZE), 0);

    Avtp_Sensor_Init((Avtp_Sensor_t*)pdu);
    Avtp_Sensor_SetAcfMsgLength((Avtp_Sensor_t*)pdu, 5);
    assert_int_equal(Avtp_Sensor_IsValid((Avtp_Sensor_t*)pdu, 25), 1);

    Avtp_Sensor_Init((Avtp_Sensor_t*)pdu);
    Avtp_Sensor_SetAcfMsgLength((Avtp_Sensor_t*)pdu, 5);
    assert_int_equal(Avtp_Sensor_IsValid((Avtp_Sensor_t*)pdu, 8), 0);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(sensor_init),
        cmocka_unit_test(sensor_get_set_fields),
        cmocka_unit_test(sensor_is_valid),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

