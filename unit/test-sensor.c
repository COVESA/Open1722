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

#include "avtp/acf/Sensor.h"
#include "avtp/acf/SensorBrief.h"

#define MAX_PDU_SIZE 1500

static void sensor_init(void **state)
{
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t init_pdu[AVTP_SENSOR_HEADER_LEN];

    Avtp_Sensor_Init(NULL);

    Avtp_Sensor_Init((Avtp_Sensor_t *)pdu);
    memset(init_pdu, 0, AVTP_SENSOR_HEADER_LEN);
    init_pdu[0] = AVTP_ACF_TYPE_SENSOR << 1;
    assert_memory_equal(init_pdu, pdu, AVTP_SENSOR_HEADER_LEN);
}

static void sensor_get_set_fields(void **state)
{
    uint8_t pdu[MAX_PDU_SIZE];

    Avtp_Sensor_Init((Avtp_Sensor_t *)pdu);

    Avtp_Sensor_SetAcfMsgType((Avtp_Sensor_t *)pdu, AVTP_ACF_TYPE_SENSOR);
    assert_int_equal(Avtp_Sensor_GetAcfMsgType((Avtp_Sensor_t *)pdu), AVTP_ACF_TYPE_SENSOR);

    Avtp_Sensor_SetAcfMsgLength((Avtp_Sensor_t *)pdu, 80);
    assert_int_equal(Avtp_Sensor_GetAcfMsgLength((Avtp_Sensor_t *)pdu), 80);

    Avtp_Sensor_SetMtv((Avtp_Sensor_t *)pdu, true);
    assert_int_equal(Avtp_Sensor_IsMtv((Avtp_Sensor_t *)pdu), 1);

    Avtp_Sensor_SetMtv((Avtp_Sensor_t *)pdu, false);
    assert_int_equal(Avtp_Sensor_IsMtv((Avtp_Sensor_t *)pdu), 0);

    Avtp_Sensor_SetNumSensor((Avtp_Sensor_t *)pdu, 10);
    assert_int_equal(Avtp_Sensor_GetNumSensor((Avtp_Sensor_t *)pdu), 10);

    Avtp_Sensor_SetSz((Avtp_Sensor_t *)pdu, 3);
    assert_int_equal(Avtp_Sensor_GetSz((Avtp_Sensor_t *)pdu), 3);

    Avtp_Sensor_SetSensorGroup((Avtp_Sensor_t *)pdu, 5);
    assert_int_equal(Avtp_Sensor_GetSensorGroup((Avtp_Sensor_t *)pdu), 5);

    Avtp_Sensor_SetMessageTimestamp((Avtp_Sensor_t *)pdu, 0x123456789ABCULL);
    assert_int_equal(Avtp_Sensor_GetMessageTimestamp((Avtp_Sensor_t *)pdu), 0x123456789ABCULL);
}

static void sensor_is_valid(void **state)
{
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t payload[6] = {0, 1, 2, 3, 4, 5};

    // An Init-only PDU has AcfMsgLength == 0, so IsValid must reject it.
    Avtp_Sensor_Init((Avtp_Sensor_t *)pdu);
    assert_int_equal(Avtp_Sensor_IsValid((Avtp_Sensor_t *)pdu, MAX_PDU_SIZE), 0);

    memset(pdu, 0, MAX_PDU_SIZE);
    assert_int_equal(Avtp_Sensor_IsValid((Avtp_Sensor_t *)pdu, MAX_PDU_SIZE), 0);

    Avtp_Sensor_CreateAcfMessage((Avtp_Sensor_t *)pdu, 3, 2, payload, sizeof(payload));
    assert_int_equal(Avtp_Sensor_IsValid((Avtp_Sensor_t *)pdu, MAX_PDU_SIZE), 1);
    assert_int_equal(Avtp_Sensor_IsValid((Avtp_Sensor_t *)pdu, 20), 1);

    // Buffer smaller than the message length.
    Avtp_Sensor_CreateAcfMessage((Avtp_Sensor_t *)pdu, 3, 2, payload, sizeof(payload));
    assert_int_equal(Avtp_Sensor_IsValid((Avtp_Sensor_t *)pdu, 8), 0);

    // AcfMsgLength inconsistent with num_sensors and sz.
    Avtp_Sensor_Init((Avtp_Sensor_t *)pdu);
    Avtp_Sensor_SetNumSensor((Avtp_Sensor_t *)pdu, 3);
    Avtp_Sensor_SetSz((Avtp_Sensor_t *)pdu, 2);
    Avtp_Sensor_SetAcfMsgLength((Avtp_Sensor_t *)pdu, 4);
    assert_int_equal(Avtp_Sensor_IsValid((Avtp_Sensor_t *)pdu, MAX_PDU_SIZE), 0);

    Avtp_Sensor_Init((Avtp_Sensor_t *)pdu);
    Avtp_Sensor_SetNumSensor((Avtp_Sensor_t *)pdu, 3);
    Avtp_Sensor_SetSz((Avtp_Sensor_t *)pdu, 2);
    Avtp_Sensor_SetAcfMsgLength((Avtp_Sensor_t *)pdu, 6);
    assert_int_equal(Avtp_Sensor_IsValid((Avtp_Sensor_t *)pdu, MAX_PDU_SIZE), 0);
}

static void sensor_create_message(void **state)
{
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t payload[6] = {0, 1, 2, 3, 4, 5};

    // 3 sensors * 2 octets each = 6 bytes of payload.
    Avtp_Sensor_CreateAcfMessage((Avtp_Sensor_t *)pdu, 3, 2, payload, sizeof(payload));

    assert_int_equal(Avtp_Sensor_GetAcfMsgType((Avtp_Sensor_t *)pdu), AVTP_ACF_TYPE_SENSOR);
    assert_int_equal(Avtp_Sensor_GetNumSensor((Avtp_Sensor_t *)pdu), 3);
    assert_int_equal(Avtp_Sensor_GetSz((Avtp_Sensor_t *)pdu), 2);
    assert_int_equal(Avtp_Sensor_GetPayloadLength((Avtp_Sensor_t *)pdu), 6);
    assert_memory_equal(payload, pdu + AVTP_SENSOR_HEADER_LEN, sizeof(payload));
    assert_int_equal(Avtp_Sensor_IsValid((Avtp_Sensor_t *)pdu, MAX_PDU_SIZE), 1);
}

static void sensor_get_payload_length(void **state)
{
    uint8_t pdu[MAX_PDU_SIZE];

    // num_sensors = 3, sz = 2 -> 6 bytes.
    Avtp_Sensor_Init((Avtp_Sensor_t *)pdu);
    Avtp_Sensor_SetNumSensor((Avtp_Sensor_t *)pdu, 3);
    Avtp_Sensor_SetSz((Avtp_Sensor_t *)pdu, 2);
    assert_int_equal(Avtp_Sensor_GetPayloadLength((Avtp_Sensor_t *)pdu), 6);

    // num_sensors = 0 -> 128 sensors, sz = 0 -> 4 octets each -> 512 bytes.
    Avtp_Sensor_Init((Avtp_Sensor_t *)pdu);
    Avtp_Sensor_SetNumSensor((Avtp_Sensor_t *)pdu, 0);
    Avtp_Sensor_SetSz((Avtp_Sensor_t *)pdu, 0);
    assert_int_equal(Avtp_Sensor_GetPayloadLength((Avtp_Sensor_t *)pdu), 512);

    // num_sensors = 1, sz = 3 -> 3 bytes.
    Avtp_Sensor_Init((Avtp_Sensor_t *)pdu);
    Avtp_Sensor_SetNumSensor((Avtp_Sensor_t *)pdu, 1);
    Avtp_Sensor_SetSz((Avtp_Sensor_t *)pdu, 3);
    assert_int_equal(Avtp_Sensor_GetPayloadLength((Avtp_Sensor_t *)pdu), 3);

    // num_sensors = 0 -> 128 sensors, sz = 1 -> 128 bytes.
    Avtp_Sensor_Init((Avtp_Sensor_t *)pdu);
    Avtp_Sensor_SetNumSensor((Avtp_Sensor_t *)pdu, 0);
    Avtp_Sensor_SetSz((Avtp_Sensor_t *)pdu, 1);
    assert_int_equal(Avtp_Sensor_GetPayloadLength((Avtp_Sensor_t *)pdu), 128);
}

static void sensor_create_from_garbage(void **state)
{
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t payload[6] = {0, 1, 2, 3, 4, 5};

    // CreateAcfMessage must fully initialize the header even on garbage input.
    memset(pdu, 0xAA, MAX_PDU_SIZE);
    Avtp_Sensor_CreateAcfMessage((Avtp_Sensor_t *)pdu, 3, 2, payload, sizeof(payload));

    assert_int_equal(Avtp_Sensor_GetAcfMsgType((Avtp_Sensor_t *)pdu), AVTP_ACF_TYPE_SENSOR);
    assert_int_equal(Avtp_Sensor_IsMtv((Avtp_Sensor_t *)pdu), 0);
    assert_int_equal(Avtp_Sensor_GetSensorGroup((Avtp_Sensor_t *)pdu), 0);
    assert_int_equal(Avtp_Sensor_GetMessageTimestamp((Avtp_Sensor_t *)pdu), 0);
    assert_memory_equal(payload, pdu + AVTP_SENSOR_HEADER_LEN, sizeof(payload));
    assert_int_equal(Avtp_Sensor_IsValid((Avtp_Sensor_t *)pdu, MAX_PDU_SIZE), 1);
}

static void sensor_brief_init(void **state)
{
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t init_pdu[AVTP_SENSOR_BRIEF_HEADER_LEN];

    Avtp_SensorBrief_Init(NULL);

    Avtp_SensorBrief_Init((Avtp_SensorBrief_t *)pdu);
    memset(init_pdu, 0, AVTP_SENSOR_BRIEF_HEADER_LEN);
    init_pdu[0] = AVTP_ACF_TYPE_SENSOR_BRIEF << 1;
    assert_memory_equal(init_pdu, pdu, AVTP_SENSOR_BRIEF_HEADER_LEN);
}

static void sensor_brief_get_set_fields(void **state)
{
    uint8_t pdu[MAX_PDU_SIZE];

    Avtp_SensorBrief_Init((Avtp_SensorBrief_t *)pdu);

    Avtp_SensorBrief_SetAcfMsgType((Avtp_SensorBrief_t *)pdu, AVTP_ACF_TYPE_SENSOR_BRIEF);
    assert_int_equal(Avtp_SensorBrief_GetAcfMsgType((Avtp_SensorBrief_t *)pdu),
                     AVTP_ACF_TYPE_SENSOR_BRIEF);

    Avtp_SensorBrief_SetAcfMsgLength((Avtp_SensorBrief_t *)pdu, 5);
    assert_int_equal(Avtp_SensorBrief_GetAcfMsgLength((Avtp_SensorBrief_t *)pdu), 5);

    Avtp_SensorBrief_SetMtv((Avtp_SensorBrief_t *)pdu, true);
    assert_int_equal(Avtp_SensorBrief_IsMtv((Avtp_SensorBrief_t *)pdu), 1);

    Avtp_SensorBrief_SetMtv((Avtp_SensorBrief_t *)pdu, false);
    assert_int_equal(Avtp_SensorBrief_IsMtv((Avtp_SensorBrief_t *)pdu), 0);

    Avtp_SensorBrief_SetNumSensor((Avtp_SensorBrief_t *)pdu, 10);
    assert_int_equal(Avtp_SensorBrief_GetNumSensor((Avtp_SensorBrief_t *)pdu), 10);

    Avtp_SensorBrief_SetSz((Avtp_SensorBrief_t *)pdu, 3);
    assert_int_equal(Avtp_SensorBrief_GetSz((Avtp_SensorBrief_t *)pdu), 3);

    Avtp_SensorBrief_SetSensorGroup((Avtp_SensorBrief_t *)pdu, 5);
    assert_int_equal(Avtp_SensorBrief_GetSensorGroup((Avtp_SensorBrief_t *)pdu), 5);
}

static void sensor_brief_is_valid(void **state)
{
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t payload[6] = {0, 1, 2, 3, 4, 5};

    // An Init-only PDU has AcfMsgLength == 0, so IsValid must reject it.
    Avtp_SensorBrief_Init((Avtp_SensorBrief_t *)pdu);
    assert_int_equal(Avtp_SensorBrief_IsValid((Avtp_SensorBrief_t *)pdu, MAX_PDU_SIZE), 0);

    memset(pdu, 0, MAX_PDU_SIZE);
    assert_int_equal(Avtp_SensorBrief_IsValid((Avtp_SensorBrief_t *)pdu, MAX_PDU_SIZE), 0);

    Avtp_SensorBrief_CreateAcfMessage((Avtp_SensorBrief_t *)pdu, 3, 2, payload, sizeof(payload));
    assert_int_equal(Avtp_SensorBrief_IsValid((Avtp_SensorBrief_t *)pdu, MAX_PDU_SIZE), 1);
    assert_int_equal(Avtp_SensorBrief_IsValid((Avtp_SensorBrief_t *)pdu, 12), 1);

    // AcfMsgLength inconsistent with num_sensors and sz.
    Avtp_SensorBrief_Init((Avtp_SensorBrief_t *)pdu);
    Avtp_SensorBrief_SetNumSensor((Avtp_SensorBrief_t *)pdu, 3);
    Avtp_SensorBrief_SetSz((Avtp_SensorBrief_t *)pdu, 2);
    Avtp_SensorBrief_SetAcfMsgLength((Avtp_SensorBrief_t *)pdu, 2);
    assert_int_equal(Avtp_SensorBrief_IsValid((Avtp_SensorBrief_t *)pdu, MAX_PDU_SIZE), 0);
}

static void sensor_brief_create_message(void **state)
{
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t payload[6] = {0, 1, 2, 3, 4, 5};

    // 3 sensors * 2 octets each = 6 bytes of payload.
    Avtp_SensorBrief_CreateAcfMessage((Avtp_SensorBrief_t *)pdu, 3, 2, payload, sizeof(payload));

    assert_int_equal(Avtp_SensorBrief_GetAcfMsgType((Avtp_SensorBrief_t *)pdu),
                     AVTP_ACF_TYPE_SENSOR_BRIEF);
    assert_int_equal(Avtp_SensorBrief_GetNumSensor((Avtp_SensorBrief_t *)pdu), 3);
    assert_int_equal(Avtp_SensorBrief_GetSz((Avtp_SensorBrief_t *)pdu), 2);
    assert_int_equal(Avtp_SensorBrief_GetPayloadLength((Avtp_SensorBrief_t *)pdu), 6);
    assert_memory_equal(payload, pdu + AVTP_SENSOR_BRIEF_HEADER_LEN, sizeof(payload));
    assert_int_equal(Avtp_SensorBrief_IsValid((Avtp_SensorBrief_t *)pdu, MAX_PDU_SIZE), 1);
}

static void sensor_brief_get_payload_length(void **state)
{
    uint8_t pdu[MAX_PDU_SIZE];

    // num_sensors = 3, sz = 2 -> 6 bytes.
    Avtp_SensorBrief_Init((Avtp_SensorBrief_t *)pdu);
    Avtp_SensorBrief_SetNumSensor((Avtp_SensorBrief_t *)pdu, 3);
    Avtp_SensorBrief_SetSz((Avtp_SensorBrief_t *)pdu, 2);
    assert_int_equal(Avtp_SensorBrief_GetPayloadLength((Avtp_SensorBrief_t *)pdu), 6);

    // num_sensors = 0 -> 128 sensors, sz = 0 -> 4 octets each -> 512 bytes.
    Avtp_SensorBrief_Init((Avtp_SensorBrief_t *)pdu);
    Avtp_SensorBrief_SetNumSensor((Avtp_SensorBrief_t *)pdu, 0);
    Avtp_SensorBrief_SetSz((Avtp_SensorBrief_t *)pdu, 0);
    assert_int_equal(Avtp_SensorBrief_GetPayloadLength((Avtp_SensorBrief_t *)pdu), 512);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(sensor_init),
        cmocka_unit_test(sensor_get_set_fields),
        cmocka_unit_test(sensor_is_valid),
        cmocka_unit_test(sensor_create_message),
        cmocka_unit_test(sensor_get_payload_length),
        cmocka_unit_test(sensor_create_from_garbage),
        cmocka_unit_test(sensor_brief_init),
        cmocka_unit_test(sensor_brief_get_set_fields),
        cmocka_unit_test(sensor_brief_is_valid),
        cmocka_unit_test(sensor_brief_create_message),
        cmocka_unit_test(sensor_brief_get_payload_length),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
