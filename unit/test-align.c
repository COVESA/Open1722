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

/**
 * @file
 * Verifies that the accessors and the field-access engine work on PDUs with
 * every possible byte alignment. IEEE 1722 only defines the wire ordering of
 * fields, so a frame may sit at any offset in a receive buffer; these tests
 * build and parse the same frame at offsets 0-3 and require byte-identical
 * results. Run under -fsanitize=alignment to catch unaligned accesses on
 * targets where they would otherwise fault (see docs/alignment.md).
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
#include <string.h>

#include "avtp/acf/Can.h"
#include "avtp/acf/custom/Vss.h"

#define MAX_PDU_SIZE 1500

static void align_typed_accessors(void **state)
{
    (void)state;

    const uint32_t can_bus_id = 5;
    const uint64_t timestamp = 0x0102030405060708ULL;
    const uint32_t can_identifier = 0x1ABCDEF;
    uint8_t reference[MAX_PDU_SIZE];
    uint8_t raw[MAX_PDU_SIZE + 4];

    memset(reference, 0, sizeof(reference));
    Avtp_Can_Init((Avtp_Can_t *)reference);
    Avtp_Can_SetCanBusId((Avtp_Can_t *)reference, can_bus_id);
    Avtp_Can_SetMessageTimestamp((Avtp_Can_t *)reference, timestamp);
    Avtp_Can_SetCanIdentifier((Avtp_Can_t *)reference, can_identifier);
    Avtp_Can_SetPayloadLength((Avtp_Can_t *)reference, 0);

    for (size_t offset = 0; offset < 4; offset++) {
        uint8_t *pdu = raw + offset;

        memset(raw, 0xAA, sizeof(raw));
        Avtp_Can_Init((Avtp_Can_t *)pdu);
        Avtp_Can_SetCanBusId((Avtp_Can_t *)pdu, can_bus_id);
        Avtp_Can_SetMessageTimestamp((Avtp_Can_t *)pdu, timestamp);
        Avtp_Can_SetCanIdentifier((Avtp_Can_t *)pdu, can_identifier);
        Avtp_Can_SetPayloadLength((Avtp_Can_t *)pdu, 0);

        assert_memory_equal(reference, pdu, AVTP_CAN_HEADER_LEN);
        assert_int_equal(Avtp_Can_GetCanBusId((Avtp_Can_t *)pdu), can_bus_id);
        assert_int_equal(Avtp_Can_GetMessageTimestamp((Avtp_Can_t *)pdu), timestamp);
        assert_int_equal(Avtp_Can_GetCanIdentifier((Avtp_Can_t *)pdu), can_identifier);
        assert_true(Avtp_Can_IsValid((Avtp_Can_t *)pdu, MAX_PDU_SIZE - offset));
    }
}

static void align_generic_engine(void **state)
{
    (void)state;

    const uint64_t timestamp = 0x8877665544332211ULL;
    const uint64_t msg_length = 0x1F;
    const uint64_t identifier = 0x1FFFFFFF;
    uint8_t raw[AVTP_CAN_HEADER_LEN + 4];

    for (size_t offset = 0; offset < 4; offset++) {
        uint8_t *pdu = raw + offset;

        memset(raw, 0, sizeof(raw));
        Avtp_SetField(Avtp_CanFieldDesc, AVTP_CAN_FIELD_MAX, pdu, AVTP_CAN_FIELD_MESSAGE_TIMESTAMP,
                      timestamp);
        Avtp_SetField(Avtp_CanFieldDesc, AVTP_CAN_FIELD_MAX, pdu, AVTP_CAN_FIELD_ACF_MSG_LENGTH,
                      msg_length);
        Avtp_SetField(Avtp_CanFieldDesc, AVTP_CAN_FIELD_MAX, pdu, AVTP_CAN_FIELD_CAN_IDENTIFIER,
                      identifier);

        assert_int_equal(Avtp_GetField(Avtp_CanFieldDesc, AVTP_CAN_FIELD_MAX, pdu,
                                       AVTP_CAN_FIELD_MESSAGE_TIMESTAMP),
                         timestamp);
        assert_int_equal(Avtp_GetField(Avtp_CanFieldDesc, AVTP_CAN_FIELD_MAX, pdu,
                                       AVTP_CAN_FIELD_ACF_MSG_LENGTH),
                         msg_length);
        assert_int_equal(Avtp_GetField(Avtp_CanFieldDesc, AVTP_CAN_FIELD_MAX, pdu,
                                       AVTP_CAN_FIELD_CAN_IDENTIFIER),
                         identifier);
    }
}

static void vss_build_static_frame(uint8_t *buf, uint16_t data_length, uint32_t *values)
{
    Avtp_Vss_t *pdu = (Avtp_Vss_t *)buf;
    VssPath_t path;
    VssDataUint32Array_t array;
    VssData_t data;

    memset(&path, 0, sizeof(path));
    path.vss_static_id_path = 0xDEADBEEF;

    array.data_length = data_length;
    array.data = values;

    memset(&data, 0, sizeof(data));
    data.data_uint32_array = &array;

    Avtp_Vss_Init(pdu);
    Avtp_Vss_SetAddrMode(pdu, VSS_STATIC_ID_MODE);
    Avtp_Vss_SetVssPath(pdu, &path);
    Avtp_Vss_SetDatatype(pdu, VSS_UINT32_ARRAY);
    Avtp_Vss_SetVssData(pdu, &data);
    Avtp_Vss_SetPayloadLength(pdu, (uint16_t)(4 + 2 + data_length));
}

static void align_vss_static_mode(void **state)
{
    (void)state;

    uint32_t values[2] = {0x01020304, 0xAABBCCDD};
    uint8_t reference[MAX_PDU_SIZE];
    uint8_t raw[MAX_PDU_SIZE + 4];

    memset(reference, 0, sizeof(reference));
    vss_build_static_frame(reference, (uint16_t)sizeof(values), values);

    for (size_t offset = 0; offset < 4; offset++) {
        Avtp_Vss_t *pdu = (Avtp_Vss_t *)(raw + offset);
        VssDataUint32Array_t got_array;
        VssData_t got_data;
        uint32_t got_values[2] = {0, 0};
        VssPath_t got_path;

        memset(raw, 0xAA, sizeof(raw));
        vss_build_static_frame(raw + offset, (uint16_t)sizeof(values), values);

        assert_memory_equal(reference, pdu, AVTP_VSS_FIXED_HEADER_LEN + 4 + 2 + 8 + 2);
        assert_true(Avtp_Vss_IsValid(pdu, MAX_PDU_SIZE - offset));

        memset(&got_array, 0, sizeof(got_array));
        got_array.data = got_values;
        memset(&got_data, 0, sizeof(got_data));
        got_data.data_uint32_array = &got_array;

        Avtp_Vss_GetVssData(pdu, &got_data);
        assert_int_equal(got_array.data_length, sizeof(values));
        assert_int_equal(got_values[0], values[0]);
        assert_int_equal(got_values[1], values[1]);

        memset(&got_path, 0, sizeof(got_path));
        Avtp_Vss_GetVssPath(pdu, &got_path);
        assert_int_equal(got_path.vss_static_id_path, 0xDEADBEEF);
    }
}

static void align_vss_interop_mode(void **state)
{
    (void)state;

    char path[] = "Vehicle.Speed";
    uint32_t values[2] = {0x11223344, 0x55667788};
    uint8_t raw[MAX_PDU_SIZE + 4];

    for (size_t offset = 0; offset < 4; offset++) {
        Avtp_Vss_t *pdu = (Avtp_Vss_t *)(raw + offset);
        VssPath_t set_path;
        VssDataUint32Array_t set_array;
        VssData_t set_data;
        VssPath_t got_path;
        VssDataUint32Array_t got_array;
        VssData_t got_data;
        char got_path_buffer[sizeof(path)];
        uint32_t got_values[2] = {0, 0};

        memset(&set_path, 0, sizeof(set_path));
        set_path.vss_interop_path.path = path;
        set_path.vss_interop_path.path_length = (uint16_t)strlen(path);

        set_array.data_length = (uint16_t)sizeof(values);
        set_array.data = values;

        memset(&set_data, 0, sizeof(set_data));
        set_data.data_uint32_array = &set_array;

        memset(raw, 0xAA, sizeof(raw));
        Avtp_Vss_Init(pdu);
        Avtp_Vss_SetAddrMode(pdu, VSS_INTEROP_MODE);
        Avtp_Vss_SetVssPath(pdu, &set_path);
        Avtp_Vss_SetDatatype(pdu, VSS_UINT32_ARRAY);
        Avtp_Vss_SetVssData(pdu, &set_data);
        Avtp_Vss_SetPayloadLength(pdu, (uint16_t)(2 + strlen(path) + 2 + sizeof(values)));

        assert_true(Avtp_Vss_IsValid(pdu, MAX_PDU_SIZE - offset));

        memset(&got_path, 0, sizeof(got_path));
        memset(got_path_buffer, 0, sizeof(got_path_buffer));
        got_path.vss_interop_path.path = got_path_buffer;
        Avtp_Vss_GetVssPath(pdu, &got_path);
        assert_int_equal(got_path.vss_interop_path.path_length, strlen(path));
        assert_memory_equal(got_path.vss_interop_path.path, path, strlen(path));

        memset(&got_array, 0, sizeof(got_array));
        got_array.data = got_values;
        memset(&got_data, 0, sizeof(got_data));
        got_data.data_uint32_array = &got_array;

        Avtp_Vss_GetVssData(pdu, &got_data);
        assert_int_equal(got_array.data_length, sizeof(values));
        assert_int_equal(got_values[0], values[0]);
        assert_int_equal(got_values[1], values[1]);
    }
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(align_typed_accessors),
        cmocka_unit_test(align_generic_engine),
        cmocka_unit_test(align_vss_static_mode),
        cmocka_unit_test(align_vss_interop_mode),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
