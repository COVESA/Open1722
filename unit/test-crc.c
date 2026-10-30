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

#include "avtp/acf/Crc.h"

#define MAX_PDU_SIZE 1500

static void crc_init(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t init_pdu[AVTP_CRC_HEADER_LEN] = {0};

    assert_int_equal(sizeof(Avtp_Crc_t), AVTP_CRC_HEADER_LEN);

    Avtp_Crc_Init(NULL);

    memset(pdu, 0xAA, sizeof(pdu));
    Avtp_Crc_Init((Avtp_Crc_t *)pdu);
    init_pdu[0] = AVTP_ACF_TYPE_CRC << 1;
    assert_memory_equal(init_pdu, pdu, AVTP_CRC_HEADER_LEN);
    assert_int_equal(pdu[AVTP_CRC_HEADER_LEN], 0xAA);
}

static void crc_field_descriptors_cover_header(void **state)
{
    (void)state;
    uint8_t coverage[(AVTP_CRC_HEADER_LEN + AVTP_QUADLET_SIZE) * 8] = {0};

    for (uint8_t field = 0; field < AVTP_CRC_FIELD_MAX; field++) {
        const Avtp_FieldDescriptor_t *desc = &Avtp_CrcFieldDesc[field];

        for (uint8_t bit = 0; bit < desc->bits; bit++) {
            size_t bit_index = (desc->quadlet * 32) + desc->offset + bit;

            assert_true(bit_index < sizeof(coverage));
            assert_int_equal(coverage[bit_index], 0);
            coverage[bit_index] = 1;
        }
    }

    for (size_t bit = 0; bit < sizeof(coverage); bit++) {
        assert_int_equal(coverage[bit], 1);
    }
}

static void crc_fields(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Crc_t *crc = (Avtp_Crc_t *)pdu;

    Avtp_Crc_Init(crc);
    assert_int_equal(Avtp_AcfCommon_GetAcfMsgType((Avtp_AcfCommon_t *)crc), AVTP_ACF_TYPE_CRC);

    Avtp_Crc_SetCrcType(crc, AVTP_CRC_TYPE_CRC_32P4);
    assert_int_equal(Avtp_Crc_GetCrcType(crc), AVTP_CRC_TYPE_CRC_32P4);

    Avtp_SetField(Avtp_CrcFieldDesc, AVTP_CRC_FIELD_MAX, pdu, AVTP_CRC_FIELD_RESERVED, 0xABC);
    assert_int_equal(
        Avtp_GetField(Avtp_CrcFieldDesc, AVTP_CRC_FIELD_MAX, pdu, AVTP_CRC_FIELD_RESERVED), 0xABC);
    assert_int_equal(Avtp_Crc_GetCrcType(crc), AVTP_CRC_TYPE_CRC_32P4);

    Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)crc, 1);
    assert_int_equal(Avtp_AcfCommon_GetAcfMsgLength((Avtp_AcfCommon_t *)crc), 1);
}

static void crc_payload_and_length(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t payload[] = {0x10, 0x20, 0x30, 0x40, 0x50};
    Avtp_Crc_t *crc = (Avtp_Crc_t *)pdu;

    for (uint16_t payload_length = 0; payload_length <= sizeof(payload); payload_length++) {
        uint16_t message_length = AVTP_CRC_HEADER_LEN + payload_length;
        uint16_t padded_length =
            ((message_length + AVTP_QUADLET_SIZE - 1) / AVTP_QUADLET_SIZE) * AVTP_QUADLET_SIZE;

        memset(pdu, 0xAA, sizeof(pdu));
        Avtp_Crc_Init(crc);
        Avtp_Crc_SetPayload(crc, payload, payload_length);
        assert_ptr_equal(Avtp_Crc_GetPayload(crc), pdu + AVTP_CRC_HEADER_LEN);
        if (payload_length > 0) {
            assert_memory_equal(Avtp_Crc_GetPayload(crc), payload, payload_length);
        }

        Avtp_Crc_SetPayloadLength(crc, payload_length);
        assert_int_equal(Avtp_AcfCommon_GetAcfMsgLengthInBytes((Avtp_AcfCommon_t *)crc),
                         padded_length);
        for (uint16_t pad = 0; pad < padded_length - message_length; pad++) {
            assert_int_equal(pdu[message_length + pad], 0);
        }
    }
}

static void crc_create_message(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint32_t crcdata = 0xdeadbeef;
    Avtp_Crc_t *crc = (Avtp_Crc_t *)pdu;

    memset(pdu, 0xAA, sizeof(pdu));
    Avtp_Crc_CreateAcfMessage(crc, AVTP_CRC_TYPE_CRC_ETH, (uint8_t *)&crcdata, sizeof(crcdata));

    assert_int_equal(Avtp_AcfCommon_GetAcfMsgType((Avtp_AcfCommon_t *)crc), AVTP_ACF_TYPE_CRC);
    assert_int_equal(Avtp_Crc_GetCrcType(crc), AVTP_CRC_TYPE_CRC_ETH);
    assert_int_equal(Avtp_AcfCommon_GetAcfMsgLengthInBytes((Avtp_AcfCommon_t *)crc), 8);
    assert_int_equal(Avtp_Crc_GetCrcData(crc), crcdata);
    assert_true(Avtp_Crc_IsValid(crc, 8));
}

static void crc_is_valid(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Crc_t *crc = (Avtp_Crc_t *)pdu;
    uint8_t payload[] = {0, 1, 2, 3};

    assert_false(Avtp_Crc_IsValid(NULL, sizeof(pdu)));

    Avtp_Crc_CreateAcfMessage(crc, AVTP_CRC_TYPE_CRC_ETH, payload, sizeof(payload));
    assert_true(Avtp_Crc_IsValid(crc, 8));

    assert_false(Avtp_Crc_IsValid(crc, AVTP_CRC_HEADER_LEN - 1));

    Avtp_AcfCommon_SetAcfMsgType((Avtp_AcfCommon_t *)crc, AVTP_ACF_TYPE_GPC);
    assert_false(Avtp_Crc_IsValid(crc, sizeof(pdu)));

    Avtp_Crc_CreateAcfMessage(crc, AVTP_CRC_TYPE_CRC_ETH, payload, sizeof(payload));
    Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)crc, 0);
    assert_false(Avtp_Crc_IsValid(crc, sizeof(pdu)));

    Avtp_Crc_CreateAcfMessage(crc, AVTP_CRC_TYPE_CRC_ETH, payload, sizeof(payload));
    assert_false(Avtp_Crc_IsValid(crc, 7));
}

/* CRC_ETH and CRC_32P4 carry a fixed 4 byte CRC, so the message must be exactly 8 bytes. */
static void crc_is_valid_fixed_length_types(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t payload[8] = {0};
    Avtp_Crc_t *crc = (Avtp_Crc_t *)pdu;
    const Avtp_CrcType_t types[] = {AVTP_CRC_TYPE_CRC_ETH, AVTP_CRC_TYPE_CRC_32P4,
                                    AVTP_CRC_TYPE_CRC_USER};

    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        Avtp_CrcType_t type = types[i];

        Avtp_Crc_CreateAcfMessage(crc, type, payload, 4);
        assert_true(Avtp_Crc_IsValid(crc, sizeof(pdu)));

        /* Too short: header only, and below the fixed length. */
        Avtp_Crc_CreateAcfMessage(crc, type, payload, 0);
        Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)crc, 0);
        assert_false(Avtp_Crc_IsValid(crc, sizeof(pdu)));

        /* Too long: fits the buffer but exceeds the fixed length. */
        Avtp_Crc_CreateAcfMessage(crc, type, payload, 12);
        Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)crc, 3);
        if (type == AVTP_CRC_TYPE_CRC_ETH || type == AVTP_CRC_TYPE_CRC_32P4) {
            assert_false(Avtp_Crc_IsValid(crc, sizeof(pdu)));
        } else {
            assert_true(Avtp_Crc_IsValid(crc, sizeof(pdu)));
        }

        /* Zero length */
        Avtp_Crc_CreateAcfMessage(crc, type, payload, 8);
        Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)crc, 0);
        assert_false(Avtp_Crc_IsValid(crc, sizeof(pdu)));
    }
}

/* CRC_USER has a variable payload length, so lengths other than 8 bytes remain valid. */
static void crc_is_valid_user_type_variable_length(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t payload[16] = {0};
    Avtp_Crc_t *crc = (Avtp_Crc_t *)pdu;

    for (uint16_t payload_length = 0; payload_length < 4; payload_length += 4) {
        Avtp_Crc_CreateAcfMessage(crc, AVTP_CRC_TYPE_CRC_USER, payload, payload_length);
        assert_false(Avtp_Crc_IsValid(crc, AVTP_CRC_HEADER_LEN + payload_length));
    }

    for (uint16_t payload_length = 8; payload_length <= sizeof(payload); payload_length += 4) {
        Avtp_Crc_CreateAcfMessage(crc, AVTP_CRC_TYPE_CRC_USER, payload, payload_length);
        assert_true(Avtp_Crc_IsValid(crc, AVTP_CRC_HEADER_LEN + payload_length));
    }
}

static void crc_get_payload_length_fixed_types(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t payload[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    Avtp_Crc_t *crc = (Avtp_Crc_t *)pdu;

    Avtp_Crc_CreateAcfMessage(crc, AVTP_CRC_TYPE_CRC_ETH, payload, sizeof(payload));
    assert_int_equal(Avtp_Crc_GetPayloadLength(crc), 4);

    Avtp_Crc_CreateAcfMessage(crc, AVTP_CRC_TYPE_CRC_32P4, payload, sizeof(payload));
    assert_int_equal(Avtp_Crc_GetPayloadLength(crc), 4);
}

/* There is no pad field, so the returned length includes the zero padding. */
static void crc_get_payload_length_user_type_includes_padding(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t payload[16] = {0};
    Avtp_Crc_t *crc = (Avtp_Crc_t *)pdu;

    for (uint16_t payload_length = 0; payload_length <= sizeof(payload); payload_length++) {
        uint16_t padded_length =
            ((payload_length + AVTP_QUADLET_SIZE - 1) / AVTP_QUADLET_SIZE) * AVTP_QUADLET_SIZE;

        Avtp_Crc_CreateAcfMessage(crc, AVTP_CRC_TYPE_CRC_USER, payload, payload_length);
        assert_int_equal(Avtp_Crc_GetPayloadLength(crc), padded_length);
    }
}

static void crc_get_payload_length_from_message_length(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Crc_t *crc = (Avtp_Crc_t *)pdu;

    /* Header only, no payload. */
    Avtp_Crc_Init(crc);
    Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)crc, 1);
    assert_int_equal(Avtp_Crc_GetPayloadLength(crc), 0);

    /* Lengths above 255 bytes must not be truncated to uint8_t. */
    Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)crc, 101);
    assert_int_equal(Avtp_Crc_GetPayloadLength(crc), 400);

    /* Maximum 9-bit quadlet length. */
    Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)crc, 0x1FF);
    assert_int_equal(Avtp_Crc_GetPayloadLength(crc),
                     0x1FF * AVTP_QUADLET_SIZE - AVTP_CRC_HEADER_LEN);
}

/* Init + CRC_32P4 + 4-byte CRC data. */
static void crc_wire_format(void **state)
{
    (void)state;
    const uint8_t expected[] = {0xEE, 0x02, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44};
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Crc_t *crc = (Avtp_Crc_t *)pdu;

    memset(pdu, 0xAA, sizeof(pdu));
    Avtp_Crc_Init(crc);
    Avtp_Crc_SetCrcType(crc, AVTP_CRC_TYPE_CRC_32P4);
    Avtp_Crc_SetCrcData(crc, 0x11223344);
    Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)crc, 2);
    assert_memory_equal(pdu, expected, sizeof(expected));
    assert_int_equal(pdu[sizeof(expected)], 0xAA);

    assert_int_equal(Avtp_Crc_GetCrcType(crc), AVTP_CRC_TYPE_CRC_32P4);
    assert_int_equal(Avtp_Crc_GetCrcData(crc), 0x11223344);
    assert_true(Avtp_Crc_IsValid(crc, sizeof(expected)));
}

/* CreateAcfMessage takes the CRC data as a host-order integer, so the wire bytes are the same. */
static void crc_wire_format_create_message(void **state)
{
    (void)state;
    const uint8_t expected[] = {0xEE, 0x02, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44};
    uint8_t pdu[MAX_PDU_SIZE];
    uint32_t crc_data = 0x11223344;

    memset(pdu, 0xAA, sizeof(pdu));
    Avtp_Crc_CreateAcfMessage((Avtp_Crc_t *)pdu, AVTP_CRC_TYPE_CRC_32P4, (uint8_t *)&crc_data,
                              sizeof(crc_data));
    assert_memory_equal(pdu, expected, sizeof(expected));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(crc_init),
        cmocka_unit_test(crc_field_descriptors_cover_header),
        cmocka_unit_test(crc_fields),
        cmocka_unit_test(crc_payload_and_length),
        cmocka_unit_test(crc_create_message),
        cmocka_unit_test(crc_is_valid),
        cmocka_unit_test(crc_is_valid_fixed_length_types),
        cmocka_unit_test(crc_is_valid_user_type_variable_length),
        cmocka_unit_test(crc_get_payload_length_fixed_types),
        cmocka_unit_test(crc_get_payload_length_user_type_includes_padding),
        cmocka_unit_test(crc_get_payload_length_from_message_length),
        cmocka_unit_test(crc_wire_format),
        cmocka_unit_test(crc_wire_format_create_message),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
