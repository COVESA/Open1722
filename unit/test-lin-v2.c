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

#include "avtp/acf/LinV2.h"

#define MAX_PDU_SIZE 1500

static void lin_v2_init(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t init_pdu[AVTP_LIN_V2_HEADER_LEN] = {0};

    assert_int_equal(sizeof(Avtp_LinV2_t), AVTP_LIN_V2_HEADER_LEN);

    Avtp_LinV2_Init(NULL);

    memset(pdu, 0xAA, sizeof(pdu));
    Avtp_LinV2_Init((Avtp_LinV2_t *)pdu);
    init_pdu[0] = AVTP_ACF_TYPE_LIN_V2 << 1;
    assert_memory_equal(init_pdu, pdu, sizeof(init_pdu));
    assert_int_equal(pdu[AVTP_LIN_V2_HEADER_LEN], 0xAA);
}

static void lin_v2_field_descriptors_cover_header(void **state)
{
    (void)state;
    uint8_t coverage[AVTP_LIN_V2_HEADER_LEN * 8] = {0};

    for (uint8_t field = 0; field < AVTP_LIN_V2_FIELD_MAX; field++) {
        const Avtp_FieldDescriptor_t *desc = &Avtp_LinV2FieldDesc[field];
        size_t first_bit = (size_t)desc->quadlet * 32 + desc->offset;

        assert_true(desc->bits > 0);
        for (uint8_t bit = 0; bit < desc->bits; bit++) {
            size_t bit_index = first_bit + bit;

            assert_true(bit_index < sizeof(coverage));
            assert_int_equal(coverage[bit_index], 0);
            coverage[bit_index] = 1;
        }
    }

    for (size_t bit = 0; bit < sizeof(coverage); bit++) {
        assert_int_equal(coverage[bit], 1);
    }
}

static void lin_v2_get_set_fields(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_LinV2_t *lin = (Avtp_LinV2_t *)pdu;

    Avtp_LinV2_Init(lin);
    assert_int_equal(Avtp_AcfCommon_GetAcfMsgType((Avtp_AcfCommon_t *)lin), AVTP_ACF_TYPE_LIN_V2);

    Avtp_LinV2_SetPad(lin, 2);
    assert_int_equal(Avtp_LinV2_GetPad(lin), 2);

    Avtp_LinV2_SetMtv(lin, true);
    assert_true(Avtp_LinV2_IsMtv(lin));
    Avtp_LinV2_SetMtv(lin, false);
    assert_false(Avtp_LinV2_IsMtv(lin));

    Avtp_LinV2_SetLinBusId(lin, 0x5AB);
    assert_int_equal(Avtp_LinV2_GetLinBusId(lin), 0x5AB);

    Avtp_LinV2_SetLinIdentifier(lin, 0xC7);
    assert_int_equal(Avtp_LinV2_GetLinIdentifier(lin), 0xC7);

    Avtp_LinV2_SetMessageTimestamp(lin, 0x123456789ABCDEF0ULL);
    assert_int_equal(Avtp_LinV2_GetMessageTimestamp(lin), 0x123456789ABCDEF0ULL);
}

static void lin_v2_payload_and_length(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t payload[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    Avtp_LinV2_t *lin = (Avtp_LinV2_t *)pdu;

    for (uint16_t payload_length = 0; payload_length <= sizeof(payload); payload_length++) {
        uint16_t message_length = AVTP_LIN_V2_HEADER_LEN + payload_length;
        uint8_t pad =
            (uint8_t)(AVTP_QUADLET_SIZE - message_length % AVTP_QUADLET_SIZE) % AVTP_QUADLET_SIZE;
        uint16_t padded_length = message_length + pad;

        memset(pdu, 0xAA, sizeof(pdu));
        Avtp_LinV2_Init(lin);
        Avtp_LinV2_SetPayload(lin, payload, payload_length);
        assert_ptr_equal(Avtp_LinV2_GetPayload(lin), pdu + AVTP_LIN_V2_HEADER_LEN);
        if (payload_length > 0) {
            assert_memory_equal(Avtp_LinV2_GetPayload(lin), payload, payload_length);
        }

        Avtp_LinV2_SetPayloadLength(lin, payload_length);
        assert_int_equal(Avtp_LinV2_GetPad(lin), pad);
        assert_int_equal(Avtp_AcfCommon_GetAcfMsgLengthInBytes((Avtp_AcfCommon_t *)lin),
                         padded_length);
        assert_true(Avtp_LinV2_IsValid(lin, padded_length));
        assert_int_equal(Avtp_LinV2_GetPayloadLength(lin), payload_length);
        for (uint8_t pad_byte = 0; pad_byte < pad; pad_byte++) {
            assert_int_equal(pdu[message_length + pad_byte], 0);
        }
    }
}

static void lin_v2_is_valid(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t payload[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    Avtp_LinV2_t *lin = (Avtp_LinV2_t *)pdu;

    assert_false(Avtp_LinV2_IsValid(NULL, sizeof(pdu)));

    Avtp_LinV2_CreateAcfMessage(lin, 7, 0x3F, 0x123456789ABCULL, payload, sizeof(payload));
    assert_true(Avtp_LinV2_IsValid(lin, AVTP_LIN_V2_HEADER_LEN + sizeof(payload)));
    assert_false(Avtp_LinV2_IsValid(lin, AVTP_LIN_V2_HEADER_LEN - 1));
    assert_false(Avtp_LinV2_IsValid(lin, AVTP_LIN_V2_HEADER_LEN + sizeof(payload) - 1));

    Avtp_AcfCommon_SetAcfMsgType((Avtp_AcfCommon_t *)lin, AVTP_ACF_TYPE_LIN);
    assert_false(Avtp_LinV2_IsValid(lin, sizeof(pdu)));

    Avtp_LinV2_Init(lin);
    Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)lin, 3);
    assert_false(Avtp_LinV2_IsValid(lin, sizeof(pdu)));

    Avtp_LinV2_Init(lin);
    Avtp_LinV2_SetPad(lin, 1);
    Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)lin, 4);
    assert_false(Avtp_LinV2_IsValid(lin, sizeof(pdu)));

    Avtp_LinV2_Init(lin);
    Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)lin, 7);
    assert_false(Avtp_LinV2_IsValid(lin, sizeof(pdu)));
}

static void lin_v2_create_message(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t payload[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    Avtp_LinV2_t *lin = (Avtp_LinV2_t *)pdu;

    memset(pdu, 0xAA, sizeof(pdu));
    Avtp_LinV2_CreateAcfMessage(lin, 7, 0x3F, 0x123456789ABCULL, payload, sizeof(payload));

    assert_int_equal(Avtp_AcfCommon_GetAcfMsgType((Avtp_AcfCommon_t *)lin), AVTP_ACF_TYPE_LIN_V2);
    assert_int_equal(Avtp_LinV2_GetLinBusId(lin), 7);
    assert_int_equal(Avtp_LinV2_GetLinIdentifier(lin), 0x3F);
    assert_int_equal(Avtp_LinV2_GetMessageTimestamp(lin), 0x123456789ABCULL);
    assert_memory_equal(Avtp_LinV2_GetPayload(lin), payload, sizeof(payload));
    assert_int_equal(Avtp_LinV2_GetPayloadLength(lin), sizeof(payload));
    assert_int_equal(Avtp_AcfCommon_GetAcfMsgLength((Avtp_AcfCommon_t *)lin), 6);
    assert_true(Avtp_LinV2_IsValid(lin, AVTP_LIN_V2_HEADER_LEN + sizeof(payload)));
}

static void lin_v2_create_from_garbage(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t payload[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    Avtp_LinV2_t *lin = (Avtp_LinV2_t *)pdu;

    memset(pdu, 0xAA, sizeof(pdu));
    Avtp_LinV2_CreateAcfMessage(lin, 7, 0x3F, 0x123456789ABCULL, payload, sizeof(payload));

    assert_int_equal(Avtp_AcfCommon_GetAcfMsgType((Avtp_AcfCommon_t *)lin), AVTP_ACF_TYPE_LIN_V2);
    assert_int_equal(Avtp_LinV2_GetPad(lin), 0);
    assert_false(Avtp_LinV2_IsMtv(lin));
    assert_int_equal(Avtp_LinV2_GetLinBusId(lin), 7);
    assert_int_equal(Avtp_LinV2_GetLinIdentifier(lin), 0x3F);
    assert_int_equal(Avtp_LinV2_GetMessageTimestamp(lin), 0x123456789ABCULL);
    assert_memory_equal(Avtp_LinV2_GetPayload(lin), payload, sizeof(payload));
    assert_true(Avtp_LinV2_IsValid(lin, AVTP_LIN_V2_HEADER_LEN + sizeof(payload)));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(lin_v2_init),
        cmocka_unit_test(lin_v2_field_descriptors_cover_header),
        cmocka_unit_test(lin_v2_get_set_fields),
        cmocka_unit_test(lin_v2_payload_and_length),
        cmocka_unit_test(lin_v2_is_valid),
        cmocka_unit_test(lin_v2_create_message),
        cmocka_unit_test(lin_v2_create_from_garbage),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
