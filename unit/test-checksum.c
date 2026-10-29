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

#include "avtp/acf/Checksum.h"

static void checksum_init(void **state)
{
    (void)state;
    uint8_t pdu[AVTP_CHECKSUM_HEADER_LEN];
    const uint8_t init_pdu[AVTP_CHECKSUM_HEADER_LEN] = {AVTP_ACF_TYPE_CHECKSUM << 1, 0, 0, 0};

    assert_int_equal(sizeof(Avtp_Checksum_t), AVTP_CHECKSUM_HEADER_LEN);

    Avtp_Checksum_Init(NULL);

    memset(pdu, 0xAA, sizeof(pdu));
    Avtp_Checksum_Init((Avtp_Checksum_t *)pdu);
    assert_memory_equal(init_pdu, pdu, sizeof(init_pdu));
}

static void checksum_field_descriptors_cover_header(void **state)
{
    (void)state;
    uint8_t coverage[AVTP_CHECKSUM_HEADER_LEN * 8] = {0};

    for (uint8_t field = 0; field < AVTP_CHECKSUM_FIELD_MAX; field++) {
        const Avtp_FieldDescriptor_t *desc = &Avtp_ChecksumFieldDesc[field];

        assert_int_equal(desc->quadlet, 0);
        for (uint8_t bit = 0; bit < desc->bits; bit++) {
            size_t bit_index = desc->offset + bit;

            assert_true(bit_index < sizeof(coverage));
            assert_int_equal(coverage[bit_index], 0);
            coverage[bit_index] = 1;
        }
    }

    for (size_t bit = 0; bit < sizeof(coverage); bit++) {
        assert_int_equal(coverage[bit], 1);
    }
}

static void checksum_fields(void **state)
{
    (void)state;
    uint8_t pdu[AVTP_CHECKSUM_HEADER_LEN];
    Avtp_Checksum_t *checksum = (Avtp_Checksum_t *)pdu;

    Avtp_Checksum_Init(checksum);
    assert_int_equal(Avtp_AcfCommon_GetAcfMsgType((Avtp_AcfCommon_t *)checksum),
                     AVTP_ACF_TYPE_CHECKSUM);

    Avtp_Checksum_SetChecksum(checksum, 0xABCD);
    assert_int_equal(Avtp_Checksum_GetChecksum(checksum), 0xABCD);

    Avtp_SetField(Avtp_ChecksumFieldDesc, AVTP_CHECKSUM_FIELD_MAX, pdu,
                  AVTP_CHECKSUM_FIELD_ACF_MSG_LENGTH, 1);
    assert_int_equal(Avtp_GetField(Avtp_ChecksumFieldDesc, AVTP_CHECKSUM_FIELD_MAX, pdu,
                                   AVTP_CHECKSUM_FIELD_ACF_MSG_LENGTH),
                     1);
    assert_int_equal(Avtp_Checksum_GetChecksum(checksum), 0xABCD);
}

static void checksum_create_message(void **state)
{
    (void)state;
    uint8_t pdu[AVTP_CHECKSUM_HEADER_LEN];
    Avtp_Checksum_t *checksum = (Avtp_Checksum_t *)pdu;

    memset(pdu, 0xAA, sizeof(pdu));
    Avtp_Checksum_CreateAcfMessage(checksum, 0x1234);

    assert_int_equal(Avtp_AcfCommon_GetAcfMsgType((Avtp_AcfCommon_t *)checksum),
                     AVTP_ACF_TYPE_CHECKSUM);
    assert_int_equal(Avtp_AcfCommon_GetAcfMsgLength((Avtp_AcfCommon_t *)checksum), 1);
    assert_int_equal(Avtp_AcfCommon_GetAcfMsgLengthInBytes((Avtp_AcfCommon_t *)checksum),
                     AVTP_CHECKSUM_HEADER_LEN);
    assert_int_equal(Avtp_Checksum_GetChecksum(checksum), 0x1234);
    assert_true(Avtp_Checksum_IsValid(checksum, sizeof(pdu)));
}

static void checksum_is_valid(void **state)
{
    (void)state;
    uint8_t pdu[AVTP_CHECKSUM_HEADER_LEN];
    Avtp_Checksum_t *checksum = (Avtp_Checksum_t *)pdu;

    assert_false(Avtp_Checksum_IsValid(NULL, sizeof(pdu)));

    Avtp_Checksum_CreateAcfMessage(checksum, 0xFFFF);
    assert_true(Avtp_Checksum_IsValid(checksum, sizeof(pdu)));
    assert_false(Avtp_Checksum_IsValid(checksum, sizeof(pdu) - 1));
    assert_true(Avtp_Checksum_IsValid(checksum, sizeof(pdu) + 1));

    Avtp_AcfCommon_SetAcfMsgType((Avtp_AcfCommon_t *)checksum, AVTP_ACF_TYPE_CRC);
    assert_false(Avtp_Checksum_IsValid(checksum, sizeof(pdu)));

    Avtp_Checksum_CreateAcfMessage(checksum, 0xFFFF);
    Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)checksum, 0);
    assert_false(Avtp_Checksum_IsValid(checksum, sizeof(pdu)));

    Avtp_Checksum_CreateAcfMessage(checksum, 0xFFFF);
    Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)checksum, 2);
    assert_false(Avtp_Checksum_IsValid(checksum, sizeof(pdu)));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(checksum_init),
        cmocka_unit_test(checksum_field_descriptors_cover_header),
        cmocka_unit_test(checksum_fields),
        cmocka_unit_test(checksum_create_message),
        cmocka_unit_test(checksum_is_valid),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
