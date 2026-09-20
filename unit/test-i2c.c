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

#include "avtp/acf/I2C.h"
#include "avtp/acf/I2CBrief.h"

#define MAX_PDU_SIZE 1500

static void i2c_init(void **state)
{
    uint8_t pdu[MAX_PDU_SIZE];

    Avtp_I2C_Init(NULL);
    memset(pdu, 0xAA, sizeof(pdu));
    Avtp_I2C_Init((Avtp_I2C_t *)pdu);

    assert_int_equal(Avtp_AcfCommon_GetAcfMsgType((Avtp_AcfCommon_t *)pdu), AVTP_ACF_TYPE_I2C);
    assert_int_equal(Avtp_I2C_GetPad((Avtp_I2C_t *)pdu), 0);
    assert_int_equal(Avtp_I2C_IsMtv((Avtp_I2C_t *)pdu), 0);
    assert_int_equal(Avtp_I2C_GetI2CBusId((Avtp_I2C_t *)pdu), 0);
    assert_int_equal(Avtp_I2C_GetMessageTimestamp((Avtp_I2C_t *)pdu), 0);
    assert_int_equal(Avtp_I2C_GetI2CCode((Avtp_I2C_t *)pdu), 0);
    assert_int_equal(Avtp_I2C_IsTrr((Avtp_I2C_t *)pdu), 0);
    assert_int_equal(Avtp_I2C_GetTransactionNum((Avtp_I2C_t *)pdu), 0);
    assert_int_equal(Avtp_I2C_GetEvt((Avtp_I2C_t *)pdu), 0);
    assert_int_equal(Avtp_I2C_GetExceptionCode((Avtp_I2C_t *)pdu), 0);
    assert_int_equal(Avtp_I2C_GetI2CData((Avtp_I2C_t *)pdu), 0);
}

static void i2c_get_set_fields(void **state)
{
    uint8_t pdu[MAX_PDU_SIZE];

    Avtp_I2C_Init((Avtp_I2C_t *)pdu);
    Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)pdu, AVTP_I2C_HEADER_LEN / 4);

    Avtp_I2C_SetPad((Avtp_I2C_t *)pdu, 3);
    Avtp_I2C_SetMtv((Avtp_I2C_t *)pdu, true);
    Avtp_I2C_SetI2CBusId((Avtp_I2C_t *)pdu, 0x456);
    Avtp_I2C_SetMessageTimestamp((Avtp_I2C_t *)pdu, 0x123456789ABCDEF0ULL);
    Avtp_I2C_SetI2CCode((Avtp_I2C_t *)pdu, 0xA);
    Avtp_I2C_SetTrr((Avtp_I2C_t *)pdu, true);
    Avtp_I2C_SetTransactionNum((Avtp_I2C_t *)pdu, 0x12);
    Avtp_I2C_SetEvt((Avtp_I2C_t *)pdu, 0xB);
    Avtp_I2C_SetExceptionCode((Avtp_I2C_t *)pdu, 0xC);
    Avtp_I2C_SetI2CData((Avtp_I2C_t *)pdu, 0xD);

    assert_int_equal(Avtp_I2C_GetPad((Avtp_I2C_t *)pdu), 3);
    assert_int_equal(Avtp_I2C_IsMtv((Avtp_I2C_t *)pdu), 1);
    assert_int_equal(Avtp_I2C_GetI2CBusId((Avtp_I2C_t *)pdu), 0x456);
    assert_int_equal(Avtp_I2C_GetMessageTimestamp((Avtp_I2C_t *)pdu), 0x123456789ABCDEF0ULL);
    assert_int_equal(Avtp_I2C_GetI2CCode((Avtp_I2C_t *)pdu), 0xA);
    assert_int_equal(Avtp_I2C_IsTrr((Avtp_I2C_t *)pdu), 1);
    assert_int_equal(Avtp_I2C_GetTransactionNum((Avtp_I2C_t *)pdu), 0x12);
    assert_int_equal(Avtp_I2C_GetEvt((Avtp_I2C_t *)pdu), 0xB);
    assert_int_equal(Avtp_I2C_GetExceptionCode((Avtp_I2C_t *)pdu), 0xC);
    assert_int_equal(Avtp_I2C_GetI2CData((Avtp_I2C_t *)pdu), 0xD);
    assert_int_equal(Avtp_I2C_IsValid((Avtp_I2C_t *)pdu, AVTP_I2C_HEADER_LEN + 1), 1);
    assert_int_equal(Avtp_I2C_IsValid((Avtp_I2C_t *)pdu, AVTP_I2C_HEADER_LEN - 1), 0);
    assert_int_equal(Avtp_I2C_IsValid((Avtp_I2C_t *)pdu, AVTP_I2C_HEADER_LEN), 1);
}

static void i2c_wire_format(void **state)
{
    uint8_t pdu[MAX_PDU_SIZE];
    // Expected header bytes for msg_type=I2C(0x0F), msg_length=4 quadlets, pad=3,
    // mtv=1, i2c_bus_id=0x456, timestamp=0x123456789ABCDEF0, i2c_code=0xA, trr=1,
    // transaction_num=0x12, evt=0xB, exception_code=0xC, i2c_data=0xD.
    uint8_t expected[AVTP_I2C_HEADER_LEN] = {
        0x1E, 0x04, 0xE4, 0x56, 0x12, 0x34, 0x56, 0x78,
        0x9A, 0xBC, 0xDE, 0xF0, 0xA8, 0x12, 0xBC, 0x0D,
    };

    Avtp_I2C_Init((Avtp_I2C_t *)pdu);
    Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)pdu, AVTP_I2C_HEADER_LEN / 4);
    Avtp_I2C_SetPad((Avtp_I2C_t *)pdu, 3);
    Avtp_I2C_SetMtv((Avtp_I2C_t *)pdu, true);
    Avtp_I2C_SetI2CBusId((Avtp_I2C_t *)pdu, 0x456);
    Avtp_I2C_SetMessageTimestamp((Avtp_I2C_t *)pdu, 0x123456789ABCDEF0ULL);
    Avtp_I2C_SetI2CCode((Avtp_I2C_t *)pdu, 0xA);
    Avtp_I2C_SetTrr((Avtp_I2C_t *)pdu, true);
    Avtp_I2C_SetTransactionNum((Avtp_I2C_t *)pdu, 0x12);
    Avtp_I2C_SetEvt((Avtp_I2C_t *)pdu, 0xB);
    Avtp_I2C_SetExceptionCode((Avtp_I2C_t *)pdu, 0xC);
    Avtp_I2C_SetI2CData((Avtp_I2C_t *)pdu, 0xD);

    assert_memory_equal(expected, pdu, AVTP_I2C_HEADER_LEN);
}

static void i2c_is_valid(void **state)
{
    uint8_t pdu[MAX_PDU_SIZE];

    // Negative: NULL pdu.
    assert_int_equal(Avtp_I2C_IsValid(NULL, MAX_PDU_SIZE), 0);

    // Negative: buffer smaller than the fixed header size.
    Avtp_I2C_CreateAcfMessage((Avtp_I2C_t *)pdu, 0xA, true, 0x12, 0xB, 0xC, 0xD);
    assert_int_equal(Avtp_I2C_IsValid((Avtp_I2C_t *)pdu, AVTP_I2C_HEADER_LEN - 1), 0);

    // Negative: AcfMsgLength does not match the fixed I2C header length.
    Avtp_I2C_CreateAcfMessage((Avtp_I2C_t *)pdu, 0xA, true, 0x12, 0xB, 0xC, 0xD);
    Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)pdu, AVTP_I2C_HEADER_LEN / 4 + 1);
    assert_int_equal(Avtp_I2C_IsValid((Avtp_I2C_t *)pdu, MAX_PDU_SIZE), 0);

    // Negative: AcfMsgType is not ACF_TYPE_I2C.
    Avtp_I2C_CreateAcfMessage((Avtp_I2C_t *)pdu, 0xA, true, 0x12, 0xB, 0xC, 0xD);
    Avtp_AcfCommon_SetAcfMsgType((Avtp_AcfCommon_t *)pdu, AVTP_ACF_TYPE_I2C_BRIEF);
    assert_int_equal(Avtp_I2C_IsValid((Avtp_I2C_t *)pdu, MAX_PDU_SIZE), 0);

    // Positive: properly formed ACF_I2C frame with buffer exactly matching the
    // header length, and again with extra buffer space.
    Avtp_I2C_CreateAcfMessage((Avtp_I2C_t *)pdu, 0xA, true, 0x12, 0xB, 0xC, 0xD);
    assert_int_equal(Avtp_I2C_IsValid((Avtp_I2C_t *)pdu, AVTP_I2C_HEADER_LEN), 1);
    assert_int_equal(Avtp_I2C_IsValid((Avtp_I2C_t *)pdu, AVTP_I2C_HEADER_LEN + 1), 1);
}

static void i2c_create_message(void **state)
{
    uint8_t pdu[MAX_PDU_SIZE];

    Avtp_I2C_CreateAcfMessage((Avtp_I2C_t *)pdu, 0xA, true, 0x12, 0xB, 0xC, 0xD);

    assert_int_equal(Avtp_AcfCommon_GetAcfMsgType((Avtp_AcfCommon_t *)pdu), AVTP_ACF_TYPE_I2C);
    assert_int_equal(Avtp_I2C_GetI2CCode((Avtp_I2C_t *)pdu), 0xA);
    assert_int_equal(Avtp_I2C_IsTrr((Avtp_I2C_t *)pdu), 1);
    assert_int_equal(Avtp_I2C_GetTransactionNum((Avtp_I2C_t *)pdu), 0x12);
    assert_int_equal(Avtp_I2C_GetEvt((Avtp_I2C_t *)pdu), 0xB);
    assert_int_equal(Avtp_I2C_GetExceptionCode((Avtp_I2C_t *)pdu), 0xC);
    assert_int_equal(Avtp_I2C_GetI2CData((Avtp_I2C_t *)pdu), 0xD);
}

static void i2c_brief_init(void **state)
{
    uint8_t pdu[MAX_PDU_SIZE];

    Avtp_I2CBrief_Init(NULL);
    memset(pdu, 0xAA, sizeof(pdu));
    Avtp_I2CBrief_Init((Avtp_I2CBrief_t *)pdu);

    assert_int_equal(Avtp_AcfCommon_GetAcfMsgType((Avtp_AcfCommon_t *)pdu),
                     AVTP_ACF_TYPE_I2C_BRIEF);
    assert_int_equal(Avtp_I2CBrief_GetPad((Avtp_I2CBrief_t *)pdu), 0);
    assert_int_equal(Avtp_I2CBrief_IsMtv((Avtp_I2CBrief_t *)pdu), 0);
    assert_int_equal(Avtp_I2CBrief_GetI2CBusId((Avtp_I2CBrief_t *)pdu), 0);
    assert_int_equal(Avtp_I2CBrief_GetI2CCode((Avtp_I2CBrief_t *)pdu), 0);
    assert_int_equal(Avtp_I2CBrief_IsTrr((Avtp_I2CBrief_t *)pdu), 0);
    assert_int_equal(Avtp_I2CBrief_GetTransactionNum((Avtp_I2CBrief_t *)pdu), 0);
    assert_int_equal(Avtp_I2CBrief_GetEvt((Avtp_I2CBrief_t *)pdu), 0);
    assert_int_equal(Avtp_I2CBrief_GetExceptionCode((Avtp_I2CBrief_t *)pdu), 0);
    assert_int_equal(Avtp_I2CBrief_GetI2CData((Avtp_I2CBrief_t *)pdu), 0);
}

static void i2c_brief_get_set_fields(void **state)
{
    uint8_t pdu[MAX_PDU_SIZE];

    Avtp_I2CBrief_Init((Avtp_I2CBrief_t *)pdu);
    Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)pdu, AVTP_I2C_BRIEF_HEADER_LEN / 4);

    Avtp_I2CBrief_SetPad((Avtp_I2CBrief_t *)pdu, 3);
    Avtp_I2CBrief_SetMtv((Avtp_I2CBrief_t *)pdu, true);
    Avtp_I2CBrief_SetI2CBusId((Avtp_I2CBrief_t *)pdu, 0x456);
    Avtp_I2CBrief_SetI2CCode((Avtp_I2CBrief_t *)pdu, 0xA);
    Avtp_I2CBrief_SetTrr((Avtp_I2CBrief_t *)pdu, true);
    Avtp_I2CBrief_SetTransactionNum((Avtp_I2CBrief_t *)pdu, 0x12);
    Avtp_I2CBrief_SetEvt((Avtp_I2CBrief_t *)pdu, 0xB);
    Avtp_I2CBrief_SetExceptionCode((Avtp_I2CBrief_t *)pdu, 0xC);
    Avtp_I2CBrief_SetI2CData((Avtp_I2CBrief_t *)pdu, 0xD);

    assert_int_equal(Avtp_I2CBrief_GetPad((Avtp_I2CBrief_t *)pdu), 3);
    assert_int_equal(Avtp_I2CBrief_IsMtv((Avtp_I2CBrief_t *)pdu), 1);
    assert_int_equal(Avtp_I2CBrief_GetI2CBusId((Avtp_I2CBrief_t *)pdu), 0x456);
    assert_int_equal(Avtp_I2CBrief_GetI2CCode((Avtp_I2CBrief_t *)pdu), 0xA);
    assert_int_equal(Avtp_I2CBrief_IsTrr((Avtp_I2CBrief_t *)pdu), 1);
    assert_int_equal(Avtp_I2CBrief_GetTransactionNum((Avtp_I2CBrief_t *)pdu), 0x12);
    assert_int_equal(Avtp_I2CBrief_GetEvt((Avtp_I2CBrief_t *)pdu), 0xB);
    assert_int_equal(Avtp_I2CBrief_GetExceptionCode((Avtp_I2CBrief_t *)pdu), 0xC);
    assert_int_equal(Avtp_I2CBrief_GetI2CData((Avtp_I2CBrief_t *)pdu), 0xD);
    assert_int_equal(Avtp_I2CBrief_IsValid((Avtp_I2CBrief_t *)pdu, AVTP_I2C_BRIEF_HEADER_LEN), 1);
}

static void i2c_brief_create_message(void **state)
{
    uint8_t pdu[MAX_PDU_SIZE];

    Avtp_I2CBrief_CreateAcfMessage((Avtp_I2CBrief_t *)pdu, 0xA, true, 0x12, 0xB, 0xC, 0xD);

    assert_int_equal(Avtp_AcfCommon_GetAcfMsgType((Avtp_AcfCommon_t *)pdu),
                     AVTP_ACF_TYPE_I2C_BRIEF);
    assert_int_equal(Avtp_I2CBrief_GetI2CCode((Avtp_I2CBrief_t *)pdu), 0xA);
    assert_int_equal(Avtp_I2CBrief_IsTrr((Avtp_I2CBrief_t *)pdu), 1);
    assert_int_equal(Avtp_I2CBrief_GetTransactionNum((Avtp_I2CBrief_t *)pdu), 0x12);
    assert_int_equal(Avtp_I2CBrief_GetEvt((Avtp_I2CBrief_t *)pdu), 0xB);
    assert_int_equal(Avtp_I2CBrief_GetExceptionCode((Avtp_I2CBrief_t *)pdu), 0xC);
    assert_int_equal(Avtp_I2CBrief_GetI2CData((Avtp_I2CBrief_t *)pdu), 0xD);
    assert_int_equal(Avtp_I2CBrief_IsValid((Avtp_I2CBrief_t *)pdu, AVTP_I2C_BRIEF_HEADER_LEN + 1),
                     1);
    assert_int_equal(Avtp_I2CBrief_IsValid((Avtp_I2CBrief_t *)pdu, AVTP_I2C_BRIEF_HEADER_LEN - 1),
                     0);
}

static void i2c_brief_wire_format(void **state)
{
    uint8_t pdu[MAX_PDU_SIZE];
    // Expected header bytes for msg_type=I2C_BRIEF(0x10), msg_length=2 quadlets,
    // pad=3, mtv=1, i2c_bus_id=0x456, i2c_code=0xA, trr=1, transaction_num=0x12,
    // evt=0xB, exception_code=0xC, i2c_data=0xD.
    uint8_t expected[AVTP_I2C_BRIEF_HEADER_LEN] = {
        0x20, 0x02, 0xE4, 0x56, 0xA8, 0x12, 0xBC, 0x0D,
    };

    Avtp_I2CBrief_Init((Avtp_I2CBrief_t *)pdu);
    Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)pdu, AVTP_I2C_BRIEF_HEADER_LEN / 4);
    Avtp_I2CBrief_SetPad((Avtp_I2CBrief_t *)pdu, 3);
    Avtp_I2CBrief_SetMtv((Avtp_I2CBrief_t *)pdu, true);
    Avtp_I2CBrief_SetI2CBusId((Avtp_I2CBrief_t *)pdu, 0x456);
    Avtp_I2CBrief_SetI2CCode((Avtp_I2CBrief_t *)pdu, 0xA);
    Avtp_I2CBrief_SetTrr((Avtp_I2CBrief_t *)pdu, true);
    Avtp_I2CBrief_SetTransactionNum((Avtp_I2CBrief_t *)pdu, 0x12);
    Avtp_I2CBrief_SetEvt((Avtp_I2CBrief_t *)pdu, 0xB);
    Avtp_I2CBrief_SetExceptionCode((Avtp_I2CBrief_t *)pdu, 0xC);
    Avtp_I2CBrief_SetI2CData((Avtp_I2CBrief_t *)pdu, 0xD);

    assert_memory_equal(expected, pdu, AVTP_I2C_BRIEF_HEADER_LEN);
}

static void i2c_brief_is_valid(void **state)
{
    uint8_t pdu[MAX_PDU_SIZE];

    // Negative: NULL pdu.
    assert_int_equal(Avtp_I2CBrief_IsValid(NULL, MAX_PDU_SIZE), 0);

    // Negative: buffer smaller than the fixed header size.
    Avtp_I2CBrief_CreateAcfMessage((Avtp_I2CBrief_t *)pdu, 0xA, true, 0x12, 0xB, 0xC, 0xD);
    assert_int_equal(Avtp_I2CBrief_IsValid((Avtp_I2CBrief_t *)pdu, AVTP_I2C_BRIEF_HEADER_LEN - 1),
                     0);

    // Negative: AcfMsgLength does not match the fixed I2C_BRIEF header length.
    Avtp_I2CBrief_CreateAcfMessage((Avtp_I2CBrief_t *)pdu, 0xA, true, 0x12, 0xB, 0xC, 0xD);
    Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)pdu, AVTP_I2C_BRIEF_HEADER_LEN / 4 + 1);
    assert_int_equal(Avtp_I2CBrief_IsValid((Avtp_I2CBrief_t *)pdu, MAX_PDU_SIZE), 0);

    // Negative: AcfMsgType is not ACF_TYPE_I2C_BRIEF.
    Avtp_I2CBrief_CreateAcfMessage((Avtp_I2CBrief_t *)pdu, 0xA, true, 0x12, 0xB, 0xC, 0xD);
    Avtp_AcfCommon_SetAcfMsgType((Avtp_AcfCommon_t *)pdu, AVTP_ACF_TYPE_I2C);
    assert_int_equal(Avtp_I2CBrief_IsValid((Avtp_I2CBrief_t *)pdu, MAX_PDU_SIZE), 0);

    // Positive: properly formed ACF_I2C_BRIEF frame with buffer exactly matching
    // the header length, and again with extra buffer space.
    Avtp_I2CBrief_CreateAcfMessage((Avtp_I2CBrief_t *)pdu, 0xA, true, 0x12, 0xB, 0xC, 0xD);
    assert_int_equal(Avtp_I2CBrief_IsValid((Avtp_I2CBrief_t *)pdu, AVTP_I2C_BRIEF_HEADER_LEN), 1);
    assert_int_equal(Avtp_I2CBrief_IsValid((Avtp_I2CBrief_t *)pdu, AVTP_I2C_BRIEF_HEADER_LEN + 1),
                     1);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(i2c_init),
        cmocka_unit_test(i2c_get_set_fields),
        cmocka_unit_test(i2c_wire_format),
        cmocka_unit_test(i2c_is_valid),
        cmocka_unit_test(i2c_create_message),
        cmocka_unit_test(i2c_brief_init),
        cmocka_unit_test(i2c_brief_get_set_fields),
        cmocka_unit_test(i2c_brief_wire_format),
        cmocka_unit_test(i2c_brief_is_valid),
        cmocka_unit_test(i2c_brief_create_message),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
