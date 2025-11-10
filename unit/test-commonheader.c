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
#include <string.h>

#include "avtp/CommonHeader.h"

#define MAX_PDU_SIZE 1500

static void common_header_get_set_fields(void **state) {
    uint8_t pdu[MAX_PDU_SIZE];
    
    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_CommonHeader_SetSubtype((Avtp_CommonHeader_t*)pdu, AVTP_SUBTYPE_AAF);
    assert_int_equal(Avtp_CommonHeader_GetSubtype((Avtp_CommonHeader_t*)pdu), AVTP_SUBTYPE_AAF);

    Avtp_CommonHeader_SetSubtype((Avtp_CommonHeader_t*)pdu, AVTP_SUBTYPE_CVF);
    assert_int_equal(Avtp_CommonHeader_GetSubtype((Avtp_CommonHeader_t*)pdu), AVTP_SUBTYPE_CVF);

    Avtp_CommonHeader_SetSubtype((Avtp_CommonHeader_t*)pdu, AVTP_SUBTYPE_TSCF);
    assert_int_equal(Avtp_CommonHeader_GetSubtype((Avtp_CommonHeader_t*)pdu), AVTP_SUBTYPE_TSCF);

    Avtp_CommonHeader_SetSubtype((Avtp_CommonHeader_t*)pdu, AVTP_SUBTYPE_NTSCF);
    assert_int_equal(Avtp_CommonHeader_GetSubtype((Avtp_CommonHeader_t*)pdu), AVTP_SUBTYPE_NTSCF);

    Avtp_CommonHeader_SetH((Avtp_CommonHeader_t*)pdu, 1);
    assert_int_equal(Avtp_CommonHeader_GetH((Avtp_CommonHeader_t*)pdu), 1);

    Avtp_CommonHeader_SetH((Avtp_CommonHeader_t*)pdu, 0);
    assert_int_equal(Avtp_CommonHeader_GetH((Avtp_CommonHeader_t*)pdu), 0);

    Avtp_CommonHeader_SetVersion((Avtp_CommonHeader_t*)pdu, 0);
    assert_int_equal(Avtp_CommonHeader_GetVersion((Avtp_CommonHeader_t*)pdu), 0);

    Avtp_CommonHeader_SetVersion((Avtp_CommonHeader_t*)pdu, 3);
    assert_int_equal(Avtp_CommonHeader_GetVersion((Avtp_CommonHeader_t*)pdu), 3);
}

static void common_header_subtypes(void **state) {
    assert_int_equal(AVTP_SUBTYPE_AAF, 0x2);
    assert_int_equal(AVTP_SUBTYPE_CVF, 0x3);
    assert_int_equal(AVTP_SUBTYPE_CRF, 0x4);
    assert_int_equal(AVTP_SUBTYPE_TSCF, 0x5);
    assert_int_equal(AVTP_SUBTYPE_RVF, 0x7);
    assert_int_equal(AVTP_SUBTYPE_NTSCF, 0x82);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(common_header_get_set_fields),
        cmocka_unit_test(common_header_subtypes),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
