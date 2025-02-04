/*
 * Copyright (c) 2025, COVESA
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
#include <errno.h>
#include <string.h>
#include <math.h>
#include <stdio.h>

#include "avtp/acf/Tscf.h"
#include "avtp/CommonHeader.h"

#define MAX_PDU_SIZE        1500

static void tscf_init(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t init_pdu[AVTP_TSCF_HEADER_LEN];

    // Check the lengths
    assert_int_equal(sizeof(Avtp_Tscf_t), AVTP_TSCF_HEADER_LEN);

    // Check init function while passing in a null pointer
    Avtp_Tscf_Init(NULL);

    // Check if the function is initializing properly
    Avtp_Tscf_Init((Avtp_Tscf_t*)pdu);
    memset(init_pdu, 0, AVTP_TSCF_HEADER_LEN);
    init_pdu[0] = AVTP_SUBTYPE_TSCF; // Setting AVTP Subtype as TSCF
    init_pdu[1] = 0x80; // Setting Stream as valid
    assert_memory_equal(init_pdu, pdu, AVTP_TSCF_HEADER_LEN);
}

static void tscf_is_valid(void **state) {

    uint8_t pdu[MAX_PDU_SIZE], result;

    // Valid IEEE 1722 TSCF Frame
    Avtp_Tscf_Init((Avtp_Tscf_t*)pdu);
    assert_int_equal(Avtp_Tscf_IsValid((Avtp_Tscf_t*)pdu, MAX_PDU_SIZE), 1);

    // Not a IEEE 1722 TSCF Frame
    memset(pdu, 0, MAX_PDU_SIZE);
    assert_int_equal(Avtp_Tscf_IsValid((Avtp_Tscf_t*)pdu, MAX_PDU_SIZE), 0);

    // Valid IEEE 1722 TSCF Frame (Length 28, Buffer 30)
    Avtp_Tscf_Init((Avtp_Tscf_t*)pdu);
    Avtp_Tscf_SetStreamDataLength((Avtp_Tscf_t*)pdu, 28);
    assert_int_equal(Avtp_Tscf_IsValid((Avtp_Tscf_t*)pdu, 30), 1);

    // Invalid IEEE 1722 TSCF Frame (Length 24 but buffer only 9!)
    Avtp_Tscf_Init((Avtp_Tscf_t*)pdu);
    Avtp_Tscf_SetStreamDataLength((Avtp_Tscf_t*)pdu, 24);
    assert_int_equal(Avtp_Tscf_IsValid((Avtp_Tscf_t*)pdu, 9), 0);

}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(tscf_init),
        cmocka_unit_test(tscf_is_valid),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}