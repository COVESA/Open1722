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

#include "avtp/Udp.h"

#define MAX_PDU_SIZE 1500

static void udp_init(void **state) {
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t init_pdu[AVTP_UDP_HEADER_LEN];

    Avtp_Udp_Init(NULL);

    Avtp_Udp_Init((Avtp_Udp_t*)pdu);
    memset(init_pdu, 0, AVTP_UDP_HEADER_LEN);
    assert_memory_equal(init_pdu, pdu, AVTP_UDP_HEADER_LEN);
}

static void udp_get_set_fields(void **state) {
    uint8_t pdu[MAX_PDU_SIZE];
    
    Avtp_Udp_Init((Avtp_Udp_t*)pdu);

    Avtp_Udp_SetEncapsulationSeqNo((Avtp_Udp_t*)pdu, 0x12345678);
    assert_int_equal(Avtp_Udp_GetEncapsulationSeqNo((Avtp_Udp_t*)pdu), 0x12345678);

    Avtp_Udp_SetEncapsulationSeqNo((Avtp_Udp_t*)pdu, 0xABCDEF00);
    assert_int_equal(Avtp_Udp_GetEncapsulationSeqNo((Avtp_Udp_t*)pdu), 0xABCDEF00);

    Avtp_Udp_SetEncapsulationSeqNo((Avtp_Udp_t*)pdu, 0);
    assert_int_equal(Avtp_Udp_GetEncapsulationSeqNo((Avtp_Udp_t*)pdu), 0);

    Avtp_Udp_SetEncapsulationSeqNo((Avtp_Udp_t*)pdu, 0xFFFFFFFF);
    assert_int_equal(Avtp_Udp_GetEncapsulationSeqNo((Avtp_Udp_t*)pdu), 0xFFFFFFFF);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(udp_init),
        cmocka_unit_test(udp_get_set_fields),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
