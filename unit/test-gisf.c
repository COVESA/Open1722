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

#ifdef __cplusplus
extern "C" {
#endif
    
#include "avtp/acf/Gisf.h"
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>

static void Test_Gisf_Init(void** state)
{
    const size_t buffer_len = AVTP_GISF_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {0};
    Avtp_Gisf_t* gisf = (Avtp_Gisf_t*)buffer;
    Avtp_Gisf_Init(gisf);

    uint8_t expected_buf[buffer_len] = {
        0x18, 0x05, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };

    // for (int i = 0; i < buffer_len; ++i) {
    //     printf("%x ", buffer[i]);
    // }
    // printf("\n");
    // for (int i = 0; i < buffer_len; ++i) {
    //     printf("%x ", expected_buf[i]);
    // }
    // printf("\n");

    assert_memory_equal(buffer, expected_buf, buffer_len);
}

static void Test_Gisf_GetPad(void** state)
{
    const size_t buffer_len = AVTP_GISF_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {
        0x18, 0x06, 0xC0, 0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
    };
    Avtp_Gisf_t* gisf = (Avtp_Gisf_t*)buffer;
    assert_int_equal(Avtp_Gisf_GetPad(gisf), 3);
}

static void Test_Gisf_IsMtv(void** state)
{
    const size_t buffer_len = AVTP_GISF_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {
        0x18, 0x05, 0x20, 0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
    };
    Avtp_Gisf_t* gisf = (Avtp_Gisf_t*)buffer;
    assert_int_equal(Avtp_Gisf_IsMtv(gisf), true);
}

static void Test_Gisf_GetImageSensorId(void** state)
{
    const size_t buffer_len = AVTP_GISF_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {
        0x18, 0x05, 0x5,  0xFF,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
    };
    Avtp_Gisf_t* gisf = (Avtp_Gisf_t*)buffer;
    assert_int_equal(Avtp_Gisf_GetImageSensorId(gisf), 0x5FF);
}

static void Test_Gisf_GetMessageTimestamp(void** state)
{
    const size_t buffer_len = AVTP_GISF_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {
        0x18, 0x05, 0x0,  0x0,
        0xBF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
    };
    Avtp_Gisf_t* gisf = (Avtp_Gisf_t*)buffer;
    assert_int_equal(Avtp_Gisf_GetMessageTimestamp(gisf), 0xBFFFFFFFFFFFFFFFull);
}

static void Test_Gisf_IsEl(void** state)
{
    const size_t buffer_len = AVTP_GISF_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {
        0x18, 0x05, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x40, 0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
    };
    Avtp_Gisf_t* gisf = (Avtp_Gisf_t*)buffer;
    assert_int_equal(Avtp_Gisf_IsEl(gisf), true);
}

static void Test_Gisf_IsTl(void** state)
{
    const size_t buffer_len = AVTP_GISF_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {
        0x18, 0x05, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x20, 0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
    };
    Avtp_Gisf_t* gisf = (Avtp_Gisf_t*)buffer;
    assert_int_equal(Avtp_Gisf_IsTl(gisf), true);
}

static void Test_Gisf_IsEf(void** state)
{
    const size_t buffer_len = AVTP_GISF_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {
        0x18, 0x05, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x10, 0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
    };
    Avtp_Gisf_t* gisf = (Avtp_Gisf_t*)buffer;
    assert_int_equal(Avtp_Gisf_IsEf(gisf), true);
}

static void Test_Gisf_GetEvt(void** state)
{
    const size_t buffer_len = AVTP_GISF_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {
        0x18, 0x05, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0xB,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
    };
    Avtp_Gisf_t* gisf = (Avtp_Gisf_t*)buffer;
    assert_int_equal(Avtp_Gisf_GetEvt(gisf), 0xB);
}

static void Test_Gisf_IsBf(void** state)
{
    const size_t buffer_len = AVTP_GISF_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {
        0x18, 0x05, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x20,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
    };
    Avtp_Gisf_t* gisf = (Avtp_Gisf_t*)buffer;
    assert_int_equal(Avtp_Gisf_IsBf(gisf), true);
}

static void Test_Gisf_GetLineTypeId(void** state)
{
    const size_t buffer_len = AVTP_GISF_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {
        0x18, 0x05, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x17,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
    };
    Avtp_Gisf_t* gisf = (Avtp_Gisf_t*)buffer;
    assert_int_equal(Avtp_Gisf_GetLineTypeId(gisf), 0x17);
}

static void Test_Gisf_GetEvt2(void** state)
{
    const size_t buffer_len = AVTP_GISF_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {
        0x18, 0x05, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0xBF, 0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
    };
    Avtp_Gisf_t* gisf = (Avtp_Gisf_t*)buffer;
    assert_int_equal(Avtp_Gisf_GetEvt2(gisf), 0xBF);
}

static void Test_Gisf_GetISeqNum(void** state)
{
    const size_t buffer_len = AVTP_GISF_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {
        0x18, 0x05, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0xBF, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
    };
    Avtp_Gisf_t* gisf = (Avtp_Gisf_t*)buffer;
    assert_int_equal(Avtp_Gisf_GetISeqNum(gisf), 0xBF);
}

static void Test_Gisf_GetLineNumber(void** state)
{
    const size_t buffer_len = AVTP_GISF_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {
        0x18, 0x05, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0xBF, 0xFF,
        0x0,  0x0,  0x0,  0x0,
    };
    Avtp_Gisf_t* gisf = (Avtp_Gisf_t*)buffer;
    assert_int_equal(Avtp_Gisf_GetLineNumber(gisf), 0xBFFFul);
}

static void Test_Gisf_GetPayloadLen(void** state)
{
    const size_t buffer_len = AVTP_GISF_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {
        0x18, 0x06, 0xC0, 0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0xBF, 0xFF,
        0x0,  0x0,  0x0,  0x0,
    };
    Avtp_Gisf_t* gisf = (Avtp_Gisf_t*)buffer;
    assert_int_equal(Avtp_Gisf_GetPayloadLen(gisf), 1);
}

static void Test_Gisf_GetPayloadLen_NoPadding(void** state)
{
    const size_t buffer_len = AVTP_GISF_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {
        0x18, 0x06, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0xBF, 0xFF,
        0x0,  0x0,  0x0,  0x0,
    };
    Avtp_Gisf_t* gisf = (Avtp_Gisf_t*)buffer;
    assert_int_equal(Avtp_Gisf_GetPayloadLen(gisf), 4);
}

static void Test_Gisf_GetLen(void** state)
{
    const size_t buffer_len = AVTP_GISF_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {
        0x18, 0x06, 0xC0, 0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0xBF, 0xFF,
        0x0,  0x0,  0x0,  0x0,
    };
    Avtp_Gisf_t* gisf = (Avtp_Gisf_t*)buffer;
    assert_int_equal(Avtp_Gisf_GetLen(gisf), 6 * 4);
}

static void Test_Gisf_SetMtv(void** state)
{
    const size_t buffer_len = AVTP_GISF_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {0};
    Avtp_Gisf_t* gisf = (Avtp_Gisf_t*)buffer;
    Avtp_Gisf_Init(gisf);
    Avtp_Gisf_SetMtv(gisf, true);

    uint8_t expected_buf[buffer_len] = {
        0x18, 0x05, 0x20, 0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(buffer, expected_buf, buffer_len);
}

static void Test_Gisf_SetImageSensorId(void** state)
{
    const size_t buffer_len = AVTP_GISF_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {0};
    Avtp_Gisf_t* gisf = (Avtp_Gisf_t*)buffer;
    Avtp_Gisf_Init(gisf);
    Avtp_Gisf_SetImageSensorId(gisf, 0x5FF);

    uint8_t expected_buf[buffer_len] = {
        0x18, 0x05, 0x5,  0xFF,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(buffer, expected_buf, buffer_len);
}

static void Test_Gisf_SetMessageTimestamp(void** state)
{
    const size_t buffer_len = AVTP_GISF_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {0};
    Avtp_Gisf_t* gisf = (Avtp_Gisf_t*)buffer;
    Avtp_Gisf_Init(gisf);
    Avtp_Gisf_SetMessageTimestamp(gisf, 0xBFFFFFFFull);

    uint8_t expected_buf[buffer_len] = {
        0x18, 0x05, 0x0,  0x0,
        0xBF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };

    for (int i = 0; i < buffer_len; ++i) {
        printf("%x ", buffer[i]);
    }
    printf("\n");
    for (int i = 0; i < buffer_len; ++i) {
        printf("%x ", expected_buf[i]);
    }
    printf("\n");

    assert_memory_equal(buffer, expected_buf, buffer_len);
}

static void Test_Gisf_SetEl(void** state)
{
    const size_t buffer_len = AVTP_GISF_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {0};
    Avtp_Gisf_t* gisf = (Avtp_Gisf_t*)buffer;
    Avtp_Gisf_Init(gisf);
    Avtp_Gisf_SetEl(gisf, true);

    uint8_t expected_buf[buffer_len] = {
        0x18, 0x05, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x40,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(buffer, expected_buf, buffer_len);
}

static void Test_Gisf_SetTl(void** state)
{
    const size_t buffer_len = AVTP_GISF_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {0};
    Avtp_Gisf_t* gisf = (Avtp_Gisf_t*)buffer;
    Avtp_Gisf_Init(gisf);
    Avtp_Gisf_SetTl(gisf, true);

    uint8_t expected_buf[buffer_len] = {
        0x18, 0x05, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x20,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(buffer, expected_buf, buffer_len);
}

static void Test_Gisf_SetEf(void** state)
{
    const size_t buffer_len = AVTP_GISF_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {0};
    Avtp_Gisf_t* gisf = (Avtp_Gisf_t*)buffer;
    Avtp_Gisf_Init(gisf);
    Avtp_Gisf_SetEf(gisf, true);

    uint8_t expected_buf[buffer_len] = {
        0x18, 0x05, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x10,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(buffer, expected_buf, buffer_len);
}

static void Test_Gisf_SetEvt(void** state)
{
    const size_t buffer_len = AVTP_GISF_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {0};
    Avtp_Gisf_t* gisf = (Avtp_Gisf_t*)buffer;
    Avtp_Gisf_Init(gisf);
    Avtp_Gisf_SetEvt(gisf, 0xB);

    uint8_t expected_buf[buffer_len] = {
        0x18, 0x05, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0xB,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(buffer, expected_buf, buffer_len);
}

static void Test_Gisf_SetBf(void** state)
{
    const size_t buffer_len = AVTP_GISF_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {0};
    Avtp_Gisf_t* gisf = (Avtp_Gisf_t*)buffer;
    Avtp_Gisf_Init(gisf);
    Avtp_Gisf_SetBf(gisf, true);

    uint8_t expected_buf[buffer_len] = {
        0x18, 0x05, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x20,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(buffer, expected_buf, buffer_len);
}

static void Test_Gisf_SetLineTypeId(void** state)
{
    const size_t buffer_len = AVTP_GISF_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {0};
    Avtp_Gisf_t* gisf = (Avtp_Gisf_t*)buffer;
    Avtp_Gisf_Init(gisf);
    Avtp_Gisf_SetLineTypeId(gisf, 0x17);

    uint8_t expected_buf[buffer_len] = {
        0x18, 0x05, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x17,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(buffer, expected_buf, buffer_len);
}

static void Test_Gisf_SetEvt2(void** state)
{
    const size_t buffer_len = AVTP_GISF_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {0};
    Avtp_Gisf_t* gisf = (Avtp_Gisf_t*)buffer;
    Avtp_Gisf_Init(gisf);
    Avtp_Gisf_SetEvt2(gisf, 0xBF);

    uint8_t expected_buf[buffer_len] = {
        0x18, 0x05, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0xBF, 0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(buffer, expected_buf, buffer_len);
}

static void Test_Gisf_SetISeqNum(void** state)
{
    const size_t buffer_len = AVTP_GISF_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {0};
    Avtp_Gisf_t* gisf = (Avtp_Gisf_t*)buffer;
    Avtp_Gisf_Init(gisf);
    Avtp_Gisf_SetISeqNum(gisf, 0xBF);

    uint8_t expected_buf[buffer_len] = {
        0x18, 0x05, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0xBF, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(buffer, expected_buf, buffer_len);
}

static void Test_Gisf_SetLineNumber(void** state)
{
    const size_t buffer_len = AVTP_GISF_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {0};
    Avtp_Gisf_t* gisf = (Avtp_Gisf_t*)buffer;
    Avtp_Gisf_Init(gisf);
    Avtp_Gisf_SetLineNumber(gisf, 0xBFFF);

    uint8_t expected_buf[buffer_len] = {
        0x18, 0x05, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0xBF, 0xFF,
        0x0,  0x0,  0x0,  0x0
    };
    assert_memory_equal(buffer, expected_buf, buffer_len);
}

static void Test_Gisf_SetPayloadLen(void** state)
{
    const size_t buffer_len = AVTP_GISF_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {0};
    Avtp_Gisf_t* gisf = (Avtp_Gisf_t*)buffer;
    Avtp_Gisf_Init(gisf);
    Avtp_Gisf_SetPayloadLen(gisf, 3);

    uint8_t expected_buf[buffer_len] = {
        0x18, 0x06, 0x40, 0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
    };
    assert_memory_equal(buffer, expected_buf, buffer_len);
}

static void Test_Gisf_SetPayloadLen_NoPadding(void** state)
{
    const size_t buffer_len = AVTP_GISF_HEADER_LEN + 4;
    uint8_t buffer[buffer_len] = {0};
    Avtp_Gisf_t* gisf = (Avtp_Gisf_t*)buffer;
    Avtp_Gisf_Init(gisf);
    Avtp_Gisf_SetPayloadLen(gisf, 4);

    uint8_t expected_buf[buffer_len] = {
        0x18, 0x06, 0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,
    };
    assert_memory_equal(buffer, expected_buf, buffer_len);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(Test_Gisf_Init),
        cmocka_unit_test(Test_Gisf_GetPad),
        cmocka_unit_test(Test_Gisf_IsMtv),
        cmocka_unit_test(Test_Gisf_GetImageSensorId),
        cmocka_unit_test(Test_Gisf_GetMessageTimestamp),
        cmocka_unit_test(Test_Gisf_IsEl),
        cmocka_unit_test(Test_Gisf_IsTl),
        cmocka_unit_test(Test_Gisf_IsEf),
        cmocka_unit_test(Test_Gisf_GetEvt),
        cmocka_unit_test(Test_Gisf_IsBf),
        cmocka_unit_test(Test_Gisf_GetLineTypeId),
        cmocka_unit_test(Test_Gisf_GetEvt2),
        cmocka_unit_test(Test_Gisf_GetISeqNum),
        cmocka_unit_test(Test_Gisf_GetPayloadLen),
        cmocka_unit_test(Test_Gisf_GetPayloadLen_NoPadding),
        cmocka_unit_test(Test_Gisf_GetLen),
        cmocka_unit_test(Test_Gisf_SetMtv),
        cmocka_unit_test(Test_Gisf_SetImageSensorId),
        cmocka_unit_test(Test_Gisf_SetMessageTimestamp),
        cmocka_unit_test(Test_Gisf_SetEl),
        cmocka_unit_test(Test_Gisf_SetTl),
        cmocka_unit_test(Test_Gisf_SetEf),
        cmocka_unit_test(Test_Gisf_SetEvt),
        cmocka_unit_test(Test_Gisf_SetBf),
        cmocka_unit_test(Test_Gisf_SetLineTypeId),
        cmocka_unit_test(Test_Gisf_SetEvt2),
        cmocka_unit_test(Test_Gisf_SetISeqNum),
        cmocka_unit_test(Test_Gisf_SetLineNumber),
        cmocka_unit_test(Test_Gisf_SetPayloadLen),
        cmocka_unit_test(Test_Gisf_SetPayloadLen_NoPadding),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

#ifdef __cplusplus
}
#endif
