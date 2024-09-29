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
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <math.h>
#include <stdio.h>

#include "avtp/acf/custom/Vss.h"
#include "avtp/acf/AcfCommon.h"

#define MAX_PDU_SIZE        1500

static void vss_init(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t init_pdu[AVTP_VSS_FIXED_HEADER_LEN];

    // Check if the function is initializing properly
    Avtp_Vss_Init((Avtp_Vss_t*)pdu);
    memset(init_pdu, 0, AVTP_VSS_FIXED_HEADER_LEN);
    init_pdu[0] = 0x42 << 1; // Setting ACF type as ACF_VSS
    assert_memory_equal(init_pdu, pdu, AVTP_VSS_FIXED_HEADER_LEN);

    Avtp_AcfMsgType_t type = Avtp_AcfCommon_GetAcfMsgType((Avtp_AcfCommon_t*) pdu);
    assert_int_equal(type, 0x42);
}

static void vss_pad(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Vss_t* vss_pdu = (Avtp_Vss_t*) pdu;

    // Check if the function is initializing properly
    Avtp_Vss_Init(vss_pdu);

    for(int i = 1; i < 4; i++) {
        int vss_length = AVTP_VSS_FIXED_HEADER_LEN + i;
        Avtp_Vss_Pad(vss_pdu, vss_length);

        uint8_t vss_quadlets = Avtp_Vss_GetAcfMsgLength(vss_pdu);
        assert_int_equal(vss_quadlets, AVTP_VSS_FIXED_HEADER_LEN/4 + 1);

        uint8_t vss_pad = Avtp_Vss_GetPad(vss_pdu);
        assert_int_equal(vss_pad, 4-i);
    }
}

static void vss_static_path(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Vss_t* vss_pdu = (Avtp_Vss_t*) pdu;

    VssPath_t path_id = {
        .vss_static_id_path = 0x01020304
    };
    Avtp_Vss_SetAddrMode(vss_pdu, VSS_STATIC_ID_MODE);
    Avtp_Vss_SetVssPath(vss_pdu, &path_id);

    uint8_t exp_static_id[] = {1,2,3,4};
    assert_memory_equal(pdu+AVTP_VSS_FIXED_HEADER_LEN, exp_static_id, 4);

    VssPath_t get_path_id;
    Avtp_Vss_GetVssPath(vss_pdu, &get_path_id);
    assert_int_equal(get_path_id.vss_static_id_path, path_id.vss_static_id_path);
    assert_int_equal(Avtp_Vss_GetAddrMode(vss_pdu), VSS_STATIC_ID_MODE);
    assert_int_equal(Avtp_Vss_CalcVssPathLength(vss_pdu), 4);
}

static void vss_interop_path(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Vss_t* vss_pdu = (Avtp_Vss_t*) pdu;

    char path[] = "Vehicle.Speed";
    uint32_t path_length = strlen(path);

    VssPath_t path_id = {
        .vss_interop_path.path = path,
        .vss_interop_path.path_length = path_length
    };
    Avtp_Vss_SetAddrMode(vss_pdu, VSS_INTEROP_MODE);
    Avtp_Vss_SetVssPath(vss_pdu, &path_id);

    uint8_t get_path_len[] = {0, 13};
    assert_memory_equal(pdu+AVTP_VSS_FIXED_HEADER_LEN, get_path_len, 2);
    assert_int_equal(Avtp_Vss_GetAddrMode(vss_pdu), VSS_INTEROP_MODE);
    assert_int_equal(Avtp_Vss_CalcVssPathLength(vss_pdu), 15);

    VssPath_t get_vss_path;
    char buffer[15];
    get_vss_path.vss_interop_path.path = buffer;
    Avtp_Vss_GetVssPath(vss_pdu, &get_vss_path);
    assert_int_equal(get_vss_path.vss_interop_path.path_length, 13);
    assert_memory_equal(get_vss_path.vss_interop_path.path, path, 13);

}

static void vss_data_uint8(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Vss_t* vss_pdu = (Avtp_Vss_t*) pdu;
    char path[] = "Vehicle.Speed";
    uint32_t path_length = strlen(path);

    VssPath_t path_id = {
        .vss_interop_path.path = path,
        .vss_interop_path.path_length = path_length
    };
    Avtp_Vss_SetAddrMode(vss_pdu, VSS_INTEROP_MODE);
    Avtp_Vss_SetVssPath(vss_pdu, &path_id);

    VssData_t vss_data_uint8 = {
        .data_uint8 = 0x05
    };
    Avtp_Vss_SetDatatype(vss_pdu, VSS_UINT8);
    Avtp_Vss_SetVssData(vss_pdu, &vss_data_uint8);
    uint8_t mem[] = {5};
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 15, mem, 1);

    VssData_t vss_data_uint8_get;
    assert_int_equal(Avtp_Vss_GetDatatype(vss_pdu), VSS_UINT8);
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_uint8_get);
    assert_int_equal(vss_data_uint8_get.data_uint8, 0x05);

}

static void vss_data_int8(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Vss_t* vss_pdu = (Avtp_Vss_t*) pdu;
    char path[] = "Vehicle.Speed";
    uint32_t path_length = strlen(path);

    VssPath_t path_id = {
        .vss_interop_path.path = path,
        .vss_interop_path.path_length = path_length
    };
    Avtp_Vss_SetAddrMode(vss_pdu, VSS_INTEROP_MODE);
    Avtp_Vss_SetVssPath(vss_pdu, &path_id);

    VssData_t vss_data_int8 = {
        .data_int8 = -0x05
    };
    Avtp_Vss_SetDatatype(vss_pdu, VSS_INT8);
    Avtp_Vss_SetVssData(vss_pdu, &vss_data_int8);
    int8_t mem[] = {-5};
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 15, (uint8_t*) mem, 1);

    VssData_t vss_data_int8_get;
    assert_int_equal(Avtp_Vss_GetDatatype(vss_pdu), VSS_INT8);
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_int8_get);
    assert_int_equal(vss_data_int8_get.data_int8, -0x05);

}

static void vss_data_uint16(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Vss_t* vss_pdu = (Avtp_Vss_t*) pdu;
    char path[] = "Vehicle.Speed";
    uint32_t path_length = strlen(path);

    VssPath_t path_id = {
        .vss_interop_path.path = path,
        .vss_interop_path.path_length = path_length
    };
    Avtp_Vss_SetAddrMode(vss_pdu, VSS_INTEROP_MODE);
    Avtp_Vss_SetVssPath(vss_pdu, &path_id);

    VssData_t vss_data_uint16 = {
        .data_uint16 = 0x0504
    };
    Avtp_Vss_SetDatatype(vss_pdu, VSS_UINT16);
    Avtp_Vss_SetVssData(vss_pdu, &vss_data_uint16);
    uint8_t mem[] = {5, 4};
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 15, mem, 2);

    VssData_t vss_data_uint16_get;
    assert_int_equal(Avtp_Vss_GetDatatype(vss_pdu), VSS_UINT16);
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_uint16_get);
    assert_int_equal(vss_data_uint16_get.data_uint16, 0x0504);

}

static void vss_data_int16(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Vss_t* vss_pdu = (Avtp_Vss_t*) pdu;
    char path[] = "Vehicle.Speed";
    uint32_t path_length = strlen(path);

    VssPath_t path_id = {
        .vss_interop_path.path = path,
        .vss_interop_path.path_length = path_length
    };
    Avtp_Vss_SetAddrMode(vss_pdu, VSS_INTEROP_MODE);
    Avtp_Vss_SetVssPath(vss_pdu, &path_id);

    VssData_t vss_data_int16 = {
        .data_int16 = -0x0504
    };
    Avtp_Vss_SetDatatype(vss_pdu, VSS_INT16);
    Avtp_Vss_SetVssData(vss_pdu, &vss_data_int16);
    uint8_t mem[] = {0xFA, 0xFC};
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 15, mem, 2);

    VssData_t vss_data_int16_get;
    assert_int_equal(Avtp_Vss_GetDatatype(vss_pdu), VSS_INT16);
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_int16_get);
    assert_int_equal(vss_data_int16_get.data_int16, -0x0504);

}

static void vss_data_uint32(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Vss_t* vss_pdu = (Avtp_Vss_t*) pdu;
    char path[] = "Vehicle.Speed";
    uint32_t path_length = strlen(path);

    VssPath_t path_id = {
        .vss_interop_path.path = path,
        .vss_interop_path.path_length = path_length
    };
    Avtp_Vss_SetAddrMode(vss_pdu, VSS_INTEROP_MODE);
    Avtp_Vss_SetVssPath(vss_pdu, &path_id);

    VssData_t vss_data_uint32 = {
        .data_uint32 = 0x05040302
    };
    Avtp_Vss_SetDatatype(vss_pdu, VSS_UINT32);
    Avtp_Vss_SetVssData(vss_pdu, &vss_data_uint32);
    uint8_t mem[] = {5, 4, 3, 2};
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 15, mem, 4);

    VssData_t vss_data_uint32_get;
    assert_int_equal(Avtp_Vss_GetDatatype(vss_pdu), VSS_UINT32);
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_uint32_get);
    assert_int_equal(vss_data_uint32_get.data_uint32, 0x05040302);

}

static void vss_data_int32(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Vss_t* vss_pdu = (Avtp_Vss_t*) pdu;
    char path[] = "Vehicle.Speed";
    uint32_t path_length = strlen(path);

    VssPath_t path_id = {
        .vss_interop_path.path = path,
        .vss_interop_path.path_length = path_length
    };
    Avtp_Vss_SetAddrMode(vss_pdu, VSS_INTEROP_MODE);
    Avtp_Vss_SetVssPath(vss_pdu, &path_id);

    VssData_t vss_data_int32 = {
        .data_int32 = -0x05040302
    };
    Avtp_Vss_SetDatatype(vss_pdu, VSS_INT32);
    Avtp_Vss_SetVssData(vss_pdu, &vss_data_int32);
    uint8_t mem[] = {0xFA, 0xFB, 0xFC, 0xFE};
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 15, mem, 4);

    VssData_t vss_data_int32_get;
    assert_int_equal(Avtp_Vss_GetDatatype(vss_pdu), VSS_INT32);
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_int32_get);
    assert_int_equal(vss_data_int32_get.data_int32, -0x05040302);
}

static void vss_data_uint64(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Vss_t* vss_pdu = (Avtp_Vss_t*) pdu;
    char path[] = "Vehicle.Speed";
    uint32_t path_length = strlen(path);

    VssPath_t path_id = {
        .vss_interop_path.path = path,
        .vss_interop_path.path_length = path_length
    };
    Avtp_Vss_SetAddrMode(vss_pdu, VSS_INTEROP_MODE);
    Avtp_Vss_SetVssPath(vss_pdu, &path_id);

    VssData_t vss_data_uint64 = {
        .data_uint64 = 0x0504030201060708
    };
    Avtp_Vss_SetDatatype(vss_pdu, VSS_UINT64);
    Avtp_Vss_SetVssData(vss_pdu, &vss_data_uint64);
    uint8_t mem[] = {5, 4, 3, 2, 1, 6, 7, 8};
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 15, mem, 8);

    VssData_t vss_data_uint64_get;
    assert_int_equal(Avtp_Vss_GetDatatype(vss_pdu), VSS_UINT64);
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_uint64_get);
    uint8_t mem_cpu[] = {8, 7, 6, 1, 2, 3, 4, 5};
    assert_memory_equal(&(vss_data_uint64_get.data_uint64), mem_cpu, 8);

}

static void vss_data_int64(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Vss_t* vss_pdu = (Avtp_Vss_t*) pdu;
    char path[] = "Vehicle.Speed";
    uint32_t path_length = strlen(path);

    VssPath_t path_id = {
        .vss_interop_path.path = path,
        .vss_interop_path.path_length = path_length
    };
    Avtp_Vss_SetAddrMode(vss_pdu, VSS_INTEROP_MODE);
    Avtp_Vss_SetVssPath(vss_pdu, &path_id);

    VssData_t vss_data_int64 = {
        .data_int64 = -0x0504030201060708
    };
    Avtp_Vss_SetDatatype(vss_pdu, VSS_INT64);
    Avtp_Vss_SetVssData(vss_pdu, &vss_data_int64);
    uint8_t mem[] = {0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xF9, 0xF8, 0xF8};
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 15, mem, 8);

    VssData_t vss_data_int64_get;
    assert_int_equal(Avtp_Vss_GetDatatype(vss_pdu), VSS_INT64);
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_int64_get);
    uint8_t mem_cpu[] = {0xF8, 0xF8, 0xF9, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA};
    assert_memory_equal(&(vss_data_int64_get.data_int64), mem_cpu, 8);

}

static void vss_data_bool(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Vss_t* vss_pdu = (Avtp_Vss_t*) pdu;
    char path[] = "Vehicle.Speed";
    uint32_t path_length = strlen(path);

    VssPath_t path_id = {
        .vss_interop_path.path = path,
        .vss_interop_path.path_length = path_length
    };
    Avtp_Vss_SetAddrMode(vss_pdu, VSS_INTEROP_MODE);
    Avtp_Vss_SetVssPath(vss_pdu, &path_id);

    VssData_t vss_data_bool = {
        .data_bool = 0x01
    };
    Avtp_Vss_SetDatatype(vss_pdu, VSS_BOOL);
    Avtp_Vss_SetVssData(vss_pdu, &vss_data_bool);
    uint8_t mem[] = {1};
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 15, mem, 1);

    VssData_t vss_data_bool_get;
    assert_int_equal(Avtp_Vss_GetDatatype(vss_pdu), VSS_BOOL);
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_bool_get);
    assert_int_equal(vss_data_bool_get.data_bool, 1);

}

static void vss_data_float(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Vss_t* vss_pdu = (Avtp_Vss_t*) pdu;
    char path[] = "Vehicle.Speed";
    uint32_t path_length = strlen(path);

    VssPath_t path_id = {
        .vss_interop_path.path = path,
        .vss_interop_path.path_length = path_length
    };
    Avtp_Vss_SetAddrMode(vss_pdu, VSS_INTEROP_MODE);
    Avtp_Vss_SetVssPath(vss_pdu, &path_id);

    VssData_t vss_data_float = {
        .data_float = -1.2
    };
    Avtp_Vss_SetDatatype(vss_pdu, VSS_FLOAT);
    Avtp_Vss_SetVssData(vss_pdu, &vss_data_float);
    uint8_t mem[] = {0xbf, 0x99, 0x99, 0x9a};
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 15, mem, 4);

    VssData_t vss_data_float_get;
    assert_int_equal(Avtp_Vss_GetDatatype(vss_pdu), VSS_FLOAT);
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_float_get);
    assert_float_equal(vss_data_float_get.data_float, -1.2, 0.5);

}

static void vss_data_double(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Vss_t* vss_pdu = (Avtp_Vss_t*) pdu;
    char path[] = "Vehicle.Speed";
    uint32_t path_length = strlen(path);

    VssPath_t path_id = {
        .vss_interop_path.path = path,
        .vss_interop_path.path_length = path_length
    };
    Avtp_Vss_SetAddrMode(vss_pdu, VSS_INTEROP_MODE);
    Avtp_Vss_SetVssPath(vss_pdu, &path_id);

    VssData_t vss_data_double = {
        .data_double = -1.2
    };
    Avtp_Vss_SetDatatype(vss_pdu, VSS_DOUBLE);
    Avtp_Vss_SetVssData(vss_pdu, &vss_data_double);
    uint8_t mem[] = {0xbf, 0xf3, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33};
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 15, mem, 8);

    VssData_t vss_data_double_get;
    assert_int_equal(Avtp_Vss_GetDatatype(vss_pdu), VSS_DOUBLE);
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_double_get);
    assert_float_equal(vss_data_double_get.data_double, -1.2, 0.1);

}

static void vss_data_string(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Vss_t* vss_pdu = (Avtp_Vss_t*) pdu;
    char path[] = "Vehicle.Speed";
    uint32_t path_length = strlen(path);

    VssPath_t path_id = {
        .vss_interop_path.path = path,
        .vss_interop_path.path_length = path_length
    };
    Avtp_Vss_SetAddrMode(vss_pdu, VSS_INTEROP_MODE);
    Avtp_Vss_SetVssPath(vss_pdu, &path_id);

    char str_value[] = "10m/s2";
    VssDataString_t vss_data_string = {
        .data = str_value,
        .data_length = strlen(str_value)
    };
    VssData_t data = {
        .data_string = &vss_data_string
    };
    Avtp_Vss_SetDatatype(vss_pdu, VSS_STRING);
    Avtp_Vss_SetVssData(vss_pdu, &data);
    uint8_t len_in_mem[] = {0, strlen(str_value)};
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 15, len_in_mem, 2);
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 17, str_value, strlen(str_value));

    VssData_t vss_data_get;
    VssDataString_t vss_data_string_get = {
        .data = 0
    };
    vss_data_get.data_string = &vss_data_string_get;
    assert_int_equal(Avtp_Vss_GetDatatype(vss_pdu), VSS_STRING);
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_get);
    assert_int_equal(vss_data_get.data_string->data_length, strlen(str_value));
    char str_value_recv[vss_data_get.data_string->data_length];
    vss_data_string_get.data = str_value_recv;
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_get);
    assert_string_equal(vss_data_get.data_string->data, str_value);
}

static void vss_data_uint8_array(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Vss_t* vss_pdu = (Avtp_Vss_t*) pdu;
    char path[] = "Vehicle.Speed";
    uint32_t path_length = strlen(path);

    VssPath_t path_id = {
        .vss_interop_path.path = path,
        .vss_interop_path.path_length = path_length
    };
    Avtp_Vss_SetAddrMode(vss_pdu, VSS_INTEROP_MODE);
    Avtp_Vss_SetVssPath(vss_pdu, &path_id);

    uint8_t uint8_arr_value[] = {5, 4, 3, 2, 1};
    VssDataUint8Array_t vss_data_uint8_arr = {
        .data = uint8_arr_value,
        .data_length = 5
    };
    VssData_t data = {
        .data_uint8_array = &vss_data_uint8_arr
    };
    Avtp_Vss_SetDatatype(vss_pdu, VSS_UINT8_ARRAY);
    Avtp_Vss_SetVssData(vss_pdu, &data);
    uint8_t len_in_mem[] = {0, 5};
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 15, len_in_mem, 2);
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 17, uint8_arr_value, 5);

    VssData_t vss_data_get;
    VssDataUint8Array_t vss_data_uint8_arr_get = {
        .data = 0
    };
    vss_data_get.data_uint8_array = &vss_data_uint8_arr_get;
    assert_int_equal(Avtp_Vss_GetDatatype(vss_pdu), VSS_UINT8_ARRAY);
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_get);
    assert_int_equal(vss_data_get.data_uint8_array->data_length, 5);
    uint8_t uint8_arr_value_recv[vss_data_get.data_uint8_array->data_length];
    vss_data_uint8_arr_get.data = uint8_arr_value_recv;
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_get);
    assert_memory_equal(vss_data_get.data_uint8_array->data, uint8_arr_value, 5);
}

static void vss_data_int8_array(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Vss_t* vss_pdu = (Avtp_Vss_t*) pdu;
    char path[] = "Vehicle.Speed";
    uint32_t path_length = strlen(path);

    VssPath_t path_id = {
        .vss_interop_path.path = path,
        .vss_interop_path.path_length = path_length
    };
    Avtp_Vss_SetAddrMode(vss_pdu, VSS_INTEROP_MODE);
    Avtp_Vss_SetVssPath(vss_pdu, &path_id);

    int8_t int8_arr_value[] = {-5, -4, -3, -2, -1};
    VssDataInt8Array_t vss_data_int8_arr = {
        .data = int8_arr_value,
        .data_length = 5
    };
    VssData_t data = {
        .data_int8_array = &vss_data_int8_arr
    };
    Avtp_Vss_SetDatatype(vss_pdu, VSS_INT8_ARRAY);
    Avtp_Vss_SetVssData(vss_pdu, &data);
    uint8_t len_in_mem[] = {0, 5};
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 15, len_in_mem, 2);
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 17, int8_arr_value, 5);

    VssData_t vss_data_get;
    VssDataInt8Array_t vss_data_int8_arr_get = {
        .data = 0
    };
    vss_data_get.data_int8_array = &vss_data_int8_arr_get;
    assert_int_equal(Avtp_Vss_GetDatatype(vss_pdu), VSS_INT8_ARRAY);
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_get);
    assert_int_equal(vss_data_get.data_int8_array->data_length, 5);
    int8_t int8_arr_value_recv[vss_data_get.data_int8_array->data_length];
    vss_data_int8_arr_get.data = int8_arr_value_recv;
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_get);
    assert_memory_equal(vss_data_get.data_int8_array->data, int8_arr_value, 5);
}

static void vss_data_uint16_array(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Vss_t* vss_pdu = (Avtp_Vss_t*) pdu;
    char path[] = "Vehicle.Speed";
    uint32_t path_length = strlen(path);

    VssPath_t path_id = {
        .vss_interop_path.path = path,
        .vss_interop_path.path_length = path_length
    };
    Avtp_Vss_SetAddrMode(vss_pdu, VSS_INTEROP_MODE);
    Avtp_Vss_SetVssPath(vss_pdu, &path_id);

    uint16_t uint16_arr_value[] = {0x100, 0x101, 0x102, 0x103, 0x104};
    VssDataUint16Array_t vss_data_uint16_arr = {
        .data = uint16_arr_value,
        .data_length = 10
    };
    VssData_t data = {
        .data_uint16_array = &vss_data_uint16_arr
    };
    Avtp_Vss_SetDatatype(vss_pdu, VSS_UINT16_ARRAY);
    Avtp_Vss_SetVssData(vss_pdu, &data);
    uint8_t len_in_mem[] = {0, 10};
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 15, len_in_mem, 2);
    uint8_t arr_in_mem[] = {1, 0, 1, 1, 1, 2, 1, 3, 1, 4};
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 17, arr_in_mem, 10);

    VssData_t vss_data_get;
    VssDataUint16Array_t vss_data_uint16_arr_get = {
        .data = 0
    };
    vss_data_get.data_uint16_array = &vss_data_uint16_arr_get;
    assert_int_equal(Avtp_Vss_GetDatatype(vss_pdu), VSS_UINT16_ARRAY);
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_get);
    assert_int_equal(vss_data_get.data_uint16_array->data_length, 10);
    uint16_t uint16_arr_value_recv[vss_data_get.data_uint16_array->data_length/2];
    vss_data_uint16_arr_get.data = uint16_arr_value_recv;
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_get);
    assert_memory_equal(vss_data_get.data_uint16_array->data, uint16_arr_value, 10);
}

static void vss_data_int16_array(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Vss_t* vss_pdu = (Avtp_Vss_t*) pdu;
    char path[] = "Vehicle.Speed";
    uint32_t path_length = strlen(path);

    VssPath_t path_id = {
        .vss_interop_path.path = path,
        .vss_interop_path.path_length = path_length
    };
    Avtp_Vss_SetAddrMode(vss_pdu, VSS_INTEROP_MODE);
    Avtp_Vss_SetVssPath(vss_pdu, &path_id);

    int16_t int16_arr_value[] = {-0x100, -0x101, -0x102, -0x103, -0x104};
    VssDataInt16Array_t vss_data_int16_arr = {
        .data = int16_arr_value,
        .data_length = 10
    };
    VssData_t data = {
        .data_int16_array = &vss_data_int16_arr
    };
    Avtp_Vss_SetDatatype(vss_pdu, VSS_INT16_ARRAY);
    Avtp_Vss_SetVssData(vss_pdu, &data);
    uint8_t len_in_mem[] = {0, 10};
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 15, len_in_mem, 2);
    uint8_t arr_in_mem[] = {0xFF, 0, 0xFE, 0xFF, 0xfe, 0xfe, 0xfe, 0xfd, 0xfe, 0xfc};
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 17, arr_in_mem, 10);

    VssData_t vss_data_get;
    VssDataInt16Array_t vss_data_int16_arr_get = {
        .data = 0
    };
    vss_data_get.data_int16_array = &vss_data_int16_arr_get;
    assert_int_equal(Avtp_Vss_GetDatatype(vss_pdu), VSS_INT16_ARRAY);
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_get);
    assert_int_equal(vss_data_get.data_int16_array->data_length, 10);
    int16_t int16_arr_value_recv[vss_data_get.data_int16_array->data_length/2];
    vss_data_int16_arr_get.data = int16_arr_value_recv;
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_get);
    assert_memory_equal(vss_data_get.data_int16_array->data, int16_arr_value, 10);
}

static void vss_data_uint32_array(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Vss_t* vss_pdu = (Avtp_Vss_t*) pdu;
    char path[] = "Vehicle.Speed";
    uint32_t path_length = strlen(path);

    VssPath_t path_id = {
        .vss_interop_path.path = path,
        .vss_interop_path.path_length = path_length
    };
    Avtp_Vss_SetAddrMode(vss_pdu, VSS_INTEROP_MODE);
    Avtp_Vss_SetVssPath(vss_pdu, &path_id);

    uint32_t uint32_arr_value[] = {0x10000, 0x10100, 0x10200, 0x10300, 0x10400};
    VssDataUint32Array_t vss_data_uint32_arr = {
        .data = uint32_arr_value,
        .data_length = 20
    };
    VssData_t data = {
        .data_uint32_array = &vss_data_uint32_arr
    };
    Avtp_Vss_SetDatatype(vss_pdu, VSS_UINT32_ARRAY);
    Avtp_Vss_SetVssData(vss_pdu, &data);
    uint8_t len_in_mem[] = {0, 20};
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 15, len_in_mem, 2);
    uint8_t arr_in_mem[] = {0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 2, 0, 0, 1, 3, 0, 0, 1, 4, 0};
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 17, arr_in_mem, 20);

    VssData_t vss_data_get;
    VssDataUint32Array_t vss_data_uint32_arr_get = {
        .data = 0
    };
    vss_data_get.data_uint32_array = &vss_data_uint32_arr_get;
    assert_int_equal(Avtp_Vss_GetDatatype(vss_pdu), VSS_UINT32_ARRAY);
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_get);
    assert_int_equal(vss_data_get.data_uint32_array->data_length, 20);
    uint32_t uint32_arr_value_recv[vss_data_get.data_uint32_array->data_length/4];
    vss_data_uint32_arr_get.data = uint32_arr_value_recv;
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_get);
    assert_memory_equal(vss_data_get.data_uint32_array->data, uint32_arr_value, 20);
}

static void vss_data_int32_array(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Vss_t* vss_pdu = (Avtp_Vss_t*) pdu;
    char path[] = "Vehicle.Speed";
    uint32_t path_length = strlen(path);

    VssPath_t path_id = {
        .vss_interop_path.path = path,
        .vss_interop_path.path_length = path_length
    };
    Avtp_Vss_SetAddrMode(vss_pdu, VSS_INTEROP_MODE);
    Avtp_Vss_SetVssPath(vss_pdu, &path_id);

    int32_t int32_arr_value[] = {-0x10000, -0x10100, -0x10200, -0x10300, -0x10400};
    VssDataInt32Array_t vss_data_int32_arr = {
        .data = int32_arr_value,
        .data_length = 20
    };
    VssData_t data = {
        .data_int32_array = &vss_data_int32_arr
    };
    Avtp_Vss_SetDatatype(vss_pdu, VSS_INT32_ARRAY);
    Avtp_Vss_SetVssData(vss_pdu, &data);
    uint8_t len_in_mem[] = {0, 20};
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 15, len_in_mem, 2);
    uint8_t arr_in_mem[] = {0xff, 0xff, 0, 0,
                            0xff, 0xfe, 0xff, 0,
                            0xff, 0xfe, 0xfe, 0,
                            0xff, 0xfe, 0xfd, 0,
                            0xff, 0xfe, 0xfc, 0};
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 17, arr_in_mem, 20);

    VssData_t vss_data_get;
    VssDataInt32Array_t vss_data_int32_arr_get = {
        .data = 0
    };
    vss_data_get.data_int32_array = &vss_data_int32_arr_get;
    assert_int_equal(Avtp_Vss_GetDatatype(vss_pdu), VSS_INT32_ARRAY);
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_get);
    assert_int_equal(vss_data_get.data_int32_array->data_length, 20);
    int32_t int32_arr_value_recv[vss_data_get.data_int32_array->data_length/4];
    vss_data_int32_arr_get.data = int32_arr_value_recv;
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_get);
    assert_memory_equal(vss_data_get.data_int32_array->data, int32_arr_value, 20);
}

static void vss_data_uint64_array(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Vss_t* vss_pdu = (Avtp_Vss_t*) pdu;
    char path[] = "Vehicle.Speed";
    uint32_t path_length = strlen(path);

    VssPath_t path_id = {
        .vss_interop_path.path = path,
        .vss_interop_path.path_length = path_length
    };
    Avtp_Vss_SetAddrMode(vss_pdu, VSS_INTEROP_MODE);
    Avtp_Vss_SetVssPath(vss_pdu, &path_id);

    uint64_t uint64_arr_value[] = {0x10000, 0x10100, 0x10200, 0x10300, 0x10400};
    VssDataUint64Array_t vss_data_uint64_arr = {
        .data = uint64_arr_value,
        .data_length = 40
    };
    VssData_t data = {
        .data_uint64_array = &vss_data_uint64_arr
    };
    Avtp_Vss_SetDatatype(vss_pdu, VSS_UINT64_ARRAY);
    Avtp_Vss_SetVssData(vss_pdu, &data);
    uint8_t len_in_mem[] = {0, 40};
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 15, len_in_mem, 2);
    uint8_t arr_in_mem[] = {0, 0, 0, 0, 0, 1, 0, 0,
                             0, 0, 0, 0, 0, 1, 1, 0,
                             0, 0, 0, 0, 0, 1, 2, 0,
                             0, 0, 0, 0, 0, 1, 3, 0,
                             0, 0, 0, 0, 0, 1, 4, 0};
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 17, arr_in_mem, 40);

    VssData_t vss_data_get;
    VssDataUint64Array_t vss_data_uint64_arr_get = {
        .data = 0
    };
    vss_data_get.data_uint64_array = &vss_data_uint64_arr_get;
    assert_int_equal(Avtp_Vss_GetDatatype(vss_pdu), VSS_UINT64_ARRAY);
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_get);
    assert_int_equal(vss_data_get.data_uint64_array->data_length, 40);
    uint64_t uint64_arr_value_recv[vss_data_get.data_uint64_array->data_length/8];
    vss_data_uint64_arr_get.data = uint64_arr_value_recv;
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_get);
    assert_memory_equal(vss_data_get.data_uint64_array->data, uint64_arr_value, 40);
}

static void vss_data_int64_array(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Vss_t* vss_pdu = (Avtp_Vss_t*) pdu;
    char path[] = "Vehicle.Speed";
    uint32_t path_length = strlen(path);

    VssPath_t path_id = {
        .vss_interop_path.path = path,
        .vss_interop_path.path_length = path_length
    };
    Avtp_Vss_SetAddrMode(vss_pdu, VSS_INTEROP_MODE);
    Avtp_Vss_SetVssPath(vss_pdu, &path_id);

    int64_t int64_arr_value[] = {-0x10000, -0x10100, -0x10200, -0x10300, -0x10400};
    VssDataInt64Array_t vss_data_int64_arr = {
        .data = int64_arr_value,
        .data_length = 40
    };
    VssData_t data = {
        .data_int64_array = &vss_data_int64_arr
    };
    Avtp_Vss_SetDatatype(vss_pdu, VSS_INT64_ARRAY);
    Avtp_Vss_SetVssData(vss_pdu, &data);
    uint8_t len_in_mem[] = {0, 40};
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 15, len_in_mem, 2);
    uint8_t arr_in_mem[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0,
                             0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0,
                             0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xfe, 0,
                             0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xfd, 0,
                             0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xfc, 0,};
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 17, arr_in_mem, 40);

    VssData_t vss_data_get;
    VssDataInt64Array_t vss_data_int64_arr_get = {
        .data = 0
    };
    vss_data_get.data_int64_array = &vss_data_int64_arr_get;
    assert_int_equal(Avtp_Vss_GetDatatype(vss_pdu), VSS_INT64_ARRAY);
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_get);
    assert_int_equal(vss_data_get.data_int64_array->data_length, 40);
    int64_t int64_arr_value_recv[vss_data_get.data_int64_array->data_length/8];
    vss_data_int64_arr_get.data = int64_arr_value_recv;
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_get);
    assert_memory_equal(vss_data_get.data_int64_array->data, int64_arr_value, 40);
}

static void vss_data_bool_array(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Vss_t* vss_pdu = (Avtp_Vss_t*) pdu;
    char path[] = "Vehicle.Speed";
    uint32_t path_length = strlen(path);

    VssPath_t path_id = {
        .vss_interop_path.path = path,
        .vss_interop_path.path_length = path_length
    };
    Avtp_Vss_SetAddrMode(vss_pdu, VSS_INTEROP_MODE);
    Avtp_Vss_SetVssPath(vss_pdu, &path_id);

    uint8_t bool_arr_value[] = {1, 0, 0, 0, 1};
    VssDataBoolArray_t vss_data_bool_arr = {
        .data = bool_arr_value,
        .data_length = 5
    };
    VssData_t data = {
        .data_bool_array = &vss_data_bool_arr
    };
    Avtp_Vss_SetDatatype(vss_pdu, VSS_BOOL_ARRAY);
    Avtp_Vss_SetVssData(vss_pdu, &data);
    uint8_t len_in_mem[] = {0, 5};
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 15, len_in_mem, 2);
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 17, bool_arr_value, 5);

    VssData_t vss_data_get;
    VssDataBoolArray_t vss_data_bool_arr_get = {
        .data = 0
    };
    vss_data_get.data_bool_array = &vss_data_bool_arr_get;
    assert_int_equal(Avtp_Vss_GetDatatype(vss_pdu), VSS_BOOL_ARRAY);
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_get);
    assert_int_equal(vss_data_get.data_bool_array->data_length, 5);
    uint8_t bool_arr_value_recv[vss_data_get.data_bool_array->data_length];
    vss_data_bool_arr_get.data = bool_arr_value_recv;
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_get);
    assert_memory_equal(vss_data_get.data_bool_array->data, bool_arr_value, 5);
}

static void vss_data_float_array(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Vss_t* vss_pdu = (Avtp_Vss_t*) pdu;
    char path[] = "Vehicle.Speed";
    uint32_t path_length = strlen(path);

    VssPath_t path_id = {
        .vss_interop_path.path = path,
        .vss_interop_path.path_length = path_length
    };
    Avtp_Vss_SetAddrMode(vss_pdu, VSS_INTEROP_MODE);
    Avtp_Vss_SetVssPath(vss_pdu, &path_id);

    float float_arr_value[] = {1.2, -1.2, 1.3, -1.3, 1.5};
    VssDataFloatArray_t vss_data_float_arr = {
        .data = float_arr_value,
        .data_length = 20
    };
    VssData_t data = {
        .data_float_array = &vss_data_float_arr
    };
    Avtp_Vss_SetDatatype(vss_pdu, VSS_FLOAT_ARRAY);
    Avtp_Vss_SetVssData(vss_pdu, &data);
    uint8_t len_in_mem[] = {0, 20};
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 15, len_in_mem, 2);
    uint8_t arr_in_mem[] = {0x3f, 0x99, 0x99, 0x9a,
                             0xbf, 0x99, 0x99, 0x9a,
                             0x3f, 0xa6, 0x66, 0x66,
                             0xbf, 0xa6, 0x66, 0x66,
                             0x3f, 0xc0, 0, 0, 0};
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 17, arr_in_mem, 20);

    VssData_t vss_data_get;
    VssDataFloatArray_t vss_data_float_arr_get = {
        .data = 0
    };
    vss_data_get.data_float_array = &vss_data_float_arr_get;
    assert_int_equal(Avtp_Vss_GetDatatype(vss_pdu), VSS_FLOAT_ARRAY);
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_get);
    assert_int_equal(vss_data_get.data_float_array->data_length, 20);
    float float_arr_value_recv[vss_data_get.data_float_array->data_length/4];
    vss_data_float_arr_get.data = float_arr_value_recv;
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_get);
    assert_memory_equal(vss_data_get.data_float_array->data, float_arr_value, 20);
}

static void vss_data_double_array(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Vss_t* vss_pdu = (Avtp_Vss_t*) pdu;
    char path[] = "Vehicle.Speed";
    uint32_t path_length = strlen(path);

    VssPath_t path_id = {
        .vss_interop_path.path = path,
        .vss_interop_path.path_length = path_length
    };
    Avtp_Vss_SetAddrMode(vss_pdu, VSS_INTEROP_MODE);
    Avtp_Vss_SetVssPath(vss_pdu, &path_id);

    double double_arr_value[] = {1.2, -1.2, 1.3, -1.3, 1.5};
    VssDataDoubleArray_t vss_data_double_arr = {
        .data = double_arr_value,
        .data_length = 40
    };
    VssData_t data = {
        .data_double_array = &vss_data_double_arr
    };
    Avtp_Vss_SetDatatype(vss_pdu, VSS_DOUBLE_ARRAY);
    Avtp_Vss_SetVssData(vss_pdu, &data);
    uint8_t len_in_mem[] = {0, 40};
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 15, len_in_mem, 2);
    uint8_t arr_in_mem[] = {0x3f, 0xf3, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
                             0xbf, 0xf3, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
                             0x3f, 0xf4, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcd,
                             0xbf, 0xf4, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcd,
                             0x3f, 0xf8, 0, 0, 0, 0, 0, 0};
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 17, arr_in_mem, 40);

    VssData_t vss_data_get;
    VssDataDoubleArray_t vss_data_double_arr_get = {
        .data = 0
    };
    vss_data_get.data_double_array = &vss_data_double_arr_get;
    assert_int_equal(Avtp_Vss_GetDatatype(vss_pdu), VSS_DOUBLE_ARRAY);
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_get);
    assert_int_equal(vss_data_get.data_double_array->data_length, 40);
    double double_arr_value_recv[vss_data_get.data_double_array->data_length/8];
    vss_data_double_arr_get.data = double_arr_value_recv;
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_get);
    assert_memory_equal(vss_data_get.data_double_array->data, double_arr_value, 40);
}

static void vss_data_string_array(void **state) {

    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Vss_t* vss_pdu = (Avtp_Vss_t*) pdu;
    char path[] = "Vehicle.Speed";
    uint32_t path_length = strlen(path);

    VssPath_t path_id = {
        .vss_interop_path.path = path,
        .vss_interop_path.path_length = path_length
    };
    Avtp_Vss_SetAddrMode(vss_pdu, VSS_INTEROP_MODE);
    Avtp_Vss_SetVssPath(vss_pdu, &path_id);

    char str1[] = "Hello";
    char str2[] = "World";
    char str3[] = "Tschuss";
    VssDataString_t vss_str1 = {
        .data = str1,
        .data_length = strlen(str1)
    };
    VssDataString_t vss_str2 = {
        .data = str2,
        .data_length = strlen(str2)
    };
    VssDataString_t vss_str3 = {
        .data = str3,
        .data_length = strlen(str3)
    };

    VssDataString_t* arr[] = {&vss_str1, &vss_str2, &vss_str3};
    uint8_t buffer[strlen(str1) + strlen(str2) + strlen(str3)+2];
    VssDataStringArray_t vss_str_array = {
        .data = buffer
    };
    Avtp_Vss_SerializeStringArray(&vss_str_array, arr, 3);

    VssData_t data = {
        .data_string_array = &vss_str_array
    };
    Avtp_Vss_SetDatatype(vss_pdu, VSS_STRING_ARRAY);
    Avtp_Vss_SetVssData(vss_pdu, &data);
    uint8_t len_in_mem[] = {0, 23};
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 15, len_in_mem, 2);
    uint8_t arr_in_mem[] = {0x00, 0x05, 'H', 'e', 'l', 'l', 'o',
                             0x00, 0x05, 'W', 'o', 'r', 'l', 'd',
                             0x00, 0x07, 'T', 's', 'c', 'h', 'u', 's', 's'};
    assert_memory_equal(pdu + AVTP_VSS_FIXED_HEADER_LEN + 17, arr_in_mem, 23);

    VssData_t vss_data_get;
    VssDataStringArray_t vss_data_string_arr_get = {
        .data = 0
    };
    vss_data_get.data_string_array = &vss_data_string_arr_get;
    assert_int_equal(Avtp_Vss_GetDatatype(vss_pdu), VSS_STRING_ARRAY);
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_get);
    assert_int_equal(vss_data_get.data_string_array->data_length, 23);
    uint8_t string_arr_value_recv[vss_data_get.data_string_array->data_length];
    vss_data_string_arr_get.data = string_arr_value_recv;
    Avtp_Vss_GetVssData(vss_pdu, &vss_data_get);
    assert_memory_equal(vss_data_get.data_string_array->data, arr_in_mem, 23);

    assert_int_equal(Avtp_Vss_GetVSSDataStringArrayLength(vss_data_get.data_string_array), 3);
    VssDataString_t strings[3] = {
        {.data = 0},
        {.data = 0},
        {.data = 0}
    };
    VssDataString_t* strings_array[] = {&strings[0], &strings[1], &strings[2]};
    Avtp_Vss_DeserializeStringArray(vss_data_get.data_string_array, (VssDataString_t**) &strings_array, 3);

    assert_int_equal(strings[0].data_length, 5);
    assert_int_equal(strings[1].data_length, 5);
    assert_int_equal(strings[2].data_length, 7);

    char str1_recd[5];
    char str2_recd[5];
    char str3_recd[7];
    strings[0].data = str1_recd,
    strings[1].data = str2_recd,
    strings[2].data = str3_recd,

    Avtp_Vss_DeserializeStringArray(vss_data_get.data_string_array, (VssDataString_t**) &strings_array, 3);
    assert_memory_equal(strings[0].data, str1, 5);
    assert_memory_equal(strings[1].data, str2, 5);
    assert_memory_equal(strings[2].data, str3, 7);

}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(vss_init),
        cmocka_unit_test(vss_pad),
        cmocka_unit_test(vss_static_path),
        cmocka_unit_test(vss_interop_path),
        cmocka_unit_test(vss_data_uint8),
        cmocka_unit_test(vss_data_int8),
        cmocka_unit_test(vss_data_uint16),
        cmocka_unit_test(vss_data_int16),
        cmocka_unit_test(vss_data_uint32),
        cmocka_unit_test(vss_data_int32),
        cmocka_unit_test(vss_data_uint64),
        cmocka_unit_test(vss_data_int64),
        cmocka_unit_test(vss_data_bool),
        cmocka_unit_test(vss_data_float),
        cmocka_unit_test(vss_data_double),
        cmocka_unit_test(vss_data_string),
        cmocka_unit_test(vss_data_uint8_array),
        cmocka_unit_test(vss_data_int8_array),
        cmocka_unit_test(vss_data_uint16_array),
        cmocka_unit_test(vss_data_int16_array),
        cmocka_unit_test(vss_data_uint32_array),
        cmocka_unit_test(vss_data_int32_array),
        cmocka_unit_test(vss_data_uint64_array),
        cmocka_unit_test(vss_data_int64_array),
        cmocka_unit_test(vss_data_bool_array),
        cmocka_unit_test(vss_data_float_array),
        cmocka_unit_test(vss_data_double_array),
        cmocka_unit_test(vss_data_string_array),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
