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

#include <errno.h>
#include <string.h>

#include "avtp/acf/AcfCommon.h"
#include "avtp/acf/custom/Vss.h"
#include "avtp/Utils.h"
#include "avtp/Defines.h"

#define GET_FIELD(field) \
        (Avtp_GetField(Avtp_VssFieldDesc, AVTP_VSS_FIELD_MAX, (uint8_t*)pdu, field))
#define SET_FIELD(field, value) \
        (Avtp_SetField(Avtp_VssFieldDesc, AVTP_VSS_FIELD_MAX, (uint8_t*)pdu, field, value))

/**
 * This table maps all IEEE 1722 ACF VSS header fields to a descriptor.
 */
static const Avtp_FieldDescriptor_t Avtp_VssFieldDesc[AVTP_VSS_FIELD_MAX] =
{
    /* ACF common header fields */
    [AVTP_VSS_FIELD_ACF_MSG_TYPE]       = { .quadlet = 0, .offset =  0, .bits = 7 },
    [AVTP_VSS_FIELD_ACF_MSG_LENGTH]     = { .quadlet = 0, .offset =  7, .bits = 9 },
    /* ACF VSS header fields */
    [AVTP_VSS_FIELD_PAD]                = { .quadlet = 0, .offset = 16, .bits =  2 },
    [AVTP_VSS_FIELD_MTV]                = { .quadlet = 0, .offset = 18, .bits =  1 },
    [AVTP_VSS_FIELD_ADDR_MODE]          = { .quadlet = 0, .offset = 19, .bits =  2 },
    [AVTP_VSS_FIELD_VSS_OP]             = { .quadlet = 0, .offset = 21, .bits =  3 },
    [AVTP_VSS_FIELD_VSS_DATATYPE]       = { .quadlet = 0, .offset = 24, .bits =  8 },
    [AVTP_VSS_FIELD_MSG_TIMESTAMP]      = { .quadlet = 1, .offset =  0, .bits = 64 }
};

void Avtp_Vss_Init(Avtp_Vss_t* vss_pdu) {

    if(vss_pdu != NULL) {
        memset(vss_pdu, 0, sizeof(Avtp_Vss_t));
        Avtp_Vss_SetField(vss_pdu, AVTP_VSS_FIELD_ACF_MSG_TYPE, AVTP_ACF_TYPE_VSS);
    }
}

uint64_t Avtp_Vss_GetField(Avtp_Vss_t* pdu, Avtp_VssFields_t field)
{
    return GET_FIELD(field);
}

void Avtp_Vss_SetField(Avtp_Vss_t* pdu,
                      Avtp_VssFields_t field, uint64_t value)
{
    SET_FIELD(field, value);
}

void Avtp_Vss_Pad(Avtp_Vss_t* vss_pdu, uint16_t vss_length) {

    uint8_t padSize;

    // Check if padding is required
    padSize = (AVTP_QUADLET_SIZE - (vss_length % AVTP_QUADLET_SIZE)) % AVTP_QUADLET_SIZE;
    if (vss_length % AVTP_QUADLET_SIZE) {
        memset(vss_pdu + vss_length, 0, padSize);
    }

    // Set the length and padding fields
    Avtp_Vss_SetField(vss_pdu, AVTP_VSS_FIELD_ACF_MSG_LENGTH,
                        (uint64_t) (vss_length+padSize)/AVTP_QUADLET_SIZE);
    Avtp_Vss_SetField(vss_pdu, AVTP_VSS_FIELD_PAD, padSize);
}

Avtp_AcfMsgType_t Avtp_Vss_GetAcfMsgType(Avtp_Vss_t* pdu) {
    return GET_FIELD(AVTP_VSS_FIELD_ACF_MSG_TYPE);
}

uint8_t Avtp_Vss_GetAcfMsgLength(Avtp_Vss_t* pdu) {
    return GET_FIELD(AVTP_VSS_FIELD_ACF_MSG_LENGTH);
}

uint8_t Avtp_Vss_GetPad(Avtp_Vss_t* pdu) {
    return GET_FIELD(AVTP_VSS_FIELD_PAD);
}

uint8_t Avtp_Vss_GetMtv(Avtp_Vss_t* pdu) {
    return GET_FIELD(AVTP_VSS_FIELD_MTV);
}

Vss_AddrMode_t Avtp_Vss_GetAddrMode(Avtp_Vss_t* pdu) {
    return GET_FIELD(AVTP_VSS_FIELD_ADDR_MODE);
}

Vss_OpCode_t Avtp_Vss_GetOpCode(Avtp_Vss_t* pdu) {
    return GET_FIELD(AVTP_VSS_FIELD_VSS_OP);
}

Vss_Datatype_t Avtp_Vss_GetDatatype(Avtp_Vss_t* pdu) {
    return GET_FIELD(AVTP_VSS_FIELD_VSS_DATATYPE);
}

uint64_t Avtp_Vss_GetMsgTimestamp(Avtp_Vss_t* pdu) {
    return GET_FIELD(AVTP_VSS_FIELD_MSG_TIMESTAMP);
}

void Avtp_Vss_GetVssPath(Avtp_Vss_t* pdu, VssPath_t* val) {

    uint8_t* vss_path_ptr = (uint8_t*) pdu + AVTP_VSS_FIXED_HEADER_LEN;

    // Check the used VSS addressing mode
    Vss_AddrMode_t addr_mode = Avtp_Vss_GetAddrMode(pdu);

    if (addr_mode == VSS_STATIC_ID_MODE) {
        val->vss_static_id_path = Avtp_BeToCpu32(*(uint32_t*)vss_path_ptr);
    } else if (addr_mode == VSS_INTEROP_MODE) {
        val->vss_interop_path.path_length = Avtp_BeToCpu16(*(uint16_t*)vss_path_ptr);
        memcpy(val->vss_interop_path.path, vss_path_ptr+2, val->vss_interop_path.path_length);
    }
}

uint16_t Avtp_Vss_CalcVssPathLength(Avtp_Vss_t* pdu) {

    uint8_t* vss_path_ptr = (uint8_t*) pdu + AVTP_VSS_FIXED_HEADER_LEN;

    // Check the used VSS addressing mode
    Vss_AddrMode_t addr_mode = Avtp_Vss_GetAddrMode(pdu);
    uint16_t path_length = 0;

    if (addr_mode == VSS_STATIC_ID_MODE) {
        path_length = 4;
    } else if (addr_mode == VSS_INTEROP_MODE) {
        path_length = Avtp_BeToCpu16(*(uint16_t*)vss_path_ptr) + 2;
    }
    return path_length;
}

uint8_t Avtp_Vss_GetVSSDataStringArrayLength(VssDataStringArray_t* str_array) {

    uint16_t total_length = str_array->data_length;
    uint8_t * vss_data_string_array_raw = str_array->data;
    uint16_t idx = 0, ptr_idx = 0;
    while (ptr_idx < total_length) {

        uint16_t str_length = Avtp_BeToCpu16(*(uint16_t*)(vss_data_string_array_raw+ptr_idx));
        ptr_idx += 2 + str_length;
        idx++;
    }

    return idx;
}

void Avtp_Vss_DeserializeStringArray(VssDataStringArray_t* vss_data_string_array,
                                     VssDataString_t* strings[],
                                     uint16_t num_strings) {

    uint16_t array_length = vss_data_string_array->data_length;
    uint8_t* array_data = vss_data_string_array->data;
    uint16_t idx = 0;

    for (int i = 0; i < num_strings; i++) {
        if(idx >= array_length) break;

        strings[i]->data_length = Avtp_BeToCpu16(*(uint16_t*)array_data);
        if (strings[i]->data != NULL) {
            memcpy(strings[i]->data, array_data+2, strings[i]->data_length);
        }
        array_data += 2 + strings[i]->data_length;
    }
}

void Avtp_Vss_GetVssData(Avtp_Vss_t* pdu, VssData_t* val) {

    // Get a pointer to the start of the VSS data
    uint8_t* vss_data_ptr = (uint8_t*) pdu + AVTP_VSS_FIXED_HEADER_LEN +
                                Avtp_Vss_CalcVssPathLength(pdu);
    Vss_Datatype_t datatype = Avtp_Vss_GetDatatype(pdu);

    uint32_t temp_float;
    uint64_t temp_double;

    // Check VSS Datatype
    switch (datatype) {
        case VSS_UINT8:
            val->data_uint8 = *vss_data_ptr;
            break;

        case VSS_INT8:
            val->data_int8 = *(int8_t*) vss_data_ptr;
            break;

        case VSS_UINT16:
            val->data_uint16 = Avtp_BeToCpu16(*(uint16_t*) vss_data_ptr);
            break;

        case VSS_INT16:
            val->data_int16 =  (int16_t) Avtp_BeToCpu16(*(uint16_t*) vss_data_ptr);
            break;

        case VSS_UINT32:
            val->data_uint32 = Avtp_BeToCpu32(*(uint32_t*) vss_data_ptr);
            break;

        case VSS_INT32:
            val->data_int32 = (int32_t) Avtp_BeToCpu32(*(uint32_t*) vss_data_ptr);
            break;

        case VSS_UINT64:
            val->data_uint64 = Avtp_BeToCpu64(*(uint64_t*) vss_data_ptr);
            break;

        case VSS_INT64:
            val->data_int64 = (int64_t) Avtp_BeToCpu64(*(uint64_t*) vss_data_ptr);
            break;

        case VSS_BOOL:
            val->data_bool = *vss_data_ptr;
            break;

        case VSS_FLOAT:
            temp_float =  Avtp_BeToCpu32(*(uint32_t*) vss_data_ptr);
            memcpy(&(val->data_float), &temp_float, sizeof(float));
            break;

        case VSS_DOUBLE:
            temp_double = Avtp_BeToCpu64(*(uint64_t*) vss_data_ptr);
            memcpy(&(val->data_double), &temp_double, sizeof(double));
            break;

        case VSS_STRING:
            val->data_string->data_length = Avtp_BeToCpu16(*(uint16_t*)vss_data_ptr);
            if (val->data_string->data != NULL) {
                memcpy(val->data_string->data, vss_data_ptr+2, val->data_string->data_length);
            }
            break;

        case VSS_UINT8_ARRAY:
            val->data_uint8_array->data_length = Avtp_BeToCpu16(*(uint16_t*)vss_data_ptr);
            if (val->data_uint8_array->data != NULL) {
                memcpy(val->data_uint8_array->data, vss_data_ptr+2, val->data_uint8_array->data_length);
            }
            break;

        case VSS_INT8_ARRAY:
            val->data_int8_array->data_length = Avtp_BeToCpu16(*(uint16_t*)vss_data_ptr);
            if (val->data_int8_array->data != NULL) {
                memcpy(val->data_int8_array->data, vss_data_ptr+2, val->data_int8_array->data_length);
            }
            break;

        case VSS_UINT16_ARRAY:
            val->data_uint16_array->data_length = Avtp_BeToCpu16(*(uint16_t*)vss_data_ptr);
            vss_data_ptr += 2;
            if (val->data_uint16_array->data != NULL) {
                for (int i = 0; i < val->data_uint16_array->data_length/2; i++) {
                    *(val->data_uint16_array->data + i) = Avtp_BeToCpu16(*((uint16_t*)vss_data_ptr+i));
                }
            }
            break;

        case VSS_INT16_ARRAY:
            val->data_int16_array->data_length = Avtp_BeToCpu16(*(uint16_t*)vss_data_ptr);
            vss_data_ptr += 2;
            if (val->data_int16_array->data != NULL) {
                for (int i = 0; i < val->data_int16_array->data_length/2; i++) {
                    *(val->data_int16_array->data + i) = (int16_t) Avtp_BeToCpu16(*((uint16_t*)vss_data_ptr+i));
                }
            }
            break;

        case VSS_UINT32_ARRAY:
            val->data_uint32_array->data_length = Avtp_BeToCpu16(*(uint16_t*)vss_data_ptr);
            vss_data_ptr += 2;
            if (val->data_uint32_array->data != NULL) {
                for (int i = 0; i < val->data_uint32_array->data_length/4; i++) {
                    *(val->data_uint32_array->data + i) = Avtp_BeToCpu32(*((uint32_t*)vss_data_ptr+i));
                }
            }
            break;

        case VSS_INT32_ARRAY:
            val->data_int32_array->data_length = Avtp_BeToCpu16(*(uint16_t*)vss_data_ptr);
            vss_data_ptr += 2;
            if (val->data_int32_array->data != NULL) {
                for (int i = 0; i < val->data_int32_array->data_length/4; i++) {
                    *(val->data_int32_array->data + i) = (int32_t) Avtp_BeToCpu32(*((uint32_t*)vss_data_ptr+i));
                }
            }
            break;

        case VSS_UINT64_ARRAY:
            val->data_uint64_array->data_length = Avtp_BeToCpu16(*(uint16_t*)vss_data_ptr);
            vss_data_ptr += 2;
            if (val->data_int64_array->data != NULL) {
                for (int i = 0; i < val->data_uint64_array->data_length/8; i++) {
                    *(val->data_uint64_array->data + i) = Avtp_BeToCpu64(*((uint64_t*)vss_data_ptr+i));
                }
            }
            break;

        case VSS_INT64_ARRAY:
            val->data_int64_array->data_length = Avtp_BeToCpu16(*(uint16_t*)vss_data_ptr);
            vss_data_ptr += 2;
            if (val->data_int64_array->data != NULL) {
                for (int i = 0; i < val->data_int64_array->data_length/8; i++) {
                    *(val->data_int64_array->data + i) = (int64_t) Avtp_BeToCpu64(*((uint64_t*)vss_data_ptr+i));
                }
            }
            break;

        case VSS_BOOL_ARRAY:
            val->data_bool_array->data_length = Avtp_BeToCpu16(*(uint16_t*)vss_data_ptr);
            if (val->data_bool_array->data != NULL) {
                memcpy(val->data_bool_array->data, vss_data_ptr+2, val->data_bool_array->data_length);
            }
            break;

        case VSS_FLOAT_ARRAY:
            val->data_float_array->data_length = Avtp_BeToCpu16(*(uint16_t*)vss_data_ptr);
            vss_data_ptr += 2;
            if (val->data_float_array->data != NULL) {
                for (int i = 0; i < val->data_float_array->data_length/4; i++) {
                    uint32_t temp_float = Avtp_BeToCpu32(*((uint32_t*)vss_data_ptr+i));
                    memcpy(val->data_float_array->data + i, &temp_float, sizeof(float));
                }
            }
            break;

        case VSS_DOUBLE_ARRAY:
            val->data_double_array->data_length = Avtp_BeToCpu16(*(uint16_t*)vss_data_ptr);
            vss_data_ptr += 2;
            if (val->data_double_array->data != NULL) {
                for (int i = 0; i < val->data_double_array->data_length/8; i++) {
                    uint64_t temp_double = Avtp_BeToCpu64(*((uint64_t*)vss_data_ptr+i));
                    memcpy(val->data_double_array->data + i, &temp_double, sizeof(double));
                }
            }
            break;

        case VSS_STRING_ARRAY:
            val->data_string_array->data_length = Avtp_BeToCpu16(*(uint16_t*)vss_data_ptr);
            vss_data_ptr += 2;
            if (val->data_double_array->data != NULL) {
                memcpy(val->data_string_array->data, vss_data_ptr, val->data_string_array->data_length);
            }
            break;

        default:
            break;

    }
}

void Avtp_Vss_SetAcfMsgType(Avtp_Vss_t* pdu, Avtp_AcfMsgType_t val) {
    SET_FIELD(AVTP_VSS_FIELD_ACF_MSG_TYPE, val);
}

void Avtp_Vss_SetAcfMsgLength(Avtp_Vss_t* pdu, uint8_t val) {
    SET_FIELD(AVTP_VSS_FIELD_ACF_MSG_LENGTH, val);
}

void Avtp_Vss_SetPad(Avtp_Vss_t* pdu, uint8_t val) {
    SET_FIELD(AVTP_VSS_FIELD_PAD, val);
}

void Avtp_Vss_SetMtv(Avtp_Vss_t* pdu, uint8_t val) {
    SET_FIELD(AVTP_VSS_FIELD_MTV, val);
}

void Avtp_Vss_SetAddrMode(Avtp_Vss_t* pdu, Vss_AddrMode_t val) {
    SET_FIELD(AVTP_VSS_FIELD_ADDR_MODE, val);
}

void Avtp_Vss_SetOpCode(Avtp_Vss_t* pdu, Vss_OpCode_t val) {
    SET_FIELD(AVTP_VSS_FIELD_VSS_OP, val);
}

void Avtp_Vss_SetDatatype(Avtp_Vss_t* pdu, Vss_Datatype_t val) {
    SET_FIELD(AVTP_VSS_FIELD_VSS_DATATYPE, val);
}

void Avtp_Vss_SetMsgTimestamp(Avtp_Vss_t* pdu, uint64_t val)  {
    SET_FIELD(AVTP_VSS_FIELD_MSG_TIMESTAMP, val);
 }

void Avtp_Vss_SetVssPath(Avtp_Vss_t* pdu, VssPath_t* val)
{
    uint8_t* vss_path_ptr = (uint8_t*) pdu + AVTP_VSS_FIXED_HEADER_LEN;

    // Check the used VSS addressing mode
    Vss_AddrMode_t addr_mode = Avtp_Vss_GetAddrMode(pdu);

    if (addr_mode == VSS_STATIC_ID_MODE) {
        uint32_t* static_id = (uint32_t*) vss_path_ptr;
        *static_id = Avtp_CpuToBe32(val->vss_static_id_path);
    } else if (addr_mode == VSS_INTEROP_MODE) {
        uint16_t* interop_path_len = (uint16_t*) vss_path_ptr;
        *interop_path_len = Avtp_CpuToBe16(val->vss_interop_path.path_length);
        memcpy(vss_path_ptr+2, val->vss_interop_path.path, val->vss_interop_path.path_length);
    }
}

void Avtp_Vss_SetVssData(Avtp_Vss_t* pdu, VssData_t* val) {

    // Get a pointer to the start of the VSS data
    uint8_t* vss_data_ptr = (uint8_t*) pdu + AVTP_VSS_FIXED_HEADER_LEN +
                                Avtp_Vss_CalcVssPathLength(pdu);
    Vss_Datatype_t datatype = Avtp_Vss_GetDatatype(pdu);

    uint32_t temp_float;
    uint64_t temp_double;

    // Check VSS Datatype
    switch (datatype) {
        case VSS_UINT8:
            *vss_data_ptr = val->data_uint8;
            break;

        case VSS_INT8:
            *(int8_t*) vss_data_ptr = val->data_int8;
            break;

        case VSS_UINT16:
            *(uint16_t*) vss_data_ptr = Avtp_CpuToBe16(val->data_uint16);
            break;

        case VSS_INT16:
            *(int16_t*) vss_data_ptr = (int16_t)Avtp_CpuToBe16((uint16_t)val->data_int16);
            break;

        case VSS_UINT32:
            *(uint32_t*) vss_data_ptr = Avtp_CpuToBe32(val->data_uint32);
            break;

        case VSS_INT32:
            *(int32_t*) vss_data_ptr = (int32_t)Avtp_CpuToBe32((uint32_t)val->data_int32);
            break;

        case VSS_UINT64:
            *(uint64_t*) vss_data_ptr = Avtp_CpuToBe64(val->data_uint64);
            break;

        case VSS_INT64:
            *(int64_t*) vss_data_ptr = (int64_t)Avtp_CpuToBe64((uint64_t)val->data_int64);
            break;

        case VSS_BOOL:
            *vss_data_ptr = val->data_bool;
            break;

        case VSS_FLOAT:
            temp_float = Avtp_CpuToBe32(*(uint32_t*)&(val->data_float));
            memcpy(vss_data_ptr, &temp_float, sizeof(float));
            break;

        case VSS_DOUBLE:
            temp_double = Avtp_CpuToBe64(*(uint64_t*)&(val->data_double));
            memcpy(vss_data_ptr, &temp_double, sizeof(double));
            break;

        case VSS_STRING:
            *(uint16_t*)vss_data_ptr = Avtp_CpuToBe16(val->data_string->data_length);
            memcpy(vss_data_ptr+2, val->data_string->data,
                    val->data_string->data_length);
            break;

        case VSS_UINT8_ARRAY:
            *(uint16_t*)vss_data_ptr = Avtp_CpuToBe16(val->data_uint8_array->data_length);
            memcpy(vss_data_ptr+2, val->data_uint8_array->data,
                    val->data_uint8_array->data_length);
            break;

        case VSS_INT8_ARRAY:
            *(uint16_t*)vss_data_ptr = Avtp_CpuToBe16(val->data_int8_array->data_length);
            memcpy(vss_data_ptr+2, val->data_int8_array->data,
                    val->data_int8_array->data_length);
            break;

        case VSS_UINT16_ARRAY:
            *(uint16_t*)vss_data_ptr = Avtp_CpuToBe16(val->data_uint16_array->data_length);
            for (int i = 0; i < val->data_uint16_array->data_length/2; i++) {
                *((uint16_t*)(vss_data_ptr+2) + i) = Avtp_CpuToBe16(*(val->data_uint16_array->data+i));
            }
            break;

        case VSS_INT16_ARRAY:
            *(uint16_t*)vss_data_ptr = Avtp_CpuToBe16(val->data_int16_array->data_length);
            for (int i = 0; i < val->data_int16_array->data_length/2; i++) {
                *((int16_t*)(vss_data_ptr+2) + i) = Avtp_CpuToBe16(*(val->data_int16_array->data+i));
            }
            break;

        case VSS_UINT32_ARRAY:
            *(uint16_t*)vss_data_ptr = Avtp_CpuToBe16(val->data_uint32_array->data_length);
            for (int i = 0; i < val->data_uint32_array->data_length/4; i++) {
                *((uint32_t*)(vss_data_ptr+2) + i) = Avtp_CpuToBe32(*(val->data_uint32_array->data+i));
            }
            break;

        case VSS_INT32_ARRAY:
            *(uint16_t*)vss_data_ptr = Avtp_CpuToBe16(val->data_int32_array->data_length);
            for (int i = 0; i < val->data_int32_array->data_length/4; i++) {
                *((int32_t*)(vss_data_ptr+2) + i) = Avtp_CpuToBe32(*(val->data_int32_array->data+i));
            }
            break;

        case VSS_UINT64_ARRAY:
            *(uint16_t*)vss_data_ptr = Avtp_CpuToBe16(val->data_uint64_array->data_length);
            for (int i = 0; i < val->data_uint64_array->data_length/8; i++) {
                *((uint64_t*)(vss_data_ptr+2) + i) = Avtp_CpuToBe64(*(val->data_uint64_array->data+i));
            }
            break;

        case VSS_INT64_ARRAY:
            *(uint16_t*)vss_data_ptr = Avtp_CpuToBe16(val->data_int64_array->data_length);
            for (int i = 0; i < val->data_int64_array->data_length/8; i++) {
                *((int64_t*)(vss_data_ptr+2) + i) = Avtp_CpuToBe64(*(val->data_int64_array->data+i));
            }
            break;

        case VSS_BOOL_ARRAY:
            *(uint16_t*)vss_data_ptr = Avtp_CpuToBe16(val->data_bool_array->data_length);
            memcpy(vss_data_ptr+2, val->data_bool_array->data,
                    val->data_bool_array->data_length);
            break;

        case VSS_FLOAT_ARRAY:
            *(uint16_t*)vss_data_ptr = Avtp_CpuToBe16(val->data_float_array->data_length);
            for (int i = 0; i < val->data_float_array->data_length/4; i++) {
                uint32_t temp_float = Avtp_CpuToBe32(*(uint32_t*)(val->data_float_array->data+i));
                memcpy((uint32_t*)(vss_data_ptr+2) + i, &temp_float, sizeof(float));
            }
            break;

        case VSS_DOUBLE_ARRAY:
            *(uint16_t*)vss_data_ptr = Avtp_CpuToBe16(val->data_double_array->data_length);
            for (int i = 0; i < val->data_double_array->data_length/8; i++) {
                uint64_t temp_double = Avtp_CpuToBe64(*(uint64_t*)(val->data_double_array->data+i));
                memcpy((uint64_t*)(vss_data_ptr+2) + i, &temp_double, sizeof(double));
            }
            break;

        case VSS_STRING_ARRAY:
            *(uint16_t*)vss_data_ptr = Avtp_CpuToBe16(val->data_string_array->data_length);
            vss_data_ptr += 2;
            memcpy(vss_data_ptr, val->data_string_array->data, val->data_string_array->data_length);
            break;

        default:
            break;

    }

}

void Avtp_Vss_SerializeStringArray(VssDataStringArray_t* vss_data_string_array,
                                   VssDataString_t* strings[], uint16_t num_strings) {

    uint16_t total_length = 0;
    uint8_t* data = vss_data_string_array->data;
    for (int i = 0; i < num_strings; i++) {
        total_length += strings[i]->data_length+2;

        *(uint16_t*)data = Avtp_CpuToBe16(strings[i]->data_length);
        memcpy(data+2, strings[i]->data, strings[i]->data_length);
        data += strings[i]->data_length+2;
    }
    vss_data_string_array->data_length = total_length;

}