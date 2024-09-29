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

/**
 * @file
 * This file contains the fields descriptions of COVESA VSS serailzation over
 * IEEE 1722 and functions to invoke corresponding parser and deparser.
 */

#pragma once

#include <stdint.h>

#include "avtp/Defines.h"
#include "avtp/acf/AcfCommon.h"

#define AVTP_VSS_FIXED_HEADER_LEN         (3 * AVTP_QUADLET_SIZE)
#define AVTP_ACF_TYPE_VSS           0x42

typedef struct {
    uint8_t header[AVTP_VSS_FIXED_HEADER_LEN];
    uint8_t payload[0];
} Avtp_Vss_t;

typedef enum vss_op_code {
    PUBLISH_CURRENT_VALUE   = 0,
    PUBLISH_TARGET_VALUE    = 1
} Vss_OpCode_t;

typedef enum vss_addr_mode {
    VSS_INTEROP_MODE    = 0,
    VSS_STATIC_ID_MODE  = 1
} Vss_AddrMode_t;

typedef enum vss_datatype {
    VSS_UINT8 = 0,
    VSS_INT8 = 0x1,
    VSS_UINT16 = 0x2,
    VSS_INT16 = 0x3,
    VSS_UINT32 = 0x4,
    VSS_INT32 = 0x5,
    VSS_UINT64 = 0x6,
    VSS_INT64 = 0x7,
    VSS_BOOL = 0x8,
    VSS_FLOAT = 0x9,
    VSS_DOUBLE = 0xA,
    VSS_STRING = 0xB,
    VSS_UINT8_ARRAY = 0x80,
    VSS_INT8_ARRAY = 0x81,
    VSS_UINT16_ARRAY = 0x82,
    VSS_INT16_ARRAY = 0x83,
    VSS_UINT32_ARRAY = 0x84,
    VSS_INT32_ARRAY = 0x85,
    VSS_UINT64_ARRAY = 0x86,
    VSS_INT64_ARRAY = 0x87,
    VSS_BOOL_ARRAY = 0x88,
    VSS_FLOAT_ARRAY = 0x89,
    VSS_DOUBLE_ARRAY = 0x8A,
    VSS_STRING_ARRAY = 0x8B,
} Vss_Datatype_t;

typedef enum  {

    /* ACF common header fields */
    AVTP_VSS_FIELD_ACF_MSG_TYPE = 0,
    AVTP_VSS_FIELD_ACF_MSG_LENGTH,

    /* ACF VSS header fields */
    AVTP_VSS_FIELD_PAD,
    AVTP_VSS_FIELD_MTV,
    AVTP_VSS_FIELD_ADDR_MODE,
    AVTP_VSS_FIELD_VSS_OP,
    AVTP_VSS_FIELD_VSS_DATATYPE,
    AVTP_VSS_FIELD_MSG_TIMESTAMP,

    /* Count number of fields for bound checks */
    AVTP_VSS_FIELD_MAX
} Avtp_VssFields_t;

typedef struct vss_interop_path {
    uint16_t path_length;
    char *path;
} VssInteropPath_t;    // Used for VSS Path in Interop Mode

typedef union vss_path {
    VssInteropPath_t vss_interop_path;
    uint32_t vss_static_id_path;
} VssPath_t;

typedef struct vss_data_string {
    uint16_t data_length;
    char* data;
} VssDataString_t;

typedef struct  vss_data_uint8_array {
    uint16_t data_length;
    uint8_t* data;
} VssDataUint8Array_t;

typedef struct  vss_data_int8_array {
    uint16_t data_length;
    int8_t* data;
} VssDataInt8Array_t;

typedef struct  vss_data_uint16_array {
    uint16_t data_length;
    uint16_t* data;
} VssDataUint16Array_t;

typedef struct  vss_data_int16_array {
    uint16_t data_length;
    int16_t* data;
} VssDataInt16Array_t;

typedef struct  vss_data_uint32_array {
    uint16_t data_length;
    uint32_t* data;
} VssDataUint32Array_t;

typedef struct  vss_data_int32_array {
    uint16_t data_length;
    int32_t* data;
} VssDataInt32Array_t;

typedef struct  vss_data_uint64_array {
    uint16_t data_length;
    uint64_t* data;
} VssDataUint64Array_t;

typedef struct  vss_data_int64_array {
    uint16_t data_length;
    int64_t* data;
} VssDataInt64Array_t;

typedef struct  vss_data_bool_array {
    uint16_t data_length;
    uint8_t* data;
} VssDataBoolArray_t;

typedef struct  vss_data_float_array {
    uint16_t data_length;
    float* data;
} VssDataFloatArray_t;

typedef struct  vss_data_double_array {
    uint16_t data_length;
    double* data;
} VssDataDoubleArray_t;

typedef struct  vss_data_string_array {
    uint16_t data_length;
    uint8_t* data;
} VssDataStringArray_t;

typedef union vss_data {
    uint8_t data_uint8;
    int8_t data_int8;
    uint16_t data_uint16;
    int16_t data_int16;
    uint32_t data_uint32;
    int32_t data_int32;
    uint64_t data_uint64;
    int64_t data_int64;
    uint8_t data_bool;
    float data_float;
    double data_double;
    VssDataString_t* data_string;
    VssDataUint8Array_t* data_uint8_array;
    VssDataInt8Array_t* data_int8_array;
    VssDataUint16Array_t* data_uint16_array;
    VssDataInt16Array_t* data_int16_array;
    VssDataUint32Array_t* data_uint32_array;
    VssDataInt32Array_t* data_int32_array;
    VssDataUint64Array_t* data_uint64_array;
    VssDataInt64Array_t* data_int64_array;
    VssDataBoolArray_t* data_bool_array;
    VssDataFloatArray_t* data_float_array;
    VssDataDoubleArray_t* data_double_array;
    VssDataStringArray_t* data_string_array;
} VssData_t;

/**
 * Initializes an ACF VSS PDU header as specified in the VSS - IEEE 1722
 * Mapping Specification.
 *
 * @param vss_pdu Pointer to the first bit of a 1722 ACF VSS PDU.
 */
void Avtp_Vss_Init(Avtp_Vss_t* vss_pdu);

/**
 * Returns the value of an an ACF VSS PDU field as specified in the
 * VSS - IEEE 1722 Mapping Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF VSS PDU.
 * @param field Specifies the position of the data field to be read
 * @returns Value of the specified field of the ACF VSS PDU
 */
uint64_t Avtp_Vss_GetField(Avtp_Vss_t* pdu, Avtp_VssFields_t field);

/**
 * Sets the value of an an ACF VSS PDU field as specified in the
 * VSS - IEEE 1722 Mapping Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF VSS PDU.
 * @param field Specifies the position of the data field to be read
 * @param value Value of the specified field
 */
void Avtp_Vss_SetField(Avtp_Vss_t* pdu, Avtp_VssFields_t field, uint64_t value);


/**
 * Finalizes the ACF VSS frame. This function will set the
 * length and pad fields while inserting the padded bytes.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF VSS PDU.
 * @param vss_length Length of the VSS frame including the header bytes.
 */
void Avtp_Vss_Pad(Avtp_Vss_t* pdu, uint16_t vss_length);

/* Getter and Setter Functions*/
Avtp_AcfMsgType_t Avtp_Vss_GetAcfMsgType(Avtp_Vss_t* pdu);
uint8_t Avtp_Vss_GetAcfMsgLength(Avtp_Vss_t* pdu);
uint8_t Avtp_Vss_GetPad(Avtp_Vss_t* pdu);
uint8_t Avtp_Vss_GetMtv(Avtp_Vss_t* pdu);
Vss_AddrMode_t Avtp_Vss_GetAddrMode(Avtp_Vss_t* pdu);
Vss_OpCode_t Avtp_Vss_GetOpCode(Avtp_Vss_t* pdu);
Vss_Datatype_t Avtp_Vss_GetDatatype(Avtp_Vss_t* pdu);
uint64_t Avtp_Vss_GetMsgTimestamp(Avtp_Vss_t* pdu);
void Avtp_Vss_GetVssPath(Avtp_Vss_t* pdu, VssPath_t* val);
void Avtp_Vss_GetVssData(Avtp_Vss_t* pdu, VssData_t* val);
uint8_t Avtp_Vss_GetVSSDataStringArrayLength(VssDataStringArray_t* str_array);
uint16_t Avtp_Vss_CalcVssPathLength (Avtp_Vss_t* pdu);
void Avtp_Vss_DeserializeStringArray(VssDataStringArray_t* vss_data_string_array,
                                     VssDataString_t* strings[],
                                     uint16_t num_strings);
void Avtp_Vss_SetAcfMsgType(Avtp_Vss_t* pdu, Avtp_AcfMsgType_t val);
void Avtp_Vss_SetAcfMsgLength(Avtp_Vss_t* pdu, uint8_t val);
void Avtp_Vss_SetPad(Avtp_Vss_t* pdu, uint8_t val);
void Avtp_Vss_SetMtv(Avtp_Vss_t* pdu, uint8_t val);
void Avtp_Vss_SetAddrMode(Avtp_Vss_t* pdu, Vss_AddrMode_t val);
void Avtp_Vss_SetOpCode(Avtp_Vss_t* pdu, Vss_OpCode_t val);
void Avtp_Vss_SetDatatype(Avtp_Vss_t* pdu, Vss_Datatype_t val);
void Avtp_Vss_SetMsgTimestamp(Avtp_Vss_t* pdu, uint64_t val);
void Avtp_Vss_SetVssPath(Avtp_Vss_t* pdu, VssPath_t* val);
void Avtp_Vss_SetVssData(Avtp_Vss_t* pdu, VssData_t* val);
void Avtp_Vss_SerializeStringArray(VssDataStringArray_t* vss_data_string_array,
                                   VssDataString_t* strings[],
                                   uint16_t num_strings);
