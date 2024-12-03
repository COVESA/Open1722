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
 * This file contains the parser for reading and writing data fields within IEEE
 * 1722 Base PDUs and perform all the necessary conversion from/to host/network
 * byte-order.
 */

#pragma once

#include <stdint.h>
#include "avtp/Defines.h"
#include "avtp/Byteorder.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Extracts a data field from a 1722 frame and handles necessary byte-order
 * conversions.
 *
 * @param pdu Pointer to the first bit of an 1722 PDU. This is typically an 1722
 * AVTP- or an ACF header.
 * @param field Specifies the position of the data field to be read
 * @returns This function returns the field value from the PDU.
 */
uint64_t Avtp_GetField(const Avtp_FieldDescriptor_t* fieldDescriptors,
        uint8_t numFields, uint8_t* pdu, uint8_t field);

/**
 * Sets a data field in a 1722 frame to a specified value and handles necessary
 * byte-order conversions.
 *
 * @param pdu Pointer to the first bit of a 1722 PDU. This is typically an AVTP-
 * or an ACF header.
 * @param field Specifies the position of the data field to be written
 * @param value The value to set.
 */
void Avtp_SetField(const Avtp_FieldDescriptor_t* fieldDescriptors,
        uint8_t numFields, uint8_t* pdu, uint8_t field, uint64_t value);

#ifdef __cplusplus
}
#endif
