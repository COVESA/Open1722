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
 *
 * The field-access engine is defined inline so that accessors using constant
 * descriptors and field indices can be folded into direct bit manipulation by
 * the compiler. The shared library exports the same functions as regular
 * symbols (see src/avtp/export/InlineExports.c) for FFI users.
 */

#pragma once

#include "avtp/Inline.h"
#include "avtp/Defines.h"
#include "avtp/Byteorder.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Returns the smaller of two octet values. Implementation detail of the field
 * access engine.
 */
static inline uint8_t Avtp_MinU8(uint8_t a, uint8_t b)
{
    return a < b ? a : b;
}

/**
 * Extracts a data field from a 1722 frame and handles necessary byte-order
 * conversions.
 *
 * @param fieldDescriptors Pointer to the field descriptor table.
 * @param numFields Number of entries in the descriptor table.
 * @param pdu Pointer to the first bit of an 1722 PDU. This is typically an 1722
 * AVTP- or an ACF header.
 * @param field Specifies the position of the data field to be read
 * @returns This function returns the field value from the PDU.
 */
OPEN1722_INLINE uint64_t Avtp_GetField(const Avtp_FieldDescriptor_t *fieldDescriptors,
                                       uint8_t numFields, const uint8_t *const pdu, uint8_t field)
{
    uint64_t result = 0;
    if (fieldDescriptors != NULL && pdu != NULL && field < numFields) {
        const Avtp_FieldDescriptor_t *fieldDescriptor = &fieldDescriptors[field];
        uint8_t quadletOffset = 0;
        uint8_t processedBits = 0;
        while (processedBits < fieldDescriptor->bits) {
            uint8_t quadletId = fieldDescriptor->quadlet + quadletOffset;
            uint8_t quadletBits;
            uint8_t quadletShift;
            if (processedBits == 0) {
                quadletBits = Avtp_MinU8((uint8_t)(32 - fieldDescriptor->offset),
                                         (uint8_t)(fieldDescriptor->bits - processedBits));
                quadletShift = (uint8_t)(32 - quadletBits - fieldDescriptor->offset);
            } else {
                quadletBits = Avtp_MinU8(32, (uint8_t)(fieldDescriptor->bits - processedBits));
                quadletShift = (uint8_t)(32 - quadletBits);
            }
            uint32_t quadletMask = (uint32_t)(((1ULL << quadletBits) - 1ULL) << quadletShift);
            const uint32_t *quadletPtr = (const uint32_t *)(pdu + quadletId * 4);
            uint32_t quadletHostOrder = Avtp_BeToCpu32(*quadletPtr);
            uint32_t partialValue = (quadletHostOrder & quadletMask) >> quadletShift;
            result |= (uint64_t)(partialValue)
                      << (fieldDescriptor->bits - processedBits - quadletBits);

            quadletOffset += 1;
            processedBits += quadletBits;
        }
    }
    return result;
}

/**
 * Sets a data field in a 1722 frame to a specified value and handles necessary
 * byte-order conversions.
 *
 * @param fieldDescriptors Pointer to the field descriptor table.
 * @param numFields Number of entries in the descriptor table.
 * @param pdu Pointer to the first bit of a 1722 PDU. This is typically an AVTP-
 * or an ACF header.
 * @param field Specifies the position of the data field to be written
 * @param value The value to set.
 */
OPEN1722_INLINE void Avtp_SetField(const Avtp_FieldDescriptor_t *fieldDescriptors,
                                   uint8_t numFields, uint8_t *pdu, uint8_t field, uint64_t value)
{
    if (fieldDescriptors != NULL && pdu != NULL && field < numFields) {
        const Avtp_FieldDescriptor_t *fieldDescriptor = &fieldDescriptors[field];
        uint8_t quadletOffset = 0;
        uint8_t processedBits = 0;
        while (processedBits < fieldDescriptor->bits) {
            uint8_t quadletId = fieldDescriptor->quadlet + quadletOffset;
            uint8_t quadletBits;
            uint8_t quadletShift;
            if (processedBits == 0) {
                quadletBits = Avtp_MinU8((uint8_t)(32 - fieldDescriptor->offset),
                                         (uint8_t)(fieldDescriptor->bits - processedBits));
                quadletShift = (uint8_t)(32 - quadletBits - fieldDescriptor->offset);
            } else {
                quadletBits = Avtp_MinU8(32, (uint8_t)(fieldDescriptor->bits - processedBits));
                quadletShift = (uint8_t)(32 - quadletBits);
            }
            uint32_t partialValue =
                (uint32_t)(value >> (fieldDescriptor->bits - processedBits - quadletBits));
            uint32_t quadletMask = (uint32_t)(((1ULL << quadletBits) - 1ULL) << quadletShift);
            uint32_t *quadletPtr = (uint32_t *)(pdu + quadletId * 4);
            uint32_t quadletHostOrder = Avtp_BeToCpu32(*quadletPtr);
            quadletHostOrder =
                (quadletHostOrder & ~quadletMask) | ((partialValue << quadletShift) & quadletMask);
            *quadletPtr = Avtp_CpuToBe32(quadletHostOrder);

            quadletOffset += 1;
            processedBits += quadletBits;
        }
    }
}

#ifdef __cplusplus
}
#endif
