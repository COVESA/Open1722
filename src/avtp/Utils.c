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

#ifdef LINUX_KERNEL1722
#include <linux/errno.h>
#else
#include <errno.h>
#include <stddef.h>
#endif


#include "avtp/Utils.h"
#include "avtp/Defines.h"
#include "avtp/Byteorder.h"

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

static int IsFieldDescriptorValid(const Avtp_FieldDescriptor_t* fieldDescriptor)
{
    return fieldDescriptor->bits <= 64 && fieldDescriptor->offset <= 31;
}

uint64_t Avtp_GetField(const Avtp_FieldDescriptor_t* fieldDescriptors,
        uint8_t numFields, uint8_t* pdu, uint8_t field)
{
    uint64_t result = 0;
    if (fieldDescriptors != NULL && pdu != NULL && field < numFields) {
        const Avtp_FieldDescriptor_t* fieldDescriptor = &fieldDescriptors[field];
        uint8_t quadletOffset = 0;
        uint8_t processedBits = 0;
        while (processedBits < fieldDescriptor->bits) {
            uint8_t quadletId = fieldDescriptor->quadlet + quadletOffset;
            uint8_t quadletBits;
            uint8_t quadletShift;
            if (processedBits == 0) {
                quadletBits = MIN(32 - fieldDescriptor->offset, fieldDescriptor->bits - processedBits);
                quadletShift = 32 - quadletBits - fieldDescriptor->offset;
            } else {
                quadletBits = MIN(32, fieldDescriptor->bits - processedBits);
                quadletShift = 32 - quadletBits;
            }
            uint32_t quadletMask = ((1ULL << quadletBits) - 1ULL) << quadletShift;
            uint32_t* quadletPtr = (uint32_t*)(pdu + quadletId * 4);
            uint32_t quadletHostOrder = Avtp_BeToCpu32(*quadletPtr);
            uint32_t partialValue = (quadletHostOrder & quadletMask) >> quadletShift;
            result |= (uint64_t)(partialValue) << (fieldDescriptor->bits - processedBits - quadletBits);

            quadletOffset += 1;
            processedBits += quadletBits;
        }
    }
    return result;
}

void Avtp_SetField(const Avtp_FieldDescriptor_t* fieldDescriptors,
        uint8_t numFields, uint8_t* pdu, uint8_t field, uint64_t value)
{
    if (fieldDescriptors != NULL && pdu != NULL && field < numFields) {
        const Avtp_FieldDescriptor_t* fieldDescriptor = &fieldDescriptors[field];
        uint8_t quadletOffset = 0;
        uint8_t processedBits = 0;
        while (processedBits < fieldDescriptor->bits) {
            uint8_t quadletId = fieldDescriptor->quadlet + quadletOffset;
            uint8_t quadletBits;
            uint8_t quadletShift;
            if (processedBits == 0) {
                quadletBits = MIN(32 - fieldDescriptor->offset, fieldDescriptor->bits - processedBits);
                quadletShift = 32 - quadletBits - fieldDescriptor->offset;
            } else {
                quadletBits = MIN(32, fieldDescriptor->bits - processedBits);
                quadletShift = 32 - quadletBits;
            }
            uint32_t partialValue = value >> (fieldDescriptor->bits - processedBits - quadletBits);
            uint32_t quadletMask = ((1ULL << quadletBits) - 1ULL) << quadletShift;
            uint32_t* quadletPtr = (uint32_t*)(pdu + quadletId * 4);
            uint32_t quadletHostOrder = Avtp_BeToCpu32(*quadletPtr);
            quadletHostOrder = (quadletHostOrder & ~quadletMask) | ((partialValue << quadletShift) & quadletMask);
            *quadletPtr = Avtp_CpuToBe32(quadletHostOrder);

            quadletOffset += 1;
            processedBits += quadletBits;
        }
    }
}
