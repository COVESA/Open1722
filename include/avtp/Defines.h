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

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#ifdef LINUX_KERNEL1722
#include <linux/types.h>
#else
#include <stdint.h>
#endif

/**
 * Max bits that the parser supports for a single data field within a 1722
 * frame. If for some niche use-case a data field bigger than 64bits must be
 * supported this data filed must be split into two or more fields.
 */
#define AVTP_FIELD_MAX_BITS 64

// Sizes of 1722 PDU formats
#define AVTP_QUADLET_SIZE 4

/**
 * This type describes the position of a data field within an 1722 frame.
 * A data field can be uniquely identified by
 *
 * (1) the number of quadlet the contains the first bit of the data field,
 * (2) the bit position within the quadlet (aka shift) and
 * (3) The size of the data field in bits (max 64 bits).
 */
typedef struct Avtp_FieldDescriptor {
    uint8_t quadlet;
    uint8_t offset;
    uint8_t bits;
} Avtp_FieldDescriptor_t;

#define TRUE 1
#define FALSE 0

#ifdef __cplusplus
}
#endif
