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

#ifdef LINUX_KERNEL1722
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Swap byteorder of 16bit integer
 */
static inline uint16_t Avtp_Bswap16(uint16_t x)
{
    return    ((x & 0xff00u) >> 8u)
            | ((x & 0x00ffu) << 8u);
}

/**
 * Swap byteorder of 32bit integer
 */
static inline uint32_t Avtp_Bswap32(uint32_t x)
{
    return    ((x & 0xff000000u) >> 24u)
            | ((x & 0x00ff0000u) >>  8u)
            | ((x & 0x0000ff00u) <<  8u)
            | ((x & 0x000000ffu) << 24u);
}

/**
 * Swap byteorder of 64bit integer
 */
static inline uint64_t Avtp_Bswap64(uint64_t x)
{
    return    ((x & 0xff00000000000000u) >> 56u)
            | ((x & 0x00ff000000000000u) >> 40u)
            | ((x & 0x0000ff0000000000u) >> 24u)
            | ((x & 0x000000ff00000000u) >>  8u)
            | ((x & 0x00000000ff000000u) <<  8u)
            | ((x & 0x0000000000ff0000u) << 24u)
            | ((x & 0x000000000000ff00u) << 40u)
            | ((x & 0x00000000000000ffu) << 56u);
}

#if(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
/* System uses little-endian */
static inline uint16_t Avtp_CpuToLe16(uint16_t x) { return x; }
static inline uint32_t Avtp_CpuToLe32(uint32_t x) { return x; }
static inline uint64_t Avtp_CpuToLe64(uint64_t x) { return x; }
static inline uint16_t Avtp_CpuToBe16(uint16_t x) { return Avtp_Bswap16(x); }
static inline uint32_t Avtp_CpuToBe32(uint32_t x) { return Avtp_Bswap32(x); }
static inline uint64_t Avtp_CpuToBe64(uint64_t x) { return Avtp_Bswap64(x); }
static inline uint16_t Avtp_LeToCpu16(uint16_t x) { return x; }
static inline uint32_t Avtp_LeToCpu32(uint32_t x) { return x; }
static inline uint64_t Avtp_LeToCpu64(uint64_t x) { return x; }
static inline uint16_t Avtp_BeToCpu16(uint16_t x) { return Avtp_Bswap16(x); }
static inline uint32_t Avtp_BeToCpu32(uint32_t x) { return Avtp_Bswap32(x); }
static inline uint64_t Avtp_BeToCpu64(uint64_t x) { return Avtp_Bswap64(x); }
#else
/* System uses big-endian */
static inline uint16_t Avtp_CpuToLe16(uint16_t x) { return Avtp_Bswap16(x); }
static inline uint32_t Avtp_CpuToLe32(uint32_t x) { return Avtp_Bswap32(x); }
static inline uint64_t Avtp_CpuToLe64(uint64_t x) { return Avtp_Bswap64(x); }
static inline uint16_t Avtp_CpuToBe16(uint16_t x) { return x; }
static inline uint32_t Avtp_CpuToBe32(uint32_t x) { return x; }
static inline uint64_t Avtp_CpuToBe64(uint64_t x) { return x; }
static inline uint16_t Avtp_LeToCpu16(uint16_t x) { return Avtp_Bswap16(x); }
static inline uint32_t Avtp_LeToCpu32(uint32_t x) { return Avtp_Bswap32(x); }
static inline uint64_t Avtp_LeToCpu64(uint64_t x) { return Avtp_Bswap64(x); }
static inline uint16_t Avtp_BeToCpu16(uint16_t x) { return x; }
static inline uint32_t Avtp_BeToCpu32(uint32_t x) { return x; }
static inline uint64_t Avtp_BeToCpu64(uint64_t x) { return x; }
#endif

#ifdef __cplusplus
}
#endif
