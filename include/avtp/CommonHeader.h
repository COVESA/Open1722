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
 * 1722 AVTP common header and performs all the necessary conversion from/to host/network
 * byte-order.
 */

#pragma once
#include "avtp/Inline.h"

#ifdef LINUX_KERNEL1722
#include <linux/string.h>
#else
#include <string.h>
#include <stdbool.h>
#endif

#include "avtp/Defines.h"
#include "avtp/Utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AVTPDU_COMMON_LEN (1 * AVTP_QUADLET_SIZE)

/* Version field values (IEEE 1722-2025, 4.7.3.4). */
#define AVTP_VERSION_0 0
#define AVTP_VERSION_1 1

typedef struct {
    uint8_t header[AVTPDU_COMMON_LEN];
    uint8_t payload[0];
} Avtp_CommonHeader_t;

/**
 * Enumeration over all IEEE 1722 common header fields. The naming convention
 * used is AVTPDU_<HEADER>_FIELD_<FIELD_NAME>.
 */
typedef enum Avtp_CommonHeaderField {
    /* Common AVTP header fields */
    AVTPDU_COMMON_FIELD_SUBTYPE = 0,
    AVTPDU_COMMON_FIELD_H,
    AVTPDU_COMMON_FIELD_VERSION,

    /* Count number of fields for bound checks */
    AVTPDU_COMMON_FIELD_MAX
} Avtp_CommonHeaderField_t;

typedef enum {
    AVTP_SUBTYPE_61883_IIDC = 0x0,
    AVTP_SUBTYPE_MMA_STREAM = 0x1,
    AVTP_SUBTYPE_AAF = 0x2,
    AVTP_SUBTYPE_CVF = 0x3,
    AVTP_SUBTYPE_CRF = 0x4,
    AVTP_SUBTYPE_TSCF = 0x5,
    AVTP_SUBTYPE_SVF = 0x6,
    AVTP_SUBTYPE_RVF = 0x7,
    AVTP_SUBTYPE_AEF_CONTINUOUS = 0x6E,
    AVTP_SUBTYPE_VSF_STREAM = 0x6F,
    AVTP_SUBTYPE_EF_STREAM = 0x7F,
    AVTP_SUBTYPE_NTSCF = 0x82,
    AVTP_SUBTYPE_IEEE_8021_MLAA = 0xEB,
    AVTP_SUBTYPE_ESCF = 0xEC,
    AVTP_SUBTYPE_EECF = 0xED,
    AVTP_SUBTYPE_AEF_DISCRETE = 0xEE,
    AVTP_SUBTYPE_ADP = 0xFA,
    AVTP_SUBTYPE_AECP = 0xFB,
    AVTP_SUBTYPE_ACMP = 0xFC,
    AVTP_SUBTYPE_MAAP = 0xFE,
    AVTP_SUBTYPE_EF_CONTROL = 0xFF,
} Avtp_AvtpSubtype_t;

#define GET_COMMON_HEADER_FIELD(field)                                                             \
    (Avtp_GetField(Avtp_CommonHeaderFieldDesc, AVTPDU_COMMON_FIELD_MAX, (const uint8_t *)pdu,      \
                   field))
#define SET_COMMON_HEADER_FIELD(field, value)                                                      \
    (Avtp_SetField(Avtp_CommonHeaderFieldDesc, AVTPDU_COMMON_FIELD_MAX, (uint8_t *)pdu, field,     \
                   value))

/**
 * This table maps all IEEE 1722 common header fields to a descriptor.
 */
static const Avtp_FieldDescriptor_t Avtp_CommonHeaderFieldDesc[AVTPDU_COMMON_FIELD_MAX] = {
    /* Common AVTP header */
    [AVTPDU_COMMON_FIELD_SUBTYPE] = {.quadlet = 0, .offset = 0, .bits = 8},
    [AVTPDU_COMMON_FIELD_H] = {.quadlet = 0, .offset = 8, .bits = 1},
    [AVTPDU_COMMON_FIELD_VERSION] = {.quadlet = 0, .offset = 9, .bits = 3},
};

/**
 * Returns true if the given AVTP version is present in the supported-version mask.
 *
 * @param versionMask Bit mask in which bit N marks version N as supported.
 * @param version Version number to test (0 to 7).
 * @returns true if the version is supported, false otherwise.
 */
OPEN1722_INLINE bool Avtp_Version_IsSupported(uint8_t versionMask, uint8_t version)
{
    if (version >= 8U) {
        return false;
    }
    return ((versionMask >> version) & 0x01U) != 0U;
}

/**
 * Returns the value of an an AVTP common header field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AVTP PDU.
 * @param field Specifies the position of the data field to be read
 * @returns This function the value of the specified PDU field
 */
OPEN1722_INLINE uint64_t Avtp_CommonHeader_GetField(const Avtp_CommonHeader_t *const pdu,
                                                    Avtp_CommonHeaderField_t field)
{
    return GET_COMMON_HEADER_FIELD(field);
}

/**
 * Returns the subtype field of the AVTP common header.
 */
OPEN1722_INLINE uint8_t Avtp_CommonHeader_GetSubtype(const Avtp_CommonHeader_t *const pdu)
{
    return (uint8_t)GET_COMMON_HEADER_FIELD(AVTPDU_COMMON_FIELD_SUBTYPE);
}

/**
 * Returns the h (header specific) bit of the AVTP common header. The meaning of this bit is defined
 * by the header/format: the common stream header (4.7.4) and common control header (4.7.5) define
 * it as sv (stream_id valid), while formats using the alternative header (4.7.6) define it
 * themselves or leave it reserved.
 */
OPEN1722_INLINE uint8_t Avtp_CommonHeader_GetH(const Avtp_CommonHeader_t *const pdu)
{
    return (uint8_t)GET_COMMON_HEADER_FIELD(AVTPDU_COMMON_FIELD_H);
}

/**
 * Returns the version field of the AVTP common header.
 */
OPEN1722_INLINE uint8_t Avtp_CommonHeader_GetVersion(const Avtp_CommonHeader_t *const pdu)
{
    return (uint8_t)GET_COMMON_HEADER_FIELD(AVTPDU_COMMON_FIELD_VERSION);
}

/**
 * Sets the value of an an AVTP common header field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AVTP PDU.
 * @param field Specifies the position of the data field to be read
 * @param value Pointer to location to store the value.
 */
OPEN1722_INLINE void Avtp_CommonHeader_SetField(Avtp_CommonHeader_t *pdu,
                                                Avtp_CommonHeaderField_t field, uint64_t value)
{
    SET_COMMON_HEADER_FIELD(field, value);
}

/**
 * Set the subtype field of the AVTP common header.
 */
OPEN1722_INLINE void Avtp_CommonHeader_SetSubtype(Avtp_CommonHeader_t *pdu, uint8_t value)
{
    SET_COMMON_HEADER_FIELD(AVTPDU_COMMON_FIELD_SUBTYPE, value);
}

/**
 * Sets the h (header specific) bit of the AVTP common header. See Avtp_CommonHeader_GetH for the
 * definition of this bit.
 */
OPEN1722_INLINE void Avtp_CommonHeader_SetH(Avtp_CommonHeader_t *pdu, uint8_t value)
{
    SET_COMMON_HEADER_FIELD(AVTPDU_COMMON_FIELD_H, value);
}

/**
 * Set the version field of the AVTP common header.
 */
OPEN1722_INLINE void Avtp_CommonHeader_SetVersion(Avtp_CommonHeader_t *pdu, uint8_t value)
{
    SET_COMMON_HEADER_FIELD(AVTPDU_COMMON_FIELD_VERSION, value);
}

#ifdef __cplusplus
}
#endif
