/*
 * Copyright (c) 2026, COVESA
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
 * This file contains the field descriptions of the IEEE 1722 AVTPDU
 * alternative header (4.7.6) for versions 0 and 1 and functions to invoke the
 * corresponding parser and deparser.
 *
 * The version 1 alternative header is modelled as the byte-aligned prefix
 * through ptp_grandmaster_identity (16 octets). The trailing reserved field
 * (12 bits at the head of the following quadlet) and the format fields that
 * follow it are described by the individual format tables. Format modules
 * declare complete descriptor tables per version in absolute coordinates,
 * reusing these positions for the alternative header fields. A consistency
 * test keeps the common entries of each format aligned with the tables here.
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
#include "avtp/CommonHeader.h"

#ifdef __cplusplus
extern "C" {
#endif

/* AVTPDU alternative header prefix length in octets (IEEE 1722-2025, 4.7.6). */
#define AVTPDU_AH_LEN_V0 (1 * AVTP_QUADLET_SIZE) /* 4 */
#define AVTPDU_AH_LEN_V1 (4 * AVTP_QUADLET_SIZE) /* 16 */

/**
 * View type for the AVTPDU alternative header prefix. The prefix is 4 octets
 * for version 0 (the common header) and 16 octets for version 1. Every accessor
 * dispatches on the version field of the common header.
 */
typedef struct {
    uint8_t header[AVTPDU_AH_LEN_V1];
    uint8_t payload[0];
} Avtp_AlternativeHeader_t;

/**
 * Enumeration over all IEEE 1722 AVTPDU alternative header fields. The naming
 * convention used is AVTPDU_<HEADER>_FIELD_<FIELD_NAME>. The trailing 12-bit
 * reserved field of version 1 is not listed here; it belongs to the
 * format-specific data area and is described by the format tables.
 */
typedef enum {
    AVTPDU_AH_FIELD_RESERVED1 = 0,
    AVTPDU_AH_FIELD_SEQUENCE_NUM,
    AVTPDU_AH_FIELD_PTP_GRANDMASTER_IDENTITY,

    /* Count number of fields for bound checks */
    AVTPDU_AH_FIELD_MAX
} Avtp_AlternativeHeaderField_t;

/**
 * These tables map all IEEE 1722 AVTPDU alternative header fields to a
 * descriptor, one table per version. The version 0 alternative header has no
 * fields beyond the common header, so all descriptors are zero.
 */
static const Avtp_FieldDescriptor_t Avtp_AhFieldDescV0[AVTPDU_AH_FIELD_MAX] = {
    [AVTPDU_AH_FIELD_RESERVED1] = {.quadlet = 0, .offset = 0, .bits = 0},
    [AVTPDU_AH_FIELD_SEQUENCE_NUM] = {.quadlet = 0, .offset = 0, .bits = 0},
    [AVTPDU_AH_FIELD_PTP_GRANDMASTER_IDENTITY] = {.quadlet = 0, .offset = 0, .bits = 0},
};

static const Avtp_FieldDescriptor_t Avtp_AhFieldDescV1[AVTPDU_AH_FIELD_MAX] = {
    [AVTPDU_AH_FIELD_RESERVED1] = {.quadlet = 0, .offset = 12, .bits = 20},
    [AVTPDU_AH_FIELD_SEQUENCE_NUM] = {.quadlet = 1, .offset = 0, .bits = 32},
    [AVTPDU_AH_FIELD_PTP_GRANDMASTER_IDENTITY] = {.quadlet = 2, .offset = 0, .bits = 64},
};

/**
 * Returns the raw version field of the AVTPDU common header. Values other than
 * 0 or 1 are reserved; the accessors treat anything other than 1 as version 0.
 */
OPEN1722_INLINE uint8_t Avtp_AlternativeHeader_GetVersion(const Avtp_AlternativeHeader_t *const pdu)
{
    return Avtp_CommonHeader_GetVersion((const Avtp_CommonHeader_t *)pdu);
}

/**
 * Returns the value of an AVTPDU alternative header field.
 *
 * @param pdu Pointer to the first bit of an 1722 AVTP PDU.
 * @param field Specifies the position of the data field to be read.
 * @returns The value of the specified field.
 */
OPEN1722_INLINE uint64_t Avtp_AlternativeHeader_GetField(const Avtp_AlternativeHeader_t *const pdu,
                                                         Avtp_AlternativeHeaderField_t field)
{
    const Avtp_FieldDescriptor_t *desc = Avtp_AlternativeHeader_GetVersion(pdu) == AVTP_VERSION_1
                                             ? Avtp_AhFieldDescV1
                                             : Avtp_AhFieldDescV0;
    return Avtp_GetField(desc, AVTPDU_AH_FIELD_MAX, (const uint8_t *)pdu, (uint8_t)field);
}

/**
 * Sets the value of an AVTPDU alternative header field. Fields absent from the
 * version in use are left untouched.
 *
 * @param pdu Pointer to the first bit of an 1722 AVTP PDU.
 * @param field Specifies the position of the data field to be written.
 * @param value The value to set.
 */
OPEN1722_INLINE void Avtp_AlternativeHeader_SetField(Avtp_AlternativeHeader_t *pdu,
                                                     Avtp_AlternativeHeaderField_t field,
                                                     uint64_t value)
{
    const Avtp_FieldDescriptor_t *desc = Avtp_AlternativeHeader_GetVersion(pdu) == AVTP_VERSION_1
                                             ? Avtp_AhFieldDescV1
                                             : Avtp_AhFieldDescV0;
    Avtp_SetField(desc, AVTPDU_AH_FIELD_MAX, (uint8_t *)pdu, (uint8_t)field, value);
}

/**
 * Returns the sequence_num field of the AVTPDU alternative header. The field
 * only exists in version 1; version 0 returns 0.
 */
OPEN1722_INLINE uint32_t
Avtp_AlternativeHeader_GetSequenceNum(const Avtp_AlternativeHeader_t *const pdu)
{
    return (uint32_t)Avtp_AlternativeHeader_GetField(pdu, AVTPDU_AH_FIELD_SEQUENCE_NUM);
}

/**
 * Sets the sequence_num field of the AVTPDU alternative header. The field only
 * exists in version 1; on version 0 this is a no-op.
 */
OPEN1722_INLINE void Avtp_AlternativeHeader_SetSequenceNum(Avtp_AlternativeHeader_t *pdu,
                                                           uint32_t value)
{
    Avtp_AlternativeHeader_SetField(pdu, AVTPDU_AH_FIELD_SEQUENCE_NUM, value);
}

/**
 * Returns the ptp_grandmaster_identity field of the AVTPDU alternative header.
 * The field only exists in version 1; version 0 returns 0.
 */
OPEN1722_INLINE uint64_t
Avtp_AlternativeHeader_GetPtpGrandmasterIdentity(const Avtp_AlternativeHeader_t *const pdu)
{
    return Avtp_AlternativeHeader_GetField(pdu, AVTPDU_AH_FIELD_PTP_GRANDMASTER_IDENTITY);
}

/**
 * Sets the ptp_grandmaster_identity field of the AVTPDU alternative header.
 * The field only exists in version 1; on version 0 this is a no-op.
 */
OPEN1722_INLINE void Avtp_AlternativeHeader_SetPtpGrandmasterIdentity(Avtp_AlternativeHeader_t *pdu,
                                                                      uint64_t value)
{
    Avtp_AlternativeHeader_SetField(pdu, AVTPDU_AH_FIELD_PTP_GRANDMASTER_IDENTITY, value);
}

#ifdef __cplusplus
}
#endif
