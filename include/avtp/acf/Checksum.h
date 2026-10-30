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
 * @file This file contains functions for de-/serialization of the ACF_CHECKSUM
 * message format. For details see IEEE Std. 1722-2025, chapter 9.4.20.
 */

#pragma once
#include "avtp/Inline.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "avtp/Utils.h"
#include "avtp/Defines.h"
#include "avtp/acf/AcfCommon.h"

#define GET_CHECKSUM_FIELD(field)                                                                  \
    (Avtp_GetField(Avtp_ChecksumFieldDesc, AVTP_CHECKSUM_FIELD_MAX, (const uint8_t *)pdu, field))
#define SET_CHECKSUM_FIELD(field, value)                                                           \
    (Avtp_SetField(Avtp_ChecksumFieldDesc, AVTP_CHECKSUM_FIELD_MAX, (uint8_t *)pdu, field, value))

/**
 * Length of ACF_CHECKSUM message header in bytes.
 */
#define AVTP_CHECKSUM_HEADER_LEN (1 * AVTP_QUADLET_SIZE)

/**
 * ACF_CHECKSUM message structure suitable for in-place de-/serialization of fields
 * in the ACF_CHECKSUM message header.
 */
typedef struct {
    uint8_t header[AVTP_CHECKSUM_HEADER_LEN];
} __attribute__((packed)) Avtp_Checksum_t;

/**
 * Fields encoded in the ACF_CHECKSUM header.
 */
typedef enum {
    /* ACF common header fields */
    AVTP_CHECKSUM_FIELD_ACF_MSG_TYPE = 0,
    AVTP_CHECKSUM_FIELD_ACF_MSG_LENGTH,
    /* ACF_CHECKSUM header fields */
    AVTP_CHECKSUM_FIELD_CHECKSUM,
    /* Count number of fields for bound checks */
    AVTP_CHECKSUM_FIELD_MAX
} Avtp_ChecksumFields_t;

/**
 * This table describes all the offsets of the ACF_CHECKSUM header fields.
 */
static const Avtp_FieldDescriptor_t Avtp_ChecksumFieldDesc[AVTP_CHECKSUM_FIELD_MAX] = {
    /* ACF common header fields */
    [AVTP_CHECKSUM_FIELD_ACF_MSG_TYPE] = {.quadlet = 0, .offset = 0, .bits = 7},
    [AVTP_CHECKSUM_FIELD_ACF_MSG_LENGTH] = {.quadlet = 0, .offset = 7, .bits = 9},
    /* ACF_CHECKSUM header fields */
    [AVTP_CHECKSUM_FIELD_CHECKSUM] = {.quadlet = 0, .offset = 16, .bits = 16},
};

/**
 * Sets the Checksum field in an ACF_CHECKSUM message header.
 *
 * @param pdu Pointer to an ACF_CHECKSUM message.
 * @param checksum The value to set.
 */
OPEN1722_INLINE void Avtp_Checksum_SetChecksum(Avtp_Checksum_t *pdu, uint16_t checksum)
{
    SET_CHECKSUM_FIELD(AVTP_CHECKSUM_FIELD_CHECKSUM, checksum);
}

/**
 * Returns the value of the Checksum field from an ACF_CHECKSUM message header.
 *
 * @param pdu Pointer to an ACF_CHECKSUM message.
 * @returns The value of the Checksum field.
 */
OPEN1722_INLINE uint16_t Avtp_Checksum_GetChecksum(const Avtp_Checksum_t *const pdu)
{
    return (uint16_t)GET_CHECKSUM_FIELD(AVTP_CHECKSUM_FIELD_CHECKSUM);
}

/*
 * Note: there is intentionally no Avtp_Checksum_*Payload*() functions, as the ACF_CHECKSUM format
 * has no payload. The ACF_CHECKSUM message is used to carry a 16-bit checksum value, and does not
 * include any additional payload data.
 */

/**
 * Initializes an ACF CHECKSUM PDU header as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF CHECKSUM PDU.
 */
OPEN1722_INLINE void Avtp_Checksum_Init(Avtp_Checksum_t *pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_Checksum_t));
        Avtp_AcfCommon_SetAcfMsgType((Avtp_AcfCommon_t *)pdu, AVTP_ACF_TYPE_CHECKSUM);
    }
}

/**
 * Creates an ACF CHECKSUM PDU with the specified checksum.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CHECKSUM PDU.
 * @param checksum The checksum value to set.
 */
OPEN1722_INLINE void Avtp_Checksum_CreateAcfMessage(Avtp_Checksum_t *pdu, uint16_t checksum)
{
    // Initialize the ACF CHECKSUM header
    Avtp_Checksum_Init(pdu);

    // Set the ACF message length to 1 quadlet (the size of the ACF CHECKSUM header)
    Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)pdu,
                                   AVTP_CHECKSUM_HEADER_LEN / AVTP_QUADLET_SIZE);

    // Set the checksum
    Avtp_Checksum_SetChecksum(pdu, checksum);
}

/**
 * Checks if the ACF Checksum frame is valid by checking:
 *     1) if the length field of AVTP/ACF messages contains a value larger than the actual size of
 * the buffer that contains the AVTP message. 2) if other format specific invariants are not upheld
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CHECKSUM PDU.
 * @param bufferSize Size of the buffer containing the ACF CHECKSUM frame.
 * @return true if the ACF CHECKSUM frame is valid, false otherwise.
 */
OPEN1722_INLINE bool Avtp_Checksum_IsValid(const Avtp_Checksum_t *const pdu, size_t bufferSize)
{
    if (pdu == NULL) {
        return false;
    }

    if (bufferSize < AVTP_CHECKSUM_HEADER_LEN) {
        return false;
    }

    if (Avtp_AcfCommon_GetAcfMsgType((const Avtp_AcfCommon_t *)pdu) != AVTP_ACF_TYPE_CHECKSUM) {
        return false;
    }

    uint16_t msg_length_bytes =
        Avtp_AcfCommon_GetAcfMsgLengthInBytes((const Avtp_AcfCommon_t *)pdu);
    if (msg_length_bytes != AVTP_CHECKSUM_HEADER_LEN) {
        return false;
    }

    return true;
}

#ifdef __cplusplus
}
#endif
