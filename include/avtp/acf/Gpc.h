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
 * This file contains the fields descriptions of the IEEE 1722-2016 ACF GPC PDUs and
 * functions to invoke corresponding parser and deparser.
 */
#pragma once
#include "avtp/Inline.h"

#ifdef LINUX_KERNEL1722
#include <linux/string.h>
#else
#include <string.h>
#include <stdbool.h>
#endif

#include "avtp/Utils.h"
#include "avtp/Defines.h"
#include "avtp/acf/AcfCommon.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AVTP_GPC_HEADER_LEN (2 * AVTP_QUADLET_SIZE)

#define GET_GPC_FIELD(field)                                                                       \
    (Avtp_GetField(Avtp_GpcFieldDesc, AVTP_GPC_FIELD_MAX, (uint8_t *)pdu, field))
#define SET_GPC_FIELD(field, value)                                                                \
    (Avtp_SetField(Avtp_GpcFieldDesc, AVTP_GPC_FIELD_MAX, (uint8_t *)pdu, field, value))

typedef struct {
    uint8_t header[AVTP_GPC_HEADER_LEN];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_Gpc_t;

/** Fields of ACF GPC PDU. */
typedef enum {

    /* ACF common header fields */
    AVTP_GPC_FIELD_ACF_MSG_TYPE = 0,
    AVTP_GPC_FIELD_ACF_MSG_LENGTH,

    /* ACF GPC header fields */
    AVTP_GPC_FIELD_GPC_MSG_ID,

    /* Count number of fields for bound checks */
    AVTP_GPC_FIELD_MAX
} Avtp_GpcFields_t;

/**
 * This table maps all IEEE 1722 ACF GPC header fields to a descriptor.
 */
static const Avtp_FieldDescriptor_t Avtp_GpcFieldDesc[AVTP_GPC_FIELD_MAX] = {
    /* ACF common header fields */
    [AVTP_GPC_FIELD_ACF_MSG_TYPE] = {.quadlet = 0, .offset = 0, .bits = 7},
    [AVTP_GPC_FIELD_ACF_MSG_LENGTH] = {.quadlet = 0, .offset = 7, .bits = 9},
    /* ACF GPC header fields */
    [AVTP_GPC_FIELD_GPC_MSG_ID] = {.quadlet = 0, .offset = 16, .bits = 48},
};

/**
 * Return the value of the GPC Message ID Field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF GPC PDU.
 * @returns The value of the GPC Message ID Field.
 */
OPEN1722_INLINE uint64_t Avtp_Gpc_GetGpcMsgId(const Avtp_Gpc_t *const pdu)
{
    return (uint64_t)GET_GPC_FIELD(AVTP_GPC_FIELD_GPC_MSG_ID);
}

/**
 * Set the value of an GPC Message ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF GPC PDU.
 * @param value Value to set the GPC Message ID field to.
 */
OPEN1722_INLINE void Avtp_Gpc_SetGpcMsgId(Avtp_Gpc_t *pdu, uint64_t value)
{
    SET_GPC_FIELD(AVTP_GPC_FIELD_GPC_MSG_ID, value);
}

/**
 * Returns pointer to payload of an ACF GPC frame.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF GPC PDU.
 * @return Pointer to ACF GPC frame payload
 */
OPEN1722_INLINE const uint8_t *Avtp_Gpc_GetPayload(const Avtp_Gpc_t *const pdu)
{
    return pdu->payload;
}

/**
 * Sets the payload in an ACF GPC frame.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF GPC PDU.
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload
 */
OPEN1722_INLINE void Avtp_Gpc_SetPayload(Avtp_Gpc_t *pdu, uint8_t *payload, uint16_t payload_length)
{
    memcpy(pdu->payload, payload, payload_length);
}

/**
 * Finalizes the ACF GPC frame. This function sets the quadlet-encoded length
 * field based on the given payload length and zeroes the trailing padding
 * octets.
 *
 * The ACF GPC format has no explicit pad field. The number of padding octets
 * required to reach an integer number of quadlets is determined by the total
 * payload length.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF GPC PDU.
 * @param payload_length Length of the payload.
 */
OPEN1722_INLINE void Avtp_Gpc_SetPayloadLength(Avtp_Gpc_t *pdu, uint16_t payload_length)
{
    uint16_t msgLenBytes = AVTP_GPC_HEADER_LEN + payload_length;
    uint8_t pad = (uint8_t)(4 - (msgLenBytes % 4)) % 4;
    if (pad > 0) {
        memset(pdu->payload + payload_length, 0, pad);
    }
    uint16_t msgLenQuadlets = (uint16_t)((msgLenBytes + pad) / 4);
    Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)pdu, msgLenQuadlets);
}

/*
 * Note: there is intentionally no Avtp_Gpc_GetPayloadLength() function.
 *
 * The ACF GPC header carries neither a pad field nor a payload-length field, so
 * the true payload length cannot be recovered from the wire format alone. The
 * acf_msg_length field only gives the total message length in quadlets (header
 * + payload + implicit padding), and the split between payload and padding is
 * not encoded anywhere. Callers that need the payload length must track it
 * themselves (e.g. from a higher-level protocol).
 */

/**
 * Initializes an ACF GPC PDU header as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF GPC PDU.
 */
OPEN1722_INLINE void Avtp_Gpc_Init(Avtp_Gpc_t *pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_Gpc_t));
        Avtp_AcfCommon_SetAcfMsgType((Avtp_AcfCommon_t *)pdu, AVTP_ACF_TYPE_GPC);
    }
}

/**
 * Copies the payload data and GPC message ID into the ACF GPC frame. This
 * function will also set the length field while inserting the padded bytes.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF GPC PDU.
 * @param gpc_msg_id GPC message ID
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload.
 */
OPEN1722_INLINE void Avtp_Gpc_CreateAcfMessage(Avtp_Gpc_t *pdu, uint64_t gpc_msg_id,
                                               uint8_t *payload, uint16_t payload_length)
{
    // Initialize the ACF GPC header
    Avtp_Gpc_Init(pdu);

    // Set the GPC message ID
    Avtp_Gpc_SetGpcMsgId(pdu, gpc_msg_id);

    // Copy the payload into the GPC PDU
    Avtp_Gpc_SetPayload(pdu, payload, payload_length);

    // Finalize the AVTP GPC Frame
    Avtp_Gpc_SetPayloadLength(pdu, payload_length);
}

/**
 * Checks if the ACF Gpc frame is valid by checking:
 *     1) if the length field of AVTP/ACF messages contains a value larger than the actual size of
 * the buffer that contains the AVTP message. 2) if other format specific invariants are not upheld
 * @param pdu Pointer to the first bit of an 1722 ACF Gpc PDU.
 * @param bufferSize Size of the buffer containing the ACF Gpc frame.
 * @return true if the ACF Gpc frame is valid, false otherwise.
 */
OPEN1722_INLINE bool Avtp_Gpc_IsValid(const Avtp_Gpc_t *const pdu, size_t bufferSize)
{
    if (pdu == NULL) {
        return false;
    }

    if (bufferSize < AVTP_GPC_HEADER_LEN) {
        return false;
    }

    if (Avtp_AcfCommon_GetAcfMsgType((const Avtp_AcfCommon_t *)pdu) != AVTP_ACF_TYPE_GPC) {
        return false;
    }

    uint16_t msg_length_bytes =
        Avtp_AcfCommon_GetAcfMsgLengthInBytes((const Avtp_AcfCommon_t *)pdu);
    if (msg_length_bytes > bufferSize) {
        return false;
    }

    if (msg_length_bytes < AVTP_GPC_HEADER_LEN) {
        return false;
    }

    return true;
}

#ifdef __cplusplus
}
#endif
