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
 * @file This files contains functions for de-/serialization of IEEE1722's ACF
 * FlexRay PDU formats. For details see IEEE Std. 1722-2016, chapter 9.4.2.
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

#define GET_FLEXRAY_FIELD(field)                                                                   \
    (Avtp_GetField(Avtp_FlexRayFieldDesc, AVTP_FLEXRAY_FIELD_MAX, (uint8_t *)pdu, field))
#define SET_FLEXRAY_FIELD(field, value)                                                            \
    (Avtp_SetField(Avtp_FlexRayFieldDesc, AVTP_FLEXRAY_FIELD_MAX, (uint8_t *)pdu, field, value))

/** Length of ACF FlexRay header. */
#define AVTP_FLEXRAY_HEADER_LEN (4 * AVTP_QUADLET_SIZE)

/** ACF FlexRay PDU. */
typedef struct {
    uint8_t header[AVTP_FLEXRAY_HEADER_LEN];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_FlexRay_t;

/** Fields of ACF FlexRay PDU. */
typedef enum {
    /* ACF common header fields */
    AVTP_FLEXRAY_FIELD_ACF_MSG_TYPE = 0,
    AVTP_FLEXRAY_FIELD_ACF_MSG_LENGTH,
    /* ACF FlexRay header fields */
    AVTP_FLEXRAY_FIELD_PAD,
    AVTP_FLEXRAY_FIELD_MTV,
    AVTP_FLEXRAY_FIELD_FR_BUS_ID,
    AVTP_FLEXRAY_FIELD_RESERVED,
    AVTP_FLEXRAY_FIELD_CHAN,
    AVTP_FLEXRAY_FIELD_STR,
    AVTP_FLEXRAY_FIELD_SYN,
    AVTP_FLEXRAY_FIELD_PRE,
    AVTP_FLEXRAY_FIELD_NFI,
    AVTP_FLEXRAY_FIELD_MESSAGE_TIMESTAMP,
    AVTP_FLEXRAY_FIELD_FR_FRAME_ID,
    AVTP_FLEXRAY_FIELD_RESERVED_2,
    AVTP_FLEXRAY_FIELD_CYCLE,
    /* Count number of fields for bound checks */
    AVTP_FLEXRAY_FIELD_MAX
} Avtp_FlexRayFields_t;

/**
 * This table describes all the offsets of the ACF FlexRay header fields.
 */
static const Avtp_FieldDescriptor_t Avtp_FlexRayFieldDesc[AVTP_FLEXRAY_FIELD_MAX] = {
    /* ACF common header fields */
    [AVTP_FLEXRAY_FIELD_ACF_MSG_TYPE] = {.quadlet = 0, .offset = 0, .bits = 7},
    [AVTP_FLEXRAY_FIELD_ACF_MSG_LENGTH] = {.quadlet = 0, .offset = 7, .bits = 9},
    /* ACF Flexray header fields */
    [AVTP_FLEXRAY_FIELD_PAD] = {.quadlet = 0, .offset = 16, .bits = 2},
    [AVTP_FLEXRAY_FIELD_MTV] = {.quadlet = 0, .offset = 18, .bits = 1},
    [AVTP_FLEXRAY_FIELD_FR_BUS_ID] = {.quadlet = 0, .offset = 19, .bits = 5},
    [AVTP_FLEXRAY_FIELD_RESERVED] = {.quadlet = 0, .offset = 24, .bits = 2},
    [AVTP_FLEXRAY_FIELD_CHAN] = {.quadlet = 0, .offset = 26, .bits = 2},
    [AVTP_FLEXRAY_FIELD_STR] = {.quadlet = 0, .offset = 28, .bits = 1},
    [AVTP_FLEXRAY_FIELD_SYN] = {.quadlet = 0, .offset = 29, .bits = 1},
    [AVTP_FLEXRAY_FIELD_PRE] = {.quadlet = 0, .offset = 30, .bits = 1},
    [AVTP_FLEXRAY_FIELD_NFI] = {.quadlet = 0, .offset = 31, .bits = 1},
    [AVTP_FLEXRAY_FIELD_MESSAGE_TIMESTAMP] = {.quadlet = 1, .offset = 0, .bits = 64},
    [AVTP_FLEXRAY_FIELD_FR_FRAME_ID] = {.quadlet = 3, .offset = 0, .bits = 11},
    [AVTP_FLEXRAY_FIELD_RESERVED_2] = {.quadlet = 3, .offset = 11, .bits = 15},
    [AVTP_FLEXRAY_FIELD_CYCLE] = {.quadlet = 3, .offset = 26, .bits = 6},
};

/**
 * Return the value of an an ACF message length field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @returns Value of the ACF message length field.
 */
OPEN1722_INLINE uint16_t Avtp_FlexRay_GetAcfMsgLength(const Avtp_FlexRay_t *const pdu)
{
    return Avtp_AcfCommon_GetAcfMsgLength((const Avtp_AcfCommon_t *)pdu);
}

/**
 * Return the value of an an ACF FlexRay PDU padding field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @returns Value of the ACF FlexRay PDU padding field.
 */
OPEN1722_INLINE uint8_t Avtp_FlexRay_GetPad(const Avtp_FlexRay_t *const pdu)
{
    return (uint8_t)GET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_PAD);
}

/**
 * Return the value of an an ACF FlexRay PDU MTV field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @returns Value of the ACF FlexRay PDU MTV field.
 */
OPEN1722_INLINE bool Avtp_FlexRay_IsMtv(const Avtp_FlexRay_t *const pdu)
{
    return (bool)GET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_MTV);
}

/**
 * Return the value of an an ACF FlexRay PDU FR Bus ID field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @returns Value of the ACF FlexRay PDU FR Bus ID field.
 */
OPEN1722_INLINE uint8_t Avtp_FlexRay_GetFrBusId(const Avtp_FlexRay_t *const pdu)
{
    return (uint8_t)GET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_FR_BUS_ID);
}

/**
 * Return the value of an an ACF FlexRay PDU Channel field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @returns Value of the ACF FlexRay PDU Channel field.
 */
OPEN1722_INLINE uint8_t Avtp_FlexRay_GetChan(const Avtp_FlexRay_t *const pdu)
{
    return (uint8_t)GET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_CHAN);
}

/**
 * Return the value of an an ACF FlexRay PDU STR field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @returns Value of the ACF FlexRay PDU STR field.
 */
OPEN1722_INLINE bool Avtp_FlexRay_IsStr(const Avtp_FlexRay_t *const pdu)
{
    return (bool)GET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_STR);
}

/**
 * Return the value of an an ACF FlexRay PDU SYN field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @returns Value of the ACF FlexRay PDU SYN field.
 */
OPEN1722_INLINE bool Avtp_FlexRay_IsSyn(const Avtp_FlexRay_t *const pdu)
{
    return (bool)GET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_SYN);
}

/**
 * Return the value of an an ACF FlexRay PDU PRE field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @returns Value of the ACF FlexRay PDU PRE field.
 */
OPEN1722_INLINE bool Avtp_FlexRay_IsPre(const Avtp_FlexRay_t *const pdu)
{
    return (bool)GET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_PRE);
}

/**
 * Return the value of an an ACF FlexRay PDU NFI field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @returns Value of the ACF FlexRay PDU NFI field.
 */
OPEN1722_INLINE bool Avtp_FlexRay_IsNfi(const Avtp_FlexRay_t *const pdu)
{
    return (bool)GET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_NFI);
}

/**
 * Return the value of an an ACF FlexRay PDU Message Timestamp field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @returns Value of the ACF FlexRay PDU Message Timestamp field.
 */
OPEN1722_INLINE uint64_t Avtp_FlexRay_GetMessageTimestamp(const Avtp_FlexRay_t *const pdu)
{
    return GET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_MESSAGE_TIMESTAMP);
}

/**
 * Return the value of an an ACF FlexRay PDU FR Frame ID field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @returns Value of the ACF FlexRay PDU FR Frame ID field.
 */
OPEN1722_INLINE uint16_t Avtp_FlexRay_GetFrFrameId(const Avtp_FlexRay_t *const pdu)
{
    return (uint16_t)GET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_FR_FRAME_ID);
}

/**
 * Return the value of an an ACF FlexRay PDU Cycle field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @returns Value of the ACF FlexRay PDU Cycle field.
 */
OPEN1722_INLINE uint8_t Avtp_FlexRay_GetCycle(const Avtp_FlexRay_t *const pdu)
{
    return (uint8_t)GET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_CYCLE);
}

/**
 * Set the value of an an ACF message length field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @param value Value to set the ACF message length field to.
 */
OPEN1722_INLINE void Avtp_FlexRay_SetAcfMsgLength(Avtp_FlexRay_t *pdu, uint16_t value)
{
    Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)pdu, value);
}

/**
 * Set the value of an an ACF FlexRay PDU padding field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @param value Value to set the ACF FlexRay PDU padding field to.
 */
OPEN1722_INLINE void Avtp_FlexRay_SetPad(Avtp_FlexRay_t *pdu, uint8_t value)
{
    SET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_PAD, value);
}

/**
 * Set the MTV bit in an ACF FlexRay frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @param mtv Value to set the MTV bit to.
 */
OPEN1722_INLINE void Avtp_FlexRay_SetMtv(Avtp_FlexRay_t *pdu, bool mtv)
{
    SET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_MTV, mtv);
}

/**
 * Set the value of an an ACF FlexRay PDU FR Bus ID field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @param value Value to set the ACF FlexRay PDU FR Bus ID field to.
 */
OPEN1722_INLINE void Avtp_FlexRay_SetFrBusId(Avtp_FlexRay_t *pdu, uint8_t value)
{
    SET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_FR_BUS_ID, value);
}

/**
 * Set the value of an an ACF FlexRay PDU Channel field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @param value Value to set the ACF FlexRay PDU Channel field to.
 */
OPEN1722_INLINE void Avtp_FlexRay_SetChan(Avtp_FlexRay_t *pdu, uint8_t value)
{
    SET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_CHAN, value);
}

/**
 * Set the STR bit in an ACF FlexRay frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @param str Value to set the STR bit to.
 */
OPEN1722_INLINE void Avtp_FlexRay_SetStr(Avtp_FlexRay_t *pdu, bool str)
{
    SET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_STR, str);
}

/**
 * Set the SYN bit in an ACF FlexRay frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @param syn Value to set the SYN bit to.
 */
OPEN1722_INLINE void Avtp_FlexRay_SetSyn(Avtp_FlexRay_t *pdu, bool syn)
{
    SET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_SYN, syn);
}

/**
 * Set the PRE bit in an ACF FlexRay frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @param pre Value to set the PRE bit to.
 */
OPEN1722_INLINE void Avtp_FlexRay_SetPre(Avtp_FlexRay_t *pdu, bool pre)
{
    SET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_PRE, pre);
}

/**
 * Set the NFI bit in an ACF FlexRay frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @param nfi Value to set the NFI bit to.
 */
OPEN1722_INLINE void Avtp_FlexRay_SetNfi(Avtp_FlexRay_t *pdu, bool nfi)
{
    SET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_NFI, nfi);
}

/**
 * Set the value of an an ACF FlexRay PDU Message Timestamp field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @param value Value to set the ACF FlexRay PDU Message Timestamp field to.
 */
OPEN1722_INLINE void Avtp_FlexRay_SetMessageTimestamp(Avtp_FlexRay_t *pdu, uint64_t value)
{
    SET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_MESSAGE_TIMESTAMP, value);
}

/**
 * Set the value of an an ACF FlexRay PDU FR Frame ID field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @param value Value to set the ACF FlexRay PDU FR Frame ID field to.
 */
OPEN1722_INLINE void Avtp_FlexRay_SetFrFrameId(Avtp_FlexRay_t *pdu, uint16_t value)
{
    SET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_FR_FRAME_ID, value);
}

/**
 * Set the value of an an ACF FlexRay PDU Cycle field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @param value Value to set the ACF FlexRay PDU Cycle field to.
 */
OPEN1722_INLINE void Avtp_FlexRay_SetCycle(Avtp_FlexRay_t *pdu, uint8_t value)
{
    SET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_CYCLE, value);
}

/**
 * Return the ACF message length in bytes.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @returns Length of the ACF message in bytes.
 */
OPEN1722_INLINE uint16_t Avtp_FlexRay_GetAcfMsgLengthInBytes(const Avtp_FlexRay_t *const pdu)
{
    return (uint16_t)Avtp_AcfCommon_GetAcfMsgLength((const Avtp_AcfCommon_t *)pdu) * 4;
}

/**
 * Returns pointer to payload of an ACF FlexRay frame.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @return Pointer to ACF FlexRay frame payload
 */
OPEN1722_INLINE const uint8_t *Avtp_FlexRay_GetPayload(const Avtp_FlexRay_t *const pdu)
{
    return pdu->payload;
}

/**
 * Sets the FlexRay payload in an ACF FlexRay frame.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload
 */
OPEN1722_INLINE void Avtp_FlexRay_SetPayload(Avtp_FlexRay_t *pdu, uint8_t *payload,
                                             uint16_t payload_length)
{
    memcpy(pdu->payload, payload, payload_length);
}

/**
 * Finalizes the ACF FlexRay frame. This function will set the length and pad
 * fields while inserting the padded bytes. This will also set padding bytes to
 * zero if the payload length is not a multiple of 4 to avoid leaking information.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @param payload_length Length of the FlexRay frame payload.
 */
OPEN1722_INLINE void Avtp_FlexRay_SetPayloadLength(Avtp_FlexRay_t *pdu, uint16_t payload_length)
{
    uint16_t msgLenBytes = AVTP_FLEXRAY_HEADER_LEN + payload_length;
    uint8_t pad = (uint8_t)(4 - (msgLenBytes % 4)) % 4;
    if (pad > 0) {
        memset(pdu->payload + payload_length, 0, pad);
    }
    uint16_t msgLenQuadlets = (uint16_t)((msgLenBytes + pad) / 4);
    Avtp_FlexRay_SetPad(pdu, pad);
    Avtp_FlexRay_SetAcfMsgLength(pdu, msgLenQuadlets);
}

/**
 * Returns the length of the FlexRay payload without the padding bytes and the
 * header length of the encapsulating ACF Frame.
 *
 * Precondition: the caller must have validated the PDU with
 * Avtp_FlexRay_IsValid(). This function performs no further bounds checking
 * and assumes those invariants already hold.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @return  Length of FlexRay payload in bytes
 */
OPEN1722_INLINE uint8_t Avtp_FlexRay_GetPayloadLength(const Avtp_FlexRay_t *const pdu)
{
    uint8_t pad_length = Avtp_FlexRay_GetPad(pdu);
    uint16_t acf_length_bytes = Avtp_FlexRay_GetAcfMsgLengthInBytes(pdu);
    return (uint8_t)(acf_length_bytes - AVTP_FLEXRAY_HEADER_LEN - pad_length);
}

/**
 * Initializes an ACF FlexRay PDU.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF FlexRay PDU.
 */
OPEN1722_INLINE void Avtp_FlexRay_Init(Avtp_FlexRay_t *pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_FlexRay_t));
        Avtp_AcfCommon_SetAcfMsgType((Avtp_AcfCommon_t *)pdu, AVTP_ACF_TYPE_FLEXRAY);
    }
}

/**
 * Copies the payload data, FR frame ID and cycle into the ACF FlexRay frame.
 * This function will also set the length and pad fields while inserting the
 * padded bytes.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @param frame_id FR frame ID
 * @param cycle Cycle number
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload.
 */
OPEN1722_INLINE void Avtp_FlexRay_CreateAcfMessage(Avtp_FlexRay_t *pdu, uint16_t frame_id,
                                                   uint8_t cycle, uint8_t *payload,
                                                   uint16_t payload_length)
{
    // Initialize the ACF FlexRay header
    Avtp_FlexRay_Init(pdu);

    // Set the FR frame ID and cycle
    Avtp_FlexRay_SetFrFrameId(pdu, frame_id);
    Avtp_FlexRay_SetCycle(pdu, cycle);

    // Copy the payload into the FlexRay PDU
    Avtp_FlexRay_SetPayload(pdu, payload, payload_length);

    // Finalize the AVTP FlexRay Frame
    Avtp_FlexRay_SetPayloadLength(pdu, payload_length);
}

/**
 * Checks if the ACF FlexRay frame is valid by checking:
 *     1) if the length field of AVTP/ACF messages contains a value larger than the actual size of
 * the buffer that contains the AVTP message. 2) if other format specific invariants are not upheld
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @param bufferSize Size of the buffer containing the ACF FlexRay frame.
 * @return true if the ACF FlexRay frame is valid, false otherwise.
 */
OPEN1722_INLINE bool Avtp_FlexRay_IsValid(const Avtp_FlexRay_t *const pdu, size_t bufferSize)
{
    if (pdu == NULL) {
        return false;
    }

    if (bufferSize < AVTP_FLEXRAY_HEADER_LEN) {
        return false;
    }

    if (Avtp_AcfCommon_GetAcfMsgType((const Avtp_AcfCommon_t *)pdu) != AVTP_ACF_TYPE_FLEXRAY) {
        return false;
    }

    // Avtp_FlexRay_GetAcfMsgLength returns quadlets. Convert the length field to octets.
    uint16_t msg_length_bytes = (uint16_t)Avtp_FlexRay_GetAcfMsgLength(pdu) * 4;
    if (msg_length_bytes > bufferSize) {
        return false;
    }

    /* FlexRay payload-length invariant: the encoded message length must also
     * accommodate header + declared padding so the payload computation in
     * Avtp_FlexRay_GetPayloadLength() doesn't underflow. */
    uint8_t pad_length = Avtp_FlexRay_GetPad(pdu);
    uint16_t header_and_pad = (uint16_t)AVTP_FLEXRAY_HEADER_LEN + pad_length;
    if (msg_length_bytes < header_and_pad) {
        return false;
    }
    uint16_t payload_length = msg_length_bytes - header_and_pad;
    if (payload_length > 254u) {
        return false;
    }
    return true;
}

#ifdef __cplusplus
}
#endif
