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

#include <stdint.h>

#include "avtp/Defines.h"
#include "avtp/acf/AcfCommon.h"
#include "avtp/Utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GET_FLEXRAY_FIELD(field) \
    (Avtp_GetField(Avtp_FlexRayFieldDesc, AVTP_FLEXRAY_FIELD_MAX, (uint8_t *)pdu, field))
#define SET_FLEXRAY_FIELD(field, value) \
    (Avtp_SetField(Avtp_FlexRayFieldDesc, AVTP_FLEXRAY_FIELD_MAX, (uint8_t *)pdu, field, value))

/** Length of ACF FlexRay header. */
#define AVTP_FLEXRAY_HEADER_LEN (4 * AVTP_QUADLET_SIZE)

/** ACF FlexRay PDU. */
typedef struct {
    uint8_t header[AVTP_FLEXRAY_HEADER_LEN];
    uint8_t payload[0];
} Avtp_FlexRay_t;

/** Fields of ACF FlexRay PDU. */
typedef enum  {
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
static const Avtp_FieldDescriptor_t Avtp_FlexRayFieldDesc[AVTP_FLEXRAY_FIELD_MAX] =
    {
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
 * Return the value of an an ACF message type field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @returns Value of the ACF message type field.
 */
static inline uint8_t Avtp_FlexRay_GetAcfMsgType(const Avtp_FlexRay_t* const pdu) {
    return GET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_ACF_MSG_TYPE);
}

/** 
 * Return the value of an an ACF message length field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @returns Value of the ACF message length field.
 */
static inline uint16_t Avtp_FlexRay_GetAcfMsgLength(const Avtp_FlexRay_t* const pdu) {
    return GET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_ACF_MSG_LENGTH);
}

/**
 * Return the value of an an ACF FlexRay PDU padding field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @returns Value of the ACF FlexRay PDU padding field.
 */
static inline uint8_t Avtp_FlexRay_GetPad(const Avtp_FlexRay_t* const pdu) {
    return GET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_PAD);
}

/**
 * Return the value of an an ACF FlexRay PDU MTV field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @returns Value of the ACF FlexRay PDU MTV field.
 */
static inline uint8_t Avtp_FlexRay_GetMtv(const Avtp_FlexRay_t* const pdu) {
    return GET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_MTV);
}

/**
 * Return the value of an an ACF FlexRay PDU FR Bus ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @returns Value of the ACF FlexRay PDU FR Bus ID field.
 */
static inline uint8_t Avtp_FlexRay_GetFrBusId(const Avtp_FlexRay_t* const pdu) {
    return GET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_FR_BUS_ID);
}

/**
 * Return the value of an an ACF FlexRay PDU Channel field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @returns Value of the ACF FlexRay PDU Channel field.
 */
static inline uint8_t Avtp_FlexRay_GetChan(const Avtp_FlexRay_t* const pdu) {
    return GET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_CHAN);
}

/**
 * Return the value of an an ACF FlexRay PDU STR field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @returns Value of the ACF FlexRay PDU STR field.
 */
static inline uint8_t Avtp_FlexRay_GetStr(const Avtp_FlexRay_t* const pdu) {
    return GET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_STR);
}

/**
 * Return the value of an an ACF FlexRay PDU SYN field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @returns Value of the ACF FlexRay PDU SYN field.
 */
static inline uint8_t Avtp_FlexRay_GetSyn(const Avtp_FlexRay_t* const pdu) {
    return GET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_SYN);
}

/**
 * Return the value of an an ACF FlexRay PDU PRE field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @returns Value of the ACF FlexRay PDU PRE field.
 */
static inline uint8_t Avtp_FlexRay_GetPre(const Avtp_FlexRay_t* const pdu) {
    return GET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_PRE);
}

/**
 * Return the value of an an ACF FlexRay PDU NFI field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @returns Value of the ACF FlexRay PDU NFI field.
 */
static inline uint8_t Avtp_FlexRay_GetNfi(const Avtp_FlexRay_t* const pdu) {
    return GET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_NFI);
}

/**
 * Return the value of an an ACF FlexRay PDU Message Timestamp field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @returns Value of the ACF FlexRay PDU Message Timestamp field.
 */
static inline uint64_t Avtp_FlexRay_GetMessageTimestamp(const Avtp_FlexRay_t* const pdu) {
    return GET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_MESSAGE_TIMESTAMP);
}

/**
 * Return the value of an an ACF FlexRay PDU FR Frame ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @returns Value of the ACF FlexRay PDU FR Frame ID field.
 */
static inline uint16_t Avtp_FlexRay_GetFrFrameId(const Avtp_FlexRay_t* const pdu) {
    return GET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_FR_FRAME_ID);
}

/**
 * Return the value of an an ACF FlexRay PDU Cycle field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @returns Value of the ACF FlexRay PDU Cycle field.
 */
static inline uint8_t Avtp_FlexRay_GetCycle(const Avtp_FlexRay_t* const pdu) {
    return GET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_CYCLE);
}

/**
 * Set the value of an an ACF message type field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @param value Value to set the ACF message type field to.
 */
static inline void Avtp_FlexRay_SetAcfMsgType(Avtp_FlexRay_t* pdu, uint8_t value) {
    SET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_ACF_MSG_TYPE, value);
}

/**
 * Set the value of an an ACF message length field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @param value Value to set the ACF message length field to.
 */
static inline void Avtp_FlexRay_SetAcfMsgLength(Avtp_FlexRay_t* pdu, uint16_t value) {
    SET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_ACF_MSG_LENGTH, value);
}

/**
 * Set the value of an an ACF FlexRay PDU padding field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @param value Value to set the ACF FlexRay PDU padding field to.
 */
static inline void Avtp_FlexRay_SetPad(Avtp_FlexRay_t* pdu, uint8_t value) {
    SET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_PAD, value);
}

/**
 * Enable the MTV bit in an ACF FlexRay frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 */
static inline void Avtp_FlexRay_EnableMtv(Avtp_FlexRay_t* pdu) {
    SET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_MTV, 1);
}

/**
 * Disable the MTV bit in an ACF FlexRay frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 */
static inline void Avtp_FlexRay_DisableMtv(Avtp_FlexRay_t* pdu) {
    SET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_MTV, 0);
}

/**
 * Set the value of an an ACF FlexRay PDU FR Bus ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @param value Value to set the ACF FlexRay PDU FR Bus ID field to.
 */
static inline void Avtp_FlexRay_SetFrBusId(Avtp_FlexRay_t* pdu, uint8_t value) {
    SET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_FR_BUS_ID, value);
}

/**
 * Set the value of an an ACF FlexRay PDU Channel field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @param value Value to set the ACF FlexRay PDU Channel field to.
 */
static inline void Avtp_FlexRay_SetChan(Avtp_FlexRay_t* pdu, uint8_t value) {
    SET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_CHAN, value);
}

/**
 * Enable the STR bit in an ACF FlexRay frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 */
static inline void Avtp_FlexRay_EnableStr(Avtp_FlexRay_t* pdu) {
    SET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_STR, 1);
}

/**
 * Disable the STR bit in an ACF FlexRay frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 */
static inline void Avtp_FlexRay_DisableStr(Avtp_FlexRay_t* pdu) {
    SET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_STR, 0);
}

/**
 * Enable the SYN bit in an ACF FlexRay frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 */
static inline void Avtp_FlexRay_EnableSyn(Avtp_FlexRay_t* pdu) {
    SET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_SYN, 1);
}

/**
 * Disable the SYN bit in an ACF FlexRay frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 */
static inline void Avtp_FlexRay_DisableSyn(Avtp_FlexRay_t* pdu) {
    SET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_SYN, 0);
}

/**
 * Enable the PRE bit in an ACF FlexRay frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 */
static inline void Avtp_FlexRay_EnablePre(Avtp_FlexRay_t* pdu) {
    SET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_PRE, 1);
}

/**
 * Disable the PRE bit in an ACF FlexRay frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 */
static inline void Avtp_FlexRay_DisablePre(Avtp_FlexRay_t* pdu) {
    SET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_PRE, 0);
}

/**
 * Enable the NFI bit in an ACF FlexRay frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 */
static inline void Avtp_FlexRay_EnableNfi(Avtp_FlexRay_t* pdu) {
    SET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_NFI, 1);
}

/**
 * Disable the NFI bit in an ACF FlexRay frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 */
static inline void Avtp_FlexRay_DisableNfi(Avtp_FlexRay_t* pdu) {
    SET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_NFI, 0);
}

/**
 * Set the value of an an ACF FlexRay PDU Message Timestamp field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @param value Value to set the ACF FlexRay PDU Message Timestamp field to.
 */
static inline void Avtp_FlexRay_SetMessageTimestamp(Avtp_FlexRay_t* pdu, uint64_t value) {
    SET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_MESSAGE_TIMESTAMP, value);
}

/**
 * Set the value of an an ACF FlexRay PDU FR Frame ID field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @param value Value to set the ACF FlexRay PDU FR Frame ID field to.
 */
static inline void Avtp_FlexRay_SetFrFrameId(Avtp_FlexRay_t* pdu, uint16_t value) {
    SET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_FR_FRAME_ID, value);
}

/**
 * Set the value of an an ACF FlexRay PDU Cycle field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @param value Value to set the ACF FlexRay PDU Cycle field to.
 */
static inline void Avtp_FlexRay_SetCycle(Avtp_FlexRay_t* pdu, uint8_t value) {
    SET_FLEXRAY_FIELD(AVTP_FLEXRAY_FIELD_CYCLE, value);
}

/**
 * Checks if the ACF FlexRay frame is valid by checking:
 *     1) if the length field of AVTP/ACF messages contains a value larger than the actual size of the buffer that contains the AVTP message.
 *     2) if other format specific invariants are not upheld
 * @param pdu Pointer to the first bit of an 1722 ACF FlexRay PDU.
 * @param bufferSize Size of the buffer containing the ACF FlexRay frame.
 * @return true if the ACF FlexRay frame is valid, false otherwise.
 */
uint8_t Avtp_FlexRay_IsValid(const Avtp_FlexRay_t* const pdu, size_t bufferSize);

/**
 * Initializes an ACF FlexRay PDU.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF FlexRay PDU.
 */
static inline void Avtp_FlexRay_Init(Avtp_FlexRay_t *pdu)
{
    if (pdu != NULL)
    {
        memset(pdu, 0, sizeof(Avtp_FlexRay_t));
        Avtp_FlexRay_SetAcfMsgType(pdu, AVTP_ACF_TYPE_FLEXRAY);
    }
}

#ifdef __cplusplus
}
#endif
