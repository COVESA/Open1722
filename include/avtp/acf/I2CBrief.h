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
 * @file This file contains functions for de-/serialization of the ACF_I2C_BRIEF
 * message format. For details see IEEE Std. 1722-2025 chapter 9.4.17.
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

#define GET_I2C_BRIEF_FIELD(field)                                                                 \
    (Avtp_GetField(Avtp_I2CBriefFieldDesc, AVTP_I2C_BRIEF_FIELD_MAX, (const uint8_t *)pdu, field))
#define SET_I2C_BRIEF_FIELD(field, value)                                                          \
    (Avtp_SetField(Avtp_I2CBriefFieldDesc, AVTP_I2C_BRIEF_FIELD_MAX, (uint8_t *)pdu, field, value))

/**
 * Length of ACF_I2C_BRIEF message header in bytes.
 */
#define AVTP_I2C_BRIEF_HEADER_LEN (2 * AVTP_QUADLET_SIZE)

/**
 * ACF_I2C_BRIEF message structure suitable for in-place de-/serialization of fields
 * in the ACF_I2C_BRIEF message header.
 */
typedef struct {
    uint8_t header[AVTP_I2C_BRIEF_HEADER_LEN];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_I2CBrief_t;

/**
 * Fields encoded in the ACF_I2C_BRIEF header.
 */
typedef enum {
    /* ACF common header fields */
    AVTP_I2C_BRIEF_FIELD_ACF_MSG_TYPE = 0,
    AVTP_I2C_BRIEF_FIELD_ACF_MSG_LENGTH,
    /* ACF I2C header fields */
    AVTP_I2C_BRIEF_FIELD_PAD,
    AVTP_I2C_BRIEF_FIELD_MTV,
    AVTP_I2C_BRIEF_FIELD_RSV,
    AVTP_I2C_BRIEF_FIELD_I2C_BUS_ID,
    AVTP_I2C_BRIEF_FIELD_I2C_CODE,
    AVTP_I2C_BRIEF_FIELD_TRR,
    AVTP_I2C_BRIEF_FIELD_RESERVED,
    AVTP_I2C_BRIEF_FIELD_TRANSACTION_NUM,
    AVTP_I2C_BRIEF_FIELD_EVT,
    AVTP_I2C_BRIEF_FIELD_EXCEPTION_CODE,
    AVTP_I2C_BRIEF_FIELD_I2C_DATA,
    /* Count number of fields for bound checks */
    AVTP_I2C_BRIEF_FIELD_MAX
} Avtp_I2CBriefFields_t;

/**
 * This table describes all the offsets of the ACF_I2C_BRIEF header fields.
 */
static const Avtp_FieldDescriptor_t Avtp_I2CBriefFieldDesc[AVTP_I2C_BRIEF_FIELD_MAX] = {
    /* ACF common header fields */
    [AVTP_I2C_BRIEF_FIELD_ACF_MSG_TYPE] = {.quadlet = 0, .offset = 0, .bits = 7},
    [AVTP_I2C_BRIEF_FIELD_ACF_MSG_LENGTH] = {.quadlet = 0, .offset = 7, .bits = 9},
    /* ACF I2C header fields */
    [AVTP_I2C_BRIEF_FIELD_PAD] = {.quadlet = 0, .offset = 16, .bits = 2},
    [AVTP_I2C_BRIEF_FIELD_MTV] = {.quadlet = 0, .offset = 18, .bits = 1},
    [AVTP_I2C_BRIEF_FIELD_RSV] = {.quadlet = 0, .offset = 19, .bits = 2},
    [AVTP_I2C_BRIEF_FIELD_I2C_BUS_ID] = {.quadlet = 0, .offset = 21, .bits = 11},
    [AVTP_I2C_BRIEF_FIELD_I2C_CODE] = {.quadlet = 1, .offset = 0, .bits = 4},
    [AVTP_I2C_BRIEF_FIELD_TRR] = {.quadlet = 1, .offset = 4, .bits = 1},
    [AVTP_I2C_BRIEF_FIELD_RESERVED] = {.quadlet = 1, .offset = 5, .bits = 3},
    [AVTP_I2C_BRIEF_FIELD_TRANSACTION_NUM] = {.quadlet = 1, .offset = 8, .bits = 8},
    [AVTP_I2C_BRIEF_FIELD_EVT] = {.quadlet = 1, .offset = 16, .bits = 4},
    [AVTP_I2C_BRIEF_FIELD_EXCEPTION_CODE] = {.quadlet = 1, .offset = 20, .bits = 4},
    [AVTP_I2C_BRIEF_FIELD_I2C_DATA] = {.quadlet = 1, .offset = 24, .bits = 8},
};

/**
 * Return the value of an ACF padding field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF I2C PDU.
 * @returns Value of the ACF padding field.
 */
OPEN1722_INLINE uint8_t Avtp_I2CBrief_GetPad(const Avtp_I2CBrief_t *const pdu)
{
    return (uint8_t)GET_I2C_BRIEF_FIELD(AVTP_I2C_BRIEF_FIELD_PAD);
}

/**
 * Return the value of an ACF I2C PDU MTV field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF I2C PDU.
 * @returns Value of the ACF I2C PDU MTV field.
 */
OPEN1722_INLINE bool Avtp_I2CBrief_IsMtv(const Avtp_I2CBrief_t *const pdu)
{
    return (bool)GET_I2C_BRIEF_FIELD(AVTP_I2C_BRIEF_FIELD_MTV);
}

/**
 * Return the value of an ACF I2C Bus ID as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF I2C PDU.
 * @returns Value of the ACF I2C Bus ID.
 */
OPEN1722_INLINE uint16_t Avtp_I2CBrief_GetI2CBusId(const Avtp_I2CBrief_t *const pdu)
{
    return (uint16_t)GET_I2C_BRIEF_FIELD(AVTP_I2C_BRIEF_FIELD_I2C_BUS_ID);
}

/**
 * Return the value of an ACF I2C Code field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF I2C PDU.
 * @returns Value of the ACF I2C Code field.
 */
OPEN1722_INLINE uint8_t Avtp_I2CBrief_GetI2CCode(const Avtp_I2CBrief_t *const pdu)
{
    return (uint8_t)GET_I2C_BRIEF_FIELD(AVTP_I2C_BRIEF_FIELD_I2C_CODE);
}

/**
 * Return the value of an ACF I2C PDU TRR field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF I2C PDU.
 * @returns Value of the ACF I2C TRR field.
 */
OPEN1722_INLINE bool Avtp_I2CBrief_IsTrr(const Avtp_I2CBrief_t *const pdu)
{
    return (bool)GET_I2C_BRIEF_FIELD(AVTP_I2C_BRIEF_FIELD_TRR);
}

/**
 * Return the value of an I2C transaction number as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF I2C PDU.
 * @returns Value of the ACF I2C transaction number.
 */
OPEN1722_INLINE uint8_t Avtp_I2CBrief_GetTransactionNum(const Avtp_I2CBrief_t *const pdu)
{
    return (uint8_t)GET_I2C_BRIEF_FIELD(AVTP_I2C_BRIEF_FIELD_TRANSACTION_NUM);
}

/**
 * Return the value of an I2C event as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF I2C PDU.
 * @returns Value of the ACF I2C event.
 */
OPEN1722_INLINE uint8_t Avtp_I2CBrief_GetEvt(const Avtp_I2CBrief_t *const pdu)
{
    return (uint8_t)GET_I2C_BRIEF_FIELD(AVTP_I2C_BRIEF_FIELD_EVT);
}

/**
 * Return the value of an I2C exception code as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF I2C PDU.
 * @returns Value of the ACF I2C exception code.
 */
OPEN1722_INLINE uint8_t Avtp_I2CBrief_GetExceptionCode(const Avtp_I2CBrief_t *const pdu)
{
    return (uint8_t)GET_I2C_BRIEF_FIELD(AVTP_I2C_BRIEF_FIELD_EXCEPTION_CODE);
}

/**
 * Return the value of an I2C data as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF I2C PDU.
 * @returns Value of the ACF I2C data.
 */
OPEN1722_INLINE uint8_t Avtp_I2CBrief_GetI2CData(const Avtp_I2CBrief_t *const pdu)
{
    return (uint8_t)GET_I2C_BRIEF_FIELD(AVTP_I2C_BRIEF_FIELD_I2C_DATA);
}

/**
 * Set the value of an ACF padding field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF I2C PDU.
 * @param value Value to set the ACF padding field to.
 */
OPEN1722_INLINE void Avtp_I2CBrief_SetPad(Avtp_I2CBrief_t *pdu, uint8_t value)
{
    SET_I2C_BRIEF_FIELD(AVTP_I2C_BRIEF_FIELD_PAD, value);
}

/**
 * Set the MTV bit in an ACF I2C PDU as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF I2C PDU.
 * @param mtv Value to set the MTV bit to.
 */
OPEN1722_INLINE void Avtp_I2CBrief_SetMtv(Avtp_I2CBrief_t *pdu, bool mtv)
{
    SET_I2C_BRIEF_FIELD(AVTP_I2C_BRIEF_FIELD_MTV, mtv);
}

/**
 * Set the value of an ACF I2C Bus ID as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF I2C PDU.
 * @param value Value to set the ACF I2C Bus ID to.
 */
OPEN1722_INLINE void Avtp_I2CBrief_SetI2CBusId(Avtp_I2CBrief_t *pdu, uint16_t value)
{
    SET_I2C_BRIEF_FIELD(AVTP_I2C_BRIEF_FIELD_I2C_BUS_ID, value);
}

/**
 * Set the value of an ACF I2C Code field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF I2C PDU.
 * @param value Value to set the ACF I2C Code field to.
 */
OPEN1722_INLINE void Avtp_I2CBrief_SetI2CCode(Avtp_I2CBrief_t *pdu, uint8_t value)
{
    SET_I2C_BRIEF_FIELD(AVTP_I2C_BRIEF_FIELD_I2C_CODE, value);
}

/**
 * Set the TRR bit in an ACF I2C PDU as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF I2C PDU.
 * @param trr Value to set the TRR bit to.
 */
OPEN1722_INLINE void Avtp_I2CBrief_SetTrr(Avtp_I2CBrief_t *pdu, bool trr)
{
    SET_I2C_BRIEF_FIELD(AVTP_I2C_BRIEF_FIELD_TRR, trr);
}

/**
 * Set the value of an I2C transaction number as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF I2C PDU.
 * @param value Value to set the ACF I2C transaction number to.
 */
OPEN1722_INLINE void Avtp_I2CBrief_SetTransactionNum(Avtp_I2CBrief_t *pdu, uint8_t value)
{
    SET_I2C_BRIEF_FIELD(AVTP_I2C_BRIEF_FIELD_TRANSACTION_NUM, value);
}

/**
 * Set the value of an I2C event as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF I2C PDU.
 * @param value Value to set the ACF I2C event to.
 */
OPEN1722_INLINE void Avtp_I2CBrief_SetEvt(Avtp_I2CBrief_t *pdu, uint8_t value)
{
    SET_I2C_BRIEF_FIELD(AVTP_I2C_BRIEF_FIELD_EVT, value);
}

/**
 * Set the value of an I2C exception code as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF I2C PDU.
 * @param value Value to set the ACF I2C exception code to.
 */
OPEN1722_INLINE void Avtp_I2CBrief_SetExceptionCode(Avtp_I2CBrief_t *pdu, uint8_t value)
{
    SET_I2C_BRIEF_FIELD(AVTP_I2C_BRIEF_FIELD_EXCEPTION_CODE, value);
}

/**
 * Set the value of an I2C data field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF I2C PDU.
 * @param value Value to set the ACF I2C data field to.
 */
OPEN1722_INLINE void Avtp_I2CBrief_SetI2CData(Avtp_I2CBrief_t *pdu, uint8_t value)
{
    SET_I2C_BRIEF_FIELD(AVTP_I2C_BRIEF_FIELD_I2C_DATA, value);
}

/**
 * Initializes an ACF I2C PDU header as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF I2C PDU.
 */
OPEN1722_INLINE void Avtp_I2CBrief_Init(Avtp_I2CBrief_t *pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_I2CBrief_t));
        Avtp_AcfCommon_SetAcfMsgType((Avtp_AcfCommon_t *)pdu, AVTP_ACF_TYPE_I2C_BRIEF);
    }
}

/**
 * Creates an ACF I2C message with the specified parameters.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF I2C PDU.
 * @param i2c_code The I2C code to set.
 * @param trr The TRR bit value.
 * @param transaction_num The transaction number.
 * @param event The event.
 * @param exception_code The exception code.
 * @param i2c_data The I2C data.
 */
OPEN1722_INLINE void Avtp_I2CBrief_CreateAcfMessage(Avtp_I2CBrief_t *pdu, uint8_t i2c_code,
                                                    bool trr, uint8_t transaction_num,
                                                    uint8_t event, uint8_t exception_code,
                                                    uint8_t i2c_data)
{
    // Initialize the ACF I2C header
    Avtp_I2CBrief_Init(pdu);

    // Set the I2C Code, TRR, Transaction Number, Event, Exception Code and I2C Data
    Avtp_I2CBrief_SetI2CCode(pdu, i2c_code);
    Avtp_I2CBrief_SetTrr(pdu, trr);
    Avtp_I2CBrief_SetTransactionNum(pdu, transaction_num);
    Avtp_I2CBrief_SetEvt(pdu, event);
    Avtp_I2CBrief_SetExceptionCode(pdu, exception_code);
    Avtp_I2CBrief_SetI2CData(pdu, i2c_data);

    // Set the message length field in the ACF common header
    Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)pdu, AVTP_I2C_BRIEF_HEADER_LEN / 4);
}

/**
 * Checks if the ACF I2C frame is valid by checking:
 * 1) if the length field of AVTP/ACF messages contains a value larger than the actual size of
 * the buffer that contains the AVTP message.
 * 2) if other format specific invariants are not upheld
 * @param pdu Pointer to the first bit of an 1722 ACF I2C PDU.
 * @param bufferSize Size of the buffer containing the ACF I2C frame.
 * @return true if the ACF I2C frame is valid, false otherwise.
 */
OPEN1722_INLINE bool Avtp_I2CBrief_IsValid(const Avtp_I2CBrief_t *const pdu, size_t bufferSize)
{
    if (pdu == NULL) {
        return false;
    }

    if (bufferSize < AVTP_I2C_BRIEF_HEADER_LEN) {
        return false;
    }

    uint16_t msg_length_bytes =
        Avtp_AcfCommon_GetAcfMsgLengthInBytes((const Avtp_AcfCommon_t *)pdu);
    if (msg_length_bytes != AVTP_I2C_BRIEF_HEADER_LEN) {
        return false;
    }

    if (Avtp_AcfCommon_GetAcfMsgType((const Avtp_AcfCommon_t *)pdu) != AVTP_ACF_TYPE_I2C_BRIEF) {
        return false;
    }

    return true;
}

#ifdef __cplusplus
}
#endif
