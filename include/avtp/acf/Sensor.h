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
 * This file contains the fields descriptions of the IEEE 1722 ACF Sensor PDUs and
 * functions to invoke corresponding parser and deparser.
 */

#pragma once

#include <string.h>

#include "avtp/Defines.h"
#include "avtp/acf/AcfCommon.h"
#include "avtp/Utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AVTP_SENSOR_HEADER_LEN         (3 * AVTP_QUADLET_SIZE)

#define GET_SENSOR_FIELD(field) \
        (Avtp_GetField(Avtp_SensorFieldDesc, AVTP_SENSOR_FIELD_MAX, (uint8_t*)pdu, field))
#define SET_SENSOR_FIELD(field, value) \
        (Avtp_SetField(Avtp_SensorFieldDesc, AVTP_SENSOR_FIELD_MAX, (uint8_t*)pdu, field, value))

typedef struct {
    uint8_t header[AVTP_SENSOR_HEADER_LEN];
    uint8_t payload[0];
} Avtp_Sensor_t;

typedef enum {

    /* ACF common header fields */
    AVTP_SENSOR_FIELD_ACF_MSG_TYPE = 0,
    AVTP_SENSOR_FIELD_ACF_MSG_LENGTH,

    /* ACF Sensor header fields */
    AVTP_SENSOR_FIELD_MTV,
    AVTP_SENSOR_FIELD_NUM_SENSOR,
    AVTP_SENSOR_FIELD_SZ,
    AVTP_SENSOR_FIELD_SENSOR_GROUP,
    AVTP_SENSOR_FIELD_MESSAGE_TIMESTAMP,

    /* Count number of fields for bound checks */
    AVTP_SENSOR_FIELD_MAX
} Avtp_SensorFields_t;

/**
 * This table maps all IEEE 1722 ACF Sensor header fields to a descriptor.
 */
static const Avtp_FieldDescriptor_t Avtp_SensorFieldDesc[AVTP_SENSOR_FIELD_MAX] =
{
    /* ACF common header fields */
    [AVTP_SENSOR_FIELD_ACF_MSG_TYPE]        = { .quadlet = 0, .offset =  0, .bits = 7 },
    [AVTP_SENSOR_FIELD_ACF_MSG_LENGTH]      = { .quadlet = 0, .offset =  7, .bits = 9 },
    /* ACF Sensor header fields */
    [AVTP_SENSOR_FIELD_MTV]                 = { .quadlet = 0, .offset = 16, .bits = 1 },
    [AVTP_SENSOR_FIELD_NUM_SENSOR]          = { .quadlet = 0, .offset = 17, .bits = 7 },
    [AVTP_SENSOR_FIELD_SZ]                  = { .quadlet = 0, .offset = 24, .bits = 2 },
    [AVTP_SENSOR_FIELD_SENSOR_GROUP]        = { .quadlet = 0, .offset = 26, .bits = 6 },
    [AVTP_SENSOR_FIELD_MESSAGE_TIMESTAMP]   = { .quadlet = 1, .offset =  0, .bits = 64 },
};

/**
 * Return the value of an an ACF Sensor ACF message type field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF Sensor PDU.
 * @returns Value of the ACF message type field.
 */
static inline uint8_t Avtp_Sensor_GetAcfMsgType(const Avtp_Sensor_t* const pdu) {
    return GET_SENSOR_FIELD(AVTP_SENSOR_FIELD_ACF_MSG_TYPE);
}

/**
 * Return the value of an an ACF Sensor ACF message length field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF Sensor PDU.
 * @returns Value of the ACF message length field.
 */
static inline uint16_t Avtp_Sensor_GetAcfMsgLength(const Avtp_Sensor_t* const pdu) {
    return GET_SENSOR_FIELD(AVTP_SENSOR_FIELD_ACF_MSG_LENGTH);
}

/**
 * Return the value of an an ACF Sensor MTV field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Sensor PDU.
 * @returns Value of the MTV field.
 */
static inline uint8_t Avtp_Sensor_GetMtv(const Avtp_Sensor_t* const pdu) {
    return GET_SENSOR_FIELD(AVTP_SENSOR_FIELD_MTV);
}

/**
 * Return the value of an an ACF Sensor Num Sensor field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Sensor PDU.
 * @returns Value of the Num Sensor field.
 */
static inline uint8_t Avtp_Sensor_GetNumSensor(const Avtp_Sensor_t* const pdu) {
    return GET_SENSOR_FIELD(AVTP_SENSOR_FIELD_NUM_SENSOR);
}

/**
 * Return the value of an an ACF Sensor Sz field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Sensor PDU.
 * @returns Value of the Sz field.
 */
static inline uint8_t Avtp_Sensor_GetSz(const Avtp_Sensor_t* const pdu) {
    return GET_SENSOR_FIELD(AVTP_SENSOR_FIELD_SZ);
}

/**
 * Return the value of an an ACF Sensor Sensor Group field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Sensor PDU.
 * @returns Value of the Sensor Group field.
 */
static inline uint8_t Avtp_Sensor_GetSensorGroup(const Avtp_Sensor_t* const pdu) {
    return GET_SENSOR_FIELD(AVTP_SENSOR_FIELD_SENSOR_GROUP);
}

/**
 * Return the value of an an ACF Sensor Message Timestamp field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Sensor PDU.
 * @returns Value of the Message Timestamp field.
 */
static inline uint64_t Avtp_Sensor_GetMessageTimestamp(const Avtp_Sensor_t* const pdu) {
    return GET_SENSOR_FIELD(AVTP_SENSOR_FIELD_MESSAGE_TIMESTAMP);
}

/**
 * Set the value of an an ACF Sensor ACF message type field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Sensor PDU.
 * @param value Value to set the ACF message type field.
 */
static inline void Avtp_Sensor_SetAcfMsgType(Avtp_Sensor_t* pdu, uint8_t value) {
    SET_SENSOR_FIELD(AVTP_SENSOR_FIELD_ACF_MSG_TYPE, value);
}

/**
 * Set the value of an an ACF Sensor ACF message length field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Sensor PDU.
 * @param value Value to set the ACF message length field.
 */
static inline void Avtp_Sensor_SetAcfMsgLength(Avtp_Sensor_t* pdu, uint16_t value) {
    SET_SENSOR_FIELD(AVTP_SENSOR_FIELD_ACF_MSG_LENGTH, value);
}

/**
 * Enable the MTV field in an ACF Sensor PDU as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Sensor PDU.
 */
static inline void Avtp_Sensor_EnableMtv(Avtp_Sensor_t* pdu) {
    SET_SENSOR_FIELD(AVTP_SENSOR_FIELD_MTV, 1);
}

/**
 * Disable the MTV field in an ACF Sensor PDU as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Sensor PDU.
 */
static inline void Avtp_Sensor_DisableMtv(Avtp_Sensor_t* pdu) {
    SET_SENSOR_FIELD(AVTP_SENSOR_FIELD_MTV, 0);
}

/**
 * Set the value of an an ACF Sensor Num Sensor field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Sensor PDU.
 * @param value Value to set the Num Sensor field.
 */
static inline void Avtp_Sensor_SetNumSensor(Avtp_Sensor_t* pdu, uint8_t value) {
    SET_SENSOR_FIELD(AVTP_SENSOR_FIELD_NUM_SENSOR, value);
}

/**
 * Set the value of an an ACF Sensor Sz field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Sensor PDU.
 * @param value Value to set the Sz field (2 bits).
 */
static inline void Avtp_Sensor_SetSz(Avtp_Sensor_t* pdu, uint8_t value) {
    SET_SENSOR_FIELD(AVTP_SENSOR_FIELD_SZ, value);
}

/**
 * Set the value of an an ACF Sensor Sensor Group field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Sensor PDU.
 * @param value Value to set the Sensor Group field.
 */
static inline void Avtp_Sensor_SetSensorGroup(Avtp_Sensor_t* pdu, uint8_t value) {
    SET_SENSOR_FIELD(AVTP_SENSOR_FIELD_SENSOR_GROUP, value);
}

/**
 * Set the value of an an ACF Sensor Message Timestamp field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Sensor PDU.
 * @param value Value to set the Message Timestamp field.
 */
static inline void Avtp_Sensor_SetMessageTimestamp(Avtp_Sensor_t* pdu, uint64_t value) {
    SET_SENSOR_FIELD(AVTP_SENSOR_FIELD_MESSAGE_TIMESTAMP, value);
}

/**
 * Checks if the ACF Sensor frame is valid by checking:
 *     1) if the length field of AVTP/ACF messages contains a value larger than the actual size of the buffer that contains the AVTP message.
 *     2) if other format specific invariants are not upheld
 * @param pdu Pointer to the first bit of an 1722 ACF Sensor PDU.
 * @param bufferSize Size of the buffer containing the ACF Sensor frame.
 * @return true if the ACF Sensor frame is valid, false otherwise.
 */
uint8_t Avtp_Sensor_IsValid(const Avtp_Sensor_t* const pdu, size_t bufferSize);

/**
 * Initializes an ACF Sensor PDU header as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF Sensor PDU.
 */
static inline void Avtp_Sensor_Init(Avtp_Sensor_t* pdu) {
    if(pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_Sensor_t));
        Avtp_Sensor_SetAcfMsgType(pdu, AVTP_ACF_TYPE_SENSOR);
    }
}

#ifdef __cplusplus
}
#endif
