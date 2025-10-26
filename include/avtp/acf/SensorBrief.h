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
 * This file contains the fields descriptions of the IEEE 1722 ACF Abbreviated Sensor PDUs and
 * functions to invoke corresponding parser and deparser.
 */

#pragma once

#include <string.h>

#include "avtp/Defines.h"
#include "avtp/Utils.h"
#include "avtp/acf/AcfCommon.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AVTP_SENSOR_HEADER_LEN         (1 * AVTP_QUADLET_SIZE)

#define GET_SENSOR_BRIEF_FIELD(field) \
        (Avtp_GetField(Avtp_SensorBriefFieldDesc, AVTP_SENSOR_FIELD_MAX, (uint8_t*)pdu, field))
#define SET_SENSOR_BRIEF_FIELD(field, value) \
        (Avtp_SetField(Avtp_SensorBriefFieldDesc, AVTP_SENSOR_FIELD_MAX, (uint8_t*)pdu, field, value))

typedef struct {
    uint8_t header[AVTP_SENSOR_HEADER_LEN];
    uint8_t payload[0];
} Avtp_SensorBrief_t;

typedef enum {
    /* ACF common header fields */
    AVTP_SENSOR_BRIEF_FIELD_ACF_MSG_TYPE = 0,
    AVTP_SENSOR_BRIEF_FIELD_ACF_MSG_LENGTH,
    /* ACF Abbreviated Sensor header fields */
    AVTP_SENSOR_BRIEF_FIELD_MTV,
    AVTP_SENSOR_BRIEF_FIELD_NUM_SENSOR,
    AVTP_SENSOR_BRIEF_FIELD_SZ,
    AVTP_SENSOR_BRIEF_FIELD_SENSOR_GROUP,
    /* Count number of fields for bound checks */
    AVTP_SENSOR_FIELD_MAX
} Avtp_SensorBriefFields_t;

/**
 * This table maps all IEEE 1722 ACF Abbreviated Sensor header fields to a descriptor.
 */
static const Avtp_FieldDescriptor_t Avtp_SensorBriefFieldDesc[AVTP_SENSOR_FIELD_MAX] =
{

    /* ACF common header fields */
    [AVTP_SENSOR_BRIEF_FIELD_ACF_MSG_TYPE]      = { .quadlet = 0, .offset = 0, .bits = 7 },
    [AVTP_SENSOR_BRIEF_FIELD_ACF_MSG_LENGTH]    = { .quadlet = 0, .offset = 7, .bits = 9 },

    /* ACF Abbreviated Sensor header fields */
    [AVTP_SENSOR_BRIEF_FIELD_MTV]               = { .quadlet = 0, .offset = 16, .bits = 1 },
    [AVTP_SENSOR_BRIEF_FIELD_NUM_SENSOR]        = { .quadlet = 0, .offset = 17, .bits = 7 },
    [AVTP_SENSOR_BRIEF_FIELD_SZ]                = { .quadlet = 0, .offset = 24, .bits = 2 },
    [AVTP_SENSOR_BRIEF_FIELD_SENSOR_GROUP]      = { .quadlet = 0, .offset = 26, .bits = 6 },
};

/**
 * Return the value of an an ACF SensorBrief ACF message type field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF SensorBrief PDU.
 * @returns Value of the ACF message type field.
 */
static inline uint8_t Avtp_SensorBrief_GetAcfMsgType(const Avtp_SensorBrief_t* const pdu) {
    return GET_SENSOR_BRIEF_FIELD(AVTP_SENSOR_BRIEF_FIELD_ACF_MSG_TYPE);
}

/**
 * Return the value of an an ACF SensorBrief ACF message length field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF SensorBrief PDU.
 * @returns Value of the ACF message length field.
 */
static inline uint16_t Avtp_SensorBrief_GetAcfMsgLength(const Avtp_SensorBrief_t* const pdu) {
    return GET_SENSOR_BRIEF_FIELD(AVTP_SENSOR_BRIEF_FIELD_ACF_MSG_LENGTH);
}

/**
 * Return the value of an an ACF SensorBrief MTV field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF SensorBrief PDU.
 * @returns Value of the MTV field.
 */
static inline uint8_t Avtp_SensorBrief_GetMtv(const Avtp_SensorBrief_t* const pdu) {
    return GET_SENSOR_BRIEF_FIELD(AVTP_SENSOR_BRIEF_FIELD_MTV);
}

/**
 * Return the value of an an ACF SensorBrief Num Sensor field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF SensorBrief PDU.
 * @returns Value of the Num Sensor field.
 */
static inline uint8_t Avtp_SensorBrief_GetNumSensor(const Avtp_SensorBrief_t* const pdu) {
    return GET_SENSOR_BRIEF_FIELD(AVTP_SENSOR_BRIEF_FIELD_NUM_SENSOR);
}

/**
 * Return the value of an an ACF SensorBrief Sz field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF SensorBrief PDU.
 * @returns Value of the Sz field.
 */
static inline uint8_t Avtp_SensorBrief_GetSz(const Avtp_SensorBrief_t* const pdu) {
    return GET_SENSOR_BRIEF_FIELD(AVTP_SENSOR_BRIEF_FIELD_SZ);
}

/**
 * Return the value of an an ACF SensorBrief Sensor Group field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF SensorBrief PDU.
 * @returns Value of the Sensor Group field.
 */
static inline uint8_t Avtp_SensorBrief_GetSensorGroup(const Avtp_SensorBrief_t* const pdu) {
    return GET_SENSOR_BRIEF_FIELD(AVTP_SENSOR_BRIEF_FIELD_SENSOR_GROUP);
}

/**
 * Sets the value of an ACF SensorBrief PDU ACF message type field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF SensorBrief PDU.
 * @param value Value to set the ACF message type field to.
 */
static inline void Avtp_SensorBrief_SetAcfMsgType(Avtp_SensorBrief_t* pdu, uint8_t value) {
    SET_SENSOR_BRIEF_FIELD(AVTP_SENSOR_BRIEF_FIELD_ACF_MSG_TYPE, value);
}

/**
 * Sets the value of an ACF SensorBrief PDU ACF message length field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF SensorBrief PDU.
 * @param value Value to set the ACF message length field to.
 */
static inline void Avtp_SensorBrief_SetAcfMsgLength(Avtp_SensorBrief_t* pdu, uint16_t value) {
    SET_SENSOR_BRIEF_FIELD(AVTP_SENSOR_BRIEF_FIELD_ACF_MSG_LENGTH, value);
}

/**
 * Enable the MTV field in an ACF SensorBrief PDU as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF SensorBrief PDU.
 */
static inline void Avtp_SensorBrief_EnableMtv(Avtp_SensorBrief_t* pdu) {
    SET_SENSOR_BRIEF_FIELD(AVTP_SENSOR_BRIEF_FIELD_MTV, 1);
}

/**
 * Disable the MTV field in an ACF SensorBrief PDU as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF SensorBrief PDU.
 */
static inline void Avtp_SensorBrief_DisableMtv(Avtp_SensorBrief_t* pdu) {
    SET_SENSOR_BRIEF_FIELD(AVTP_SENSOR_BRIEF_FIELD_MTV, 0);
}

/**
 * Sets the value of an ACF SensorBrief PDU Num Sensor field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF SensorBrief PDU.
 * @param value Value to set the Num Sensor field to.
 */
static inline void Avtp_SensorBrief_SetNumSensor(Avtp_SensorBrief_t* pdu, uint8_t value) {
    SET_SENSOR_BRIEF_FIELD(AVTP_SENSOR_BRIEF_FIELD_NUM_SENSOR, value);
}

/**
 * Sets the value of an ACF SensorBrief PDU Sz field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF SensorBrief PDU.
 * @param value Value to set the Sz field to.
 */
static inline void Avtp_SensorBrief_SetSz(Avtp_SensorBrief_t* pdu, uint8_t value) {
    SET_SENSOR_BRIEF_FIELD(AVTP_SENSOR_BRIEF_FIELD_SZ, value);
}

/**
 * Sets the value of an ACF SensorBrief PDU Sensor Group field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF SensorBrief PDU.
 * @param value Value to set the Sensor Group field to.
 */
static inline void Avtp_SensorBrief_SetSensorGroup(Avtp_SensorBrief_t* pdu, uint8_t value) {
    SET_SENSOR_BRIEF_FIELD(AVTP_SENSOR_BRIEF_FIELD_SENSOR_GROUP, value);
}

/**
 * Checks if the ACF SensorBrief frame is valid by checking:
 *     1) if the length field of AVTP/ACF messages contains a value larger than the actual size of the buffer that contains the AVTP message.
 *     2) if other format specific invariants are not upheld
 * @param pdu Pointer to the first bit of an 1722 ACF SensorBrief PDU.
 * @param bufferSize Size of the buffer containing the ACF SensorBrief frame.
 * @return true if the ACF SensorBrief frame is valid, false otherwise.
 */
uint8_t Avtp_SensorBrief_IsValid(const Avtp_SensorBrief_t* const pdu, size_t bufferSize);

/**
 * Initializes an ACF Abbreviated Sensor PDU header as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF Abbreviated Sensor PDU.
 */
static inline void Avtp_SensorBrief_Init(Avtp_SensorBrief_t* pdu) {
    if(pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_SensorBrief_t));
        Avtp_SensorBrief_SetAcfMsgType(pdu, AVTP_ACF_TYPE_SENSOR_BRIEF);
    }
}

#ifdef __cplusplus
}
#endif
