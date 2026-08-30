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

#define AVTP_SENSOR_BRIEF_HEADER_LEN (1 * AVTP_QUADLET_SIZE)

#define GET_SENSOR_BRIEF_FIELD(field)                                                              \
    (Avtp_GetField(Avtp_SensorBriefFieldDesc, AVTP_SENSOR_BRIEF_FIELD_MAX, (uint8_t *)pdu, field))
#define SET_SENSOR_BRIEF_FIELD(field, value)                                                       \
    (Avtp_SetField(Avtp_SensorBriefFieldDesc, AVTP_SENSOR_BRIEF_FIELD_MAX, (uint8_t *)pdu, field,  \
                   value))

typedef struct {
    uint8_t header[AVTP_SENSOR_BRIEF_HEADER_LEN];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_SensorBrief_t;

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
    AVTP_SENSOR_BRIEF_FIELD_MAX
} Avtp_SensorBriefFields_t;

/**
 * This table maps all IEEE 1722 ACF Abbreviated Sensor header fields to a descriptor.
 */
static const Avtp_FieldDescriptor_t Avtp_SensorBriefFieldDesc[AVTP_SENSOR_BRIEF_FIELD_MAX] = {
    /* ACF common header fields */
    [AVTP_SENSOR_BRIEF_FIELD_ACF_MSG_TYPE] = {.quadlet = 0, .offset = 0, .bits = 7},
    [AVTP_SENSOR_BRIEF_FIELD_ACF_MSG_LENGTH] = {.quadlet = 0, .offset = 7, .bits = 9},

    /* ACF Abbreviated Sensor header fields */
    [AVTP_SENSOR_BRIEF_FIELD_MTV] = {.quadlet = 0, .offset = 16, .bits = 1},
    [AVTP_SENSOR_BRIEF_FIELD_NUM_SENSOR] = {.quadlet = 0, .offset = 17, .bits = 7},
    [AVTP_SENSOR_BRIEF_FIELD_SZ] = {.quadlet = 0, .offset = 24, .bits = 2},
    [AVTP_SENSOR_BRIEF_FIELD_SENSOR_GROUP] = {.quadlet = 0, .offset = 26, .bits = 6},
};

/**
 * Return the value of the ACF message type field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF SensorBrief PDU.
 * @returns Value of the ACF message type field.
 */
OPEN1722_INLINE uint8_t Avtp_SensorBrief_GetAcfMsgType(const Avtp_SensorBrief_t *const pdu)
{
    return (uint8_t)GET_SENSOR_BRIEF_FIELD(AVTP_SENSOR_BRIEF_FIELD_ACF_MSG_TYPE);
}

/**
 * Return the value of the ACF message length field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF SensorBrief PDU.
 * @returns Value of the ACF message length field.
 */
OPEN1722_INLINE uint16_t Avtp_SensorBrief_GetAcfMsgLength(const Avtp_SensorBrief_t *const pdu)
{
    return (uint16_t)GET_SENSOR_BRIEF_FIELD(AVTP_SENSOR_BRIEF_FIELD_ACF_MSG_LENGTH);
}

/**
 * Return the ACF message length in bytes.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF SensorBrief PDU.
 * @returns Length of the ACF message in bytes.
 */
OPEN1722_INLINE uint16_t
Avtp_SensorBrief_GetAcfMsgLengthInBytes(const Avtp_SensorBrief_t *const pdu)
{
    return (uint16_t)GET_SENSOR_BRIEF_FIELD(AVTP_SENSOR_BRIEF_FIELD_ACF_MSG_LENGTH) * 4;
}

/**
 * Return the value of the ACF SensorBrief MTV field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF SensorBrief PDU.
 * @returns Value of the MTV field.
 */
OPEN1722_INLINE bool Avtp_SensorBrief_IsMtv(const Avtp_SensorBrief_t *const pdu)
{
    return (bool)GET_SENSOR_BRIEF_FIELD(AVTP_SENSOR_BRIEF_FIELD_MTV);
}

/**
 * Return the value of the ACF SensorBrief Num Sensor field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF SensorBrief PDU.
 * @returns Value of the Num Sensor field.
 */
OPEN1722_INLINE uint8_t Avtp_SensorBrief_GetNumSensor(const Avtp_SensorBrief_t *const pdu)
{
    return (uint8_t)GET_SENSOR_BRIEF_FIELD(AVTP_SENSOR_BRIEF_FIELD_NUM_SENSOR);
}

/**
 * Return the value of the ACF SensorBrief Sz field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF SensorBrief PDU.
 * @returns Value of the Sz field.
 */
OPEN1722_INLINE uint8_t Avtp_SensorBrief_GetSz(const Avtp_SensorBrief_t *const pdu)
{
    return (uint8_t)GET_SENSOR_BRIEF_FIELD(AVTP_SENSOR_BRIEF_FIELD_SZ);
}

/**
 * Return the value of the ACF SensorBrief Sensor Group field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF SensorBrief PDU.
 * @returns Value of the Sensor Group field.
 */
OPEN1722_INLINE uint8_t Avtp_SensorBrief_GetSensorGroup(const Avtp_SensorBrief_t *const pdu)
{
    return (uint8_t)GET_SENSOR_BRIEF_FIELD(AVTP_SENSOR_BRIEF_FIELD_SENSOR_GROUP);
}

/**
 * Sets the value of the ACF message type field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF SensorBrief PDU.
 * @param value Value to set the ACF message type field to.
 */
OPEN1722_INLINE void Avtp_SensorBrief_SetAcfMsgType(Avtp_SensorBrief_t *pdu, uint8_t value)
{
    SET_SENSOR_BRIEF_FIELD(AVTP_SENSOR_BRIEF_FIELD_ACF_MSG_TYPE, value);
}

/**
 * Sets the value of the ACF message length field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF SensorBrief PDU.
 * @param value Value to set the ACF message length field to.
 */
OPEN1722_INLINE void Avtp_SensorBrief_SetAcfMsgLength(Avtp_SensorBrief_t *pdu, uint16_t value)
{
    SET_SENSOR_BRIEF_FIELD(AVTP_SENSOR_BRIEF_FIELD_ACF_MSG_LENGTH, value);
}

/**
 * Set the MTV bit in an ACF SensorBrief PDU as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF SensorBrief PDU.
 * @param mtv Value to set the MTV bit to.
 */
OPEN1722_INLINE void Avtp_SensorBrief_SetMtv(Avtp_SensorBrief_t *pdu, bool mtv)
{
    SET_SENSOR_BRIEF_FIELD(AVTP_SENSOR_BRIEF_FIELD_MTV, mtv);
}

/**
 * Sets the value of the ACF SensorBrief Num Sensor field as specified in the IEEE 1722
 * Specification.
 *
 * Note: a value of 0 means 128 sensor values are present in the payload
 * (see Avtp_SensorBrief_GetPayloadLength for the interpreted payload length).
 *
 * @param pdu Pointer to the first bit of an 1722 ACF SensorBrief PDU.
 * @param value Value to set the Num Sensor field to.
 */
OPEN1722_INLINE void Avtp_SensorBrief_SetNumSensor(Avtp_SensorBrief_t *pdu, uint8_t value)
{
    SET_SENSOR_BRIEF_FIELD(AVTP_SENSOR_BRIEF_FIELD_NUM_SENSOR, value);
}

/**
 * Sets the value of the ACF SensorBrief Sz field as specified in the IEEE 1722 Specification.
 *
 * Note: a value of 0 means each sensor value is 4 octets long
 * (see Avtp_SensorBrief_GetPayloadLength for the interpreted payload length).
 *
 * @param pdu Pointer to the first bit of an 1722 ACF SensorBrief PDU.
 * @param value Value to set the Sz field to.
 */
OPEN1722_INLINE void Avtp_SensorBrief_SetSz(Avtp_SensorBrief_t *pdu, uint8_t value)
{
    SET_SENSOR_BRIEF_FIELD(AVTP_SENSOR_BRIEF_FIELD_SZ, value);
}

/**
 * Sets the value of the ACF SensorBrief Sensor Group field as specified in the IEEE 1722
 * Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF SensorBrief PDU.
 * @param value Value to set the Sensor Group field to.
 */
OPEN1722_INLINE void Avtp_SensorBrief_SetSensorGroup(Avtp_SensorBrief_t *pdu, uint8_t value)
{
    SET_SENSOR_BRIEF_FIELD(AVTP_SENSOR_BRIEF_FIELD_SENSOR_GROUP, value);
}

/**
 * Returns pointer to payload of an ACF SensorBrief frame.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF SensorBrief PDU.
 * @return Pointer to ACF SensorBrief frame payload
 */
OPEN1722_INLINE const uint8_t *Avtp_SensorBrief_GetPayload(const Avtp_SensorBrief_t *const pdu)
{
    return pdu->payload;
}

/**
 * Sets the sensor payload in an ACF SensorBrief frame.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF SensorBrief PDU.
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload
 */
OPEN1722_INLINE void Avtp_SensorBrief_SetPayload(Avtp_SensorBrief_t *pdu, uint8_t *payload,
                                                 uint16_t payload_length)
{
    memcpy(pdu->payload, payload, payload_length);
}

/**
 * Finalizes the ACF SensorBrief frame. This function sets the quadlet-encoded
 * length field based on the given payload length and zeroes the trailing
 * padding octets.
 *
 * The ACF Sensor format has no explicit pad field. The number of padding
 * octets required to reach an integer number of quadlets is determined by the
 * num_sensors and sz fields (i.e. by the total payload length).
 *
 * @param pdu Pointer to the first bit of an 1722 ACF SensorBrief PDU.
 * @param payload_length Length of the sensor payload.
 */
OPEN1722_INLINE void Avtp_SensorBrief_SetPayloadLength(Avtp_SensorBrief_t *pdu,
                                                       uint16_t payload_length)
{
    uint16_t msgLenBytes = AVTP_SENSOR_BRIEF_HEADER_LEN + payload_length;
    uint8_t pad = (uint8_t)(4 - (msgLenBytes % 4)) % 4;
    if (pad > 0) {
        memset(pdu->payload + payload_length, 0, pad);
    }
    uint16_t msgLenQuadlets = (uint16_t)((msgLenBytes + pad) / 4);
    Avtp_SensorBrief_SetAcfMsgLength(pdu, msgLenQuadlets);
}

/**
 * Returns the length of the sensor payload (sensor_msg_payload) in bytes.
 *
 * The ACF Sensor format has no explicit pad field, so the payload length is
 * recovered from the num_sensors and sz fields rather than the length field:
 *
 *   - num_sensors == 0 means 128 sensor values are present.
 *   - sz == 0 means each sensor value is 4 octets long.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF SensorBrief PDU.
 * @return  Length of the sensor payload in bytes.
 */
OPEN1722_INLINE uint16_t Avtp_SensorBrief_GetPayloadLength(const Avtp_SensorBrief_t *const pdu)
{
    /* num_sensors == 0 means 128 sensor values are present. */
    uint8_t num = Avtp_SensorBrief_GetNumSensor(pdu);
    uint8_t count = (num == 0) ? 128u : num;

    /* sz == 0 means each sensor value is 4 octets long. */
    uint8_t sz = Avtp_SensorBrief_GetSz(pdu);
    uint8_t size = (sz == 0) ? 4u : sz;

    return (uint16_t)(count * size);
}

/**
 * Initializes an ACF Abbreviated Sensor PDU header as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF Abbreviated Sensor PDU.
 */
OPEN1722_INLINE void Avtp_SensorBrief_Init(Avtp_SensorBrief_t *pdu)
{
    if (pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_SensorBrief_t));
        Avtp_SensorBrief_SetAcfMsgType(pdu, AVTP_ACF_TYPE_SENSOR_BRIEF);
    }
}

/**
 * Copies the payload data, number of sensors and sensor value size into the ACF
 * SensorBrief frame. This function will also set the length field while
 * inserting the padded bytes.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF SensorBrief PDU.
 * @param num_sensors Number of sensor values (0 means 128)
 * @param sz Sensor value size (0 means 4 octets)
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload.
 */
OPEN1722_INLINE void Avtp_SensorBrief_CreateAcfMessage(Avtp_SensorBrief_t *pdu, uint8_t num_sensors,
                                                       uint8_t sz, uint8_t *payload,
                                                       uint16_t payload_length)
{
    // Initialize the ACF SensorBrief header
    Avtp_SensorBrief_Init(pdu);

    // Set the number of sensors and sensor value size
    Avtp_SensorBrief_SetNumSensor(pdu, num_sensors);
    Avtp_SensorBrief_SetSz(pdu, sz);

    // Copy the payload into the SensorBrief PDU
    Avtp_SensorBrief_SetPayload(pdu, payload, payload_length);

    // Finalize the AVTP SensorBrief Frame
    Avtp_SensorBrief_SetPayloadLength(pdu, payload_length);
}

/**
 * Checks if the ACF SensorBrief frame is valid by checking:
 *     1) if the length field of AVTP/ACF messages contains a value larger than the actual size of
 * the buffer that contains the AVTP message. 2) if other format specific invariants are not upheld
 * @param pdu Pointer to the first bit of an 1722 ACF SensorBrief PDU.
 * @param bufferSize Size of the buffer containing the ACF SensorBrief frame.
 * @return true if the ACF SensorBrief frame is valid, false otherwise.
 */
OPEN1722_INLINE bool Avtp_SensorBrief_IsValid(const Avtp_SensorBrief_t *const pdu,
                                              size_t bufferSize)
{
    if (pdu == NULL) {
        return false;
    }

    if (bufferSize < AVTP_SENSOR_BRIEF_HEADER_LEN) {
        return false;
    }

    if (Avtp_SensorBrief_GetAcfMsgType(pdu) != AVTP_ACF_TYPE_SENSOR_BRIEF) {
        return false;
    }

    // Avtp_SensorBrief_GetAcfMsgLength returns quadlets. Convert the length field to octets.
    uint16_t msg_length_bytes = (uint16_t)Avtp_SensorBrief_GetAcfMsgLength(pdu) * 4;
    if (msg_length_bytes > bufferSize) {
        return false;
    }

    if (msg_length_bytes < AVTP_SENSOR_BRIEF_HEADER_LEN) {
        return false;
    }

    return true;
}

#ifdef __cplusplus
}
#endif
