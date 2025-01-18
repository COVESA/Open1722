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

#include <errno.h>
#include <string.h>

#include "avtp/acf/Sensor.h"
#include "avtp/Utils.h"
#include "avtp/Defines.h"

#define GET_FIELD(field) \
        (Avtp_GetField(Avtp_SensorFieldDesc, AVTP_SENSOR_FIELD_MAX, (uint8_t*)pdu, field))
#define SET_FIELD(field, value) \
        (Avtp_SetField(Avtp_SensorFieldDesc, AVTP_SENSOR_FIELD_MAX, (uint8_t*)pdu, field, value))

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


void Avtp_Sensor_Init(Avtp_Sensor_t* pdu)
{
    if(pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_Sensor_t));
        Avtp_Sensor_SetField(pdu, AVTP_SENSOR_FIELD_ACF_MSG_TYPE, AVTP_ACF_TYPE_SENSOR);
    }
}

uint64_t Avtp_Sensor_GetField(Avtp_Sensor_t* pdu, Avtp_SensorFields_t field)
{
    return GET_FIELD(field);
}

uint8_t Avtp_Sensor_GetAcfMsgType(Avtp_Sensor_t* pdu)
{
    return GET_FIELD(AVTP_SENSOR_FIELD_ACF_MSG_TYPE);
}

uint16_t Avtp_Sensor_GetAcfMsgLength(Avtp_Sensor_t* pdu)
{
    return GET_FIELD(AVTP_SENSOR_FIELD_ACF_MSG_LENGTH);
}

uint8_t Avtp_Sensor_GetMtv(Avtp_Sensor_t* pdu)
{
    return GET_FIELD(AVTP_SENSOR_FIELD_MTV);
}

uint8_t Avtp_Sensor_GetNumSensor(Avtp_Sensor_t* pdu)
{
    return GET_FIELD(AVTP_SENSOR_FIELD_NUM_SENSOR);
}

uint8_t Avtp_Sensor_GetSz(Avtp_Sensor_t* pdu)
{
    return GET_FIELD(AVTP_SENSOR_FIELD_SZ);
}

uint8_t Avtp_Sensor_GetSensorGroup(Avtp_Sensor_t* pdu)
{
    return GET_FIELD(AVTP_SENSOR_FIELD_SENSOR_GROUP);
}

uint64_t Avtp_Sensor_GetMessageTimestamp(Avtp_Sensor_t* pdu)
{
    return GET_FIELD(AVTP_SENSOR_FIELD_MESSAGE_TIMESTAMP);
}

void Avtp_Sensor_SetField(Avtp_Sensor_t* pdu, Avtp_SensorFields_t field, uint64_t value)
{
    Avtp_SetField(Avtp_SensorFieldDesc, AVTP_SENSOR_FIELD_MAX, (uint8_t *)pdu, (uint8_t)field, value);
}

void Avtp_Sensor_SetAcfMsgType(Avtp_Sensor_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_SENSOR_FIELD_ACF_MSG_TYPE, value);
}

void Avtp_Sensor_SetAcfMsgLength(Avtp_Sensor_t* pdu, uint16_t value)
{
    SET_FIELD(AVTP_SENSOR_FIELD_ACF_MSG_LENGTH, value);
}

void Avtp_Sensor_EnableMtv(Avtp_Sensor_t* pdu)
{
    SET_FIELD(AVTP_SENSOR_FIELD_MTV, 1);
}

void Avtp_Sensor_DisableMtv(Avtp_Sensor_t* pdu)
{
    SET_FIELD(AVTP_SENSOR_FIELD_MTV, 0);
}

void Avtp_Sensor_SetNumSensor(Avtp_Sensor_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_SENSOR_FIELD_NUM_SENSOR, value);
}

void Avtp_Sensor_SetSz(Avtp_Sensor_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_SENSOR_FIELD_SZ, value);
}

void Avtp_Sensor_SetSensorGroup(Avtp_Sensor_t* pdu, uint8_t value)
{
    SET_FIELD(AVTP_SENSOR_FIELD_SENSOR_GROUP, value);
}

void Avtp_Sensor_SetMessageTimestamp(Avtp_Sensor_t* pdu, uint64_t value)
{
    SET_FIELD(AVTP_SENSOR_FIELD_MESSAGE_TIMESTAMP, value);
}
