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
 * This file contains the fields descriptions of the IEEE 1722-2016 ACF Abbreviated CAN PDUs and
 * functions to invoke corresponding parser and deparser.
 */

#pragma once

#include "avtp/Utils.h"
#include "avtp/Defines.h"
#include "avtp/acf/AcfCommon.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GET_CAN_BRIEF_FIELD(field) \
        (Avtp_GetField(Avtp_CanBriefFieldDesc, AVTP_CAN_BRIEF_FIELD_MAX, (uint8_t*)pdu, field))
#define SET_CAN_BRIEF_FIELD(field, value) \
        (Avtp_SetField(Avtp_CanBriefFieldDesc, AVTP_CAN_BRIEF_FIELD_MAX, (uint8_t*)pdu, field, value))

#define AVTP_CAN_BRIEF_HEADER_LEN         (2 * AVTP_QUADLET_SIZE)

typedef struct {
    uint8_t header[AVTP_CAN_BRIEF_HEADER_LEN];
    uint8_t payload[0];
} Avtp_CanBrief_t;

typedef enum {

    /* ACF common header fields */
    AVTP_CAN_BRIEF_FIELD_ACF_MSG_TYPE = 0,
    AVTP_CAN_BRIEF_FIELD_ACF_MSG_LENGTH,

    /* ACF Abbreviated CAN Brief header fields */
    AVTP_CAN_BRIEF_FIELD_PAD,
    AVTP_CAN_BRIEF_FIELD_MTV,
    AVTP_CAN_BRIEF_FIELD_RTR,
    AVTP_CAN_BRIEF_FIELD_EFF,
    AVTP_CAN_BRIEF_FIELD_BRS,
    AVTP_CAN_BRIEF_FIELD_FDF,
    AVTP_CAN_BRIEF_FIELD_ESI,
    AVTP_CAN_BRIEF_FIELD_CAN_BUS_ID,
    AVTP_CAN_BRIEF_FIELD_CAN_IDENTIFIER,

    /* Count number of fields for bound checks */
    AVTP_CAN_BRIEF_FIELD_MAX
} Avtp_CanBriefFields_t;

/**
 * This table maps all IEEE 1722 ACF Abbreviated CAN header fields to a descriptor.
 */
static const Avtp_FieldDescriptor_t Avtp_CanBriefFieldDesc[AVTP_CAN_BRIEF_FIELD_MAX] =
{
    /* ACF common header fields */
    [AVTP_CAN_BRIEF_FIELD_ACF_MSG_TYPE]           = { .quadlet = 0, .offset =  0, .bits = 7 },
    [AVTP_CAN_BRIEF_FIELD_ACF_MSG_LENGTH]         = { .quadlet = 0, .offset =  7, .bits = 9 },
    /* ACF Abbreviated CAN header fields */
    [AVTP_CAN_BRIEF_FIELD_PAD]                   = { .quadlet = 0, .offset = 16, .bits =  2 },
    [AVTP_CAN_BRIEF_FIELD_MTV]                   = { .quadlet = 0, .offset = 18, .bits =  1 },
    [AVTP_CAN_BRIEF_FIELD_RTR]                   = { .quadlet = 0, .offset = 19, .bits =  1 },
    [AVTP_CAN_BRIEF_FIELD_EFF]                   = { .quadlet = 0, .offset = 20, .bits =  1 },
    [AVTP_CAN_BRIEF_FIELD_BRS]                   = { .quadlet = 0, .offset = 21, .bits =  1 },
    [AVTP_CAN_BRIEF_FIELD_FDF]                   = { .quadlet = 0, .offset = 22, .bits =  1 },
    [AVTP_CAN_BRIEF_FIELD_ESI]                   = { .quadlet = 0, .offset = 23, .bits =  1 },
    [AVTP_CAN_BRIEF_FIELD_CAN_BUS_ID]            = { .quadlet = 0, .offset = 27, .bits =  5 },
    [AVTP_CAN_BRIEF_FIELD_CAN_IDENTIFIER]        = { .quadlet = 1, .offset =  3, .bits = 29 },
};

/**
 * Returns the value of an an ACF Abbreviated CAN PDU field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Abbreviated CAN PDU.
 * @param field Specifies the position of the data field to be read
 * @returns Field of CAN Brief PDU.
 */
static inline uint64_t Avtp_CanBrief_GetField(const Avtp_CanBrief_t* const pdu, Avtp_CanBriefFields_t field) {
    return GET_CAN_BRIEF_FIELD(field);
}

/**
 * Return the value of an an ACF message type field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
 * @returns Value of the ACF message type field.
 */
static inline uint8_t Avtp_CanBrief_GetAcfMsgType(const Avtp_CanBrief_t* const pdu) {
    return GET_CAN_BRIEF_FIELD(AVTP_CAN_BRIEF_FIELD_ACF_MSG_TYPE);
}
/**
 * Return the value of an an ACF message length field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
 * @returns Value of the ACF message length field.
 */
static inline uint16_t Avtp_CanBrief_GetAcfMsgLength(const Avtp_CanBrief_t* const pdu) {
    return GET_CAN_BRIEF_FIELD(AVTP_CAN_BRIEF_FIELD_ACF_MSG_LENGTH);
}

/**
 * Return the value of an an ACF padding field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
 * @returns Value of the ACF padding field.
 */
static inline uint8_t Avtp_CanBrief_GetPad(const Avtp_CanBrief_t* const pdu) {
    return GET_CAN_BRIEF_FIELD(AVTP_CAN_BRIEF_FIELD_PAD);
}

/** 
 * Return the value of an an ACF CAN Brief PDU MTV field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
 * @returns Value of the ACF CAN Brief PDU MTV field.
 */
static inline uint8_t Avtp_CanBrief_GetMtv(const Avtp_CanBrief_t* const pdu) {
    return GET_CAN_BRIEF_FIELD(AVTP_CAN_BRIEF_FIELD_MTV);
}

/**
 * Return the value of an an ACF CAN Brief PDU RTR field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
 * @returns Value of the ACF CAN Brief PDU RTR field.
 */
static inline uint8_t Avtp_CanBrief_GetRtr(const Avtp_CanBrief_t* const pdu) {
    return GET_CAN_BRIEF_FIELD(AVTP_CAN_BRIEF_FIELD_RTR);
}

/**
 * Return the value of an an ACF CAN Brief PDU EFF field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
 * @returns Value of the ACF CAN Brief PDU EFF field.
 */
static inline uint8_t Avtp_CanBrief_GetEff(const Avtp_CanBrief_t* const pdu) {
    return GET_CAN_BRIEF_FIELD(AVTP_CAN_BRIEF_FIELD_EFF);
}

/** 
 * Return the value of an an ACF CAN Brief PDU BRS field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
 * @returns Value of the ACF CAN Brief PDU BRS field.
 */
static inline uint8_t Avtp_CanBrief_GetBrs(const Avtp_CanBrief_t* const pdu) {
    return GET_CAN_BRIEF_FIELD(AVTP_CAN_BRIEF_FIELD_BRS);
}

/**
 * Return the value of an an ACF CAN Brief PDU FDF field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
 * @returns Value of the ACF CAN Brief PDU FDF field.
 */
static inline uint8_t Avtp_CanBrief_GetFdf(const Avtp_CanBrief_t* const pdu) {
    return GET_CAN_BRIEF_FIELD(AVTP_CAN_BRIEF_FIELD_FDF);
}

/**
 * Return the value of an an ACF CAN Brief PDU ESI field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
 * @returns Value of the ACF CAN Brief PDU ESI field.
 */
static inline uint8_t Avtp_CanBrief_GetEsi(const Avtp_CanBrief_t* const pdu) {
    return GET_CAN_BRIEF_FIELD(AVTP_CAN_BRIEF_FIELD_ESI);
}

/**
 * Return the value of an an ACF CAN Brief PDU CAN Bus ID field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
 * @returns Value of the ACF CAN Brief PDU CAN Bus ID field.
 */
static inline uint8_t Avtp_CanBrief_GetCanBusId(const Avtp_CanBrief_t* const pdu) {
    return GET_CAN_BRIEF_FIELD(AVTP_CAN_BRIEF_FIELD_CAN_BUS_ID);
}

/**
 * Return the value of an an ACF CAN Brief PDU CAN Identifier field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
 * @returns Value of the ACF CAN Brief PDU CAN Identifier field.
 */
static inline uint32_t Avtp_CanBrief_GetCanIdentifier(const Avtp_CanBrief_t* const pdu) {
    return GET_CAN_BRIEF_FIELD(AVTP_CAN_BRIEF_FIELD_CAN_IDENTIFIER);
}

/**
 * Sets the value of an an ACF Abbreviated CAN PDU field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF Abbreviated CAN PDU.
 * @param field Specifies the position of the data field to be read
 * @param value Pointer to location to store the value.
 */
static inline void Avtp_CanBrief_SetField(Avtp_CanBrief_t* pdu, Avtp_CanBriefFields_t field, uint64_t value) {
    SET_CAN_BRIEF_FIELD(field, value);
}

/**
 * Set the value of an an ACF message type field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
 * @param value Value to set the ACF message type field to.
 */
static inline void Avtp_CanBrief_SetAcfMsgType(Avtp_CanBrief_t* pdu, uint8_t value) {
    SET_CAN_BRIEF_FIELD(AVTP_CAN_BRIEF_FIELD_ACF_MSG_TYPE, value);
}

/**
 * Set the value of an an ACF message length field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
 * @param value Value to set the ACF message length field to.
 */
static inline void Avtp_CanBrief_SetAcfMsgLength(Avtp_CanBrief_t* pdu, uint16_t value) {
    SET_CAN_BRIEF_FIELD(AVTP_CAN_BRIEF_FIELD_ACF_MSG_LENGTH, value);
}

/**
 * Set the value of an an ACF padding field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
 * @param value Value to set the ACF padding field to.
 */
static inline void Avtp_CanBrief_SetPad(Avtp_CanBrief_t* pdu, uint8_t value) {
    SET_CAN_BRIEF_FIELD(AVTP_CAN_BRIEF_FIELD_PAD, value);
}

/**
 * Enable the MTV bit in an ACF CAN Brief frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
 */
static inline void Avtp_CanBrief_EnableMtv(Avtp_CanBrief_t* pdu) {
    SET_CAN_BRIEF_FIELD(AVTP_CAN_BRIEF_FIELD_MTV, 1);
}

/**
 * Disable the MTV bit in an ACF CAN Brief frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
 */
static inline void Avtp_CanBrief_DisableMtv(Avtp_CanBrief_t* pdu) {
    SET_CAN_BRIEF_FIELD(AVTP_CAN_BRIEF_FIELD_MTV, 0);
}

/**
 * Enable the RTR bit in an ACF CAN Brief frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
 */
static inline void Avtp_CanBrief_EnableRtr(Avtp_CanBrief_t* pdu) {
    SET_CAN_BRIEF_FIELD(AVTP_CAN_BRIEF_FIELD_RTR, 1);
}

/**
 * Disable the RTR bit in an ACF CAN Brief frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
 */
static inline void Avtp_CanBrief_DisableRtr(Avtp_CanBrief_t* pdu) {
    SET_CAN_BRIEF_FIELD(AVTP_CAN_BRIEF_FIELD_RTR, 0);
}

/**
 * Enable the EFF bit in an ACF CAN Brief frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
 */
static inline void Avtp_CanBrief_EnableEff(Avtp_CanBrief_t* pdu) {
    SET_CAN_BRIEF_FIELD(AVTP_CAN_BRIEF_FIELD_EFF, 1);
}

/**
 * Disable the EFF bit in an ACF CAN Brief frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
 */
static inline void Avtp_CanBrief_DisableEff(Avtp_CanBrief_t* pdu) {
    SET_CAN_BRIEF_FIELD(AVTP_CAN_BRIEF_FIELD_EFF, 0);
}

/**
 * Enable the BRS bit in an ACF CAN Brief frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
 */
static inline void Avtp_CanBrief_EnableBrs(Avtp_CanBrief_t* pdu) {
    SET_CAN_BRIEF_FIELD(AVTP_CAN_BRIEF_FIELD_BRS, 1);
}

/**
 * Disable the BRS bit in an ACF CAN Brief frame as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
 */
static inline void Avtp_CanBrief_DisableBrs(Avtp_CanBrief_t* pdu) {
    SET_CAN_BRIEF_FIELD(AVTP_CAN_BRIEF_FIELD_BRS, 0);
}

/**
 * Enable the FDF bit in an ACF CAN Brief frame as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
 */
static inline void Avtp_CanBrief_EnableFdf(Avtp_CanBrief_t* pdu) {
    SET_CAN_BRIEF_FIELD(AVTP_CAN_BRIEF_FIELD_FDF, 1);
}

/**
 * Disable the FDF bit in an ACF CAN Brief frame as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
 */
static inline void Avtp_CanBrief_DisableFdf(Avtp_CanBrief_t* pdu) {
    SET_CAN_BRIEF_FIELD(AVTP_CAN_BRIEF_FIELD_FDF, 0);
}

/**
 * Enable the ESI bit in an ACF CAN Brief frame as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
 */
static inline void Avtp_CanBrief_EnableEsi(Avtp_CanBrief_t* pdu) {
    SET_CAN_BRIEF_FIELD(AVTP_CAN_BRIEF_FIELD_ESI, 1);
}

/**
 * Disable the ESI bit in an ACF CAN Brief frame as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
 */
static inline void Avtp_CanBrief_DisableEsi(Avtp_CanBrief_t* pdu) {
    SET_CAN_BRIEF_FIELD(AVTP_CAN_BRIEF_FIELD_ESI, 0);
}

/**
 * Set the value of an an ACF CAN Brief PDU CAN Bus ID field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
 * @param value Value to set the ACF CAN Brief PDU CAN Bus ID field to.
 */
static inline void Avtp_CanBrief_SetCanBusId(Avtp_CanBrief_t* pdu, uint8_t value) {
    SET_CAN_BRIEF_FIELD(AVTP_CAN_BRIEF_FIELD_CAN_BUS_ID, value);
}

/**
 * Set the value of an an ACF CAN Brief PDU CAN Identifier field as specified in the IEEE 1722 Specification.
 * 
 * @param pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
 * @param value Value to set the ACF CAN Brief PDU CAN Identifier field to.
 */
static inline void Avtp_CanBrief_SetCanIdentifier(Avtp_CanBrief_t* pdu, uint32_t value) {
    SET_CAN_BRIEF_FIELD(AVTP_CAN_BRIEF_FIELD_CAN_IDENTIFIER, value);
}

/**
 * Copies the payload data and CAN frame ID into the ACF CAN Brief frame. This function will
 * also set the length and pad fields while inserting the padded bytes.
 *
 * @param can_pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
 * @param frame_id ID of the CAN frame
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload.
 * @param can_variant Classic CAN or CAN-FD
 */
void Avtp_CanBrief_CreateAcfMessage(Avtp_CanBrief_t* can_pdu, uint32_t frame_id, uint8_t* payload,
    uint16_t payload_length, Avtp_CanVariant_t can_variant);

/**
* Returns pointer to payload of an ACF CAN Brief frame.
*
* @param can_pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
* @return Pointer to ACF CAN Brief frame payload
*/
const uint8_t* Avtp_CanBrief_GetPayload(const Avtp_CanBrief_t* const can_pdu);

/**
* Sets the CAN payload in an ACF CAN Brief frame.
*
* @param can_pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
* @param payload Pointer to the payload byte array
* @param payload_length Length of the payload
*/
void Avtp_CanBrief_SetPayload(Avtp_CanBrief_t* can_pdu, uint8_t* payload,
            uint16_t payload_length);

/**
* Finalizes the ACF CAN Brief frame. This function will set the
* length and pad fields while inserting the padded bytes.
*
* @param can_pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
* @param payload Pointer to the payload byte array
* @param payload_length Length of the CAN frame payload.
*/
void Avtp_CanBrief_Finalize(Avtp_CanBrief_t* can_pdu, uint16_t payload_length);

/**
* Returns the length of the CAN payload without the padding bytes and the
* header length of the encapsulating ACF Frame.
*
* @param pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
* @return  Length of CAN payload in bytes
*/
uint8_t Avtp_CanBrief_GetCanPayloadLength(const Avtp_CanBrief_t* const pdu);

/**
 * Checks if the ACF CAN Brief frame is valid by checking:
 *     1) if the length field of AVTP/ACF messages contains a value larger than the actual size of the buffer that contains the AVTP message.
 *     2) if other format specific invariants are not upheld
 * @param pdu Pointer to the first bit of an 1722 ACF CAN Brief PDU.
 * @param bufferSize Size of the buffer containing the ACF CAN Brief frame.
 * @return true if the ACF CAN Brief frame is valid, false otherwise.
 */
uint8_t Avtp_CanBrief_IsValid(const Avtp_CanBrief_t* const pdu, size_t bufferSize);

/**
 * Initializes an ACF Abbreviated CAN PDU header as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of a 1722 ACF Abbreviated CAN PDU.
 */
static inline void Avtp_CanBrief_Init(Avtp_CanBrief_t* pdu) {
    if(pdu != NULL) {
        memset(pdu, 0, sizeof(Avtp_CanBrief_t));
        Avtp_CanBrief_SetAcfMsgType(pdu, AVTP_ACF_TYPE_CAN_BRIEF);
    }
}

#ifdef __cplusplus
}
#endif
