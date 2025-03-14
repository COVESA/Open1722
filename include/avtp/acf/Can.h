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
 * This file contains the fields descriptions of the IEEE 1722-2016 ACF CAN PDUs and
 * functions to invoke corresponding parser and deparser.
 */

#pragma once

#include "avtp/Defines.h"
#include "avtp/acf/AcfCommon.h"

#ifdef __cplusplus
extern "C" {
#endif


#define AVTP_CAN_HEADER_LEN         (4 * AVTP_QUADLET_SIZE)

typedef struct {
    uint8_t header[AVTP_CAN_HEADER_LEN];
    uint8_t payload[0];
} __attribute__((packed)) Avtp_Can_t;

typedef enum {
    AVTP_CAN_CLASSIC = 0,
    AVTP_CAN_FD
} Avtp_CanVariant_t;

typedef enum  {

    /* ACF common header fields */
    AVTP_CAN_FIELD_ACF_MSG_TYPE = 0,
    AVTP_CAN_FIELD_ACF_MSG_LENGTH,

    /* ACF CAN header fields */
    AVTP_CAN_FIELD_PAD,
    AVTP_CAN_FIELD_MTV,
    AVTP_CAN_FIELD_RTR,
    AVTP_CAN_FIELD_EFF,
    AVTP_CAN_FIELD_BRS,
    AVTP_CAN_FIELD_FDF,
    AVTP_CAN_FIELD_ESI,
    AVTP_CAN_FIELD_CAN_BUS_ID,
    AVTP_CAN_FIELD_MESSAGE_TIMESTAMP,
    AVTP_CAN_FIELD_CAN_IDENTIFIER,

    /* Count number of fields for bound checks */
    AVTP_CAN_FIELD_MAX
} Avtp_CanFields_t;

/**
 * Initializes an ACF CAN PDU header as specified in the IEEE 1722 Specification.
 *
 * @param can_pdu Pointer to the first bit of a 1722 ACF CAN PDU.
 */
void Avtp_Can_Init(Avtp_Can_t* can_pdu);

/**
 * Return the value of an an ACF CAN PDU field as specified in the IEEE 1722 Specification.
 *
 * @param can_pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @returns Value of the ACF CAN PDU field.
 */

uint8_t Avtp_Can_GetAcfMsgType(Avtp_Can_t* pdu);
uint16_t Avtp_Can_GetAcfMsgLength(Avtp_Can_t* pdu);
uint8_t Avtp_Can_GetPad(Avtp_Can_t* pdu);
uint8_t Avtp_Can_GetMtv(Avtp_Can_t* pdu);
uint8_t Avtp_Can_GetRtr(Avtp_Can_t* pdu);
uint8_t Avtp_Can_GetEff(Avtp_Can_t* pdu);
uint8_t Avtp_Can_GetBrs(Avtp_Can_t* pdu);
uint8_t Avtp_Can_GetFdf(Avtp_Can_t* pdu);
uint8_t Avtp_Can_GetEsi(Avtp_Can_t* pdu);
uint8_t Avtp_Can_GetCanBusId(Avtp_Can_t* pdu);
uint64_t Avtp_Can_GetMessageTimestamp(Avtp_Can_t* pdu);
uint32_t Avtp_Can_GetCanIdentifier(Avtp_Can_t* pdu);

/**
 * Set the values of an an ACF CAN PDU field as specified in the IEEE 1722 Specification.
 *
 * @param can_pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @param value Pointer to location with the value.
 */

/* Integer fields */
void Avtp_Can_SetAcfMsgType(Avtp_Can_t* pdu, uint8_t value);
void Avtp_Can_SetAcfMsgLength(Avtp_Can_t* pdu, uint16_t value);
void Avtp_Can_SetPad(Avtp_Can_t* pdu, uint8_t value);
void Avtp_Can_SetCanBusId(Avtp_Can_t* pdu, uint8_t value);
void Avtp_Can_SetMessageTimestamp(Avtp_Can_t* pdu, uint64_t value);
void Avtp_Can_SetCanIdentifier(Avtp_Can_t* pdu, uint32_t value);

/**
 * Set or unset 1 bit bool ACF CAN PDU field as specified in the IEEE 1722 Specification.
 *
 * @param can_pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 */
void Avtp_Can_EnableMtv(Avtp_Can_t* pdu);
void Avtp_Can_DisableMtv(Avtp_Can_t* pdu);
void Avtp_Can_EnableRtr(Avtp_Can_t* pdu);
void Avtp_Can_DisableRtr(Avtp_Can_t* pdu);
void Avtp_Can_EnableEff(Avtp_Can_t* pdu);
void Avtp_Can_DisableEff(Avtp_Can_t* pdu);
void Avtp_Can_EnableBrs(Avtp_Can_t* pdu);
void Avtp_Can_DisableBrs(Avtp_Can_t* pdu);
void Avtp_Can_EnableFdf(Avtp_Can_t* pdu);
void Avtp_Can_DisableFdf(Avtp_Can_t* pdu);
void Avtp_Can_EnableEsi(Avtp_Can_t* pdu);
void Avtp_Can_DisableEsi(Avtp_Can_t* pdu);


/**
 * Copies the payload data and CAN frame ID into the ACF CAN frame. This function will
 * also set the length and pad fields while inserting the padded bytes.
 *
 * @param can_pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @param frame_id ID of the CAN frame
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload.
 * @param can_variant Classic CAN or CAN-FD
 */
void Avtp_Can_CreateAcfMessage(Avtp_Can_t* can_pdu, uint32_t frame_id, uint8_t* payload,
                        uint16_t payload_length, Avtp_CanVariant_t can_variant);

/**
 * Returns pointer to payload of an ACF CAN frame.
 *
 * @param can_pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @return Pointer to ACF CAN frame payload
 */
uint8_t* Avtp_Can_GetPayload(Avtp_Can_t* can_pdu);

/**
 * Sets the CAN payload in an ACF CAN frame.
 *
 * @param can_pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the payload
 */
void Avtp_Can_SetPayload(Avtp_Can_t* can_pdu, uint8_t* payload,
                                uint16_t payload_length);

/**
 * Finalizes the ACF CAN frame. This function will set the
 * length and pad fields while inserting the padded bytes.
 *
 * @param can_pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @param payload Pointer to the payload byte array
 * @param payload_length Length of the CAN frame payload.
 */
void Avtp_Can_Finalize(Avtp_Can_t* can_pdu, uint16_t payload_length);

/**
 * Returns the length of the CAN payload without the padding bytes and the
 * header length of the encapsulating ACF Frame.
 *
 * @param pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @return  Length of CAN payload in bytes
 */
uint8_t Avtp_Can_GetCanPayloadLength(Avtp_Can_t* pdu);


/**
 * Checks if the ACF CAN frame is valid by checking:
 *     1) if the length field of AVTP/ACF messages contains a value larger than the actual size of the buffer that contains the AVTP message.
 *     2) if other format specific invariants are not upheld
 * @param pdu Pointer to the first bit of an 1722 ACF CAN PDU.
 * @param bufferSize Size of the buffer containing the ACF CAN frame.
 * @return true if the ACF CAN frame is valid, false otherwise.
 */
uint8_t Avtp_Can_IsValid(Avtp_Can_t* pdu, size_t bufferSize);


#ifdef __cplusplus
}
#endif
