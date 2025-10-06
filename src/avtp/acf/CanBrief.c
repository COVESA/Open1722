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

#include "avtp/acf/CanBrief.h"

void Avtp_CanBrief_CreateAcfMessage(Avtp_CanBrief_t* can_pdu, uint32_t frame_id, uint8_t* payload,
    uint16_t payload_length, Avtp_CanVariant_t can_variant)
{
    // Copy the payload into the CAN PDU
    Avtp_CanBrief_SetPayload(can_pdu, payload, payload_length);

    // Set the Frame ID and CAN variant
    if (frame_id > 0x7ff) {
        Avtp_CanBrief_EnableEff(can_pdu);
    }

    Avtp_CanBrief_SetCanIdentifier(can_pdu, frame_id);
    if (can_variant == AVTP_CAN_FD) {
        Avtp_CanBrief_EnableFdf(can_pdu);
    }

    // Finalize the AVTP CAN Frame
    Avtp_CanBrief_Finalize(can_pdu, payload_length);
}

void Avtp_CanBrief_SetPayload(Avtp_CanBrief_t* can_pdu, uint8_t* payload,
    uint16_t payload_length)
{
    memcpy(can_pdu->payload, payload, payload_length);
}

void Avtp_CanBrief_Finalize(Avtp_CanBrief_t* can_pdu, uint16_t payload_length)
{
    uint8_t padSize;
    uint32_t avtpCanLength = AVTP_CAN_BRIEF_HEADER_LEN + payload_length;

    // Check if padding is required
    padSize = AVTP_QUADLET_SIZE - (payload_length % AVTP_QUADLET_SIZE);
    if (payload_length % AVTP_QUADLET_SIZE) {
        memset(can_pdu->payload + payload_length, 0, padSize);
        avtpCanLength += padSize;
    }

    // Set the length and padding fields
    Avtp_CanBrief_SetAcfMsgLength(can_pdu, (uint16_t) avtpCanLength/AVTP_QUADLET_SIZE);
    Avtp_CanBrief_SetPad(can_pdu, padSize);
}

const uint8_t* Avtp_CanBrief_GetPayload(const Avtp_CanBrief_t* const can_pdu) {
    return can_pdu->payload;
}

uint8_t Avtp_CanBrief_GetCanPayloadLength(const Avtp_CanBrief_t* const pdu) {
    uint8_t acf_msg_length = Avtp_CanBrief_GetAcfMsgLength(pdu) * 4;
    uint8_t acf_pad_length = Avtp_CanBrief_GetPad(pdu);
    return acf_msg_length - AVTP_CAN_BRIEF_HEADER_LEN - acf_pad_length;
}

uint8_t Avtp_CanBrief_IsValid(const Avtp_CanBrief_t* const pdu, size_t bufferSize)
{
    if (pdu == NULL) {
        return FALSE;
    }

    if (bufferSize < AVTP_CAN_BRIEF_HEADER_LEN) {
        return FALSE;
    }

    if (Avtp_CanBrief_GetAcfMsgType(pdu) != AVTP_ACF_TYPE_CAN_BRIEF) {
        return FALSE;
    }

    // Avtp_CanBrief_GetAcfMsgLength returns quadlets. Convert the length field to octets
    if (Avtp_CanBrief_GetAcfMsgLength(pdu) * 4 > bufferSize) {
        return FALSE;
    }

    return TRUE;
}