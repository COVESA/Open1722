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

#include "avtp/acf/Can.h"

void Avtp_Can_CreateAcfMessage(Avtp_Can_t* pdu, uint32_t frame_id, uint8_t* payload,
                        uint16_t payload_length, Avtp_CanVariant_t can_variant)
{
    // Copy the payload into the CAN PDU
    Avtp_Can_SetPayload(pdu, payload, payload_length);

    // Set the Frame ID and CAN variant
    if (frame_id > 0x7ff) {
        Avtp_Can_EnableEff(pdu);
    }

    Avtp_Can_SetCanIdentifier(pdu, frame_id);
    if (can_variant == AVTP_CAN_FD) {
        Avtp_Can_EnableFdf(pdu);
    }

    // Finalize the AVTP CAN Frame
    Avtp_Can_Finalize(pdu, payload_length);
}

void Avtp_Can_Finalize(Avtp_Can_t* pdu, uint16_t payload_length)
{
    uint8_t padSize;
    uint32_t avtpCanLength = AVTP_CAN_HEADER_LEN + payload_length;

    // Check if padding is required
    padSize = AVTP_QUADLET_SIZE - (payload_length % AVTP_QUADLET_SIZE);
    if (payload_length % AVTP_QUADLET_SIZE) {
        memset(pdu->payload + payload_length, 0, padSize);
        avtpCanLength += padSize;
    }

    // Set the length and padding fields
    Avtp_Can_SetAcfMsgLength(pdu, (uint16_t) avtpCanLength/AVTP_QUADLET_SIZE);
    Avtp_Can_SetPad(pdu, padSize);
}

uint8_t Avtp_Can_GetCanPayloadLength(const Avtp_Can_t* const pdu)
{
    /* CAN-FD's maximum valid payload is 64 bytes (classic CAN: 8). Any
     * encoded length outside that range cannot represent a valid CAN
     * frame, so we reject by returning 0 rather than silently producing
     * a wrong number.
     *
     * The earlier implementation stored both the byte-count and the
     * return value in uint8_t. The byte-count is computed as
     * AcfMsgLength * 4, where AcfMsgLength is a 9-bit field, so the
     * (uint8_t)(...*4) truncated mod 256 for any frame whose AcfMsgLength
     * exceeded 63 quadlets — yielding a plausible-looking but incorrect
     * payload length. We compute in uint16_t internally and bounds-
     * reject before narrowing back to uint8_t for the return. */
    static const uint16_t MAX_CAN_FD_PAYLOAD = 64;
    uint16_t msg_length_bytes = (uint16_t)Avtp_Can_GetAcfMsgLength(pdu) * 4;
    uint8_t  pad_length       = Avtp_Can_GetPad(pdu);
    uint16_t header_and_pad   = (uint16_t)AVTP_CAN_HEADER_LEN + pad_length;

    /* Underflow guard: header + pad must not exceed the encoded message
     * length. Otherwise the subtraction below wraps and we'd return a
     * huge value cast to uint8_t. */
    if (msg_length_bytes < header_and_pad) {
        return 0;
    }
    uint16_t payload_length = msg_length_bytes - header_and_pad;

    /* Overflow guard: a valid CAN/CAN-FD payload can't exceed 64 bytes. */
    if (payload_length > MAX_CAN_FD_PAYLOAD) {
        return 0;
    }
    return (uint8_t)payload_length;
}

uint8_t Avtp_Can_IsValid(const Avtp_Can_t* const pdu, size_t bufferSize)
{
    if (pdu == NULL) {
        return FALSE;
    }

    if (bufferSize < AVTP_CAN_HEADER_LEN) {
        return FALSE;
    }

    if (Avtp_Can_GetAcfMsgType(pdu) != AVTP_ACF_TYPE_CAN) {
        return FALSE;
    }

    // Avtp_Can_GetAcfMsgLength returns quadlets. Convert the length field to octets
    if (Avtp_Can_GetAcfMsgLength(pdu) * 4 > bufferSize) {
        return FALSE;
    }
    return TRUE;
}
