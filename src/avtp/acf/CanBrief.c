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

#include "avtp/acf/CanBrief.h"

void Avtp_CanBrief_CreateAcfMessage(Avtp_CanBrief_t *pdu, uint32_t frame_id, uint8_t *payload,
                                    uint16_t payload_length, Avtp_CanVariant_t can_variant)
{
    // Copy the payload into the CAN PDU
    Avtp_CanBrief_SetPayload(pdu, payload, payload_length);

    // Set the Frame ID and CAN variant
    if (frame_id > 0x7ff) {
        Avtp_CanBrief_SetEff(pdu, true);
    }

    Avtp_CanBrief_SetCanIdentifier(pdu, frame_id);
    if (can_variant == AVTP_CAN_FD) {
        Avtp_CanBrief_SetFdf(pdu, true);
    }

    // Finalize the AVTP CAN Frame
    Avtp_CanBrief_SetPayloadLength(pdu, payload_length);
}

bool Avtp_CanBrief_IsValid(const Avtp_CanBrief_t *const pdu, size_t bufferSize)
{
    if (pdu == NULL) {
        return false;
    }

    if (bufferSize < AVTP_CAN_BRIEF_HEADER_LEN) {
        return false;
    }

    if (Avtp_CanBrief_GetAcfMsgType(pdu) != AVTP_ACF_TYPE_CAN_BRIEF) {
        return false;
    }

    // Avtp_CanBrief_GetAcfMsgLength returns quadlets. Convert the length field to octets.
    uint16_t msg_length_bytes = (uint16_t)Avtp_CanBrief_GetAcfMsgLength(pdu) * 4;
    if (msg_length_bytes > bufferSize) {
        return false;
    }

    /* CAN payload-length invariant: classic CAN ≤ 8 bytes, CAN-FD ≤ 64
     * bytes (selected by the FDF bit). The encoded message length must
     * also accommodate header + declared padding so the payload
     * computation in Avtp_CanBrief_GetPayloadLength() doesn't underflow. */
    uint8_t pad_length = Avtp_CanBrief_GetPad(pdu);
    uint16_t header_and_pad = (uint16_t)AVTP_CAN_BRIEF_HEADER_LEN + pad_length;
    if (msg_length_bytes < header_and_pad) {
        return false;
    }
    uint16_t payload_length = msg_length_bytes - header_and_pad;
    uint16_t max_payload = Avtp_CanBrief_IsFdf(pdu) ? 64u : 8u;
    if (payload_length > max_payload) {
        return false;
    }
    return true;
}
