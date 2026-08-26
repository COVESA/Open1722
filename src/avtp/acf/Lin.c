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

#include "avtp/acf/Lin.h"

void Avtp_Lin_CreateAcfMessage(Avtp_Lin_t *pdu, uint8_t lin_bus_id, uint8_t lin_identifier,
                               uint64_t message_timestamp, uint8_t *payload,
                               uint16_t payload_length)
{
    // Copy the payload into the LIN PDU
    Avtp_Lin_SetPayload(pdu, payload, payload_length);

    // Set the LIN bus ID, identifier and message timestamp
    Avtp_Lin_SetLinBusId(pdu, lin_bus_id);
    Avtp_Lin_SetLinIdentifier(pdu, lin_identifier);
    Avtp_Lin_SetMessageTimestamp(pdu, message_timestamp);

    // Finalize the AVTP LIN Frame
    Avtp_Lin_SetPayloadLength(pdu, payload_length);
}

bool Avtp_Lin_IsValid(const Avtp_Lin_t* const pdu, size_t bufferSize)
{
    if (pdu == NULL) {
        return false;
    }

    if (bufferSize < AVTP_LIN_HEADER_LEN) {
        return false;
    }

    if (Avtp_Lin_GetAcfMsgType(pdu) != AVTP_ACF_TYPE_LIN) {
        return false;
    }

    // Avtp_Lin_GetAcfMsgLength returns quadlets. Convert the length field to octets.
    uint16_t msg_length_bytes = (uint16_t)Avtp_Lin_GetAcfMsgLength(pdu) * 4;
    if (msg_length_bytes > bufferSize) {
        return false;
    }

    /* LIN payload-length invariant: the encoded message length must also
     * accommodate header + declared padding so the payload computation in
     * Avtp_Lin_GetPayloadLength() doesn't underflow. */
    uint8_t pad_length = Avtp_Lin_GetPad(pdu);
    uint16_t header_and_pad = (uint16_t)AVTP_LIN_HEADER_LEN + pad_length;
    if (msg_length_bytes < header_and_pad) {
        return false;
    }
    uint16_t payload_length = msg_length_bytes - header_and_pad;
    if (payload_length > 8u) {
        return false;
    }
    return true;
}
