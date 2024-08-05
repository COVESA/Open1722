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

#include "avtp/acf/Common.h"
#include "avtp/acf/Can.h"
#include "avtp/Utils.h" 
#include "avtp/Defines.h"

/**
 * This table maps all IEEE 1722 ACF CAN header fields to a descriptor.
 */
static const Avtp_FieldDescriptor_t Avtp_CanFieldDesc[AVTP_CAN_FIELD_MAX] =
{
    /* ACF common header fields */
    [AVTP_CAN_FIELD_ACF_MSG_TYPE]       = { .quadlet = 0, .offset =  0, .bits = 7 },
    [AVTP_CAN_FIELD_ACF_MSG_LENGTH]     = { .quadlet = 0, .offset =  7, .bits = 9 },  
    /* ACF CAN header fields */
    [AVTP_CAN_FIELD_PAD]                = { .quadlet = 0, .offset = 16, .bits =  2 },
    [AVTP_CAN_FIELD_MTV]                = { .quadlet = 0, .offset = 18, .bits =  1 },
    [AVTP_CAN_FIELD_RTR]                = { .quadlet = 0, .offset = 19, .bits =  1 },
    [AVTP_CAN_FIELD_EFF]                = { .quadlet = 0, .offset = 20, .bits =  1 },
    [AVTP_CAN_FIELD_BRS]                = { .quadlet = 0, .offset = 21, .bits =  1 },
    [AVTP_CAN_FIELD_FDF]                = { .quadlet = 0, .offset = 22, .bits =  1 },
    [AVTP_CAN_FIELD_ESI]                = { .quadlet = 0, .offset = 23, .bits =  1 },
    [AVTP_CAN_FIELD_CAN_BUS_ID]         = { .quadlet = 0, .offset = 27, .bits =  5 },
    [AVTP_CAN_FIELD_MESSAGE_TIMESTAMP]  = { .quadlet = 1, .offset =  0, .bits = 64 },
    [AVTP_CAN_FIELD_CAN_IDENTIFIER]     = { .quadlet = 3, .offset =  3, .bits = 29 },    
};

int Avtp_Can_Init(Avtp_Can_t* can_pdu)
{
    if(!can_pdu) {
        return -EINVAL;
    }

    memset(can_pdu, 0, sizeof(Avtp_Can_t));  
    Avtp_Can_SetField(can_pdu, AVTP_CAN_FIELD_ACF_MSG_TYPE, AVTP_ACF_TYPE_CAN);

    return 0;
}

int Avtp_Can_GetField(Avtp_Can_t* can_pdu, 
                            Avtp_CanFields_t field, uint64_t* value)
{    
    return Avtp_GetField(Avtp_CanFieldDesc, AVTP_CAN_FIELD_MAX, (uint8_t *) can_pdu, (uint8_t) field, value);
}

int Avtp_Can_SetField(Avtp_Can_t* can_pdu, 
                            Avtp_CanFields_t field, uint64_t value)
{    
    return Avtp_SetField(Avtp_CanFieldDesc, AVTP_CAN_FIELD_MAX, (uint8_t *) can_pdu, (uint8_t) field, value);
}

int Avtp_Can_SetPayload(Avtp_Can_t* can_pdu, uint32_t frame_id , uint8_t* payload, 
                        uint16_t payload_length, Avtp_CanVariant_t can_variant) {

    int ret = 0;
    int eff;

    // Copy the payload into the CAN PDU
    memcpy(can_pdu->payload, payload, payload_length);

    // Set the Frame ID and CAN variant
    eff = frame_id > 0x7ff? 1 : 0;
    ret = Avtp_Can_SetField(can_pdu, AVTP_CAN_FIELD_EFF, eff);
    if (ret) return ret;
    ret = Avtp_Can_SetField(can_pdu, AVTP_CAN_FIELD_CAN_IDENTIFIER, frame_id);
    if (ret) return ret;
    ret = Avtp_Can_SetField(can_pdu, AVTP_CAN_FIELD_FDF, (uint8_t) can_variant);
    if (ret) return ret;

    // Finalize the AVTP CAN Frame
    ret = Avtp_Can_Finalize(can_pdu, payload_length);

    return ret;

}

int Avtp_Can_Finalize(Avtp_Can_t* can_pdu, uint16_t payload_length) {

    int ret = 0;
    uint8_t padSize;
    uint32_t avtpCanLength = AVTP_CAN_HEADER_LEN + payload_length;

    // Check if padding is required
    padSize = AVTP_QUADLET_SIZE - (payload_length % AVTP_QUADLET_SIZE);
    if (payload_length % AVTP_QUADLET_SIZE) {
        memset(can_pdu->payload + payload_length, 0, padSize);
        avtpCanLength += padSize;
    }

    // Set the length and padding fields
    ret = Avtp_Can_SetField(can_pdu, AVTP_CAN_FIELD_ACF_MSG_LENGTH, 
                        (uint64_t) avtpCanLength/AVTP_QUADLET_SIZE);
    if (ret) return ret;
    ret = Avtp_Can_SetField(can_pdu, AVTP_CAN_FIELD_PAD, padSize);
    if (ret) return ret;

    return avtpCanLength;
}

uint8_t* Avtp_Can_GetPayload(Avtp_Can_t* can_pdu, uint16_t* payload_length, uint16_t *pdu_length)
{
    uint64_t pad_len, pdu_len;
    int res = Avtp_Can_GetField((Avtp_Can_t*)can_pdu, AVTP_CAN_FIELD_ACF_MSG_LENGTH,
                                    &pdu_len);
    if (res < 0) {    
        return 0;
    }

    res = Avtp_Can_GetField((Avtp_Can_t*)can_pdu, AVTP_CAN_FIELD_PAD, 
                                &pad_len);
    if (res < 0) {        
        return 0;
    }
    
    if(payload_length != NULL){
        *payload_length = pdu_len*4-AVTP_CAN_HEADER_LEN-pad_len;
    }

    if(pdu_length != NULL){
        *pdu_length = pdu_len;
    }

    return can_pdu->payload;
}