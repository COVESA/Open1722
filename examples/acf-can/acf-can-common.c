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

#ifdef __linux__
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <sys/ioctl.h>
#elif defined(__ZEPHYR__)
#include <zephyr/kernel.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/socketcan.h>
#include <zephyr/net/socketcan_utils.h>
#include <zephyr/net/ethernet.h>

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(acf_can_common, LOG_LEVEL_DBG);
#endif

#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

#include "avtp/Udp.h"
#include "avtp/CommonHeader.h"
#include "avtp/acf/Ntscf.h"
#include "avtp/acf/Tscf.h"
#include "acf-can-common.h"

#ifdef __ZEPHYR__
typedef uint32_t canid_t;
#endif

#ifdef __linux__
int setup_can_socket(const char* can_ifname,
                     Avtp_CanVariant_t can_variant) {

    int can_socket, res;
    struct sockaddr_can can_addr;

    can_socket = socket(AF_CAN, SOCK_RAW, CAN_RAW);
    if (can_socket < 0) {
        perror("Failed to create CAN socket");
        return can_socket;
    }

    // Get the CAN address to bind the socket to.
    memset(&can_addr, 0, sizeof(can_addr));

    struct ifreq ifr;
    strcpy(ifr.ifr_name, can_ifname);
    ioctl(can_socket, SIOCGIFINDEX, &ifr);
    can_addr.can_family = AF_CAN;
    can_addr.can_ifindex = ifr.ifr_ifindex;

    if (can_variant == AVTP_CAN_FD) {
        int enable_canfx = 1;
        setsockopt(can_socket, SOL_CAN_RAW, CAN_RAW_FD_FRAMES,
                    &enable_canfx, sizeof(enable_canfx));
    }

    res = bind(can_socket, (struct sockaddr *)&can_addr, sizeof(can_addr));
    if (res < 0) {
        perror("Failed to bind CAN socket");
        close(can_socket);
        return res;
    }

    return can_socket;
}
#endif

static int is_valid_acf_packet(uint8_t* acf_pdu)
{
    Avtp_AcfCommon_t *pdu = (Avtp_AcfCommon_t*) acf_pdu;
    uint8_t acf_msg_type = Avtp_AcfCommon_GetAcfMsgType(pdu);
    if (acf_msg_type != AVTP_ACF_TYPE_CAN) {
        return 0;
    }

    return 1;
}

static int init_cf_pdu(uint8_t* pdu, uint64_t stream_id, int use_tscf, int seq_num)
{
    int res;
    if (use_tscf) {
        Avtp_Tscf_t* tscf_pdu = (Avtp_Tscf_t*) pdu;
        memset(tscf_pdu, 0, AVTP_TSCF_HEADER_LEN);
        Avtp_Tscf_Init(tscf_pdu);
        Avtp_Tscf_SetField(tscf_pdu, AVTP_TSCF_FIELD_TU, 0U);
        Avtp_Tscf_SetField(tscf_pdu, AVTP_TSCF_FIELD_SEQUENCE_NUM, seq_num);
        Avtp_Tscf_SetField(tscf_pdu, AVTP_TSCF_FIELD_STREAM_ID, stream_id);
        res = AVTP_TSCF_HEADER_LEN;
    } else {
        Avtp_Ntscf_t* ntscf_pdu = (Avtp_Ntscf_t*) pdu;
        memset(ntscf_pdu, 0, AVTP_NTSCF_HEADER_LEN);
        Avtp_Ntscf_Init(ntscf_pdu);
        Avtp_Ntscf_SetField(ntscf_pdu, AVTP_NTSCF_FIELD_SEQUENCE_NUM, seq_num);
        Avtp_Ntscf_SetField(ntscf_pdu, AVTP_NTSCF_FIELD_STREAM_ID, stream_id);
        res = AVTP_NTSCF_HEADER_LEN;
    }
    return res;
}

static int update_cf_length(uint8_t* cf_pdu, uint64_t length, int use_tscf)
{
    if (use_tscf) {
        uint64_t payloadLen = length - AVTP_TSCF_HEADER_LEN;
        Avtp_Tscf_SetField((Avtp_Tscf_t*)cf_pdu, AVTP_TSCF_FIELD_STREAM_DATA_LENGTH, payloadLen);
    } else {
        uint64_t payloadLen = length - AVTP_NTSCF_HEADER_LEN;
        Avtp_Ntscf_SetField((Avtp_Ntscf_t*)cf_pdu, AVTP_NTSCF_FIELD_NTSCF_DATA_LENGTH, payloadLen);
    }
    return 0;
}

static int prepare_acf_packet(uint8_t* acf_pdu,
                              frame_t* frame,
                              Avtp_CanVariant_t can_variant) {

    struct timespec now;
    canid_t can_id;
    uint8_t can_payload_length;

    // Clear bits
    Avtp_Can_t* pdu = (Avtp_Can_t*) acf_pdu;
    memset(pdu, 0, AVTP_CAN_HEADER_LEN);

    // Prepare ACF PDU for CAN
    Avtp_Can_Init(pdu);
    clock_gettime(CLOCK_REALTIME, &now);
    Avtp_Can_SetField(pdu, AVTP_CAN_FIELD_MESSAGE_TIMESTAMP,
                      (uint64_t)now.tv_nsec + (uint64_t)(now.tv_sec * 1e9));
    Avtp_Can_SetField(pdu, AVTP_CAN_FIELD_MTV, 1U);

    // Set required CAN Flags
#ifdef __linux__
    can_id = (can_variant == AVTP_CAN_FD) ? (*frame).fd.can_id : (*frame).cc.can_id;
    can_payload_length = (can_variant == AVTP_CAN_FD) ? (*frame).fd.len : (*frame).cc.len;
#elif defined(__ZEPHYR__)
    can_id = (can_variant == AVTP_CAN_FD) ? (*frame).fd.id : (*frame).cc.id;
    can_payload_length = (can_variant == AVTP_CAN_FD) ? (*frame).fd.dlc : (*frame).cc.dlc;
#endif
    Avtp_Can_SetField(pdu, AVTP_CAN_FIELD_RTR, can_id & CAN_RTR_FLAG);
    Avtp_Can_SetField(pdu, AVTP_CAN_FIELD_EFF, can_id & CAN_EFF_FLAG);

    if (can_variant == AVTP_CAN_FD) {
        Avtp_Can_SetField(pdu, AVTP_CAN_FIELD_BRS, frame->fd.flags & CANFD_BRS);
        Avtp_Can_SetField(pdu, AVTP_CAN_FIELD_FDF, frame->fd.flags & CANFD_FDF);
        Avtp_Can_SetField(pdu, AVTP_CAN_FIELD_ESI, frame->fd.flags & CANFD_ESI);
    }

    // Copy payload to ACF CAN PDU
    if(can_variant == AVTP_CAN_FD)
        Avtp_Can_CreateAcfMessage(pdu, can_id & CAN_EFF_MASK, frame->fd.data,
                                         can_payload_length, can_variant);
    else
        Avtp_Can_CreateAcfMessage(pdu, can_id & CAN_EFF_MASK, frame->cc.data,
                                         can_payload_length, can_variant);

    return Avtp_Can_GetAcfMsgLength(pdu)*4;
}

int can_to_avtp(frame_t* can_frames, Avtp_CanVariant_t can_variant, uint8_t* pdu,
                     int use_udp, int use_tscf, uint64_t stream_id,
                     uint8_t num_acf_msgs, uint8_t cf_seq_num, uint32_t udp_seq_num) {

    // Pack into control formats
    uint8_t *cf_pdu;
    uint16_t pdu_length = 0, cf_length = 0;
    int res;

    // Usage of UDP means the PDU needs an encapsulation
    if (use_udp) {
        Avtp_Udp_t *udp_pdu = (Avtp_Udp_t *) pdu;
        Avtp_Udp_SetField(udp_pdu, AVTP_UDP_FIELD_ENCAPSULATION_SEQ_NO,
                            udp_seq_num);
        pdu_length +=  sizeof(Avtp_Udp_t);
    }

    // Prepare the control format: TSCF/NTSCF
    cf_pdu = pdu + pdu_length;
    res = init_cf_pdu(cf_pdu, stream_id, use_tscf, cf_seq_num++);
    pdu_length += res;
    cf_length += res;

    int i = 0;
    while (i < num_acf_msgs) {
        uint8_t* acf_pdu = pdu + pdu_length;
        res = prepare_acf_packet(acf_pdu, &(can_frames[i]), can_variant);
        pdu_length += res;
        cf_length += res;
        i++;
    }

    // Update the length of the PDU
    update_cf_length(cf_pdu, cf_length, use_tscf);

    return pdu_length;

}

int avtp_to_can(uint8_t* pdu, frame_t* can_frames, Avtp_CanVariant_t can_variant,
                int use_udp, uint64_t stream_id, uint8_t* exp_cf_seqnum,
                uint32_t* exp_udp_seqnum) {

    uint8_t *cf_pdu, *acf_pdu, *udp_pdu, seq_num, i = 0;
    uint32_t udp_seq_num;
    uint16_t proc_bytes = 0, msg_length = 0;
    uint64_t s_id;

    // Check for UDP encapsulation
    if (use_udp) {
        udp_pdu = pdu;
        udp_seq_num = Avtp_Udp_GetEncapsulationSeqNo((Avtp_Udp_t *)udp_pdu);
        cf_pdu = pdu + AVTP_UDP_HEADER_LEN;
        proc_bytes += AVTP_UDP_HEADER_LEN;
        msg_length += AVTP_UDP_HEADER_LEN;
        if (udp_seq_num != *exp_udp_seqnum) {
            printf("Incorrect UDP sequence num. Expected: %d Recd.: %d\n",
                                                *exp_udp_seqnum, udp_seq_num);
            *exp_udp_seqnum = udp_seq_num;
        }
    } else {
        cf_pdu = pdu;
    }

    // Only NTSCF and TSCF formats allowed
    uint8_t subtype = Avtp_CommonHeader_GetSubtype((Avtp_CommonHeader_t*)cf_pdu);
    if (subtype == AVTP_SUBTYPE_TSCF) {
        proc_bytes += AVTP_TSCF_HEADER_LEN;
        msg_length += Avtp_Tscf_GetStreamDataLength((Avtp_Tscf_t*)cf_pdu) + AVTP_TSCF_HEADER_LEN;
        s_id = Avtp_Tscf_GetStreamId((Avtp_Tscf_t*)cf_pdu);
        seq_num = Avtp_Tscf_GetSequenceNum((Avtp_Tscf_t*)cf_pdu);
    } else if (subtype == AVTP_SUBTYPE_NTSCF) {
        proc_bytes += AVTP_NTSCF_HEADER_LEN;
        msg_length += Avtp_Ntscf_GetNtscfDataLength((Avtp_Ntscf_t*)cf_pdu) + AVTP_NTSCF_HEADER_LEN;
        s_id = Avtp_Ntscf_GetStreamId((Avtp_Ntscf_t*)cf_pdu);
        seq_num = Avtp_Ntscf_GetSequenceNum((Avtp_Ntscf_t*)cf_pdu);
    } else {
        return -1;
    }

    // Check for stream id
    if (s_id != stream_id) {
        return -1;
    }

    // Check sequence numbers.
    if (seq_num != *exp_cf_seqnum) {
        printf("Incorrect sequence num. Expected: %d Recd.: %d\n",
                                            *exp_cf_seqnum, seq_num);
        *exp_cf_seqnum = seq_num;
    }

    while (proc_bytes < msg_length) {

        acf_pdu = &pdu[proc_bytes];

        if (!is_valid_acf_packet(acf_pdu)) {
            return -1;
        }

        canid_t can_id = Avtp_Can_GetCanIdentifier((Avtp_Can_t*)acf_pdu);
        uint8_t* can_payload = Avtp_Can_GetPayload((Avtp_Can_t*)acf_pdu);
        uint16_t acf_msg_length = Avtp_Can_GetAcfMsgLength((Avtp_Can_t*)acf_pdu)*4;
        uint16_t can_payload_length = Avtp_Can_GetCanPayloadLength((Avtp_Can_t*)acf_pdu);
        proc_bytes += acf_msg_length;
        frame_t* frame = &(can_frames[i++]);

        // Handle EFF Flag
        if (Avtp_Can_GetEff((Avtp_Can_t*)acf_pdu)) {
            can_id |= CAN_EFF_FLAG;
        } else if (can_id > 0x7FF) {
            printf("Error: CAN ID is > 0x7FF but the EFF bit is not set.\n");
            return -1;
        }

        // Handle RTR Flag
        if (Avtp_Can_GetRtr((Avtp_Can_t*)acf_pdu)) {
            can_id |= CAN_RTR_FLAG;
        }

        if (can_variant == AVTP_CAN_FD) {
            if (Avtp_Can_GetBrs((Avtp_Can_t*)acf_pdu)) {
                frame->fd.flags |= CANFD_BRS;
            }
            if (Avtp_Can_GetFdf((Avtp_Can_t*)acf_pdu)) {
                frame->fd.flags |= CANFD_FDF;
            }
            if (Avtp_Can_GetEsi((Avtp_Can_t*)acf_pdu)) {
                frame->fd.flags |= CANFD_ESI;
            }
#ifdef __linux__
            frame->fd.can_id = can_id;
            frame->fd.len = can_payload_length;
#elif defined(__ZEPHYR__)
            frame->fd.id = can_id;
            frame->fd.dlc = can_payload_length;
#endif
            memcpy(frame->fd.data, can_payload, can_payload_length);
        } else {
#ifdef __linux__
            frame->cc.can_id = can_id;
            frame->cc.len = can_payload_length;
#elif defined(__ZEPHYR__)
            frame->cc.id = can_id;
            frame->cc.dlc = can_payload_length;
#endif
            memcpy(frame->cc.data, can_payload, can_payload_length);
        }
    }

    return i;
}