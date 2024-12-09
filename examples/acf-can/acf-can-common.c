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

#include <linux/if.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

#include "avtp/Udp.h"
#include "avtp/acf/Ntscf.h"
#include "avtp/acf/Tscf.h"
#include "acf-can-common.h"

int setup_can_socket(const char* can_ifname,
                     Avtp_CanVariant_t can_variant) {

    int can_socket, res;
    struct ifreq ifr;
    struct sockaddr_can can_addr;

    can_socket = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (can_socket < 0) return can_socket;

    strcpy(ifr.ifr_name, can_ifname);
    ioctl(can_socket, SIOCGIFINDEX, &ifr);

    memset(&can_addr, 0, sizeof(can_addr));
    can_addr.can_family = AF_CAN;
    can_addr.can_ifindex = ifr.ifr_ifindex;

    if (can_variant == AVTP_CAN_FD) {
        int enable_canfx = 1;
        setsockopt(can_socket, SOL_CAN_RAW, CAN_RAW_FD_FRAMES,
                    &enable_canfx, sizeof(enable_canfx));
    }

    res = bind(can_socket, (struct sockaddr *)&can_addr, sizeof(can_addr));
    if (res < 0) {
        close(can_socket);
        return res;
    }

    return can_socket;
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

    int processedBytes;
    struct timespec now;
    canid_t can_id;

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
    can_id = (can_variant == AVTP_CAN_FD) ? frame->fd.can_id : frame->cc.can_id;
    Avtp_Can_SetField(pdu, AVTP_CAN_FIELD_RTR, can_id & CAN_RTR_FLAG);
    Avtp_Can_SetField(pdu, AVTP_CAN_FIELD_EFF, can_id & CAN_EFF_FLAG);

    if (can_variant == AVTP_CAN_FD) {
        Avtp_Can_SetField(pdu, AVTP_CAN_FIELD_BRS, frame->fd.flags & CANFD_BRS);
        Avtp_Can_SetField(pdu, AVTP_CAN_FIELD_FDF, frame->fd.flags & CANFD_FDF);
        Avtp_Can_SetField(pdu, AVTP_CAN_FIELD_ESI, frame->fd.flags & CANFD_ESI);
    }

    // Copy payload to ACF CAN PDU
    if(can_variant == AVTP_CAN_FD)
        Avtp_Can_CreateAcfMessage(pdu, frame->fd.can_id & CAN_EFF_MASK, frame->fd.data,
                                         frame->fd.len, can_variant);
    else
        Avtp_Can_CreateAcfMessage(pdu, frame->cc.can_id & CAN_EFF_MASK, frame->cc.data,
                                         frame->cc.len, can_variant);

    return Avtp_Can_GetAcfMsgLength(pdu)*4;
}

void can_to_avtp(int eth_socket, int can_socket,
                    Avtp_CanVariant_t can_variant,
                     int use_udp, int use_tscf, uint64_t stream_id,
                     uint8_t num_acf_msgs, struct sockaddr* dst_addr) {

    uint8_t cf_seq_num = 0;
    uint32_t udp_seq_num = 0;

    uint8_t pdu[MAX_ETH_PDU_SIZE];
    uint16_t pdu_length = 0, cf_length = 0;
    frame_t can_frame;
    int res;

    // Sending loop
    for(;;) {

        // Pack into control formats
        uint8_t *cf_pdu;
        pdu_length = 0;
        cf_length = 0;

        // Usage of UDP means the PDU needs a
        if (use_udp) {
            Avtp_Udp_t *udp_pdu = (Avtp_Udp_t *) pdu;
            Avtp_Udp_SetField(udp_pdu, AVTP_UDP_FIELD_ENCAPSULATION_SEQ_NO,
                              udp_seq_num++);
            pdu_length +=  sizeof(Avtp_Udp_t);
        }

        cf_pdu = pdu + pdu_length;
        res = init_cf_pdu(cf_pdu, stream_id, use_tscf, cf_seq_num++);
        pdu_length += res;
        cf_length += res;

        int i = 0;
        while (i < num_acf_msgs) {
            // Get payload -- will 'spin' here until we get the requested number
            //                of CAN frames.
            if(can_variant == AVTP_CAN_FD){
                res = read(can_socket, &can_frame.fd, sizeof(struct canfd_frame));
            } else {
                res = read(can_socket, &can_frame.cc, sizeof(struct can_frame));
            }
            if (!res) continue;

            uint8_t* acf_pdu = pdu + pdu_length;
            res = prepare_acf_packet(acf_pdu, &can_frame, can_variant);
            pdu_length += res;
            cf_length += res;
            i++;
        }

        update_cf_length(cf_pdu, cf_length, use_tscf);

        if (use_udp) {
            res = sendto(eth_socket, pdu, pdu_length, 0,
                    (struct sockaddr *) dst_addr, sizeof(struct sockaddr_in));
        } else {
            res = sendto(eth_socket, pdu, pdu_length, 0,
                         (struct sockaddr *) dst_addr, sizeof(struct sockaddr_ll));
        }
        if (res < 0) {
            perror("Failed to send data");
        }
    }

}

void avtp_to_can(int eth_socket, int can_socket, int udp, uint64_t stream_id) {

}