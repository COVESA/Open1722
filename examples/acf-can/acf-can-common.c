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
#include <poll.h>

#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

#include "avtp/Udp.h"
#include "avtp/CommonHeader.h"
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

static int is_valid_acf_packet(uint8_t* acf_pdu)
{
    Avtp_AcfCommon_t *pdu = (Avtp_AcfCommon_t*) acf_pdu;
    uint8_t acf_msg_type = Avtp_AcfCommon_GetAcfMsgType(pdu);
    if (acf_msg_type != AVTP_ACF_TYPE_CAN) {
        return 0;
    }

    return 1;
}

static int new_packet(int eth_socket, int can_socket,
                      int use_udp, Avtp_CanVariant_t can_variant,
                      uint64_t stream_id) {

    int res = 0;
    uint64_t proc_bytes = 0, msg_proc_bytes = 0, s_id;
    uint32_t udp_seq_num;
    uint16_t msg_length, can_payload_length, acf_msg_length, seq_num;
    uint8_t subtype;
    uint8_t pdu[MAX_ETH_PDU_SIZE], i;
    uint8_t *cf_pdu, *acf_pdu, *udp_pdu, *can_payload;
    frame_t frame;
    canid_t can_id;

    memset(&frame, 0, sizeof(struct canfd_frame));
    res = recv(eth_socket, pdu, MAX_ETH_PDU_SIZE, 0);
    if (res < 0 || res > MAX_ETH_PDU_SIZE) {
        perror("Failed to receive data");
        return -1;
    }

    // Check for UDP encapsulation
    if (use_udp) {
        udp_pdu = pdu;
        udp_seq_num = Avtp_Udp_GetEncapsulationSeqNo((Avtp_Udp_t *)udp_pdu);
        cf_pdu = pdu + AVTP_UDP_HEADER_LEN;
        proc_bytes += AVTP_UDP_HEADER_LEN;
    } else {
        cf_pdu = pdu;
    }

    // Only NTSCF and TSCF formats allowed
    subtype = Avtp_CommonHeader_GetSubtype((Avtp_CommonHeader_t*)cf_pdu);
    if (subtype == AVTP_SUBTYPE_TSCF) {
        proc_bytes += AVTP_TSCF_HEADER_LEN;
        msg_length = Avtp_Tscf_GetStreamDataLength((Avtp_Tscf_t*)cf_pdu);
        s_id = Avtp_Tscf_GetStreamId((Avtp_Tscf_t*)cf_pdu);
        seq_num = Avtp_Tscf_GetSequenceNum((Avtp_Tscf_t*)cf_pdu);
    } else if (subtype == AVTP_SUBTYPE_NTSCF) {
        proc_bytes += AVTP_NTSCF_HEADER_LEN;
        msg_length = Avtp_Ntscf_GetNtscfDataLength((Avtp_Ntscf_t*)cf_pdu);
        s_id = Avtp_Ntscf_GetStreamId((Avtp_Ntscf_t*)cf_pdu);
        seq_num = Avtp_Ntscf_GetSequenceNum((Avtp_Ntscf_t*)cf_pdu);
    } else {
        return -1;
    }

    // Check for stream id
    if (s_id != stream_id) {
        return -1;
    }

    while (msg_proc_bytes < msg_length) {

        acf_pdu = &pdu[proc_bytes + msg_proc_bytes];

        if (!is_valid_acf_packet(acf_pdu)) {
            return -1;
        }

        can_id = Avtp_Can_GetCanIdentifier((Avtp_Can_t*)acf_pdu);

        can_payload = Avtp_Can_GetPayload((Avtp_Can_t*)acf_pdu);
        acf_msg_length = Avtp_Can_GetAcfMsgLength((Avtp_Can_t*)acf_pdu)*4;
        can_payload_length = Avtp_Can_GetCanPayloadLength((Avtp_Can_t*)acf_pdu);
        msg_proc_bytes += acf_msg_length;

        // Handle EFF Flag
        if (Avtp_Can_GetEff((Avtp_Can_t*)acf_pdu)) {
            can_id |= CAN_EFF_FLAG;
        } else if (can_id > 0x7FF) {
            fprintf(stderr, "Error: CAN ID is > 0x7FF but the EFF bit is not set.\n");
            return -1;
        }

        // Handle RTR Flag
        if (Avtp_Can_GetRtr((Avtp_Can_t*)acf_pdu)) {
            can_id |= CAN_RTR_FLAG;
        }

        if (can_variant == AVTP_CAN_FD) {
            if (Avtp_Can_GetBrs((Avtp_Can_t*)acf_pdu)) {
                frame.fd.flags |= CANFD_BRS;
            }
            if (Avtp_Can_GetFdf((Avtp_Can_t*)acf_pdu)) {
                frame.fd.flags |= CANFD_FDF;
            }
            if (Avtp_Can_GetEsi((Avtp_Can_t*)acf_pdu)) {
                frame.fd.flags |= CANFD_ESI;
            }
            frame.fd.can_id = can_id;
            frame.fd.len = can_payload_length;
            memcpy(frame.fd.data, can_payload, can_payload_length);
            res = write(can_socket, &frame.fd, sizeof(struct canfd_frame));
        } else {
            frame.cc.can_id = can_id;
            frame.cc.len = can_payload_length;
            memcpy(frame.cc.data, can_payload, can_payload_length);
            res = write(can_socket, &frame.cc, sizeof(struct can_frame));
        }

        if(res < 0)
        {
            perror("Failed to write to CAN bus");
            return res;
        }
    }
    return seq_num;
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

void avtp_to_can(int eth_socket, int can_socket,
                    Avtp_CanVariant_t can_variant,
                     int use_udp, uint64_t stream_id) {

    uint16_t pdu_length = 0, cf_length = 0;
    struct pollfd fds;
    int res;
    uint8_t seq_num = -1;

    fds.fd = eth_socket;
    fds.events = POLLIN;

    while (1) {

        res = poll(&fds, 1, -1);
        if (res < 0) {
            perror("Failed to poll() fds");
        }

        if (fds.revents & POLLIN) {
            res = new_packet(eth_socket, can_socket, use_udp,
                                can_variant, stream_id);
            if (res < 0) {
                continue;
            }
            if ((++seq_num != res) && (res != 0)) {
                printf("Incorrect sequence num. Expected: %d Recd.: %d\n", seq_num, res);
                seq_num = res;
            }
        }
    }
}