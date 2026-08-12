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
#endif

#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

#include "avtp/Udp.h"
#include "avtp/CommonHeader.h"
#include "avtp/acf/Ntscf.h"
#include "avtp/acf/Tscf.h"
#include "acf-lin-common.h"

#ifdef __linux__
// Define LOG macros for Linux
#ifndef LOG_ERR
#define LOG_ERR(...) fprintf(stderr, "[ERROR]" __VA_ARGS__)
#endif

#ifndef LOG_DBG
#define LOG_DBG(...) fprintf(stderr, "[DEBUG]" __VA_ARGS__)
#endif

#ifndef LOG_INF
#define LOG_INF(...) fprintf(stderr, "[INFO]" __VA_ARGS__)
#endif

#endif

#ifdef __linux__
int setup_lin_socket(const char* lin_ifname) {

    int lin_socket, res;
    struct sockaddr_can lin_addr;

    lin_socket = socket(AF_CAN, SOCK_RAW, CAN_RAW);
    if (lin_socket < 0) {
        perror("Failed to create LIN socket");
        return lin_socket;
    }

    // Get the CAN address to bind the socket to.
    memset(&lin_addr, 0, sizeof(lin_addr));

    struct ifreq ifr;
    strcpy(ifr.ifr_name, lin_ifname);
    ioctl(lin_socket, SIOCGIFINDEX, &ifr);
    lin_addr.can_family = AF_CAN;
    lin_addr.can_ifindex = ifr.ifr_ifindex;

    res = bind(lin_socket, (struct sockaddr *)&lin_addr, sizeof(lin_addr));
    if (res < 0) {
        perror("Failed to bind LIN socket");
        close(lin_socket);
        return res;
    }

    return lin_socket;
}
#endif

static int is_valid_acf_packet(uint8_t* acf_pdu)
{
    Avtp_AcfCommon_t *pdu = (Avtp_AcfCommon_t*) acf_pdu;
    uint8_t acf_msg_type = Avtp_AcfCommon_GetAcfMsgType(pdu);
    if (acf_msg_type != AVTP_ACF_TYPE_LIN) {
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
        Avtp_Tscf_DisableTu(tscf_pdu);
        Avtp_Tscf_SetSequenceNum(tscf_pdu, seq_num);
        Avtp_Tscf_SetStreamId(tscf_pdu, stream_id);
        res = AVTP_TSCF_HEADER_LEN;
    } else {
        Avtp_Ntscf_t* ntscf_pdu = (Avtp_Ntscf_t*) pdu;
        memset(ntscf_pdu, 0, AVTP_NTSCF_HEADER_LEN);
        Avtp_Ntscf_Init(ntscf_pdu);
        Avtp_Ntscf_SetSequenceNum(ntscf_pdu, seq_num);
        Avtp_Ntscf_SetStreamId(ntscf_pdu, stream_id);
        res = AVTP_NTSCF_HEADER_LEN;
    }
    return res;
}

static int update_cf_length(uint8_t* cf_pdu, uint64_t length, int use_tscf)
{
    if (use_tscf) {
        uint64_t payloadLen = length - AVTP_TSCF_HEADER_LEN;
        Avtp_Tscf_SetStreamDataLength((Avtp_Tscf_t*)cf_pdu, payloadLen);
    } else {
        uint64_t payloadLen = length - AVTP_NTSCF_HEADER_LEN;
        Avtp_Ntscf_SetNtscfDataLength((Avtp_Ntscf_t*)cf_pdu, payloadLen);
    }
    return 0;
}

static int prepare_lin_acf_packet(uint8_t* acf_pdu,
                                  struct can_frame* frame,
                                  uint8_t lin_bus_id) {

    struct timespec now;
    uint8_t lin_id;
    uint8_t payload_length;

    // Clear bits
    Avtp_Lin_t* pdu = (Avtp_Lin_t*) acf_pdu;
    memset(pdu, 0, AVTP_LIN_HEADER_LEN);

    // Prepare ACF PDU for LIN
    Avtp_Lin_Init(pdu);
    clock_gettime(CLOCK_REALTIME, &now);
    Avtp_Lin_SetMessageTimestamp(pdu, (uint64_t)now.tv_nsec + (uint64_t)(now.tv_sec * 1e9));
    Avtp_Lin_EnableMtv(pdu);

    // Set LIN Bus ID
    Avtp_Lin_SetLinBusId(pdu, lin_bus_id);

    // LIN ID is in the lower 8 bits of can_id for sllin SFF non-RTR frames
    lin_id = (uint8_t)(frame->can_id & 0xFF);
    payload_length = frame->len > 8 ? 8 : frame->len;

    // Copy payload to ACF LIN PDU
    Avtp_Lin_CreateAcfMessage(pdu, lin_id, frame->data, payload_length);

    return Avtp_Lin_GetAcfMsgLength(pdu)*4;
}

int lin_to_avtp(struct can_frame* lin_frame, uint8_t* pdu,
                int use_udp, int use_tscf, uint64_t stream_id,
                uint8_t lin_bus_id, uint8_t cf_seq_num, uint32_t udp_seq_num) {

    // Pack into control formats
    uint8_t *cf_pdu;
    uint16_t pdu_length = 0, cf_length = 0;
    int res;

    // Usage of UDP means the PDU needs an encapsulation
    if (use_udp) {
        Avtp_Udp_t *udp_pdu = (Avtp_Udp_t *) pdu;
        Avtp_Udp_SetEncapsulationSeqNo(udp_pdu, udp_seq_num);
        pdu_length +=  sizeof(Avtp_Udp_t);
    }

    // Prepare the control format: TSCF/NTSCF
    cf_pdu = pdu + pdu_length;
    res = init_cf_pdu(cf_pdu, stream_id, use_tscf, cf_seq_num);
    pdu_length += res;
    cf_length += res;

    // Pack a single LIN frame into the ACF PDU
    uint8_t* acf_pdu = pdu + pdu_length;
    res = prepare_lin_acf_packet(acf_pdu, lin_frame, lin_bus_id);
    pdu_length += res;
    cf_length += res;

    // Update the length of the PDU
    update_cf_length(cf_pdu, cf_length, use_tscf);

    return pdu_length;
}

int avtp_to_lin(uint8_t* pdu, struct can_frame* lin_frame,
                int use_udp, uint64_t stream_id, uint8_t* exp_cf_seqnum,
                uint32_t* exp_udp_seqnum) {

    uint8_t *cf_pdu, *acf_pdu, *udp_pdu, seq_num;
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
            LOG_ERR("Incorrect UDP sequence num. Expected: %d Recd.: %d\n",
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
        LOG_ERR("Incorrect sequence num. Expected: %d Recd.: %d\n",
                                            *exp_cf_seqnum, seq_num);
        *exp_cf_seqnum = seq_num;
    }

    // Process a single ACF LIN message
    acf_pdu = &pdu[proc_bytes];

    if (!is_valid_acf_packet(acf_pdu)) {
        return -1;
    }

    /* Verify the LIN-specific invariants now that the ACF message
     * type is confirmed: the encoded message length must fit the
     * remaining buffer. */
    if (!Avtp_Lin_IsValid((Avtp_Lin_t*)acf_pdu, msg_length - proc_bytes)) {
        LOG_ERR("Error: ACF LIN frame failed validation, ignoring frame.\n");
        return -1;
    }

    uint8_t lin_id = Avtp_Lin_GetLinIdentifier((Avtp_Lin_t*)acf_pdu);
    const uint8_t* lin_payload = Avtp_Lin_GetPayload((Avtp_Lin_t*)acf_pdu);
    uint8_t payload_length = Avtp_Lin_GetLinPayloadLength((Avtp_Lin_t*)acf_pdu);

    // Pack into struct can_frame: LIN ID goes into can_id,
    // payload length into len, data copied from payload
    memset(lin_frame, 0, sizeof(struct can_frame));
    lin_frame->can_id = lin_id;
    lin_frame->len = payload_length;
    memcpy(lin_frame->data, lin_payload, payload_length);

    return 1;
}
