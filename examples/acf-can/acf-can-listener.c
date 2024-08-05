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

#include <argp.h>
#include <poll.h>
#include <stdlib.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <sys/ioctl.h>

#include "common/common.h"
#include "avtp/Udp.h"
#include "avtp/acf/Ntscf.h"
#include "avtp/acf/Tscf.h"
#include "avtp/acf/Common.h"
#include "avtp/acf/Can.h"
#include "avtp/CommonHeader.h"
#include "acf-can-common.h"

#define MAX_PDU_SIZE                1500
#define ARGPARSE_CAN_FD_OPTION      500

static char ifname[IFNAMSIZ];
static uint8_t macaddr[ETH_ALEN];
static uint8_t use_udp;
static uint32_t udp_port = 17220;
static Avtp_CanVariant_t can_variant = AVTP_CAN_CLASSIC;
static char can_ifname[IFNAMSIZ];

static char doc[] = "\nacf-can-listener -- a program designed to receive CAN messages from \
                    a remote CAN bus over Ethernet using Open1722 \
                    \vEXAMPLES\
                    \n\n  acf-can-listener eth0 aa:bb:cc:dd:ee:ff can1\
                    \n\n    (tunnel Open1722 CAN messages received from eth0 to STDOUT)\
                    \n\n  acf-can-listener can1 -up 1722\
                    \n\n    (tunnel Open1722 CAN messages received over UDP from port 1722 to can1)\
                    \n\n  acf-can-listener -up 1722 | canplayer can1=elmcan\
                    \n\n    (another method to tunnel Open1722 CAN messages to can1)";

static char args_doc[] = "[ifname] dst-mac-address [can ifname]";

static struct argp_option options[] = {
    {"port", 'p', "UDP_PORT", 0, "UDP Port to listen on if UDP enabled"},
    {"udp", 'u', 0, 0, "Use UDP"},
    {"fd", ARGPARSE_CAN_FD_OPTION, 0, 0, "Use CAN-FD"},
    {"can ifname", 0, 0, OPTION_DOC, "CAN interface (set to STDOUT by default)"},
    {"dst-mac-address", 0, 0, OPTION_DOC, "Stream destination MAC address (If Ethernet)"},
    {"ifname", 0, 0, OPTION_DOC, "Network interface (If Ethernet)" },
    { 0 }
};

static error_t parser(int key, char *arg, struct argp_state *state)
{
    int res;

    switch (key) {
    case 'p':
        udp_port = atoi(arg);
        break;
    case 'u':
        use_udp = 1;
        break;
    case ARGPARSE_CAN_FD_OPTION:
        can_variant = AVTP_CAN_FD;

    case ARGP_KEY_NO_ARGS:
        break;

    case ARGP_KEY_ARG:

        if(state->argc < 2){
            argp_usage(state);
        }

        if(!use_udp){
            strncpy(ifname, arg, sizeof(ifname) - 1);

            if(state->next < state->argc)
            {
                res = sscanf(state->argv[state->next], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                        &macaddr[0], &macaddr[1], &macaddr[2],
                        &macaddr[3], &macaddr[4], &macaddr[5]);
                if (res != 6) {
                    fprintf(stderr, "Invalid MAC address\n\n");
                    argp_usage(state);
                }
                state->next += 1;
            }

            if(state->next < state->argc)
            {
                strncpy(can_ifname, state->argv[state->next], sizeof(can_ifname) - 1);
                state->next = state->argc;
            }

        }else{
            strncpy(can_ifname, arg, sizeof(can_ifname) - 1);
            state->next = state->argc;
        }

        break;
    }

    return 0;
}

static struct argp argp = { options, parser, args_doc, doc };

static int is_valid_acf_packet(uint8_t* acf_pdu) {

    uint64_t val64;

    Avtp_AcfCommon_GetField((Avtp_AcfCommon_t*)acf_pdu, AVTP_ACF_FIELD_ACF_MSG_TYPE, &val64);
    if (val64 != AVTP_ACF_TYPE_CAN) {
        fprintf(stderr, "ACF type mismatch: expected %u, got %lu\n",
                AVTP_ACF_TYPE_CAN, val64);
        return 0;
    }

    return 1;
}

void print_can_acf(uint8_t* acf_pdu)
{
    uint64_t acf_msg_len, can_bus_id, timestamp, can_identifier, pad;

    Avtp_Can_t *pdu = (Avtp_Can_t*) acf_pdu;

    Avtp_Can_GetField(pdu, AVTP_CAN_FIELD_ACF_MSG_LENGTH, &acf_msg_len);
    Avtp_Can_GetField(pdu, AVTP_CAN_FIELD_CAN_BUS_ID, &can_bus_id);
    Avtp_Can_GetField(pdu, AVTP_CAN_FIELD_MESSAGE_TIMESTAMP, &timestamp);
    Avtp_Can_GetField(pdu, AVTP_CAN_FIELD_CAN_IDENTIFIER, &can_identifier);
    Avtp_Can_GetField(pdu, AVTP_CAN_FIELD_PAD, &pad);

    fprintf(stderr, "------------------------------------\n");
    fprintf(stderr, "Msg Length: %"PRIu64"\n", acf_msg_len);
    fprintf(stderr, "Can Bus ID: %"PRIu64"\n", can_bus_id);
    fprintf(stderr, "Timestamp: %#lx\n", timestamp);
    fprintf(stderr, "Can Identifier: %#lx\n", can_identifier);
    fprintf(stderr, "Pad: %"PRIu64"\n", pad);
}

static int new_packet(int sk_fd, int can_socket) {

    int res;
    uint64_t msg_length, proc_bytes = 0, msg_proc_bytes = 0;
    uint64_t can_frame_id, udp_seq_num, subtype, flag;
    uint16_t payload_length, pdu_length;
    uint8_t pdu[MAX_PDU_SIZE], i;
    uint8_t *cf_pdu, *acf_pdu, *udp_pdu, *can_payload;
    struct canfd_frame frame;

    memset(&frame, 0, sizeof(struct canfd_frame));
    res = recv(sk_fd, pdu, MAX_PDU_SIZE, 0);

    if (res < 0 || res > MAX_PDU_SIZE) {
        perror("Failed to receive data");
        return -1;
    }

    if (use_udp) {
        udp_pdu = pdu;
        Avtp_UDP_GetField((Avtp_UDP_t *)udp_pdu, AVTP_UDP_FIELD_ENCAPSULATION_SEQ_NO, &udp_seq_num);
        cf_pdu = pdu + AVTP_UDP_HEADER_LEN;
        proc_bytes += AVTP_UDP_HEADER_LEN;
    } else {
        cf_pdu = pdu;
    }

    res = Avtp_CommonHeader_GetField((Avtp_CommonHeader_t*)cf_pdu, AVTP_COMMON_HEADER_FIELD_SUBTYPE, &subtype);
    if (res < 0) {
        fprintf(stderr, "Failed to get subtype field: %d\n", res);
        return -1;
    }

    if (!((subtype == AVTP_SUBTYPE_NTSCF) ||
        (subtype == AVTP_SUBTYPE_TSCF))) {
        fprintf(stderr, "Subtype mismatch: expected %u or %u, got %"PRIu64". Dropping packet\n",
                AVTP_SUBTYPE_NTSCF, AVTP_SUBTYPE_TSCF, subtype);
        return -1;
    }

    if(subtype == AVTP_SUBTYPE_TSCF){
        proc_bytes += AVTP_TSCF_HEADER_LEN;
        Avtp_Tscf_GetField((Avtp_Tscf_t*)cf_pdu, AVTP_TSCF_FIELD_STREAM_DATA_LENGTH, (uint64_t *) &msg_length);
    }else{
        proc_bytes += AVTP_NTSCF_HEADER_LEN;
        Avtp_Ntscf_GetField((Avtp_Ntscf_t*)cf_pdu, AVTP_NTSCF_FIELD_NTSCF_DATA_LENGTH, (uint64_t *) &msg_length);
    }

    while (msg_proc_bytes < msg_length) {

        acf_pdu = &pdu[proc_bytes + msg_proc_bytes];

        if (!is_valid_acf_packet(acf_pdu)) {
            fprintf(stderr, "Error: Invalid ACF packet.\n");
            return -1;
        }

        Avtp_Can_GetField((Avtp_Can_t*)acf_pdu, AVTP_CAN_FIELD_CAN_IDENTIFIER,
                                &(can_frame_id));
        frame.can_id = can_frame_id;

        can_payload = Avtp_Can_GetPayload((Avtp_Can_t*)acf_pdu, &payload_length, &pdu_length);
        msg_proc_bytes += pdu_length*4;

        // Handle EFF Flag
        Avtp_Can_GetField((Avtp_Can_t*)acf_pdu, AVTP_CAN_FIELD_EFF, &flag);
        if (frame.can_id > 0x7FF && !flag) {
          fprintf(stderr, "Error: CAN ID is > 0x7FF but the EFF bit is not set.\n");
          return -1;
        }
        if (flag) frame.can_id |= CAN_EFF_FLAG;

        // Handle RTR Flag
        Avtp_Can_GetField((Avtp_Can_t*)acf_pdu, AVTP_CAN_FIELD_RTR, &flag);
        if (flag) frame.can_id |= CAN_RTR_FLAG;

        if (can_variant == AVTP_CAN_FD) {
            Avtp_Can_GetField((Avtp_Can_t*)acf_pdu, AVTP_CAN_FIELD_BRS, &flag);
            if (flag) frame.flags |= CANFD_BRS;

            Avtp_Can_GetField((Avtp_Can_t*)acf_pdu, AVTP_CAN_FIELD_FDF, &flag);
            if (flag) frame.flags |= CANFD_FDF;

            Avtp_Can_GetField((Avtp_Can_t*)acf_pdu, AVTP_CAN_FIELD_ESI, &flag);
            if (flag) frame.flags |= CANFD_ESI;
        }

        frame.len = payload_length;
        memcpy(frame.data, can_payload, payload_length);
        res = write(can_socket, &frame, sizeof(struct canfd_frame)) != sizeof(struct canfd_frame);
        if (res < 0) {
            return res;
        }

    }
    return 1;
}

int main(int argc, char *argv[])
{
    int fd, res;
    struct pollfd fds;

    int can_socket = 0;
    struct sockaddr_can can_addr;
    struct ifreq ifr;

    argp_parse(&argp, argc, argv, 0, NULL, NULL);

    // Configure an appropriate socket: UDP or Ethernet Raw
    if (use_udp) {
        fd = create_listener_socket_udp(udp_port);
    } else {
        fd = create_listener_socket(ifname, macaddr, ETH_P_TSN);
    }
    fds.fd = fd;
    fds.events = POLLIN;

    if (fd < 0)
        return 1;

    // Open a CAN socket for reading frames
    can_socket = setup_can_socket(can_ifname, can_variant);
    if (!can_socket) goto err;

    while (1) {

        res = poll(&fds, 1, -1);
        if (res < 0) {
            perror("Failed to poll() fds");
            goto err;
        }

        if (fds.revents & POLLIN) {
            res = new_packet(fd, can_socket);
            if (res < 0)
                goto err;
        }

    }

    return 0;

err:
    close(fd);
    return 1;

}
