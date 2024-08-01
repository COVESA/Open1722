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

#include <linux/if_packet.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <sys/ioctl.h>
#include <time.h>

#include <arpa/inet.h>
#include <stdlib.h>
#include <argp.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>

#include "common/common.h"
#include "avtp/Udp.h"
#include "avtp/acf/Ntscf.h"
#include "avtp/acf/Tscf.h"
#include "avtp/acf/Can.h"
#include "avtp/CommonHeader.h"

#define MAX_PDU_SIZE                1500
#define STREAM_ID                   0xAABBCCDDEEFF0001
#define CAN_PAYLOAD_MAX_SIZE        16*4
#define CAN_FD_OPTION               500

static char ifname[IFNAMSIZ];
static uint8_t macaddr[ETH_ALEN];
static uint8_t ip_addr[sizeof(struct in_addr)];
static uint32_t udp_port=17220;
static int priority = -1;
static uint8_t seq_num = 0;
static uint8_t use_tscf;
static uint8_t use_udp;
static Can_Variant_t can_variant = CAN_CLASSIC;
static uint8_t multi_can_frames = 1;
static char can_ifname[IFNAMSIZ] = "STDIN\0";

static char doc[] = "\nacf-can-talker -- a program designed to send CAN messages to \
                    a remote CAN bus over Ethernet using Open1722 \
                    \vEXAMPLES\
                    \n\n  acf-can-talker eth0 aa:bb:cc:ee:dd:ff\
                    \n\n    (tunnel transactions from STDIN to a remote CAN bus over Ethernet)\
                    \n\n  acf-can-talker --count 10 eth0 aa:bb:cc:ee:dd:ff\
                    \n\n    (as above, but pack 10 CAN frames in one Ethernet frame)\
                    \n\n  acf-can-talker -u 10.0.0.2:17220 vcan1\
                    \n\n    (tunnel transactions from can1 interface to a remote CAN bus over IP)\
                    \n\n  candump can1 | acf-can-talker -u 10.0.0.2:17220\
                    \n\n    (another method to tunnel transactions from vcan1 to a remote CAN bus)";

static char args_doc[] = "[ifname] dst-mac-address/dst-nw-address:port [can ifname]";

static struct argp_option options[] = {
    {"tscf", 't', 0, 0, "Use TSCF"},
    {"udp", 'u', 0, 0, "Use UDP" },
    {"fd", CAN_FD_OPTION, 0, 0, "Use CAN-FD"},
    {"count", 'c', "COUNT", 0, "Set count of CAN messages per Ethernet frame"},
    {"can ifname", 0, 0, OPTION_DOC, "CAN interface (set to STDIN by default)"},
    {"ifname", 0, 0, OPTION_DOC, "Network interface (If Ethernet)"},
    {"dst-mac-address", 0, 0, OPTION_DOC, "Stream destination MAC address (If Ethernet)"},
    {"dst-nw-address:port", 0, 0, OPTION_DOC, "Stream destination network address and port (If UDP)"},
    { 0 }
};

static error_t parser(int key, char *arg, struct argp_state *state)
{
    int res;
    char ip_addr_str[100];

    switch (key) {
    case 't':
        use_tscf = 1;
        break;
    case 'u':
        use_udp = 1;
        break;
    case 'c':
        multi_can_frames = atoi(arg);
        break;
    case CAN_FD_OPTION:
        can_variant = CAN_FD;
        break;

    case ARGP_KEY_NO_ARGS:
        argp_usage(state);

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

        } else {
            res = sscanf(arg, "%[^:]:%d", ip_addr_str, &udp_port);
            if (!res) {
                fprintf(stderr, "Invalid IP address or port\n\n");
                argp_usage(state);
            }
            res = inet_pton(AF_INET, ip_addr_str, ip_addr);
            if (!res) {
                fprintf(stderr, "Invalid IP address\n\n");
                argp_usage(state);
            }
        }

        if(state->next < state->argc)
        {
            strncpy(can_ifname, state->argv[state->next], sizeof(can_ifname) - 1);
            state->next = state->argc;
        }

        break;
    }

    return 0;
}

static struct argp argp = { options, parser, args_doc, doc };

static int init_cf_pdu(uint8_t* pdu)
{
    int res;
    if (use_tscf) {
        Avtp_Tscf_t* tscf_pdu = (Avtp_Tscf_t*) pdu;
        memset(tscf_pdu, 0, AVTP_TSCF_HEADER_LEN);
        Avtp_Tscf_Init(tscf_pdu);
        Avtp_Tscf_SetField(tscf_pdu, AVTP_TSCF_FIELD_TU, 0U);
        Avtp_Tscf_SetField(tscf_pdu, AVTP_TSCF_FIELD_SEQUENCE_NUM, seq_num++);
        Avtp_Tscf_SetField(tscf_pdu, AVTP_TSCF_FIELD_STREAM_ID, STREAM_ID);
        res = AVTP_TSCF_HEADER_LEN;
    } else {
        Avtp_Ntscf_t* ntscf_pdu = (Avtp_Ntscf_t*) pdu;
        memset(ntscf_pdu, 0, AVTP_NTSCF_HEADER_LEN);
        Avtp_Ntscf_Init(ntscf_pdu);
        Avtp_Ntscf_SetField(ntscf_pdu, AVTP_NTSCF_FIELD_SEQUENCE_NUM, seq_num++);
        Avtp_Ntscf_SetField(ntscf_pdu, AVTP_NTSCF_FIELD_STREAM_ID, STREAM_ID);
        res = AVTP_NTSCF_HEADER_LEN;
    }
    return res;
}

static int update_pdu_length(uint8_t* pdu, uint64_t length)
{
    if (use_tscf) {
        uint64_t payloadLen = length - AVTP_TSCF_HEADER_LEN;
        Avtp_Tscf_SetField((Avtp_Tscf_t*)pdu, AVTP_TSCF_FIELD_STREAM_DATA_LENGTH, payloadLen);
    } else {
        uint64_t payloadLen = length - AVTP_NTSCF_HEADER_LEN;
        Avtp_Ntscf_SetField((Avtp_Ntscf_t*)pdu, AVTP_NTSCF_FIELD_NTSCF_DATA_LENGTH, payloadLen);
    }
    return 0;
}

static int prepare_acf_packet(uint8_t* acf_pdu,
                          uint8_t* payload, uint8_t length,
                          uint32_t can_frame_id) {

    int processedBytes;
    struct timespec now;
    Avtp_Can_t* pdu = (Avtp_Can_t*) acf_pdu;

    // Clear bits
    memset(pdu, 0, AVTP_CAN_HEADER_LEN);

    // Prepare ACF PDU for CAN
    Avtp_Can_Init(pdu);
    clock_gettime(CLOCK_REALTIME, &now);
    Avtp_Can_SetField(pdu, AVTP_CAN_FIELD_MESSAGE_TIMESTAMP, 
                      (uint64_t)now.tv_nsec + (uint64_t)(now.tv_sec * 1e9));
    Avtp_Can_SetField(pdu, AVTP_CAN_FIELD_MTV, 1U);

    // Copy payload to ACF CAN PDU
    processedBytes = Avtp_Can_SetPayload(pdu, can_frame_id, payload, length, can_variant);

    return processedBytes;
}

static int get_payload(int can_socket, uint8_t* payload, uint32_t *frame_id, uint8_t *length) {

    char stdin_str[1000];
    char can_str[10];
    char can_payload[1000];
    char *token;
    size_t n;
    int res;
    struct canfd_frame frame;

    if (can_socket == 0) {
        n = read(STDIN_FILENO, stdin_str, 1000);
        if (n < 0) {
            return -1;
        }

        res = sscanf(stdin_str, "%s %x [%hhu] %[0-9A-F ]s", can_str, frame_id,
                                                        length, can_payload);
        if (res < 0) {
            return -1;
        }

        token = strtok(can_payload, " ");
        int index = 0;
        while (token != NULL) {
            payload[index++] = (unsigned short)strtol(token, NULL, 16);
            token = strtok(NULL, " ");
        }
    } else {
        n = read(can_socket, &frame, sizeof(struct canfd_frame));
        if (n > 0) {
            *frame_id = (uint32_t) frame.can_id;
            *length = (uint8_t) frame.len;
            memcpy(payload, frame.data, (size_t) *length);
        }
    }

    return n;
}

int main(int argc, char *argv[])
{

    int fd, res;
    struct sockaddr_ll sk_ll_addr;
    struct sockaddr_in sk_udp_addr;
    uint8_t pdu[MAX_PDU_SIZE];

    uint8_t payload[CAN_PAYLOAD_MAX_SIZE];
    uint8_t payload_length = 0;
    uint32_t frame_id = 0;
    uint8_t num_acf_msgs = 1;
    uint32_t pdu_length;

    int can_socket = 0;
    struct sockaddr_can can_addr;
    struct ifreq ifr;

    argp_parse(&argp, argc, argv, 0, NULL, NULL);

    if (use_udp) {
        fd = create_talker_socket_udp(priority);
    } else {
        fd = create_talker_socket(priority);
    }
    if (fd < 0)
        return 1;

    num_acf_msgs = multi_can_frames;

    // Open a CAN socket for reading frames if required
    if (strcmp(can_ifname, "STDIN\0")) {
        can_socket = socket(PF_CAN, SOCK_RAW, CAN_RAW);
        if (can_socket < 0)
            return 1;

        strcpy(ifr.ifr_name, can_ifname);
        ioctl(can_socket, SIOCGIFINDEX, &ifr);

        memset(&can_addr, 0, sizeof(can_addr));
        can_addr.can_family = AF_CAN;
        can_addr.can_ifindex = ifr.ifr_ifindex;

        if (can_variant == CAN_FD) {
            int enable_canfx = 1;
            setsockopt(can_socket, SOL_CAN_RAW, CAN_RAW_FD_FRAMES,
                        &enable_canfx, sizeof(enable_canfx));
        }

        if (bind(can_socket, (struct sockaddr *)&can_addr, sizeof(can_addr)) < 0)
            return 1;
    }


    if (use_udp) {
        res = setup_udp_socket_address((struct in_addr*) ip_addr,
                                       udp_port, &sk_udp_addr);
        if (res < 0)
            goto err;
    } else {
        res = setup_socket_address(fd, ifname, macaddr, ETH_P_TSN, &sk_ll_addr);
        if (res < 0)
            goto err;
    }

    // Sending loop
    for(;;) {

        // Pack into control formats
        uint8_t *cf_pdu;
        pdu_length = 0;

        if (use_udp) {
            Avtp_UDP_t *udp_pdu = (Avtp_UDP_t *) pdu;
            Avtp_UDP_SetField(udp_pdu, AVTP_UDP_FIELD_ENCAPSULATION_SEQ_NO,
                              seq_num);
            cf_pdu = &pdu[sizeof(Avtp_UDP_t)];
        } else {
            cf_pdu = pdu;
        }

        res = init_cf_pdu(cf_pdu);
        if (res < 0)
            goto err;
        pdu_length += res;

        int i = 0;
        while (i < num_acf_msgs) {
            // Get payload -- will 'spin' here until we get the requested number
            //                of CAN frames.
            res = get_payload(can_socket, payload, &frame_id, &payload_length);
            if (!res) {
                continue;
            }

            uint8_t* acf_pdu = cf_pdu + pdu_length;
            res = prepare_acf_packet(acf_pdu, payload, payload_length, frame_id);
            if (res < 0)
                goto err;
            pdu_length += res;

            i++;
        }

        res = update_pdu_length(cf_pdu, pdu_length);
        if (res < 0)
            goto err;

        if (use_udp) {
            pdu_length += sizeof(uint32_t);
            res = sendto(fd, pdu, pdu_length, 0,
                    (struct sockaddr *) &sk_udp_addr, sizeof(sk_udp_addr));
            if (res < 0) {
                perror("Failed to send data");
                goto err;
            }
        } else {
            res = sendto(fd, pdu, pdu_length, 0,
                         (struct sockaddr *) &sk_ll_addr, sizeof(sk_ll_addr));
            if (res < 0) {
                perror("Failed to send data");
                goto err;
            }
        }
    }

err:
    close(fd);
    return 1;

}
