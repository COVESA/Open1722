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

#include "common.h"
#include "avtp/Udp.h"
#include "avtp/acf/Ntscf.h"
#include "avtp/acf/Tscf.h"
#include "avtp/acf/Common.h"
#include "avtp/acf/Can.h"
#include "avtp/CommonHeader.h"

#define MAX_PDU_SIZE                1500

static char ifname[IFNAMSIZ];
static uint8_t macaddr[ETH_ALEN];
static uint8_t use_udp;
static uint32_t udp_port = 17220;
static char can_ifname[IFNAMSIZ] = "STDOUT\0";

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

    Avtp_Can_GetField(pdu, AVTP_ACF_FIELD_ACF_MSG_LENGTH, &acf_msg_len);
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
    uint64_t msg_length, proc_bytes = 0;
    uint64_t can_frame_id, udp_seq_num = 0, subtype;
    uint16_t payload_length, pdu_length;
    uint8_t *can_payload, i;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t* cf_pdu;
    uint8_t* acf_pdu;
    Avtp_UDP_t *udp_pdu;
    char stdout_string[1000] = "\0";
	struct can_frame frame;

    res = recv(sk_fd, pdu, MAX_PDU_SIZE, 0);    

    if (res < 0 || res > MAX_PDU_SIZE) {
        perror("Failed to receive data");
        return -1;
    }

    if (use_udp) {
        udp_pdu = (Avtp_UDP_t *) pdu;
        Avtp_UDP_GetField(udp_pdu, AVTP_UDP_FIELD_ENCAPSULATION_SEQ_NO, &udp_seq_num);
        cf_pdu = pdu + sizeof(Avtp_UDP_t);        
    } else {
        cf_pdu = pdu;
    }

    res = Avtp_CommonHeader_GetField((Avtp_CommonHeader_t*)pdu, AVTP_COMMON_HEADER_FIELD_SUBTYPE, &subtype);
    if (res < 0) {
        fprintf(stderr, "Failed to get subtype field: %d\n", res);
        return 0;
    }

    if (!((subtype == AVTP_SUBTYPE_NTSCF) || 
        (subtype == AVTP_SUBTYPE_TSCF))) {
        fprintf(stderr, "Subtype mismatch: expected %u or %u, got %"PRIu64". Dropping packet\n",
                AVTP_SUBTYPE_NTSCF, AVTP_SUBTYPE_TSCF, subtype);
        return -1;        
    }        

    if(subtype == AVTP_SUBTYPE_TSCF){
        proc_bytes += AVTP_TSCF_HEADER_LEN;        
        res = Avtp_Tscf_GetField((Avtp_Tscf_t*)pdu, AVTP_TSCF_FIELD_STREAM_DATA_LENGTH, (uint64_t *) &msg_length);
    }else{
        proc_bytes += AVTP_NTSCF_HEADER_LEN;        
        res = Avtp_Ntscf_GetField((Avtp_Ntscf_t*)pdu, AVTP_NTSCF_FIELD_NTSCF_DATA_LENGTH, (uint64_t *) &msg_length);
    }

    if (res < 0) {
        fprintf(stderr, "Failed to get message length: %d\n", res);
        return 0;
    }

    while (proc_bytes < msg_length) {        

        acf_pdu = &pdu[proc_bytes];

        if (!is_valid_acf_packet(acf_pdu)) {
            fprintf(stderr, "Error: Invalid ACF packet.\n");
            return 0;
        }

        res = Avtp_Can_GetField((Avtp_Can_t*)acf_pdu, AVTP_CAN_FIELD_CAN_IDENTIFIER, 
                                &can_frame_id);
        if (res < 0) {
            fprintf(stderr, "Error: Getting CAN frame ID\n");
            return 0;
        }        

        can_payload = Avtp_Can_GetPayload((Avtp_Can_t*)acf_pdu, &payload_length, &pdu_length);
        proc_bytes += pdu_length*4;

        if (can_socket == 0) {
            for (i = 0; i < payload_length; i++) {
                sprintf(stdout_string+(2*i), "%02x", can_payload[i]);
            }

            fprintf(stdout, "(000000.000000) elmcan %03lx#%s\n", can_frame_id, 
                                                            stdout_string);
            fflush(stdout);
        } else {
            frame.can_id = (canid_t) can_frame_id;
            frame.can_dlc = payload_length;
            memcpy(frame.data, can_payload, payload_length);
            if (write(can_socket, &frame, sizeof(struct can_frame)) != sizeof(struct can_frame)) {
                return 1;
            }
        }
    }
    return 1;
}

int main(int argc, char *argv[])
{
    int sk_fd, res;
    struct pollfd fds;

    int can_socket = 0;
	struct sockaddr_can can_addr;
	struct ifreq ifr;

    argp_parse(&argp, argc, argv, 0, NULL, NULL);

    // Open a CAN socket for reading frames if required
    if (strcmp(can_ifname, "STDOUT\0")) {
        can_socket = socket(PF_CAN, SOCK_RAW, CAN_RAW);
        if (can_socket < 0)
            return 1;

        strcpy(ifr.ifr_name, can_ifname);
        ioctl(can_socket, SIOCGIFINDEX, &ifr);

        memset(&can_addr, 0, sizeof(can_addr));
        can_addr.can_family = AF_CAN;
        can_addr.can_ifindex = ifr.ifr_ifindex;
        if (bind(can_socket, (struct sockaddr *)&can_addr, sizeof(can_addr)) < 0) 
            return 1;
    }

    if (use_udp) {
        sk_fd = create_listener_socket_udp(udp_port);
    } else {
        sk_fd = create_listener_socket(ifname, macaddr, ETH_P_TSN);
    }
    fds.fd = sk_fd;
    fds.events = POLLIN;

    if (sk_fd < 0)
        return 1;

    while (1) {

        res = poll(&fds, 1, -1);
        if (res < 0) {
            perror("Failed to poll() fds");
            goto err;
        }

        if (fds.revents & POLLIN) {
            res = new_packet(sk_fd, can_socket);
            if (res < 0)
                goto err;
        }

    }

    return 0;

err:
    close(sk_fd);
    return 1;

}