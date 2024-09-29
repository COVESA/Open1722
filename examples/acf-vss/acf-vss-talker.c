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
#include <linux/can/raw.h>
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
#include "avtp/CommonHeader.h"
#include "avtp/acf/custom/Vss.h"

#define MAX_PDU_SIZE                1500
#define STREAM_ID                   0xAABBCCDDEEFF0001

static char ifname[IFNAMSIZ];
static uint8_t macaddr[ETH_ALEN];
static uint8_t ip_addr[sizeof(struct in_addr)];
static uint32_t udp_port=17220;
static int priority = -1;
static uint8_t seq_num = 0;
static uint32_t udp_seq_num = 0;
static uint8_t use_tscf = 0;
static uint8_t use_udp = 0;
static char VSS_PATH[] = "Vehicle.Speed";

static struct argp_option options[] = {
    {"tscf", 't', 0, 0, "Use TSCF"},
    {"udp", 'u', 0, 0, "Use UDP" },
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

        break;
    }

    return 0;
}

static struct argp argp = { options, parser, NULL, NULL };

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

static int update_cf_length(uint8_t* cf_pdu, uint64_t length)
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

static int prepare_vss_interop_packet(uint8_t* acf_pdu, Vss_Datatype_t dt,
                              Vss_OpCode_t op, Vss_AddrMode_t am,
                              VssPath_t* vp, VssData_t* vd) {

    int processedBytes;
    struct timespec now;
    Avtp_Vss_t* pdu = (Avtp_Vss_t*) acf_pdu;

    // Clear bits
    memset(pdu, 0, AVTP_VSS_FIXED_HEADER_LEN);

    // Prepare ACF PDU for VSS
    Avtp_Vss_Init(pdu);
    clock_gettime(CLOCK_REALTIME, &now);
    Avtp_Vss_SetField(pdu, AVTP_VSS_FIELD_MSG_TIMESTAMP,
                      (uint64_t)now.tv_nsec + (uint64_t)(now.tv_sec * 1e9));
    Avtp_Vss_SetField(pdu, AVTP_VSS_FIELD_MTV, 1U);

    // Set ACF VSS Metadata fields
    Avtp_Vss_SetField(pdu, AVTP_VSS_FIELD_ADDR_MODE, am);
    Avtp_Vss_SetField(pdu, AVTP_VSS_FIELD_VSS_DATATYPE, dt);
    Avtp_Vss_SetField(pdu, AVTP_VSS_FIELD_VSS_OP, op);

    // Setup VSS Path in the PDU
    Avtp_Vss_SetVssPath(pdu, vp);

    // Copy data
    Avtp_Vss_SetVssData(pdu, vd);

    // Count the processed bytes
    processedBytes = AVTP_VSS_FIXED_HEADER_LEN + 2 + vp->vss_interop_path.path_length + 4;
    return processedBytes;
}

int main(int argc, char *argv[])
{

    int fd, res, can_socket=0;
    struct sockaddr_ll sk_ll_addr;
    struct sockaddr_in sk_udp_addr;
    uint8_t pdu[MAX_PDU_SIZE];
    uint16_t pdu_length, cf_length;
    struct canfd_frame can_frame;

    argp_parse(&argp, argc, argv, 0, NULL, NULL);

    // Create an appropriate talker socket: UDP or Ethernet raw
    // Setup the socket for sending to the destination
    if (use_udp) {
        fd = create_talker_socket_udp(priority);
        if (fd < 0) return fd;

        res = setup_udp_socket_address((struct in_addr*) ip_addr,
                                       udp_port, &sk_udp_addr);
    } else {
        fd = create_talker_socket(priority);
        if (fd < 0) return fd;
        res = setup_socket_address(fd, ifname, macaddr,
                                   ETH_P_TSN, &sk_ll_addr);
    }
    if (res < 0) goto err;

    // Sending loop
    for(;;) {

        // Pack into control formats
        uint8_t *cf_pdu;
        pdu_length = 0;
        cf_length = 0;
        uint8_t acf_length= 0;

        // Usage of UDP means the PDU needs a
        if (use_udp) {
            Avtp_Udp_t *udp_pdu = (Avtp_Udp_t *) pdu;
            Avtp_Udp_SetField(udp_pdu, AVTP_UDP_FIELD_ENCAPSULATION_SEQ_NO,
                              udp_seq_num++);
            pdu_length +=  sizeof(Avtp_Udp_t);
        }

        cf_pdu = pdu + pdu_length;
        res = init_cf_pdu(cf_pdu);
        if (res < 0)
            goto err;
        pdu_length += res;
        cf_length += res;

        uint8_t* acf_pdu = pdu + pdu_length;
        VssPath_t vss_path = {
            .vss_interop_path.path_length = strlen(VSS_PATH),
            .vss_interop_path.path = VSS_PATH
        };
        VssData_t data = {
            .data_float = 1.234
        };
        res = prepare_vss_interop_packet(acf_pdu, VSS_FLOAT,
                                            PUBLISH_CURRENT_VALUE,
                                            VSS_INTEROP_MODE, &vss_path, &data);
        if (res < 0) goto err;
        pdu_length += res;
        cf_length += res;
        acf_length = res;

        Avtp_Vss_Pad((Avtp_Vss_t*) acf_pdu, acf_length);
        uint8_t pad_length = Avtp_Vss_GetField((Avtp_Vss_t*)acf_pdu, AVTP_VSS_FIELD_PAD);
        pdu_length += pad_length;
        cf_length += pad_length;

        res = update_cf_length(cf_pdu, cf_length);
        if (res < 0)
            goto err;

        if (use_udp) {
            res = sendto(fd, pdu, pdu_length, 0,
                    (struct sockaddr *) &sk_udp_addr, sizeof(sk_udp_addr));
        } else {
            res = sendto(fd, pdu, pdu_length, 0,
                         (struct sockaddr *) &sk_ll_addr, sizeof(sk_ll_addr));
        }
        if (res < 0) {
            perror("Failed to send data");
            goto err;
        }
        sleep(1);
    }

err:
    close(fd);
    return 1;

}
