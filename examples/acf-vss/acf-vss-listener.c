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
#include <stdlib.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include "common/common.h"
#include "avtp/Udp.h"
#include "avtp/acf/Ntscf.h"
#include "avtp/acf/Tscf.h"
#include "avtp/acf/AcfCommon.h"
#include "avtp/acf/custom/Vss.h"
#include "avtp/CommonHeader.h"

#define MAX_PDU_SIZE                1500
#define MAX_MSG_SIZE                100

static char ifname[IFNAMSIZ];
static uint8_t macaddr[ETH_ALEN];
static uint8_t use_udp;
static uint32_t udp_port = 17220;

static struct argp_option options[] = {
    {"port", 'p', "UDP_PORT", 0, "UDP Port to listen on if UDP enabled"},
    {"udp", 'u', 0, 0, "Use UDP"},
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
        }

        break;
    }

    return 0;
}

static struct argp argp = { options, parser, 0, 0};

int main(int argc, char *argv[])
{
    int sk_fd, res;
    uint64_t proc_bytes = 0, msg_proc_bytes = 0;
    uint32_t udp_seq_num;
    uint16_t msg_length, acf_msg_length;
    uint8_t subtype, acf_type;
    uint64_t flag;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t *cf_pdu, *acf_pdu, *udp_pdu;
    char *recd_msg;

    argp_parse(&argp, argc, argv, 0, NULL, NULL);

    if (use_udp) {
        sk_fd = create_listener_socket_udp(udp_port);
    } else {
        sk_fd = create_listener_socket(ifname, macaddr, ETH_P_TSN);
    }

    if (sk_fd < 0)
        return 1;

    while (1) {
        proc_bytes = 0;

        res = recv(sk_fd, pdu, MAX_PDU_SIZE, 0);
        if (res < 0 || res > MAX_PDU_SIZE) {
            perror("Failed to receive data");
            goto err;
        }

        // If UDP is used the packets starts with an encapsulation number
        if (use_udp) {
            udp_pdu = pdu;
            udp_seq_num = Avtp_Udp_GetEncapsulationSeqNo((Avtp_Udp_t *)udp_pdu);
            cf_pdu = pdu + AVTP_UDP_HEADER_LEN;
            proc_bytes += AVTP_UDP_HEADER_LEN;
        } else {
            cf_pdu = pdu;
        }

        // Check if the packet is a control format packet (i.e. NTSCF or TSCF)
        subtype = Avtp_CommonHeader_GetSubtype((Avtp_CommonHeader_t*)cf_pdu);
        if (subtype == AVTP_SUBTYPE_TSCF){
            proc_bytes += AVTP_TSCF_HEADER_LEN;
            msg_length = Avtp_Tscf_GetStreamDataLength((Avtp_Tscf_t*)cf_pdu);
        } else {
            proc_bytes += AVTP_NTSCF_HEADER_LEN;
            msg_length = Avtp_Ntscf_GetNtscfDataLength((Avtp_Ntscf_t*)cf_pdu);
        }

        // Check if the control packet payload is a ACF GPC.
        acf_pdu = &pdu[proc_bytes];
        acf_type = Avtp_AcfCommon_GetAcfMsgType((Avtp_AcfCommon_t*)acf_pdu);
        if (acf_type != AVTP_ACF_TYPE_VSS) {
            // Ignore further processing.
            continue;
        }

        // Parse the VSS Packet and print contents on the STDOUT
        Vss_AddrMode_t addrMode;
        VssPath_t path;
        addrMode = Avtp_Vss_GetAddrMode((Avtp_Vss_t*)acf_pdu);
        Avtp_Vss_GetVssPath((Avtp_Vss_t*)acf_pdu, &path);

        if (addrMode == VSS_INTEROP_MODE) {
            char path_string[path.vss_interop_path.path_length+1];
            memset(path_string, '\0', path.vss_interop_path.path_length+1);
            memcpy(path_string, path.vss_interop_path.path, path.vss_interop_path.path_length);
            printf("VSS Path: %s, ", path_string);
        } else if (addrMode == VSS_STATIC_ID_MODE) {
            printf("VSS Path: %d, ", path.vss_static_id_path);
        }

        VssData_t data;
        Vss_Datatype_t dt = Avtp_Vss_GetDatatype((Avtp_Vss_t*)acf_pdu);
        Avtp_Vss_GetVssData((Avtp_Vss_t*)acf_pdu, &data);

        if (dt == VSS_FLOAT) {
            printf("VSS Value: %f\n", data.data_float);
        }

    }

    return 0;

err:
    close(sk_fd);
    return 1;

}