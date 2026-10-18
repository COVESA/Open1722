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

/* ACF-LIN Listener example.
 *
 * This example implements a simple ACF-LIN listener that receives LIN frames
 * encapsulated in ACF-LIN PDUs (IEEE Std. 1722-2016, chapter 9.4.5) carried
 * inside NTSCF or TSCF control format packets over Ethernet or UDP.
 *
 * For each received LIN frame the listener prints the LIN bus ID, identifier,
 * message timestamp, and raw payload bytes to stdout.
 *
 * Run 'acf-lin-listener --help' for usage information.
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
#include "avtp/acf/Lin.h"
#include "avtp/CommonHeader.h"

#define MAX_PDU_SIZE        1500

static char ifname[IFNAMSIZ];
static uint8_t macaddr[ETH_ALEN];
static uint8_t use_udp;
static uint32_t udp_port = 17220;

static struct argp_option options[] = {
    {"udp", 'u', 0, 0, "Use UDP (default: Ethernet)"},
    {"ifname", 'i', "IFNAME", 0, "Network interface (if Ethernet)"},
    {"dst-addr", 'd', "MACADDR", 0, "Stream destination MAC address (if Ethernet)"},
    {"udp-port", 'p', "UDP_PORT", 0, "UDP port to listen on (if UDP, default: 17220)"},
    { 0 }
};

static error_t parser(int key, char *arg, struct argp_state *state)
{
    int res;

    switch (key) {
    case 'p':
        udp_port = (uint32_t) atoi(arg);
        break;
    case 'u':
        use_udp = 1;
        break;
    case 'i':
        strncpy(ifname, arg, sizeof(ifname) - 1);
        break;
    case 'd':
        res = sscanf(arg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                &macaddr[0], &macaddr[1], &macaddr[2],
                &macaddr[3], &macaddr[4], &macaddr[5]);
        if (res != 6) {
            fprintf(stderr, "Invalid MAC address\n");
            exit(EXIT_FAILURE);
        }
        break;
    }

    return 0;
}

static struct argp argp = { options, parser, 0, 0 };

int main(int argc, char *argv[])
{
    int sk_fd, res;
    uint32_t proc_bytes;
    uint16_t msg_length, acf_msg_length_quadlets;
    uint8_t subtype, acf_type;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t *cf_pdu, *acf_pdu;

    argp_parse(&argp, argc, argv, 0, NULL, NULL);

    if (use_udp) {
        sk_fd = create_listener_socket_udp(udp_port);
    } else {
        sk_fd = create_listener_socket(ifname, macaddr, ETH_P_TSN);
    }

    if (sk_fd < 0)
        return 1;

    printf("acf-lin-listener: waiting for LIN frames...\n");

    while (1) {
        proc_bytes = 0;

        res = recv(sk_fd, pdu, MAX_PDU_SIZE, 0);
        if (res < 0 || res > MAX_PDU_SIZE) {
            perror("Failed to receive data");
            goto err;
        }

        /* Skip optional UDP encapsulation header */
        if (use_udp) {
            proc_bytes += AVTP_UDP_HEADER_LEN;
        }

        /* Determine control format (NTSCF or TSCF) and get payload length */
        cf_pdu = pdu + proc_bytes;
        subtype = Avtp_CommonHeader_GetSubtype((Avtp_CommonHeader_t *) cf_pdu);
        if (subtype == AVTP_SUBTYPE_TSCF) {
            proc_bytes += AVTP_TSCF_HEADER_LEN;
            msg_length = Avtp_Tscf_GetStreamDataLength((Avtp_Tscf_t *) cf_pdu);
        } else if (subtype == AVTP_SUBTYPE_NTSCF) {
            proc_bytes += AVTP_NTSCF_HEADER_LEN;
            msg_length = Avtp_Ntscf_GetNtscfDataLength((Avtp_Ntscf_t *) cf_pdu);
        } else {
            continue;
        }

        /* Validate and parse ACF-LIN PDU */
        acf_pdu = pdu + proc_bytes;
        acf_type = Avtp_AcfCommon_GetAcfMsgType((Avtp_AcfCommon_t *) acf_pdu);
        if (acf_type != AVTP_ACF_TYPE_LIN) {
            fprintf(stderr, "ACF type mismatch: expected LIN (%u), got %u\n",
                    AVTP_ACF_TYPE_LIN, acf_type);
            continue;
        }

        Avtp_Lin_t *lin_pdu = (Avtp_Lin_t *) acf_pdu;
        if (!Avtp_Lin_IsValid(lin_pdu, (size_t)(res - proc_bytes))) {
            fprintf(stderr, "Invalid ACF-LIN PDU\n");
            continue;
        }

        acf_msg_length_quadlets = Avtp_Lin_GetAcfMsgLength(lin_pdu);
        uint8_t bus_id = Avtp_Lin_GetLinBusId(lin_pdu);
        uint8_t lin_id = Avtp_Lin_GetLinIdentifier(lin_pdu);
        uint64_t timestamp = Avtp_Lin_GetMessageTimestamp(lin_pdu);

        uint16_t payload_len = acf_msg_length_quadlets * 4 - AVTP_LIN_HEADER_LEN;
        uint8_t *payload = acf_pdu + AVTP_LIN_HEADER_LEN;

        printf("LIN frame: bus=%u id=0x%02X ts=0x%016" PRIx64 " payload[%u]=",
               bus_id, lin_id, timestamp, payload_len);
        for (uint16_t i = 0; i < payload_len; i++) {
            printf("%02X ", payload[i]);
        }
        printf("\n");

        (void) msg_length;
    }

    return 0;

err:
    close(sk_fd);
    return 1;
}
