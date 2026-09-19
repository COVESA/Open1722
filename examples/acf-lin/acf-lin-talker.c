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

/* ACF-LIN Talker example.
 *
 * This example implements a simple ACF-LIN talker that sends simulated LIN
 * frames over Ethernet (raw TSN) or UDP using the ACF-LIN PDU format defined
 * in IEEE Std. 1722-2016, chapter 9.4.5.
 *
 * LIN frames are carried inside NTSCF or TSCF control format packets.
 * The talker sends one LIN frame per second containing a single-byte counter
 * payload on the configured LIN bus/identifier.
 *
 * TSN stream parameters are passed via command-line arguments.
 * Run 'acf-lin-talker --help' for more information.
 */

#include <linux/if_packet.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <time.h>

#include <arpa/inet.h>
#include <stdlib.h>
#include <argp.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include "common/common.h"
#include "avtp/Udp.h"
#include "avtp/acf/Ntscf.h"
#include "avtp/acf/Tscf.h"
#include "avtp/acf/Lin.h"
#include "avtp/CommonHeader.h"

#define MAX_PDU_SIZE                1500
#define LIN_PAYLOAD_MAX_SIZE        8
#define STREAM_ID                   0xAABBCCDDEEFF0001
#define ARGPARSE_LIN_BUS_ID_OPTION  500
#define ARGPARSE_LIN_ID_OPTION      501

static char ifname[IFNAMSIZ];
static uint8_t macaddr[ETH_ALEN];
static uint8_t ip_addr[sizeof(struct in_addr)];
static uint32_t udp_port = 17220;
static int priority = -1;
static uint8_t seq_num = 0;
static uint32_t udp_seq_num = 0;
static uint8_t use_tscf = 0;
static uint8_t use_udp = 0;
static uint8_t lin_bus_id = 0;
static uint8_t lin_identifier = 0x01;

static char doc[] =
        "\nacf-lin-talker -- a program to send simulated LIN frames over"
        " Ethernet using Open1722 (ACF-LIN)."
        "\vEXAMPLES\n"
        "  acf-lin-talker -i eth0 -d aa:bb:cc:dd:ee:ff\n"
        "    (send LIN frames over Ethernet)\n"
        "  acf-lin-talker -u -n 10.0.0.2:17220\n"
        "    (send LIN frames over UDP)\n";

static struct argp_option options[] = {
    {"tscf", 't', 0, 0, "Use TSCF (default: NTSCF)"},
    {"udp", 'u', 0, 0, "Use UDP (default: Ethernet)"},
    {"ifname", 'i', "IFNAME", 0, "Network interface (if Ethernet)"},
    {"dst-addr", 'd', "MACADDR", 0, "Stream destination MAC address (if Ethernet)"},
    {"dst-nw-addr", 'n', "NW_ADDR", 0, "Stream destination network address and port (if UDP)"},
    {"lin-bus-id", ARGPARSE_LIN_BUS_ID_OPTION, "BUS_ID", 0, "LIN bus ID (0-31, default: 0)"},
    {"lin-id", ARGPARSE_LIN_ID_OPTION, "LIN_ID", 0, "LIN frame identifier (0-63, default: 1)"},
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
    case 'n':
        res = sscanf(arg, "%[^:]:%d", ip_addr_str, &udp_port);
        if (!res) {
            fprintf(stderr, "Invalid IP address or port\n");
            exit(EXIT_FAILURE);
        }
        res = inet_pton(AF_INET, ip_addr_str, ip_addr);
        if (!res) {
            fprintf(stderr, "Invalid IP address\n");
            exit(EXIT_FAILURE);
        }
        break;
    case ARGPARSE_LIN_BUS_ID_OPTION:
        lin_bus_id = (uint8_t) atoi(arg);
        if (lin_bus_id > 31) {
            fprintf(stderr, "LIN bus ID must be in range 0-31\n");
            exit(EXIT_FAILURE);
        }
        break;
    case ARGPARSE_LIN_ID_OPTION:
        lin_identifier = (uint8_t) atoi(arg);
        if (lin_identifier > 63) {
            fprintf(stderr, "LIN identifier must be in range 0-63\n");
            exit(EXIT_FAILURE);
        }
        break;
    }

    return 0;
}

static struct argp argp = { options, parser, 0, doc };

static int init_cf_pdu(uint8_t *pdu)
{
    int res;
    if (use_tscf) {
        Avtp_Tscf_t *tscf_pdu = (Avtp_Tscf_t *) pdu;
        memset(tscf_pdu, 0, AVTP_TSCF_HEADER_LEN);
        Avtp_Tscf_Init(tscf_pdu);
        Avtp_Tscf_DisableTu(tscf_pdu);
        Avtp_Tscf_SetSequenceNum(tscf_pdu, seq_num++);
        Avtp_Tscf_SetStreamId(tscf_pdu, STREAM_ID);
        res = AVTP_TSCF_HEADER_LEN;
    } else {
        Avtp_Ntscf_t *ntscf_pdu = (Avtp_Ntscf_t *) pdu;
        memset(ntscf_pdu, 0, AVTP_NTSCF_HEADER_LEN);
        Avtp_Ntscf_Init(ntscf_pdu);
        Avtp_Ntscf_SetSequenceNum(ntscf_pdu, seq_num++);
        Avtp_Ntscf_SetStreamId(ntscf_pdu, STREAM_ID);
        res = AVTP_NTSCF_HEADER_LEN;
    }
    return res;
}

static int update_cf_length(uint8_t *cf_pdu, uint64_t length)
{
    if (use_tscf) {
        uint64_t payloadLen = length - AVTP_TSCF_HEADER_LEN;
        Avtp_Tscf_SetStreamDataLength((Avtp_Tscf_t *) cf_pdu, payloadLen);
    } else {
        uint64_t payloadLen = length - AVTP_NTSCF_HEADER_LEN;
        Avtp_Ntscf_SetNtscfDataLength((Avtp_Ntscf_t *) cf_pdu, payloadLen);
    }
    return 0;
}

static int prepare_lin_pdu(uint8_t *acf_pdu, uint8_t bus_id, uint8_t lin_id,
                           uint8_t *payload, uint8_t payload_len)
{
    Avtp_Lin_t *lin_pdu = (Avtp_Lin_t *) acf_pdu;
    uint8_t acf_length_quadlets;

    memset(lin_pdu, 0, AVTP_LIN_HEADER_LEN);
    Avtp_Lin_Init(lin_pdu);
    Avtp_Lin_SetLinBusId(lin_pdu, bus_id);
    Avtp_Lin_SetLinIdentifier(lin_pdu, lin_id);

    memcpy(acf_pdu + AVTP_LIN_HEADER_LEN, payload, payload_len);

    /* ACF message length is in quadlets; round up to next quadlet */
    acf_length_quadlets = (AVTP_LIN_HEADER_LEN + payload_len + 3) / 4;
    Avtp_Lin_SetAcfMsgLength(lin_pdu, acf_length_quadlets);

    /* Zero-pad to quadlet boundary */
    memset(acf_pdu + AVTP_LIN_HEADER_LEN + payload_len, 0,
           acf_length_quadlets * 4 - AVTP_LIN_HEADER_LEN - payload_len);

    return acf_length_quadlets * 4;
}

int main(int argc, char *argv[])
{
    int fd, res;
    struct sockaddr_ll sk_ll_addr;
    struct sockaddr_in sk_udp_addr;
    uint8_t pdu[MAX_PDU_SIZE];
    uint16_t pdu_length, cf_length;
    uint8_t lin_payload = 0;

    argp_parse(&argp, argc, argv, 0, NULL, NULL);

    printf("acf-lin-talker configuration:\n");
    printf("\tLIN bus ID     : %u\n", lin_bus_id);
    printf("\tLIN identifier : 0x%02X\n", lin_identifier);
    if (use_udp) {
        printf("\tTransport      : UDP port %u\n", udp_port);
    } else {
        printf("\tTransport      : Ethernet, interface %s\n", ifname);
    }

    if (use_udp) {
        fd = create_talker_socket_udp(priority);
        if (fd < 0)
            return 1;
        res = setup_udp_socket_address((struct in_addr *) ip_addr,
                                       udp_port, &sk_udp_addr);
    } else {
        fd = create_talker_socket(priority);
        if (fd < 0)
            return 1;
        res = setup_socket_address(fd, ifname, macaddr,
                                   ETH_P_TSN, &sk_ll_addr);
    }
    if (res < 0)
        goto err;

    for (;;) {
        pdu_length = 0;
        cf_length = 0;

        if (use_udp) {
            Avtp_Udp_t *udp_pdu = (Avtp_Udp_t *) pdu;
            Avtp_Udp_SetEncapsulationSeqNo(udp_pdu, udp_seq_num++);
            pdu_length += sizeof(Avtp_Udp_t);
        }

        uint8_t *cf_pdu = pdu + pdu_length;
        res = init_cf_pdu(cf_pdu);
        if (res < 0)
            goto err;
        pdu_length += res;
        cf_length += res;

        uint8_t *acf_pdu = pdu + pdu_length;
        res = prepare_lin_pdu(acf_pdu, lin_bus_id, lin_identifier,
                              &lin_payload, sizeof(lin_payload));
        if (res < 0)
            goto err;
        pdu_length += res;
        cf_length += res;

        update_cf_length(cf_pdu, cf_length);

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

        printf("Sent LIN frame: bus=%u id=0x%02X payload=0x%02X\n",
               lin_bus_id, lin_identifier, lin_payload);
        lin_payload++;
        sleep(1);
    }

err:
    close(fd);
    return 1;
}
