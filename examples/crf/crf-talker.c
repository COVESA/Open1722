/*
 * Copyright (c) 2018, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of Intel Corporation nor the names of its contributors
 *      may be used to endorse or promote products derived from this software
 *      without specific prior written permission.
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
 * /

/* CRF Talker example.
 *
 * This example implements a very simple CRF talker application which reads
 * system clock to get current time, generates CRF timestamps, creates AVTP CRF
 * packets and transmit them via the network.
 *
 * TSN stream parameters (e.g. destination mac address and maximum transit
 * time) are passed via command-line arguments. Run 'crf-talker --help' for
 * more information.
 *
 * This example relies on system clock to generate CRF timestamps and to keep
 * transmission rate. So make sure the system clock is synchronized with the
 * PTP Hardware Clock (PHC) from your NIC and that the PHC is synchronized with
 * the PTP time from the network. For further information on how to synchronize
 * those clocks see ptp4l(8) and phc2sys(8) man pages.
 *
 * Here is an example to setup ptp4l and phc2sys on PTP master host. Replace
 * $IFNAME by your PTP capable NIC name. The gPTP.cfg file mentioned below can
 * be found in /usr/share/doc/linuxptp/ (depending on your distro).
 *	$ ptp4l -f gPTP.cfg -i $IFNAME
 *	$ phc2sys -f gPTP.cfg -c $IFNAME -s CLOCK_REALTIME -w
 */

#include <alloca.h>
#include <argp.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
#include <math.h>
#include <endian.h>

#include "avtp/Crf.h"
#include "common/common.h"
#include "avtp/CommonHeader.h"

#define STREAM_ID		0xAABBCCDDEEFF0002

/* Values based on Spec 1722 Table 28 recommendation. */
#define SAMPLE_RATE		48000
#define TIMESTAMP_INTERVAL	160
#define TIMESTAMPS_PER_SEC	300
#define TIMESTAMPS_PER_PKT	6

#define NSEC_PER_SEC		1000000000ULL
#define NSEC_PER_MSEC		1000000ULL

#define DATA_LEN		(sizeof(uint64_t) * TIMESTAMPS_PER_PKT)
#define PDU_SIZE		(sizeof(struct avtp_crf_pdu) + DATA_LEN)
#define PDUS_PER_SEC		(TIMESTAMPS_PER_SEC / TIMESTAMPS_PER_PKT)
#define CRF_PERIOD		(NSEC_PER_SEC / TIMESTAMPS_PER_SEC)
#define NOMINAL_PERIOD		(1.0 / SAMPLE_RATE)
#define TX_INTERVAL		(NSEC_PER_SEC / PDUS_PER_SEC)

static char ifname[IFNAMSIZ];
static uint8_t macaddr[ETH_ALEN];
static int mtt;

static struct argp_option options[] = {
    {"dst-addr", 'd', "MACADDR", 0, "Stream Destination MAC address" },
    {"ifname", 'i', "IFNAME", 0, "Network Interface" },
    {"max-transit-time", 'm', "MSEC", 0, "Maximum Transit Time in ms" },
    { 0 }
};

static error_t parser(int key, char *arg, struct argp_state *state)
{
    int res;

    switch (key) {
    case 'd':
        res = sscanf(arg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                    &macaddr[0], &macaddr[1], &macaddr[2],
                    &macaddr[3], &macaddr[4], &macaddr[5]);
        if (res != 6) {
            fprintf(stderr, "Invalid address\n");
            exit(EXIT_FAILURE);
        }

        break;
    case 'i':
        strncpy(ifname, arg, sizeof(ifname) - 1);
        break;
    case 'm':
        mtt = atoi(arg) * NSEC_PER_MSEC;
        break;
    }

    return 0;
}

static struct argp argp = { options, parser };

static uint64_t calculate_crf_timestamp(struct timespec tspec, uint64_t rounded_mtt)
{
    uint64_t ts, crf_time;
    const uint64_t tc = 0;

    ts = (tspec.tv_sec * NSEC_PER_SEC) + tspec.tv_nsec;

    /* Equation 14 defined in spec 1722:
     * Tcrf = Ts + (ceil(TTmax/p) * p) + Tc
     * TCRF	: CRF timestamp placed in the CRF AVTPDU
     * Ts	: the original timestamp, sampled at the source
     * TTmax: the Max Transit Time value chosen for the network
     * P	: the nominal period of the clock source
     * TC	: the amount of time that samples spend accumulating in the
     *	  Talker’s transmit buffer
     */

    /* Value for sample accumulating time (TC) is system specific. Since
     * this is a CRF talker example, for simplicity, the value for Tc
     * is set to 0.
     */
    crf_time =  ts + rounded_mtt + tc;

    return crf_time;
}

static int init_pdu(struct avtp_crf_pdu *pdu)
{
    int res;

    res = avtp_crf_pdu_init(pdu);
    if (res < 0)
        return -1;

    res = avtp_crf_pdu_set(pdu, AVTP_CRF_FIELD_FS, 0);
    if (res < 0)
        return -1;

    res = avtp_crf_pdu_set(pdu, AVTP_CRF_FIELD_TYPE,
                        AVTP_CRF_TYPE_AUDIO_SAMPLE);
    if (res < 0)
        return -1;

    res = avtp_crf_pdu_set(pdu, AVTP_CRF_FIELD_STREAM_ID, STREAM_ID);
    if (res < 0)
        return -1;

    res = avtp_crf_pdu_set(pdu, AVTP_CRF_FIELD_PULL,
                        AVTP_CRF_PULL_MULT_BY_1);
    if (res < 0)
        return -1;

    res = avtp_crf_pdu_set(pdu, AVTP_CRF_FIELD_BASE_FREQ,
                            SAMPLE_RATE);
    if (res < 0)
        return -1;

    res = avtp_crf_pdu_set(pdu, AVTP_CRF_FIELD_TIMESTAMP_INTERVAL,
                            TIMESTAMP_INTERVAL);
    if (res < 0)
        return -1;

    res = avtp_crf_pdu_set(pdu, AVTP_CRF_FIELD_CRF_DATA_LEN, DATA_LEN);
    if (res < 0)
        return -1;

    return 0;
}

int main(int argc, char *argv[])
{
    int sk_fd, res, idx;
    uint8_t seq_num = 0;
    uint64_t crf_time, rounded_mtt;
    struct timespec clksrc_ts = {0};
    struct sockaddr_ll sk_addr = {0};
    struct avtp_crf_pdu *pdu = alloca(PDU_SIZE);

    argp_parse(&argp, argc, argv, 0, NULL, NULL);

    sk_fd = create_talker_socket(-1);
    if (sk_fd < 0) {
        return 1;
    }

    res = setup_socket_address(sk_fd, ifname, macaddr, ETH_P_TSN, &sk_addr);
    if (res < 0)
        goto err;

    res = init_pdu(pdu);
    if (res < 0)
        goto err;

    res = clock_gettime(CLOCK_REALTIME, &clksrc_ts);
    if (res < 0) {
        perror("Failed to get time");
        goto err;
    }

    rounded_mtt = ceil(mtt / NOMINAL_PERIOD) * NOMINAL_PERIOD;

    while (1) {
        ssize_t n;

        crf_time = calculate_crf_timestamp(clksrc_ts, rounded_mtt);
        for (idx = 0; idx < TIMESTAMPS_PER_PKT; idx++)
            pdu->crf_data[idx] = htobe64(crf_time + (CRF_PERIOD * idx));

        res = avtp_crf_pdu_set(pdu, AVTP_CRF_FIELD_SEQ_NUM, seq_num++);
        if (res < 0)
            goto err;

        n = sendto(sk_fd, pdu, PDU_SIZE, 0,
                (struct sockaddr *) &sk_addr, sizeof(sk_addr));
        if (n < 0) {
            perror("Failed to send data");
            goto err;
        }

        if (n != PDU_SIZE) {
            fprintf(stderr, "wrote %zd bytes, expected %zd\n",
                                n, PDU_SIZE);
        }

        clksrc_ts.tv_nsec += TX_INTERVAL;
        if (clksrc_ts.tv_nsec >= NSEC_PER_SEC) {
            clksrc_ts.tv_sec++;
            clksrc_ts.tv_nsec -= NSEC_PER_SEC;
        }
        clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &clksrc_ts, NULL);
    }

    close(sk_fd);
    return 0;

err:
    close(sk_fd);
    return 1;
}
