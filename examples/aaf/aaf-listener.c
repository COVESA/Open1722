/*
 * Copyright (c) 2017, Intel Corporation
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
 *
 */

/* AAF Listener example.
 *
 * This example implements a very simple AAF listener application which
 * receives AFF packets from the network, retrieves the PCM samples, and
 * writes them to stdout once the presentation time is reached.
 *
 * For simplicity, the example accepts only AAF packets with the following
 * specification:
 *    - Sample format: 16-bit little endian
 *    - Sample rate: 48 kHz
 *    - Number of channels: 2 (stereo)
 *
 * TSN stream parameters such as destination mac address are passed via
 * command-line arguments. Run 'aaf-listener --help' for more information.
 *
 * This example relies on the system clock to schedule PCM samples for
 * playback. So make sure the system clock is synchronized with the PTP
 * Hardware Clock (PHC) from your NIC and that the PHC is synchronized with
 * the PTP time from the network. For further information on how to synchronize
 * those clocks see ptp4l(8) and phc2sys(8) man pages.
 *
 * The easiest way to use this example is combining it with 'aplay' tool
 * provided by alsa-utils. 'aplay' reads a PCM stream from stdin and sends it
 * to a ALSA playback device (e.g. your speaker). So, to play Audio from a TSN
 * stream, you should do something like this:
 *
 * $ aaf-listener <args> | aplay -f dat -t raw -D <playback-device>
 */

#include <assert.h>
#include <argp.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <poll.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/timerfd.h>
#include <unistd.h>
#include <inttypes.h>

#include "avtp/aaf/Pcm.h"
#include "common/common.h"
#include "avtp/CommonHeader.h"

#define STREAM_ID 0xAABBCCDDEEFF0001
#define SAMPLE_SIZE 2 /* Sample size in bytes. */
#define NUM_CHANNELS 2
#define DATA_LEN (SAMPLE_SIZE * NUM_CHANNELS)
#define PDU_SIZE (sizeof(Avtp_Pcm_t) + DATA_LEN)
#define NSEC_PER_SEC 1000000000ULL

struct sample_entry {
    STAILQ_ENTRY(sample_entry) entries;

    struct timespec tspec;
    uint8_t pcm_sample[DATA_LEN];
};

static STAILQ_HEAD(sample_queue, sample_entry) samples;
static char ifname[IFNAMSIZ];
static uint8_t macaddr[ETH_ALEN];
static uint8_t expected_seq;

static struct argp_option options[] = {
    {"dst-addr", 'd', "MACADDR", 0, "Stream Destination MAC address"},
    {"ifname", 'i', "IFNAME", 0, "Network Interface"},
    {0}};

static error_t parser(int key, char *arg, struct argp_state *state)
{
    int res;

    switch (key) {
    case 'd':
        res = sscanf(arg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &macaddr[0], &macaddr[1], &macaddr[2],
                     &macaddr[3], &macaddr[4], &macaddr[5]);
        if (res != 6) {
            fprintf(stderr, "Invalid address\n");
            exit(EXIT_FAILURE);
        }

        break;
    case 'i':
        strncpy(ifname, arg, sizeof(ifname) - 1);
        break;
    }

    return 0;
}

static struct argp argp = {options, parser};

/* Schedule 'pcm_sample' to be presented at time specified by 'tspec'. */
static int schedule_sample(int fd, struct timespec *tspec, uint8_t *pcm_sample)
{
    struct sample_entry *entry;

    entry = malloc(sizeof(*entry));
    if (!entry) {
        fprintf(stderr, "Failed to allocate memory\n");
        return -1;
    }

    entry->tspec.tv_sec = tspec->tv_sec;
    entry->tspec.tv_nsec = tspec->tv_nsec;
    memcpy(entry->pcm_sample, pcm_sample, DATA_LEN);

    STAILQ_INSERT_TAIL(&samples, entry, entries);

    /* If this was the first entry inserted onto the queue, we need to arm
     * the timer.
     */
    if (STAILQ_FIRST(&samples) == entry) {
        int res;

        res = arm_timer(fd, tspec);
        if (res < 0) {
            STAILQ_REMOVE(&samples, entry, sample_entry, entries);
            free(entry);
            return -1;
        }
    }

    return 0;
}

static bool is_valid_packet(Avtp_Pcm_t *pdu)
{
    uint64_t val64;
    uint8_t val8;

    if (!Avtp_Pcm_IsValid(pdu, PDU_SIZE)) {
        fprintf(stderr, "Invalid AAF PCM PDU\n");
        return false;
    }

    val8 = Avtp_CommonHeader_GetVersion((const Avtp_CommonHeader_t *)pdu);
    if (val8 != 0) {
        fprintf(stderr, "Version mismatch: expected %u, got %u\n", 0, val8);
        return false;
    }

    if (!Avtp_Pcm_IsTv(pdu)) {
        fprintf(stderr, "tv mismatch: expected %u, got %u\n", 1, 0);
        return false;
    }

    if (Avtp_Pcm_IsSp(pdu)) {
        fprintf(stderr, "sp mismatch: expected %u, got %u\n", AVTP_AAF_SP_NORMAL,
                AVTP_AAF_SP_SPARSE);
        return false;
    }

    val64 = Avtp_Pcm_GetStreamId(pdu);
    if (val64 != STREAM_ID) {
        fprintf(stderr, "Stream ID mismatch: expected %" PRIu64 ", got %" PRIu64 "\n", STREAM_ID,
                val64);
        return false;
    }

    val8 = Avtp_Pcm_GetSequenceNum(pdu);
    if (val8 != expected_seq) {
        /* If we have a sequence number mismatch, we simply log the
         * issue and continue to process the packet. We don't want to
         * invalidate it since it is a valid packet after all.
         */
        fprintf(stderr, "Sequence number mismatch: expected %u, got %u\n", expected_seq, val8);
        expected_seq = val8;
    }

    expected_seq++;

    if (Avtp_Pcm_GetFormat(pdu) != AVTP_AAF_FORMAT_INT_16BIT) {
        fprintf(stderr, "Format mismatch: expected %u, got %u\n", AVTP_AAF_FORMAT_INT_16BIT,
                Avtp_Pcm_GetFormat(pdu));
        return false;
    }

    if (Avtp_Pcm_GetNsr(pdu) != AVTP_PCM_NSR_48KHZ) {
        fprintf(stderr, "Sample rate mismatch: expected %u, got %u\n", AVTP_PCM_NSR_48KHZ,
                Avtp_Pcm_GetNsr(pdu));
        return false;
    }

    if (Avtp_Pcm_GetChannelsPerFrame(pdu) != NUM_CHANNELS) {
        fprintf(stderr, "Channels mismatch: expected %u, got %u\n", NUM_CHANNELS,
                Avtp_Pcm_GetChannelsPerFrame(pdu));
        return false;
    }

    if (Avtp_Pcm_GetBitDepth(pdu) != 16) {
        fprintf(stderr, "Depth mismatch: expected %u, got %u\n", 16, Avtp_Pcm_GetBitDepth(pdu));
        return false;
    }

    if (Avtp_Pcm_GetStreamDataLength(pdu) != DATA_LEN) {
        fprintf(stderr, "Data len mismatch: expected %u, got %u\n", DATA_LEN,
                Avtp_Pcm_GetStreamDataLength(pdu));
        return false;
    }

    return true;
}

static int new_packet(int sk_fd, int timer_fd)
{
    int res;
    ssize_t n;
    uint32_t avtp_time;
    struct timespec tspec;
    Avtp_Pcm_t *pdu = alloca(PDU_SIZE);

    memset(pdu, 0, PDU_SIZE);

    n = recv(sk_fd, pdu, PDU_SIZE, 0);
    if (n < 0 || n != PDU_SIZE) {
        perror("Failed to receive data");
        return -1;
    }

    if (!is_valid_packet(pdu)) {
        fprintf(stderr, "Dropping packet\n");
        return 0;
    }

    avtp_time = Avtp_Pcm_GetAvtpTimestamp(pdu);

    res = get_presentation_time(avtp_time, &tspec);
    if (res < 0)
        return -1;

    res = schedule_sample(timer_fd, &tspec, pdu->payload);
    if (res < 0)
        return -1;

    return 0;
}

static int timeout(int fd)
{
    int res;
    ssize_t n;
    uint64_t expirations;
    struct sample_entry *entry;

    n = read(fd, &expirations, sizeof(uint64_t));
    if (n < 0) {
        perror("Failed to read timerfd");
        return -1;
    }

    assert(expirations == 1);

    entry = STAILQ_FIRST(&samples);
    assert(entry != NULL);

    res = present_data(entry->pcm_sample, DATA_LEN);
    if (res < 0)
        return -1;

    STAILQ_REMOVE_HEAD(&samples, entries);
    free(entry);

    if (!STAILQ_EMPTY(&samples)) {
        entry = STAILQ_FIRST(&samples);

        res = arm_timer(fd, &entry->tspec);
        if (res < 0)
            return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int sk_fd, timer_fd, res;
    struct pollfd fds[2];

    argp_parse(&argp, argc, argv, 0, NULL, NULL);

    STAILQ_INIT(&samples);

    sk_fd = create_listener_socket(ifname, macaddr, ETH_P_TSN);
    if (sk_fd < 0)
        return 1;

    timer_fd = timerfd_create(CLOCK_REALTIME, 0);
    if (timer_fd < 0) {
        close(sk_fd);
        return 1;
    }

    fds[0].fd = sk_fd;
    fds[0].events = POLLIN;
    fds[1].fd = timer_fd;
    fds[1].events = POLLIN;

    while (1) {
        res = poll(fds, 2, -1);
        if (res < 0) {
            perror("Failed to poll() fds");
            goto err;
        }

        if (fds[0].revents & POLLIN) {
            res = new_packet(sk_fd, timer_fd);
            if (res < 0)
                goto err;
        }

        if (fds[1].revents & POLLIN) {
            res = timeout(timer_fd);
            if (res < 0)
                goto err;
        }
    }

    return 0;

err:
    close(sk_fd);
    close(timer_fd);
    return 1;
}
