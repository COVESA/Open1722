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
 */

/* CRF Listener example.
 *
 * This example implements a very simple CRF listener application which receives
 * CRF packets from the network and recovers media clock.
 * Additionally, it operates as AAF listener or AAF talker according to the
 * operation mode option passed via command-line argument.
 *
 * When operating as AAF talker, it sends dummy AAF packets with presentation
 * time that align with the reference clock. AAF packets are sent only after
 * the first CRF packet is received.
 *
 * When operating as AAF listener, it receives AAF packets and checks if their
 * presentation time is aligned with the clock reference provided by the CRF
 * stream.
 *
 * Note that the application running on AAF listener mode should be started
 * before the application running on AAF talker mode so the former is able to
 * recover the media clock and check for AAF stream alignment.
 *
 * TSN stream parameters (e.g. destination mac address and mode) are passed
 * via command-line arguments. Run 'crf-listener --help' for more information.
 *
 * This example relies on the system clock to keep the transmission interval
 * when operating in AAF talker mode. So make sure the system clock is
 * synchronized with PTP time. For further information on how to synchronize
 * those clocks see ptp4l(8) and phc2sys(8) man pages. Additionally, make sure
 * you have configured FQTSS feature from your NIC according (for further
 * information see tc-cbs(8)).
 *
 * Below we provide an example to setup ptp4l, phc2sys and to configure
 * the qdiscs to transmit an AAF stream with 48 kHz sampling rate, 16-bit
 * sample size, stereo.
 *
 * On PTP slave host: Replace $IFNAME by your PTP capable NIC name. The
 * gPTP.cfg file mentioned below can be found in /usr/share/doc/linuxptp/
 * (depending on your distro).
 *	$ ptp4l -f gPTP.cfg -i $IFNAME -s
 *	$ phc2sys -f gPTP.cfg -a -r
 *
 * Configure mpqrio (replace $HANDLE_ID by an unused handle ID):
 *	$ tc qdisc add dev $IFNAME parent root handle $HANDLE_ID mqprio \
 * 			num_tc 3 map 2 2 1 0 2 2 2 2 2 2 2 2 2 2 2 2 \
 *			queues 1@0 1@1 2@2 hw 0
 *
 * Configure cbs:
 *	$ tc qdisc replace dev $IFNAME parent $HANDLE_ID:1 cbs idleslope 5760 \
 *			sendslope -994240 hicredit 9 locredit -89 offload 1
 *
 * Finally, the AAF listener mode implemented by this example application is
 * limited and doesn't work with multiple AAF talkers.
 */

#include <assert.h>
#include <argp.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/timerfd.h>
#include <unistd.h>
#include <math.h>
#include <inttypes.h>

#include "avtp/Crf.h"
#include "avtp/aaf/Pcm.h"
#include "common/common.h"
#include "avtp/CommonHeader.h"

#define AAF_STREAM_ID 0xAABBCCDDEEFF0001
#define AAF_NUM_SAMPLES 6  /* Number of samples per packet. */
#define AAF_SAMPLE_SIZE 2  /* Sample size in bytes. */
#define AAF_NUM_CHANNELS 2 /* Number of channels per frame */
#define AAF_DATA_LEN (AAF_NUM_SAMPLES * AAF_SAMPLE_SIZE * AAF_NUM_CHANNELS)
#define AAF_PDU_SIZE (sizeof(Avtp_Pcm_t) + AAF_DATA_LEN)
#define AAF_SAMPLE_RATE 48000

#define CRF_STREAM_ID 0xAABBCCDDEEFF0002
/* Values based on Spec 1722 Table 28 recommendation. */
#define CRF_SAMPLE_RATE 48000
#define CRF_TIMESTAMPS_PER_SEC 300
#define TIMESTAMPS_PER_PKT 6
#define CRF_DATA_LEN (sizeof(uint64_t) * TIMESTAMPS_PER_PKT)
#define CRF_PDU_SIZE (sizeof(struct avtp_crf_pdu) + CRF_DATA_LEN)

#define MAX_PDU_SIZE MAX(AAF_PDU_SIZE, CRF_PDU_SIZE)
#define TIME_PERIOD_NS ((double)NSEC_PER_SEC / CRF_SAMPLE_RATE)
#define AAF_PERIOD (NSEC_PER_SEC * AAF_NUM_SAMPLES / AAF_SAMPLE_RATE)
#define MCLK_PERIOD AAF_PERIOD
#define MCLKLIST_TS_PER_CRF (CRF_SAMPLE_RATE / CRF_TIMESTAMPS_PER_SEC)

#define NSEC_PER_SEC 1000000000ULL
#define NSEC_PER_MSEC 1000000ULL

struct media_clock_entry {
    STAILQ_ENTRY(media_clock_entry) mclk_entries;
    uint64_t timestamp;
};

static enum {
    MODE_TALKER,
    MODE_LISTENER,
} mode;

static char ifname[IFNAMSIZ];
static uint8_t crf_macaddr[ETH_ALEN];
static uint8_t aaf_macaddr[ETH_ALEN];
static int priority = -1;
static int mtt;
static bool prev_state;
static bool first_aaf_pdu = true;
static bool need_mclk_lookup = true;
static uint8_t crf_seq_num;
static uint8_t aaf_seq_num;
static uint64_t prev_mclk_timestamp, rounded_mtt;
static STAILQ_HEAD(timestamp_queue, media_clock_entry) mclk_timestamps;

static struct argp_option options[] = {
    {"crf-addr", 'c', "MACADDR", 0, "CRF Stream Destination MAC address"},
    {"aaf-addr", 'a', "MACADDR", 0, "AAF Stream Destination MAC address"},
    {"ifname", 'i', "IFNAME", 0, "Network Interface"},
    {"prio", 'p', "NUM", 0, "SO_PRIORITY to be set in AAF stream"},
    {"mtt", 'm', "MSEC", 0, "Max Transit time from AAF stream (in ms)"},
    {"mode", 'o', "talker|listener", 0, "AAF operation mode"},
    {0}};

static error_t parser(int key, char *arg, struct argp_state *state)
{
    int res;

    switch (key) {
    case 'c':
        res = sscanf(arg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &crf_macaddr[0], &crf_macaddr[1],
                     &crf_macaddr[2], &crf_macaddr[3], &crf_macaddr[4], &crf_macaddr[5]);
        if (res != 6) {
            fprintf(stderr, "Invalid CRF address\n");
            exit(EXIT_FAILURE);
        }

        break;
    case 'a':
        res = sscanf(arg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &aaf_macaddr[0], &aaf_macaddr[1],
                     &aaf_macaddr[2], &aaf_macaddr[3], &aaf_macaddr[4], &aaf_macaddr[5]);
        if (res != 6) {
            fprintf(stderr, "Invalid AAF address\n");
            exit(EXIT_FAILURE);
        }

        break;
    case 'm':
        mtt = atoi(arg) * NSEC_PER_MSEC;
        break;
    case 'i':
        strncpy(ifname, arg, sizeof(ifname) - 1);
        break;
    case 'p':
        priority = atoi(arg);
        break;
    case 'o':
        if (strcmp(arg, "talker") == 0)
            mode = MODE_TALKER;
        else if (strcmp(arg, "listener") == 0)
            mode = MODE_LISTENER;
        else {
            fprintf(stderr, "Invalid mode\n");
            exit(EXIT_FAILURE);
        }
        break;
    }

    return 0;
}

static struct argp argp = {options, parser};

static uint64_t mclk_dequeue_ts(void)
{
    uint64_t mclk_timestamp;
    struct media_clock_entry *mclk_entry;

    mclk_entry = STAILQ_FIRST(&mclk_timestamps);
    mclk_timestamp = mclk_entry->timestamp;
    STAILQ_REMOVE_HEAD(&mclk_timestamps, mclk_entries);
    free(mclk_entry);

    return mclk_timestamp;
}

static int mclk_enqueue_ts(uint64_t ts)
{
    struct media_clock_entry *mclk_entry;

    mclk_entry = malloc(sizeof(*mclk_entry));
    if (!mclk_entry) {
        fprintf(stderr, "Failed to allocate memory\n");
        return -1;
    }

    mclk_entry->timestamp = ts;
    STAILQ_INSERT_TAIL(&mclk_timestamps, mclk_entry, mclk_entries);

    return 0;
}

static uint64_t get_next_mclk_timestamp(void)
{
    uint64_t mclk_timestamp;

    if (STAILQ_EMPTY(&mclk_timestamps)) {
        mclk_timestamp = prev_mclk_timestamp + MCLK_PERIOD;
        need_mclk_lookup = true;
    } else {
        mclk_timestamp = mclk_dequeue_ts();
    }

    prev_mclk_timestamp = mclk_timestamp;

    return mclk_timestamp;
}

static uint64_t mclk_lookup(uint32_t avtp_time)
{
    uint64_t mclk_timestamp = get_next_mclk_timestamp();

    while (mclk_timestamp % (1ULL << 32) != avtp_time)
        mclk_timestamp = get_next_mclk_timestamp();

    return mclk_timestamp;
}

static bool is_valid_crf_pdu(struct avtp_crf_pdu *pdu)
{
    int res;
    uint32_t val32;
    uint64_t val64;
    struct avtp_common_pdu *common = (struct avtp_common_pdu *)pdu;

    res = avtp_pdu_get(common, AVTP_FIELD_SUBTYPE, &val32);
    if (res < 0) {
        fprintf(stderr, "Failed to get CRF subtype field: %d\n", res);
        return false;
    }
    if (val32 != AVTP_SUBTYPE_CRF)
        return false;

    res = avtp_pdu_get(common, AVTP_FIELD_VERSION, &val32);
    if (res < 0) {
        fprintf(stderr, "Failed to get CRF version field: %d\n", res);
        return false;
    }
    if (val32 != 0) {
        fprintf(stderr, "CRF: Version mismatch: expected %u, got %u\n", 0, val32);
        return false;
    }

    res = avtp_crf_pdu_get(pdu, AVTP_CRF_FIELD_SV, &val64);
    if (res < 0) {
        fprintf(stderr, "Failed to get CRF sv field: %d\n", res);
        return false;
    }
    if (val64 != 1) {
        fprintf(stderr, "CRF: sv mismatch: expected %u, got %" PRIu64 "\n", 1, val64);
        return false;
    }

    res = avtp_crf_pdu_get(pdu, AVTP_CRF_FIELD_FS, &val64);
    if (res < 0) {
        fprintf(stderr, "Failed to get CRF fs field: %d\n", res);
        return false;
    }
    if (val64 != 0) {
        fprintf(stderr, "CRF: fs mismatch: expected %u, got %" PRIu64 "\n", 0, val64);
        return false;
    }

    res = avtp_crf_pdu_get(pdu, AVTP_CRF_FIELD_SEQ_NUM, &val64);
    if (res < 0) {
        fprintf(stderr, "Failed to get CRF sequence num field: %d\n", res);
        return false;
    }
    if (val64 != crf_seq_num) {
        /* If we have a sequence number mismatch, we simply log the
         * issue and continue to process the packet. We don't want to
         * invalidate it since it is a valid packet after all.
         */
        fprintf(stderr, "CRF: Sequence number mismatch: expected %u, got %" PRIu64 "\n",
                crf_seq_num, val64);

        crf_seq_num = val64;
    }

    crf_seq_num++;

    res = avtp_crf_pdu_get(pdu, AVTP_CRF_FIELD_TYPE, &val64);
    if (res < 0) {
        fprintf(stderr, "Failed to get CRF format field: %d\n", res);
        return false;
    }
    if (val64 != AVTP_CRF_TYPE_AUDIO_SAMPLE) {
        fprintf(stderr, "CRF: Format mismatch: expected %u, got %" PRIu64 "\n",
                AVTP_CRF_TYPE_AUDIO_SAMPLE, val64);
        return false;
    }

    res = avtp_crf_pdu_get(pdu, AVTP_CRF_FIELD_STREAM_ID, &val64);
    if (res < 0) {
        fprintf(stderr, "Failed to get CRF stream ID field: %d\n", res);
        return false;
    }
    if (val64 != CRF_STREAM_ID) {
        fprintf(stderr, "CRF: Stream ID mismatch: expected %" PRIu64 ", got %" PRIu64 "\n",
                CRF_STREAM_ID, val64);
        return false;
    }

    res = avtp_crf_pdu_get(pdu, AVTP_CRF_FIELD_PULL, &val64);
    if (res < 0) {
        fprintf(stderr, "Failed to get CRF multiplier modifier field: %d\n", res);
        return false;
    }
    if (val64 != AVTP_CRF_PULL_MULT_BY_1) {
        fprintf(stderr, "CRF Pull mismatch: expected %u, got %" PRIu64 "\n",
                AVTP_CRF_PULL_MULT_BY_1, val64);
        return false;
    }

    res = avtp_crf_pdu_get(pdu, AVTP_CRF_FIELD_BASE_FREQ, &val64);
    if (res < 0) {
        fprintf(stderr, "Failed to get CRF base frequency field: %d\n", res);
        return false;
    }
    if (val64 != CRF_SAMPLE_RATE) {
        fprintf(stderr, "CRF Base frequency: expected %u, got %" PRIu64 "\n", CRF_SAMPLE_RATE,
                val64);
        return false;
    }

    res = avtp_crf_pdu_get(pdu, AVTP_CRF_FIELD_CRF_DATA_LEN, &val64);
    if (res < 0) {
        fprintf(stderr, "Failed to get CRF data length field: %d\n", res);
        return false;
    }
    if (val64 != CRF_DATA_LEN) {
        fprintf(stderr, "CRF Data length mismatch: expected %zu, got %" PRIu64 "\n", CRF_DATA_LEN,
                val64);
        return false;
    }

    return true;
}

static bool is_valid_aaf_pdu(Avtp_Pcm_t *pdu)
{
    uint64_t val64;
    uint8_t val8;

    if (!Avtp_Pcm_IsValid(pdu, AAF_PDU_SIZE)) {
        fprintf(stderr, "AAF: Invalid AAF PCM PDU\n");
        return false;
    }

    val8 = Avtp_CommonHeader_GetVersion((const Avtp_CommonHeader_t *)pdu);
    if (val8 != 0) {
        fprintf(stderr, "AAF: Version mismatch: expected %u, got %u\n", 0, val8);
        return false;
    }

    if (!Avtp_Pcm_IsTv(pdu)) {
        fprintf(stderr, "AAF: tv mismatch: expected %u, got %u\n", 1, 0);
        return false;
    }

    if (Avtp_Pcm_IsSp(pdu)) {
        fprintf(stderr, "AAF: sp mismatch: expected %u, got %u\n", AVTP_AAF_SP_NORMAL,
                AVTP_AAF_SP_SPARSE);
        return false;
    }

    val64 = Avtp_Pcm_GetStreamId(pdu);
    if (val64 != AAF_STREAM_ID) {
        fprintf(stderr, "AAF: Stream ID mismatch: expected %" PRIu64 ", got %" PRIu64 "\n",
                AAF_STREAM_ID, val64);
        return false;
    }

    val8 = Avtp_Pcm_GetSequenceNum(pdu);
    if (val8 != aaf_seq_num) {
        /* If we have a sequence number mismatch, we simply log the
         * issue and continue to process the packet. We don't want to
         * invalidate it since it is a valid packet after all.
         */
        fprintf(stderr, "AAF Sequence number mismatch: expected %u, got %u\n", aaf_seq_num, val8);

        aaf_seq_num = val8;
    }

    aaf_seq_num++;

    if (Avtp_Pcm_GetFormat(pdu) != AVTP_AAF_FORMAT_INT_16BIT) {
        fprintf(stderr, "AAF: Format mismatch: expected %u, got %u\n", AVTP_AAF_FORMAT_INT_16BIT,
                Avtp_Pcm_GetFormat(pdu));
        return false;
    }

    if (Avtp_Pcm_GetNsr(pdu) != AVTP_PCM_NSR_48KHZ) {
        fprintf(stderr, "AAF: Sample rate mismatch: expected %u, got %u\n", AVTP_PCM_NSR_48KHZ,
                Avtp_Pcm_GetNsr(pdu));
        return false;
    }

    if (Avtp_Pcm_GetChannelsPerFrame(pdu) != AAF_NUM_CHANNELS) {
        fprintf(stderr, "AAF: Channels mismatch: expected %u, got %u\n", AAF_NUM_CHANNELS,
                Avtp_Pcm_GetChannelsPerFrame(pdu));
        return false;
    }

    if (Avtp_Pcm_GetBitDepth(pdu) != 16) {
        fprintf(stderr, "AAF: Depth mismatch: expected %u, got %u\n", 16,
                Avtp_Pcm_GetBitDepth(pdu));
        return false;
    }

    if (Avtp_Pcm_GetStreamDataLength(pdu) != AAF_DATA_LEN) {
        fprintf(stderr, "AAF: Data len mismatch: expected %u, got %u\n", AAF_DATA_LEN,
                Avtp_Pcm_GetStreamDataLength(pdu));
        return false;
    }

    return true;
}

static void init_aaf_pdu(Avtp_Pcm_t *pdu)
{
    Avtp_Pcm_Init(pdu);
    Avtp_Pcm_SetTv(pdu, true);
    Avtp_Pcm_SetStreamId(pdu, AAF_STREAM_ID);
    Avtp_Pcm_SetFormat(pdu, AVTP_AAF_FORMAT_INT_16BIT);
    Avtp_Pcm_SetNsr(pdu, AVTP_PCM_NSR_48KHZ);
    Avtp_Pcm_SetChannelsPerFrame(pdu, AAF_NUM_CHANNELS);
    Avtp_Pcm_SetBitDepth(pdu, 16);
    Avtp_Pcm_SetStreamDataLength(pdu, AAF_DATA_LEN);
    Avtp_Pcm_SetSp(pdu, false);
}

static int aaf_talker_tx_timeout(int fd_timer, int fd_sk, const struct sockaddr_ll *addr,
                                 Avtp_Pcm_t *pdu)
{
    int res;
    ssize_t n;
    uint64_t expirations;
    uint32_t avtp_time = 0;

    n = read(fd_timer, &expirations, sizeof(uint64_t));
    if (n < 0) {
        perror("Failed to read timerfd");
        return -1;
    }

    while (expirations--) {
        avtp_time = get_next_mclk_timestamp();

        Avtp_Pcm_SetAvtpTimestamp(pdu, avtp_time);
        Avtp_Pcm_SetSequenceNum(pdu, aaf_seq_num++);

        n = sendto(fd_sk, pdu, AAF_PDU_SIZE, 0, (struct sockaddr *)addr, sizeof(*addr));
        if (n < 0) {
            perror("Failed to send data");
            return -1;
        }
        if (n != AAF_PDU_SIZE) {
            fprintf(stderr, "AAF: wrote %zd bytes, expected %zd\n", n, AAF_PDU_SIZE);
        }
    }

    return 0;
}

/* This routine generates media clock timestamps using timestamps from CRF
 * stream.
 */
static int recover_mclk(struct avtp_crf_pdu *pdu)
{
    int res, idx;
    uint64_t ts_mclk, ts_crf;

    /* For simplicity's sake, we consider only the first timestamp from
     * CRF PDU to recover the media clock.
     */
    ts_crf = be64toh(pdu->crf_data[0]);

    for (idx = 0; idx < MCLKLIST_TS_PER_CRF; idx++) {
        ts_mclk = ts_crf + (idx * MCLK_PERIOD);

        if (mode == MODE_TALKER) {
            /* If we are operating in talker mode, the max transit
             * time is added to the recovered timestamp, rounding
             * it up to the nearest multiple fo the media clock.
             */
            ts_mclk += rounded_mtt;
        }

        if (ts_mclk <= prev_mclk_timestamp)
            /* If the recovered timestamp is less than the
             * timestamp from the last AAF pdu received, we discard
             * it. This situation happens when the CRF pdu is
             * received late and the media clock has already
             * freewheeled.
             */
            continue;

        res = mclk_enqueue_ts(ts_mclk);
        if (res < 0)
            return res;
    }

    return 0;
}

static int is_ts_aligned(uint32_t mclk_ts, uint32_t avtp_ts)
{
    int n = 0;
    int t_offset, delta_ll, delta_hl;

    t_offset = avtp_ts - mclk_ts;

    delta_ll = (n * TIME_PERIOD_NS) - (TIME_PERIOD_NS / 4);
    delta_hl = (n * TIME_PERIOD_NS) + (TIME_PERIOD_NS / 4);

    /* Equation 16 defined in spec 1722:
     * ((n * Ps) - Ps/4) < Toffset < ((n * Ps) + Ps/4)
     * Toffset:	timestamp offset in nanoseconds between the
            AVTP Presentation Timestamp of the media stream
            and the timestamp of the CRF stream
     * n	:	positive integer chosen for the implementation
     * Ps	:	the sample period of the CRF stream in nanoseconds
     */
    if (delta_ll > t_offset || t_offset > delta_hl)
        return false;

    return true;
}

static int handle_crf_pdu(struct avtp_crf_pdu *pdu)
{
    if (!is_valid_crf_pdu(pdu))
        return 0;

    return recover_mclk(pdu);
}

static int handle_aaf_pdu(Avtp_Pcm_t *pdu)
{
    bool state;
    uint32_t avtp_time, mclk_time;

    if (!is_valid_aaf_pdu(pdu))
        return 0;

    avtp_time = Avtp_Pcm_GetAvtpTimestamp(pdu);

    if (need_mclk_lookup) {
        mclk_time = mclk_lookup(avtp_time);
        need_mclk_lookup = false;
    } else {
        mclk_time = get_next_mclk_timestamp();
    }

    state = is_ts_aligned(mclk_time, avtp_time);
    if (prev_state != state) {
        if (state)
            printf("AAF Stream is aligned with common media clock\n");
        else
            printf("AAF Stream is not aligned with common media clock\n");
    }
    prev_state = state;

    return 0;
}

static int aaf_talker_recv_pdu(int fd_sk, int fd_timer)
{
    int res;
    ssize_t n;
    struct avtp_crf_pdu *pdu = alloca(CRF_PDU_SIZE);

    memset(pdu, 0, CRF_PDU_SIZE);

    n = recv(fd_sk, pdu, CRF_PDU_SIZE, 0);
    if (n < 0) {
        perror("Failed to receive data");
        return -1;
    }

    /* The protocol type from rx socket is set to ETH_P_ALL so we receive
     * non-AVTP packets as well. In order to filter out those packets, we
     * check the number of bytes received. If it doesn't match the CRF pdu
     * size we drop the packet.
     */
    if (n != CRF_PDU_SIZE)
        return 0;

    res = handle_crf_pdu(pdu);
    if (res < 0)
        return -1;

    /* Arm the timer for the first time to start sending AAF stream. */
    if (first_aaf_pdu) {
        struct itimerspec itspec = {0};
        uint64_t ts = mclk_dequeue_ts();

        first_aaf_pdu = false;

        itspec.it_value.tv_sec = ts / NSEC_PER_SEC;
        itspec.it_value.tv_nsec = ts % NSEC_PER_SEC;
        itspec.it_interval.tv_sec = 0;
        itspec.it_interval.tv_nsec = AAF_PERIOD;
        res = timerfd_settime(fd_timer, TFD_TIMER_ABSTIME, &itspec, NULL);
        if (res < 0) {
            perror("Failed to set timer");
            return -1;
        }
    }
    return 0;
}

static int aaf_listener_recv_pdu(int fd)
{
    int res = 0;
    ssize_t n;
    uint8_t subtype;
    void *pdu = alloca(MAX_PDU_SIZE);

    memset(pdu, 0, MAX_PDU_SIZE);

    n = recv(fd, pdu, MAX_PDU_SIZE, 0);
    if (n < 0) {
        perror("Failed to receive data");
        return -1;
    }

    /* The protocol type from rx socket is set to ETH_P_ALL so we receive
     * non-AVTP packets as well. In order to filter out those packets, we
     * check the number of bytes received. If it doesn't match the CRF or
     * AAF pdu size we drop the packet.
     */
    if (n != AAF_PDU_SIZE && n != CRF_PDU_SIZE)
        return 0;

    subtype = Avtp_CommonHeader_GetSubtype((const Avtp_CommonHeader_t *)pdu);

    switch (subtype) {
    case AVTP_SUBTYPE_CRF:
        res = handle_crf_pdu(pdu);
        break;
    case AVTP_SUBTYPE_AAF:
        res = handle_aaf_pdu((Avtp_Pcm_t *)pdu);
        break;
    }

    return res;
}

static int setup_rx_socket(void)
{
    int res, fd;
    struct ifreq req = {0};
    struct packet_mreq mreq = {0};

    /* In case this example is running on the same host where crf-talker is
     * running, we set protocol type to ETH_P_ALL to allow CRF traffic to
     * loop back.
     */
    fd = create_listener_socket(ifname, crf_macaddr, ETH_P_ALL);
    if (fd < 0) {
        perror("Failed to open socket");
        return -1;
    }

    if (mode == MODE_LISTENER) {
        snprintf(req.ifr_name, sizeof(req.ifr_name), "%s", ifname);
        res = ioctl(fd, SIOCGIFINDEX, &req);
        if (res < 0) {
            perror("Failed to get interface index");
            goto err;
        }

        mreq.mr_ifindex = req.ifr_ifindex;
        mreq.mr_type = PACKET_MR_MULTICAST;
        mreq.mr_alen = ETH_ALEN;
        memcpy(&mreq.mr_address, aaf_macaddr, ETH_ALEN);

        res = setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(struct packet_mreq));
        if (res < 0) {
            perror("Couldn't add membership for AAF stream");
            goto err;
        }
    }

    return fd;

err:
    close(fd);
    return -1;
}

static int aaf_talker(int fd_rx)
{
    int res, fd_tx, fd_timer;
    struct pollfd poll_fd[2];
    struct sockaddr_ll sk_addr = {0};
    struct ifreq req = {0};
    Avtp_Pcm_t *pdu;

    fd_tx = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_TSN));
    if (fd_tx < 0) {
        perror("Failed to open socket");
        return -1;
    }

    if (priority != -1) {
        res = setsockopt(fd_tx, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority));
        if (res < 0) {
            perror("Failed to set priority");
            goto fd_tx_close;
        }
    }

    snprintf(req.ifr_name, sizeof(req.ifr_name), "%s", ifname);
    res = ioctl(fd_tx, SIOCGIFINDEX, &req);
    if (res < 0) {
        perror("Failed to get interface index");
        goto fd_tx_close;
    }

    sk_addr.sll_family = AF_PACKET;
    sk_addr.sll_protocol = htons(ETH_P_TSN);
    sk_addr.sll_halen = ETH_ALEN;
    sk_addr.sll_ifindex = req.ifr_ifindex;
    memcpy(&sk_addr.sll_addr, aaf_macaddr, ETH_ALEN);

    fd_timer = timerfd_create(CLOCK_REALTIME, 0);
    if (fd_timer < 0)
        goto fd_tx_close;

    pdu = alloca(AAF_PDU_SIZE);
    init_aaf_pdu(pdu);
    memset(pdu->payload, 0, AAF_DATA_LEN);

    poll_fd[0].fd = fd_rx;
    poll_fd[0].events = POLLIN;
    poll_fd[1].fd = fd_timer;
    poll_fd[1].events = POLLIN;

    while (1) {
        res = poll(poll_fd, 2, -1);
        if (res < 0) {
            perror("Failed to poll() fds");
            goto fd_timer_close;
        }

        if (poll_fd[0].revents & POLLIN) {
            res = aaf_talker_recv_pdu(fd_rx, fd_timer);
            if (res < 0)
                goto fd_timer_close;
        }

        if (poll_fd[1].revents & POLLIN) {
            res = aaf_talker_tx_timeout(fd_timer, fd_tx, &sk_addr, pdu);
            if (res < 0)
                goto fd_timer_close;
        }
    }

    close(fd_timer);
    close(fd_tx);
    return 0;

fd_timer_close:
    close(fd_timer);
fd_tx_close:
    close(fd_tx);
    return 1;
}

static int aaf_listener(int fd_rx)
{
    int res;

    while (1) {
        res = aaf_listener_recv_pdu(fd_rx);
        if (res < 0)
            return -1;
    }
}

int main(int argc, char *argv[])
{
    int fd_rx;

    argp_parse(&argp, argc, argv, 0, NULL, NULL);

    STAILQ_INIT(&mclk_timestamps);
    rounded_mtt = ceil((double)mtt / MCLK_PERIOD) * MCLK_PERIOD;

    fd_rx = setup_rx_socket();
    if (fd_rx < 0)
        return 1;

    switch (mode) {
    case MODE_LISTENER:
        aaf_listener(fd_rx);
        break;
    case MODE_TALKER:
        aaf_talker(fd_rx);
        break;
    }

    close(fd_rx);
    return 0;
}
