/*
 * Copyright (c) 2024, COVESA
 * Copyright (c) 2019, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of COVESA, Intel Corporation nor the names of its
 *      contributors  may be used to endorse or promote products derived from
 *      this software without specific prior written permission.
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

/* CVF Listener example.
 *
 * This example implements a very simple CVF listener application which
 * receives CVF packets from the network, retrieves video data and writes
 * them to stdout once the presentation time is reached.
 *
 * For simplicity, this examples accepts only CVF H.264 packets, and the H.264
 * data must be composed of NAL and each NAL unit can not exceed 1400 bytes.
 *
 * The H.264 data sent to output is in H.264 byte-stream format.
 *
 * TSN stream parameters such as destination mac address are passed via
 * command-line arguments. Run 'cvf-listener --help' for more information.
 *
 * This example relies on the system clock to schedule video data samples for
 * presentation. So make sure the system clock is synchronized with the PTP
 * Hardware Clock (PHC) from your NIC and that the PHC is synchronized with
 * the PTP time from the network. For further information on how to synchronize
 * those clocks see ptp4l(8) and phc2sys(8) man pages.
 *
 * The easiest way to use this example is by combining it with a GStreamer
 * pipeline. We use GStreamer to read the H.264 byte-stream from stdin and
 * present it. So, to play an H.264 video from a TSN strem and show it on a X
 * display, you can do something like:
 *
 * $ cvf-listener <args> | gst-launch-1.0 filesrc location=/dev/stdin \
 *  ! decodebin ! videoconvert ! autovideosink
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

#include "avtp.h"
#include "avtp/cvf/Cvf.h"
#include "avtp/cvf/H264.h"
#include "avtp/CommonHeader.h"
#include "common.h"

#define STREAM_ID				0xAABBCCDDEEFF0001
#define DATA_LEN				1400
#define AVTP_H264_HEADER_LEN	(sizeof(Avtp_H264_t))
#define AVTP_FULL_HEADER_LEN	(sizeof(Avtp_Cvf_t) + sizeof(Avtp_H264_t))
#define MAX_PDU_SIZE			(AVTP_FULL_HEADER_LEN + DATA_LEN)

struct nal_entry {
	STAILQ_ENTRY(nal_entry) entries;

	uint16_t len;
	struct timespec tspec;
	uint8_t nal[DATA_LEN];
};

static STAILQ_HEAD(nal_queue, nal_entry) nals;
static char ifname[IFNAMSIZ];
static uint8_t macaddr[ETH_ALEN];
static uint8_t expected_seq;

static struct argp_option options[] = {
	{"dst-addr", 'd', "MACADDR", 0, "Stream Destination MAC address" },
	{"ifname", 'i', "IFNAME", 0, "Network Interface" },
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
	}

	return 0;
}

static struct argp argp = { options, parser };

static int schedule_nal(int fd, struct timespec *tspec, uint8_t *nal,
								ssize_t len)
{
	struct nal_entry *entry;

	entry = malloc(sizeof(*entry));
	if (!entry) {
		fprintf(stderr, "Failed to allocate memory\n");
		return -1;
	}

	entry->len = len;
	entry->tspec.tv_sec = tspec->tv_sec;
	entry->tspec.tv_nsec = tspec->tv_nsec;
	memcpy(entry->nal, nal, entry->len);

	STAILQ_INSERT_TAIL(&nals, entry, entries);

	/* If this was the first entry inserted onto the queue, we need to arm
	 * the timer.
	 */
	if (STAILQ_FIRST(&nals) == entry) {
		int res;

		res = arm_timer(fd, tspec);
		if (res < 0) {
			STAILQ_REMOVE(&nals, entry, nal_entry, entries);
			free(entry);
			return -1;
		}
	}

	return 0;
}

static bool is_valid_packet(Avtp_Cvf_t* cvf)
{
	uint64_t val;
	int res;

	res = Avtp_Cvf_GetField(cvf, AVTP_CVF_FIELD_SUBTYPE, &val);
	if (res < 0) {
		fprintf(stderr, "Failed to get subtype field: %d\n", res);
		return false;
	}
	if (val != AVTP_SUBTYPE_CVF) {
		fprintf(stderr, "Subtype mismatch: expected %u, got %"PRIu64"\n", AVTP_SUBTYPE_CVF, val);
		return false;
	}

	res = Avtp_Cvf_GetField(cvf, AVTP_CVF_FIELD_VERSION, &val);
	if (res < 0) {
		fprintf(stderr, "Failed to get version field: %d\n", res);
		return false;
	}
	if (val != 0) {
		fprintf(stderr, "Version mismatch: expected %u, got %"PRIu64"\n", 0, val);
		return false;
	}

	res = Avtp_Cvf_GetField(cvf, AVTP_CVF_FIELD_TV, &val);
	if (res < 0) {
		fprintf(stderr, "Failed to get tv field: %d\n", res);
		return false;
	}
	if (val != 1) {
		fprintf(stderr, "tv mismatch: expected %u, got %lu\n",
								1, val);
		return false;
	}

	res = Avtp_Cvf_GetField(cvf, AVTP_CVF_FIELD_STREAM_ID, &val);
	if (res < 0) {
		fprintf(stderr, "Failed to get stream ID field: %d\n", res);
		return false;
	}
	if (val != STREAM_ID) {
		fprintf(stderr, "Stream ID mismatch: expected %lu, got %lu\n",
							STREAM_ID, val);
		return false;
	}

	res = Avtp_Cvf_GetField(cvf, AVTP_CVF_FIELD_SEQUENCE_NUM, &val);
	if (res < 0) {
		fprintf(stderr, "Failed to get sequence num field: %d\n", res);
		return false;
	}

	if (val != expected_seq) {
		/* If we have a sequence number mismatch, we simply log the
		 * issue and continue to process the packet. We don't want to
		 * invalidate it since it is a valid packet after all.
		 */
		fprintf(stderr,
			"Sequence number mismatch: expected %u, got %lu\n",
							expected_seq, val);
		expected_seq = val;
	}

	expected_seq++;

	res = Avtp_Cvf_GetField(cvf, AVTP_CVF_FIELD_FORMAT, &val);
	if (res < 0) {
		fprintf(stderr, "Failed to get format field: %d\n", res);
		return false;
	}
	if (val != AVTP_CVF_FORMAT_RFC) {
		fprintf(stderr, "Format mismatch: expected %u, got %lu\n",
					AVTP_CVF_FORMAT_RFC, val);
		return false;
	}

	res = Avtp_Cvf_GetField(cvf, AVTP_CVF_FIELD_FORMAT_SUBTYPE, &val);
	if (res < 0) {
		fprintf(stderr, "Failed to get format subtype field: %d\n",
									res);
		return false;
	}
	if (val != AVTP_CVF_FORMAT_SUBTYPE_H264) {
		fprintf(stderr, "Format mismatch: expected %u, got %lu\n",
					AVTP_CVF_FORMAT_SUBTYPE_H264, val);
		return false;
	}

	return true;
}

static int get_h264_data_len(Avtp_Cvf_t* cvfHeader, uint16_t *stream_data_len)
{
	int res;
	uint64_t val;

	res = Avtp_Cvf_GetField(cvfHeader, AVTP_CVF_FIELD_STREAM_DATA_LENGTH, &val);
	if (res < 0) {
		fprintf(stderr, "Failed to get data_len field\n");
		return -1;
	}
	*stream_data_len = val - AVTP_H264_HEADER_LEN;

	return 0;
}

static int new_packet(int sk_fd, int timer_fd)
{
	int res;
	ssize_t n;
	uint16_t h264_data_len;
	uint64_t avtp_time;
	struct timespec tspec;
	Avtp_Cvf_t* cvfHeader = alloca(MAX_PDU_SIZE);
	Avtp_H264_t* h264Header = (Avtp_H264_t*)(&cvfHeader->payload);
	uint8_t* h264Payload = (uint8_t*)(&h264Header->payload);

	memset(cvfHeader, 1, MAX_PDU_SIZE);

	n = recv(sk_fd, cvfHeader, MAX_PDU_SIZE, 0);
	if (n < 0 || n > MAX_PDU_SIZE) {
		perror("Failed to receive data");
		return -1;
	}

	if (!is_valid_packet(cvfHeader)) {
		fprintf(stderr, "Dropping packet\n");
		return 0;
	}

	res = Avtp_Cvf_GetField(cvfHeader, AVTP_CVF_FIELD_AVTP_TIMESTAMP, &avtp_time);
	if (res < 0) {
		fprintf(stderr, "Failed to get AVTP time from PDU\n");
		return -1;
	}

	res = get_presentation_time(avtp_time, &tspec);
	if (res < 0)
		return -1;

	res = get_h264_data_len(cvfHeader, &h264_data_len);
	if (res < 0)
		return -1;

	res = schedule_nal(timer_fd, &tspec, h264Payload, h264_data_len);
	if (res < 0)
		return -1;

	return 0;
}

static int timeout(int fd)
{
	int res;
	ssize_t n;
	uint64_t expirations;
	struct nal_entry *entry;

	n = read(fd, &expirations, sizeof(uint64_t));
	if (n < 0) {
		perror("Failed to read timerfd");
		return -1;
	}

	assert(expirations == 1);

	entry = STAILQ_FIRST(&nals);
	assert(entry != NULL);

	res = present_data(entry->nal, entry->len);
	if (res < 0)
		return -1;

	STAILQ_REMOVE_HEAD(&nals, entries);
	free(entry);

	if (!STAILQ_EMPTY(&nals)) {
		entry = STAILQ_FIRST(&nals);

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

	STAILQ_INIT(&nals);

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
