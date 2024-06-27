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

/* CVF Talker example.
 *
 * This example implements a very simple CVF talker application which reads
 * an H.264 byte-stream from stdin, creates CVF packets and transmit them via
 * network.
 *
 * For simplicity, this example supports only NAL units in byte-stream format,
 * and each NAL unit can not exceed 1400 bytes.
 *
 * TSN stream parameters (e.g. destination mac address, traffic priority) are
 * passed via command-line arguments. Run 'cvf-talker --help' for more
 * information.
 *
 * In order to have this example working properly, make sure you have
 * configured FQTSS feature from your NIC according (for further information
 * see tc-cbs(8)). Also, this example relies on system clock to set the AVTP
 * timestamp so make sure it is synchronized with the PTP Hardware Clock (PHC)
 * from your NIC and that the PHC is synchronized with the network clock. For
 * further information see ptp4l(8) and phc2sys(8).
 *
 * The easiest way to use this example is by combining it with a GStreamer
 * pipeline. We use GStreamer to provide an H.264 stream that is sent to
 * stdout, from where this example reads the stream. So, to generate
 * an H.264 video to send via TSN network, you can do something like:
 *
 * $ gst-launch-1.0 -e -q videotestsrc pattern=ball \
 *  ! video/x-raw,width=192,height=144 ! x264enc \
 *  ! video/x-h264,stream-format=byte-stream ! filesink location=/dev/stdout \
 *  | cvf-talker <args>
 *
 * Note that the `x264enc` may be changed by any other H.264 encoder
 * available, as long as it generates a byte-stream with NAL units no longer
 * than 1400 bytes.
 */

#include <alloca.h>
#include <argp.h>
#include <arpa/inet.h>
#include <assert.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "avtp.h"
#include "avtp/cvf/Cvf.h"
#include "avtp/cvf/H264.h"
#include "common.h"
#include "avtp/CommonHeader.h"

#define STREAM_ID				0xAABBCCDDEEFF0001
#define DATA_LEN				1400
#define AVTP_H264_HEADER_LEN	(sizeof(Avtp_H264_t))
#define AVTP_FULL_HEADER_LEN	(sizeof(Avtp_Cvf_t) + sizeof(Avtp_H264_t))
#define MAX_PDU_SIZE			(AVTP_FULL_HEADER_LEN + DATA_LEN)

static char ifname[IFNAMSIZ];
static uint8_t macaddr[ETH_ALEN];
static int priority = -1;
static int max_transit_time;

static char buffer[MAX_PDU_SIZE * 2];
static size_t buffer_level;

static uint8_t seq_num;

enum process_result {PROCESS_OK, PROCESS_NONE, PROCESS_ERROR};

static struct argp_option options[] = {
	{"dst-addr", 'd', "MACADDR", 0, "Stream Destination MAC address" },
	{"ifname", 'i', "IFNAME", 0, "Network Interface" },
	{"max-transit-time", 'm', "MSEC", 0, "Maximum Transit Time in ms" },
	{"prio", 'p', "NUM", 0, "SO_PRIORITY to be set in socket" },
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
		max_transit_time = atoi(arg);
		break;
	case 'p':
		priority = atoi(arg);
		break;
	}

	return 0;
}

static struct argp argp = { options, parser };

static int init_pdu(Avtp_Cvf_t* cvf)
{
	Avtp_Cvf_Init(cvf);
	Avtp_Cvf_SetField(cvf, AVTP_CVF_FIELD_FORMAT_SUBTYPE, AVTP_CVF_FORMAT_SUBTYPE_H264);
	Avtp_Cvf_SetField(cvf, AVTP_CVF_FIELD_TV, 1);
	Avtp_Cvf_SetField(cvf, AVTP_CVF_FIELD_STREAM_ID, STREAM_ID);
	Avtp_Cvf_SetField(cvf, AVTP_CVF_FIELD_M, 1);
	Avtp_Cvf_SetField(cvf, AVTP_CVF_FIELD_PTV, 0);

	Avtp_H264_t* h264 = (Avtp_H264_t*)(&cvf->payload);
	Avtp_H264_Init(h264);
	Avtp_H264_SetField(h264, AVTP_H264_FIELD_TIMESTAMP, 0);

	return 0;
}

static ssize_t fill_buffer(void)
{
	ssize_t n;

	n = read(STDIN_FILENO, buffer + buffer_level,
					sizeof(buffer) - buffer_level);
	if (n < 0) {
		perror("Could not read from standard input");
	}

	buffer_level += n;

	return n;
}

static ssize_t start_code_position(size_t offset)
{
	assert(offset < buffer_level);

	/* Simplified Boyer-Moore, inspired by gstreamer */
	while (offset < buffer_level - 2) {
		if (buffer[offset + 2] == 0x1) {
			if (buffer[offset] == 0x0 && buffer[offset + 1] == 0x0)
				return offset;
			offset += 3;
		} else if (buffer[offset + 2] == 0x0) {
			offset++;
		} else {
			offset += 3;
		}
	}

	return -1;
}

static int prepare_packet(Avtp_Cvf_t* cvfHeader, char *nal_data, size_t nal_data_len)
{
	int res;
	uint32_t avtp_time;
	Avtp_H264_t* h264Header = (Avtp_H264_t*)(&cvfHeader->payload);
	uint8_t* h264Payload = (uint8_t*)(&h264Header->payload);

	res = calculate_avtp_time(&avtp_time, max_transit_time);
	if (res < 0) {
		fprintf(stderr, "Failed to calculate avtp time\n");
		return -1;
	}

	Avtp_Cvf_SetField(cvfHeader, AVTP_CVF_FIELD_AVTP_TIMESTAMP, avtp_time);
	Avtp_Cvf_SetField(cvfHeader, AVTP_CVF_FIELD_SEQUENCE_NUM, seq_num++);
	Avtp_Cvf_SetField(cvfHeader, AVTP_CVF_FIELD_STREAM_DATA_LENGTH, nal_data_len + AVTP_H264_HEADER_LEN);

	memcpy(h264Payload, nal_data, nal_data_len);

	return 0;
}

static int process_nal(Avtp_Cvf_t* pdu, bool process_last,
							size_t* nal_len)
{
	int res;
	ssize_t start, end;

	*nal_len = 0;

	start = start_code_position(0);
	if (start == -1) {
		fprintf(stderr, "Unable to find NAL start\n");
		return PROCESS_NONE;
	}
	/* Now, let's find where the next starts. This is where current ends */
	end = start_code_position(start + 1);
	if (end == -1) {
		if (process_last == false) {
			return PROCESS_NONE;
		} else {
			end = buffer_level;
		}
	}

	*nal_len = end - start;
	if (*nal_len > DATA_LEN) {
		fprintf(stderr, "NAL length bigger than expected. Expected %u, "
					"found %zd\n", DATA_LEN, *nal_len);
		goto err;
	}

	/* Sets AVTP packet headers and content - the NAL unit */
	res = prepare_packet(pdu, &buffer[start], *nal_len);
	if (res < 0) {
		goto err;
	}

	/* Finally, let's offset any remaining data on the buffer to the
	 * beginning. Not really efficient, but keep things simple */
	memmove(buffer, buffer + end, buffer_level - end);
	buffer_level -= end;

	return PROCESS_OK;

err:
	return PROCESS_ERROR;
}

int main(int argc, char *argv[])
{
	int fd, res;
	struct sockaddr_ll sk_addr;
	uint8_t* pdu = alloca(MAX_PDU_SIZE);
	Avtp_Cvf_t* cvf = (Avtp_Cvf_t*)pdu;

	argp_parse(&argp, argc, argv, 0, NULL, NULL);

	fd = create_talker_socket(priority);
	if (fd < 0)
		return 1;

	res = setup_socket_address(fd, ifname, macaddr, ETH_P_TSN, &sk_addr);
	if (res < 0)
		goto err;

	res = init_pdu(cvf);
	if (res < 0)
		goto err;

	while (1) {
		ssize_t n;
		bool end = false;

		n = fill_buffer();
		if (n == 0)
			end = true;

		while (buffer_level > 0) {
			enum process_result pr =
					process_nal(cvf, end, (size_t *)&n);
			if (pr == PROCESS_ERROR)
				goto err;
			if (pr == PROCESS_NONE)
				break;

			n = sendto(fd, pdu, AVTP_FULL_HEADER_LEN + n, 0,
				(struct sockaddr *) &sk_addr, sizeof(sk_addr));
			if (n < 0) {
				perror("Failed to send data");
				goto err;
			}
		}

		if (end)
			break;
	}

	close(fd);
	return 0;

err:
	close(fd);
	return 1;
}
