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

#include "avtp/acf/Can.h"

#define MAX_ETH_PDU_SIZE                1500

/* CAN CC/FD frame union */
typedef union {
    struct can_frame cc;
    struct canfd_frame fd;
} frame_t;

/**
 * Creates a CAN socket.
 *
 * @param can_ifname Pointer to the first bit of an 1722 AVTP PDU.
 * @param can_variant CAN or CAN-FD
 * @returns CAN socket on success else the error
 */
int setup_can_socket(const char* can_ifname, Avtp_CanVariant_t can_variant);

/**
 * Function that converts AVTP Frames to CAN
 *
 * @param eth_socket Ethernet/UDP socket.
 * @param can_socket CAN/CAN-FD socket
 * @param use_udp 1: UDP encapsulation, 0: Ethernet
 * @param stream_id: AVTP stream ID of interest
 */
void avtp_to_can(int eth_socket, int can_socket,
                    Avtp_CanVariant_t can_variant,
                     int use_udp, uint64_t stream_id);

/**
 * Function that converts AVTP Frames to CAN
 *
 * @param eth_socket Ethernet/UDP socket.
 * @param can_socket CAN/CAN-FD socket
 * @param use_udp 1: UDP encapsulation, 0: Ethernet
 * @param use_tscf 1: TSCF, 0: NTSCF
 * @param stream_id: AVTP stream ID of interest
 * @param num_acf_msgs: No. of ACF CAN messages to aggregate
 * @param dst_addr: Destination
 */
void can_to_avtp(int eth_socket, int can_socket,
                    Avtp_CanVariant_t can_variant,
                     int use_udp, int use_tscf, uint64_t stream_id,
                     uint8_t num_acf_msgs, struct sockaddr* dst_addr);