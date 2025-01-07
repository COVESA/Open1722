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

#ifdef __linux__
#include <linux/can.h>
#elif defined(__ZEPHYR__)
#include <zephyr/drivers/can.h>

/* Defined missing in Zephyr or different from Linux but
   required for acf-can applications*/
#define CAN_EFF_FLAG 0x80000000U
#define CAN_RTR_FLAG 0x40000000U
#define CAN_ERR_FLAG 0x20000000U
#define CAN_EFF_MASK 0x1FFFFFFFU
#endif

#include "avtp/acf/Can.h"

#define MAX_ETH_PDU_SIZE                1500
#define MAX_CAN_FRAMES_IN_ACF           15

#ifdef __linux__
typedef struct can_frame can_frame_t;
typedef struct canfd_frame canfd_frame_t;
#elif defined (__ZEPHYR__)
typedef struct can_frame can_frame_t;
typedef struct can_frame canfd_frame_t;
#endif

/* CAN CC/FD frame union */
/* This is needed because the data structures for CAN and CAN-FD in Linux
    are slightly different. However, in Zephyr same data structure is used for both.
*/
typedef union {
    can_frame_t cc;
    canfd_frame_t fd;
} frame_t;

#ifdef __linux__
/**
 * Creates a CAN socket.
 *
 * @param can_ifname Pointer to the first bit of an 1722 AVTP PDU.
 * @param can_variant CAN or CAN-FD
 * @returns CAN socket on success else the error
 */
int setup_can_socket(const char* can_ifname, Avtp_CanVariant_t can_variant);
#endif

/**
 * Function that converts AVTP Frames to CAN
 *
 * @param pdu: Start of the AVTP Frame
 * @param can_frames: Array of CAM Frames to be recovered from AVTP Frames
 * @param can_variant: AVTP_CAN_CLASSIC or AVTP_CAN_FD
 * @param use_udp 1: UDP encapsulation, 0: Ethernet
 * @param stream_id: AVTP stream ID of interest
 * @param exp_cf_seqnum: Expected Control format sequence num.
 * @param exp_udp_seqnum: Expected UDP Encapsulation sequence num.
 * @return Number of CAN messages received
 */
int avtp_to_can(uint8_t* pdu, frame_t* can_frames, Avtp_CanVariant_t can_variant,
                int use_udp, uint64_t stream_id, uint8_t* exp_cf_seqnum,
                uint32_t* exp_udp_seqnum);

/**
 * Function that converts AVTP Frames to CAN
 *
 * @param can_frames: Array of CAM Frames to be translated to AVTP Frames
 * @param can_variant: AVTP_CAN_CLASSIC or AVTP_CAN_FD
 * @param pdu: Start of AVTP Frame
 * @param use_udp 1: UDP encapsulation, 0: Ethernet
 * @param use_tscf 1: TSCF, 0: NTSCF
 * @param stream_id: AVTP stream ID of interest
 * @param num_acf_msgs: No. of ACF CAN messages to aggregate
 * @param cf_seq_num: Control format sequence num.
 * @param udp_seq_num: UDP Encapsulation sequence num.
 * @return Length of the PDU
 */
int can_to_avtp(frame_t* can_frames, Avtp_CanVariant_t can_variant, uint8_t* pdu,
                     int use_udp, int use_tscf, uint64_t stream_id,
                     uint8_t num_acf_msgs, uint8_t cf_seq_num, uint32_t udp_seq_num);