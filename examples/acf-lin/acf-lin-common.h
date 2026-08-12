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
#endif

#include "avtp/acf/Lin.h"

#define MAX_ETH_PDU_SIZE                1500

#ifdef __linux__
/**
 * Creates a LIN (sllin) socket.
 *
 * @param lin_ifname Name of the sllin network interface (e.g. "sllin0")
 * @returns LIN socket on success else the error
 */
int setup_lin_socket(const char* lin_ifname);
#endif

/**
 * Function that converts AVTP Frames to LIN.
 *
 * @param pdu: Start of the AVTP Frame
 * @param lin_frame: LIN frame to be recovered from AVTP Frame
 * @param use_udp 1: UDP encapsulation, 0: Ethernet
 * @param stream_id: AVTP stream ID of interest
 * @param exp_cf_seqnum: Expected Control format sequence num.
 * @param exp_udp_seqnum: Expected UDP Encapsulation sequence num.
 * @return 1 on success, <= 0 on error
 */
int avtp_to_lin(uint8_t* pdu, struct can_frame* lin_frame,
                int use_udp, uint64_t stream_id, uint8_t* exp_cf_seqnum,
                uint32_t* exp_udp_seqnum);

/**
 * Function that converts LIN frames to AVTP Frames.
 *
 * @param lin_frame: LIN frame to be translated to an AVTP Frame
 * @param pdu: Start of AVTP Frame
 * @param use_udp 1: UDP encapsulation, 0: Ethernet
 * @param use_tscf 1: TSCF, 0: NTSCF
 * @param stream_id: AVTP stream ID of interest
 * @param lin_bus_id: LIN bus ID for the ACF field
 * @param cf_seq_num: Control format sequence num.
 * @param udp_seq_num: UDP Encapsulation sequence num.
 * @return Length of the PDU
 */
int lin_to_avtp(struct can_frame* lin_frame, uint8_t* pdu,
                int use_udp, int use_tscf, uint64_t stream_id,
                uint8_t lin_bus_id, uint8_t cf_seq_num, uint32_t udp_seq_num);
