/* Virtual IEEE 1722 acf-can CAN interface
 *
 * Copyright (c) 2024 COVESA Open1722
 * All rights reserved.
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
 * Alternatively, provided that this notice is retained in full, this
 * software may be distributed under the terms of the GNU General
 * Public License ("GPL") version 2, in which case the provisions of the
 * GPL apply INSTEAD OF those given above.
 *
 * The provided data structures and external interfaces from this code
 * are not restricted to be used by modules with a GPL compatible license.
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
 * SPDX-License-Identifier: BSD-3-Clause or GPL-2.0-only
 */

#include <linux/can.h>
#include <linux/can/dev.h>
#include <linux/can/skb.h>

#include "acfcandev.h"

#include "avtp/acf/Ntscf.h"
#include "avtp/acf/Can.h"
#include "avtp/CommonHeader.h"

#define CAN_PAYLOAD_LEN 64
typedef struct
{
    // IEEE 1722 NTSCF header
    Avtp_Ntscf_t ntscf;
    // IEEE 1722 ACF message #1
    Avtp_Can_t can;
} __attribute__((packed)) ACFCANPdu_t;

void prepare_ntscf_header(Avtp_Ntscf_t *ntscf_header, struct acfcan_cfg *cfg);
void prepare_can_header(Avtp_Can_t *can_header, struct acfcan_cfg *cfg, const struct sk_buff *skb);
void calculate_and_set_ntscf_size(ACFCANPdu_t *pdu);

int forward_can_frame(struct net_device *can_dev, const struct sk_buff *skb);

int ieee1722_packet_handdler(struct sk_buff *skb, struct net_device *dev,
                             struct packet_type *pt, struct net_device *orig_dev);
