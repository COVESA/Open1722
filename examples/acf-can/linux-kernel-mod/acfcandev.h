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


#pragma once

#include <linux/types.h>
#include <linux/can/can-ml.h>
#include <net/net_trackers.h>
#include <linux/list.h>

#define IEEE1722_PROTO 0x22f0

#define TX_ENABLE (1 << 7)
#define RX_ENABLE (1 << 6)

// this is more guesswork. We need some space and it seems
// raw can is using one int.... Not sure what would happen with
// ISO-TP and such things....
#define SKB_CB_LOCATION 4
#define SKB_CB_MINE (1 << 7)

/* Private per-device configuration */
struct acfcan_cfg
{
    struct list_head list; // we need a list so we can map received ethernet packets
    __u8 dstmac[6];        // send acf-can frames to this mac
    __u64 rx_streamid;     // listen to this acf-can stream-id
    __u64 tx_streamid;     // send acf-can frames with this stream-id
    __u8 flags;
    __u8 sequenceNum;
    __u8 canbusId;
    char ethif[IFNAMSIZ];
    struct net_device *eth_netdev; // this is the eth if used for sending and receiving
    struct net_device *can_netdev; // this is the (virtual) can if
    netdevice_tracker tracker;
};

// get the acfcan_cfg struct from the device
#define get_acfcan_cfg(dev) ((struct acfcan_cfg *)((char *)(can_get_ml_priv(dev)) + sizeof(struct can_ml_priv)))
