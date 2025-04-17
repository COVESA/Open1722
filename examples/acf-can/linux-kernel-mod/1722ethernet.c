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

#include "1722ethernet.h"

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/can/core.h>
#include <linux/if_ether.h>
#include <linux/timekeeping.h>

void prepare_ntscf_header(Avtp_Ntscf_t *ntscf_header, struct acfcan_cfg *cfg)
{
    Avtp_Ntscf_Init(ntscf_header);
    Avtp_Ntscf_SetVersion(ntscf_header, 0);
    Avtp_Ntscf_SetSequenceNum(ntscf_header, cfg->sequenceNum++); // This can't be right. Increase?
    Avtp_Ntscf_SetStreamId(ntscf_header, cfg->tx_streamid);
}

void prepare_can_header(Avtp_Can_t *can_header, struct acfcan_cfg *cfg, const struct sk_buff *skb)
{
    struct canfd_frame *cfd = (struct canfd_frame *)skb->data; // this also works work can_frame struct, as the beginning is similar

    Avtp_Can_Init(can_header);
    Avtp_Can_SetCanBusId(can_header, cfg->canbusId);
    if (cfd->can_id & CAN_RTR_FLAG)
    {
        Avtp_Can_EnableRtr(can_header);
    }
    if (cfd->can_id & CAN_EFF_FLAG)
    {
        Avtp_Can_EnableEff(can_header);
    }

    if (cfd->can_id & CAN_EFF_FLAG)
    {
        Avtp_Can_SetCanIdentifier(can_header, cfd->can_id & CAN_EFF_MASK);
    }
    else
    {
        Avtp_Can_SetCanIdentifier(can_header, cfd->can_id & CAN_SFF_MASK);
    }

    if (can_is_canfd_skb(skb))
    {
        if (cfd->flags & CANFD_BRS)
        {
            Avtp_Can_EnableBrs(can_header);
        }
        if (cfd->flags & CANFD_FDF)
        {
            Avtp_Can_EnableFdf(can_header);
        }
        if (cfd->flags & CANFD_ESI)
        {
            Avtp_Can_GetEsi(can_header);
        }
    }

    // 1722 is a mess. Here we need to pad to quadlets
    uint8_t padSize = (AVTP_QUADLET_SIZE - ((AVTP_CAN_HEADER_LEN + cfd->len) % AVTP_QUADLET_SIZE)) % AVTP_QUADLET_SIZE;
    Avtp_Can_SetAcfMsgLength(can_header, (AVTP_CAN_HEADER_LEN + cfd->len + padSize) / AVTP_QUADLET_SIZE);
    Avtp_Can_SetPad(can_header, padSize);

    pr_debug("Prepared AVTP ACFCAN msg for can id 0x%08x, len %i\n", Avtp_Can_GetCanIdentifier(can_header), cfd->len);
    /*
    printk(KERN_INFO "Prepared CAN  packet for send,  ID: 0x%04x ", Avtp_Can_GetCanIdentifier(can_header));
    printk(KERN_CONT " frame data: ");
    for (int i = 0; i < cfd->len; i++)
    {
        printk(KERN_CONT "%02x ", cfd->data[i]);
    }
    printk(KERN_CONT "\n");
    */
}

void calculate_and_set_ntscf_size(ACFCANPdu_t *pdu)
{
    // 1722 is a mess. Bytes, lukicly we have padded quadlets in can already....
    uint16_t canandpadinbytes = Avtp_Can_GetAcfMsgLength(&pdu->can) * AVTP_QUADLET_SIZE;
    Avtp_Ntscf_SetNtscfDataLength(&pdu->ntscf, canandpadinbytes);
}

int forward_can_frame(struct net_device *can_dev, const struct sk_buff *skb_can)
{
    struct acfcan_cfg *cfg = get_acfcan_cfg(can_dev);
    if (cfg->eth_netdev == NULL)
    {
        printk(KERN_INFO "No ethernet device set for ACFCAN device %s\n", can_dev->name);
        return -1;
    }

    ACFCANPdu_t pdu;
    // Init TSCF header
    prepare_ntscf_header(&pdu.ntscf, cfg);
    prepare_can_header(&pdu.can, cfg, skb_can);
    calculate_and_set_ntscf_size(&pdu);

    // Prepare ethernet
    struct sk_buff *skb_eth;
    struct canfd_frame *cfd = (struct canfd_frame *)skb_can->data;

    // Allocate a socket buffer
    skb_eth = alloc_skb(ETH_HLEN + sizeof(ACFCANPdu_t) + cfd->len + Avtp_Can_GetPad(&pdu.can), GFP_KERNEL);
    pr_debug("ACFCAN: Allocating skb for ethernet frame: 0x%p\n", (void *)skb_eth->data);
    if (!skb_eth)
    {
        printk(KERN_ERR "Failed to allocate skb\n");
        return -ENOMEM;
    }

    skb_reserve(skb_eth, ETH_HLEN);                      // Reserve space for Ethernet header
    unsigned char *data = skb_put(skb_eth, sizeof(pdu)); // Add Headers
    memcpy(data, (uint8_t *)&pdu, sizeof(pdu));          // Fill payload with avtp +  acf-can header
    data = skb_put(skb_eth, cfd->len);                   // Add payload data
    memcpy(data, (uint8_t *)cfd->data, cfd->len);        // Fill payload with avtp +  acf-can header

    data = skb_put(skb_eth, Avtp_Can_GetPad(&pdu.can)); // Add payload data
    memset(data, 0, Avtp_Can_GetPad(&pdu.can));

    // Set up the Ethernet header
    struct ethhdr *eth = (struct ethhdr *)skb_push(skb_eth, sizeof(struct ethhdr));

    memcpy(eth->h_dest, cfg->dstmac, ETH_ALEN);
    memcpy(eth->h_source, cfg->eth_netdev->dev_addr, ETH_ALEN);
    eth->h_proto = htons(0x22F0);

    // Set the network device
    skb_eth->dev = cfg->eth_netdev;
    skb_eth->protocol = eth->h_proto;
    skb_eth->ip_summed = CHECKSUM_NONE;

    // Send the frame
    pr_debug("ACFCAN sending ethernet frame\n");
    int ret = dev_queue_xmit(skb_eth);
    if (ret != NET_XMIT_SUCCESS)
    {
        printk(KERN_ERR "Failed to send ethernet frame: %d\n", ret);
        kfree_skb(skb_eth);
        return -1;
    }

    return 0;
}

extern struct list_head acfcaninterface_list;

int ieee1722_packet_handdler(struct sk_buff *skb, struct net_device *dev,
                             struct packet_type *pt, struct net_device *orig_dev)
{

    struct ethhdr *eth = eth_hdr(skb);
    if (ntohs(eth->h_proto) != IEEE1722_PROTO)
    {
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    // Ignore packets not destined for us
    if (skb->pkt_type != PACKET_HOST && skb->pkt_type != PACKET_BROADCAST)
    {
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    pr_debug("ETH Received 1722 packet: src=%pM, dst=%pM, proto=0x%04x, type %i, buf is %p with %i refs\n",
             eth->h_source, eth->h_dest, ntohs(eth->h_proto), skb->pkt_type, (void *)skb->data, refcount_read(&skb->users));

    /*
    printk(KERN_CONT "Data: ");
    for (int i = 0; i < skb->len; i++)
    {
        printk(KERN_CONT "%02x ", skb->data[i]);
    }
    printk(KERN_CONT "\n");
    */

    // Check if this is an ACF-CAN packet
    if (skb->len < sizeof(Avtp_Ntscf_t) + sizeof(Avtp_Can_t))
    {
        printk(KERN_INFO "ACFCAN short packet, %u > %li\n", skb->len, sizeof(Avtp_Ntscf_t) + sizeof(Avtp_Can_t));
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    Avtp_CommonHeader_t *common = (Avtp_CommonHeader_t *)skb->data;
    if (Avtp_CommonHeader_GetSubtype(common) != AVTP_SUBTYPE_NTSCF)
    {
        printk(KERN_INFO "ACFCAN: Drop non NTSCF-type %i\n", Avtp_CommonHeader_GetSubtype(common));
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    Avtp_Ntscf_t *ntscf = (Avtp_Ntscf_t *)skb->data;
    Avtp_Can_t *can = (Avtp_Can_t *)(skb->data + sizeof(Avtp_Ntscf_t));

    // This is bytes, not quadlets
    uint16_t msg_length = Avtp_Ntscf_GetNtscfDataLength(ntscf);

    // seq_num = Avtp_Ntscf_GetSequenceNum((Avtp_Ntscf_t*)cf_pdu);
    if (msg_length > skb->len - sizeof(Avtp_Ntscf_t))
    {
        printk(KERN_INFO "ACFCAN: Drop short packet. NTSCF length %i, packet bytes: %li\n", msg_length, skb->len - sizeof(Avtp_Ntscf_t));
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    uint64_t stream_id = Avtp_Ntscf_GetStreamId(ntscf);
    uint8_t busid = Avtp_Can_GetCanBusId(can);

    pr_debug("ACFCAN: Received valid ACFCAN packet, stream_id=%016llx, busid=%i , msg_length=%i on %s\n", stream_id, busid, msg_length, dev->name);

    // Iterate over all active devices
    struct list_head *pos = NULL;
    struct acfcan_cfg *cfg = NULL;
    struct net_device *can_dev = NULL;
    list_for_each(pos, &acfcaninterface_list)
    {
        cfg = list_entry(pos, struct acfcan_cfg, list);
        if (cfg->rx_streamid == stream_id && cfg->canbusId == busid && strcmp(cfg->ethif, dev->name) == 0)
        {
            pr_debug("ACFCAN Found match, if=%s, stream=%016llx, busid %i\n", cfg->ethif, cfg->rx_streamid, cfg->canbusId);
            can_dev = cfg->can_netdev;
            break; // Only first match
        }
    }

    if (can_dev == NULL)
    {
        printk(KERN_WARNING "No receiving ACFCAN for stream=%016llx, busid %i\n", stream_id, busid);
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    uint8_t is_fd = Avtp_Can_GetFdf(can);
    struct sk_buff *can_skb;
    struct can_frame *cf;
    struct canfd_frame *cfd;

    int err;

    // Allocate a CAN skb
    if (is_fd)
    {
        pr_debug("ACFCAN: Allocating CAN FD skb\n");
        can_skb = alloc_canfd_skb(can_dev, &cfd);
        cf = (struct can_frame *)cfd; // This is a bit of a hack, but the beginning of the struct is the same
    }
    else
    {
        pr_debug("ACFCAN: Allocating CAN skb\n");
        can_skb = alloc_can_skb(can_dev, &cf);
    }
    if (!can_skb)
    {
        printk(KERN_ERR "Failed to allocate CAN skb\n");
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    cf->can_id = Avtp_Can_GetCanIdentifier(can);
    if (Avtp_Can_GetEff(can))
    {
        cf->can_id |= CAN_EFF_FLAG;
    }
    if (Avtp_Can_GetRtr(can))
    {
        cf->can_id |= CAN_RTR_FLAG;
    }

    if (is_fd)
    {
        cfd->flags = 0;
        if (Avtp_Can_GetBrs(can))
        {
            cfd->flags |= CANFD_BRS;
        }
        if (Avtp_Can_GetFdf(can))
        {
            cfd->flags |= CANFD_FDF;
        }
        if (Avtp_Can_GetEsi(can))
        {
            cfd->flags |= CANFD_ESI;
        }
        cfd->len = msg_length - AVTP_CAN_HEADER_LEN - Avtp_Can_GetPad(can);
    }
    else
    {
        cf->len = msg_length - AVTP_CAN_HEADER_LEN - Avtp_Can_GetPad(can);
    }

    if (is_fd && cfd->len > CANFD_MAX_DLEN)
    {
        printk(KERN_ERR "DLC too large for CAN FD\n");
        kfree_skb(skb);
        return NET_RX_DROP;
    }
    else if (!is_fd && cf->len > CAN_MAX_DLEN)
    {
        printk(KERN_ERR "DLC too large for CAN\n");
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    if (is_fd)
    {
        memcpy(cfd->data, skb->data + sizeof(Avtp_Ntscf_t) + sizeof(Avtp_Can_t), cfd->len);
    }
    else
    {
        memcpy(cf->data, skb->data + sizeof(Avtp_Ntscf_t) + sizeof(Avtp_Can_t), cf->len);
    }

    can_skb->cb[SKB_CB_LOCATION] |= SKB_CB_MINE; // Mark the skb as our own
    // Send the CAN skb, disable loop (otherwise the module would receive and forward
    // it's own frame)
    // TODO: Do we need to free can_skb?
    err = can_send(can_skb, 1);
    if (err)
    {
        printk(KERN_ERR "Failed to send CAN skb: %d\n", err);
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    kfree_skb(skb);
    return NET_RX_SUCCESS;
}
