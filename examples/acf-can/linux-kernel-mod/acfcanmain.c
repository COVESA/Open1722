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

#include <linux/init.h>
#include <linux/uaccess.h>

#include <linux/if_arp.h>

#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/can.h>
#include <linux/can/can-ml.h>
#include <linux/can/dev.h>
#include <linux/list.h>

#include <linux/can/skb.h>
#include <net/rtnetlink.h>
#include <linux/sysfs.h>

#include "1722ethernet.h"
#include "acfcandev.h"
#include "acfcandevsysfs.h"

#include "acfcanmodulemetadata.h"

char *version = "2016";

static struct packet_type ieee1722_packet_type;

LIST_HEAD(acfcaninterface_list);

static void acfcan_rx(struct sk_buff *skb, struct net_device *dev)
{
	struct net_device_stats *stats = &dev->stats;
	printk(KERN_INFO "ACF-CAN RX\n");
	stats->rx_packets++;
	stats->rx_bytes += can_skb_get_data_len(skb);

	skb->pkt_type = PACKET_HOST;
	skb->dev = dev;
	skb->ip_summed = CHECKSUM_UNNECESSARY;

	netif_rx(skb);
}

static netdev_tx_t acfcan_tx(struct sk_buff *skb, struct net_device *dev)
{
	struct net_device_stats *stats = &dev->stats;
	unsigned int len;
	int loop;
	bool echo = false;

	if (can_dropped_invalid_skb(dev, skb))
		return NETDEV_TX_OK;

	len = can_skb_get_data_len(skb);
	stats->tx_packets++;
	stats->tx_bytes += len;

	/* set flag whether this packet has to be looped back */
	loop = skb->pkt_type == PACKET_LOOPBACK;

	// This means we generated the frame ourself so we should NOT
	// forward it to the TX stream
	uint8_t mine = skb->cb[SKB_CB_LOCATION] & SKB_CB_MINE;

	skb_tx_timestamp(skb);

	if (!mine)
	{
		// Forward the frame to the TX stream
		forward_can_frame(dev, skb);
	}

	if (!echo)
	{
		/* no echo handling available inside this driver */
		if (loop)
		{
			/* only count the packets here, because the
			 * CAN core already did the echo for us
			 */
			stats->rx_packets++;
			stats->rx_bytes += len;
		}
		consume_skb(skb);
		return NETDEV_TX_OK;
	}

	/* perform standard echo handling for CAN network interfaces */
	if (loop)
	{
		skb = can_create_echo_skb(skb);
		if (!skb)
			return NETDEV_TX_OK;

		/* receive with packet counting */
		acfcan_rx(skb, dev);
	}
	else
	{
		/* no looped packets => no counting */
		consume_skb(skb);
	}
	return NETDEV_TX_OK;
}

static int acfcan_change_mtu(struct net_device *dev, int new_mtu)
{
	/* Do not allow changing the MTU while running */
	if (dev->flags & IFF_UP)
		return -EBUSY;

	if (new_mtu != CAN_MTU && new_mtu != CANFD_MTU &&
		!can_is_canxl_dev_mtu(new_mtu))
		return -EINVAL;

	WRITE_ONCE(dev->mtu, new_mtu);
	return 0;
}

static int acfcan_up(struct net_device *dev)
{
	struct acfcan_cfg *cfg = get_acfcan_cfg(dev);

	// chek we have an a valid ethernet device
	struct net_device *ethif;

	ethif = netdev_get_by_name(&init_net, cfg->ethif, &cfg->tracker, GFP_KERNEL);

	if (!ethif)
	{
		printk(KERN_WARNING "ACFCAN Can not use interface %s for %s\n", cfg->ethif, dev->name);
		return -EINVAL;
	}

	cfg->eth_netdev = ethif;

	list_add(&cfg->list, &acfcaninterface_list);

	printk(KERN_INFO "ACFCAN interface %s on %s up.  TX-streamid 0x%llX, RX-streamid 0x%0llX, bus-id %i.\n", dev->name, cfg->ethif, cfg->tx_streamid, cfg->rx_streamid, cfg->canbusId);
	return 0;
}

static int acfcan_down(struct net_device *dev)
{
	struct acfcan_cfg *cfg = get_acfcan_cfg(dev);
	if (cfg->eth_netdev)
	{
		netdev_put(cfg->eth_netdev, &cfg->tracker);
	}
	list_del(&cfg->list);
	printk(KERN_INFO "ACFCAN interface %s down\n", dev->name);
	return 0;
}

static const struct net_device_ops acfcan_netdev_ops = {
	.ndo_start_xmit = acfcan_tx,
	.ndo_change_mtu = acfcan_change_mtu,
	.ndo_open = acfcan_up,
	.ndo_stop = acfcan_down,
};

static const struct ethtool_ops acfcan_ethtool_ops = {
	.get_ts_info = ethtool_op_get_ts_info,
};

// The default stuff. Newlink can do more
static void acfcan_setup(struct net_device *dev)
{
	bool echo = false;
	dev->type = ARPHRD_CAN;
	dev->mtu = CANFD_MTU;
	dev->hard_header_len = 0;
	dev->addr_len = 0;
	dev->tx_queue_len = 0;
	dev->flags = IFF_NOARP;
	can_set_ml_priv(dev, netdev_priv(dev));

	void *canpriv = can_get_ml_priv(dev);
	pr_debug("Setting up new acfcan device %s, priv is at %p \n", dev->name, canpriv);

	/* set flags according to driver capabilities */
	if (echo)
		dev->flags |= IFF_ECHO;

	dev->netdev_ops = &acfcan_netdev_ops;
	dev->ethtool_ops = &acfcan_ethtool_ops;
	dev->needs_free_netdev = true;

	struct acfcan_cfg *cfg = get_acfcan_cfg(dev);
	cfg->rx_streamid = 0xbbbb;
	cfg->tx_streamid = 0xaaaa;
	cfg->dstmac[0] = 0xff;
	cfg->dstmac[1] = 0xff;
	cfg->dstmac[2] = 0xff;
	cfg->dstmac[3] = 0xff;
	cfg->dstmac[4] = 0xff;
	cfg->dstmac[5] = 0xff;
	cfg->eth_netdev = NULL;
	cfg->can_netdev = dev;
	cfg->ethif[0] = '\0'; // this is a string so setting first byte to 0 is fine
	cfg->sequenceNum = 0;
	cfg->canbusId = 0;
	cfg->flags = TX_ENABLE | RX_ENABLE; // todo: Make configurable
}

// is this deleting or downing the interfae?
static void acfcan_remove(struct net_device *dev, struct list_head *head)
{
	// Remove the custom sysfs attribute
	device_remove_file(&dev->dev, &dev_attr_dstmac);
	struct acfcan_cfg *cfg = get_acfcan_cfg(dev);
	if (cfg->eth_netdev)
	{
		netdev_put(cfg->eth_netdev, &cfg->tracker);
	}

	unregister_netdevice(dev);

	printk(KERN_INFO "ACFCAN interface %s unregistered\n", dev->name);
}

static int acfcan_newlink(struct net *net, struct net_device *dev,
						  struct nlattr *tb[], struct nlattr *data[],
						  struct netlink_ext_ack *extack)
{
	int err = register_netdevice(dev);

	if (err)
	{
		printk(KERN_ERR "Failed to register acfcan netdevice %s\n", dev->name);
		return err;
	}

	pr_debug("Creating group for device %s\n", dev->name);
	int ret = sysfs_create_group(&dev->dev.kobj, &dev_attr_group);
	if (ret)
	{
		pr_err("Failed to create sysfs group for net_device\n");
	}

	printk(KERN_INFO "Registered new ACFCAN device %s\n", dev->name);

	return 0;
}

//	.dellink = acfcan_remove, ?
static struct rtnl_link_ops acfcan_link_ops __read_mostly = {
	.kind = DRV_NAME,
	.priv_size = sizeof(struct can_ml_priv) + sizeof(struct acfcan_cfg),
	.setup = acfcan_setup,
	.newlink = acfcan_newlink,
	.dellink = acfcan_remove,
};

static int __init init_acfcan(void)
{
	if (strcmp(version, "2016") == 0)
	{
		printk(KERN_INFO "ACFCAN version: %s\n", version);
	}
	else
	{
		printk(KERN_ERR "ACFCAN unsupported 1722 version %s\n", version);
		return -1;
	}

	// We want all the 1722 packets. <
	ieee1722_packet_type.type = htons(IEEE1722_PROTO);
	ieee1722_packet_type.func = ieee1722_packet_handdler;
	ieee1722_packet_type.dev = NULL;
	dev_add_pack(&ieee1722_packet_type);

	return rtnl_link_register(&acfcan_link_ops);
}

static void __exit cleanup_acfcan(void)
{
	pr_info("Unloading ACFCAN\n");
	dev_remove_pack(&ieee1722_packet_type);
	rtnl_link_unregister(&acfcan_link_ops);
}

module_init(init_acfcan);
module_exit(cleanup_acfcan);

module_param(version, charp, 0);
MODULE_PARM_DESC(version, "IEEE-1722 version");
