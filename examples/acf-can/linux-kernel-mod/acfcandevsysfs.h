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

#include <linux/sysfs.h>

#define NOCHANGE_IF_UP(what) ({                                                                       \
	if (netif_running(net_dev))                                                                       \
	{                                                                                                 \
		printk(KERN_WARNING "ACFCAN: Cannot change %s while device %s is up\n", what, net_dev->name); \
		return -EBUSY;                                                                                \
	}                                                                                                 \
})

static ssize_t dstmac_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	if (count == 1 && *buf == '\n')
	{
		return 1;
	}
	struct net_device *net_dev = to_net_dev(dev);

	NOCHANGE_IF_UP("destination MAC");
	struct acfcan_cfg *cfg = get_acfcan_cfg(net_dev);

	// Handle the input value here
	__u8 newmac[6] = {0, 1, 2, 3, 4, 5};
	int rc = sscanf(buf, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", &newmac[0], &newmac[1], &newmac[2], &newmac[3], &newmac[4], &newmac[5]);
	if (rc != 6)
	{
		printk(KERN_WARNING "ACFCAN Can not set destination MAC for %s to %s\n", net_dev->name, buf);
		return -EINVAL;
	}
	memcpy(cfg->dstmac, newmac, 6);
	pr_debug("ACFCAN: Setting destination MAC for %s to %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx \n", net_dev->name, newmac[0], newmac[1], newmac[2], newmac[3], newmac[4], newmac[5]);
	return 17;
}

static ssize_t dstmac_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	pr_debug("ACFCAN: Reading destination MAC\n");
	struct net_device *net_dev = to_net_dev(dev);
	struct acfcan_cfg *cfg = get_acfcan_cfg(net_dev);

	return sprintf(buf, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", cfg->dstmac[0], cfg->dstmac[1], cfg->dstmac[2], cfg->dstmac[3], cfg->dstmac[4], cfg->dstmac[5]);
}

// Only store the interface name. we will check if it is valid later when the interface is opened/upped
static ssize_t ethif_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	if (count == 1 && *buf == '\n')
	{
		return 1;
	}

	struct net_device *net_dev = to_net_dev(dev);

	NOCHANGE_IF_UP("ethernet interface");

	struct acfcan_cfg *cfg = get_acfcan_cfg(net_dev);

	if (count >= (IFNAMSIZ - 1))
	{
		printk(KERN_WARNING "ACFCAN: Interface name too long\n");
		return -EINVAL;
	}

	memcpy(cfg->ethif, buf, count);
	cfg->ethif[count] = '\0';

	pr_debug("ACFCAN Storing interface %s for %s\n", buf, net_dev->name);
	return count;
}

static ssize_t ethif_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct net_device *net_dev = to_net_dev(dev);
	struct acfcan_cfg *cfg = get_acfcan_cfg(net_dev);

	if (cfg->eth_netdev)
	{
		return sprintf(buf, "%s", cfg->eth_netdev->name);
	}
	else
	{
		buf[0] = '\0';
		return 0;
	}
}

static ssize_t tx_streamid_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	if (count == 1 && *buf == '\n')
	{
		return 1;
	}

	struct net_device *net_dev = to_net_dev(dev);

	NOCHANGE_IF_UP("tx stream id");

	struct acfcan_cfg *cfg = get_acfcan_cfg(net_dev);

	__u64 tx_streamid;
	int rc = sscanf(buf, "%llx", &tx_streamid);
	if (!rc)
	{
		printk(KERN_WARNING "ACFCAN: Invalid stream id\n");
		return -EINVAL;
	}

	cfg->tx_streamid = tx_streamid;

	pr_debug("ACFCAN TX streamid 0x%016llx for %s\n", tx_streamid, net_dev->name);
	return count;
}

static ssize_t rx_streamid_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	if (count == 1 && *buf == '\n')
	{
		return 1;
	}

	struct net_device *net_dev = to_net_dev(dev);

	NOCHANGE_IF_UP("rx stream id");

	struct acfcan_cfg *cfg = get_acfcan_cfg(net_dev);

	__u64 rx_streamid;
	int rc = sscanf(buf, "%llx", &rx_streamid);
	if (!rc)
	{
		printk(KERN_WARNING "ACFCAN: Invalid stream id\n");
		return -EINVAL;
	}

	cfg->rx_streamid = rx_streamid;

	pr_debug("ACFCAN RX streamid 0x%016llx for %s\n", rx_streamid, net_dev->name);
	return count;
}

static ssize_t busid_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	if (count == 1 && *buf == '\n')
	{
		return 1;
	}

	struct net_device *net_dev = to_net_dev(dev);

	NOCHANGE_IF_UP("bus id");

	struct acfcan_cfg *cfg = get_acfcan_cfg(net_dev);

	__u8 busid;
	int rc = sscanf(buf, "%hhu", &busid);
	if (!rc)
	{
		printk(KERN_WARNING "ACFCAN: Invalid bus id\n");
		return -EINVAL;
	}

	cfg->canbusId = busid;

	pr_debug("ACFCAN setting busid to %u for %s\n", busid, net_dev->name);
	return count;
}

static ssize_t rx_streamid_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct net_device *net_dev = to_net_dev(dev);
	struct acfcan_cfg *cfg = get_acfcan_cfg(net_dev);

	return sprintf(buf, "0x%016llx", cfg->rx_streamid);
}

static ssize_t tx_streamid_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct net_device *net_dev = to_net_dev(dev);
	struct acfcan_cfg *cfg = get_acfcan_cfg(net_dev);

	return sprintf(buf, "0x%016llx", cfg->tx_streamid);
}

static ssize_t busid_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct net_device *net_dev = to_net_dev(dev);
	struct acfcan_cfg *cfg = get_acfcan_cfg(net_dev);

	return sprintf(buf, "%i", cfg->canbusId);
}

static DEVICE_ATTR_RW(dstmac);
static DEVICE_ATTR_RW(ethif);
static DEVICE_ATTR_RW(rx_streamid);
static DEVICE_ATTR_RW(tx_streamid);
static DEVICE_ATTR_RW(busid);

static struct attribute *dev_attrs[] = {
	&dev_attr_dstmac.attr,
	&dev_attr_ethif.attr,
	&dev_attr_tx_streamid.attr,
	&dev_attr_rx_streamid.attr,
	&dev_attr_busid.attr,
	NULL, /* NULL-terminated list */
};

static struct attribute_group dev_attr_group = {
	.name = "acfcan",
	.attrs = dev_attrs,
};
