/* 
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <linux/module.h>


#define DRV_NAME "acfcan"

// Module metadata
MODULE_AUTHOR("Sebastian Schildt");
MODULE_DESCRIPTION("IEEE-1722 ACF-CAN bridge");
MODULE_LICENSE("BSD3");

MODULE_ALIAS_RTNL_LINK(DRV_NAME);