/** Normally we are using stdint. Howeer, this header is not available when building for e.g. Linxu kernel space, and also can not be added due to cnflicting declaration with intt types used in the kernel.
 * This header will typedef neesare stdtint types to the Linux Kernel types IF compiled in kernel space and just include stdtint otherweise.
 * That way Open1722 code is written in a portable way and can be used in both user and kernel space.
 */
#pragma once

#ifdef LINUX_KERNEL1722
#include <linux/types.h>
#else
#include <stdint.h>
#endif

