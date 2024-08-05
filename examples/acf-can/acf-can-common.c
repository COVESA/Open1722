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

#include <linux/if.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include "acf-can-common.h"

int setup_can_socket(const char* can_ifname, Avtp_CanVariant_t can_variant) {
    
    int can_socket, res;
    struct ifreq ifr;
    struct sockaddr_can can_addr;
    
    can_socket = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (can_socket < 0) return can_socket;

    strcpy(ifr.ifr_name, can_ifname);
    ioctl(can_socket, SIOCGIFINDEX, &ifr);

    memset(&can_addr, 0, sizeof(can_addr));
    can_addr.can_family = AF_CAN;
    can_addr.can_ifindex = ifr.ifr_ifindex;

    if (can_variant == AVTP_CAN_FD) {
        int enable_canfx = 1;
        setsockopt(can_socket, SOL_CAN_RAW, CAN_RAW_FD_FRAMES,
                    &enable_canfx, sizeof(enable_canfx));
    }

    res = bind(can_socket, (struct sockaddr *)&can_addr, sizeof(can_addr));
    if (res < 0) {
        close(can_socket);
        return res;
    }

    return can_socket;
}
