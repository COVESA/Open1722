 /*
 * Copyright (c) 2024, COVESA
 * Copyright (c) 2019, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of Intel Corporation, COVESA nor the names of their
 *      contributors  may be used to endorse or promote products derived from
 *      this software without specific prior written permission.
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
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#elif defined(__ZEPHYR__)
#include <zephyr/net/socket.h>
#endif

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "common.h"

#ifdef __linux__
#define NSEC_PER_SEC		1000000000ULL
#define NSEC_PER_MSEC		1000000ULL

int calculate_avtp_time(uint32_t *avtp_time, uint32_t max_transit_time)
{
    int res;
    struct timespec tspec;
    uint64_t ptime;

    res = clock_gettime(CLOCK_REALTIME, &tspec);
    if (res < 0) {
        perror("Failed to get time");
        return -1;
    }

    ptime = (tspec.tv_sec * NSEC_PER_SEC) +
            (max_transit_time * NSEC_PER_MSEC) + tspec.tv_nsec;

    *avtp_time = ptime % (1ULL << 32);

    return 0;
}

int get_presentation_time(uint64_t avtp_time, struct timespec *tspec)
{
    int res;
    uint64_t ptime, now;

    res = clock_gettime(CLOCK_REALTIME, tspec);
    if (res < 0) {
        perror("Failed to get time from PHC");
        return -1;
    }

    now = (tspec->tv_sec * NSEC_PER_SEC) + tspec->tv_nsec;

    /* The avtp_timestamp within AAF packet is the lower part (32
     * less-significant bits) from presentation time calculated by the
     * talker.
     */
    ptime = (now & 0xFFFFFFFF00000000ULL) | avtp_time;

    /* If 'ptime' is less than the 'now', it means the higher part
     * from 'ptime' needs to be incremented by 1 in order to recover the
     * presentation time set by the talker.
     */
    if (ptime < now)
        ptime += (1ULL << 32);

    tspec->tv_sec = ptime / NSEC_PER_SEC;
    tspec->tv_nsec = ptime % NSEC_PER_SEC;

    return 0;
}

int arm_timer(int fd, struct timespec *tspec)
{
    int res;
    struct itimerspec timer_spec = { 0 };

    timer_spec.it_value.tv_sec = tspec->tv_sec;
    timer_spec.it_value.tv_nsec = tspec->tv_nsec;

    res = timerfd_settime(fd, TFD_TIMER_ABSTIME, &timer_spec, NULL);
    if (res < 0) {
        perror("Failed to set timer");
        return -1;
    }

    return 0;
}

int present_data(uint8_t *data, size_t len)
{
    ssize_t n;

    n = write(STDOUT_FILENO, data, len);
    if (n < 0 || n != len) {
        perror("Failed to write()");
        return -1;
    }

    return 0;
}
#endif

int setup_socket_address(int fd, const char *ifname, uint8_t macaddr[],
                int protocol, struct sockaddr_ll *sk_addr)
{
#ifdef __linux__
    int res;
    struct ifreq req;
    snprintf(req.ifr_name, sizeof(req.ifr_name), "%s", ifname);
    res = ioctl(fd, SIOCGIFINDEX, &req);
    if (res < 0) {
        perror("Failed to get interface index");
        return -1;
    }

    sk_addr->sll_family = AF_PACKET;
    sk_addr->sll_protocol = htons(protocol);
    sk_addr->sll_halen = ETH_ALEN;
    sk_addr->sll_ifindex = req.ifr_ifindex;
#elif defined(__ZEPHYR__)
    sk_addr->sll_family = AF_PACKET;
    sk_addr->sll_protocol = htons(protocol);
    sk_addr->sll_halen = ETH_ALEN;
    sk_addr->sll_ifindex = net_if_get_by_iface(net_if_get_default());
#endif
    memcpy(sk_addr->sll_addr, macaddr, ETH_ALEN);

    return 0;
}

int setup_udp_socket_address(struct in_addr *addr, uint32_t port,
                struct sockaddr_in *sk_addr) {

    sk_addr->sin_family = AF_INET;
    sk_addr->sin_addr = *addr;
    sk_addr->sin_port = htons(port);

    return 0;

}

int create_talker_socket_udp(int priority)
{
    int fd, res;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("Failed to open socket");
        return -1;
    }

    if (priority != -1) {
        res = setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &priority,
                            sizeof(priority));
        if (res < 0) {
            perror("Failed to set priority");
            goto err;
        }
    }

    return fd;

err:
    close(fd);
    return -1;
}

int create_talker_socket(int priority)
{
    int fd, res;

    fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_TSN));
    if (fd < 0) {
        perror("Failed to open socket");
        return -1;
    }

    if (priority != -1) {
        res = setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &priority,
                            sizeof(priority));
        if (res < 0) {
            perror("Failed to set priority");
            goto err;
        }
    }

    return fd;

err:
    close(fd);
    return -1;
}

int create_listener_socket_udp(uint32_t udp_port) {

    int fd, res;
    struct sockaddr_in sk_addr;

    //create a UDP socket
    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        perror("Failed to open socket");
        return -1;
    }

    // Initialize the socket
    memset((char *) &sk_addr, 0, sizeof(sk_addr));
    sk_addr.sin_family = AF_INET;
    sk_addr.sin_port = htons(udp_port);
    sk_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    res = bind(fd, (struct sockaddr *) &sk_addr, sizeof(sk_addr));
    if (res < 0) {
        perror("Couldn't bind() to port");
        goto err;
    }

    return fd;

err:
    close(fd);
    return -1;
}

int create_listener_socket(char *ifname, uint8_t* macaddr, int protocol)
{
    int fd, res;
    struct sockaddr_ll sk_addr;

    fd = socket(AF_PACKET, SOCK_DGRAM, htons(protocol));
    if (fd < 0) {
        perror("Failed to open socket");
        return -1;
    }

    res = setup_socket_address(fd, ifname, macaddr, protocol, &sk_addr);
    if (res < 0)
        goto err;

    res = bind(fd, (struct sockaddr *) &sk_addr, sizeof(sk_addr));
    if (res < 0) {
        perror("Couldn't bind() to interface");
        goto err;
    }

#ifdef __linux__
    struct packet_mreq mreq;
    mreq.mr_ifindex = sk_addr.sll_ifindex;
    mreq.mr_type = PACKET_MR_MULTICAST;
    mreq.mr_alen = ETH_ALEN;
    memcpy(&mreq.mr_address, macaddr, ETH_ALEN);

    res = setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                    &mreq, sizeof(struct packet_mreq));
    if (res < 0) {
        perror("Couldn't set PACKET_ADD_MEMBERSHIP");
        goto err;
    }
#endif

    return fd;

err:
    close(fd);
    return -1;
}


