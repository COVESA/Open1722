/*
 * Copyright (c) 2017 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "avtp/Udp.h"
#include "avtp/acf/Tscf.h"
#include "avtp/acf/Ntscf.h"
#include "avtp/acf/Can.h"
#include "avtp/CommonHeader.h"

#ifndef __ZEPHYR__

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <linux/if.h>
#include <zephyr/net/net_stats.h>

#else

#include <zephyr/devicetree.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_pkt_sock_sample, LOG_LEVEL_DBG);

#include <zephyr/net/net_ip.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/ethernet.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_stats.h>

#include <zephyr/sys/printk.h>
#include <zephyr/device.h>
#include <zephyr/drivers/can.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/sys/byteorder.h>

#endif

#define BIND_PORT 4242
#define ETH_P_TSN	0x22F0		/* TSN (IEEE 1722) packet	*/
#define ETH_ALEN	6
#define MAX_PDU_SIZE                1500
#define CAN_PAYLOAD_MAX_SIZE        16*4
#define STREAM_ID                   0xAABBCCDDEEFF0001
#define CAN_TX_ID 1
#define CAN_RX_ID 1
#define CAN_TX_DLC 3U
#define CAN_RX_DLC 3U
#define SLEEP_TIME K_MSEC(5000)

#define TIME_MEASUREMENT true

static K_SEM_DEFINE(iface_up, 0, 1);

static uint8_t pdu[MAX_PDU_SIZE];
static int use_udp = 1;
const struct device *const can_dev = DEVICE_DT_GET(DT_NODELABEL(fdcan1)); /* for zephyr native_sim: can0 */
static struct can_frame tx_frame;
uint64_t t1_tick, t2_tick, t3_tick, t4_tick, t1, t2, t3 ,t4;

CAN_MSGQ_DEFINE(rx_msgq, 2);

static int init_can_dev()
{
    int ret;
    struct can_timing timing;

    if (!device_is_ready(can_dev)) {
    printf("CAN: Device %s not ready.\n", can_dev->name);
    return 0;
	}

	ret = can_start(can_dev);
	if (ret != 0) {
		printf("Error starting CAN controller [%d]", ret);
		return 0;
	}
	else {
		printf("Starting CAN controller [%d]\n", ret);
	}
    return ret;
}


static void iface_up_handler(struct net_mgmt_event_callback *cb,
			     uint32_t mgmt_event, struct net_if *iface)
{
	if (mgmt_event == NET_EVENT_IF_UP) {
		k_sem_give(&iface_up);
	}
}

static void wait_for_interface(void)
{
	struct net_if *iface = net_if_get_default();
	struct net_mgmt_event_callback iface_up_cb;

	if (net_if_is_up(iface)) {
		return;
	}

	net_mgmt_init_event_callback(&iface_up_cb, iface_up_handler,
				     NET_EVENT_IF_UP);
	net_mgmt_add_event_callback(&iface_up_cb);

	// Wait for the interface to come up.
	k_sem_take(&iface_up, K_FOREVER);

	net_mgmt_del_event_callback(&iface_up_cb);
}

static int is_valid_acf_packet(uint8_t* acf_pdu) {

    uint64_t val64;

    Avtp_AcfCommon_GetField((Avtp_AcfCommon_t*)acf_pdu, AVTP_ACF_FIELD_ACF_MSG_TYPE, &val64);
    if (val64 != AVTP_ACF_TYPE_CAN) {
        printf("ACF type mismatch: expected %u, got %"PRIu64"\n",
                AVTP_ACF_TYPE_CAN, val64);
        return 0;
    }

    return 1;
}

int main(void)
{
    uint8_t * cf_pdu, *acf_pdu;
    int res;
    uint64_t msg_length, proc_bytes = 0, msg_proc_bytes = 0;
    uint64_t can_frame_id, subtype, udp_seq_num;
    uint16_t payload_length, pdu_length;
    uint8_t *can_payload;
    uint64_t eff, cnt=0;
	int fd=0;
    struct sockaddr_ll dst = { 0 };
    struct sockaddr_in dst_udp = { 0 };
    struct in_addr ip_addr;
    Avtp_UDP_t *udp_pdu;


	//uint8_t dstmac[] = {0x8a, 0xeb, 0xa5, 0x05, 0x9d, 0xe1};    // S32G3  8a:eb:a5:05:9d:e1
	//uint8_t dstmac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}; // Broadcast

    // init CAN Dev
    res = init_can_dev();
    if (res < 0){
            return -1;
    }

    wait_for_interface();

	// Create RAW Socket to send
    if(use_udp){
        fd = socket(AF_INET, SOCK_DGRAM, 0);
    }
    else{
        fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_TSN));
    }
    if (fd < 0) {
        perror("Failed to open socket");
        return -1;
    }
    if(use_udp){
        res = inet_pton(AF_INET, CONFIG_NET_CONFIG_MY_IPV4_ADDR, &ip_addr);
        if (!res) {
            perror("Invalid IP address\n\n");
        }
        dst_udp.sin_family = AF_INET;
        dst_udp.sin_port = htons(17220);
        dst_udp.sin_addr = ip_addr;
        res = bind(fd, (const struct sockaddr *)&dst_udp,
            sizeof(struct sockaddr_in));
        if (res < 0) {
            printf("Failed to bind packet socket : %d", errno);
            return -errno;
        }
    }
    else{
        dst.sll_ifindex = net_if_get_by_iface(net_if_get_default());
        dst.sll_family = AF_PACKET;

        res = bind(fd, (const struct sockaddr *)&dst,
            sizeof(struct sockaddr_ll));
        if (res < 0) {
            printf("Failed to bind packet socket : %d", errno);
            return -errno;
        }
    }


    printf("Starting \n");

	// Sending loop
    for(;;) {
        cnt ++;
        msg_length= 0, proc_bytes = 0, msg_proc_bytes = 0;
#if TIME_MEASUREMENT == true
        t1_tick = k_cycle_get_64();
#endif
        res = recv(fd, pdu, MAX_PDU_SIZE, 0);
#if TIME_MEASUREMENT == true
        t2_tick = k_cycle_get_64();
#endif
        if (res < 0 || res > MAX_PDU_SIZE) {
                perror("Failed to receive data");
                return -1;
            }

        if (use_udp) {
            udp_pdu = (Avtp_UDP_t *) pdu;
            Avtp_UDP_GetField(udp_pdu, AVTP_UDP_FIELD_ENCAPSULATION_SEQ_NO, &udp_seq_num);
            cf_pdu = pdu + AVTP_UDP_HEADER_LEN;
            proc_bytes += AVTP_UDP_HEADER_LEN;
        }
        else {
            cf_pdu = pdu;
        }

        res = Avtp_CommonHeader_GetField((Avtp_CommonHeader_t*)cf_pdu, AVTP_COMMON_HEADER_FIELD_SUBTYPE, &subtype);
        if (res < 0) {
            printf("Failed to get subtype field: %d\n", res);
            return -1;
        }

        if (!((subtype == AVTP_SUBTYPE_NTSCF) ||
            (subtype == AVTP_SUBTYPE_TSCF))) {
            printf("Subtype mismatch: expected %u or %u, got %"PRIu64". Dropping packet\n",
                    AVTP_SUBTYPE_NTSCF, AVTP_SUBTYPE_TSCF, subtype);
            return -1;
        }

        if(subtype == AVTP_SUBTYPE_TSCF){
            proc_bytes += AVTP_TSCF_HEADER_LEN;
            res = Avtp_Tscf_GetField((Avtp_Tscf_t*)cf_pdu, AVTP_TSCF_FIELD_STREAM_DATA_LENGTH, (uint64_t *) &msg_length);
        }
        else{
            proc_bytes += AVTP_NTSCF_HEADER_LEN;
            res = Avtp_Ntscf_GetField((Avtp_Ntscf_t*)cf_pdu, AVTP_NTSCF_FIELD_NTSCF_DATA_LENGTH, (uint64_t *) &msg_length);
        }

        if (res < 0) {
            printf("Failed to get message length: %d\n", res);
            return -1;
        }

        while (msg_proc_bytes < msg_length) {

            acf_pdu = &pdu[proc_bytes + msg_proc_bytes];

            if (!is_valid_acf_packet(acf_pdu)) {
                printf("Error: Invalid ACF packet.\n");
                return -1;
            }

            res = Avtp_Can_GetField((Avtp_Can_t*)acf_pdu, AVTP_CAN_FIELD_CAN_IDENTIFIER,
                                &can_frame_id);
            if (res < 0) {
                printf("Error: Getting CAN frame ID\n");
                return -1;
            }

            can_payload = Avtp_Can_GetPayload((Avtp_Can_t*)acf_pdu, &payload_length, &pdu_length);
            msg_proc_bytes += pdu_length*4;

            res = Avtp_Can_GetField((Avtp_Can_t*)acf_pdu, AVTP_CAN_FIELD_EFF, &eff);
            if (res < 0) {
                printf("Failed to get eff field: %d\n", res);
                return -1;
            }

            if (can_frame_id > 0x7FF && !eff) {
                printf("Error: CAN ID is > 0x7FF but the EFF bit is not set.\n");
                return -1;
            }
            tx_frame.id = can_frame_id;
            tx_frame.dlc = payload_length;
            for (uint8_t i=0; i<payload_length; i++)
            {
                tx_frame.data[i]= can_payload[i];
            }
#if TIME_MEASUREMENT == true
            t3_tick = k_cycle_get_64();
#endif
           can_send(can_dev, &tx_frame, K_FOREVER, NULL, NULL);
#if TIME_MEASUREMENT == true
            t4_tick = k_cycle_get_64();
            // total
            t1 = k_cyc_to_ns_near64(t4_tick-t1_tick);
            // eth rx
            t2 = k_cyc_to_ns_near64(t2_tick-t1_tick);
            // 1772 listener
            t3 = k_cyc_to_ns_near64(t3_tick-t2_tick);
            // CAN tx
            t4 = k_cyc_to_ns_near64(t4_tick-t3_tick);
            printf("%llu\t time total %llu ns\teth rx %llu ns\t1722 %llu ns\tcan tx %llu ns\n", cnt, t1, t2, t3, t4);
#endif
        }
    }
    return 1;
}
