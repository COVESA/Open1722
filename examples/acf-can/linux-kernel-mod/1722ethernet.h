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
