#include <linux/can.h>
#include <linux/can/dev.h>
#include <linux/can/skb.h>



#include "avtp/acf/Tscf.h"
#include "avtp/acf/Can.h"


#define CAN_PAYLOAD_LEN 64
typedef struct {
    // IEEE 1722 TSCF header
    Avtp_Tscf_t tscf;
    // IEEE 1722 ACF message #1
    Avtp_Can_t can;
} ACFCANPdu_t;


int send_canfd_frame(struct net_device *can_dev, struct canfd_frame *cfd);
int send_can_frame(struct net_device *can_dev, struct can_frame *cf);
