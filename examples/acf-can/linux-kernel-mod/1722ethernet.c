
#include "1722ethernet.h"

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/timekeeping.h>

#include "acfcandev.h"

int send_canfd_frame(struct net_device *can_dev, struct canfd_frame *cfd)
{
    struct acfcan_cfg *cfg = get_acfcan_cfg(can_dev);
    if (cfg->netdev == NULL)
    {
        printk(KERN_INFO "No ethernet device set for ACF-CAN device %s\n", can_dev->name);
        return -1;
    }

    canid_t id = cfd->can_id;
    printk(KERN_INFO "Sending CAN FD packet,  ID: ");
    if (id & CAN_EFF_FLAG)
    {
        printk(KERN_CONT "0x%08x", id & CAN_EFF_MASK);
    }
    else
    {
        printk(KERN_CONT "0x%03x", id & CAN_SFF_MASK);
    }
    printk(KERN_CONT " Packet data: ");
    for (int i = 0; i < cfd->len; i++)
    {
        printk(KERN_CONT "%02x ", cfd->data[i]);
    }
    printk(KERN_CONT "\n");

    __u8 *mac = cfg->dstmac;
    printk(KERN_INFO " dst Mac: ");
    for (int i = 0; i < 6; i++)
    {
        printk(KERN_CONT "%02x ", *(mac + i));
    }
    printk(KERN_CONT "\n");
    //Not sending now, need to replace with O1722 anyway
    return 0;
}

int send_can_frame(struct net_device *can_dev, struct can_frame *cf)
{
    struct acfcan_cfg *cfg = get_acfcan_cfg(can_dev);
    if (cfg->netdev == NULL)
    {
        printk(KERN_INFO "No ethernet device set for ACF-CAN device %s\n", can_dev->name);
        return -1;
    }
    uint16_t datalen = 0;
    canid_t id = cf->can_id;
    printk(KERN_INFO "Sending CAN  packet,  ID: ");
    if (id & CAN_EFF_FLAG)
    {
        printk(KERN_CONT "0x%08x", id & CAN_EFF_MASK);
        datalen += 4;
    }
    else
    {
        printk(KERN_CONT "0x%03x", id & CAN_SFF_MASK);
        datalen += 2;
    }
    printk(KERN_CONT " Packet data: ");
    for (int i = 0; i < cf->len; i++)
    {
        printk(KERN_CONT "%02x ", cf->data[i]);
    }
    printk(KERN_CONT "\n");

    ACFCANPdu_t pdu;
    // Init TSCF header
    Avtp_Tscf_Init(&pdu.tscf);
    Avtp_Tscf_SetVersion(&pdu.tscf, 0);
    Avtp_Tscf_SetSequenceNum(&pdu.tscf, cfg->sequenceNum++); //This can't be right. Increase?
    Avtp_Tscf_SetStreamId(&pdu.tscf, cfg->streamid);
    Avtp_Tscf_SetTv(&pdu.tscf, 1);
    // add a ns avtp-ish timestamp. Note: this will roll over often (as designed)
    Avtp_Tscf_SetAvtpTimestamp(&pdu.tscf, (uint32_t) (ktime_get_real_ns()&0xFFFFFFFF) ); //This can't be good. Better find a timestamp from somehwere

    // Init CAN ACF message
    Avtp_Can_Init(&pdu.can);
    Avtp_Can_SetCanBusId(&pdu.can, cfg->canbusId); 
    Avtp_Can_SetRtr(&pdu.can, cf->can_id & CAN_RTR_FLAG);
    Avtp_Can_SetEff(&pdu.can, cf->can_id & CAN_EFF_FLAG);
    

    //FD stuff
    /*
    Avtp_Can_SetBrs(&pdu, cf->flags & CANFD_BRS);
    Avtp_Can_SetFdf(&pdu.can, cf->flags & CANFD_FDF );
    Avtp_Can_SetEsi(&pdu.can, cf->flags & CANFD_ESI);
    */

    if ( cf->can_id & CAN_EFF_FLAG) {
        Avtp_Can_SetCanIdentifier(&pdu.can, cf->can_id & CAN_EFF_MASK );
    }
    else {
        Avtp_Can_SetCanIdentifier(&pdu.can, cf->can_id & CAN_SFF_MASK );
    }
    

    // Prepare ethernet
    struct sk_buff *skb;

    // Allocate a socket buffer
    skb = alloc_skb(ETH_HLEN + sizeof(ACFCANPdu_t) + cf->len, GFP_KERNEL);
    if (!skb)
    {
        printk(KERN_ERR "Failed to allocate skb\n");
        return -ENOMEM;
    }

    skb_reserve(skb, ETH_HLEN);                  // Reserve space for Ethernet header
    unsigned char *data = skb_put(skb, sizeof(pdu)); // Add payload data
    memcpy(data, (uint8_t *) &pdu, sizeof(pdu)); // Fill payload with avtp +  acf-can header
    data = skb_put(skb, cf->len); // Add payload data
    memcpy(data, (uint8_t *) cf->data, cf->len); // Fill payload with avtp +  acf-can header


    // Set up the Ethernet header

    struct ethhdr *eth = (struct ethhdr *)skb_push(skb, sizeof(struct ethhdr));

    memcpy(eth->h_dest, cfg->dstmac, ETH_ALEN);
    memcpy(eth->h_source, cfg->netdev->dev_addr, ETH_ALEN);
    eth->h_proto = htons(0x22F0);

    // Set the network device
    skb->dev = cfg->netdev;
    skb->protocol = eth->h_proto;
    skb->ip_summed = CHECKSUM_NONE;

    // Send the frame
    printk(KERN_INFO "Sending Ethernet frame\n");
    dev_queue_xmit(skb);

    return 0;
}
