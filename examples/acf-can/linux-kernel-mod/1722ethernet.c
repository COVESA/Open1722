
#include "1722ethernet.h"

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/timekeeping.h>


void prepare_ntscf_header(Avtp_Ntscf_t *ntscf_header, struct acfcan_cfg *cfg) {
    Avtp_Ntscf_Init(ntscf_header);
    Avtp_Ntscf_SetVersion(ntscf_header, 0);
    Avtp_Ntscf_SetSequenceNum(ntscf_header, cfg->sequenceNum++); //This can't be right. Increase?
    Avtp_Ntscf_SetStreamId(ntscf_header, cfg->streamid);
}

void prepare_can_header(Avtp_Can_t *can_header, struct acfcan_cfg *cfg, const struct sk_buff *skb) {
    struct canfd_frame *cfd = (struct canfd_frame *)skb->data; //this also works work can_frame struct, as the beginning is similar

    Avtp_Can_Init(can_header);
    Avtp_Can_SetCanBusId(can_header, cfg->canbusId); 
    if (cfd->can_id & CAN_RTR_FLAG) {
        Avtp_Can_SetRtr(can_header, 1);
    } 
    if (cfd->can_id & CAN_EFF_FLAG) {
        Avtp_Can_SetEff(can_header, 1);
    }

    if ( cfd->can_id & CAN_EFF_FLAG) {
        Avtp_Can_SetCanIdentifier(can_header, cfd->can_id & CAN_EFF_MASK );
    }
    else {
        Avtp_Can_SetCanIdentifier(can_header, cfd->can_id & CAN_SFF_MASK );
    }

    if ( can_is_canfd_skb(skb) ) {
        if ( cfd->flags & CANFD_BRS ) {
            Avtp_Can_SetBrs(can_header, 1);
        }
        if ( cfd->flags & CANFD_FDF ) {
            Avtp_Can_SetFdf(can_header, 1);
        }
        if ( cfd->flags & CANFD_ESI ) {
            Avtp_Can_SetEsi(can_header, 1);
        }
    } 

    //1722 is a mess. Here we need to pad to quadlets
    uint8_t padSize = ( AVTP_QUADLET_SIZE - ( (AVTP_CAN_HEADER_LEN+cfd->len) % AVTP_QUADLET_SIZE) )  % AVTP_QUADLET_SIZE;
    Avtp_Can_SetAcfMsgLength(can_header, (AVTP_CAN_HEADER_LEN+cfd->len+padSize)/AVTP_QUADLET_SIZE);
    Avtp_Can_SetPad(can_header, padSize);
}

void calculate_and_set_ntscf_size(ACFCANPdu_t *pdu) {
    //1722 is a mess. Bytes, lukicly we have padded quadlets in can already....
    uint16_t canandpadinbytes = Avtp_Can_GetAcfMsgLength(&pdu->can)*AVTP_QUADLET_SIZE;
    Avtp_Ntscf_SetNtscfDataLength(&pdu->ntscf, canandpadinbytes);
}

int send_canfd_frame(struct net_device *can_dev, const struct sk_buff *skb_can, struct canfd_frame *cfd)
{
    struct acfcan_cfg *cfg = get_acfcan_cfg(can_dev);
    if (cfg->netdev == NULL)
    {
        printk(KERN_INFO "No ethernet device set for ACF-CAN device %s\n", can_dev->name);
        return -1;
    }
    uint16_t datalen = 0;
    canid_t id = cfd->can_id;
    printk(KERN_INFO "Sending CAN FD packet,  ID: ");
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
    for (int i = 0; i < cfd->len; i++)
    {
        printk(KERN_CONT "%02x ", cfd->data[i]);
    }
    printk(KERN_CONT "\n");

    ACFCANPdu_t pdu;
    // Init TSCF header
    prepare_ntscf_header(&pdu.ntscf, cfg);
    prepare_can_header(&pdu.can, cfg, skb_can);      
    calculate_and_set_ntscf_size(&pdu);

    // Prepare ethernet
    struct sk_buff *skb;

    // Allocate a socket buffer
    skb = alloc_skb(ETH_HLEN + sizeof(ACFCANPdu_t) + cfd->len, GFP_KERNEL);
    if (!skb)
    {
        printk(KERN_ERR "Failed to allocate skb\n");
        return -ENOMEM;
    }

    skb_reserve(skb, ETH_HLEN);                  // Reserve space for Ethernet header
    unsigned char *data = skb_put(skb, sizeof(pdu)); // Add payload data
    memcpy(data, (uint8_t *) &pdu, sizeof(pdu)); // Fill payload with avtp +  acf-can header
    data = skb_put(skb, cfd->len); // Add payload data
    memcpy(data, (uint8_t *) cfd->data, cfd->len); // Fill payload with avtp +  acf-can header


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

    //Not sending now, need to replace with O1722 anyway
    return 0;
}

int send_can_frame(struct net_device *can_dev, const struct sk_buff *skb_can, struct can_frame *cf)
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
    prepare_ntscf_header(&pdu.ntscf, cfg);
    prepare_can_header(&pdu.can, cfg, skb_can);
    calculate_and_set_ntscf_size(&pdu);

/*
    //1722 is a mess 
    uint8_t padSize = ( AVTP_QUADLET_SIZE - ( (AVTP_CAN_HEADER_LEN+cf->len) % AVTP_QUADLET_SIZE) )  % AVTP_QUADLET_SIZE;
    Avtp_Ntscf_SetNtscfDataLength(&pdu.ntscf, (AVTP_CAN_HEADER_LEN+cf->len+padSize));

    //now then INSUDE Tscf we have ACF CAN, that does count in quadlets INCLUDING header
    //Also quadlets... so we need ANOTHER field to tell it the pad length
    Avtp_Can_SetAcfMsgLength(&pdu.can, (AVTP_CAN_HEADER_LEN+cf->len+padSize)/AVTP_QUADLET_SIZE);
    printk(KERN_INFO "ACF CAN length: %d\n", Avtp_Can_GetAcfMsgLength(&pdu.can));
    Avtp_Can_SetPad(&pdu.can, padSize);
*/
    
    // Prepare ethernet
    struct sk_buff *skb;

    // Allocate a socket buffer
    uint8_t padSize = Avtp_Can_GetPad(&pdu.can);
    uint16_t acfcansize=Avtp_Can_GetCanPayloadLength(&pdu.can)*AVTP_QUADLET_SIZE+padSize;
    skb = alloc_skb(ETH_HLEN + sizeof(ACFCANPdu_t) + acfcansize, GFP_KERNEL);
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
    
    //Todo: Clear pad?
    data = skb_put(skb, padSize); // Add payload data
    memset(data,0,padSize);



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
