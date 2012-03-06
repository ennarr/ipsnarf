/* Packet handling thread routines
 * Written by Nigel Roberts <nigel.roberts@team.telstraclear.co.nz>
 */

#include "ipsnarf.h"

extern int pretend;

void *
snarf(void *myvoidint) {

      /* This is where the thread starts and then enters the packet
         handling loop. 
      */

  pcap_t *handle;                        /* Session handle */
  char errbuf[PCAP_ERRBUF_SIZE];         /* Error string */
  char filter_app[BUFSIZ];               /* Uncompiled filter */
  struct bpf_program filter;             /* The compiled filter */
  bpf_u_int32 net = 0;                   /* Our IP */

  char msg[BUFSIZ];

  struct interface *myint = (struct interface *) myvoidint;

  snprintf(msg, BUFSIZ, "%s thread starting...", myint->name);
  log(msg, LOG_INFO);
  
      /* open the pcap handle for listening. If to_ms is set to 0,
         this function seems to buffer for 20-30 seconds at a time (on
         FreeBSD 4.x anyway), which is pretty useless. Setting to_ms
         to 10 (ms) seems to fix the problem.  */
  
  if ((handle = pcap_open_live(myint->name, BUFSIZ, 0, 10, errbuf)) == NULL) {
    
    snprintf(msg, BUFSIZ, "Opening device %s failed, %s", myint->name, errbuf);
    log(msg, LOG_ERR);
    return(NULL);
    
  }

  if ((myint->network = libnet_open_link_interface(myint->name, errbuf)) == NULL) {

    libnet_error(LIBNET_ERR_FATAL, "libnet_open_link_interface: %s", errbuf);

  }

  
      /* Construct the filter */
  
  sprintf(filter_app, 
          "arp and not ether src host %x:%x:%x:%x:%x:%x",
          myint->macaddress[0],
          myint->macaddress[1],
          myint->macaddress[2],
          myint->macaddress[3],
          myint->macaddress[4],
          myint->macaddress[5]
          );

      /* Compile and apply the filter */ 
  
  if((pcap_compile(handle, &filter, filter_app, 0, net)) == -1) {
    snprintf(msg, BUFSIZ, "Error calling pcap_compile: %s", errbuf);
    log(msg, LOG_ERR);
    return(NULL);
  }
  
  if((pcap_setfilter(handle, &filter)) == -1) {
    snprintf(msg, BUFSIZ, "Error calling pcap_setfilter: %s", errbuf);
    log(msg, LOG_ERR);
    return(NULL);
  } 
  
  pcap_loop(handle, 0, &got_packet, (u_char *) myint);
  
  if (libnet_close_link_interface(myint->network) == -1) {
    libnet_error(LN_ERR_WARNING, 
                 "libnet_close_link_interface couldn't close the interace"
                 );
  }
  
  return NULL;

}

void
got_packet (u_char *args, const struct pcap_pkthdr *header, const u_char *pkt) {

      /* Packet handling routine, called each time a packet that has
         passed the filter arrives. This is where the good stuff
         happens. */

  const struct libnet_ethernet_hdr *ethernet;  /* The ethernet header */
  const struct libnet_arp_hdr *arp;          /* The ARP header */
  u_int spa, tpa, netspa, nettpa;
  u_short ar_op;
  u_char sha[6];
  char srcipstring[16];
  char dstipstring[16]; 
  char msg[BUFSIZ];
  char *tmp;
  time_t currenttime;
  struct iplist **checkip;
  struct iplist *ipptr;
  struct iplist newip;

  struct interface *myint = (struct interface *) args;

  ethernet = (struct libnet_ethernet_hdr*)(pkt);

      /* What's the time? */

  currenttime = time(0);

  arp = (struct libnet_arp_hdr*)(pkt + sizeof(struct libnet_ethernet_hdr));
  
      /* what sort of ARP is this? */

  ar_op = ntohs(arp->ar_op);
  
      /* What is the source mac address? */

  memcpy (&sha, arp->ar_sha, sizeof(u_char) * 6);

      /* What is the source IP address? */

  memcpy (&netspa, arp->ar_spa, sizeof(u_long));

  spa = ntohl(netspa);

      /* What is the destination IP address? */

  memcpy (&nettpa, arp->ar_tpa, sizeof(u_long));

  tpa = ntohl(nettpa);

      /* Create strings from the IP addresses for logging and stuff */

  tmp = int_to_ip (spa);
  strncpy(srcipstring, tmp, 16);
  tmp = int_to_ip (tpa);
  strncpy(dstipstring, tmp, 16);

  snprintf(msg, BUFSIZ,
          "%s Received ARP request packet, source: %s dest: %s",
          myint->name,
          srcipstring,
          dstipstring
          );
  log(msg, LOG_DEBUG);

  switch (ar_op) {

      case(ARPOP_REQUEST):

            /* Check to see if this request is coming from an IP we
               would otherwise snarf, and set lasttime to 0 if it is */

        newip.address = spa;

        checkip = (struct iplist **) tfind ((void *) &newip, 
                                            &(myint->iptree), 
                                            compare_ip);


        if (checkip != NULL) {
          
          ipptr = *checkip;
          ipptr->lasttime = 0;
          
        }
        
            /* Check to see if this request is for an IP we would
               otherwise snarf and react accordingly*/

        newip.address = tpa;
        checkip = (struct iplist **) tfind ((void *) &newip, 
                                            &(myint->iptree), 
                                            compare_ip);
        
        if (checkip != NULL && spa != 0) {
          
          ipptr = *checkip;
          
              /* Check to see if we are switch safe */

          if (myint->switchsafe == 1) {

                /* Generate a mirror arp */
            if ((generate_arp(ARPOP_REQUEST, myint, &newip)) == EXIT_SUCCESS) {
              
                  /* print if generate_arp did it's thing */
              
              snprintf(msg, BUFSIZ, 
                      "%s Sent ARP Request for %s (mirror)",
                      myint->name,
                      dstipstring
                      );
              log(msg, LOG_DEBUG);
              
            } else {

              log("Could not generate arp", LOG_ERR);
              return;

            }

          }
          
          if (ipptr->lasttime == 0 || ipptr->lastip != spa ) {
            
            ipptr->lasttime = time(0);
            ipptr->lastip = spa;
            memcpy (ipptr->lastmac, sha, sizeof(u_char) * 6);
            
            snprintf(msg, BUFSIZ,
                    "%s Initial ARP from %s (%x:%x:%x:%x:%x:%x) for %s",
                    myint->name,
                    srcipstring, 
                    ipptr->lastmac[0],
                    ipptr->lastmac[1],
                    ipptr->lastmac[2],
                    ipptr->lastmac[3],
                    ipptr->lastmac[4],
                    ipptr->lastmac[5],
                    dstipstring
                    );
            log(msg, LOG_DEBUG);

          } else {
            
            if ((currenttime - ipptr->lasttime) > 60) {
              ipptr->lasttime = 0;            
              
            } else {
              
              if ((currenttime - ipptr->lasttime) < 2) {
                
                    /* ignore */
                
              } else {
                
                ipptr->lasttime = time(0);
                
                snprintf(msg, BUFSIZ,
                        "%s Final ARP from %s (%x:%x:%x:%x:%x:%x) for %s",
                        myint->name,
                        srcipstring, 
                        ipptr->lastmac[0],
                        ipptr->lastmac[1],
                        ipptr->lastmac[2],
                        ipptr->lastmac[3],
                        ipptr->lastmac[4],
                        ipptr->lastmac[5],
                        dstipstring
                        );
                log(msg, LOG_DEBUG);
                
                if (pretend == 0) {
                  
                      /* generate an arp reply and log if it worked*/
                  
                  if ((generate_arp(ARPOP_REPLY, myint, ipptr)) == EXIT_SUCCESS) {
                    
                    snprintf(msg, BUFSIZ, 
                            "%s Sent ARP Reply for %s to %s",
                            myint->name,
                            dstipstring,
                            srcipstring
                            );
                    log(msg, LOG_NOTICE);

                  }
                  
                } else {
                  
                      /* pretend mode is on, no arp reply generated */

                  
                  snprintf(msg, BUFSIZ,
                          "%s ***PRETEND*** Sent ARP Reply for %s to %s",
                          myint->name,
                          dstipstring,
                          srcipstring
                          );
                  log(msg, LOG_NOTICE);
                }
              }
            }
          }
        }
        
        break;

      case(ARPOP_REPLY):

        newip.address = spa;
        checkip = (struct iplist **) tfind ((void *) &newip, &(myint->iptree), compare_ip);
        
        if (checkip != NULL) {
          
          ipptr = *checkip;
          
          ipptr->lasttime = 0;
          memcpy (ipptr->lastmac, sha, sizeof(u_char) * 6);
          
          snprintf(msg, BUFSIZ,
                  "%s Reply for %s (%x:%x:%x:%x:%x:%x), setting lasttime to 0",
                  myint->name,
                  srcipstring, 
                  ipptr->lastmac[0],
                  ipptr->lastmac[1],
                  ipptr->lastmac[2],
                  ipptr->lastmac[3],
                  ipptr->lastmac[4],
                  ipptr->lastmac[5]
                  );
          log(msg, LOG_DEBUG);
        }
        
        break;

      default:
        break;

  }

}

int
generate_arp (u_int arpop, struct interface *myint, struct iplist *ip) {

      /* Generate an ARP request or reply as specified by arpop */
  
  int packet_size,                    /* size of our packet */
    c;                                /* misc */
  u_int netsrc_ip, netdst_ip;         /* network order source ip, dest ip */
  u_char src_ip[4], dst_ip[4];        /* source ip, dest ip */
  u_char src_mac[6];                  /* source mac */
  u_char eth_dst_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};  /* dest mac */
  u_char arp_dst_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};  /* dest mac */
  u_char *packet;                     /* pointer to our packet buffer */
 
      /* Padding to make the ARP packet 56 Bytes long, because the RFC
         says so. Ciscos will accept lesser sizes, but Juniper
         E-series (ERX) routers won't. 
      */

  u_char pad[14] = {0x00, 0x00, 0x00, 0x00, 
                    0x00, 0x00, 0x00, 0x00, 
                    0x00, 0x00, 0x00, 0x00, 
                    0x00, 0x00}; 

  packet_size = LIBNET_ARP_H + LIBNET_ETH_H + 14;

  switch (arpop) {

      case ARPOP_REPLY:

        netsrc_ip = htonl(ip->address);
        netdst_ip = htonl(ip->lastip);
        
        memcpy(src_ip, &netsrc_ip, sizeof(u_char) * 4);
        memcpy(dst_ip, &netdst_ip, sizeof(u_char) * 4);

        memcpy(src_mac, myint->macaddress, sizeof(u_char) * 6);
        memcpy(eth_dst_mac, ip->lastmac, sizeof(u_char) * 6);
        memcpy(arp_dst_mac, ip->lastmac, sizeof(u_char) * 6);

        break;

      case ARPOP_REQUEST:

        netsrc_ip = htonl(myint->ipaddress);
        netdst_ip = htonl(ip->address);
        
        memcpy(src_ip, &netsrc_ip, sizeof(u_char) * 4);
        memcpy(dst_ip, &netdst_ip, sizeof(u_char) * 4);

        memcpy(src_mac, myint->macaddress, sizeof(u_char) * 6);

        break;

      default:
        break;
  }

  if (libnet_init_packet(packet_size, &packet) == -1) {
    libnet_error(LIBNET_ERR_FATAL, "libnet_init_packet failed");
  }
  
  libnet_build_ethernet(eth_dst_mac, 
                        src_mac, 
                        ETHERTYPE_ARP, 
                        NULL, 
                        0, 
                        packet);

  libnet_build_arp(ARPHRD_ETHER,      /* hardware addresss type */
                   0x800,             /* protocol address type */
                   6,                 /* hardware addess length */
                   4,                 /* protocol address length */
                   arpop,             /* ARP packet type */
                   src_mac,           /* Sender hardware address */
                   src_ip,            /* Sender IP address */
                   arp_dst_mac,       /* Destination hardware address */
                   dst_ip,            /* Destination IP address */
                   pad,
                   14,
                   packet+LIBNET_ETH_H
                   );
  
  c = libnet_write_link_layer(myint->network, myint->name, packet, packet_size);

  if (c < packet_size) {
    libnet_error(LN_ERR_WARNING, "libnet_write_link_layer only wrote %d bytes", c);
  }

  libnet_destroy_packet(&packet);
  
  return (c == -1 ? EXIT_FAILURE : EXIT_SUCCESS);
}

