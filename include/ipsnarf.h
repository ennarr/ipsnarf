#ifndef IPSNARF_H
#define IPSNARF_H 1

#if HAVE_CONFIG_H
#  include <config.h>
#endif

#include <pthread.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <search.h>
#include <syslog.h>
#if TM_IN_SYSTIME 
#include <sys/time.h>
#else
#include <time.h>
#endif

#if STDC_HEADERS
#  include <stdlib.h>
#  include <string.h>
#elif HAVE_STRINGS_H
#  include <strings.h>
#endif /*STDC_HEADERS*/

#if HAVE_UNISTD_H
#  include <unistd.h>
#endif

#if HAVE_ERRNO_H
#  include <errno.h>
#endif /*HAVE_ERRNO_H*/
#ifndef errno
/* Some systems #define this! */
extern int errno;
#endif

#include <libnet.h>
#include <pcap.h>

static char helpstring[] = "%s: An IP snarfer\n"
"Version %s - Copyright 2003 Nigel Roberts\n"
"Usage: ipsnarf [-p] [-d] [-v[v]] [-s (0..7)] [-c <config file>]\n"
"Options:\n"
" -p: pretend - listen only and do not respond to arps\n"
" -d: no detach - run in foreground\n"
" -s: syslog - specify local syslog facility from 0 (local0) to 7 (local7)\n"
" -v: verbose - verbose logging, repeat for even more verbose logging\n"
" -c: config file - specify a config file to use\n";


struct interface {

      /* Containts a tree of snarfable ip addresses, along with the
         filter expression used to grab them, the interface name and
         the mac address that the user wants as the source address for
         arp replies.
      */

      // Interface attributes
  
  void *iptree;
  u_long numip;   
  u_char macaddress[6];
  char name[BUFSIZ];
  u_long ipaddress;
  u_short switchsafe;

      // pointer for link interface struct

  struct libnet_link_int *network;

      // linked list pointer
  
  struct interface *nint; 

};

struct iplist {
  u_long address;
  time_t lasttime;
  u_long lastip;
  u_char lastmac[6];
};

enum cfg_type_enum {
  
      /* Configuration file directives and types of capture */

  INT_MONITOR,
  NET_MONITOR,
  IP_EXCLUDE,                   /* EXC */
  MAC_USE,
  IP_USE,
  SWITCHSAFE,
  CFG_INVALID                   /* Cfg directive invalid or missing */
};

typedef enum cfg_type_enum config_t;

char * 
parse_int (char *, struct interface *);

char * 
parse_network (char *, struct interface *);

char *
parse_exclude (char *, struct interface *);

char * 
parse_mac (char *, struct interface *);

char * 
parse_ip (char *, struct interface *);

char * 
parse_switchsafe (char *, struct interface *);

void 
cleanup (char *);

config_t
parse_type (char *);

void * 
snarf (void *);

struct interface * 
loadconf(char *);

void 
print_usage ();

int 
generate_arp (u_int, struct interface *, struct iplist *);

char * 
int_to_ip (u_long);

u_long 
ip_to_int (char *);

int 
compare_ip (const void *, const void *);

void 
got_packet(u_char *, const struct pcap_pkthdr *, const u_char *);

int 
log(char *, int);

#endif /* !IPSNARF_H */
