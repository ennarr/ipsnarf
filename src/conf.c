/* Configuration loading/parsing functions.
 * Written by Nigel Roberts <nigel.roberts@team.telstraclear.co.nz>
 */

#include "ipsnarf.h"

struct interface * 
loadconf (char conffilename[BUFSIZ]) {
      /* Read the config file (conffilename), and return a pointer to
         a linked list of interfaces */
  
  FILE *infile = NULL;
  char *rtn = NULL;
  char line[BUFSIZ];
  int lineno = 0;
  struct interface *wint = NULL;
  struct interface *interfaces = NULL;
  char msg[BUFSIZ];
  
      /* Open the config file */
  
  if ((infile = fopen(conffilename, "r")) != NULL) {
    
        /* Read the config file */

    snprintf(msg, BUFSIZ, "Parsing configuration file %s", conffilename);
    log(msg, LOG_INFO);
    
    while ((rtn = fgets(line, BUFSIZ, infile)) != NULL) {

      lineno++;

      if ((*line != '#') && (strlen(line) > 2)) {

        cleanup(line);

      } else {

        continue;

      }

      switch(parse_type(line)) {

          case INT_MONITOR:

            if (interfaces == NULL && wint == NULL) {

                  // This is the first interface in the list, so we
                  // want to get the memory, and store it's place in
                  // memory.

              wint = (struct interface *) malloc (sizeof(struct interface));
              interfaces = wint;

            } else {
              
              wint->nint = (struct interface *) malloc (sizeof(struct interface));
              wint = wint->nint;

            }

                // populate the interface struct

            if ((rtn = parse_int(line, wint)) != NULL) {
              
              snprintf(msg, BUFSIZ, "(line %d) %s", lineno, rtn);
              log(msg, LOG_ERR);
              return(NULL);
            }

            break;

          case NET_MONITOR:

            if ((rtn = parse_network(line, wint)) != NULL) {

              snprintf(msg, BUFSIZ, "(line %d) %s", lineno, rtn);
              log(msg, LOG_ERR);
              return(NULL);
            }

            break;

          case IP_EXCLUDE:

            if ((rtn = parse_exclude(line, wint)) != NULL) {

              snprintf(msg, BUFSIZ, "(line %d) %s", lineno, rtn);
              log(msg, LOG_ERR);
              return(NULL);

            }

            break;

          case MAC_USE:

            if ((rtn = parse_mac(line, wint)) != NULL) {

              snprintf(msg, BUFSIZ, "(line %d) %s", lineno, rtn);
              log(msg, LOG_ERR);
              return(NULL);

            }

            break;

          case IP_USE:

            if ((rtn = parse_ip(line, wint)) != NULL) {

              snprintf(msg, BUFSIZ, "(line %d) %s", lineno, rtn);
              log(msg, LOG_ERR);
              return(NULL);

            }

            break;

          case SWITCHSAFE:
            
            if ((rtn = parse_switchsafe(line, wint)) != NULL) {
              
              snprintf(msg, BUFSIZ, "(line %d) %s", lineno, rtn);
              log(msg, LOG_ERR);
              return(NULL);
            }
            
            break;

          case CFG_INVALID:

            snprintf(msg, BUFSIZ, "(line %d) unrecognised option \"%s\"", lineno, rtn);
            log(msg, LOG_ERR); 
            return(NULL);
            break;
            
      }
      
    }
    
    return(interfaces);
    
  } else {

    snprintf(msg, BUFSIZ, "Cannot open specified config file %s", conffilename);
    log(msg, LOG_ERR);
    return(NULL);
    
  }

}

config_t 
parse_type (char *mybuffer) {
  
  enum cfg_type_enum type;

  if ((strstr(mybuffer, "interface")) != NULL){
    type = INT_MONITOR;
  } else if ((strstr(mybuffer,"network" )) != NULL){
    type = NET_MONITOR;
  } else if ((strstr(mybuffer, "exclude")) != NULL) {
    type = IP_EXCLUDE;
  } else if ((strstr(mybuffer, "mac")) != NULL){
    type = MAC_USE;
  } else if ((strstr(mybuffer, "ip")) != NULL){
    type = IP_USE;
  } else if ((strstr(mybuffer, "switchsafe")) != NULL){
    type = SWITCHSAFE;
  } else {
    type = CFG_INVALID;
  }
  return( type );
}

char * 
parse_int (char *line, struct interface *myint) {

  char *p = NULL;
  char msg[BUFSIZ];

  sscanf(line, "interface %s", myint->name);

  myint->nint = NULL;
  myint->iptree = NULL;
  myint->ipaddress = 0;
  myint->switchsafe = 0;
  myint->macaddress[0] = 0xff;

  snprintf(msg, BUFSIZ, "interface statement: %s", myint->name);
  log(msg, LOG_INFO);

  return(p);
}

char *
parse_network (char *line, struct interface *myint) {

  char *p = NULL;
  char msg[BUFSIZ];
  char maskstring[BUFSIZ], ipstring[BUFSIZ];
  int rtn = 0;
  u_long ip;
  u_long mask;
  u_long ipnum;
  struct iplist *tip;

  rtn = sscanf(line, "network %s %s", ipstring, maskstring);

  if (rtn != 2) {

    p = (char *) malloc (BUFSIZ);
    snprintf(p, BUFSIZ, "invalid ip address or netmask %s %s", ipstring, maskstring);
    return (p);
    
  }
  
  if ((mask = ip_to_int(maskstring)) == 0) {
    
    p = (char *) malloc (BUFSIZ);
    snprintf(p, BUFSIZ, "invalid netmask %s", maskstring);
    return (p);
    
  }
  
  if ((ip = ip_to_int(ipstring)) == 0) {

    p = (char *) malloc (BUFSIZ);
    snprintf(p, BUFSIZ, "invalid ip address %s", ipstring);
    return (p);
    
  }

  if (mask != (ip | mask)) {
    
    p = (char *) malloc (BUFSIZ);
    snprintf(p, BUFSIZ, "invalid ip address, netmask combination %s %s", ipstring, maskstring);
    return (p);
    
  } 
  
  ipnum = mask ^ 0xffffffff;

  snprintf(msg, BUFSIZ, "%s network statement: %s %s (%u ip addresses)", 
          myint->name, 
          ipstring, 
          maskstring, 
          (u_int) (ipnum + 1)
          );
  log(msg, LOG_INFO);
  
  while (ipnum != -1) {

    tip = (struct iplist *) malloc (sizeof(struct iplist));

    tip->address = ip + ipnum;
    tip->lasttime = 0;
    tip->lastip = 0;
    ipnum--;
    myint->numip++;
    
        // insert it into the tree
    
    tip = tsearch((void *)tip, &(myint->iptree), compare_ip);
    
    if (tip == NULL) {
      
      log("uh-oh, tree allocation broke", LOG_ERR);
      return(NULL);
      
    } 
    
  }  

  return(p);
  
}
  
char *
parse_exclude (char *line, struct interface *myint) {

  char *p = NULL;
  char msg[BUFSIZ];
  char excludestring[BUFSIZ];
  u_long excip;
  struct iplist cip;

  sscanf(line, "exclude %s", excludestring);

  if ((excip = ip_to_int(excludestring)) == 0) {
    
    p = (char *) malloc (BUFSIZ);
    snprintf(p, BUFSIZ, "invalid exclude ip address %s", excludestring);
    return (p);
    
  }
  
  cip.address = excip;

      /* search through every IP for this interface and remove it if
         it matches the ip to exclude */
  
  tdelete((void *) &cip, &(myint->iptree), compare_ip);
  
  snprintf(msg, BUFSIZ, "%s exclude statement: %s", myint->name, excludestring);
  log(msg, LOG_INFO);
  
  
 return (p);
 
}

char * 
parse_mac (char *line, struct interface *myint) {

  int rtn = 0;
  char *p = NULL;
  char msg[BUFSIZ];
  u_int macaddress[6];
  char macstring[BUFSIZ];

  rtn = sscanf(line, "mac %s", macstring);
  rtn = sscanf(macstring, "%x:%x:%x:%x:%x:%x", &macaddress[0], \
               &macaddress[1], &macaddress[2], \
               &macaddress[3], &macaddress[4], \
               &macaddress[5] );
  
  if (rtn != 6) {

        /* uh oh, looks like we've been fed a bogus mac address */
   
    p = (char *) malloc (BUFSIZ);
    snprintf(p, BUFSIZ, "Invalid mac address %s", macstring);
    return (p);

  } else {
    
        /* convert the mac address into something libnet likes and
           store it in our struct */
    
    for (rtn--; rtn != -1; rtn--) {

      myint->macaddress[rtn] = (u_char) macaddress[rtn];

    }

    snprintf(msg, BUFSIZ, "%s mac statement: %x:%x:%x:%x:%x:%x",
            myint->name,
            myint->macaddress[0], 
            myint->macaddress[1],
            myint->macaddress[2], 
            myint->macaddress[3], 
            myint->macaddress[4],
             myint->macaddress[5]
            );
    log(msg, LOG_INFO);

    
    return (p);

  }
}

char *
parse_ip (char *line, struct interface *myint) {

  char *p = NULL;
  char ipstring[BUFSIZ];
  char msg[BUFSIZ];

  sscanf(line, "ip %s", ipstring);

  if ((myint->ipaddress = ip_to_int(ipstring)) == 0) {
    
    p = (char *) malloc (BUFSIZ);
    snprintf(p, BUFSIZ, "invalid ipaddress %s", ipstring);

  }

  snprintf(msg, BUFSIZ, "%s ip statement: %s", myint->name, ipstring);
  log(msg, LOG_INFO);
  
  return p;

}

char * 
parse_switchsafe (char *line, struct interface *myint) {

  char *p = NULL;
  char sstring[BUFSIZ];
  char msg[BUFSIZ];

  sscanf(line, "switchsafe %s", sstring);
  
  if ((strcmp(sstring, "yes")) == 0) {
    myint->switchsafe = 1;
  } else {
    if ((strcmp(sstring, "no")) == 0) {
      myint->switchsafe = 2;
    } else {
      p = (char *) malloc (BUFSIZ);
      snprintf(p, BUFSIZ, "invalid switchsafe value %s", sstring);
    }
  }
  
  snprintf(msg, BUFSIZ, "%s switchsafe statement: %s", myint->name, sstring);
  log(msg, LOG_INFO);

  return p;
}

void
cleanup (char *p) {

  char *p2 = p;
  
  while(*p != '\0') {
    if (*p == '\n')
      *p = '\0';
    else {
      p2++;
      p++;
    }
  }
}
