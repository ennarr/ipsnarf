/* Generic functions used through out the app.
 * Written by Nigel Roberts <nigel.roberts@team.telstraclear.co.nz> 
 */

#include "ipsnarf.h"

extern int nodaemon;
extern int verbose;

u_long
ip_to_int (char *ip) {

  u_long ina;

  inet_pton(AF_INET, ip, &ina);

  return ntohl(ina);

}

char * 
int_to_ip (u_long ip) {

  struct in_addr ina;

  ina.s_addr = htonl(ip);

  return inet_ntoa(ina);

}

int
compare_ip (const void *a, const void *b) {

  const struct iplist *da = (const struct iplist *) a;
  const struct iplist *db = (const struct iplist *) b;

  return (da->address > db->address) - (da->address < db->address);

}

void
print_usage () {

  printf(helpstring, PACKAGE, VERSION);

}

int
log (char msg[BUFSIZ], int log_level) {

      // Oct 12 06:47:55
  char timestring[16];
  struct tm *tm;
  time_t t;
  
  switch (verbose) {
      case 0:
        if (log_level <= LOG_NOTICE) {
          if (nodaemon == 1) {
            
            t = time(0);
            
            tm = localtime(&t);
            
            strftime(timestring, 16, "%b %d %H:%M:%S", tm);
            
            printf("%s %s\n", timestring, msg);
            return(0);
            
          }          
          syslog(log_level, msg);
        }
        break;
        
      case 1:
        if (log_level <= LOG_INFO) {
            if (nodaemon == 1) {
    
              t = time(0);
              
              tm = localtime(&t);
              
              strftime(timestring, 16, "%b %d %H:%M:%S", tm);
              
              printf("%s %s\n", timestring, msg);
              return(0);
              
            }
          syslog(log_level, msg);
        }
        break;

      case 2:
        if (log_level <= LOG_DEBUG) {
            if (nodaemon == 1) {
    
              t = time(0);
              
              tm = localtime(&t);
              
              strftime(timestring, 16, "%b %d %H:%M:%S", tm);
              
              printf("%s %s\n", timestring, msg);
              return(0);
              
            }
          syslog(log_level, msg);
        }
        break;
  }
  return(0);

}




