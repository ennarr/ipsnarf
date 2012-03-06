/* Ipsnarf - listens to arp and trys to occupy otherwise unused IP
 * address as they become available and gracefully give them up again
 * as needed.  Written by Nigel Roberts
 * <nigel.roberts@team.telstraclear.co.nz> 2003-09-12 
 */


#include "ipsnarf.h"

/* global variable governing pretend and background mode */

int pretend = 0;
int nodaemon = 0;
int verbose = 0;

int 
main (int argc, char *argv[]) {

  char conffile[FILENAME_MAX] = "";
  int c = 0;
  int rtn = 0;
  pthread_t *threads;
  struct interface *interfaces = NULL;
  struct interface *wint = NULL;
  int counter = 0;
  int tmp;
  pid_t pid;
  int syslog_fac = LOG_DAEMON;
  struct stat statbuf;
  char msg[BUFSIZ];
  char syslog[BUFSIZ];
  int nullfd;
  
      // What are my options?

  while ((c = getopt(argc, argv, "pdvs:c:")) != EOF) {
    
    switch (c) {

        case 'p':
              // listen only
          pretend = 1;
          break;
          
        case 'd':
              // foreground mode
          nodaemon = 1;
          break;

        case 'c':
              // where is my config file?
          strncpy(conffile, optarg, FILENAME_MAX);
          break;

        case 's':
              // use a different syslog facility
          tmp = atoi(optarg);

          switch (tmp) {
              case 0:
                syslog_fac = LOG_LOCAL0;
                break;
              case 1:
                syslog_fac = LOG_LOCAL1;
                break;
              case 2:
                syslog_fac = LOG_LOCAL2;
                break;
              case 3:
                syslog_fac = LOG_LOCAL3;
                break;
              case 4:
                syslog_fac = LOG_LOCAL4;
                break;
              case 5:
                syslog_fac = LOG_LOCAL5;
                break;
              case 6:
                syslog_fac = LOG_LOCAL6;
                break;
              case 7:
                syslog_fac = LOG_LOCAL7;
                break;
              default:
                printf("invalid syslog facility\n");
                print_usage();
                return(0);
                break;
          }
          break;
          
        case 'v':
          verbose++;
          break;

        case '?':
          print_usage();
          return(1);

        default:
          print_usage();
          return(1);
          break;
          
    }
    
  }

  if (*conffile == '\0') {
    
    if ((stat("/usr/local/etc/ipsnarf.conf", &statbuf)) == -1) {
      if ((stat("/etc/ipsnarf.conf", &statbuf)) == -1) {
        printf("ERROR: No configuration file found or explicity given!\n");
        print_usage();
        return(0);
      } else {
        strncpy(conffile, "/etc/ipsnarf.conf", FILENAME_MAX);
      }
    } else {
      strncpy(conffile, "/usr/local/etc/ipsnarf.conf", FILENAME_MAX);
    } 
  }

  
  if (nodaemon == 0) {
    if (!fork()) {
      setsid();
      if (!fork()) {
        chdir("/");
        nullfd = open("/dev/null", O_RDONLY);
        dup2(nullfd, STDIN_FILENO);
        dup2(nullfd, STDOUT_FILENO);
        dup2(nullfd, STDERR_FILENO);
        close(nullfd);
      } else {
        exit(0);
      }
    } else {
      exit(0);
    }
  }

      /* open the syslog */
  openlog("ipsnarf", LOG_PID, syslog_fac);

  interfaces = loadconf(conffile);
  
  if (interfaces == NULL) {

        /* bad things have happened */

    return(errno);
    
  } else {
    
        /* Count and check interface configs for sanity */

    wint = interfaces;

    while (wint != NULL) {
      
      if (wint->macaddress[0] == 0xff) {
        snprintf(msg, BUFSIZ, "No MAC address defined for interface %s\n", wint->name);
        log(msg, LOG_ERR);
        return(1);
      }
      
      if (wint->ipaddress == 0) {
        
        snprintf(msg, BUFSIZ, "No IP address defined for interface %s\n", wint->name);
        log(msg, LOG_ERR);
        return(1);
      }

      if (wint->switchsafe == 0) {

            /* switch safe is the default */
        wint->switchsafe = 1;

      }

      counter++;
      wint = wint->nint;

    }
    
    threads = (pthread_t *) malloc(sizeof(pthread_t)*counter);
    
        /* Start one snarfer thread per interface */
    
    for(counter--; counter != -1; counter--) {
      
      rtn = pthread_create(&threads[counter], NULL, snarf, (void *)interfaces);
      
      if (rtn) {
        snprintf(msg, BUFSIZ, "Return code from pthread_create() is %d\n", rtn);
        log(msg, LOG_ERR);
        return(1);
      }

      interfaces = interfaces->nint;

    }

        /* Wait until threads exit (forever) */

    pthread_exit(NULL);

  }
  
  return(0);
  
}
