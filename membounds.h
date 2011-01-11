#ifndef _MEMBOUNDS_H_
#define _MEMBOUNDS_H_


/*This file defines the upper bounds for buffers and strings used by functions like snprintf, strncopy etc.
  I defined the values and indicated their use: "->" means employed by.
*/

#define HOST_NAME_SIZE 1024               /* -> alarm.c, check with hostent */
#define HOST_NAME_LEN_FSTR "1023"        /* -> alarm.c, check with hostent */

#define MANUFACTURER_CODE_SIZE 9          /*-> struct manufacturer*/
#define MANUFACTURER_NAME_SIZE 16         /*-> struct manufacturer, struct neighbor_list */
#define MANUFACTURER_NAME_LEN_FSTR "15"

#define MAIL_MESSAGE_SIZE 1024             /* -> alarm.c/notify() */
#define MAIL_ARGS_SIZE 256                /* -> alarm.c/mail()
                                                  I quote the source code comment of alarm.c: should be sufficient... ;) */

#define NOTIFY_BUFFER_SIZE 256            /* -> alarm.c/already_sent()
                                                  all functions calling alarm.c/notify():
                                                  neighbor.c/reset_neighbor_timer()
                                                             new_station()
                                                  monitoring*.c/watch*() */
#define RA_PARAM_MISMATCHED_SIZE 30
#define RA_PARAM_MISMATCHED_LIST_SIZE 150

/*
From utils.h:
=============                                */



#define IP6_STR_SIZE 40       /*xxxx:xxxx:xxx:xxxx:xxxx:xxxx:xxxx:xxxx*/
#define MAC_STR_SIZE 18       /*xx:xx:xx:xx:xx:xx*/
#define ETHERNET_SIZE 14      /* ethernet headers are 14 bytes */
#define IPV6_SIZE 40          /* ipv6 headers without fragment ... are 40 bytes */
#define ICMP6_HEADER_SIZE 8
#define ETH_CHANGE_SIZE 10


/*
From print_packet_info.h:
=========================
*/

#define ETH_ADDRSTRLEN 17

/*
From ndpmon_defs.h:
=========================
*/

#define PATH_SIZE 128
#define ADMIN_MAIL_SIZE PATH_SIZE
#define SYSLOG_FACILITY_SIZE 16

#endif
