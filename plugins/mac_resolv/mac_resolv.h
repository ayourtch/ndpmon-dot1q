#ifndef _MAC_RESOLV_H_
#define _MAC_RESOLV_H_

#define BUFFER_SIZE 256

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <syslog.h>
#include <unistd.h> 
#include <string.h>

/* Setting headers according to OSTYPE */
#ifdef _FREEBSD_
#include <sys/types.h>
#include <net/ethernet.h>
#endif

#ifdef _OPENBSD_
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#endif

#ifdef _LINUX_
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h> 
#endif

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include "../../membounds.h" 

typedef struct manufacturer{
	char code[MANUFACTURER_CODE_SIZE];
	char name[MANUFACTURER_NAME_SIZE];
	struct manufacturer *next;
}manufacturer_t;

int read_manuf_file(char *filename, manufacturer_t **list);

int is_manufacturer(manufacturer_t *list, char *code, char *name);
int add_manufacturer(manufacturer_t **list, char *code, char *name);
char * get_manufacturer(manufacturer_t *list, struct ether_addr eth);
int clean_manufacturer(manufacturer_t **list);
void print_manufacturer(manufacturer_t *list);

#endif

