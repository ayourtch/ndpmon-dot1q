#ifndef _PARSERS_
#define _PARSERS_ 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>


#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/encoding.h>
#include <libxml/xmlwriter.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "print_packet_info.h"
#include "neighbors.h"
#include "routers.h"
#include "ndpmon_defs.h"

#define NB_CACHE_SIZE 255
#define MY_ENCODING "ISO-8859-1"

void parse_config();
void write_config();
void parse_cache();
void write_cache();
void free_xml();

#endif
