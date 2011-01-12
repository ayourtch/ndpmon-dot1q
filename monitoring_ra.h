/********************************************************************************
NDPMon - Neighbor Discovery Protocol Monitor
Copyright (C) 2006 MADYNES Project, LORIA - INRIA Lorraine (France)

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

Author Info:
  Name: Thibault Cholez
  Mail: thibault.cholez@esial.uhp-nancy.fr

Maintainer:
  Name: Frederic Beck
  Mail: frederic.beck@loria.fr

MADYNES Project, LORIA-INRIA Lorraine, hereby disclaims all copyright interest in
the tool 'NDPMon' (Neighbor Discovery Protocol Monitor) written by Thibault Cholez.

Olivier Festor, Scientific Leader of the MADYNEs Project, 20 August 2006
***********************************************************************************/

#ifndef _MONITORING_RA_
#define _MONITORING_RA_ 1

/* Setting headers according to OSTYPE */
#ifdef _FREEBSD_
#include <sys/types.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#endif

#ifdef _OPENBSD_
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#endif

#ifdef _LINUX_
#include <netinet/ether.h>
#endif

#include <netinet/ip6.h>
#include <netinet/icmp6.h>
/* ADDED: check other OS */
/*#include <arpa/inet.h>*/
/* END ADDED */

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>

/*
#include "config.h"
*/
#include "ndpmon_defs.h"
#include "print_packet_info.h"
#include "alarm.h"
#include "utils.h"

/*Test if the RA comes from a router with IP6 address specified in the
 *configuration file
 */
int watch_ra_ip(char* buffer, struct ether_header* eptr,struct ip6_hdr* ipptr);


/*Test if the RA comes from a router with MAC address specified in the
 *configuration file
 */
int watch_ra_mac(char* buffer, struct ether_header* eptr,struct ip6_hdr* ipptr );


/*Test if the prefix specfied in RA is right according to the configuration
 *file
 */
int watch_ra_prefix(char* buffer, const u_char* packet, struct ether_header* eptr, struct ip6_hdr* ipptr, int packet_len);

int watch_ra(char* buffer, uint16_t vlan_id, const u_char* packet, struct ether_header* eptr, struct ip6_hdr* ipptr, int packet_len);

#endif
