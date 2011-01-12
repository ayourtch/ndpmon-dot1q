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


#ifndef _MONITORING_NA_
#define _MONITORING_NA_ 1

/* Setting headers according to OSTYPE */
#ifdef _FREEBSD_
#include <sys/types.h>
#include <netinet/in.h>
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
#include <netinet/ether.h>
#endif

#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
/*
#include "config.h"
#include "neighborhood.h"
*/
#include "membounds.h"
#include "ndpmon_defs.h"
#include "print_packet_info.h"
#include "alarm.h"
#include "monitoring_ns.h"

/*Test if the NA enable the router flag and if true
 *test if this neighbor is an official router
 */
int watch_R_flag(char* message, uint16_t vlan_id, struct ether_header* eptr, struct ip6_hdr* ipptr, struct nd_neighbor_advert* naptr);


/*Test if the NA is doing Duplicate Address Detection DOS
 */
int watch_dad_dos(char* message, uint16_t vlan_id, struct ether_header* eptr, struct ip6_hdr* ipptr, struct nd_neighbor_advert* naptr, int new_eth);


#endif
