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

#ifndef _PRINT_PACK_INF_
#define _PRINT_PACK_INF_ 1

#include <stdio.h>
#include <stdlib.h>

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

#include "neighbors.h"
#include "routers.h"
#include "ndpmon_defs.h"
#include "utils.h"


/*Print the ipv6 addr in a readable form*/ 
void ipv6_ntoa(char* buffer,struct in6_addr addr);

/*Print the ipv6 prefix in a readable form*/
void ipv6pre_ntoa(char* buffer,struct in6_addr addr);


/*Print eth header information*/ 
void print_eth(struct ether_header eptr);

/*Print ip6 header information*/ 
void print_ip6hdr(struct ip6_hdr ipptr);

/*Print information of the Neighbor Discovery message*/
void print_ra(struct nd_router_advert raptr);

void print_rs(struct nd_router_solicit rsptr);

void print_na(struct nd_neighbor_advert naptr);

void print_ns(struct nd_neighbor_solicit nsptr);

void print_rd(struct nd_redirect rdptr);


void print_opt(struct nd_opt_hdr);

/*Print the neightbor cache*/
void print_cache();
 

#endif

