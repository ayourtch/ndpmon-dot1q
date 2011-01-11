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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>

/* Setting headers according to OSTYPE */
#ifdef _FREEBSD_
#include <sys/types.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#endif

#ifdef _OPENBSD_
#include <sys/types.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#endif

#ifdef _LINUX_
#include <netinet/ether.h>
#include <net/ethernet.h>
#endif

#include <netinet/in.h>
#include <netinet/if_ether.h> 
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <signal.h>
#include <syslog.h>

#include <pcap.h>              /*lib pcap*/
#include <unistd.h>            /*To read options from the command line*/

#include "print_packet_info.h"
#include "monitoring.h"
#include "monitoring_ra.h"
#include "monitoring_na.h"
#include "monitoring_ns.h"
#include "monitoring_rd.h"
#include "alarm.h"
#include "utils.h"

#ifdef _MACRESOLUTION_
#include "mac_resolv.h"
#endif

/*
#include "neighborhood.h"
*/
#include "neighbors.h"
#include "routers.h"
#include "ndpmon_defs.h"
#include "membounds.h"

/*
 /usr/local/ndpmon/neighbor_list.xml
 */

/*Function called each time that a packet pass the filter and is captured*/
void callback(u_char *args,const struct pcap_pkthdr* hdr,const u_char*
	      packet);

/* To display properly the network address and device's mask */
void interface_spec(char* interface, bpf_u_int32 netp, bpf_u_int32 maskp);

/*To write cache before exiting*/
void handler(int n);

void usage();

int main(int argc,char **argv);
