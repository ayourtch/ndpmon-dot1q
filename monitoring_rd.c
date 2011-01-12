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

#include "membounds.h"
#include "monitoring_rd.h"


/*Test if the RD message comes from a router with IP6 and MAC address
 *specified in the configuration file
 */
int watch_rd_src(char* message, uint16_t vlan_id, struct ether_header* eptr, struct ip6_hdr* ipptr)
{
	char ip_address[40];
	struct ether_addr *src_eth = (struct ether_addr *) eptr->ether_shost;
	int ret = 0;

	int found_router = router_has_router(routers, vlan_id, ipptr->ip6_src, *src_eth);

	if(!found_router)
	{
		int found_mac = is_router_mac_in(routers, vlan_id, *src_eth);
		int found_lla = is_router_lla_in(routers, vlan_id, ipptr->ip6_src);

		if( found_mac && found_lla)
		{
			/* valid MAC and IP, but not together */
			snprintf (message, NOTIFY_BUFFER_SIZE, "wrong couple IP/MAC %s %s in RD", (char*)ether_ntoa(src_eth), ip_address);
			notify(2, message, "wrong couple IP/MAC in RD", src_eth, ip_address, NULL);
			ret = 2;
		}
		else if( found_mac && !found_lla)
		{
			/* wrong IP */
			snprintf (message, NOTIFY_BUFFER_SIZE, "wrong router redirect ip %s %s", (char*)ether_ntoa(src_eth), ip_address);
			notify(2, message, "wrong router redirect ip", src_eth, ip_address, NULL);
			ret = 2;
		}
		else if( !found_mac && found_lla)
		{
			/* wrong MAC */
			snprintf (message, NOTIFY_BUFFER_SIZE, "wrong router redirect mac %s %s", (char*)ether_ntoa(src_eth), ip_address);
			notify(2, message, "wrong router redirect mac", src_eth, ip_address, NULL);
			ret = 2;
		}
	}

	/* Legitimate Routers can redirect */
	return ret;

#if 0
	char* mac_address = NULL;
	int mac_ok = 0, ip_ok = 0;

	if(routers != NULL)
	{
		mac_address= (char*)ether_ntoa((struct ether_addr*) (eptr->ether_shost));
		mac_ok = is_router_mac_in(routers, *src_eth);
	}
	else
		mac_ok=1;

	if(routers != NULL)
	{
		ipv6_ntoa(ip_address, ipptr->ip6_src);
		ip_ok = is_router_lla_in(routers, ipptr->ip6_src);
	}
	else
		ip_ok=1;

	if(!ip_ok || !mac_ok)
	{
		snprintf (message, NOTIFY_BUFFER_SIZE, "wrong router redirect %s %s", mac_address, ip_address);
		notify(2, message, "wrong router redirect", (struct ether_addr*) (eptr->ether_shost), ip_address, NULL);
		return 2;
	}
	else
		return 0; /*Official routers can redirect*/
#endif
}
