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
#include "monitoring_na.h"


/*Test if the NA enable the router flag and if true
 *test if this neighbor is an official router
 */
int watch_R_flag(char* message, uint16_t vlan_id, struct ether_header* eptr, struct ip6_hdr* ipptr, struct nd_neighbor_advert* naptr)
{

	/*Mask is used to select the R_FLAG from the NA*/
	int R_FLAG = (naptr->nd_na_flags_reserved)&ND_NA_FLAG_ROUTER;
	int ret = 0;

	if(DEBUG)
		printf("NA flag router: %d\n", R_FLAG);

	if (R_FLAG)
	{

		char ip_address[IP6_STR_SIZE];
		char* mac_address = NULL;
		struct ether_addr *src_eth = (struct ether_addr *)eptr->ether_shost;

		int found_mac = is_router_mac_in(routers, vlan_id, *src_eth);
		int found_lla = is_router_lla_in(routers, vlan_id, ipptr->ip6_src);

		mac_address= (char*)ether_ntoa((struct ether_addr*) (eptr->ether_shost));
		ipv6_ntoa(ip_address, ipptr->ip6_src);

		if(!found_mac)
		{
			snprintf (message, NOTIFY_BUFFER_SIZE, "NA router flag %s %s", mac_address, ip_address);
			notify(2,message, "NA router flag", (struct ether_addr*) (eptr->ether_shost), ip_address, NULL);
			return 2;
		}
		else
		{
			if(!found_lla)
			{
				int found_ip = router_has_address(routers, vlan_id, *src_eth, ipptr->ip6_src);

				if( !found_ip)
				{
					snprintf (message, NOTIFY_BUFFER_SIZE, "NA router flag %s %s", mac_address, ip_address);
					notify(2,message, "NA router flag", (struct ether_addr*) (eptr->ether_shost), ip_address, NULL);
					return 2;
				}
			}
		}
	}  

	return ret;

}



/*Test if the NA is doing Duplicate Address Detection DOS
  Detect if a host is responding a wrong IPv6 not corresponding to its mac addr
 */
int watch_dad_dos(char* message, uint16_t vlan_id, struct ether_header* eptr, struct ip6_hdr* ipptr, struct nd_neighbor_advert* naptr, int new_eth)
{
	neighbor_list_t *tmp = neighbors;
	struct in6_addr wanted_addr = *get_last_dad_addr();
	char buffer[255];

	ipv6_ntoa(buffer, wanted_addr);

	if(IN6_ARE_ADDR_EQUAL(&naptr->nd_na_target, &wanted_addr))
	{
		/* NA against the last NS for DAD :-/ */
		/* Is this response true ? */
		int find_mac = -1;
		int dos = 0;

		/*If DOS is done by a station never seen before this NA, it should be an attack*/
		if(new_eth)
		{
			fprintf(stderr,"New Ethernet DAD DoS\n");
			dos=1;
		}
		else
		{
			/*Is the mac addr in the neighbor list ?*/
			while(tmp != NULL)
			{
				if (MEMCMP(&(tmp->mac),(struct ether_addr*)eptr->ether_shost,6) == 0)
				{
					find_mac = 1;
					break;
				}
				tmp = tmp->next;
			}

			if(find_mac == 1)
			{
				struct ether_addr * src_eth = (struct ether_addr*)eptr->ether_shost;

				if( !IN6_ARE_ADDR_EQUAL(&naptr->nd_na_target,&(tmp->lla))) 
				{
					char toto[INET6_ADDRSTRLEN];
					char ip_address[40];
					ipv6_ntoa(ip_address, ipptr->ip6_src);
					ipv6_ntoa(toto,(tmp->lla));
					if (!neighbor_has_ip(neighbors, vlan_id, *src_eth, naptr->nd_na_target))
					{
						dos = 1;
					}
				}
			}
		}

		if(dos)
		{
			char ip_address[40];
			ipv6_ntoa(ip_address, ipptr->ip6_src);
			snprintf (message, NOTIFY_BUFFER_SIZE, "dad dos %s %s", (char*)ether_ntoa((struct ether_addr*) (eptr->ether_shost)), ip_address);
			notify(2,message, "dad dos", (struct ether_addr*) (eptr->ether_shost), ip_address, NULL);
			return 2;
		}
		else
			return 0;
	}
	else
		return 0;
}
