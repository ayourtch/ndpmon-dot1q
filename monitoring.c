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
#include "monitoring.h"


/*Look for mismatch between the source link layer addr and the one anounced
 *in the icmp option*/
int watch_eth_mismatch(char* buffer,  const u_char* packet, uint16_t vlan_id, struct ether_header* eptr, struct ip6_hdr* ipptr, struct icmp6_hdr* icmpptr, int packet_len)
{
	int jump=0;
	uint8_t  opt_type;
	const u_char* pos;
	struct nd_opt_hdr* optptr;  /*netinet/icmp6.h*/
	struct ether_addr* addr1, *addr2;
	char str_ip[IP6_STR_SIZE];

	switch (icmpptr->icmp6_type)
	{
		case  ND_ROUTER_SOLICIT :
			jump = sizeof(struct nd_router_solicit);
			opt_type=1;
			break;
		case ND_ROUTER_ADVERT:
			jump = sizeof(struct nd_router_advert);
			opt_type=1;
			break;
		case ND_NEIGHBOR_SOLICIT:
			jump = sizeof(struct  nd_neighbor_solicit);
			opt_type=1;
			break;
		case ND_NEIGHBOR_ADVERT:
			jump = sizeof(struct nd_neighbor_advert);
			opt_type=2;
			break;
		case ND_REDIRECT:
			return 0;
			break;
		default:
			return 0;
			break;

	}/*end switch*/


	/*We have to search the link layer option among the others options*/
	pos = packet + ETHERNET_SIZE + IPV6_SIZE + jump;
	optptr = (struct nd_opt_hdr*) ( pos ); 

	while((optptr->nd_opt_type != 0) &&((u_char*)optptr < (packet+packet_len)))
	{
		if(DEBUG)
			print_opt(*optptr);

		if(optptr->nd_opt_type ==  opt_type)
		{
			addr1 = (struct ether_addr*) eptr->ether_shost;
			addr2 = (struct ether_addr*) (pos + sizeof(struct nd_opt_hdr));
			ipv6_ntoa(str_ip, ipptr->ip6_src);

			/*mac addr = 48bits: 6Bytes*8*/
			if(MEMCMP(addr1,addr2,6)!=0)
			{
				char eth1[MAC_STR_SIZE];
				strncpy( eth1, ether_ntoa(addr1), MAC_STR_SIZE); 
				snprintf (buffer, NOTIFY_BUFFER_SIZE, "VLAN%d: ethernet mismatch %s %s %s", vlan_id, ether_ntoa(addr2),eth1, str_ip);
				notify(1, buffer, "ethernet mismatch", addr1, str_ip, addr2);
				return 1;
			}
			else
			{
				return 0;
			}
		}
		else
		{
			/*Next option field*/
			pos += (optptr->nd_opt_len)*8;
			optptr = (struct nd_opt_hdr*) ( pos ); 
		}
	}

	return 0;

}


/*Look if the source mac address is a broadcast addr or is all zeros*/
int watch_eth_broadcast(char* buffer, uint16_t vlan_id, struct ether_header* eptr, struct ip6_hdr* ipptr)
{
	struct ether_addr* eth_addr = (struct ether_addr*) eptr->ether_shost;
	struct ether_addr* test = malloc(sizeof(struct ether_addr));
	char str_ip[IP6_STR_SIZE];
	int broad =0;


	bzero(test,6);
	if (MEMCMP(eth_addr, test,6) ==0)
		broad=1;
	else
	{
		memset(test,255,6);
		if(MEMCMP(eth_addr, test,6)==0)
			broad= 1; 
		else
		{
			char* test2= "33:33:0:0:0:1";
			if(strcmp(ether_ntoa(eth_addr), test2)==0)
				broad=1;
		}
	}

	if(broad)
	{
		ipv6_ntoa(str_ip, ipptr->ip6_src);
		snprintf (buffer, NOTIFY_BUFFER_SIZE,  "VLAN%d: ethernet broadcast %s %s",vlan_id,ether_ntoa(eth_addr), str_ip);
		free(test);
		notify(1, buffer, "ethernet broadcast", eth_addr, str_ip, NULL);
		return 1;
	} else {
	    free(test);
	    return 0;	
	}
	
}


/*Look if the source ip address is a broadcast addr*/
int watch_ip_broadcast(char* buffer, uint16_t vlan_id, struct ether_header* eptr, struct ip6_hdr* ipptr)
{
	struct ether_addr* eth_addr = (struct ether_addr*) eptr->ether_shost;
	struct in6_addr* ip_addr = &ipptr->ip6_src;
	char str_ip[IP6_STR_SIZE];

	ipv6_ntoa(str_ip, *ip_addr);

	if (IN6_IS_ADDR_MULTICAST(ip_addr))
	{

		snprintf (buffer, NOTIFY_BUFFER_SIZE, "VLAN%d: ip multicast %s %s",vlan_id,ether_ntoa(eth_addr),str_ip);
		notify(1, buffer, "ip multicast", eth_addr, str_ip, NULL);
		return 1;

	}
	else
		return 0;
}


/*Look if the source ip address is local to the subnet*/
int watch_bogon(char* buffer, uint16_t vlan_id, struct ether_header* eptr, struct ip6_hdr* ipptr)
{

	struct ether_addr* eth_addr = (struct ether_addr*) eptr->ether_shost;
	struct in6_addr* ip_addr = &ipptr->ip6_src;
	char str_ip[IP6_STR_SIZE];

	router_list_t *tmp = routers;
	int find = 0;

	ipv6_ntoa(str_ip, *ip_addr);

	while( tmp != NULL)
	{
		prefix_t *ptmp = tmp->prefixes;
		while(ptmp != NULL)
		{
			if(IN6_ARE_PRE_EQUAL(ip_addr, &(ptmp->prefix)))
				find = 1;

			ptmp = ptmp->next;
		}
		tmp = tmp->next;
	}

	if (!find && !IN6_IS_ADDR_UNSPECIFIED(ip_addr)&&!IN6_IS_ADDR_LINKLOCAL(ip_addr)&&!IN6_IS_ADDR_MULTICAST(ip_addr)&&!IN6_IS_ADDR_SITELOCAL(ip_addr))
	{
		snprintf (buffer, NOTIFY_BUFFER_SIZE, "VLAN%d: bogon %s %s",vlan_id,ether_ntoa(eth_addr),str_ip);
		notify(1, buffer, "bogon", eth_addr, str_ip, NULL);
		return 1;
	}
	else
		return 0;
}


/* Look if the hop limit is set to 255 */
int watch_hop_limit(char* buffer, uint16_t vlan_id, struct ether_header* eptr, struct ip6_hdr* ipptr)
{
	struct ether_addr* eth_addr = (struct ether_addr*) eptr->ether_shost;
	struct in6_addr* ip_addr = &ipptr->ip6_src;
	char str_ip[IP6_STR_SIZE];
	int hlim;

	ipv6_ntoa(str_ip, *ip_addr);

	hlim = ipptr->ip6_hlim;

	if(hlim != 255)
	{
		snprintf (buffer, NOTIFY_BUFFER_SIZE, "VLAN%d: IPv6 Hop Limit %d", vlan_id, hlim);
		notify(1, buffer, "wrong ipv6 hop limit", eth_addr, str_ip, NULL);
		return 1;
	}

	return 0;
}
