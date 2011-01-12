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
#ifdef _COUNTERMEASURES_
#include "./plugins/countermeasures/countermeasures.h"
#endif
#include "monitoring_ra.h"

#if 0

/*Test if the RA comes from a router with IP6 address specified in the
 *configuration file.
 *@return: 0=ok, not 0=pb
 */
int watch_ra_ip(char* buffer, struct ether_header* eptr, struct ip6_hdr* ipptr)
{
	router_list_t *tmp = routers;
	char ip_address[IP6_STR_SIZE];

	while(tmp != NULL)
	{
		/* RA supposed to come from a LLA */
		if(IN6_ARE_ADDR_EQUAL(&ipptr->ip6_src,&(tmp->lla)))
			return 0;
			
        /* REM
		ipv6_ntoa(ip_address, ipptr->ip6_src);
		snprintf (buffer, NOTIFY_BUFFER_SIZE, "VLAN%d: wrong router ip %s %s", vlan_id, ether_ntoa((struct ether_addr*) (eptr->ether_shost)), ip_address);
		notify(2, buffer, "wrong router ip", (struct ether_addr*) (eptr->ether_shost), ip_address, NULL);
		return 2;
		END REM*/

		tmp = tmp->next;
	}
	
	/* if no such router is found*/
	
    ipv6_ntoa(ip_address, ipptr->ip6_src);
    snprintf (buffer, NOTIFY_BUFFER_SIZE, "VLAN%d: wrong router ip %s %s", vlan_id, ether_ntoa((struct ether_addr*) (eptr->ether_shost)), ip_address);
    notify(2, buffer, "wrong router ip", (struct ether_addr*) (eptr->ether_shost), ip_address, NULL);
    return 2;
	
}


/*Test if the RA comes from a router with MAC address specified in the
 *configuration file.
 *@return: 0=ok, not 0=pb
 */
int watch_ra_mac(char* buffer, struct ether_header* eptr, struct ip6_hdr* ipptr)
{
	router_list_t *tmp = routers;
	char ip_address[IP6_STR_SIZE];
	char* mac_address;

	mac_address= (char*)ether_ntoa((struct ether_addr*) (eptr->ether_shost));

	while(tmp != NULL)
	{
		/* RA supposed to come from a LLA */
		if(!MEMCMP(eptr->ether_shost,&(tmp->mac),sizeof(struct ether_addr)))
			return 0;

        /*REM
		ipv6_ntoa(ip_address, ipptr->ip6_src);
		snprintf (buffer, NOTIFY_BUFFER_SIZE, "VLAN%d: wrong router mac %s %s", vlan_id, mac_address, ip_address);
		notify(2, buffer, "wrong router mac", (struct ether_addr*) (eptr->ether_shost), ip_address, NULL);
		return 2;
		END REM*/

		tmp = tmp->next;
	}
	
	/* if no such router is found */
	
	ipv6_ntoa(ip_address, ipptr->ip6_src);
	snprintf (buffer, NOTIFY_BUFFER_SIZE, "VLAN%d: wrong router mac %s %s", vlan_id, mac_address, ip_address);
	notify(2, buffer, "wrong router mac", (struct ether_addr*) (eptr->ether_shost), ip_address, NULL);
	return 2;	
}


/*Test if the prefix specified in RA is right according to the configuration
 *file
 */
int watch_ra_prefix(char* buffer,  const u_char* packet, struct ether_header* eptr, struct ip6_hdr* ipptr, int packet_len)
{
	router_list_t *tmp = routers;
	char prefix[IP6_STR_SIZE];
	const u_char* pos;
	struct nd_opt_hdr* optptr;  /*netinet/icmp6.h*/
	struct nd_opt_prefix_info* preptr = NULL;
	int find=0;

	/*We have to search the prefix option among the others NA options*/
	pos = packet + ETHERNET_SIZE + IPV6_SIZE + sizeof(struct nd_router_advert);
	optptr = (struct nd_opt_hdr*) ( pos ); 

	while((optptr->nd_opt_type!=0)&&((u_char*)optptr < (packet+packet_len)))
	{
		if(optptr->nd_opt_type ==  ND_OPT_PREFIX_INFORMATION)
		{

			preptr = (struct nd_opt_prefix_info*) optptr;
			ipv6pre_ntoa(prefix, preptr->nd_opt_pi_prefix);

			while(tmp != NULL)
			{
				if(router_has_prefix(routers, tmp->lla, tmp->mac, preptr->nd_opt_pi_prefix, preptr->nd_opt_pi_prefix_len))
					find = 1;

				tmp = tmp->next;
			}

			if(!find)
			{
				char ip_address[IP6_STR_SIZE];
				ipv6_ntoa(ip_address, ipptr->ip6_src);
				snprintf (buffer, NOTIFY_BUFFER_SIZE, "VLAN%d: wrong prefix %s %s %s", vlan_id, prefix,(char*)ether_ntoa((struct ether_addr*) (eptr->ether_shost)), ip_address);
				notify(2, buffer, "wrong prefix", (struct ether_addr*) (eptr->ether_shost), ip_address, NULL);
				return 2;
			}
		}

		/*Next option field*/
		pos += (optptr->nd_opt_len)*8;
		optptr = (struct nd_opt_hdr*) ( pos ); 

	}

	return 0;
}

#endif

int watch_ra(char* buffer, uint16_t vlan_id, const u_char* packet, struct ether_header* eptr, struct ip6_hdr* ipptr, int packet_len)
{
	router_list_t* router=NULL;
	int ret = 0;
	struct ether_addr *src_eth;
	char  eth[ETH_ADDRSTRLEN], ip_address[IP6_STR_SIZE];

	src_eth = (struct ether_addr *) eptr->ether_shost;
	ipv6_ntoa(ip_address, ipptr->ip6_src);
	strncpy(eth,ether_ntoa(src_eth), ETH_ADDRSTRLEN);
	router = router_get(routers, vlan_id, ipptr->ip6_src, *src_eth);

	/* Learning phase, just populate the routers list */
	if(learning)
	{
		const u_char* pos;
		struct nd_opt_hdr* optptr;  /*netinet/icmp6.h*/
		struct nd_opt_prefix_info* option_prefix = NULL;
		struct nd_opt_mtu* option_mtu = NULL;
		char prefix[INET6_ADDRSTRLEN];
                
		prefix_t* router_prefix=NULL;
		/* Retrieve the Router Advertisement to get the RA params. */
		struct nd_router_advert *router_advert = (struct nd_router_advert*) (packet+ETHERNET_SIZE+sizeof(struct ip6_hdr));

		/* We have to search the prefix and mtu option among the others RA options: */
		pos = packet + ETHERNET_SIZE + IPV6_SIZE + sizeof(struct nd_router_advert);
		optptr = (struct nd_opt_hdr*) ( pos ); 
		while((optptr->nd_opt_type!=0)&&((u_char*)optptr < (packet+packet_len)))
		{
			switch (optptr->nd_opt_type) {
				case ND_OPT_PREFIX_INFORMATION:
					option_prefix = (struct nd_opt_prefix_info*) optptr;
					ipv6pre_ntoa(prefix, option_prefix->nd_opt_pi_prefix);
					break;
				case ND_OPT_MTU:
					option_mtu = (struct nd_opt_mtu*) optptr;
					break;
				default:
					break;
			}
			/* If all supported options were found skip remaining options: */
			if (option_prefix!=NULL && option_mtu!=NULL) {
				break;
			}
			/* Next option field*/
			pos += (optptr->nd_opt_len)*8;
			optptr = (struct nd_opt_hdr*) ( pos );
		}
		
		if (!option_prefix) /*if there is no prefix information:*/ 
		    return 1;

		if(router==NULL) /* router not seen before */
		{
			router_add(
				&routers, vlan_id, src_eth, &ipptr->ip6_src,
				router_advert->nd_ra_curhoplimit,
				router_advert->nd_ra_flags_reserved,
				ntohs(router_advert->nd_ra_router_lifetime),
				ntohl(router_advert->nd_ra_reachable),
				ntohl(router_advert->nd_ra_retransmit),
				option_mtu==NULL?0:ntohl(option_mtu->nd_opt_mtu_mtu),
				1 /* params are by default volatile (they may change).  */
			);
			router_add_prefix(
				routers, vlan_id, ipptr->ip6_src, *src_eth,
				option_prefix->nd_opt_pi_prefix,
				option_prefix->nd_opt_pi_prefix_len,
				option_prefix->nd_opt_pi_flags_reserved,
				ntohl(option_prefix->nd_opt_pi_valid_time),
				ntohl(option_prefix->nd_opt_pi_preferred_time)
			);
		}
		else /* router already learned */
		{
			/* Update router values: */
			router->param_curhoplimit     = router_advert->nd_ra_curhoplimit;
			router->param_flags_reserved  = router_advert->nd_ra_flags_reserved;
			router->param_router_lifetime = ntohs(router_advert->nd_ra_router_lifetime);
			router->param_reachable_timer = ntohl(router_advert->nd_ra_reachable);
			router->param_retrans_timer   = ntohl(router_advert->nd_ra_retransmit);
			if (option_mtu!=NULL) {
				router->param_mtu = ntohl(option_mtu->nd_opt_mtu_mtu);
			}
			router_prefix = router_get_prefix(routers, vlan_id, ipptr->ip6_src, *src_eth, option_prefix->nd_opt_pi_prefix, option_prefix->nd_opt_pi_prefix_len);
			if( router_prefix == NULL ) {
	                        /* If there is a new prefix advertised add it to the list of prefixes.*/
				router_add_prefix(
					routers, vlan_id, ipptr->ip6_src, *src_eth,
					option_prefix->nd_opt_pi_prefix,
					option_prefix->nd_opt_pi_prefix_len,
					option_prefix->nd_opt_pi_flags_reserved,
					ntohl(option_prefix->nd_opt_pi_valid_time),
					ntohl(option_prefix->nd_opt_pi_preferred_time)
				);
			} else {
				/* If the prefix is already in the list update values: */
				router_prefix->param_valid_time     = ntohl(option_prefix->nd_opt_pi_valid_time);
				router_prefix->param_preferred_time = ntohl(option_prefix->nd_opt_pi_preferred_time);
			}
		}

		return 0;
	}

	/* if the router is not known */
	if(router==NULL)
	{
		int found_mac = is_router_mac_in(routers, vlan_id, *src_eth);
		int found_lla = is_router_lla_in(routers, vlan_id, ipptr->ip6_src);

		if( found_mac && found_lla)
		{
			/* valid MAC and IP, but not together */
			snprintf (buffer, NOTIFY_BUFFER_SIZE, "VLAN%d: wrong couple IP/MAC %s %s in RA", vlan_id, (char*)ether_ntoa(src_eth), ip_address);
			notify(2, buffer, "wrong couple IP/MAC", src_eth, ip_address, NULL);
			ret = 2;
		}
		else if( found_mac && !found_lla)
		{
			/* wrong IP */
			snprintf (buffer, NOTIFY_BUFFER_SIZE, "VLAN%d: wrong router ip %s %s", vlan_id, (char*)ether_ntoa(src_eth), ip_address);
			notify(2, buffer, "wrong router ip", src_eth, ip_address, NULL);
			ret = 2;
		}
		else if( !found_mac && found_lla)
		{
			/* wrong MAC */
			snprintf (buffer, NOTIFY_BUFFER_SIZE, "VLAN%d: wrong router mac %s %s", vlan_id, (char*)ether_ntoa(src_eth), ip_address);
			notify(2, buffer, "wrong router mac", src_eth, ip_address, NULL);
			ret = 2;
		}
		else
		{
			/* wrong ipv6 router: both mac and lla are fantasist */
			snprintf (buffer, NOTIFY_BUFFER_SIZE, "VLAN%d: wrong ipv6 router %s %s", vlan_id, (char*)ether_ntoa(src_eth), ip_address);
			notify(2, buffer, "wrong ipv6 router", src_eth, ip_address, NULL);
			ret = 2;
#ifdef _COUNTERMEASURES_
                        cm_kill_illegitimate_router(src_eth, &ipptr->ip6_src);
#endif
		}
	}
	/* The router is valid, check options */
	else
	{
		const u_char* pos;
		struct nd_router_advert *ra;
		struct nd_opt_hdr* optptr;  /*netinet/icmp6.h*/
		unsigned int managed_flag, other_flag;
		char prefix[INET6_ADDRSTRLEN];
/* ADDED param spoofing detection */
                uint8_t curhoplimit, flags_reserved;
		uint16_t router_lifetime;
		uint32_t reachable_timer, retrans_timer;
		char param_mismatched_list[RA_PARAM_MISMATCHED_LIST_SIZE], param_mismatched[RA_PARAM_MISMATCHED_SIZE];
		int param_mismatch = 0;
/* END ADDED */
#ifdef _COUNTERMEASURES_
		int param_spoofing_detected = 0;
#endif
		/* Check RA parameters */
		pos = packet + ETHERNET_SIZE + IPV6_SIZE;
		ra = (struct nd_router_advert *)pos;
		managed_flag = (ra->nd_ra_flags_reserved)&ND_RA_FLAG_MANAGED;
		other_flag = (ra->nd_ra_flags_reserved)&ND_RA_FLAG_OTHER;

		/* expecting 
		 * M ==1 and O == 1
		 * M == 0 and O == 1
		 * M == 0 and 0 == 0
		 * if M == 1 and O == 0 there is a problem
		 * */
		if( managed_flag && !other_flag)
		{
			char ip_address[IP6_STR_SIZE];
			ipv6_ntoa(ip_address, ipptr->ip6_src);
			snprintf (buffer, NOTIFY_BUFFER_SIZE, "VLAN%d: wrong RA flags: M=1 and O=0", vlan_id);
			notify(2, buffer, "wrong RA flags", (struct ether_addr*) (eptr->ether_shost), ip_address, NULL);
			ret = 2;
		}

/* ADDED : param spoofing detection */
		/* Only perform checks if params are configured not to change: */
		if (router->params_volatile==0) {
			/* fetch RA params from RA */
			curhoplimit     = ra->nd_ra_curhoplimit;
			flags_reserved  = ra->nd_ra_flags_reserved;
			router_lifetime = ntohs(ra->nd_ra_router_lifetime);
			reachable_timer = ntohl(ra->nd_ra_reachable);
			retrans_timer   = ntohl(ra->nd_ra_retransmit);
			/* compare params to those stored in the router list
			   optional parameters are only checked if neither the learned nor the advertised value
			   is zero, because zero means unspecified. flags are always checked.
			*/
			memset(param_mismatched_list, 0, RA_PARAM_MISMATCHED_LIST_SIZE);
			if (curhoplimit!=0 && router->param_curhoplimit!=0 && curhoplimit != router->param_curhoplimit) {
				memset(param_mismatched, 0, RA_PARAM_MISMATCHED_SIZE);
				snprintf(param_mismatched, RA_PARAM_MISMATCHED_SIZE, "curhoplimit=%u;", curhoplimit);
				strncat(param_mismatched_list,param_mismatched,RA_PARAM_MISMATCHED_SIZE);
				param_mismatch++;
			}
			if (flags_reserved != router->param_flags_reserved) {
				memset(param_mismatched, 0, RA_PARAM_MISMATCHED_SIZE);
				snprintf(param_mismatched, RA_PARAM_MISMATCHED_SIZE, "flags=%u;", flags_reserved);
				strncat(param_mismatched_list,param_mismatched,RA_PARAM_MISMATCHED_SIZE);
				param_mismatch++;
			}
			if (router_lifetime!=0 && router->param_router_lifetime!=0 && router_lifetime != router->param_router_lifetime) {
				memset(param_mismatched, 0, RA_PARAM_MISMATCHED_SIZE);
				snprintf (param_mismatched, RA_PARAM_MISMATCHED_SIZE, "router_lifetime=%u;", router_lifetime);
				strncat(param_mismatched_list,param_mismatched,RA_PARAM_MISMATCHED_SIZE);
				param_mismatch++;
			}
			if (reachable_timer!=0 && router->param_reachable_timer!=0 && reachable_timer != router->param_reachable_timer) {
				memset(param_mismatched, 0, RA_PARAM_MISMATCHED_SIZE);
				snprintf (param_mismatched, RA_PARAM_MISMATCHED_SIZE, "reachable_timer=%u;", reachable_timer);
				strncat(param_mismatched_list,param_mismatched,RA_PARAM_MISMATCHED_SIZE);
				param_mismatch++;
			}
			if (retrans_timer!=0 && router->param_retrans_timer!=0 && retrans_timer != router->param_retrans_timer) {
				memset(param_mismatched, 0, RA_PARAM_MISMATCHED_SIZE);
				snprintf (param_mismatched, RA_PARAM_MISMATCHED_SIZE, "retrans_timer=%u;", retrans_timer);
				strncat(param_mismatched_list,param_mismatched,RA_PARAM_MISMATCHED_SIZE);
				param_mismatch++;
			}
			if (param_mismatch>0) { /* we might tune the level of reaction here */
				snprintf (buffer, NOTIFY_BUFFER_SIZE, "VLAN%d: wrong RA params: %s", vlan_id, param_mismatched_list);
				notify(2, buffer, "wrong RA params", (struct ether_addr*) (eptr->ether_shost), ip_address, NULL);
#ifdef _COUNTERMEASURES_
				param_spoofing_detected = 1;
#endif
			}
		}
/* END ADDED */

		/* Check RA options */
		/*We have to search the prefix and other options among the others RA options*/
		pos = packet + ETHERNET_SIZE + IPV6_SIZE + sizeof(struct nd_router_advert);
		optptr = (struct nd_opt_hdr*) ( pos ); 
		while((optptr->nd_opt_type!=0)&&((u_char*)optptr < (packet+packet_len))) {
			if(optptr->nd_opt_type ==  ND_OPT_PREFIX_INFORMATION) {
				struct nd_opt_prefix_info* option_prefix = (struct nd_opt_prefix_info*) optptr;
				uint8_t prefix_flags_reserved;
				uint32_t prefix_valid_time, prefix_preferred_time;
/* ADDED param spoofing detection: */
				prefix_t* router_prefix=NULL;
/* END ADDED */

				prefix_flags_reserved = option_prefix->nd_opt_pi_flags_reserved;
				prefix_valid_time     = ntohl(option_prefix->nd_opt_pi_valid_time);
				prefix_preferred_time = ntohl(option_prefix->nd_opt_pi_preferred_time);
				ipv6pre_ntoa(prefix, option_prefix->nd_opt_pi_prefix);
				/* Check prefix */
				router_prefix = router_get_prefix(routers, vlan_id, ipptr->ip6_src, *src_eth, option_prefix->nd_opt_pi_prefix, option_prefix->nd_opt_pi_prefix_len);
				if (router_prefix==NULL) /* prefix not found*/
				{
					char ip_address[IP6_STR_SIZE];
					ipv6_ntoa(ip_address, ipptr->ip6_src);
					snprintf (buffer, NOTIFY_BUFFER_SIZE, "VLAN%d: wrong prefix %s %s %s", vlan_id, prefix,(char*)ether_ntoa((struct ether_addr*) (eptr->ether_shost)), ip_address);
					notify(2, buffer, "wrong prefix", (struct ether_addr*) (eptr->ether_shost), ip_address, NULL);
					ret = 2;
#ifdef _COUNTERMEASURES_
					cm_kill_wrong_prefix(router, &ipptr->ip6_src, &option_prefix->nd_opt_pi_prefix, option_prefix->nd_opt_pi_prefix_len);
#endif
				}
				/* check the lifetimes  - RFC2462 */
				/* valid should always be > to preferred - RFC2462 */
				if (prefix_preferred_time > prefix_valid_time)
				{
					char ip_address[IP6_STR_SIZE];
					ipv6_ntoa(ip_address, ipptr->ip6_src);
					snprintf (buffer, NOTIFY_BUFFER_SIZE, "VLAN%d: RA preferred lifetime %d longer than valid lifetime %d",vlan_id, prefix_valid_time, prefix_preferred_time );
					notify(2, buffer, "wrong RA prefix option lifetimes", (struct ether_addr*) (eptr->ether_shost), ip_address, NULL);
					ret = 2;
				}
				/* valid lifetime should always be more than 2 hours - RFC2462 */
				if (prefix_valid_time < 7200)
				{
					char ip_address[IP6_STR_SIZE];
					ipv6_ntoa(ip_address, ipptr->ip6_src);
					snprintf (buffer, NOTIFY_BUFFER_SIZE, "VLAN%d: RA prefix option valid lifetime %d < 2 hours", vlan_id, prefix_valid_time );
					notify(2, buffer, "RA prefix option valid lifetime too short", (struct ether_addr*) (eptr->ether_shost), ip_address, NULL);
					ret = 2;
				}
/* ADDED : param spoofing detection */
				if (router_prefix != NULL && router->params_volatile==0) {
					/* Checking value against those learned. prefix params cannot be zero. all are checked. */
					memset(param_mismatched_list, 0, RA_PARAM_MISMATCHED_LIST_SIZE);
					if (prefix_flags_reserved != router_prefix->param_flags_reserved) {
						memset(param_mismatched, 0, RA_PARAM_MISMATCHED_SIZE);
						snprintf(param_mismatched, RA_PARAM_MISMATCHED_SIZE, "flags=%u;", prefix_flags_reserved);
						strncat(param_mismatched_list,param_mismatched,RA_PARAM_MISMATCHED_SIZE);
						param_mismatch++;
					}
					if (prefix_valid_time != router_prefix->param_valid_time) {
						memset(param_mismatched, 0, RA_PARAM_MISMATCHED_SIZE);
						snprintf (param_mismatched, RA_PARAM_MISMATCHED_SIZE, "valid_time=%u;", prefix_valid_time);
						strncat(param_mismatched_list,param_mismatched,RA_PARAM_MISMATCHED_SIZE);
						param_mismatch++;
					}
					if (prefix_preferred_time != router_prefix->param_preferred_time) {
						memset(param_mismatched, 0, RA_PARAM_MISMATCHED_SIZE);
						snprintf (param_mismatched, RA_PARAM_MISMATCHED_SIZE, "preferred_time=%u;", prefix_preferred_time);
						strncat(param_mismatched_list,param_mismatched,RA_PARAM_MISMATCHED_SIZE);
						param_mismatch++;
					}
					if (param_mismatch>0) {
						snprintf (buffer, NOTIFY_BUFFER_SIZE, "VLAN%d: wrong RA prefix option params: %s", vlan_id, param_mismatched_list);
						notify(2, buffer, "wrong RA prefix option params", (struct ether_addr*) (eptr->ether_shost), ip_address, NULL);
#ifdef _COUNTERMEASURES_
						param_spoofing_detected = 1;
#endif
					}	
				}
/* END ADDED */
			}
			/* Verify that the Source Link Option matches the Ethernet source addr of the packet */
			else if(optptr->nd_opt_type ==  ND_OPT_SOURCE_LINKADDR)
			{
				uint8_t *mac;
				mac = (uint8_t *)(pos+2);

				if( (mac[0]!=eptr->ether_shost[0]) || (mac[1]!=eptr->ether_shost[1]) || (mac[2]!=eptr->ether_shost[2]) || (mac[3]!=eptr->ether_shost[3]) || (mac[4]!=eptr->ether_shost[4]) || (mac[5]!=eptr->ether_shost[5]) )
				{
					char  eth_opt[ETH_ADDRSTRLEN];
					struct ether_addr * adv_eth = NULL;

					adv_eth = (struct ether_addr *) mac;
					strncpy(eth_opt,ether_ntoa(adv_eth), ETH_ADDRSTRLEN);
					snprintf (buffer, NOTIFY_BUFFER_SIZE, "VLAN%d: source link address %s different from ethernet source %s", vlan_id, eth_opt, eth );
					notify(2, buffer, "wrong source link address option", (struct ether_addr*) (eptr->ether_shost), ip_address, NULL);
					ret = 2;
				}
			}
/* ADDED : param spoofing detection */
			/* Checking MTU option against the value learned. A value learned = 0 means option not learned. */
			else if(optptr->nd_opt_type ==  ND_OPT_MTU) {
				uint32_t mtu;
				struct nd_opt_mtu *option_mtu = (struct nd_opt_mtu*) optptr;
				mtu = ntohl(option_mtu->nd_opt_mtu_mtu);
				if (router != NULL && router->params_volatile==0 && router->param_mtu!=0 && mtu != router->param_mtu) {
					snprintf (buffer, NOTIFY_BUFFER_SIZE, "VLAN%d: wrong RA mtu option: mtu=%u", vlan_id, mtu);
					notify(2, buffer, "wrong RA mtu option", (struct ether_addr*) (eptr->ether_shost), ip_address, NULL);
#ifdef _COUNTERMEASURES_
					param_spoofing_detected=1;
#endif
				}
/* END ADDED*/				
			}
			/*Next option field*/
			pos += (optptr->nd_opt_len)*8;
			optptr = (struct nd_opt_hdr*) ( pos );
		} /* end options */
#ifdef _COUNTERMEASURES_
	if (param_spoofing_detected!=0) {
		/* Try to restore params in the network. */
		cm_propagate_router_params(router, &ipptr->ip6_src);
	}
#endif
	} /* end valid router*/
	return ret;
}
