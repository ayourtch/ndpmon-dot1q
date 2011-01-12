#ifdef _COUNTERMEASURES_
#include "plugins/countermeasures/countermeasures.h"
#endif

#include "neighbors.h"
#include "alarm.h"
#include "membounds.h"

static int in_vlan(neighbor_list_t *tmp, int vlan_id) {
	return ((vlan_id == 0) || 
		(tmp->vlan_id == vlan_id));
}

int neighbor_has_lla(neighbor_list_t *list, uint16_t vlan_id, struct ether_addr eth, struct in6_addr lla)
{
	neighbor_list_t *tmp = list;

	while(tmp != NULL)
	{
		if(in_vlan(tmp, vlan_id) && !MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
		{
			if(IN6_ARE_ADDR_EQUAL(&lla,&(tmp->lla)))
				return 1;
			else
				return 0;
		}

		tmp = tmp->next;
	}

	return 0;
}

int neighbor_has_ip(neighbor_list_t *list, uint16_t vlan_id, struct ether_addr eth, struct in6_addr addr)
{
	neighbor_list_t *tmp = list;

	while(tmp != NULL)
	{
		if(in_vlan(tmp, vlan_id) && !MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
		{
			address_t *atmp = tmp->addresses;
			while(atmp != NULL)
			{
				if(IN6_ARE_ADDR_EQUAL(&addr,&(atmp->address)))
					return 1;
				
				atmp = atmp->next;
			}

			return 0;
		}
		tmp = tmp->next;
	}
	return 0;
}

int add_neighbor_ip(neighbor_list_t **list, uint16_t vlan_id, struct ether_addr eth, struct in6_addr addr)
{
	neighbor_list_t *tmp = *list;
	address_t *new = NULL;
	time_t current= time(NULL);

	if (IN6_IS_ADDR_MULTICAST(&addr))
		return 0;

	if( (new = (address_t *)malloc(sizeof(struct address))) == NULL)
	{
		perror("malloc");
		return 0;
	}
	new->address = addr;
	new->firstseen = current;
	new->lastseen = current;
	new->next = NULL;

	while(tmp != NULL)
	{
		if(in_vlan(tmp, vlan_id) && !MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
		{
			address_t *atmp = tmp->addresses;
			if(atmp == NULL)
				tmp->addresses = new;
			else
			{
				while(atmp->next != NULL)
					atmp=atmp->next;
				atmp->next=new;
			}
			return 1;

		}
		tmp = tmp->next;
	}
	return 0;
}

int del_neighbor_ip(neighbor_list_t **list, uint16_t vlan_id, struct ether_addr eth, struct in6_addr addr)
{
	neighbor_list_t *tmp = *list;

	while(tmp != NULL)
	{
		if(in_vlan(tmp, vlan_id) && !MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
		{
			address_t *atmp = tmp->addresses, *atmp2 = tmp->addresses;
			while(atmp != NULL)
			{
				if(IN6_ARE_ADDR_EQUAL(&addr,&(atmp->address)))
				{
					if(atmp == tmp->addresses)
					{
						tmp->addresses = atmp->next;
						free(atmp);
						return 1;
					}
					atmp2->next = atmp->next;
					free(atmp);
					return 1;
				}
				if(atmp != tmp->addresses)
					atmp2 = atmp2->next;
				atmp = atmp->next;
			}
			return 0;
		}
		tmp = tmp->next;
	}
	return 0;
}


int neighbor_set_last_mac(neighbor_list_t **list, uint16_t vlan_id, struct in6_addr lla, struct ether_addr eth)
{
	neighbor_list_t *tmp = *list;

	while(tmp != NULL)
	{
		if(in_vlan(tmp, vlan_id) && IN6_ARE_ADDR_EQUAL(&lla,&(tmp->lla)))
		{
			tmp->previous_mac = eth;
			return 1;
		}
		tmp = tmp->next;
	}

	return 0;
}

struct ether_addr neighbor_get_last_mac(neighbor_list_t *list, uint16_t vlan_id, struct in6_addr lla)
{
	neighbor_list_t *tmp = list;
	struct ether_addr ret;

	while(tmp != NULL)
	{
		if(in_vlan(tmp, vlan_id) && IN6_ARE_ADDR_EQUAL(&lla,&(tmp->lla)))
		{
			return tmp->previous_mac;
		}
		tmp = tmp->next;
	}

	memcpy(&ret, ether_aton("11:11:11:11:11:11"), sizeof(struct ether_addr));

	return ret;
}

int neighbor_has_old_mac(neighbor_list_t *list, uint16_t vlan_id, struct in6_addr lla, struct ether_addr old_mac)
{
	neighbor_list_t *tmp = list;

	while(tmp != NULL)
	{
		if(in_vlan(tmp, vlan_id) && IN6_ARE_ADDR_EQUAL(&lla,&(tmp->lla)))
		{
			ethernet_t *etmp = tmp->old_mac;
			while(etmp != NULL)
			{
				if(!MEMCMP(&old_mac,&(etmp->mac), sizeof(struct ether_addr)))
					return 1;
				
				etmp = etmp->next;
			}

			return 0;
		}
		tmp = tmp->next;
	}
	return 0;
}

int neighbor_update_mac(neighbor_list_t **list, uint16_t vlan_id, struct in6_addr lla, struct ether_addr new_mac)
{
	neighbor_list_t *tmp = *list;

	while(tmp != NULL)
	{
		if(in_vlan(tmp, vlan_id) && IN6_ARE_ADDR_EQUAL(&lla,&(tmp->lla)))
		{
			add_neighbor_old_mac(list,vlan_id,lla,tmp->mac);
			del_neighbor_old_mac(list,vlan_id,lla,new_mac);
			tmp->previous_mac = tmp->mac;
			tmp->mac = new_mac;
#ifdef _MACRESOLUTION_
			strncpy(tmp->vendor, get_manufacturer(manuf, new_mac), MANUFACTURER_NAME_SIZE);
#endif
			return 1;
		}
		tmp = tmp->next;
	}
	return 0;	
}

int add_neighbor_old_mac(neighbor_list_t **list, uint16_t vlan_id, struct in6_addr lla, struct ether_addr eth)
{
	neighbor_list_t *tmp = *list;
	ethernet_t *new = NULL;

	if( (new = (ethernet_t *)malloc(sizeof(struct ethernet))) == NULL)
	{
		perror("malloc");
		return 0;
	}
	memcpy(&(new->mac), &eth, sizeof(struct ether_addr));
#ifdef _MACRESOLUTION_
	strncpy(new->vendor, get_manufacturer(manuf, eth), MANUFACTURER_NAME_SIZE);
#endif
	new->next = NULL;

	while(tmp != NULL)
	{
		if(in_vlan(tmp, vlan_id) && IN6_ARE_ADDR_EQUAL(&lla,&(tmp->lla)))
		{
			ethernet_t *etmp = tmp->old_mac;
			if(etmp == NULL)
			{
				tmp->old_mac = new;
				return 1;
			}
			else
			{
				while(etmp->next != NULL)
					etmp = etmp->next;
				etmp->next = new;
				return 1;
			}
		}

		tmp = tmp->next;
	}

	return 0;
}

int del_neighbor_old_mac(neighbor_list_t **list, uint16_t vlan_id, struct in6_addr lla, struct ether_addr eth)
{
	neighbor_list_t *tmp = *list;

	while(tmp != NULL)
	{
		if(in_vlan(tmp, vlan_id) && IN6_ARE_ADDR_EQUAL(&lla,&(tmp->lla)))
		{
			ethernet_t *etmp = tmp->old_mac, *etmp2 = tmp->old_mac;
			while(etmp != NULL)
			{
				if(!MEMCMP(&eth,&(etmp->mac), sizeof(struct ether_addr)))
				{
					if(etmp == tmp->old_mac)
					{
						tmp->old_mac = etmp->next;
						free(etmp);
						return 1;
					}
					etmp2->next = etmp->next;
					free(etmp);
					return 1;
				}
				if(etmp != tmp->old_mac)
					etmp2 = etmp2->next;
				etmp = etmp->next;
			}
			return 0;
		}
		tmp = tmp->next;
	}

	return 0;
}


int del_neighbor(neighbor_list_t **list, uint16_t vlan_id, struct ether_addr eth)
{
	neighbor_list_t *tmp = *list, *tmp2 = *list;

	if(!is_neighbor_by_mac(*list,vlan_id,eth))
	{
		fprintf(stderr,"neighbor not in list\n");
		return 0;
	}

	while(tmp != NULL)
	{
		if(!memcmp(&eth,&(tmp->mac), sizeof(struct ether_addr)))
		{
			if(tmp == *list)
			{
				/* if it is the first item in the list */
				*list = tmp->next;
				free(tmp);
				return 1;
			}
			/* else the previous item point to the following one */
			tmp2->next = tmp->next;
			free(tmp);
			return 1;
		}
		/* if it is not the first item, go to the next one */
		if(!(tmp==*list))
			tmp2=tmp2->next;

		tmp = tmp->next;
	}
	/* should never happen */
	return 0;
}

int add_neighbor(neighbor_list_t **list, uint16_t vlan_id, struct ether_addr eth)
{
	neighbor_list_t *tmp = *list,*new=NULL;

	if(is_neighbor_by_mac(*list,vlan_id,eth))
	{
		fprintf(stderr,"Neighbor already in list\n");
		return 0;
	}

	if( (new=(neighbor_list_t *)malloc(sizeof(neighbor_list_t))) == NULL)
	{
		perror("malloc");
		return 0;
	}

	new->mac = eth;
	new->vlan_id = vlan_id;
/* ADDED */
	new->first_mac_seen = eth;
        new->trouble = 0;
/* END ADDED */
#ifdef _MACRESOLUTION_
	strncpy(new->vendor, get_manufacturer(manuf, eth), MANUFACTURER_NAME_SIZE);
#endif
	new->old_mac = NULL;
	new->lla  = in6addr_any;;
	new->addresses = NULL;
	new->timer = time(NULL);
	new->next = NULL;

	if(*list != NULL)
	{
		while(tmp->next != NULL)
			tmp=tmp->next;
		tmp->next=new;
	}
	else
		 *list = new;
	
	return 1;
}

int set_neighbor_lla(neighbor_list_t **list, uint16_t vlan_id, struct ether_addr eth, struct in6_addr lla)
{
	neighbor_list_t *tmp = *list;

	while(tmp != NULL)
	{
		if(in_vlan(tmp, vlan_id) && !MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
		{
			tmp->lla = lla;
			return 1;
		}

		tmp = tmp->next;
	}

	return 0;
}

int reset_neighbor_timer(neighbor_list_t **list, uint16_t vlan_id, struct ether_addr eth)
{
	char buffer[NOTIFY_BUFFER_SIZE];
	neighbor_list_t *tmp = *list;
	time_t current= time(NULL);

	while(tmp != NULL)
	{
		if(in_vlan(tmp, vlan_id) && !MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
		{
			/*If the station has been inactive for a long time: 6 months*/
			char str_ip[IP6_STR_SIZE];
   
			if(difftime(current, tmp->timer) > 6*30*DAY_TIME)
			{
				ipv6_ntoa(str_ip, tmp->lla);
				snprintf (buffer, NOTIFY_BUFFER_SIZE, "new activity from: %s %s", ether_ntoa((struct ether_addr*)(&(tmp->mac))),str_ip);
				notify(1,buffer,"new activity",&eth,str_ip,NULL); 
			}

			tmp->timer = current;

			return 1;
		}

		tmp = tmp->next;
	}

	return 0;
}

int reset_neighbor_address_timer(neighbor_list_t **list, uint16_t vlan_id, struct ether_addr eth, struct in6_addr addr)
{
	neighbor_list_t *tmp = *list;
	time_t current= time(NULL);


	while(tmp != NULL)
	{
		if(in_vlan(tmp, vlan_id) && !MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
		{
			address_t *atmp = tmp->addresses;
			while(atmp != NULL)
			{
				if(IN6_ARE_ADDR_EQUAL(&addr,&(atmp->address)))
				{
					/* set the timer to current time */
					atmp->lastseen = current;
					return 1;
				}
				
				atmp = atmp->next;
			}

			return 0;
		}
		tmp = tmp->next;
	}
	return 0;
}

int set_neighbor_address_timer(neighbor_list_t **list, uint16_t vlan_id, struct ether_addr eth, struct in6_addr addr, time_t value)
{
	neighbor_list_t *tmp = *list;


	while(tmp != NULL)
	{
		if(in_vlan(tmp, vlan_id) && !MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
		{
			address_t *atmp = tmp->addresses;
			while(atmp != NULL)
			{
				if(IN6_ARE_ADDR_EQUAL(&addr,&(atmp->address)))
				{
					/* set the timer to given value */
					atmp->lastseen = value;
					return 1;
				}
				
				atmp = atmp->next;
			}

			return 0;
		}
		tmp = tmp->next;
	}
	return 0;
}

int set_neighbor_first_address_timer(neighbor_list_t **list, uint16_t vlan_id, struct ether_addr eth, struct in6_addr addr, time_t value)
{
	neighbor_list_t *tmp = *list;


	while(tmp != NULL)
	{
		if(in_vlan(tmp, vlan_id) && !MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
		{
			address_t *atmp = tmp->addresses;
			while(atmp != NULL)
			{
				if(IN6_ARE_ADDR_EQUAL(&addr,&(atmp->address)))
				{
					/* set the timer to given value */
					atmp->firstseen = value;
					return 1;
				}
				
				atmp = atmp->next;
			}

			return 0;
		}
		tmp = tmp->next;
	}
	return 0;
}


int set_neighbor_timer(neighbor_list_t **list, uint16_t vlan_id, struct ether_addr eth, time_t value)
{
	neighbor_list_t *tmp = *list;

	while(tmp != NULL)
	{
		if(in_vlan(tmp, vlan_id) && !MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
		{
			tmp->timer = value;
			return 1;
		}

		tmp = tmp->next;
	}

	return 0;
}

int is_neighbor_by_mac(neighbor_list_t *list, uint16_t vlan_id, struct ether_addr eth)
{
	neighbor_list_t *tmp = list;

	while(tmp != NULL)
	{
		if(in_vlan(tmp, vlan_id) && !MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
			return 1;

		tmp = tmp->next;
	}

	return 0;
}

int is_neighbor_by_lla(neighbor_list_t *list, uint16_t vlan_id, struct in6_addr lla)
{
	neighbor_list_t *tmp = list;

	while(tmp != NULL)
	{
		if(in_vlan(tmp, vlan_id) && IN6_ARE_ADDR_EQUAL(&lla,&(tmp->lla)))
			return 1;

		tmp = tmp->next;
	}

	return 0;
}

int is_neighbor_by_ip(neighbor_list_t *list, uint16_t vlan_id, struct in6_addr addr)
{
	neighbor_list_t *tmp = list;

	while(tmp != NULL)
	{
		address_t *atmp = tmp->addresses;
		while(atmp != NULL)
		{
			if(in_vlan(tmp, vlan_id) && IN6_ARE_ADDR_EQUAL(&addr,&(atmp->address)))
				return 1;

			atmp = atmp->next;
		}
		tmp = tmp->next;
	}
	
	return 0;
}


neighbor_list_t * get_neighbor_by_mac(neighbor_list_t *list, uint16_t vlan_id, struct ether_addr eth)
{
	neighbor_list_t *tmp = list;

	while(tmp != NULL)
	{
		if(in_vlan(tmp, vlan_id) && !MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
			return tmp;

		tmp = tmp->next;
	}

	return NULL;
}

neighbor_list_t * get_neighbor_by_lla(neighbor_list_t *list, uint16_t vlan_id, struct in6_addr lla)
{
	neighbor_list_t *tmp = list;

	while(tmp != NULL)
	{
		if(in_vlan(tmp, vlan_id) && IN6_ARE_ADDR_EQUAL(&lla,&(tmp->lla)))
			return tmp;

		tmp = tmp->next;
	}

	return NULL;
}

neighbor_list_t * get_neighbor_by_ip(neighbor_list_t *list, uint16_t vlan_id, struct in6_addr addr)
{
	neighbor_list_t *tmp = list;

	while(tmp != NULL)
	{
		address_t *atmp = tmp->addresses;
		while(atmp != NULL)
		{
			if(in_vlan(tmp, vlan_id) && IN6_ARE_ADDR_EQUAL(&addr,&(atmp->address)))
				return tmp;

			atmp = atmp->next;
		}
		tmp = tmp->next;
	}
	
	return NULL;
}


int nb_neighbor(neighbor_list_t *neighbors)
{
	int n = 0;
	neighbor_list_t *tmp = neighbors;

	while(tmp != NULL)
	{
		n++;
		tmp=tmp->next;
	}

	return n;
}

void print_neighbors(neighbor_list_t *list)
{
	neighbor_list_t *tmp = list;
	while(tmp != NULL)
	{
		char eth[ETH_ADDRSTRLEN], lla[INET6_ADDRSTRLEN+1];
		address_t *atmp = tmp->addresses;
		ethernet_t *etmp = tmp->old_mac;

		ipv6_ntoa(lla,tmp->lla);
		strncpy(eth,ether_ntoa(&(tmp->mac)), ETH_ADDRSTRLEN);
		fprintf(stderr,"Neighbor (VLAN%d, %s,%s,%ld):\n", tmp->vlan_id, eth, lla, tmp->timer);
		if(atmp != NULL)
		{
			fprintf(stderr,"IPv6 Global Addresses: ");
			while(atmp != NULL)
			{
				char addr[INET6_ADDRSTRLEN+1];
				ipv6_ntoa(addr,atmp->address);
				fprintf(stderr,"\t%s", addr);
				atmp=atmp->next;
			}
			fprintf(stderr,"\n");
		}
		if(etmp != NULL)
		{
			fprintf(stderr,"Old MAC Addresses: ");
			while(etmp != NULL)
			{
				char addr[ETH_ADDRSTRLEN+1];
				strncpy(addr,ether_ntoa(&(etmp->mac)), ETH_ADDRSTRLEN);
				fprintf(stderr,"\t%s", addr);
				etmp=etmp->next;
			}
			fprintf(stderr,"\n");
		}
		fprintf(stderr,"\n");
		tmp=tmp->next;
	}
}

int new_station(neighbor_list_t **list, uint16_t vlan_id, struct ether_addr eth, struct in6_addr addr, int *new_eth)
{
	char str_ip[INET6_ADDRSTRLEN],buffer[NOTIFY_BUFFER_SIZE];
	int found_mac = is_neighbor_by_mac(*list, vlan_id, eth);
	int found_lla = is_neighbor_by_lla(*list, vlan_id, addr);
	int found_ip = is_neighbor_by_ip(*list, vlan_id, addr);
	int ret = 0;

	ipv6_ntoa(str_ip, addr);
	if( !found_mac )
	{
#ifdef _MACRESOLUTION_
		/* Verify that the MAC address is from a known vendor */
		char vendor[MANUFACTURER_NAME_SIZE];
		strncpy(vendor, get_manufacturer(manuf, eth), MANUFACTURER_NAME_SIZE);
		if( !strncmp(vendor, "unknown", MANUFACTURER_NAME_SIZE) )
		{
			/* the MAC address is not from a known vendor, may be a forged address */
			snprintf (buffer, NOTIFY_BUFFER_SIZE, "unkown mac vendor %s %s", ether_ntoa(&eth),str_ip);
			notify(1, buffer, "unkown mac vendor", &eth, str_ip, NULL);
			ret = 1;
		}
#endif
		*new_eth=1;
	}

	if(DEBUG)
		fprintf(stderr,"New Ethernet %d -> found_mac: %d found_lla: %d found_ip: %d\n",*new_eth, found_mac, found_lla, found_ip);

	if( (found_mac == 0) && (found_lla == 0) && (found_ip == 0) )
	{
		/* new station */
		add_neighbor(list, vlan_id, eth);

		if( IN6_IS_ADDR_LINKLOCAL(&addr) )
			set_neighbor_lla(list, vlan_id, eth, addr);
		else if( !IN6_IS_ADDR_MULTICAST(&addr) ) 
			add_neighbor_ip(list, vlan_id, eth, addr);

		snprintf(buffer, NOTIFY_BUFFER_SIZE, "new station VLAN%d %s %s", vlan_id, ether_ntoa(&eth),str_ip);
		notify(1, buffer, "new station",&eth,str_ip,NULL);
		ret = 1;
	}
	else if( (found_mac ==1) && (found_lla == 0) && IN6_IS_ADDR_LINKLOCAL(&addr) )
	{
		/* the neighbor is know, but not its LLA */
		set_neighbor_lla(list, vlan_id, eth, addr);
		/* reset timer for host */
		reset_neighbor_timer(list, vlan_id, eth);
		snprintf (buffer, NOTIFY_BUFFER_SIZE, "new lla %s %s\n", ether_ntoa(&eth),str_ip);
		notify(1,buffer,"new lla",&eth,str_ip,NULL);
		ret = 1;
	}
	else if( (found_mac ==1) && (found_ip == 0) && !IN6_IS_ADDR_LINKLOCAL(&addr) )
	{
		/* the neighbor is known, but not this IP */
		if( !IN6_IS_ADDR_MULTICAST(&addr) )
			add_neighbor_ip(list, vlan_id, eth, addr);
		/* reset timer for host */
		reset_neighbor_timer(list, vlan_id, eth);
		snprintf (buffer, NOTIFY_BUFFER_SIZE, "new IP %s %s\n", ether_ntoa(&eth),str_ip);
		notify(1,buffer,"new IP",&eth,str_ip,NULL);
		ret = 1;
	}
	else if( (found_mac == 1) && ( (found_lla)||(found_ip) ) )
	{
		if( !IN6_IS_ADDR_LINKLOCAL(&addr) )
			if( !neighbor_has_ip(*list,vlan_id,eth,addr) )
				if( !IN6_IS_ADDR_MULTICAST(&addr) )
					add_neighbor_ip(list, vlan_id, eth, addr);

		/* reset timer for host */
		reset_neighbor_timer(list, vlan_id, eth);
		fprintf (stderr, "Reset timer for %s %s\n", ether_ntoa(&eth),str_ip);

		/* if the IP exists, reset timer */
		if( found_ip == 1 )
		{
			reset_neighbor_address_timer(list, vlan_id, eth, addr);
			fprintf (stderr, "Reset address timer for %s %s\n", ether_ntoa(&eth),str_ip);
		}
	}
	else if( (found_mac == 0) && ( (found_lla)||(found_ip) ) )
	{
		struct in6_addr lla;
		neighbor_list_t *tmp;

		if( IN6_IS_ADDR_LINKLOCAL(&addr) )
			lla = addr;
		else 
		{
			tmp = get_neighbor_by_ip(*list,vlan_id,addr);
			lla = tmp->lla;
		}

		if( neighbor_has_old_mac(*list, vlan_id, lla, eth) )
		{
			/* Flip Flop */
			char temp[MAC_STR_SIZE],toto[MAC_STR_SIZE];

			struct ether_addr previous_mac = neighbor_get_last_mac(*list,vlan_id,lla);

			tmp = get_neighbor_by_lla(*list,vlan_id,lla);
			snprintf(temp, MAC_STR_SIZE, "%s", ether_ntoa(&(tmp->mac)));
			snprintf(toto, MAC_STR_SIZE, "%s", ether_ntoa(&previous_mac));

			if(!MEMCMP(&eth,&previous_mac, sizeof(struct ether_addr)))
			{
				snprintf (buffer, NOTIFY_BUFFER_SIZE, "flip flop between %s and %s for %s", temp, ether_ntoa(&eth), str_ip);
				if(DEBUG)
					fprintf (stderr, "flip flop between %s and %s for %s\n", temp, ether_ntoa(&eth), str_ip);
				notify(2,buffer,"flip flop",&eth,str_ip,&previous_mac); 
			}
			else
			{
				sprintf (buffer, "reused old ethernet address %s instead of %s for %s", ether_ntoa(&eth), temp, str_ip);
				if(DEBUG)
					fprintf (stderr, "reused old ethernet address %s instead of %s for %s\n", ether_ntoa(&eth), temp, str_ip);
				notify(2,buffer,"reused old ethernet address",&eth,str_ip,&previous_mac); 
			}
			neighbor_update_mac(list, vlan_id, lla, eth);
			ret = 2;
#ifdef _COUNTERMEASURES_
			cm_propagate_neighbor_mac(tmp, &addr);
#endif
		}
		else
		{
			/* Changed Ethernet Address */
			char temp[MAC_STR_SIZE];

			tmp = get_neighbor_by_lla(*list,vlan_id,lla);
			snprintf(temp, MAC_STR_SIZE, "%s", ether_ntoa(&(tmp->mac)));
			neighbor_update_mac(list, vlan_id, lla, eth);
			snprintf (buffer, NOTIFY_BUFFER_SIZE, "changed ethernet address %s to %s %s", temp, ether_ntoa(&eth),str_ip);
				if(DEBUG)
					fprintf (stderr, "changed ethernet address %s to %s %s\n", temp, ether_ntoa(&eth),str_ip);
			notify(2,buffer,"changed ethernet address",&eth,str_ip,&(tmp->mac)); 
			ret = 2;
#ifdef _COUNTERMEASURES_
			cm_propagate_neighbor_mac(tmp, &addr);
#endif

		}
	}

	return ret;
}


int clean_neighbor_old_mac(neighbor_list_t **list, uint16_t vlan_id, struct ether_addr eth)
{
	neighbor_list_t *tmp = *list;

	while(tmp != NULL)
	{
		if(!MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
		{
			ethernet_t *etmp = tmp->old_mac, *etodel = NULL;

			while( etmp != NULL)
			{
				etodel = etmp;
				etmp = etmp->next;
				free(etodel);
			}

			return 1;
		}

		tmp = tmp->next;
	}

	return 0;
}

int clean_neighbor_addresses(neighbor_list_t **list, uint16_t vlan_id, struct ether_addr eth)
{
	neighbor_list_t *tmp = *list;

	while(tmp != NULL)
	{
		if(!MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
		{
			address_t *atmp = tmp->addresses, *atodel = NULL;

			while( atmp != NULL)
			{
				atodel = atmp;
				atmp = atmp->next;
				free(atodel);
			}

			return 1;
		}

		tmp = tmp->next;
	}

	return 0;
}


int clean_neighbors(neighbor_list_t **list)
{
	neighbor_list_t *tmp = *list, *ntodel = NULL;

	while(tmp != NULL)
	{
		ntodel = tmp;
		clean_neighbor_addresses(list,0,tmp->mac);
		clean_neighbor_old_mac(list,0,tmp->mac);
		tmp = tmp->next;
		free(ntodel);
	}

	return 1;
}

