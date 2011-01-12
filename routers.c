#include "routers.h"

static int in_vlan( router_list_t *tmp, uint16_t vlan_id) {
	return ((vlan_id == 0) || (vlan_id == tmp->vlan_id));
}

int is_router_lla_in(router_list_t *list, uint16_t vlan_id, struct in6_addr lla)
{
	router_list_t *tmp = list;

	while(tmp != NULL)
	{
		if(in_vlan(tmp, vlan_id) && IN6_ARE_ADDR_EQUAL(&lla,&(tmp->lla)))
			return 1;

		tmp = tmp->next;
	}

	return 0;
}

int is_router_mac_in(router_list_t *list, uint16_t vlan_id, struct ether_addr eth)
{
	router_list_t *tmp = list;

	while(tmp != NULL)
	{
		if(in_vlan(tmp, vlan_id) && !MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
			return 1;

		tmp = tmp->next;
	}

	return 0;
}


router_list_t * router_get(router_list_t *list, uint16_t vlan_id, struct in6_addr lla, struct ether_addr eth)
{
	router_list_t *tmp = list;

	while(tmp != NULL)
	{
		if(in_vlan(tmp, vlan_id) && !MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
			if(IN6_ARE_ADDR_EQUAL(&lla,&(tmp->lla)))
				return tmp;

		tmp = tmp->next;
	}

	return NULL;
}

int router_has_router(router_list_t *list, uint16_t vlan_id, struct in6_addr lla, struct ether_addr eth) {
	if (router_get(list, vlan_id, lla, eth)==NULL) {
		return 0;
	}
	return 1;
}

int router_add(router_list_t **list, uint16_t vlan_id, struct ether_addr* eth, struct in6_addr* lla,
	uint8_t curhoplimit, uint8_t flags_reserved, uint16_t router_lifetime, uint32_t reachable_timer, uint32_t retrans_timer,
	uint32_t mtu, int p_volatile)
{
	router_list_t *tmp = *list,*new=NULL;

	if(router_has_router(*list,vlan_id,*lla,*eth))
	{
		fprintf(stderr,"Router already in list\n");
		return 0;
	}

	if( (new=(router_list_t *)malloc(sizeof(router_list_t))) == NULL)
	{
		perror("malloc");
		return 0;
	}

	memcpy(&new->mac, eth, sizeof(struct ether_addr));
	new->vlan_id = vlan_id;
	memcpy(&new->lla, lla, sizeof(struct in6_addr));
	new->param_curhoplimit     = curhoplimit;
	new->param_flags_reserved  = flags_reserved;
	new->param_router_lifetime = router_lifetime;
	new->param_reachable_timer = reachable_timer;
	new->param_retrans_timer   = retrans_timer;
	new->param_mtu   = mtu;
	new->params_volatile = p_volatile;
	new->addresses = NULL;
	new->prefixes = NULL;
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

int router_add_prefix(router_list_t *list, uint16_t vlan_id, struct in6_addr lla, struct ether_addr eth, struct in6_addr prefix, int mask, 
	uint8_t flags_reserved, uint32_t valid_lifetime, uint32_t preferred_lifetime)
{
	router_list_t *tmp = list;
	prefix_t *new, *ptmp = NULL;

	if( (new=(prefix_t *)malloc(sizeof(prefix_t))) == NULL)
	{
		perror("malloc");
		return 0;
	}

	new->prefix               = prefix;
	new->mask                 = mask;
	new->param_flags_reserved = flags_reserved;
	new->param_valid_time     = valid_lifetime;
	new->param_preferred_time = preferred_lifetime;
	new->next=NULL;

	tmp = router_get(list,  vlan_id, lla, eth);
	if (tmp==NULL) return 0;

	ptmp = tmp->prefixes;
	if(ptmp == NULL) {
		tmp->prefixes = new;
	} else {
		while(ptmp->next != NULL) {
			ptmp=ptmp->next;
		}
		ptmp->next=new;
	}
	return 1;
}


prefix_t* router_get_prefix(router_list_t *list, uint16_t vlan_id, struct in6_addr lla, struct ether_addr eth, struct in6_addr prefix, int mask)
{
	router_list_t* router = router_get(list, vlan_id, lla, eth);
	prefix_t *ptmp;

	if (router==NULL) {
		return NULL;
	}
	ptmp = router->prefixes;
	while(ptmp != NULL) {
		if( (ptmp->mask == mask) && (IN6_ARE_ADDR_EQUAL(&prefix,&(ptmp->prefix))) ) {
			return ptmp;
		}
		ptmp = ptmp->next;
	}
	return NULL;
}

int router_has_prefix(router_list_t *list, uint16_t vlan_id, struct in6_addr lla, struct ether_addr eth, struct in6_addr prefix, int mask) {
        if (router_get_prefix(list, vlan_id, lla, eth, prefix, mask)==NULL) {
		return 0;
	}
	return 1;
}


int router_add_address(router_list_t *list, uint16_t vlan_id, struct ether_addr eth, struct in6_addr addr)
{
	router_list_t *tmp = list;
	address_t *new = NULL;

	
	if(router_has_address(list,vlan_id,eth,addr))
	{
		fprintf(stderr,"Address already in list\n");
		return 0;
	}
	

	if( (new=(address_t *)malloc(sizeof(address_t))) == NULL)
	{
		perror("malloc");
		return 0;
	}

	new->address = addr;
	new->next=NULL;

	while(tmp != NULL)
	{
		if(!MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
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
		else
			tmp = tmp->next;
	}
	
	return 0;
}


int router_has_address(router_list_t *list, uint16_t vlan_id, struct ether_addr eth, struct in6_addr addr)
{
	router_list_t *tmp = list;
	while(tmp != NULL)
	{
		if(in_vlan(tmp, vlan_id) && !MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
		{
				address_t *atmp = tmp->addresses;
				while(atmp != NULL)
				{
					if( IN6_ARE_ADDR_EQUAL(&addr,&(atmp->address)) )
						return 1;

					atmp = atmp->next;
				}
				return 0;
		}
		tmp = tmp->next;
	}
	return 0;
}

int nb_router(router_list_t *routers)
{
	int n = 0;
	router_list_t *tmp = routers;

	while(tmp != NULL)
	{
		n++;
		tmp=tmp->next;
	}

	return n;
}


void print_routers(router_list_t *list)
{
	router_list_t *tmp = list;
	while(tmp != NULL)
	{
		char eth[ETH_ADDRSTRLEN+1], lla[INET6_ADDRSTRLEN+1];
		prefix_t *ptmp = tmp->prefixes;
		address_t *atmp = tmp->addresses;

		ipv6_ntoa(lla,tmp->lla);
		strncpy(eth,ether_ntoa(&(tmp->mac)), ETH_ADDRSTRLEN);
		fprintf(stderr,"Router (VLAN%d, %s,%s) :\n", tmp->vlan_id, eth, lla);
		fprintf(stderr,"    RA params:\n");
		fprintf(stderr,"        curhoplimit:     %u\n", tmp->param_curhoplimit);
		fprintf(stderr,"        flags:           [");
		if (tmp->param_flags_reserved&ND_RA_FLAG_MANAGED) {
			fprintf(stderr,"MANAGED ");
		}
		if (tmp->param_flags_reserved&ND_RA_FLAG_OTHER) {
			fprintf(stderr,"OTHER ");
		}
		if (tmp->param_flags_reserved&ND_RA_FLAG_HOME_AGENT) {
			fprintf(stderr,"HOME_AGENT ");
		}
		fprintf(stderr,"]\n");
		fprintf(stderr,"        router lifetime: %u\n", tmp->param_router_lifetime);
		fprintf(stderr,"        reachable timer: %u\n", tmp->param_reachable_timer);
		fprintf(stderr,"        retrans timer:   %u\n", tmp->param_retrans_timer);
		if (tmp->param_mtu>0) {
			fprintf(stderr,"        mtu:             %u\n", tmp->param_mtu);
		}
		if (tmp->params_volatile==0) {
			fprintf(stderr,"        Parameters of future Router Advertisements will be\n");
			fprintf(stderr,"        checked against those stored in the router list.\n");			
		}
		fprintf(stderr,"    Address(es):\n");
		while(atmp != NULL)
		{
			char addr[48];
			ipv6_ntoa(addr,atmp->address);
			fprintf(stderr,"        %s\n", addr);
			atmp=atmp->next;
		}
		fprintf(stderr,"    Prefix(es):\n");
		while(ptmp != NULL)
		{
			char prefix[64];
			ipv6_ntoa(prefix,ptmp->prefix);
			sprintf(prefix,"%s/%d", prefix,ptmp->mask);
			fprintf(stderr,"        %s\n", prefix);
			fprintf(stderr,"            flags:          [");
			if (ptmp->param_flags_reserved&ND_OPT_PI_FLAG_ONLINK) {
				fprintf(stderr,"ONLINK ");
			}
			if (ptmp->param_flags_reserved&ND_OPT_PI_FLAG_AUTO) {
				fprintf(stderr,"AUTO ");
			}
			if (ptmp->param_flags_reserved&ND_OPT_PI_FLAG_RADDR) {
				fprintf(stderr,"RADDR ");
			}
			fprintf(stderr,"]\n");
			fprintf(stderr,"            valid time:     %u\n", ptmp->param_valid_time);
			fprintf(stderr,"            preferred time: %u\n", ptmp->param_preferred_time);
			ptmp=ptmp->next;
		}
		fprintf(stderr,"\n");
		tmp=tmp->next;
	}
}

int clean_router_prefixes(router_list_t **list, struct ether_addr eth)
{
	router_list_t *tmp = *list;

	while(tmp != NULL)
	{
		if(!MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
		{
			prefix_t *ptmp = tmp->prefixes, *ptodel = NULL;

			while( ptmp != NULL)
			{
				ptodel = ptmp;
				ptmp = ptmp->next;
				free(ptodel);
			}

			return 1;
		}

		tmp = tmp->next;
	}

	return 0;
}


int clean_router_addresses(router_list_t **list, struct ether_addr eth)
{
	router_list_t *tmp = *list;

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

int clean_routers(router_list_t **list)
{
	router_list_t *tmp = *list, *rtodel = NULL;

	while(tmp != NULL)
	{
		rtodel = tmp;
		clean_router_addresses(list,tmp->mac);
		clean_router_prefixes(list,tmp->mac);
		tmp = tmp->next;
		free(rtodel);
	}

	return 1;
}

#if 0 

REMOVED COMPLICATED FUNCTIONS

int is_router_in(router_list_t *list, struct in6_addr lla, struct ether_addr eth)
{
	router_list_t *tmp = list;

	while(tmp != NULL)
	{
		if(!MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
			if(IN6_ARE_ADDR_EQUAL(&lla,&(tmp->lla)))
				return 1;

		tmp = tmp->next;
	}

	return 0;
}



router_list_t * get_router_lla_in(router_list_t *list, struct in6_addr lla)
{
	router_list_t *tmp = list;

	while(tmp != NULL)
	{
		if(IN6_ARE_ADDR_EQUAL(&lla,&(tmp->lla)))
			return tmp;

		tmp = tmp->next;
	}

	return NULL;
}

router_list_t * get_router_mac_in(router_list_t *list, struct ether_addr eth)
{
	router_list_t *tmp = list;

	while(tmp != NULL)
	{
		if(!MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
			return tmp;

		tmp = tmp->next;
	}

	return NULL;
}


int add_router(router_list_t **list, struct in6_addr lla, struct ether_addr eth)
{
	router_list_t *tmp = *list,*new=NULL;

	if(is_router_in(*list,lla,eth))
	{
		fprintf(stderr,"Router already in list\n");
		return 0;
	}

	if( (new=(router_list_t *)malloc(sizeof(router_list_t))) == NULL)
	{
		perror("malloc");
		return 0;
	}

	new->mac = eth;
	new->lla = lla;
	new->addresses = NULL;
	new->prefixes = NULL;
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

int router_add_prefix(router_list_t **list, struct in6_addr lla, struct ether_addr eth, struct in6_addr prefix, int mask, 
	uint8_t flags_reserved, uint32_t valid_lifetime, uint32_t preferred_lifetime)
{
	router_list_t *tmp = *list;
	prefix_t *new = NULL;

	/*
	if(is_prefix_in(lla,eth,prefix))
	{
		fprintf(stderr,"Prefix already in list\n");
		return 0;
	}
	*/

	if( (new=(prefix_t *)malloc(sizeof(prefix_t))) == NULL)
	{
		perror("malloc");
		return 0;
	}

	new->prefix               = prefix;
	new->mask                 = mask;
	new->param_flags_reserved = flags_reserved;
	new->param_valid_time     = valid_lifetime;
	new->param_preferred_time = preferred_lifetime;
	new->next=NULL;

	while(tmp != NULL)
	{
		if(!MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
		{
			if(IN6_ARE_ADDR_EQUAL(&lla,&(tmp->lla)))
			{
				prefix_t *ptmp = tmp->prefixes;
				if(ptmp == NULL)
					tmp->prefixes = new;
				else
				{
					while(ptmp->next != NULL)
						ptmp=ptmp->next;
					ptmp->next=new;
				}
				return 1;
			}
		}
		else
			tmp = tmp->next;
	}
	
	return 0;
}


int router_has_prefix(router_list_t *list, struct in6_addr lla, struct ether_addr eth, struct in6_addr prefix, int mask)
{
	router_list_t *tmp = list;
	while(tmp != NULL)
	{
		if(!MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
		{
			if(IN6_ARE_ADDR_EQUAL(&lla,&(tmp->lla)))
			{
				prefix_t *ptmp = tmp->prefixes;
				while(ptmp != NULL)
				{
					if( (ptmp->mask == mask) && (IN6_ARE_ADDR_EQUAL(&prefix,&(ptmp->prefix))) )
						return 1;

					ptmp = ptmp->next;
				}
				return 0;
			}
		}
		tmp = tmp->next;
	}
	return 0;
}
#endif
