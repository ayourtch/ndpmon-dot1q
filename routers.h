#ifndef _ROUTER_LIST_H_
#define _ROUTER_LIST_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <signal.h>
#include <time.h>

#include "print_packet_info.h"
#include "ndpmon_defs.h"

/** Stores entries for the prefixes advertised by routers in the network.
    The structure members starting with param_ are used to determine
    whether the params of a RA prefix info option are valid.
*/
typedef struct prefix{
        /** The prefix address.*/
        struct in6_addr prefix;
        /** The number of valid bits in the prefix address.*/
	int mask;
	/** RA param: Prefix preferred time.*/
	uint8_t param_flags_reserved;
	/** RA param: Prefix valid time.*/
	uint32_t param_valid_time;
	/** RA param: Prefix preferred time.*/
	uint32_t param_preferred_time;
        /** Pointer to the next prefix list entry.*/
	struct prefix *next;
}prefix_t;

/** Stores entries for the legitimate routers in the network.
    The members starting with "param_" are used to determine whether
    the RA params are wellformed and to send faked RA in the counter measures plugin.
*/
typedef struct router_list{
	/** The routers ETHERNET address.*/
	struct ether_addr mac;
	/** The router link local address.*/
	struct in6_addr lla;
	/** RA param: Current hop limit (default time to live).*/
	uint8_t  param_curhoplimit;
	/** RA param: M+O flag and reserved 6 bits.*/
	uint8_t  param_flags_reserved;
	/** RA param: Router lifetime.*/
	uint16_t param_router_lifetime;
	/** RA param: Reachable timer.*/
	uint32_t param_reachable_timer;
	/** RA param: Retransmission timer.*/
	uint32_t param_retrans_timer;
	/** RA param (optional): Maximum transmission unit.*/
	uint32_t param_mtu;
        /** Indicates whether the params of this router may change during operation.
	    If this is set to zero, NDPMon checks the params of captured RA (including prefix
	    lifetimes and the MTU option) against the values learned and stored in this list.
	*/
	int params_volatile;
	/** Pointer to the list of IP addresses for this router. */
	address_t *addresses;
	/** Pointer to the list of prefixes for this router.*/
	prefix_t *prefixes;
	/** Pointer to the next router list entry.*/
	struct router_list *next;
}router_list_t;

router_list_t * router_get(router_list_t *list, struct in6_addr lla, struct ether_addr eth);

int is_router_lla_in(router_list_t *list, struct in6_addr lla);
int is_router_mac_in(router_list_t *list, struct ether_addr eth);
int router_has_router(router_list_t *list, struct in6_addr lla, struct ether_addr eth);

/** Adds a router to the list a routers.
    Changed in order to take the additional router parameters.
    @param list The list of routers.
    @param eth  Pointer to the ETHERNET address of the router.
    @param lla  Pointer to the link local address (not to be confused with link layer address).
    @param curhoplimit         RA Parameter: The current hop limit.
    @param flags_reserved      RA Parameter: M+O flag and reserved bits.
    @param router_lifetime     RA Parameter: Router lifetime.
    @param reachable_timer     RA Parameter: Reachable timer.
    @param retrans_timer RA Parameter: Retransmission timer.
*/
int router_add(router_list_t **list, struct ether_addr* eth, struct in6_addr* lla,
        uint8_t curhoplimit, uint8_t flags_reserved, uint16_t router_lifetime, uint32_t reachable_timer, uint32_t retrans_timer, uint32_t param_mtu, int params_volatile);
int router_add_prefix(router_list_t *list, struct in6_addr lla, struct ether_addr eth, struct in6_addr prefix, int mask, uint8_t flags_reserved, uint32_t valid_lifetime, uint32_t preferred_lifetime);
int router_has_prefix(router_list_t *list, struct in6_addr lla, struct ether_addr eth, struct in6_addr prefix, int mask);
prefix_t* router_get_prefix(router_list_t *list, struct in6_addr lla, struct ether_addr eth, struct in6_addr prefix, int mask);

int router_has_address(router_list_t *list, struct ether_addr eth, struct in6_addr addr);
int router_add_address(router_list_t *list, struct ether_addr eth, struct in6_addr addr);

int nb_router(router_list_t *routers);
void print_routers(router_list_t *list);

int clean_router_prefixes(router_list_t **list, struct ether_addr eth);
int clean_router_addresses(router_list_t **list, struct ether_addr eth);
int clean_routers(router_list_t **list);

#endif
