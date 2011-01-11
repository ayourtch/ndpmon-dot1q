#ifndef _NEIGHBOR_LIST_H_
#define _NEIGHBOR_LIST_H_

#include "routers.h"
#include "ndpmon_defs.h"
#include "membounds.h"

#ifdef _MACRESOLUTION_
#include "./plugins/mac_resolv/mac_resolv.h"
#endif

typedef struct ethernet{
        struct ether_addr mac;
#ifdef _MACRESOLUTION_
	char vendor[MANUFACTURER_NAME_SIZE];
#endif
	struct ethernet *next;
}ethernet_t;

typedef struct neighbor_list{
	struct ether_addr mac;
/* ADDED*/
	struct ether_addr first_mac_seen;
	int trouble;
/* END ADDED */
#ifdef _MACRESOLUTION_
	char vendor[MANUFACTURER_NAME_SIZE];
#endif
	struct ether_addr previous_mac;
	ethernet_t *old_mac;
	struct in6_addr lla;
	address_t *addresses;
	time_t timer;
	struct neighbor_list *next;
}neighbor_list_t;


int add_neighbor(neighbor_list_t **list, struct ether_addr eth);
int del_neighbor(neighbor_list_t **list, struct ether_addr eth);

int neighbor_update_mac(neighbor_list_t **list, struct in6_addr lla, struct ether_addr new_mac);
int neighbor_has_old_mac(neighbor_list_t *list, struct in6_addr lla, struct ether_addr old_mac);

int set_neighbor_lla(neighbor_list_t **list, struct ether_addr eth, struct in6_addr lla);
int neighbor_has_lla(neighbor_list_t *list, struct ether_addr eth, struct in6_addr lla);

int add_neighbor_old_mac(neighbor_list_t **list, struct in6_addr lla, struct ether_addr eth);
int del_neighbor_old_mac(neighbor_list_t **list, struct in6_addr lla, struct ether_addr eth);
struct ether_addr neighbor_get_last_mac(neighbor_list_t *list, struct in6_addr lla);
int neighbor_set_last_mac(neighbor_list_t **list, struct in6_addr lla, struct ether_addr eth);

int neighbor_has_ip(neighbor_list_t *list, struct ether_addr eth, struct in6_addr addr);
int add_neighbor_ip(neighbor_list_t **list, struct ether_addr eth, struct in6_addr addr);
int del_neighbor_ip(neighbor_list_t **list, struct ether_addr eth, struct in6_addr addr);

int is_neighbor_by_mac(neighbor_list_t *list, struct ether_addr eth);
int is_neighbor_by_lla(neighbor_list_t *list, struct in6_addr lla);
int is_neighbor_by_ip(neighbor_list_t *list, struct in6_addr addr);

neighbor_list_t * get_neighbor_by_mac(neighbor_list_t *list, struct ether_addr eth);
neighbor_list_t * get_neighbor_by_lla(neighbor_list_t *list, struct in6_addr lla);
neighbor_list_t * get_neighbor_by_ip(neighbor_list_t *list, struct in6_addr addr);

int reset_neighbor_timer(neighbor_list_t **list, struct ether_addr eth);
int set_neighbor_timer(neighbor_list_t **list, struct ether_addr eth, time_t value);

int reset_neighbor_address_timer(neighbor_list_t **list, struct ether_addr eth, struct in6_addr addr);
int set_neighbor_address_timer(neighbor_list_t **list, struct ether_addr eth, struct in6_addr addr, time_t value);
int set_neighbor_first_address_timer(neighbor_list_t **list, struct ether_addr eth, struct in6_addr addr, time_t value);


int nb_neighbor(neighbor_list_t *neighbors);
void print_neighbors(neighbor_list_t *list);

int clean_neighbor_old_mac(neighbor_list_t **list, struct ether_addr eth);
int clean_neighbor_addresses(neighbor_list_t **list, struct ether_addr eth);
int clean_neighbors(neighbor_list_t **list);

/* New Station ? */
int new_station(neighbor_list_t **list, struct ether_addr eth, struct in6_addr addr, int *new_eth);

#endif
