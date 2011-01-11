#ifndef _COUNTERMEASURES_H_
#define _COUNTERMEASURES_H_

#include <stdio.h>
#include <stdint.h>
#include "openssl/sha.h"
#include "../../routers.h"
#include "icmp_lib.h"
#include "countermeasures_on_link.h"
#include "countermeasures_guard.h"

/** @file
    Interface to the countermeasures plugin.
*/

/** This initializes the countermeasures plugin.
    As the watch function are not aware of the interface
    they use, the interface must be set once during startup.
    @param p_interface The interface to be used for sending counter measures.

    To be changed if multiple interfaces shall be used.
*/
void cm_init(char* p_interface);

/** Called each time the ICMP packet level library sends a packet.
    @param packet Pointer to a pointer to the packet, including ETHERNET and IP header.
    @param packet_length Length of the packet.
*/
void cm_on_sending_hook(uint8_t** packet, int* packet_length);

/** If NDPMon detected a illegitimate router advertisment,
    we may send a zero lifetime RA for this router.
    This router advertisement does not need any ND options.
    @param router_mac Pointer to the ETHERNET address of the router.
    @param router_ip Pointer to the IP address of the router.
    @return 0 on success, -1 otherwise.
*/
int cm_kill_illegitimate_router(struct ether_addr *router_mac, struct in6_addr *router_ip);

/** Sends a router advertisement for the given router and the given prefix,
    but sets the prefix valid and preferred lifetime to zero.
    Since we don't want to give false parameters for the legitimate router but just kill
    the wrong prefix, we must propagate the last known well-formed parameters for this router.
    @param router Pointer to the router list entry of this router containing the last known parameters.
    @param router_ip Pointer to the IP of the router to be used for the bogus prefix advertisement.
    @param wrong_prefix Pointer to the bogus prefix advertised.
    @param wrong_prefix_length Length of the bogus prefix.
    @return 0 on success, -1 otherwise.
*/
int cm_kill_wrong_prefix(router_list_t *router, struct in6_addr *router_ip, struct in6_addr *wrong_prefix, int wrong_prefix_length);

/** Sends a router advertisement for the given router containing the params
    as they are currently stored in the router list.
    @param router Pointer to the router list entry of this router containing the last known parameters.
    @param router_ip Pointer to the IP of the router to be used for the bogus prefix advertisement.
    @return 0 on success, -1 otherwise.
*/
int cm_propagate_router_params(router_list_t *router, struct in6_addr *router_ip);

/** Sends an IMCP message to all-nodes multicast which indicates NDPMons presence on this link.
*/
int cm_indicate_ndpmon_presence();

/** If a NDPMon presence indication is recieved, this watch function is called by the core's capture loopback.
    It prints out the contained information about the indicated NDPMon instance.
*/
int watch_ndpmon_present(char* buffer,  const u_char* packet, struct ether_header* eptr, struct ip6_hdr* ipptr, struct nd_ndpmon_present* ndpmon_present, int packet_len);

/** Sends a neighbor advertisement for the given neighbor with a target link layer address option
    indicating @c previous_mac from the given neighbor cache entry.
    @param neighbor Pointer to the neighbor cache entry.
    @param neighbor_ip The IP to be used as IP source and neighbor advertisement target IP.
    @return 0 on success, -1 otherwise.
*/
int cm_propagate_neighbor_mac(neighbor_list_t *neighbor, struct in6_addr *neighbor_ip);

#endif

