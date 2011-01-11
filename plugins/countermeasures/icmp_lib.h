#ifndef _ICMP_LIB_
#define _ICMP_LIB_

#define IPV6_FRAME_TYPE 0x86dd
#define FAILURE -1

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "icmp_lib_nd.h"

/** @file
    Creating IP and ICMP headers and comosition and sending of packets.
*/

/** IPv6 Link Local scope. Required for create_in6_addr_for_interface. */
#define IPV6_LINKLOCAL 0x20
/** IPv6 Global scope.  Required for create_in6_addr_for_interface. */
#define IPV6_GLOBAL 0x00
/** Path to the proc file containing inet6 interface information. Required for create_in6_addr_for_interface.*/
#define PATH_PROC_INET "/proc/net/if_inet6"

/*  All * create... function failed if NULL is returned.
    All int function fail if FAILURE is returned.
*/

struct icmp_nd_opt_list;

/** Allocates a new ip6_hdr and sets source and destination address.*/
struct ip6_hdr*   create_ip6_hdr(struct in6_addr* destaddr, struct in6_addr* srcaddr);

/** Allocates a new icmp6_hdr and sets the type and code field.
    The allocated memory size differs for each ICMP ND type.
*/
struct icmp6_hdr* create_icmp6_hdr(uint8_t type, uint8_t code);

/** Sets the IPv6 header fields for the next header to be an ICMP package
    and sets the payload value according to the ICMP packet length.

    This works only if no further extension headers are provided.
    packet_length is just the payload length of the ICMP packet (without ethernet+ip header).

*/
int set_ip6_hdr_fields(struct ip6_hdr* iphdr, int packet_length);

/** Sets the ICMP header checksum field.
    Should not be called if there is still content to be added to the package.
*/
int set_icmp6_hdr_checksum(struct ip6_hdr* iphdr, struct icmp6_hdr* icmphdr, struct icmp_nd_opt_list* options);

/** ICMP checksum calculation given a field of data.
    Taken from THC.
    see also: checksum_pseudo_header for creating the pseuso header.
*/
int checksum_for_data(unsigned char *data, int data_len);

/** Creates the IPv6 pseudo header and calls calculate_checksum() for the resulting field.
    Taken from THC.
    See also http://tools.ietf.org/html/rfc2460#section-8.1 (IPv6 pseudo header)
*/
int checksum_pseudo_header(unsigned char *src, unsigned char *dst, unsigned char *data, int length);

/** Gets the right size for each ICMP ND Header Type.
*/
int get_icmp_nd_hdr_length(uint8_t type);

/** Computes the actual packet length according to
    all data contained in the structure.
    This works currently only for ND packets.
*/
int get_icmp_packet_length(struct icmp6_hdr* icmphdr, struct icmp_nd_opt_list* options);

/** Composes the IP/ICMP packet from the data structures.
    The right size is calculated using get_icmp_packet_length()
    This works currently only for ND packets.
*/
int compose_packet(struct ether_addr* dst_mac, struct ether_addr* src_mac, struct ip6_hdr* iphdr, struct icmp6_hdr* icmphdr, struct icmp_nd_opt_list* options, uint8_t** packet, int* packet_length);

/** Send the IP/ICMP packet using a socket.
*/
int send_packet(char* interface, uint8_t* packet, int packet_length);

/** This creates a packet from the given data structures and sends it to the interface.
    Returns the number of bytes sent or FAILURE.
    This works currently only for ND packets.
*/
int compose_and_send_icmp_packet(
    char* interface,
    struct ether_addr* dst_mac,
    struct ether_addr* src_mac,
    struct ip6_hdr* iphdr,
    struct icmp6_hdr* icmphdr,
    struct icmp_nd_opt_list* options
    );

/** Converts human readable node identifiers to their memory representations
    using POSIX functions getaddrinfo and getnameinfo.
    Taken with minor changes from THC.
*/ 
struct in6_addr* create_in6_addr(char* target);

/** Opens a socket to the specified interface and returns its IP address.
    The interface is supposed to use IPv6, else you get undefined behaviour.
    Made up, hope it works.
*/
struct in6_addr* create_in6_addr_for_interface(char *interface);

/** Opens a socket to the specified interface and returns its MAC address.
    If the allocation for the MAC struct or something else fails, NULL is returned.
    Taken from THC.
*/
struct ether_addr* create_mac_for_interface(char *interface);

/** Creates a multicast MAC for the given IP.
    The multicast MAC consists of: 33:33:(last-four-octets-of-IP-addr).
    Taken from THC.
*/
struct ether_addr* create_multicast_mac_for_ip(struct in6_addr* ipaddr);

/** Type for hook functions treating the IP/ICMP data.
*/
typedef void (*packet_hook) (uint8_t** packet, int* packet_length);

/** Sets a hook function that will be invoked before a packet is send.
    This may be used to extent the functions of this library.
    Remember to re-calculate the checksum if you modifiy the package.
    @param hook The hook function.
*/
void set_on_sending_hook(packet_hook hook);


#endif
