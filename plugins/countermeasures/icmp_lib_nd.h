#ifndef _ICMP_LIB_ND_
#define _ICMP_LIB_ND_

#include "icmp_lib.h"

/** @file
    Convenient functions to create ND messages.
*/

/** This is a linked list type for
    the nd options following the nd header.
*/
struct icmp_nd_opt_list {
    /**  A pointer to the ICMP ND option.*/
    struct nd_opt_hdr* option;
    /** A pointer to the next list entry.*/
    struct icmp_nd_opt_list* next;
};


/** In addition to icmp6.h we define this symbol
    because they omitted this opt type. Hopefully this
    does not result in name conflicts if the option type
    is included in later versions of this header.
    Currently this type only supports ethernet link layer addresses.
*/
struct nd_opt_link_layer_addr {
    /** The ICMP ND option type. Must be either 1 or 2.*/
    uint8_t  nd_opt_type;
    /** The Option length (in units of 8 octets), must be 1.*/
    uint8_t  nd_opt_len;
    /** The ethernet address.*/
    struct ether_addr link_layer_addr;
};

/** ND option type for NDPMon presence indication.
    The value 200 is reserved for private experimentation,
    see also http://www.iana.org/assignments/icmpv6-parameters .
*/
#define ND_NDPMON_PRESENT 200
/** The code is used to prevent this message from interfering with
    other usages of type 200.*/
#define ND_NP_CODE 200

/** In addition to icmp6.h ze define this symbol
    to indicate the presence of NDPMon on a link.
    This is intended to inform administrators if multiple 
    instances of NDPMon are running on the same link.
    Multiple NDPMon instances may interfere if counter-measures are activated.
*/
struct nd_ndpmon_present {
    /** The icmp header.*/
    struct icmp6_hdr  nd_np_hdr;
};

#define nd_np_type               nd_np_hdr.icmp6_type
#define nd_np_code               nd_np_hdr.icmp6_code
/** The version major field of a NDPMon presence indication (NP).*/
#define nd_np_version_major nd_np_hdr.icmp6_data8[0]
/** The version minor field of a NP.*/
#define nd_np_version_minor nd_np_hdr.icmp6_data8[1]
/** The version build field of a NP.*/
#define nd_np_version_build nd_np_hdr.icmp6_data8[2]
/** Flag field of a NP. These flags indicate the state and configuration of the instance: L-x-x-x-x-x-M-C 

    (L: Instance is in learning phase.
    M: Instance has mac_resolv plugin enabled.
    C: Instance has counter_measures plugin enabled.
    x: Reserved.)
*/
#define nd_np_flags nd_np_hdr.icmp6_data8[3]
#define ND_NP_FLAG_LEARNING_PHASE   0x80
#define ND_NP_FLAG_COUNTER_MEASURES 0x02
#define ND_NP_FLAG_MAC_RESOLV       0x01

/** Creates a new router advertisement header (without options).
    Do NOT treat its params with the hton functions, icmp_lib takes care of this.
    @param curhoplimit     The current hoplimit (aka default TTL).
    @param flags_reserved  The M+O flag and 6 bits reserved.
                           Tip: Use the icmp6.h defines ND_RA_FLAG_MANAGED and ND_RA_FLAG_OTHER to set the flags.
    @param router_lifetime The router lifetime.
    @param reachable_timer Reachable timer.
    @param retrans_timer   Retransmission timer.
    @return Pointer to the allocated and created RA or NULL if failed.
*/
struct nd_router_advert* create_icmp_router_advertisement(uint8_t curhoplimit, uint8_t flags_reserved, uint16_t router_lifetime, uint32_t reachable_timer, uint32_t retrans_timer);

/** Creates a new neighbor advertisement header (without options).
    Do NOT treat the flags with the hton functions, but use the icmp6.h defines like ND_NA_FLAG_ROUTER. The guys took care of byte order.
    @param flags_reserved R+S+O flags and reserved bits.
    @param target_address Pointer to the target IP of this NA.
    @return Pointer to the allocated and created NA or NULL if failed.    
*/
struct nd_neighbor_advert* create_icmp_neighbor_advertisement(uint32_t flags_reserved, struct in6_addr* target_address);

/** Creates an ICMP message header to indicate NDPMon's presence on a link.
    @param version_major Version major like 1.-.-
    @param version_minor Version minor like -.1.-
    @param version_build Version build like -.-.1
    @param flags         Flags.
    @return Pointer to the allocated and created NP or NULL if failed.
*/
struct nd_ndpmon_present* create_icmp_ndpmon_present(uint8_t version_major, uint8_t version_minor, uint8_t version_build, uint8_t flags);

/** Creates a new prefix information option.
    Returns a pointer to the struct or NULL if failed.
    Prefix initialization strongly influenced by THC.
    Do NOT treat its params with the hton functions, icmp_lib takes care of this.
    @param prefix         Pointer to the prefix.
    @param prefix_length  Number of relevant bits of the prefix (mask).
    @param flags_reserved The L+A flag and 6 bits reserved.
                          Tip: Use the icmp6.h defines ND_OPT_PI_FLAG_ONLINK and ND_OPT_PI_FLAG_AUTO to set the flags.
    @param valid_time     The valid time of this prefix.
    @param preferred_time The preferred time of this prefix.
    @return Pointer to the allocated and created prefix information or NULL if failed.
*/
struct nd_opt_prefix_info* create_nd_opt_prefix_info(struct in6_addr* prefix, uint8_t prefix_length, uint8_t flags_reserved, uint32_t valid_time, uint32_t preferred_time);

/** Creates a new option for source or target link layer address.
    @param option_type Must be 1 for source or 2 for target link layer address. Other values are rejected.
    @param mac         Pointer to the link layer address.
    @return Pointer to the allocated and created prefix information or NULL if failed.
*/
struct nd_opt_link_layer_addr* create_nd_opt_link_layer(int option_type, struct ether_addr* mac);

/** Creates a new mtu (maximum transmission unit) option.
    Do NOT treat its params with the hton functions, icmp_lib takes care of this.
    @param reserved Reserved.
    @param p_mtu    The maximum transmission unit.
    @return Pointer to the allocated and created mtu option or NULL if failed.
*/
struct nd_opt_mtu* create_nd_opt_mtu(uint16_t reserved, uint32_t p_mtu);

/** Adds a nd_opt_hdr to the linked list.
    The option added last will be sent first.
    Beaware that the pointer to the linked list is changed.
    @param options Call-by-reference with the pointer to the list of options.
    @param opt_hdr The option to be added to the list.
                   It is not copied, so don't free the pointer, unless you don't need the option list anymore. See also free_icmp_nd_opt_list().
    @return 0 on success, -1 on failure.
*/
int add_icmp_nd_opt(struct icmp_nd_opt_list** options, struct nd_opt_hdr* opt_hdr);

/** Frees all entries of the linked list of ICMP ND options.
    @param options Call-by-reference with the pointer to the list of options.
*/
void free_icmp_nd_opt_list(struct icmp_nd_opt_list** options);

#endif
