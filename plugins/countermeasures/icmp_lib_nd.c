#include "icmp_lib_nd.h"

struct nd_router_advert* create_icmp_router_advertisement(uint8_t curhoplimit, uint8_t flags_reserved, uint16_t router_lifetime, uint32_t reachable_timer, uint32_t retrans_timer) {
    struct nd_router_advert *routeradv = (struct nd_router_advert *)create_icmp6_hdr(ND_ROUTER_ADVERT, 0);
    if (routeradv==NULL)
        return NULL;
    /* 8 bit values, no endian conversion needed: */
    routeradv->nd_ra_curhoplimit = curhoplimit;
    routeradv->nd_ra_flags_reserved = flags_reserved;
    /* endian conversion needed: */
    routeradv->nd_ra_router_lifetime = htons(router_lifetime);
    routeradv->nd_ra_reachable = htonl(reachable_timer);
    routeradv->nd_ra_retransmit = htonl(retrans_timer);
    return routeradv;
}

struct nd_neighbor_advert* create_icmp_neighbor_advertisement(uint32_t flags_reserved, struct in6_addr* target_address) {
    struct nd_neighbor_advert *neighboradv = (struct nd_neighbor_advert *)create_icmp6_hdr(ND_NEIGHBOR_ADVERT, 0);
    if (neighboradv==NULL || target_address==NULL)
        return NULL;
    /* icmp6.h defines generously take care of byte order, so just assign flags:
       (and hope for heaven's sake that the average Joe developer did RTFM and didn't already call hton...) ;)
    */
    neighboradv->nd_na_flags_reserved = flags_reserved;
    /* Copy target address. */
    memcpy(&neighboradv->nd_na_target, target_address, sizeof(struct in6_addr));
    return neighboradv;
}

struct nd_ndpmon_present* create_icmp_ndpmon_present(uint8_t version_major, uint8_t version_minor, uint8_t version_build, uint8_t flags) {
    struct nd_ndpmon_present *ndpmon_present = (struct nd_ndpmon_present *)create_icmp6_hdr(ND_NDPMON_PRESENT, ND_NP_CODE);
    if (ndpmon_present==NULL) {
        return NULL;
    }
    ndpmon_present->nd_np_version_major = version_major;
    ndpmon_present->nd_np_version_minor = version_minor;
    ndpmon_present->nd_np_version_build = version_build;
    ndpmon_present->nd_np_flags = flags;
    return ndpmon_present;
}

struct nd_opt_prefix_info* create_nd_opt_prefix_info(struct in6_addr* prefix, uint8_t prefix_length, uint8_t flags_reserved, uint32_t valid_time, uint32_t preferred_time) {
    /* preparation for the prefix initialization */
    uint8_t bits_to_zero   = 128 - prefix_length;
    uint8_t bytes_to_zero  = bits_to_zero / 8;
    uint8_t remaining_bits = bits_to_zero % 8; 
    uint8_t* prefixptr;
    /* creating prefix info */
    struct nd_opt_prefix_info *prefix_info;
    if ((prefix_info=malloc(sizeof(struct nd_opt_prefix_info)))==NULL || prefix==NULL) {
        return NULL;
    }
    /* 8 bit values, no conversion needed: */
    prefix_info->nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
    prefix_info->nd_opt_pi_len = 4;
    prefix_info->nd_opt_pi_prefix_len = prefix_length;
    prefix_info->nd_opt_pi_flags_reserved = flags_reserved;
    /* 32 bit values, endian conversion needed: */
    prefix_info->nd_opt_pi_valid_time = htonl(valid_time);
    prefix_info->nd_opt_pi_preferred_time = htonl(preferred_time);
    /* copying prefix */
    prefixptr = (uint8_t*) &prefix_info->nd_opt_pi_prefix;
    memcpy(prefixptr, prefix, sizeof(struct in6_addr));
    /* setting unused bits of prefix to zero */
    if (remaining_bits > 0) {
        bytes_to_zero++;
    }
    memset(prefixptr + 16 - bytes_to_zero, 0, bytes_to_zero);
    if (remaining_bits > 0) {
        prefixptr[17-bytes_to_zero] = (prefixptr[17-bytes_to_zero] >> (8-remaining_bits)) << (8-remaining_bits);
    }
    return prefix_info;
}

struct nd_opt_link_layer_addr* create_nd_opt_link_layer(int option_type, struct ether_addr* mac) {
    struct nd_opt_link_layer_addr* link_layer_addr;
    if ( (option_type!=ND_OPT_SOURCE_LINKADDR) && (option_type!=ND_OPT_TARGET_LINKADDR) ) {
        return NULL;
    }
    if ((link_layer_addr = malloc(sizeof(struct nd_opt_link_layer_addr)))==NULL) {
        return NULL;
    }
    /* 8 bit values, no endian conversion needed: */
    link_layer_addr->nd_opt_type = option_type;
    link_layer_addr->nd_opt_len = 1;
    memcpy(&link_layer_addr->link_layer_addr, mac, sizeof(struct ether_addr));
    return link_layer_addr;
}

struct nd_opt_mtu* create_nd_opt_mtu(uint16_t reserved, uint32_t p_mtu) {
    struct nd_opt_mtu* mtu;
    if ((mtu = malloc(sizeof(struct nd_opt_mtu)))==NULL) {
        return NULL;
    }
    mtu->nd_opt_mtu_type = ND_OPT_MTU;
    mtu->nd_opt_mtu_len  = 1;
    /* 16 and 32 bit values; endian conversion needed: */
    mtu->nd_opt_mtu_reserved = htons(reserved);
    mtu->nd_opt_mtu_mtu      = htonl(p_mtu);
    return mtu;
}

int add_icmp_nd_opt(struct icmp_nd_opt_list** options, struct nd_opt_hdr* opt_hdr) {
    struct icmp_nd_opt_list* new;
    if (options==NULL)
        return FAILURE;
    if (opt_hdr==NULL)
        return FAILURE;
    if ((new=malloc(sizeof(struct icmp_nd_opt_list)))==NULL)
        return FAILURE;
    new->option = opt_hdr;
    new->next = *options;
    *options = new;
    return 0;
}

void free_icmp_nd_opt_list(struct icmp_nd_opt_list** options) {
    while (*options != NULL) {
        struct icmp_nd_opt_list* current = *options;
        (*options) = (*options)->next;
        free(current);
    }
}

