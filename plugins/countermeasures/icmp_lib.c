#include "icmp_lib.h"

static packet_hook hook_on_sending;

struct ip6_hdr* create_ip6_hdr(struct in6_addr* dstaddr, struct in6_addr* srcaddr) {
    struct ip6_hdr* iphdr;
    if ((iphdr = malloc(sizeof(struct ip6_hdr))) == NULL) {
        return NULL;
    }
    /* set source and destination address*/
    memcpy(&iphdr->ip6_src, srcaddr, sizeof(struct in6_addr));
    memcpy(&iphdr->ip6_dst, dstaddr, sizeof(struct in6_addr));
    /* ip version 6, traffic class and flow label set to zero. */
    iphdr->ip6_flow = htonl(0x60000000);
    /* initialize payload length with zero */
    iphdr->ip6_plen = 0;
    return iphdr;
}

struct icmp6_hdr* create_icmp6_hdr(uint8_t type, uint8_t code) {
    struct icmp6_hdr* icmphdr;
    if ((icmphdr = malloc(get_icmp_nd_hdr_length(type))) == NULL) {
        return NULL;
    }    
    icmphdr->icmp6_type = type;
    icmphdr->icmp6_code = code;
    icmphdr->icmp6_cksum = 0; 
    return icmphdr;
}

int set_ip6_hdr_fields(struct ip6_hdr* iphdr, int packet_length) {
    /* set next extension header to icmp */
    iphdr->ip6_nxt = 58;
    /* set hop limit to 255, required for neighbor discocvery.*/
    iphdr->ip6_hlim  = 255;
    /* set payload length according to icmp-packet length.*/
    iphdr->ip6_plen  = htons(packet_length);
    return 0;
}

int set_icmp6_hdr_checksum(struct ip6_hdr* iphdr, struct icmp6_hdr* icmphdr, struct icmp_nd_opt_list* options) {
    uint8_t *data = NULL;
    uint8_t *ptr = NULL;
    int checksum=0;
    int options_offset = get_icmp_nd_hdr_length(icmphdr->icmp6_type);
    /* First we compose the ICMP package. */
    if ((data=malloc(get_icmp_packet_length(icmphdr, options)))==NULL) {
        return FAILURE;
    }
    /* Copy ICMP header. */
    memcpy(data+0, icmphdr, options_offset);
    /* Copy ICMP ND options. */
    while (options!= NULL) {
        memcpy(data+options_offset, options->option, options->option->nd_opt_len*8);
        options_offset += options->option->nd_opt_len*8;
        options = options->next;
    }
    /* After this option_offset contains the ICMP packet size. */
    /*icmphdr->icmp6_cksum =*/
    checksum = 
        checksum_pseudo_header(
            (unsigned char*) &iphdr->ip6_src,
            (unsigned char*) &iphdr->ip6_dst,
            (unsigned char*) data,
            options_offset
        );
    ptr = (uint8_t*)(&icmphdr->icmp6_cksum);
    ptr[0] = checksum/256;
    ptr[1] = checksum%256;
    free(data);
    return (icmphdr->icmp6_cksum == 0) ? FAILURE : 0;
}

int checksum_for_data(uint8_t *data, int data_len) {
  int i=0, checksum=0;

  while (i < data_len) {
    if (i++ % 2 == 0)
      checksum += *data++;
    else
      checksum += *data++ << 8;
  }
  checksum = (checksum & 0xffff) + (checksum >> 16);
  checksum = htons(~checksum);
  return checksum;
}


int checksum_pseudo_header(unsigned char *src, unsigned char *dst, unsigned char *data, int length) {
    uint8_t* ptr;
    int checksum=0;
    if ((ptr=malloc(40 + length))== NULL) {
      return 0;
    }
    memset(ptr, 0, 40 + length);
    memcpy(ptr+0, src, 16);
    memcpy(ptr+16, dst, 16);
    ptr[34] = length / 256;
    ptr[35] = length % 256;
    ptr[39] = 58; /* next header ICMP type */
    if (data != NULL && length > 0) {
        memcpy(ptr+40, data, length);
    }
    checksum = checksum_for_data(ptr, 40 + length);
    free(ptr);
    return checksum;
}

int get_icmp_nd_hdr_length(uint8_t type) {
    switch (type) {
        case (ND_ROUTER_SOLICIT):
            return sizeof(struct nd_router_solicit);
        case (ND_ROUTER_ADVERT):
            return sizeof(struct nd_router_advert);
        case (ND_NEIGHBOR_SOLICIT):
            return sizeof(struct nd_neighbor_solicit);
        case (ND_NEIGHBOR_ADVERT):
            return sizeof(struct nd_neighbor_advert);
        case (ND_REDIRECT):
            return sizeof(struct nd_redirect);
        case (ND_NDPMON_PRESENT):
            return sizeof(struct nd_ndpmon_present);
        default:
            return FAILURE; /*type not supported*/
    }
}

int get_icmp_packet_length(struct icmp6_hdr* icmphdr, struct icmp_nd_opt_list* options) {
    /* initialize with header length */
    int length=get_icmp_nd_hdr_length(icmphdr->icmp6_type);
    /* add options length */
    while (options!=NULL) {
        length += (options->option)->nd_opt_len*8;
        options = options->next;
    }
    return length;
}

int compose_packet(struct ether_addr* dst_mac, struct ether_addr* src_mac, struct ip6_hdr* iphdr, struct icmp6_hdr* icmphdr, struct icmp_nd_opt_list* options, uint8_t** packet, int* packet_length) {
    const int eth_offset = 14;
    /* Get ICMP header length according to ICMP ND message type. */
    int icmp_nd_hdr_length = get_icmp_nd_hdr_length(icmphdr->icmp6_type);
    /* Calculate options offset*/
    int options_offset=eth_offset+sizeof(*iphdr)+icmp_nd_hdr_length;
    /* Allocate offset + 40 (fixed IP header length) + ICMP packet length. */
    *packet_length = eth_offset + sizeof(*iphdr)+get_icmp_packet_length(icmphdr, options);
    if ((*packet = malloc(*packet_length)) == NULL)
        return FAILURE;
    memset(*packet, 0, *packet_length);
    /* Copy ETHERNET header to the packet: */
    memcpy((*packet)+0, dst_mac, 6);
    memcpy((*packet)+6, src_mac, 6);
    (*packet)[12] = IPV6_FRAME_TYPE / 256;
    (*packet)[13] = IPV6_FRAME_TYPE % 256;
    /* Copy IP header to the packet. */
    memcpy((*packet)+eth_offset, iphdr, sizeof(*iphdr));
    /* Copy ICMP header to the packet. */
    memcpy((*packet)+eth_offset+sizeof(*iphdr), icmphdr, icmp_nd_hdr_length);
    /* Copy ICMP options. */
    while (options!=NULL) {
        memcpy((*packet)+options_offset, options->option, options->option->nd_opt_len*8);
        options_offset += options->option->nd_opt_len*8;
        options = options->next;
    }
    return 0;
}

int send_packet(char* interface, uint8_t* packet, int packet_length) {
    /* This stores the socket file ID. */
    static int socketfile=-1;
    struct sockaddr sa;    
    strcpy(sa.sa_data, interface);
    /* If not yet done, open socket.*/
    if (socketfile < 0)
        socketfile = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ARP));
    /* This returns -1 on failure: */
    return sendto(socketfile, packet, packet_length, 0, &sa, sizeof(sa));
}

int compose_and_send_icmp_packet(char* interface, struct ether_addr* dst_mac, struct ether_addr* src_mac, struct ip6_hdr* iphdr, struct icmp6_hdr* icmphdr, struct icmp_nd_opt_list* options) {
    int packet_length = get_icmp_packet_length(icmphdr, options);
    int sent_length = 0;
    /* Beaware those values change during compose_packet: */
        uint8_t* packet = NULL;
        int composed_packet_length=0;
    set_ip6_hdr_fields(iphdr, packet_length);
    if (set_icmp6_hdr_checksum(iphdr, icmphdr, options)==FAILURE) {
        fprintf(stderr, "Could not calculate checksum.");
        return FAILURE;
    }
    if (compose_packet(dst_mac, src_mac, iphdr, icmphdr, options, &packet, &composed_packet_length)!=FAILURE) {
        if (hook_on_sending!=NULL) {
            (*hook_on_sending)(&packet, &composed_packet_length);
        }
        sent_length = send_packet(interface, packet, composed_packet_length);
    } else {
        sent_length = FAILURE;
        fprintf(stderr, "Error while composing packet.");
    }
    free(packet);
    return sent_length;
}

struct in6_addr* create_in6_addr(char* target) {
    struct in6_addr* address;
    struct in6_addr glob_in6;
    char *glob_addr = (char *) &glob_in6;
    struct addrinfo glob_hints, *glob_result;
    char out[64];
    if (target == NULL)
        return NULL;
    memset(&glob_hints, 0, sizeof(glob_hints));
    glob_hints.ai_family = AF_INET6;
    if (getaddrinfo(target, NULL, &glob_hints, &glob_result) != 0)
        return NULL;
    if (getnameinfo(glob_result->ai_addr, glob_result->ai_addrlen, out, sizeof(out), NULL, 0, NI_NUMERICHOST) != 0)
        return NULL;
    if (inet_pton(AF_INET6, out, glob_addr) < 0)
        return NULL;
    if ((address = malloc(sizeof(struct in6_addr))) == NULL)
        return NULL;
    memcpy(address, &glob_in6, 16);  
    return address;
}


struct in6_addr* create_in6_addr_for_interface(char *interface) {
    unsigned int if_index = if_nametoindex(interface);
    int scope = IPV6_LINKLOCAL;
    FILE *f;
    char addr[8][5];
    char devname[20];
    char s_addr[INET6_ADDRSTRLEN];
    unsigned int if_id, plen, addr_scope, dad_stat;
    struct in6_addr* ip;

    if ((ip=malloc(sizeof(struct in6_addr)))==NULL) {
        return NULL;
    }
    if ((f = fopen(PATH_PROC_INET, "r")) != NULL) {
        while (
            fscanf(f, "%4s%4s%4s%4s%4s%4s%4s%4s %02x %02x%02x %02x %20s\n",
                addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
                &if_id, &plen, &addr_scope, &dad_stat,devname
            )
            != EOF
        ) {
            if ( (if_id == if_index) && (addr_scope ==scope) ) {
                sprintf(s_addr,"%s:%s:%s:%s:%s:%s:%s:%s", addr[0], addr[1], addr[2], addr[3],addr[4], addr[5], addr[6],addr[7]);
                if (inet_pton(AF_INET6, s_addr, ip) <= 0) {
                    fclose(f);
                    return NULL;
                } else {
                    fclose(f);
                    return ip;
                }
                break;
            }
        }
        fclose(f);
        return NULL;
    } else {
        perror("/proc/net/if_inet6");
        return NULL;
    }
}


struct ether_addr* create_mac_for_interface(char *interface) {
    int s=0;
    struct ifreq ifr;
    struct ether_addr *mac;
    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        return NULL;
    memset(&ifr, 0, sizeof (ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
    if (ioctl(s, SIOCGIFHWADDR, (int8_t *)&ifr) < 0)
        return NULL; 
    if ((mac = malloc(sizeof(struct ether_addr)))==NULL)
        return NULL;
    memcpy(mac, &ifr.ifr_hwaddr.sa_data, 6);
    close(s);
    return mac;
}

struct ether_addr* create_multicast_mac_for_ip(struct in6_addr* ipaddr) {
    struct ether_addr* macaddr=NULL;
    uint8_t* macptr = NULL;
    if (ipaddr==NULL)
        return NULL;
    if ((macaddr=malloc(sizeof(struct ether_addr)))==NULL) 
        return NULL;
    macptr = (uint8_t*) macaddr;
    macptr[0] = 0x33;
    macptr[1] = 0x33;
    memcpy(macptr+2, (uint8_t*)ipaddr+12, 4);
    return macaddr;
}

void set_on_sending_hook(packet_hook hook) {
    hook_on_sending = hook;
}
