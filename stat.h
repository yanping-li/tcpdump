
#ifndef netdissect_stat_h
#define netdissect_stat_h

#define CONN_HASHSIZE 65536

struct global_context {
    u_char *user;
};

enum addr_type {
	ADDR_IP = 1,
	ADDR_IP6
};

#ifndef s6_addr
#define	s6_addr   __u6_addr.__u6_addr8
#endif

#ifndef s6_addr16
#define	s6_addr16   __u6_addr.__u6_addr16
#endif

#ifndef s6_addr32
#define	s6_addr32   __u6_addr.__u6_addr32
#endif

#define ip_addr __addr.__ip
#define ip6_addr __addr.__ip6
#define ip6_addr8 __addr.__ip6.s6_addr
#define ip6_addr16 __addr.__ip6.s6_addr16
#define ip6_addr32 __addr.__ip6.s6_addr32
struct ipvx_addr {
    enum addr_type type;
    union {
        uint32_t __ip;
        struct in6_addr __ip6;
    } __addr;
};

struct pkt_context {
    struct ipvx_addr src_ip;
    struct ipvx_addr dst_ip;
    uint8_t proto;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t pkt_len;
};

struct conn {
    struct ipvx_addr src_ip;
    struct ipvx_addr dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
    uint32_t in_paks;
    uint32_t out_paks;
    uint32_t in_bytes;
    uint32_t out_bytes;
};

struct conn_hash_entry {
    struct conn_hash_entry *next;
    void *conn;
};

extern struct global_context global_ctxt;
extern struct pkt_context pkt_ctxt;


extern uint32_t stat_pkt_total;

extern uint32_t stat_lldp;
extern uint32_t stat_stp;

extern uint32_t stat_ip;
extern uint32_t stat_ip_truncated_hdr;
extern uint32_t stat_ip_first_frag;
extern uint32_t stat_ip_non_first_frag;

extern uint32_t stat_icmp;
extern uint32_t stat_icmp_echo;
extern uint32_t stat_icmp_echo_reply;
extern uint32_t stat_icmp_unreach;
extern uint32_t stat_icmp_time_exceed;

extern uint32_t stat_arp;
extern uint32_t stat_arp_request;
extern uint32_t stat_arp_reply;

extern uint32_t stat_ip6;

extern uint32_t stat_icmp6;
extern uint32_t stat_icmp6_echo;
extern uint32_t stat_icmp6_echo_reply;
extern uint32_t stat_icmp6_router_solicit;
extern uint32_t stat_icmp6_router_advert;
extern uint32_t stat_icmp6_neighbor_solicit;
extern uint32_t stat_icmp6_neighbor_advert;

extern uint32_t stat_udp;

extern uint32_t stat_tcp;

extern uint32_t stat_sctp;

extern uint32_t stat_esp;
extern uint32_t stat_ah;

extern uint32_t stat_pim;
extern uint32_t stat_igmp;

extern uint32_t stat_gre;


extern int consume_pkt();
typedef int (*conn_handler)(struct conn *conn);
extern void stat_print();

#endif /* netdissect_stat_h */
