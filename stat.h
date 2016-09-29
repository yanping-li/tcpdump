
#ifndef netdissect_stat_h
#define netdissect_stat_h

#define CONN_HASHSIZE 65536

struct global_context {
    u_char *user;
};

enum addr_type {
	ADDR_IP,
	ADDR_IP6
};

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

extern uint32_t stat_ip;
extern uint32_t stat_ipfrag;

extern uint32_t stat_ip6;

extern uint32_t stat_arp;
extern uint32_t stat_arp_request;
extern uint32_t stat_arp_reply;

extern int conn_consume_pak(struct ipvx_addr *src_ip, struct ipvx_addr *dst_ip,
        uint8_t proto, uint16_t src_port, uint16_t dst_port, uint32_t pak_len);
typedef int (*conn_handler)(struct conn *conn);
extern int conn_print(struct conn *);
extern void conn_iterate(conn_handler);
extern void stat_print();

#endif /* netdissect_stat_h */
