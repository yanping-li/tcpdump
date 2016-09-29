
#ifndef netdissect_stat_h
#define netdissect_stat_h

#define CONN_HASHSIZE 65536

struct global_context {
    u_char *user;
};

struct pkt_context {
    ipvx_addr src_addr;
    ipvx_addr dst_addr;
    uint8 proto;
    uint16 src_port;
    uint16 dst_port;
};

enum addr_type {
	ADDR_IP,
	ADDR_IP6
};

#define ip_addr __addr.__ip
#define ip6_addr __addr.__ip6.__u6_addr
#define ip6_addr8 __addr.__ip6.__u6_addr.__u6_addr8
#define ip6_addr16 __addr.__ip6.__u6_addr.__u6_addr16
#define ip6_addr32 __addr.__ip6.__u6_addr.__u6_addr32
struct ipvx_addr {
    enum addr_type type;
    union {
        uint32 __ip;
        in6_addr __ip6;
    } __addr;
};

bool ipvx_equal(struct ipvx_addr *addr1, struct ipvx_addr *addr2);

struct conn {
    ipvx_addr src_ip;
    ipvx_addr dst_ip;
    uint16 src_port;
    uint16 dst_port;
    uint8 proto;
    uint32 in_paks;
    uint32 out_paks;
    uint32 in_bytes;
    uint32 out_bytes;
};

struct conn_hash_entry {
    struct conn_hash_entry *next;
    void *conn;
};

int conn_consume_pak(struct ipvx_addr *src_addr, struct ipvx_addr *dst_addr,
        uint8 proto, uint16 src_port, uint16 dst_port, uint32 pak_len);

typedef int (*)(struct conn *conn) callback_t;

int conn_iterate(callback_t);

int conn_print(struct conn *);

#endif /* netdissect_stat_h */
