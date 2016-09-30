
/*
 * connection table
 * stats per packet
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netdissect-stdinc.h>

#include <stdlib.h>
#include <string.h>

#include "netdissect.h"
#include "addrtoname.h"
#include "extract.h"

#include "ip.h"
#include "ipproto.h"

struct global_context global_ctxt;
struct pkt_context pkt_ctxt;

uint32_t stat_ip;
uint32_t stat_ip_truncated_hdr;
uint32_t stat_ip_first_frag;
uint32_t stat_ip_non_first_frag;

uint32_t stat_ip6;

uint32_t stat_arp;
uint32_t stat_arp_request;
uint32_t stat_arp_reply;

static struct conn_hash_entry *conn_hashtbl[CONN_HASHSIZE];

/* to be called in conn_consume_pkt() */
int stat_proto_port(uint8_t proto, uint16_t port)
{
    return 0;
}

static int ipvx_equal(struct ipvx_addr *addr1, struct ipvx_addr *addr2)
{
    if (addr1->type != addr2->type) {
        return 0;
    }

    if (addr1->type == ADDR_IP) {
        if (addr1->ip_addr == addr2->ip_addr) {
            return 1;
        }
    }

    if (addr1->type == ADDR_IP6) {
        if ((addr1->ip6_addr32[0] == addr2->ip6_addr32[0])
            && (addr1->ip6_addr32[1] == addr2->ip6_addr32[1])
            && (addr1->ip6_addr32[2] == addr2->ip6_addr32[2])
            && (addr1->ip6_addr32[3] == addr2->ip6_addr32[3])) {
            return 1;
        }
    }

    return 0;
}

static uint32_t hash_5_tuple(struct ipvx_addr *src_ip, struct ipvx_addr *dst_ip, uint8_t proto, uint16_t src_port, uint16_t dst_port)
{
    uint32_t addr_hash;
    uint32_t app_hash;

    if (src_ip->type == ADDR_IP) {
        addr_hash = src_ip->ip_addr ^ dst_ip->ip_addr;
    } else {
        addr_hash = src_ip->ip6_addr32[0]
            ^ src_ip->ip6_addr32[1]
            ^ src_ip->ip6_addr32[2]
            ^ src_ip->ip6_addr32[3]
            ^ dst_ip->ip6_addr32[0]
            ^ dst_ip->ip6_addr32[1]
            ^ dst_ip->ip6_addr32[2]
            ^ dst_ip->ip6_addr32[3];
    }

    app_hash = src_port ^ dst_port ^ proto;

    return addr_hash ^ app_hash;
}

int conn_consume_pak(struct ipvx_addr *src_ip, struct ipvx_addr *dst_ip,
        uint8_t proto, uint16_t src_port, uint16_t dst_port, uint32_t pkt_len)
{
    struct conn_hash_entry *entry;
    struct conn_hash_entry *new_entry;
    struct conn *conn;
    struct conn *new_conn;

    uint32_t hash = hash_5_tuple(src_ip, dst_ip, proto, src_port, dst_port);

    for (entry = conn_hashtbl[hash % CONN_HASHSIZE]; entry; entry = entry->next) {
        conn = entry->conn;
        if (conn->proto != proto) {
            continue;
        }

        /* match in init direction */
        if (conn->src_port == src_port && conn->dst_port == dst_port
            && ipvx_equal(&conn->src_ip, src_ip) && ipvx_equal(&conn->dst_ip, dst_ip)) {
            conn->in_paks++;
            conn->in_bytes += pkt_len;
            return 0;
        }

        /* match in reverse direction */
        if (conn->src_port == dst_port && conn->dst_port == src_port
            && ipvx_equal(&conn->src_ip, dst_ip) && ipvx_equal(&conn->dst_ip, src_ip)) {
            conn->out_paks++;
            conn->out_bytes += pkt_len;
            return 0;
        }
    }
    
    /* no existing conn found, create new one and add to hashtbl */
    new_conn = (struct conn *)malloc(sizeof(struct conn));
    if (!new_conn) {
        return -1;
    }
    memset(new_conn, 0, sizeof(struct conn));
    new_conn->src_ip = *src_ip;
    new_conn->dst_ip = *dst_ip;
    new_conn->proto = proto;
    new_conn->src_port = src_port;
    new_conn->dst_port = dst_port;
    new_conn->in_paks = 1;
    new_conn->in_bytes = pkt_len;

    new_entry = (struct conn_hash_entry *)malloc(sizeof(struct conn_hash_entry));
    if (!new_entry) {
        return -1;
    }
    memset(new_entry, 0, sizeof(struct conn_hash_entry));
    new_entry->conn = new_conn;
    new_entry->next = conn_hashtbl[hash % CONN_HASHSIZE];
    conn_hashtbl[hash % CONN_HASHSIZE] = new_entry;

    return 0;
}

int conn_print(struct conn* conn)
{
    netdissect_options *ndo = (netdissect_options *)global_ctxt.user;

    /*
     * Example output:
     * src: 1.1.1.1 5012  dst: 2.2.2.2 80  proto: 6  total-paks: 27  total-bytes: 1552  in-paks: 12  in-bytes: 523  out-paks: 15  out-bytes: 1029
     */

    if (conn->src_ip.type == ADDR_IP) {
        ND_PRINT((ndo, "src: %s %u  dst: %s %u",
                ipaddr_string(ndo, &conn->src_ip.ip_addr), conn->src_port,
                ipaddr_string(ndo, &conn->dst_ip.ip_addr), conn->dst_port));
    }

    if (conn->src_ip.type == ADDR_IP6) {
        ND_PRINT((ndo, "src: %s %u  dst: %s %u",
                ip6addr_string(ndo, &conn->src_ip.ip6_addr), conn->src_port,
                ip6addr_string(ndo, &conn->dst_ip.ip6_addr), conn->dst_port));
    }

    ND_PRINT((ndo, "  proto: %s", tok2str(ipproto_values, NULL, conn->proto)));

    ND_PRINT((ndo, "  total-paks: %u  total-bytes: %u  in-paks: %u  in-bytes: %u  out-paks: %u  out-bytes: %u",
            conn->in_paks + conn->out_paks, conn->in_bytes + conn->out_bytes,
            conn->in_paks, conn->in_bytes,
            conn->out_paks, conn->out_bytes));

    ND_PRINT((ndo, "\n"));

    return 0;
}

void conn_iterate(conn_handler handler)
{
    int i;
    struct conn_hash_entry *entry;

    for (i = 0; i < CONN_HASHSIZE; i++) {
        for (entry = conn_hashtbl[i]; entry; entry = entry->next) {
            (*handler)(entry->conn);
        }
    }
}

void conn_tbl_print()
{
    netdissect_options *ndo = (netdissect_options *)global_ctxt.user;

    ND_PRINT((ndo, "\nConnection table:\n"));
    conn_iterate(conn_print);
}

void stat_print()
{
    netdissect_options *ndo = (netdissect_options *)global_ctxt.user;

    ND_PRINT((ndo, "\nPacket stats:\n"));
    ND_PRINT((ndo, "\nIP:\n"));
    ND_PRINT((ndo, "\t%u total\n", stat_ip));
    ND_PRINT((ndo, "\t%u truncated-header\n", stat_ip_truncated_hdr));
    ND_PRINT((ndo, "\t%u first-frag\n", stat_ip_first_frag));
    ND_PRINT((ndo, "\t%u non-first-frag\n", stat_ip_non_first_frag));

    ND_PRINT((ndo, "\nIP6:\n"));
    ND_PRINT((ndo, "\t%u total\n", stat_ip6));

    ND_PRINT((ndo, "\nARP:\n"));
    ND_PRINT((ndo, "\t%u total\n", stat_arp));
    ND_PRINT((ndo, "\t%u request\n", stat_arp_request));
    ND_PRINT((ndo, "\t%u reply\n", stat_arp_reply));
}

