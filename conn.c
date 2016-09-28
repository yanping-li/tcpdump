
/*
 * Stats per connection
 * Stats per packet
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netdissect-stdinc.h>

#include <string.h>

#include "netdissect.h"
#include "addrtoname.h"
#include "extract.h"

#include "ip.h"
#include "ipproto.h"

#include "conn.h"

struct pkt_context pkt_ctxt;

bool ipvx_equal(struct ipvx_addr *addr1, struct ipvx_addr *addr2)
{
    if (addr1.type != addr2.type) {
        return false;
    }

    if (addr1.type == ADDR_IP) {
        if (addr1.ip_addr == addr2.ip_addr) {
            return true;
        }
    }

    if (addr1.type == ADDR_IP6) {
        if ((addr1.ip6_addr.addr32[0] == addr2.ip6_addr.addr32[0])
            && (addr1.ip6_addr.addr32[1] == addr2.ip6_addr.addr32[1])
            && (addr1.ip6_addr.addr32[2] == addr2.ip6_addr.addr32[2])
            && (addr1.ip6_addr.addr32[3] == addr2.ip6_addr.addr32[3])) {
            return true;
        }
    }

    return false;
}

struct conn_hash_entry *conn_hashtbl[CONN_HASHSIZE];

uint32 hash_5_tuple(struct ipvx_addr *src_addr, struct ipvx_addr *dst_addr, uint8 proto, uint16 src_port, uint16 dst_port)
{
    uint32 addr_hash;
    uint32 app_hash;

    if (src_ip->type == ADDR_IP) {
        addr_hash = src_ip->ip_addr ^ dst_ip->ip_addr;
    } else {
        addr_hash = src_ip->ip6_addr.addr32[0]
            ^ src_ip->ip6_addr.addr32[1]
            ^ src_ip->ip6_addr.addr32[2]
            ^ src_ip->ip6_addr.addr32[3]
            ^ dst_ip->ip6_addr.addr32[0]
            ^ dst_ip->ip6_addr.addr32[1]
            ^ dst_ip->ip6_addr.addr32[2]
            ^ dst_ip->ip6_addr.addr32[3]
    }

    app_hash = src_port ^ dst_port ^ proto

    return addr_hash ^ app_hash;
}

int conn_print(struct conn *conn)
{
    if (!nonn) {
        return -1;
    }


}

int conn_consume_pak(struct ipvx_addr *src_addr, struct ipvx_addr *dst_addr,
        uint8 proto, uint16 src_port, uint16 dst_port, uint32 pak_len)
{
    struct conn_hash_entry *entry;
    struct conn_hash_entry *new_entry;
    struct conn *conn;
    struct conn *new_conn;

    uint32 hash = hash_5_tuple(src_addr, dst_addr, proto, src_port, dst_port);

    for (entry = conn_hashtbl[hash % CONN_HASHSIZE]; entry; entry = entry->next) {
        conn = entry->conn;
        if (conn->proto != proto) {
            continue;
        }

        /* match in init direction */
        if (conn->src_port == src_port && conn->dst_port == dst_port
            && ipvx_equal(&conn->src_addr, src_addr) && ipvx_equal(&conn->dst_addr, dst_addr)) {
            conn->in_paks++;
            conn->in_bytes += pak_len;
            return 0;
        }

        /* match in reverse direction */
        if (conn->src_port == dst_port && conn->dst_port == src_port
            && ipvx_equal(&conn->src_addr, dst_addr) && ipvx_equal(&conn->dst_addr, src_addr)) {
            conn->out_paks++;
            conn->out_bytes += pak_len;
            return 0;
        }
    }
    
    /* no existing conn found, create new one and add to hashtbl */
    new_conn = (struct conn *)zalloc(sizeof(struct conn));
    if (!new_conn) {
        return -1;
    }
    memset(new_conn, 0, sizeof(struct conn));
    new_conn->src_addr = *src_addr;
    new_conn->dst_addr = *dst_addr;
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

int conn_iterate(callback_t callback)
{
    for (i = 0; i < CONN_HASHSIZE; i++) {
        for (entry = conn_hashtbl[i]; entry; entry = entry->next) {
            (*callback)(entry->conn);
        }
    }
}


