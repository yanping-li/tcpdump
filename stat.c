
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


uint32_t stat_pkt_total;

uint32_t stat_lldp;
uint32_t stat_stp;

uint32_t stat_ip;
uint32_t stat_ip_truncated_hdr;
uint32_t stat_ip_first_frag;
uint32_t stat_ip_non_first_frag;

uint32_t stat_icmp;
uint32_t stat_icmp_echo;
uint32_t stat_icmp_echo_reply;
uint32_t stat_icmp_unreach;
uint32_t stat_icmp_time_exceed;

uint32_t stat_arp;
uint32_t stat_arp_request;
uint32_t stat_arp_reply;

uint32_t stat_ip6;

uint32_t stat_icmp6;
uint32_t stat_icmp6_echo;
uint32_t stat_icmp6_echo_reply;
uint32_t stat_icmp6_router_solicit;
uint32_t stat_icmp6_router_advert;
uint32_t stat_icmp6_neighbor_solicit;
uint32_t stat_icmp6_neighbor_advert;

uint32_t stat_udp;

uint32_t stat_tcp;

uint32_t stat_sctp;

uint32_t stat_esp;
uint32_t stat_ah;

uint32_t stat_pim;
uint32_t stat_igmp;

uint32_t stat_gre;


static struct conn_hash_entry *conn_hashtbl[CONN_HASHSIZE];
static uint32_t udp_port_pkts[65536];
static uint32_t tcp_port_pkts[65536];


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

static int conn_consume_pkt(struct ipvx_addr *src_ip, struct ipvx_addr *dst_ip,
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

int consume_pkt()
{
    if (pkt_ctxt.src_ip.type == ADDR_IP || pkt_ctxt.src_ip.type == ADDR_IP6) {
        conn_consume_pkt(&pkt_ctxt.src_ip, &pkt_ctxt.dst_ip, pkt_ctxt.proto, pkt_ctxt.src_port, pkt_ctxt.dst_port, pkt_ctxt.pkt_len);
    }

    if (pkt_ctxt.proto == IPPROTO_UDP) {
        udp_port_pkts[pkt_ctxt.dst_port]++;
    }
    if (pkt_ctxt.proto == IPPROTO_TCP) {
        tcp_port_pkts[pkt_ctxt.dst_port]++;
    }

    return 0;
}

static int conn_print(struct conn* conn)
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

static void print_conn_table()
{
    netdissect_options *ndo = (netdissect_options *)global_ctxt.user;

    ND_PRINT((ndo, "\n- Connection table\n"));
    conn_iterate(conn_print);
    ND_PRINT((ndo, "- Connection table end\n"));
}

static void print_pkts_per_port() {
    int port;
    netdissect_options *ndo = (netdissect_options *)global_ctxt.user;

    ND_PRINT((ndo, "\n- UDP packets per port\n"));
    ND_PRINT((ndo, "Port\t\tPackets\n"));
    for (port = 0; port < 65536; port++) {
        if (udp_port_pkts[port]) {
            ND_PRINT((ndo, "%u\t\t%u\n", port, udp_port_pkts[port]));
        }
    }
    ND_PRINT((ndo, "- UDP packets per port end\n"));
    
    ND_PRINT((ndo, "\n- TCP packets per port\n"));
    ND_PRINT((ndo, "Port\t\tPackets\n"));
    for (port = 0; port < 65536; port++) {
        if (tcp_port_pkts[port]) {
            ND_PRINT((ndo, "%u\t\t%u\n", port, tcp_port_pkts[port]));
        }
    }
    ND_PRINT((ndo, "- TCP packets per port end\n"));
}

void print_counters()
{
    netdissect_options *ndo = (netdissect_options *)global_ctxt.user;

    ND_PRINT((ndo, "\n- Packet counters\n"));
    ND_PRINT((ndo, "\t%u packets total\n", stat_pkt_total));

    ND_PRINT((ndo, "LLDP:\n"));
    ND_PRINT((ndo, "\t%u total\n", stat_lldp));

    ND_PRINT((ndo, "STP:\n"));
    ND_PRINT((ndo, "\t%u total\n", stat_stp));

    ND_PRINT((ndo, "IP:\n"));
    ND_PRINT((ndo, "\t%u total\n", stat_ip));
    ND_PRINT((ndo, "\t%u truncated header\n", stat_ip_truncated_hdr));
    ND_PRINT((ndo, "\t%u first frag\n", stat_ip_first_frag));
    ND_PRINT((ndo, "\t%u non first frag\n", stat_ip_non_first_frag));

    ND_PRINT((ndo, "ICMP:\n"));
    ND_PRINT((ndo, "\t%u total\n", stat_icmp));
    ND_PRINT((ndo, "\t%u echo\n", stat_icmp_echo));
    ND_PRINT((ndo, "\t%u echo reply\n", stat_icmp_echo_reply));

    ND_PRINT((ndo, "ARP:\n"));
    ND_PRINT((ndo, "\t%u total\n", stat_arp));
    ND_PRINT((ndo, "\t%u request\n", stat_arp_request));
    ND_PRINT((ndo, "\t%u reply\n", stat_arp_reply));

    ND_PRINT((ndo, "IP6:\n"));
    ND_PRINT((ndo, "\t%u total\n", stat_ip6));

    ND_PRINT((ndo, "ICMP6:\n"));
    ND_PRINT((ndo, "\t%u icmp6\n", stat_icmp6));
    ND_PRINT((ndo, "\t%u icmp6 echo\n", stat_icmp6_echo));
    ND_PRINT((ndo, "\t%u icmp6 echo reply\n", stat_icmp6_echo_reply));
    ND_PRINT((ndo, "\t%u icmp6 router solicit\n", stat_icmp6_router_solicit));
    ND_PRINT((ndo, "\t%u icmp6 router advert\n", stat_icmp6_router_advert));
    ND_PRINT((ndo, "\t%u icmp6 neighbor solicit\n", stat_icmp6_neighbor_solicit));
    ND_PRINT((ndo, "\t%u icmp6 neighbor advert\n", stat_icmp6_neighbor_advert));

    ND_PRINT((ndo, "UDP:\n"));
    ND_PRINT((ndo, "\t%u total\n", stat_udp));

    ND_PRINT((ndo, "TCP:\n"));
    ND_PRINT((ndo, "\t%u total\n", stat_tcp));

    ND_PRINT((ndo, "ESP:\n"));
    ND_PRINT((ndo, "\t%u total\n", stat_esp));

    ND_PRINT((ndo, "AH:\n"));
    ND_PRINT((ndo, "\t%u total\n", stat_ah));

    ND_PRINT((ndo, "- Packet counters end\n"));
}

void stat_print() {
    print_counters();
    print_pkts_per_port();
    print_conn_table();
}
