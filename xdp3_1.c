#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>


struct flow_key {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8  protocol;
};

struct flow_value {
    u64 start_ts;
    u64 last_seen;
    u32 total_packets;
    u32 total_bytes;
    u32 fwd_packets;
    u32 fwd_bytes;
    u32 max_fwd_len;
    u32 init_win_fwd;
    u16 sport;
    u8  connection_status;
    u32 src_ip;
    u32 dst_ip;
};

BPF_HASH(flow_table, struct flow_key, struct flow_value);

int xdp_process(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)eth + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    u8 protocol = ip->protocol;
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
        return XDP_PASS;

    u16 ip_header_len = ip->ihl * 4;
    if ((void *)ip + ip_header_len > data_end)
        return XDP_PASS;

    u16 sport = 0, dport = 0;
    u8 tcp_flags = 0;

    //head
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_header_len;
        if ((void *)tcp + sizeof(*tcp) > data_end)
            return XDP_PASS;
        sport = tcp->source;
        dport = tcp->dest;
        tcp_flags = ((u8 *)tcp)[13]; 
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_header_len;
        if ((void *)udp + sizeof(*udp) > data_end)
            return XDP_PASS;
        sport = udp->source;
        dport = udp->dest;
    }

    // standard
    int swapped = 0;
    if (ip->saddr > ip->daddr) {
        swapped = 1;
    } else if (ip->saddr == ip->daddr && sport > dport) {
        swapped = 1;
    }

    struct flow_key key = {
        .saddr = swapped ? ip->daddr : ip->saddr,
        .daddr = swapped ? ip->saddr : ip->daddr,
        .sport = swapped ? dport : sport,
        .dport = swapped ? sport : dport,
        .protocol = protocol
    };

    struct flow_value *val, zero_val = {0};
    val = flow_table.lookup_or_try_init(&key, &zero_val);
    if (!val) return XDP_PASS;

    u64 ts = bpf_ktime_get_ns();
    u32 pkt_len = ctx->data_end - ctx->data;

    //init timestamp
    if (val->start_ts == 0) {
        val->start_ts = ts;
    }

    //update
    int is_forward = (ip->saddr == key.saddr && sport == key.sport);
    val->total_packets++;
    val->total_bytes += pkt_len;
    val->last_seen = ts;

    if (is_forward) {
        val->fwd_packets++;
        val->fwd_bytes += pkt_len;
        if (pkt_len > val->max_fwd_len)
            val->max_fwd_len = pkt_len;

        //tcp win
        if (protocol == IPPROTO_TCP && (tcp_flags & 0x02)) {
            struct tcphdr *tcp = (void *)ip + ip_header_len;
            val->init_win_fwd = tcp->window;
        }
    }

    //update connect status
    if (protocol == IPPROTO_TCP) {
        if (tcp_flags & 0x01) {       // SYN
            val->connection_status = 0;
        } else if (val->connection_status == 0) {
            val->connection_status = 1;  // ESTABLISHED
        }
        if (tcp_flags & 0x02) {       // FIN
            val->connection_status = 2;
        }
    } else {
        val->connection_status = 3;  // UDP标记
    }

    //ipaddr
    val->src_ip = ip->saddr;
    val->dst_ip = ip->daddr;
    
    return XDP_PASS;
}