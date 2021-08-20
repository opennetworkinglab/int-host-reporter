#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

#include "common.h"

#define SAMPLE_SIZE 128ul
#define DP_EVENT_TRACE 1
#define DP_EVENT_DROP 2

struct bmd {
    __u64 ingress_timestamp;
    __u32 ingress_port;
    __u32 pre_nat_ip_dst;
    __u16 pre_nat_dport;
};

struct dp_event {
    __u8 type; // either DP_EVENT_TRACE or DP_EVENT_DROP notification
    __u8 reason; // drop reason or 0
    __u32 pre_nat_ip_dst;  // Set to the original pre-DNAT ip_dst in the "to-endpoint" direction. Otherwise, set to 0.
    __u16 pre_nat_dport;  // Set to the original pre-DNAT dport in the "to-endpoint" direction. Otherwise, set to 0.
    __u32 ingress_ifindex;  // ingress port
    __u32 egress_ifindex;  // egress port
    __u64 ig_tstamp;
    __u64 eg_tstamp;
} __packed;

struct bpf_elf_map SEC("maps") SHARED_MAP = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof(__u32),
    .size_value = sizeof(struct bmd),
    .pinning = PIN_GLOBAL_NS,
    .max_elem = 65536,
};

struct bpf_elf_map SEC("maps") INT_EVENTS_MAP = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .size_key	= sizeof(__u32),
    .size_value	= sizeof(__u32),
    .pinning	= PIN_GLOBAL_NS,
    .max_elem	= 2,
};

SEC("classifier/ingress")
int ingress(struct __sk_buff *skb)
{
    __u32 hash = bpf_get_hash_recalc(skb);
    bpf_printk("Ingress, skbptr=%p, port=%d, hash=%x", skb, skb->ifindex, hash);

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end)
        return TC_ACT_SHOT;

    bpf_printk("eth_type=%x", bpf_htons(eth->h_proto));

    struct iphdr *iph = data + sizeof(*eth);

    if (data + sizeof(*eth) + sizeof(*iph) > data_end)
        return TC_ACT_SHOT;

    bpf_printk("ip_src=%x, ip_dst=%x", bpf_htonl(iph->saddr), bpf_htonl(iph->daddr));

    // we parse UDP, because we are only interested in src & dst ports of L4
    struct udphdr *udp = data + sizeof(*eth) + sizeof(*iph);
    if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*udp) > data_end)
        return TC_ACT_SHOT;

    bpf_printk("udp_src=%d, udp_dst=%d", bpf_htons(udp->source), bpf_htons(udp->dest));

    struct bmd b = {
        .ingress_timestamp = bpf_ktime_get_ns(),
        .ingress_port = skb->ifindex,
        .pre_nat_ip_dst = iph->daddr,
        .pre_nat_dport = udp->dest,
    };

    bpf_map_update_elem(&SHARED_MAP, &hash, &b, 0);

    return TC_ACT_UNSPEC;
}

SEC("classifier/egress")
int egress(struct __sk_buff *skb)
{
    __u64 egress_timestamp = bpf_ktime_get_ns();
    __u32 hash = bpf_get_hash_recalc(skb);
    bpf_printk("Egress, skbptr=%p, port=%d, hash=%x", skb, skb->ifindex, hash);

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end)
        return TC_ACT_SHOT;

    bpf_printk("eth_type=%x", bpf_htons(eth->h_proto));

    struct iphdr *iph = data + sizeof(*eth);

    if (data + sizeof(*eth) + sizeof(*iph) > data_end)
        return TC_ACT_SHOT;

    bpf_printk("ip_src=%x, ip_dst=%x", bpf_htonl(iph->saddr), bpf_htonl(iph->daddr));

    struct udphdr *udp = data + sizeof(*eth) + sizeof(*iph);
    if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*udp) > data_end)
        return TC_ACT_SHOT;

    bpf_printk("udp_src=%d, udp_dst=%d", bpf_htons(udp->source), bpf_htons(udp->dest));

    struct bmd *b = bpf_map_lookup_elem(&SHARED_MAP, &hash);
    if (!b) {
        return TC_ACT_UNSPEC;
    }
    bpf_printk("Read bridged metadata for %x: ingress_tstamp=%llu, ingress_port=%d", hash, b->ingress_timestamp,
               b->ingress_port);

    bpf_printk("Hop latency=%llu, egress_port=%d, pre_nat_ip=%x", egress_timestamp-b->ingress_timestamp, skb->ifindex,
                bpf_htonl(b->pre_nat_ip_dst));

    struct dp_event evt = {};
    evt.type = DP_EVENT_TRACE;
    evt.egress_ifindex = skb->ifindex;
    evt.eg_tstamp = egress_timestamp;
    evt.ingress_ifindex = b->ingress_port;
    evt.ig_tstamp = b->ingress_timestamp;
    evt.pre_nat_ip_dst = b->pre_nat_ip_dst;
    evt.pre_nat_dport = b->pre_nat_dport;

    __u64 sample_size = skb->len < SAMPLE_SIZE ? skb->len : SAMPLE_SIZE;
    bpf_perf_event_output(skb, &INT_EVENTS_MAP, (sample_size << 32) | BPF_F_CURRENT_CPU,
                              &evt, sizeof(evt));

    return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";