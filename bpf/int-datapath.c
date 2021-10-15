// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: GPL-2.0-only

#include <stddef.h>
#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

#include "common.h"
#include "flags.h"

#define SAMPLE_SIZE 128ul
#define DP_EVENT_TRACE 1
#define DP_EVENT_DROP 2

/* struct bridged_metadata is used to pass per-packet metadata between TC Ingress and TC Egress */
struct bridged_metadata {
    __u64 ingress_timestamp;
    __u32 ingress_port;
    __u32 pre_nat_ip_dst;
    __u32 pre_nat_ip_src;
    __u16 pre_nat_proto;
    __u16 pad0;
    __u16 pre_nat_sport;
    __u16 pre_nat_dport;
    __u16 seq_no;
    /* This field is used by userspace for the packet drop detection process.
       The userspace sets this field if it sees the bridged metadata for the first time.
       If the field is still set the second time the userspace sees it,
       the entry is removed by userspace and the packet drop is reported. */
    __u16 seen_by_userspace;
};

/* struct dp_event opaques information passed to the userspace.
   The content will be used by userspace agent to create an INT report */
struct dp_event {
    __u8 type; // either DP_EVENT_TRACE or DP_EVENT_DROP notification
    __u8 reason; // drop reason or 0
    __u32 pre_nat_ip_src;
    __u32 pre_nat_ip_dst;  // Set to the original pre-DNAT ip_dst in the "to-endpoint" direction. Otherwise, set to 0.
    __u16 pre_nat_sport;
    __u16 pre_nat_dport;  // Set to the original pre-DNAT dport in the "to-endpoint" direction. Otherwise, set to 0.
    __u32 ingress_ifindex;  // ingress port
    __u32 egress_ifindex;  // egress port
    __u64 ig_tstamp;
    __u64 eg_tstamp;
} __packed;

struct flow_filter_value {
    __u64 timestamp;
    __u32 ig_port;
    __u32 eg_port;
    __u32 flow_hash;
    __u32 hop_latency;
};

struct shared_map_key {
    __u64 packet_id;
    __u32 flow_hash;
    // padding is added to pass BPF verifier, see:
    // https://stackoverflow.com/questions/60601180/af-xdp-invalid-indirect-read-from-stack
    __u32 padding;
};

struct bpf_elf_map SEC("maps") SHARED_MAP = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof(struct shared_map_key),
    .size_value = sizeof(struct bridged_metadata),
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

struct bpf_elf_map SEC("maps") INT_FLOW_FILTER1 = {
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key	= sizeof(__u32),
    .size_value	= sizeof(struct flow_filter_value),
    .pinning	= PIN_GLOBAL_NS,
    .max_elem	= 65536,
};

struct bpf_elf_map SEC("maps") INT_FLOW_FILTER2 = {
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key	= sizeof(__u32),
    .size_value	= sizeof(struct flow_filter_value),
    .pinning	= PIN_GLOBAL_NS,
    .max_elem	= 65536,
};

static __always_inline bool flow_filter_contains(void *map, __u32 hash, struct flow_filter_value *flow_info)
{
    bool result = false;
    hash &= 0x0000ffff;
    struct flow_filter_value *stored_flow_info = bpf_map_lookup_elem(map, &hash);
    if (!stored_flow_info) {
        return false;
    }
    if (stored_flow_info->ig_port == flow_info->ig_port &&
        stored_flow_info->eg_port == flow_info->eg_port &&
        stored_flow_info->flow_hash == flow_info->flow_hash &&
        stored_flow_info->timestamp == flow_info->timestamp &&
        stored_flow_info->hop_latency == flow_info->hop_latency) {
        result = true;
    }

    stored_flow_info->ig_port = flow_info->ig_port;
    stored_flow_info->eg_port = flow_info->eg_port;
    stored_flow_info->flow_hash = flow_info->flow_hash;
    stored_flow_info->timestamp = flow_info->timestamp;
    stored_flow_info->hop_latency = flow_info->hop_latency;

    return result;
}

static __always_inline bool filter_allow(__u32 ig_port, __u32 eg_port, __u32 flow_hash, __u64 current_timestamp, __u32 hop_latency)
{
    /* Report every 1 second. */
    __u64 timestamp = current_timestamp & 0xffffffffc0000000;
    /* Report if hop latency change is greater than 2^16ns (~64 us). */
    hop_latency &= 0xfffe0000;
    struct flow_filter_value new_flow_info = {
        .ig_port = ig_port,
        .eg_port = eg_port,
        .flow_hash = flow_hash,
        .timestamp = timestamp,
        .hop_latency = hop_latency,
    };

    bpf_printk("Applying flow filter for: flow_hash=%x, quantized_tstamp=%llx, quantized_hop_latency=%x",
                flow_hash, timestamp, hop_latency);

    bool flag = false;
    flag = flow_filter_contains(&INT_FLOW_FILTER1, flow_hash, &new_flow_info);
    flag = flag || flow_filter_contains(&INT_FLOW_FILTER2, flow_hash >> 16, &new_flow_info);
    if (!flag) {
        bpf_printk("Flow filter detected change, allow to report.");
        return true;
    }

    return false;
}

SEC("classifier/ingress")
int ingress(struct __sk_buff *skb)
{
    __u64 ingress_timestamp = bpf_ktime_get_ns();
    __u32 hash = bpf_get_hash_recalc(skb);
    bpf_printk("Ingress, port=%d, hash=%x", skb->ifindex, hash);

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end)
        return TC_ACT_SHOT;

    if (bpf_htons(eth->h_proto) != 0x0800) {
        return TC_ACT_UNSPEC;
    }

    struct iphdr *iph = data + sizeof(*eth);

    if (data + sizeof(*eth) + sizeof(*iph) > data_end)
        return TC_ACT_SHOT;

    // FIXME: we don't support ICMP traffic yet
    if (iph->protocol == 0x1) {
        return TC_ACT_UNSPEC;
    }

    // we parse UDP, because we are only interested in src & dst ports of L4
    struct udphdr *udp = data + sizeof(*eth) + sizeof(*iph);
    if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*udp) > data_end)
        return TC_ACT_SHOT;

    // only for the PoC purpose; don't report system flows
    if (udp->source == bpf_htons(6443) || udp->dest == bpf_htons(6443) ||
        udp->source == bpf_htons(8181) || udp->dest == bpf_htons(8181) ||
        udp->source == bpf_htons(8080) || udp->dest == bpf_htons(8080) ||
        bpf_htons(udp->source) == 4240 || bpf_htons(udp->dest) == 4240) {
        return TC_ACT_UNSPEC;
    }

    __u32 ip_src, ip_dst;
    __u32 ip_protocol;
    __u16 l4_sport, l4_dport;
    if (bpf_htons(udp->dest) == 8472 || bpf_htons(udp->dest) == 4789) {
        struct iphdr *inner_ip = data + sizeof(*eth) + sizeof(*iph) + sizeof(*udp) +
                        8 + sizeof(*eth);
        if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*udp) + 8 + sizeof(*eth) + sizeof(*iph) > data_end)
                return TC_ACT_SHOT;

        struct ethhdr *inner_eth = data + sizeof(*eth) + sizeof(*iph) + sizeof(*udp) + 8;
        if (bpf_ntohs(inner_eth->h_proto) == 0x86dd || inner_ip->protocol == 0x1) {
            return TC_ACT_UNSPEC;
        }
        ip_src = inner_ip->saddr;
        ip_dst = inner_ip->daddr;
        ip_protocol = inner_ip->protocol;
        struct udphdr *inner_udp = data + sizeof(*eth) + sizeof(*iph) + sizeof(*udp) + 8 + sizeof(*eth) + sizeof(*iph);
        if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*udp) + 8 + sizeof(*eth) + sizeof(*iph) + sizeof(*inner_udp) > data_end)
                return TC_ACT_SHOT;
        l4_sport = inner_udp->source;
        l4_dport = inner_udp->dest;

        // only for the PoC purpose; don't report system flows
        if (bpf_ntohs(inner_udp->source) == 8080 || bpf_ntohs(inner_udp->dest) == 8080 ||
            bpf_ntohs(inner_udp->source) == 4240 || bpf_ntohs(inner_udp->dest) == 4240) {
            return TC_ACT_UNSPEC;
        }
    } else {
        ip_src = iph->saddr;
        ip_dst = iph->daddr;
        ip_protocol = iph->protocol;
        l4_sport = udp->source;
        l4_dport = udp->dest;
    }

    bpf_printk("ip_src=%x, ip_dst=%x, proto=%d", bpf_htonl(ip_src), bpf_htonl(ip_dst), ip_protocol);
    bpf_printk("l4_sport=%d, l4_dport=%d", bpf_htons(l4_sport), bpf_htons(l4_dport));

    struct shared_map_key key = {};
    __builtin_memset(&key, 0, sizeof(key));
#if BMD_MODE == BMD_MODE_SKB_PTR
    key.packet_id = (__u64) skb;
#else
    __u8 rand_id = bpf_get_prandom_u32() % 255;
    skb->cb[4] = rand_id << 24;
    key.packet_id = (__u64) rand_id;
#endif
    key.flow_hash = hash;
    key.padding = 0;

    struct bridged_metadata bmd = {};
    __builtin_memset(&bmd, 0, sizeof(bmd));
    bmd.ingress_timestamp = ingress_timestamp;
    bmd.ingress_port = skb->ifindex;
    bmd.pre_nat_ip_src = ip_src;
    bmd.pre_nat_ip_dst = ip_dst;
    bmd.pre_nat_proto = ip_protocol;
    bmd.pre_nat_dport = l4_dport;
    bmd.pre_nat_sport = l4_sport;
    bmd.seq_no = 0;

    bpf_printk("Saving bridged metadata under key: hash=%x, packet_id=%llx",
               key.flow_hash, key.packet_id);

    bpf_map_update_elem(&SHARED_MAP, &key, &bmd, 0);

    return TC_ACT_UNSPEC;
}

SEC("classifier/egress")
int egress(struct __sk_buff *skb)
{
    #if BMD_MODE == BMD_MODE_SKB_PTR
        __u64 packet_id = (__u64) skb;
    #else
        __u64 packet_id = (__u64) (skb->cb[4] >> 24);
    #endif
    __u64 egress_timestamp = bpf_ktime_get_ns();
    __u32 hash = bpf_get_hash_recalc(skb);
    bpf_printk("Egress, packet_id=%llx, port=%d, hash=%x", packet_id, skb->ifindex, hash);

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

    bpf_printk("l4_sport=%d, l4_dport=%d", bpf_htons(udp->source), bpf_htons(udp->dest));

    struct shared_map_key key = {};
    __builtin_memset(&key, 0, sizeof(struct shared_map_key));
    key.packet_id = packet_id;
    key.flow_hash = hash;

    struct bridged_metadata *b = bpf_map_lookup_elem(&SHARED_MAP, &key);
    if (!b) {
        bpf_printk("No bridged metadata found for hash=%x, packet_id=%llx.", key.flow_hash, key.packet_id);
        return TC_ACT_UNSPEC;
    }

    bpf_printk("Read bridged metadata for %x: ingress_tstamp=%llu, ingress_port=%d", hash, b->ingress_timestamp,
               b->ingress_port);

    __u32 hop_latency = egress_timestamp-b->ingress_timestamp;
    bpf_printk("Hop latency=%llu, egress_port=%d, seq_no=%u", hop_latency, skb->ifindex,
                b->seq_no);

    if (filter_allow(b->ingress_port, skb->ifindex, hash, egress_timestamp, hop_latency)) {
        struct dp_event evt = {};
        evt.type = DP_EVENT_TRACE;
        evt.egress_ifindex = skb->ifindex;
        evt.eg_tstamp = egress_timestamp;
        evt.ingress_ifindex = b->ingress_port;
        evt.ig_tstamp = b->ingress_timestamp;
        evt.pre_nat_ip_src = b->pre_nat_ip_src;
        evt.pre_nat_ip_dst = b->pre_nat_ip_dst;
        evt.pre_nat_sport = b->pre_nat_sport;
        evt.pre_nat_dport = b->pre_nat_dport;
        __u64 sample_size = skb->len < SAMPLE_SIZE ? skb->len : SAMPLE_SIZE;
            bpf_perf_event_output(skb, &INT_EVENTS_MAP, (sample_size << 32) | BPF_F_CURRENT_CPU,
                                      &evt, sizeof(evt));
    }

    bpf_map_delete_elem(&SHARED_MAP, &key);
    bpf_printk("Delete element from SHARED_MAP: packet_id=%llx, hash=%x", key.packet_id, key.flow_hash);

    return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";