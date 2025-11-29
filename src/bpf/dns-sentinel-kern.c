#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4096);
} dns_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4096);
} last_seen SEC(".maps");

struct domain_key {
    __u32 ip;
    __u32 hash;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct domain_key);
    __type(value, __u8);
    __uint(max_entries, 16000);
} domain_seen SEC(".maps");

static __always_inline __u32 djb2_update(__u32 h, __u8 c) {
    return ((h << 5) + h) + c;
}

SEC("xdp")
int dns_sentinel(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(0x0800))
        return XDP_PASS;
        
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    __u32 ip_hdr_len = ip->ihl * 4;
    if ((void *)ip + ip_hdr_len + sizeof(struct udphdr) > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)((void *)ip + ip_hdr_len);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest != bpf_htons(53) && udp->source != bpf_htons(53))
        return XDP_PASS;

    __u32 src_ip = ip->saddr;

    __u64 one = 1;
    __u64 *cnt = bpf_map_lookup_elem(&dns_counter, &src_ip);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
    else
        bpf_map_update_elem(&dns_counter, &src_ip, &one, BPF_ANY);

    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&last_seen, &src_ip, &now, BPF_ANY);

    unsigned char *dns = (unsigned char *)(udp + 1);
    if (dns + 12 > (unsigned char *)data_end)
        return XDP_PASS;

    unsigned char *p = dns + 12; /* start of QNAME */

    __u32 h = 5381; /* djb2 initial */
    int total_read = 0;
    int labels = 0;

    #pragma unroll
    for (int i = 0; i < 128; i++) {
        if (p + 1 > (unsigned char *)data_end)
            break;
        
        __u8 byte = *p;
        p++;
        
        if (total_read == 0 || byte <= 63) {
            if (byte == 0) {
                labels++;
                break;
            }
            if (total_read > 0) {
                labels++;
                h = djb2_update(h, '.'); /* Add separator */
            }
        }
        
        h = djb2_update(h, byte);
        total_read++;
    }

finish_parse:
    if (labels == 0)
        return XDP_PASS;

    struct domain_key dk;
    dk.ip = src_ip;
    dk.hash = h;
    __u8 dummy = 0;
    bpf_map_update_elem(&domain_seen, &dk, &dummy, BPF_ANY);

    return XDP_PASS;
}
