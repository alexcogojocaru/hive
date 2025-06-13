#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "ratelimit.h"

#define TOKEN_REFILL_INTERVAL   5000000000ULL // 5sec
#define TOKENS_PER_TOPUP        5
#define BUCKET_SIZE             10

#define min(a, b) ((a) < (b) ? (a) : (b))

static inline bool ratelimit_check(__u32* key) {
    struct ratelimit_value value;
    struct ratelimit_value *record;
    
    __u64 now;
    __u64 delta;
    __u64 interval;

    if (!key) {
        return FALSE;
    }

    now = bpf_ktime_get_ns();
    record = bpf_map_lookup_elem(&hive_ratelimit, key);
    if (!record) {
        value.tokens = BUCKET_SIZE - 1;
        value.last_request_time = now;

        bpf_map_update_elem(&hive_ratelimit, key, &value, BPF_ANY);
        return TRUE;
    }

    delta = now - record->last_request_time;
    if (delta > TOKEN_REFILL_INTERVAL) {
        interval = delta / TOKEN_REFILL_INTERVAL;
        record->tokens += interval * TOKENS_PER_TOPUP;
        record->last_request_time = now;

        if (record->tokens > BUCKET_SIZE) {
            record->tokens = BUCKET_SIZE;
        }
    }

    if (record->tokens > 0) {
        record->tokens--;
        return TRUE;
    }

    return FALSE;
}

SEC("xdp")
int ratelimit(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
    {
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        return XDP_PASS;
    }

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
    {
        return XDP_PASS;
    }

    if (iph->protocol != IPPROTO_ICMP)
    {
        return XDP_PASS;
    }

    if (ratelimit_check(&iph->saddr) == FALSE) {
        return XDP_DROP;
    }

    return XDP_PASS;
}
