//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TRUE    1
#define FALSE   0

typedef int bool;

struct ratelimit_value {
    __u64 tokens;
    __u64 last_request_time;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct ratelimit_value);
    __uint(max_entries, 1024);
} hive_ratelimit SEC(".maps");

char __license[] SEC("license") = "Dual MIT/GPL";
