#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key,    __u32);
    __type(value,  __u64);
} read_cnt SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_read")
int count_reads(void *ctx)
{
    __u32 key = 0;
    __u32 cpu = bpf_get_smp_processor_id();
    __u64 *cnt;

    cnt = bpf_map_lookup_percpu_elem(&read_cnt, &key, cpu);
    if (!cnt)
        return 0;

    __sync_fetch_and_add(cnt, 1);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";