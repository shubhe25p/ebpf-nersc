#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 10240);
} counter_map SEC(".maps");

// The callback function
static long callback_fn(struct bpf_map *map, const void *key, void *value, void *ctx)
{
    __u64 counter = *(__u64 *)value;
    if (counter % 2) {
        bpf_printk("Deleting PID %u with odd counter %llu\n", *(__u32 *)key, counter);
        bpf_map_delete_elem(map, key);
    }
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int count_prog(struct trace_event_raw_sched_process_exec *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid();
    __u64 init = 1;

    __u64 *val = bpf_map_lookup_elem(&counter_map, &pid);
    if (val)
        (*val)++;
    else
        bpf_map_update_elem(&counter_map, &pid, &init, BPF_ANY);

    return 0;
}

// Entry point for map cleanup
SEC("iter/do_cleanup")
int run_cleanup(void *ctx)
{
    long (*cb_p)(struct bpf_map *, const void *, void *, void *) = &callback_fn;
    bpf_for_each_map_elem(&counter_map, cb_p, NULL, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";