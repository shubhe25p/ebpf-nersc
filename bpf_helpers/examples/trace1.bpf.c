/* Very simple code, increment every time someone calls openat() syscall */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 1);
} cnt_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int bpf_prog1(void* ctx)
{
    const char fmt_str[] = "Hello, world! number of openat calls total %d\n";
    u32 key = 0, init_val=0;
    u32 *cnt = bpf_map_lookup_elem(&cnt_map, &key);
    if(cnt)
        __sync_fetch_and_add(cnt, 1);
    else{
        bpf_map_update_elem(&cnt_map, &key, &init_val, BPF_ANY);
        return 0;
    }
    bpf_trace_printk(fmt_str, sizeof(fmt_str), *cnt);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
