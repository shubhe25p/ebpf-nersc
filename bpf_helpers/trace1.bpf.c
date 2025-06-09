/* Very simple code, increment every time someone calls openat() syscall */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 1);
} cnt SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int BPF_PROG1(void* ctx)
{
    u32 key = 0;
    u32* cnt = bpf_map_lookup_elem(&cnt, &key);
    if(!cnt)
        return 0;
    __sync_fetch_and_add(cnt, 1);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";