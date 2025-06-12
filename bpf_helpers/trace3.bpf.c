#include "vmlinux.sh"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 10240);
} cnt_map SEC(".maps");

SEC("tracepoints/syscalls/sys_enter_openat")
int bpf_prog1(void *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    u32 init_val=0;
    u32 *cnt = bpf_map_lookup_elem(&cnt_map, &pid);
    if(cnt){
        __sync_fetch_and_add(cnt, 1);
    }else{
        bpf_map_update_elem(&cnt_map, &key, &init_val, BPF_ANY);
        return 0;
    }
    if(cnt == 42)
        bpf_map_delete_elem(&cnt_map, &pid);
    return 0;
}

char LICENSE[] SEC("LICENSE") = "GPL"