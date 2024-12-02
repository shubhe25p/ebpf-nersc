// process_trace.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, char[16]);
    __uint(pinning, LIBBPF_PIN_BY_NAME); // Enable pinning
} proc_map SEC(".maps");

SEC("tp/syscalls/sys_enter_execve")
int trace_execve(void *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    char comm[16];
    
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_map_update_elem(&proc_map, &pid, comm, BPF_ANY);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";