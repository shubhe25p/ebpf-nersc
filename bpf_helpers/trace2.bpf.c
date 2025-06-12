#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog1(struct syscall_trace_enter* ctx)
{
    char fname[256];

    if (BPF_CORE_READ_STR_INTO(fname, sizeof(fname), (const char*)ctx->args[0]) > 0)
        bpf_printk("execve: %s\n", fnmaw);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
