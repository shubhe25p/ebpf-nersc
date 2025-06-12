#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct pt_regs *ctx, const char *filename)
{
    char filename[256];
    const char *fname = (const char *)(filename);

    /* safely read user-space filename */
    if (bpf_core_read_user_str(filename, sizeof(filename), fname) > 0)
        bpf_printk("execve: %s\n", filename);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
