#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog1(struct syscall_trace_enter* ctx)
{
    char fname[256];

    int ret = bpf_probe_read_user_str(fname, sizeof(fname), (const char*)ctx->args[0]);
	if (ret < 0) {
		return 0;
	}
    bpf_printk("String %s\n", fname);


    return 0;
}

char LICENSE[] SEC("license") = "GPL";
