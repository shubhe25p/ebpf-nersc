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
    int len=0;
    for(long unsigned i=0;i<1<<10;i++)
    {
        if(fname[i]!='\0')
            len++;
    }
    bpf_printk("filename %s with len %d \n", fname, len);


    return 0;
}

char LICENSE[] SEC("license") = "GPL";
