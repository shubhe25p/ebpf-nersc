#!/usr/bin/env python
from bcc import BPF

# bpf program: intercept mkdirat and force it to return -EPERM
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/errno.h> 

int kprobe__sys_mkdirat(struct pt_regs *ctx, int dfd, const char __user *pathname, umode_t mode) {
    bpf_trace_printk("mkdir blocked on this machine: %s\\n", pathname);
    bpf_override_return(ctx, -EPERM);
    return 0;
}
"""

b = BPF(text=bpf_text)
print("Blocking mkdir… Press Ctrl+C to exit.")
b.trace_print()
