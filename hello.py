#!/usr/bin/python3

from bcc import BPF

# BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <uapi/linux/bpf.h>

int print_avenrun_address(void *ctx) {
    const char *symbol_name = "avenrun";
    u64 symbol_address;
    int flag=0;
    bpf_kallsyms_lookup_name(symbol_name, 7, flag, &symbol_address);
    
    bpf_trace_printk("something: %d\\n", symbol_address);

    
    return 0;
}
"""
 
# Load BPF program
b = BPF(text=bpf_text)

# Attach to a kernel function (e.g., sys_sync)
b.attach_kprobe(event="blk_start_request", fn_name="print_avenrun_address")
# Print header
print("Tracing... Hit Ctrl-C to end.")

# Print output
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        print(msg.decode())
    except KeyboardInterrupt:
        exit()