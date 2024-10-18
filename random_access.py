from bcc import BPF
import time

# BPF program
bpf_program = """
#include <uapi/linux/ptrace.h>
int trace_symbol(struct pt_regs *ctx) {
    if (!PT_REGS_PARM2(ctx))
        return 0;
    
    int num_files=(int)PT_REGS_PARM2(ctx);
    bpf_trace_printk("random_file_operation called with num_files: %d\\n",num_files);
    return 0;
}
"""

# Load BPF program
b = BPF(text=bpf_program)

# Attach to the random_file_operation function
b.attach_uprobe(name="./random_access", sym="random_file_operations", fn_name="trace_symbol")

# Print output
print("Tracing... Press Ctrl+C to exit.")
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        print("%s" % (msg))
    except KeyboardInterrupt:
        print("Detaching...")
        break