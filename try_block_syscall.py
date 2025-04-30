#!/usr/bin/python
#
# This is a Hello World example that formats output as fields.

from bcc import BPF
from bcc.utils import printb

# define BPF program
prog = """
int kprobe__x64_sys_call(struct pt_regs *ctx) {
    bpf_trace_printk("Hello, World! %d \\n", PT_REGS_PARM2(ctx));
    return 0;
}
"""

# load BPF program
b = BPF(text=prog)

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    except KeyboardInterrupt:
        exit()
    printb(b"%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))