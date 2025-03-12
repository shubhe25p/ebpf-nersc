from bcc import BPF
import time



bpf_text="""
#include <linux/sched.h>
#include <linux/fs_struct.h>

void trace_sys_enter(void* ctx)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct fs_struct *fs = (struct fs_struct* )task->fs;

    bpf_trace_printk("onCPU %d with users: %d\\n", task->on_cpu, fs->users);
}
"""

b = BPF(text=bpf_text)

b.attach_tracepoint(tp="syscalls:sys_enter_open", fn_name="trace_sys_enter")

print("Tracing syscalls .. Press Ctrl-C to end.")

# Format output
print("%-18s %-6s %s" % ("TIME(s)", "ONCPU", "USERS"))


# Trace output
start_time = time.time()
try:
    while True:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        elapsed = time.time() - start_time
        
        msg_str = msg.decode('utf-8', 'replace')
        if "onCPU" in msg_str:
            parts = msg_str.split("with users: ")
            if len(parts) == 2:
                oncpu_part = parts[0].split("onCPU ")[1].strip()
                users = parts[1].strip()
                print("%-18.9f %-6s %s" % (elapsed, oncpu_part, users))
except KeyboardInterrupt:
    print("\nTracing stopped.")