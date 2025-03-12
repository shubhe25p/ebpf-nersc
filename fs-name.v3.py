from bcc import BPF
import time



bpf_text="""
#include <linux/sched.h>

int trace_sys_enter(void* ctx)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bpf_trace_printk("Process %d is using file system: %d\\n", task->on_cpu, task->on_cpu);
}
"""

b = BPF(text=bpf_text)

b.attach_tracepoint(tp="syscalls:sys_enter_open", fn_name="trace_sys_enter")

print("Tracing syscalls .. Press Ctrl-C to end.")

# Format output
print("%-18s %-6s %s" % ("TIME(s)", "PID", "FILE SYSTEM"))


# Trace output
start_time = time.time()
try:
    while True:
        elapsed = time.time() - start_time
        fields = msg.decode('utf-8', 'replace').split("is using file system: ")
        if len(fields) == 2:
            pid_info = fields[0].strip().split()
            if len(pid_info) == 2:
                pid = pid_info[1]
                fs_name = fields[1]
                print("%-18.9f %-6s %s" % (elapsed, pid, fs_name))
except KeyboardInterrupt:
    print("\nTracing stopped.")