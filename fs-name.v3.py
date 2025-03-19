from bcc import BPF
import time

bpf_text="""
#include <linux/sched.h>
#include <linux/mount.h>
#include <linux/path.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/dcache.h>

TRACEPOINT_PROBE(syscalls, sys_enter_read)
{
    char fsname[32];
    // think of storing fd somewhere
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const unsigned char *fs_name = task->files->fdt->fd[args->fd]->f_path.mnt->mnt_root->d_name.name;
    bpf_probe_read_kernel_str(&key.fsname, sizeof(key.fsname), fs_name);
    u64 ts = bpf_ktime_get_ns();
    
    bpf_trace_printk("Process %d is using file system: %s\\n", task->pid, fsname);
    return 0;
}
"""

b = BPF(text=bpf_text)

print("Tracing syscalls .. Press Ctrl-C to end.")

# Format output
print("%-18s %-6s %s" % ("TIME(s)", "PID", "FSNAME"))


# Trace output
start_time = time.time()
try:
    while True:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        elapsed = time.time() - start_time
        
        fields = msg.decode('utf-8', 'replace').split("is using file system: ")
        if len(fields) == 2:
            pid_info = fields[0].strip().split()
            if len(pid_info) >= 2:
                pid = pid_info[1]
                fs_name = fields[1]
                print("%-18.9f %-6s %s" % (elapsed, pid, fs_name))
except KeyboardInterrupt:
    print("\nTracing stopped.")