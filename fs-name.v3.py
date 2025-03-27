from bcc import BPF
import time

bpf_text="""
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/mount.h>
#include <linux/path.h>
#include <linux/fs_struct.h>

TRACEPOINT_PROBE(syscalls, sys_enter_read)
{
    struct task_struct *task;
    char fsname[32];
    struct qstr dname;
    

    // Get current task_struct
    task = (struct task_struct *)bpf_get_current_task();
    // Read task->fs
    struct file *some_file = task->files->fdt->fd[args->fd];

    int bs= some_file->f_inode->i_sb->s_type->fs_flags;
    // bpf_probe_read_kernel_str(&fsname, sizeof(fsname), name);
    bpf_trace_printk("Process %d is using file system1: %lu\\n", task->pid, bs);
    return 0;
}
"""

b = BPF(text=bpf_text)

print("Tracing syscalls .. Press Ctrl-C to end.")


# Trace output
start_time = time.time()
try:
    while True:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        elapsed = time.time() - start_time
except KeyboardInterrupt:
    print("\nTracing stopped.")