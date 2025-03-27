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

struct fs_stat_t {
    char fstype[16];
};

TRACEPOINT_PROBE(syscalls, sys_enter_read)
{
    struct fs_stat_t stat = {0};
    struct task_struct *task;

    // Get current task_struct
    task = (struct task_struct *)bpf_get_current_task();
    // Read task->fs
    struct file *some_file = task->files->fdt->fd[args->fd];

    // Access the filesystem type name through the superblock
    const char *type_name = some_file->f_inode->i_sb->s_type->name;
    bpf_probe_read_kernel_str(stat.fstype, sizeof(stat.fstype), type_name);
    bpf_trace_printk("Process %d is using file system type: %s\\n", task->pid, stat.fstype);
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