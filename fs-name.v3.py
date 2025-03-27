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
    struct files_struct *fs;
    struct fdtable *fdt;
    struct file **fd;
    struct path pwd_path;
    struct vfsmount *mnt;
    struct super_block *superblock;
    struct file_system_type *fstype;
    struct dentry *mnt_point;
    const char *fsname_ptr;
    char fsname[32];
    struct qstr dname;
    

    // Get current task_struct
    task = (struct task_struct *)bpf_get_current_task();
    // Read task->fs
    bpf_probe_read_kernel(&fs, sizeof(fs), &task->files);
    if (!fs)
        return 0;
    
    bpf_probe_read_kernel(&fdt, sizeof(fdt), &fs->fdt);
    if (!fdt)
        return 0;
    
    
    bpf_trace_printk("Process %d is using file system: %s\\n", task->pid, args->fd);
    return 0;
}
"""

b = BPF(text=bpf_text)

print("Tracing syscalls .. Press Ctrl-C to end.")
