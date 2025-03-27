from bcc import BPF
import time

bpf_text="""
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/mount.h>
#include <linux/path.h>
#include <linux/fs_struct.h>

TRACEPOINT_PROBE(syscalls, sys_enter_read)
{
    struct task_struct *task;
    struct fs_struct *fs;
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
    bpf_probe_read_kernel(&fs, sizeof(fs), &task->fs);
    if (!fs)
        return 0;

    // Read fs->pwd (current working directory)
    bpf_probe_read_kernel(&pwd_path, sizeof(pwd_path), &fs->pwd);

    // Read pwd_path.mnt (vfsmount)
    bpf_probe_read_kernel(&mnt, sizeof(mnt), &pwd_path.mnt);
    if (!mnt)
        return 0;
    

    bpf_probe_read_kernel(&mnt_point, sizeof(mnt_point), &mnt->mnt_root);
    if (!mnt_point)
        return 0;
    
    // read vfs_mount dentry
    bpf_probe_read_kernel(&dname, sizeof(dname), &mnt_point->d_name);
    
    // read dentry qstr
    bpf_probe_read_kernel(&fsname_ptr, sizeof(fsname_ptr), &dname.name);
    bpf_probe_read_kernel_str(&fsname, sizeof(fsname), fsname_ptr);
    
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