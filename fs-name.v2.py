#!/usr/bin/python3
from bcc import BPF

# Define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/dcache.h>

struct read_args {
    u64 __unused;
    int fd;
    char *buf;
    size_t count;
};

int trace_read_entry(struct read_args *args) {
    struct task_struct *task;
    char fstype[32] = {};
    
    // Get current task_struct
    task = (struct task_struct *)bpf_get_current_task();
    
    // Access the file from the file descriptor table
    struct file *some_file = NULL;
    struct files_struct *files = NULL;
    struct fdtable *fdt = NULL;
    
    // Read task->files
    bpf_probe_read(&files, sizeof(files), &task->files);
    if (!files)
        return 0;
    
    // Read files->fdt
    bpf_probe_read(&fdt, sizeof(fdt), &files->fdt);
    if (!fdt)
        return 0;
    
    // Check if fd is within bounds
    unsigned int max_fds = 0;
    bpf_probe_read(&max_fds, sizeof(max_fds), &fdt->max_fds);
    if (args->fd < 0 || args->fd >= max_fds)
        return 0;
    
    // Read the file pointer from the fd table
    bpf_probe_read(&some_file, sizeof(some_file), &fdt->fd[args->fd]);
    if (!some_file)
        return 0;
    
    // Access the filesystem type through the inode and superblock
    struct inode *inode = NULL;
    struct super_block *sb = NULL;
    struct file_system_type *fs_type = NULL;
    const char *name = NULL;
    
    bpf_probe_read(&inode, sizeof(inode), &some_file->f_inode);
    if (!inode)
        return 0;
    
    bpf_probe_read(&sb, sizeof(sb), &inode->i_sb);
    if (!sb)
        return 0;
    
    bpf_probe_read(&fs_type, sizeof(fs_type), &sb->s_type);
    if (!fs_type)
        return 0;
    
    bpf_probe_read(&name, sizeof(name), &fs_type->name);
    if (!name)
        return 0;
    
    bpf_probe_read_str(fstype, sizeof(fstype), name);
    
    // Print PID and filesystem type
    bpf_trace_printk("Process %d is using file system type: %s\\n", task->pid, fstype);
    
    return 0;
}
"""

# Load BPF program
b = BPF(text=bpf_text)
b.attach_tracepoint(tp="syscalls:sys_enter_read", fn_name="trace_read_entry")

# Print header
print("Tracing read syscalls... Ctrl-C to end.")
print("%-6s %-16s" % ("PID", "FS TYPE"))

# Process events
try:
    while True:
        # Read and print trace output
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        print(msg)
except KeyboardInterrupt:
    pass
