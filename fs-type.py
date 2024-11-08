from bcc import BPF
import time
import argparse
import subprocess

parser = argparse.ArgumentParser(
    description="Show FS calls from a process",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("-n", "--name",
    help="name of the process")

args = parser.parse_args()

def get_pid_by_name(process_name):
    try:
        # Run the ps command to find processes by name
        result = subprocess.check_output(["ps", "-e", "-o", "pid,comm"], universal_newlines=True)
        pids = []
        for line in result.splitlines()[1:]:
            pid, name = line.split(None, 1)
            if process_name.lower() in name.lower():
                pids.append(int(pid))
        return pids
    except subprocess.CalledProcessError:
        return []

# BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/mount.h>
#include <linux/path.h>
#include <linux/fs_struct.h>

int trace_sys_enter(struct pt_regs *ctx) {
    struct task_struct *task;
    struct fs_struct *fs;
    struct path pwd_path;
    struct vfsmount *mnt;
    struct super_block *superblock;
    struct file_system_type *fstype;
    struct dentry *mnt_point;
    const char *fsname_ptr;
    char fsname[32];
    u32 pid = bpf_get_current_pid_tgid();
    if (FILTER_PID)
        return 0;

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

    // Read mnt->mnt_sb (super_block)
    

    bpf_probe_read_kernel(&mnt_point, sizeof(mnt_point), &mnt->mnt_root);
    if (!mnt_point)
        return 0;
    
    bpf_probe_read_kernel(&superblock, sizeof(superblock), &mnt_point->d_sb);
    if (!superblock)
        return 0;
    
    // Read superblock->s_type (file_system_type)
    bpf_probe_read_kernel(&fstype, sizeof(fstype), &superblock->s_type);
    if (!fstype)
        return 0;

    // Read fstype->name (file system type name)
    bpf_probe_read_kernel(&fsname_ptr, sizeof(fsname_ptr), &fstype->name);
    bpf_probe_read_kernel_str(&fsname, sizeof(fsname), fsname_ptr);

    // Send the file system name to user space
    bpf_trace_printk("Process %d is using file system: %s\\n", task->pid, fsname);

    return 0;
}
"""

if args.name:
    pids=get_pid_by_name(args.name)
    if pids:
        args.pid=pids[0]

if args.pid:
    bpf_text = bpf_text.replace('FILTER_PID', 'pid != %s' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER_PID', '0')

b = BPF(text=bpf_text)

# Attach to the sys_enter tracepoint
b.attach_tracepoint(tp="syscalls:sys_exit_write", fn_name="trace_sys_enter")

print("Tracing syscalls... Press Ctrl-C to end.")

# Format output
print("%-18s %-6s %s" % ("TIME(s)", "PID", "FILE SYSTEM"))


# Trace output
start_time = time.time()
try:
    while True:
        # Read messages from the BPF ring buffer
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