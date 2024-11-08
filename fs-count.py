from bcc import BPF
import time
import argparse
import subprocess
from bcc.utils import printb
from time import sleep

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

struct key_t {
    char fsname[32];
};

BPF_HASH(counts, struct key_t);

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
    char fstypename[32];
    struct qstr dname;

    struct key_t key = {};
    u64 zero=0, *val;

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
    

    bpf_probe_read_kernel(&mnt_point, sizeof(mnt_point), &mnt->mnt_root);
    if (!mnt_point)
        return 0;
    
    // read vfs_mount dentry
    bpf_probe_read_kernel(&dname, sizeof(dname), &mnt_point->d_name);
    
    // read dentry qstr
    bpf_probe_read_kernel(&fsname_ptr, sizeof(fsname_ptr), &dname.name);
    bpf_probe_read_kernel_str(&key.fsname, sizeof(key.fsname), fsname_ptr);
    

    val = counts.lookup_or_try_init(&key, &zero);
    if(val){
        (*val)++;
    }
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
b.attach_tracepoint(tp="syscalls:sys_enter_openat", fn_name="trace_sys_enter")

print("Tracing syscalls... Press Ctrl-C to end.")

# Format output
print("%10s %s" % ("count", "FILE-SYSTEM"))

try:
    sleep(99999999)
except KeyboardInterrupt:
    pass


counts = b.get_table("counts")
for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
    printb(b"%10d \"%s\"" % (v.value, k.fsname))