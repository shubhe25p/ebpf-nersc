#!/usr/bin/env python3

from bcc import BPF
import signal
import sys
from collections import defaultdict

# BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/mount.h>
#include <linux/path.h>
#include <linux/fs_struct.h>

struct key_t{
    char fsname[32];
    u64 bucket;
};

BPF_HASH(fshist, struct key_t, u64);

TRACEPOINT_PROBE(syscalls, sys_enter_read) {
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
    u64 count = args->count;

    struct key_t key = {};
    u64 zero=0, *val;

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
   

    if (count == 0)
        return 0;
    
    key.bucket = bpf_log2l(count);

    val = fshist.lookup_or_init(&key, &zero);
    (*val)++;
    return 0;
}
"""

# Load BPF program
b = BPF(text=bpf_text)

print("Tracing 'read' syscalls... Press Ctrl+C to end.")

# Handle Ctrl+C gracefully
def signal_ignore(signal, frame):
    print()

signal.signal(signal.SIGINT, signal_ignore)

# Wait until Ctrl+C
signal.pause()

# Print the histogram
print("\nHistogram of bytes requested in read() calls per fs:")

histogram = b.get_table("fshist")

fs_hist = defaultdict(lambda: defaultdict(int))

for k, v in histogram.items():
    fsname = k.fsname
    bucket = k.bucket
    count = v.value
    fs_hist[fsname][bucket] += count

for fs, buckets in fs_hist.items():
    print(f"\nFile System {fs}:")


    total_count = sum(buckets.values())
    print(f"Total Reads: {total_count}")
    
    # Prepare data for printing
    sorted_buckets = sorted(buckets.items())
    max_bucket = max(buckets.keys())
    
    # Print the histogram header
    print("       Bytes Read      : count     distribution")

    # Calculate the maximum count for scaling the histogram bars
    max_count = max(buckets.values())
    width = 40  # Adjust the width of the histogram bars as needed

    for b, c in sorted_buckets:
        # Compute the bucket range based on log2 boundaries
        low = (1 << b) if b > 0 else 0
        high = (1 << (b + 1)) - 1
        bar_len = int(c * width / max_count) if max_count > 0 else 0
        bar = '*' * bar_len
        print(f"{low:>10} -> {high:<10} : {c:<8} |{bar}")