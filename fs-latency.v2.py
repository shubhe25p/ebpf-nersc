#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# biolatency    Summarize block device I/O latency as a histogram.
#       For Linux, uses BCC, eBPF.
#
# USAGE: biolatency [-h] [-T] [-Q] [-m] [-D] [-F] [-e] [-j] [-d DISK] [interval] [count]
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 20-Sep-2015   Brendan Gregg   Created this.
# 31-Mar-2022   Rocky Xing      Added disk filter support.
# 01-Aug-2023   Jerome Marchand Added support for block tracepoints
# 12-Nov-2024   Shubh Pachchigar Add FS VFS calls latency

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
import ctypes as ct
import os
from bcc.utils import printb
import subprocess
import signal
import sys
from collections import defaultdict

bpf_text = """
#include <linux/sched.h>
#include <linux/mount.h>
#include <linux/path.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <uapi/linux/bpf.h>
// #include <bpf/bpf_helpers.h>

void bpf_rcu_read_lock(void) __ksym;
void bpf_rcu_read_unlock(void) __ksym;

struct fs_key {
    char fsname[32];
    u64 bucket;
};

struct fd_info {
    u32 pid;
    unsigned int fd;
};

BPF_HASH(read_start, struct fs_key);
BPF_HASH(fs_latency_hist, struct fs_key, u64);
BPF_HASH(pid_fd_cache, u32, unsigned int);
BPF_HASH(fd_fs_cache, struct fd_info, struct fs_key);

TRACEPOINT_PROBE(syscalls, sys_enter_read)
{   
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    struct fdtable *fdt;
    struct file *fd;
    struct fs_key key = {};
    struct fd_info info = {};

    info.pid = bpf_get_current_pid_tgid();
    info.fd = args->fd;
    pid_fd_cache.update(&info.pid, &info.fd);
    struct fs_key *cached_key = fd_fs_cache.lookup(&info);
    if(cached_key == NULL)
    {
        // Get current task_struct
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        struct files_struct *files = task->files;
        
       bpf_rcu_read_lock();
       fdt = files->fdt;
       bpf_rcu_read_unlock();

        bpf_rcu_read_lock();
        fdt->fd[args->fd];
        bpf_rcu_read_unlock();
        
        const unsigned char *fs_name = fd->f_inode->i_sb->s_type->name;
        bpf_probe_read_kernel_str(&key.fsname, sizeof(key.fsname), fs_name);
        fd_fs_cache.update(&info, &key);
        u64 ts = bpf_ktime_get_ns();
        read_start.update(&key, &ts);
    }
    else
    {
        u64 ts = bpf_ktime_get_ns();
        read_start.update(cached_key, &ts);
    }
   
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_read) {
    u64 *start_ts, latency;
    u64 zero = 0, *count;
    struct fs_key key = {};
    struct fd_info info = {};
    info.pid = bpf_get_current_pid_tgid();
    unsigned int* fdptr = pid_fd_cache.lookup(&info.pid);
    if(fdptr==NULL)
        return 0;
    info.fd = *fdptr;
    struct fs_key *cached_key = fd_fs_cache.lookup(&info);
    if(cached_key==NULL)
        return 0;
    
    // fetch timestamp and calculate delta
    start_ts = read_start.lookup(cached_key);
    if (start_ts == 0) {
        return 0;   // missed issue
    }
    latency = bpf_ktime_get_ns() - *start_ts;

    latency /= 1000;  // convert to microseconds
    
    cached_key->bucket = bpf_log2l(latency);

    count = fs_latency_hist.lookup_or_init(cached_key, &zero);
    (*count)++;
    read_start.delete(cached_key);
    pid_fd_cache.delete(&info.pid);
    fd_fs_cache.delete(&info);
    return 0;
}
"""

label = "usecs"

# load BPF program
b = BPF(text=bpf_text)


print("Tracing FileSystem I/O... Hit Ctrl-C to end.")


def signal_ignore(signal, frame):
    print()

signal.signal(signal.SIGINT, signal_ignore)

# Wait until Ctrl+C
signal.pause()

# Print the histogram
print("\nHistogram of latency requested in read() calls per fs:")

histogram = b.get_table("fs_latency_hist")

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
    print("       usecs      : count     distribution")

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
