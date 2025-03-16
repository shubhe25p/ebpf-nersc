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

# define BPF program
bpf_text = """
#include <linux/sched.h>
#include <linux/mount.h>
#include <linux/path.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>

struct key_t{
    char fsname[32];
    u64 bucket;
};
BPF_HASH(start, struct key_t);
BPF_HASH(fshist, struct key_t, u64);


// time block I/O
TRACEPOINT_PROBE(syscalls, sys_enter_read)
{
    
    char fsname[32];
    struct key_t key = {};

    // Get current task_struct
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const unsigned char *name = task->fs->pwd.mnt->mnt_root->d_name.name;
    bpf_probe_read_kernel_str(&key.fsname, sizeof(key.fsname), name);
    
    u64 ts = bpf_ktime_get_ns();
    start.update(&key, &ts);
    return 0;
}


// output
TRACEPOINT_PROBE(syscalls, sys_exit_read) {
    u64 *tsp, delta;
    u64 zero=0, *val;
    struct key_t key = {};

    

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const unsigned char *name = task->fs->pwd.mnt->mnt_root->d_name.name;
    bpf_probe_read_kernel_str(&key.fsname, sizeof(key.fsname), name);
    
    // fetch timestamp and calculate delta
    tsp = start.lookup(&key);
    if (tsp == 0) {
        return 0;   // missed issue
    }
    delta = bpf_ktime_get_ns() - *tsp;

    delta /= 1000;

    
    key.bucket = bpf_log2l(delta);

    val = fshist.lookup_or_init(&key, &zero);
    (*val)++;
    start.delete(&key);
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
