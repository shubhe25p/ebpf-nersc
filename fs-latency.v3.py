from bcc import BPF
import signal
from collections import defaultdict


bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/mount.h>

struct fs_stat_t {
    u32 pid;
    u32 sz;
    u64 bucket;
    u64 ts;
    u64 delta_us;
    char fstype[32];
    char name[DNAME_INLINE_LEN];
    char comm[TASK_COMM_LEN];
};



BPF_HASH(read_start, pid_t, struct fs_stat_t);
BPF_HASH(fs_latency_hist, struct fs_stat_t, u64);
// BPF_PERF_OUTPUT(events);

static int trace_rw_entry(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count)
{
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    u32 pid = bpf_get_current_pid_tgid();

    // skip I/O lacking a filename
    struct dentry *de = file->f_path.dentry;
    int mode = file->f_inode->i_mode;
    if (de->d_name.len == 0)
        return 0;

    // store size and timestamp by pid
    struct fs_stat_t fs_info = {};
    fs_info.pid=pid;
    fs_info.sz=count;

    // grab file system type
    const char* fstype_name = file->f_inode->i_sb->s_type->name;
    bpf_probe_read_kernel(&fs_info.fstype, sizeof(fs_info.fstype), fstype_name);

    // grab file name
    struct qstr d_name = de->d_name;
    bpf_probe_read_kernel(&fs_info.name, sizeof(fs_info.name), d_name.name);
    bpf_get_current_comm(&fs_info.comm, sizeof(fs_info.comm));

    fs_info.ts = bpf_ktime_get_ns();
    read_start.update(&pid, &fs_info);
    return 0;
}

int trace_read_entry(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count)
{
    // skip non-sync I/O; see kernel code for __vfs_read()
    if (!(file->f_op->read_iter))
        return 0;
    return trace_rw_entry(ctx, file, buf, count);
}

int trace_read_return(struct pt_regs *ctx)
{
    u64 zero = 0, *count;
    u32 pid = bpf_get_current_pid_tgid();
    struct fs_stat_t *fs_info = read_start.lookup(&pid);
    if (fs_info == 0)
        return 0;
    

    u64 latency = bpf_ktime_get_ns() - fs_info->ts;
    latency /= 1000;  // convert to microseconds
    fs_info->bucket = bpf_log2l(latency);
    fs_info->delta_us = latency;
    count = fs_latency_hist.lookup_or_init(fs_info, &zero);
    (*count)++;
    read_start.delete(&pid);
    // events.perf_submit(ctx, fs_info, sizeof(*fs_info));
    return 0;   
}


"""

b = BPF(text=bpf_text)
try:
    b.attach_kprobe(event="__vfs_read", fn_name="trace_read_entry")
    b.attach_kretprobe(event="__vfs_read", fn_name="trace_read_return")
except Exception:
    print('Current kernel does not have __vfs_read, try vfs_read instead')
    b.attach_kprobe(event="vfs_read", fn_name="trace_read_entry")
    b.attach_kretprobe(event="vfs_read", fn_name="trace_read_return")

print("Tracing FileSystem I/O... Hit Ctrl-C to end.")


print("\nHistogram of latency requested in read() calls per fs:")


# print("%-8s %-14s %-6s %1s %-7s %7s %s" % ("TIME(s)", "COMM", "TID", "FSTYPE",
#     "BYTES", "LAT(ms)", "FILENAME"))
    
# start_ts = time.time()
# def print_event(cpu, data, size):
#     event = b["events"].event(data)

#     ms = float(event.delta_us) / 1000
#     fname = event.name.decode('utf-8', 'replace')
#     fstype = event.fstype.decode('utf-8', 'replace')

#     print("%-8.3f %-14.14s %-6s %1s %-7s %7.2f %s" % (
#         time.time() - start_ts, event.comm.decode('utf-8', 'replace'),
#         event.pid, fstype, event.bucket, ms, fname))

# b["events"].open_perf_buffer(print_event)
# while 1:
#     try:
#         b.perf_buffer_poll()
#     except KeyboardInterrupt:
#         exit()

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
    fsname = k.fstype
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
