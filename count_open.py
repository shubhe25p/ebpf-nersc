from bcc import BPF
from bcc.utils import printb

# define BPF program
prog = """
#include <linux/sched.h>


// define output data structure in C
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_HASH(counts, struct data_t, int, 256);

BPF_PERF_OUTPUT(events);

int hello(struct pt_regs *ctx) {
    struct data_t data = {};
    char *target="random_access";
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    if (data.comm[0] == 'r' && data.comm[1] == 'a' && data.comm[2] == 'n' && data.comm[3] == 'd' && data.comm[4] == 'o' &&
    data.comm[5] == 'm' && data.comm[6] == '_' && data.comm[7] == 'a' && data.comm[8] == 'c' && data.comm[9] == 'c' &&
    data.comm[10] == 'e' && data.comm[11] == 's' && data.comm[12] == 's' && data.comm[13] == 0) {
    int count=1;
    int *ptr=counts.lookup(&data);
    if(ptr)
        counts.increment(data);
    else
        counts.insert(&data, &count);
    events.perf_submit(ctx, &data, sizeof(data));
    }


    return 0;
}
"""

# load BPF program
b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("openat"), fn_name="hello")

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

# process event
start = 0
def print_event(cpu, data, size):
    global start
    event = b["events"].event(data)
    if start == 0:
            start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    printb(b"%-18.9f %-16s %-6d %s" % (time_s, event.comm, event.pid,
        b"Hello, random file!"))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
counts = b.get_table("counts")

while 1:
    try:
        b.perf_buffer_poll()
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        printb(b"%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
    except KeyboardInterrupt:
        for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
            print("%-16s %8d" % (k.comm, v.value))
        exit()