from bcc import BPF
from bcc.utils import printb

# define BPF program
prog = """
#include <linux/sched.h>

static inline int checkstring(char* input, char* target){
    int len=sizeof(input) > sizeof(target) ? sizeof(target) : sizeof(input);
    int i=0;
    int res=1;
    while(i<sizeof(input) && i<sizeof(target)){
        if(input[i]!=target[i])
            res=0;
        i++;
    }
    return res;
}

// define output data structure in C
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

int hello(struct pt_regs *ctx) {
    struct data_t data = {};
    char *target="random_access";
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    if(checkstring(&data.comm[0], target)){
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
while 1:
    try:
        b.perf_buffer_poll()
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        printb(b"%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
    except KeyboardInterrupt:
        exit()