from bcc import BPF

# Define the BPF program
bpf_text = """
#include <linux/sched.h>
#include <uapi/linux/bpf.h>

BPF_PERF_OUTPUT(events);

struct data_t {
    char message[256];
};

int syscall_execve(void *ctx) {
    struct data_t data = {};
    char msg[] = "Hello, World!";
    bpf_trace_printk("Hello world\\n");
    return 0;
}
"""

# Load the BPF program
b = BPF(text=bpf_text)

# Attach the BPF program to the execve syscall
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="syscall_execve")

# Define a callback function to process events
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"{event.message}")

# Open the perf buffer for events
b["events"].open_perf_buffer(print_event)

print("Tracing execve syscalls... Press Ctrl+C to exit.")

# Poll for events
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()