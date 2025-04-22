#!/usr/bin/python3

import sys
import time

from bcc import BPF

src = r"""
BPF_RINGBUF_OUTPUT(buffer, 1 << 4);

struct event {
    u32 pid;
    u32 tgid;
    int fd;
};

TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    int zero = 0;

    struct event event = {};
    event.fd = args->fd;
    event.pid = bpf_get_current_pid_tgid();
    event.tgid = bpf_get_current_pid_tgid() >> 32;

    buffer.ringbuf_output(&event, sizeof(event), 0);

    return 0;
}
"""

b = BPF(text=src)

def callback(ctx, data, size):
    event = b['buffer'].event(data)
    print("%10d %10d" % event.fd, event.tgid)

b['buffer'].open_ring_buffer(callback)

print("Printing read() calls, ctrl-c to exit.")

print("%10s %10s" % ("DIR_FD", "PID"))

try:
    while 1:
        b.ring_buffer_poll()
        # or b.ring_buffer_consume()
        time.sleep(0.5)
except KeyboardInterrupt:
    sys.exit()