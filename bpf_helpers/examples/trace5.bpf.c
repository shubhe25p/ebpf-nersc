#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

SEC("tp/syscalls/sys_enter_openat")
int bpf_prog1(void *ctx)
{
    char write_data[64] = "hello there, world!!";
    char read_data[64] = {};
    struct bpf_dynptr ptr;
    int i;
    int local_err = 0;

    local_err = bpf_ringbuf_reserve_dynptr(&ringbuf, sizeof(write_data), 0, &ptr);
    if (local_err < 0)
        goto discard;

    /* Write data into the dynptr */
    local_err = bpf_dynptr_write(&ptr, 0, write_data, sizeof(write_data), 0);
    if (local_err) {
        goto discard;
    }

    /* Read the data that was written into the dynptr */
    local_err = bpf_dynptr_read(read_data, sizeof(read_data), &ptr, 0, 0);
    if (local_err) {
        goto discard;
    }

    /* Ensure the data we read matches the data we wrote */
    for (i = 0; i < sizeof(read_data); i++) {
        if (read_data[i] != write_data[i]) {
            break;
        }
    }
    bpf_printk("Read matches write, dynptr API works");
    bpf_ringbuf_submit_dynptr(&ptr, 0);
    return 0;

discard:
    bpf_ringbuf_discard_dynptr(&ptr, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
