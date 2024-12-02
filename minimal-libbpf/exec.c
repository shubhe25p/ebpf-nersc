// exec.c
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "exec.skel.h"

#define PIN_PATH "/sys/fs/bpf/proc_map"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct exec_bpf *skel;
    int err;

    // Set up libbpf logging
    libbpf_set_print(libbpf_print_fn);

    // Create BPF filesystem directory if it doesn't exist
    if (system("mkdir -p /sys/fs/bpf") != 0) {
        fprintf(stderr, "Failed to create /sys/fs/bpf directory\n");
        return 1;
    }

    // Remove existing pinned map if it exists
    unlink(PIN_PATH);

    // Open and load BPF program
    skel = exec_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // Set pinning path for the map
    LIBBPF_OPTS(bpf_object_open_opts, opts,
        .pin_root_path = "/sys/fs/bpf",
    );

    // Load BPF program
    err = exec_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        exec_bpf__destroy(skel);
        return 1;
    }

    // Attach the program
    err = exec_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        exec_bpf__destroy(skel);
        return 1;
    }

    printf("Successfully started! Map is pinned at %s\n", PIN_PATH);
    printf("Press Ctrl+C to stop.\n");

    while (1) {
        sleep(1);
    }

    exec_bpf__destroy(skel);
    return 0;
}