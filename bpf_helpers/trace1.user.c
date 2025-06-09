// trace1.c make sure to gen skel file before running this
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "trace1.skel.h"

static volatile sig_atomic_t exiting = 0;

void handle_signal(int sig) {
    exiting = 1;
}

int main(int argc, char **argv) {
    struct trace1_bpf *skel;
    int map_fd;
    int err;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    skel = trace1_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }
    err = trace1_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    map_fd = bpf_map__fd(skel->maps.cnt);

    printf("Polling cnt map every 5 seconds. Ctrl+C to exit.\n");
    while (!exiting) {
        sleep(5);
        u32 key = 0, next_key;
        u64 value;
        while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
            if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0)
                printf("key=%u val=%llu\n", next_key, value);
            key = next_key;
        }
    }

cleanup:
    trace1_bpf__destroy(skel);
    return 0;
}