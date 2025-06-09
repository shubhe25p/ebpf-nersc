// trace1.user.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "trace1.skel.h"    // generated via: bpftool gen skeleton trace1.bpf.o -o trace1.skel.h

int main(int argc, char **argv)
{
    struct trace1_bpf *skel;
    int err, map_fd;
    __u32 key = 0, next_key;
    __u64 value;

    /* 1) Open & load skeleton (auto-bumps RLIMIT_MEMLOCK) */
    skel = trace1_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "ERROR: opening BPF skeleton\n");
        return 1;
    }

    /* 2) Attach to tracepoint */
    err = trace1_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "ERROR: attaching BPF program: %d\n", err);
        goto cleanup;
    }

    /* 3) Get raw map FD for FD-API calls */
    map_fd = bpf_map__fd(skel->maps.cnt);

    printf("Polling map via FD API... Ctrl-C to exit\n");
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0)
            printf("openat[%u] = %llu\n", next_key, value);
        key = next_key;
    }

cleanup:
    trace1_bpf__destroy(skel);
    return err;
}
