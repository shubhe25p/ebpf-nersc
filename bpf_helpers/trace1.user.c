#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include "trace1.skel.h"

int main(void) {
    struct trace1_openat_bpf *skel;
    uint32_t key = 0, next_key;
    uint64_t value;
    int err;

    skel = trace1_openat_bpf__open_and_load();
    if (!skel) return 1;
    err = trace1_openat_bpf__attach(skel);
    if (err) goto cleanup;

    printf("Polling… CTRL-C to exit\n");
    while (bpf_map__get_next_key(skel->maps.cnt, &key, &next_key) == 0) {
        if (bpf_map__lookup_elem(skel->maps.cnt, &next_key, &value) == 0)
            printf("openat calls: %llu\n", value);
        key = next_key;
    }

cleanup:
    trace1_openat_bpf__destroy(skel);
    return err;
}
