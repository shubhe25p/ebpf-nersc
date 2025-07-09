#include <stdio.h>
#include <bpf/libbpf.h>
#include "cleaner.skel.h"

int main()
{
    struct cleaner_bpf *skel;
    int err;

    skel = cleaner_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        return 1;
    }

    err = cleaner_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs\n");
        goto cleanup;
    }

    printf("BPF program loaded and running...\n");

    while (1) {
        sleep(10);

        // Trigger cleanup periodically
        err = bpf_program__attach_iter(skel->progs.run_cleanup, NULL);
        if (err)
            fprintf(stderr, "Failed to trigger cleanup: %d\n", err);
        else
            printf("Cleanup triggered\n");
    }

cleanup:
    cleaner_bpf__destroy(skel);
    return -err;
}