#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

int main() {
    int map_fd = bpf_obj_get("/sys/fs/bpf/fhist");
    if (map_fd < 0) {
        perror("Failed to open pinned map");
        return 1;
    }

    if (bpf_map_lookup_elem(map_fd, &key, &value) == 0) {
        printf("Value for key %llu\n", value);
    } else {
        perror("Failed to read map");
    }

    close(map_fd);
    return 0;
}