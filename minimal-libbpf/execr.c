// map_reader.c
#include <stdio.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#define PIN_PATH "/sys/fs/bpf/proc_map"

int main()
{
    int map_fd;
    int err;
    __u32 key, next_key;
    char value[16];

    // Open the pinned map
    map_fd = bpf_obj_get(PIN_PATH);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to open pinned map\n");
        return 1;
    }

    // Read and print all entries
    key = 0;
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        err = bpf_map_lookup_elem(map_fd, &next_key, value);
        if (err == 0) {
            printf("PID: %u, Command: %s\n", next_key, value);
        }
        key = next_key;
    }

    close(map_fd);
    return 0;
}