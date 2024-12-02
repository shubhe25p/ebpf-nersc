#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <linux/types.h>

// Must match the struct definition in your BPF program
struct key_t {
    char fsname[32];
    __u64 bucket;
};

#define PIN_PATH "/sys/fs/bpf/fshist"  // adjust path as needed

int main()
{
    int map_fd;
    struct key_t key, next_key;
    __u64 value;

    // Open the pinned map
    map_fd = bpf_obj_get(PIN_PATH);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to open pinned map: %s\n", PIN_PATH);
        return 1;
    }

    // Read all entries
    memset(&key, 0, sizeof(key));
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
            printf("Filesystem: %-32s, Bucket: %-10llu, Value: %llu\n", 
                   next_key.fsname, 
                   next_key.bucket, 
                   value);
        }
        key = next_key;
    }

    close(map_fd);
    return 0;
}