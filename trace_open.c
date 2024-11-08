#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

__attribute__((noinline)) void open_file() {
    int fd = open("/home/osuse", O_RDONLY);
    if (fd == -1) {
        perror("Failed to open /proc/version");
        exit(EXIT_FAILURE);
    } else {
        printf("Successfully opened /proc/version\n");
        close(fd);
    }
}

int main() {
    open_file();
    return 0;
}
