#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

// Function to randomly open, read, and close files
void random_file_operations(const char *files[], int num_files) {
    char buffer[128];
    int i, file_index;
    FILE *file;

    for (i = 0; i < 5; i++) { // Perform 10 random operations
        // Select a random file from the list
        file_index = rand() % num_files;
        const char *filename = files[file_index];

        // Open the file
        file = fopen(filename, "r");
        if (file == NULL) {
            perror("Failed to open file");
            continue;
        }

        // Read some bytes from the file
        size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, file);
        if (bytes_read > 0) {
            buffer[bytes_read] = '\0'; // Null-terminate the buffer
            printf("Read %zu bytes from %s: %s\n", bytes_read, filename, buffer);
        } else {
            perror("Failed to read file");
        }

        // Close the file
        fclose(file);

        // Sleep for a short duration to simulate some delay
        usleep(500000); // 500 milliseconds
    }
}

int main() {
    // Seed the random number generator
    srand(time(NULL));

    // List of system files to operate on
    const char *files[] = {
        "/etc/hosts",
        "/etc/passwd",
        "/etc/group",
        "/etc/hostname",
        "/etc/resolv.conf"
    };
    int num_files = sizeof(files) / sizeof(files[0]);

    // Perform random file operations
    random_file_operations(files, num_files);

    return 0;
}