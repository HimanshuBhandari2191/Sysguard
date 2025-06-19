#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
    printf("Trying to open a file...\n");
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd < 0) {
        perror("open failed");
    } else {
        printf("File opened successfully (fd=%d)\n", fd);
        close(fd);
    }
    return 0;
}
