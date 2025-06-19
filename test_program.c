#include <unistd.h>
#include <fcntl.h>

int main() {
    char buffer[100];
    int fd = open("file.txt", O_RDONLY);
    read(fd, buffer, 100);
    close(fd);
    char *args[] = {"/bin/sh", NULL};
    execve("/bin/sh", args, NULL);
    return 0;
}
