#include <unistd.h>
#include <sys/socket.h>
#include <stdio.h>

int main() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    write(sock, "Hello", 5);
    nanosleep(NULL, NULL);
    return 0;
}
