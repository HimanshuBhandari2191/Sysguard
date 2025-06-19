// test_fork.c
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>

int main() {
    printf("Attempting to fork multiple times...\n");

    int max_forks = 10;  // Limit to avoid actual fork bomb
    for (int i = 0; i < max_forks; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            printf("Child process created: PID=%d\n", getpid());
            exit(0);  // Each child exits immediately
        } else if (pid < 0) {
            perror("fork failed");
            break;
        }
    }

    printf("Forking complete or blocked.\n");
    return 0;
}
