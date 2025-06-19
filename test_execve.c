#include <stdio.h>
#include <unistd.h>

int main() {
    char *argv[] = {"/bin/ls", NULL};
    char *envp[] = {NULL};

    printf("Trying to exec /bin/ls...\n");

    if (execve("/bin/ls", argv, envp) == -1) {
        perror("execve failed");
    }

    return 0;
}
