#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[1;31m"
#define COLOR_GREEN   "\033[1;32m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_BLUE    "\033[1;34m"

// Simplified syscall table (x86_64) — expand as needed
const char* syscall_names[] = {
    [0] = "read", [1] = "write", [2] = "open", [3] = "close",
    [5] = "fstat", [9] = "mmap", [12] = "brk", [17] = "pread64",
    [21] = "access", [59] = "execve", [60] = "exit", [62] = "kill",
    [63] = "uname", [80] = "chdir", [87] = "unlink", [89] = "readlink",
    [97] = "getuid", [102] = "getgid", [104] = "getpid", [202] = "futex",
    [231] = "exit_group", [257] = "openat"
};

void print_timestamp(char* buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *local = localtime(&now);
    strftime(buffer, size, "[%H:%M:%S]", local);
}

void print_syscall(FILE* logfile, long syscall_num) {
    const char* name = NULL;
    char timestamp[20];

    if (syscall_num >= 0 && syscall_num < sizeof(syscall_names) / sizeof(char*)) {
        name = syscall_names[syscall_num];
    }

    const char* color = COLOR_GREEN;

    if (syscall_num == 59 || syscall_num == 62 || syscall_num == 257 || syscall_num == 231)
        color = COLOR_RED;
    else if (syscall_num == 0 || syscall_num == 1 || syscall_num == 2)
        color = COLOR_BLUE;

    print_timestamp(timestamp, sizeof(timestamp));

    // Print to terminal
    if (name)
        printf("%s %sSyscall: %s (%ld)%s\n", timestamp, color, name, syscall_num, COLOR_RESET);
    else
        printf("%s %sSyscall: Unknown (%ld)%s\n", timestamp, COLOR_YELLOW, syscall_num, COLOR_RESET);

    // Log to file (no color)
    if (logfile) {
        if (name)
            fprintf(logfile, "%s Syscall: %s (%ld)\n", timestamp, name, syscall_num);
        else
            fprintf(logfile, "%s Syscall: Unknown (%ld)\n", timestamp, syscall_num);
        fflush(logfile);
    }
}

int main() {
    pid_t child;
    int status;
    struct user_regs_struct regs;

    // Open syscall log file
    FILE* logfile = fopen("logs/syscall_log.txt", "w");
    if (!logfile) {
        perror("Failed to open syscall_log.txt");
        return 1;
    }

    child = fork();
    if (child == 0) {
        // Redirect child's stdout to a file
        FILE* out = freopen("logs/child_output.txt", "w", stdout);
        if (!out) {
            perror("Failed to redirect child output");
            exit(1);
        }

        // Enable tracing
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl("/bin/ls", "ls", NULL);  // You can replace with any program to trace
    } else {
        while (1) {
            wait(&status);
            if (WIFEXITED(status)) break;

            ptrace(PTRACE_GETREGS, child, NULL, &regs);
            print_syscall(logfile, regs.orig_rax);
            ptrace(PTRACE_SYSCALL, child, NULL, NULL);
        }
    }

    fclose(logfile);
    return 0;
}
