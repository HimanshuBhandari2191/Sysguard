#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <seccomp.h>
#include <json-c/json.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h> // For va_list, va_start, va_end
#include <fcntl.h>  // <--- ADD THIS LINE FOR O_CREAT and O_TMPFILE

// Path to policy file
#define POLICY_FILE "./policy.json"

// Function to apply seccomp policy from JSON
void apply_seccomp_policy() {
    FILE *file = fopen(POLICY_FILE, "r");
    if (!file) {
        perror("[libblocker] Failed to open policy.json");
        return;
    }

    fseek(file, 0, SEEK_END);
    long len = ftell(file);
    rewind(file);

    char *file_contents = malloc(len + 1);
    if (!file_contents) { // Check for malloc failure
        perror("[libblocker] Failed to allocate memory for policy file");
        fclose(file);
        return;
    }
    fread(file_contents, 1, len, file);
    file_contents[len] = '\0';
    fclose(file);

    json_object *jso = json_tokener_parse(file_contents);
    free(file_contents);

    if (!jso) {
        fprintf(stderr, "[libblocker] Failed to parse policy.json - likely malformed JSON\n");
        return;
    }

    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) {
        fprintf(stderr, "[libblocker] seccomp_init failed\n");
        json_object_put(jso);
        return;
    }

    // --- Process simple syscall names from "block_syscalls" array ---
    json_object *block_array;
    if (json_object_object_get_ex(jso, "block_syscalls", &block_array)) {
        if (!json_object_is_type(block_array, json_type_array)) {
            fprintf(stderr, "[libblocker] 'block_syscalls' is not an array in policy.json\n");
        } else {
            int array_len = json_object_array_length(block_array);
            for (int i = 0; i < array_len; i++) {
                json_object *entry = json_object_array_get_idx(block_array, i);
                const char *syscall_name = json_object_get_string(entry);

                if (syscall_name) {
                    int syscall_num = seccomp_syscall_resolve_name(syscall_name);
                    if (syscall_num == __NR_SCMP_ERROR) {
                        fprintf(stderr, "[libblocker] Unknown syscall name in policy: %s\n", syscall_name);
                        continue;
                    }

                    printf("[libblocker] Blocking syscall: %s\n", syscall_name);
                    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), syscall_num, 0) < 0) {
                      fprintf(stderr, "[libblocker] Failed to add rule for: %s\n", syscall_name);
                    }
                }
            }
        }
    } else {
        fprintf(stderr, "[libblocker] 'block_syscalls' key not found in policy.json (optional if only using args blocking)\n");
    }

    // Load the seccomp filter
    if (seccomp_load(ctx) < 0) {
        fprintf(stderr, "[libblocker] Failed to load seccomp rules\n");
    }

    seccomp_release(ctx);
    json_object_put(jso);
}

// Global variable for the real open function
typedef int (*orig_open_f_type)(const char *pathname, int flags, ...);
orig_open_f_type orig_open = NULL; // Initialize to NULL

// Intercepted open function
int open(const char *pathname, int flags, ...) {
    // This is run by the LD_PRELOAD mechanism.
    // It is called BEFORE the actual `open` syscall.

    // Sensitive files to block
    const char *blocked_paths[] = {
        "/etc/passwd",
        "/etc/shadow",
        NULL // Sentinel to mark end of array
    };

    printf("[libblocker] Intercepted open: %s\n", pathname);

    for (int i = 0; blocked_paths[i] != NULL; i++) {
        if (strcmp(pathname, blocked_paths[i]) == 0) {
            fprintf(stderr, "[libblocker] Blocking access to sensitive file: %s\n", pathname);
            errno = EPERM; // Set errno to indicate permission denied
            return -1;     // Return -1 to simulate failure
        }
    }

    // Get the real open function if not already obtained
    // This needs to be done carefully as dlsym itself might call open.
    // Best practice is to get it once in init.
    if (orig_open == NULL) { // Should ideally be set by init()
        orig_open = (orig_open_f_type)dlsym(RTLD_NEXT, "open");
        if (!orig_open) {
            fprintf(stderr, "[libblocker] Error: could not find real open function in intercepted open\n");
            errno = ENOSYS; // No system call
            return -1;
        }
    }

    // Call the original open function with its original arguments
    va_list args;
    va_start(args, flags);
    mode_t mode = 0; // Default for flags without O_CREAT
    // If O_CREAT or O_TMPFILE is set, a third argument (mode_t) is expected.
    // Check flags to correctly pass the mode argument.
    if ((flags & O_CREAT) || (flags & O_TMPFILE)) {
        mode = va_arg(args, mode_t);
    }
    va_end(args);

    int fd = orig_open(pathname, flags, mode);
    return fd;
}


// Constructor to run before main()
__attribute__((constructor)) void init() {
    printf("[libblocker] Initializing libblocker...\n");
    // Get the original open function pointer at initialization
    orig_open = (orig_open_f_type)dlsym(RTLD_NEXT, "open");
    if (!orig_open) {
        fprintf(stderr, "[libblocker] Error at init: could not find real open function. Path interception might fail.\n");
    }

    printf("[libblocker] Applying seccomp policy from %s\n", POLICY_FILE);
    apply_seccomp_policy();
}
