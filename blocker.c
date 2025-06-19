#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <seccomp.h>
#include <string.h>
#include <errno.h>
#include <json-c/json.h>

// Apply seccomp filter from JSON policy
int apply_seccomp(const char *policy_file) {
    FILE *file = fopen(policy_file, "r");
    if (!file) {
        perror("[libblocker] Failed to open policy file");
        return -1;
    }

    fseek(file, 0, SEEK_END);
    long fsize = ftell(file);
    rewind(file);

    char *data = malloc(fsize + 1);
    if (!data) {
        fclose(file);
        fprintf(stderr, "[libblocker] Memory allocation failed\n");
        return -1;
    }

    fread(data, 1, fsize, file);
    data[fsize] = 0;
    fclose(file);

    struct json_object *parsed_json = json_tokener_parse(data);
    free(data);
    if (!parsed_json) {
        fprintf(stderr, "[libblocker] Failed to parse JSON\n");
        return -1;
    }

    struct json_object *syscalls;
    if (!json_object_object_get_ex(parsed_json, "block_syscalls", &syscalls)) {
        fprintf(stderr, "[libblocker] No 'block_syscalls' key found in policy\n");
        json_object_put(parsed_json);
        return -1;
    }

    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) {
        fprintf(stderr, "[libblocker] Failed to initialize seccomp\n");
        json_object_put(parsed_json);
        return -1;
    }

    size_t n = json_object_array_length(syscalls);
    for (size_t i = 0; i < n; i++) {
        const char *sc_name = json_object_get_string(json_object_array_get_idx(syscalls, i));
        int sc_id = seccomp_syscall_resolve_name(sc_name);
        if (sc_id == __NR_SCMP_ERROR) {
            fprintf(stderr, "[libblocker] Unknown syscall: %s\n", sc_name);
            continue;
        }
        if (seccomp_rule_add(ctx, SCMP_ACT_KILL, sc_id, 0) < 0) {
            fprintf(stderr, "[libblocker] Failed to add rule for syscall: %s\n", sc_name);
        }
    }

    if (seccomp_load(ctx) < 0) {
        fprintf(stderr, "[libblocker] Failed to load seccomp filter\n");
        seccomp_release(ctx);
        json_object_put(parsed_json);
        return -1;
    }

    seccomp_release(ctx);
    json_object_put(parsed_json);
    return 0;
}

// Constructor function that runs automatically when the shared library is loaded
__attribute__((constructor))
void init_blocker() {
    const char *policy_path = "./policy.json";
    fprintf(stderr, "[libblocker] Applying seccomp policy: %s\n", policy_path);
    if (apply_seccomp(policy_path) == 0) {
        fprintf(stderr, "[libblocker] Seccomp policy applied successfully\n");
    } else {
        fprintf(stderr, "[libblocker] Failed to apply seccomp policy\n");
    }
}
