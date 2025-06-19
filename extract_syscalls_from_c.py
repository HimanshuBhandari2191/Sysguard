import re
import sys

# Map common C functions to Linux syscalls
FUNC_TO_SYSCALL = {
    "open": "open",
    "fopen": "open",
    "creat": "open",
    "read": "read",
    "fread": "read",
    "write": "write",
    "fwrite": "write",
    "close": "close",
    "fclose": "close",
    "fork": "fork",
    "vfork": "fork",
    "execve": "execve",
    "execvp": "execve",
    "execl": "execve",
    "ptrace": "ptrace",
    "wait": "wait4",
    "waitpid": "wait4",
    "setuid": "setuid",
    "kill": "kill",
    "chmod": "chmod",
    "unlink": "unlink",
    "remove": "unlink",
    "mmap": "mmap",
    "munmap": "munmap",
    "stat": "stat",
    "lstat": "lstat",
    "system": "execve",      # shell call
    "nanosleep": "nanosleep",
    "clone": "clone",
    "socket": "socket",
    "connect": "connect",
    "accept": "accept",
    "send": "send",
    "recv": "recv",
    "bind": "bind",
    "listen": "listen",
}

def extract_function_calls(c_code):
    # Match C-style function calls: func_name(...)
    matches = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', c_code)
    return matches

def map_to_syscalls(function_calls):
    syscalls = []
    for func in function_calls:
        if func in FUNC_TO_SYSCALL:
            syscalls.append(FUNC_TO_SYSCALL[func])
        else:
            syscalls.append("<OOV>")  # For unseen syscalls
    return syscalls

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 extract_syscalls_from_c.py <input.c>")
        sys.exit(1)

    filename = sys.argv[1]
    try:
        with open(filename, "r") as f:
            c_code = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)

    function_calls = extract_function_calls(c_code)
    syscall_sequence = map_to_syscalls(function_calls)

    if syscall_sequence:
        print(" ".join(syscall_sequence))
    else:
        print("No known syscall-like function calls detected.")

if __name__ == "__main__":
    main()
