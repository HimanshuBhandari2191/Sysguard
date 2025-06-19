import json
import random

syscalls = [
    "open", "read", "write", "close", "execve", "futex", "mmap", "munmap", "clone",
    "setuid", "ptrace", "chmod", "unlink", "fork", "kill", "wait4", "stat", "lstat"
]

data = []
labels = []

for _ in range(100):
    seq = random.choices(syscalls[:10], k=random.randint(4, 8))
    data.append(seq)
    labels.append(0)  # benign

malicious_patterns = [
    ["setuid", "execve", "chmod"],
    ["ptrace", "ptrace", "execve"],
    ["fork", "ptrace", "chmod"],
    ["open", "write", "chmod", "execve"],
]
for _ in range(30):
    pattern = random.choice(malicious_patterns)
    extra = random.choices(syscalls[0:5], k=2)
    seq = extra + pattern
    data.append(seq)
    labels.append(1)  # malicious

with open("lstm_syscall_data.json", "w") as f:
    json.dump({"data": data, "labels": labels}, f, indent=2)

print("Dataset generated: lstm_syscall_data.json")
