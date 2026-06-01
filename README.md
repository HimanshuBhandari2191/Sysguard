# SysGuard: Hybrid System Call Sandbox & Behavioral AI Guard

SysGuard is a multi-layered runtime application security system that protects host environments from untrusted, potentially malicious native C code. By unifying **Deterministic Kernel Restrictions**, **User-Space Hook Interception**, and **Behavioral Deep Learning (LSTM Sequential Modeling)**, SysGuard tracks and contains arbitrary binary threats before they can pivot against the host filesystem or process namespace.

---

## ⚡ Quick Start

Get SysGuard up, compiled, and running in less than two minutes:

### 1. Compile Security Libraries and Test Binaries

```bash
# Build the dynamic preloading intercept engine (libblocker.so)
make

# Compile the suite of isolated sandbox test binaries
gcc test_blocker.c -o test_blocker
gcc test_fork.c -o test_fork
gcc test_execve.c -o test_execve

```

### 2. Train the Behavioral LSTM Model

```bash
# Generate synthetic behavioral logs (benign vs malicious chains)
python3 lstm_syscall_data_generator.py

# Train the LSTM neural network and output token topology
python3 train_lstm_model.py

```

### 3. Launch the Management Console

```bash
# Start the graphical security instrumentation wrapper
python3 main.py

# Alternatively, run via the lightweight command-line interface
python3 cli.py test_program.c

```

---

## 📋 Table of Contents

1. [Quick Start](https://www.google.com/search?q=%23-quick-start)
2. [Dependencies & Requirements](https://www.google.com/search?q=%23-dependencies--requirements)
3. [File Architecture Matrix](https://www.google.com/search?q=%23-file-architecture-matrix)
4. [How It Works: Core Architecture](https://www.google.com/search?q=%23-how-it-works-core-architecture)
5. [Security Model & Sandbox Limitations](https://www.google.com/search?q=%23-security-model--sandbox-limitations)
6. [Usage Examples & Testing Run-book](https://www.google.com/search?q=%23-usage-examples--testing-run-book)
7. [Future Roadmap](https://www.google.com/search?q=%23-future-roadmap)
8. [Contributing & License](https://www.google.com/search?q=%23-contributing--license)

---

## 📦 Dependencies & Requirements

SysGuard relies on key system utilities, machine learning libraries, and C configuration parsers. Ensure the following items are available on your Linux host environment:

### Linux System Packages

* **GCC / Make:** GNU Compiler Collection for dynamic runtime compilation and library builds.
* **libseccomp-dev:** Low-level developer headers to communicate natively with Linux kernel system filters.
* **libjson-c-dev:** C-native parser framework used to handle custom external file system definitions.

```bash
# Installation on Debian/Ubuntu systems:
sudo apt-get update
sudo apt-get install build-essential libseccomp-dev libjson-c-dev python3-tk

```

### Python Framework Modules

* **TensorFlow (v2.x):** Deep learning framework handling sequential execution processing layers.
* **NumPy:** Linear algebra array processor mapping matrix structures to neural nodes.
* **Tkinter:** Standard GUI desktop wrapper built into the default core python ecosystem.

```bash
pip install tensorflow numpy

```

---

## 📂 File Architecture Matrix

The components across your codebase handle unique security responsibilities:

| File Name | Category | Primary Functional Duty |
| --- | --- | --- |
| `main.py` | Orchestration Layer | Graphical Tkinter console controlling compilation pipelines and runtime confirmations. |
| `cli.py` | Orchestration Layer | Terminal interface wrapper for scanning source targets without firing a GUI. |
| `libblocker.c` | User-Space Hook | Intercepts standard exports (`open`/`openat`) to track and canonicalize absolute paths. |
| `blocker.c` | Kernel Layer | Parses `policy.json` maps to inject restrictive filters straight into kernel space. |
| `monitor.c` / `monitor.py` | Forensic Instrumentation | Employs native kernel tracing (`ptrace`) to capture and log actual execution workflows. |
| `extract_syscalls_from_c.py` | Feature Extraction | Regex parser evaluating target C source syntax to map raw expected system tracks. |
| `train_lstm_model.py` | Machine Learning | Implements embedding arrays and an LSTM network block to learn anomaly vectors. |
| `lstm_syscall_data_gen.py` | Machine Learning | Script building out synthetic benign configurations and malicious progression loops. |
| `policy.json` | Configuration Policy | Structural configuration profiles containing explicit forbidden system call IDs. |
| `denylist.json` | Configuration Policy | Severity indexing map flagging specific high-threat actions within Python modules. |
| `test_*.c` | Test Framework Suite | Explicit exploitation files targeting file exfiltration, fork bombs, and shell spawning. |

---

## 🧠 How It Works: Core Architecture

SysGuard implements a three-tiered execution security strategy that processes source patterns both before and during active host execution.

### Phase 1: Static Code Extraction & Neural Classification

Before an uploaded C file is compiled or granted a process ID, `extract_syscalls_from_c.py` analyzes the raw source syntax. Standard functional blocks like `fopen`, `system`, or `fork` are translated directly into their low-level Linux counterparts.

This token stream is passed to an explicit, pre-trained Long Short-Term Memory (LSTM) network inside `detector.py`. The model evaluates the sequential pattern: while calling `open -> read -> close` is mapped as completely benign, a highly localized chain pattern like `setuid -> open -> write -> chmod -> execve` triggers a malicious verdict, halting execution immediately before compiler assembly can begin.

### Phase 2: User-Space Function Interception (`LD_PRELOAD`)

If the AI engine clears the code structure, SysGuard builds the target application binary inside a protected directory location (`/tmp/sysguard_test_binary`) and targets it using an `LD_PRELOAD` library environment hook (`libblocker.so`).

When the program attempts to invoke a file tracking operation, control is dynamically redirected to our intercept library. The code checks the parameter inputs against banned path strings (like `/etc/passwd`). If safe, it discovers the true function address space using `dlsym(RTLD_NEXT, "open")` and seamlessly returns control to the program; if a matching banned signature is seen, it instantly cuts execution, injects a standard Permission Denied state (`EPERM`), and throws an error code safely before the storage controller ever reads physical blocks.

### Phase 3: Hardware-Enforced Kernel Sandboxing (`seccomp`)

The deepest tier resides completely inside kernel space. Upon dynamic initialization via library constructors, SysGuard reads the operational configurations detailed inside `policy.json`. It maps human-readable system call strings into the specific numerical integers mandated by your CPU architecture using `libseccomp`.

These rules compile into Berkeley Packet Filters (BPF) and load directly into the process layout using `prctl()`. From this moment forward, even if an advanced piece of malware circumvents user-space hooks by utilizing custom inline assembly scripts (`syscall` or `int 0x80`), the kernel processor traps the specific instruction sequence IDs and drops execution immediately via an absolute signal trap (`SCMP_ACT_KILL`).

---

## 🔒 Security Model & Sandbox Limitations

While the combination of an LSTM behavioral engine and system filtering provides defense-in-depth, certain structural escape windows exist across this architecture:

### 1. User-Space Interception Evasion (`LD_PRELOAD`)

* **The Mechanism:** `libblocker.c` intercepts standard dynamic glibc library call symbols.
* **The Limitation:** If an application bypasses standard glibc functions completely by using raw, inline assembly blocks to communicate directly with the kernel (`asm("syscall")`), user-space checks are bypassed entirely. This relies heavily on the underlying Kernel Seccomp layer to provide secondary line-of-defense containment.

### 2. Path Obfuscation Faults

* **The Mechanism:** The user-space library relies on literal string parameter matching (`strcmp`) to isolate protected operating system nodes like `/etc/passwd`.
* **The Limitation:** Malicious applications passing complex paths (e.g., relative linkages like `/etc/./passwd` or directory jumps like `../../etc/passwd`) can escape literal string checks. The application requires path canonicalization before evaluation.

### 3. Static Parsing Restrictions

* **The Mechanism:** `extract_syscalls_from_c.py` employs regular expressions to extract token structures out of raw, text-based code blocks.
* **The Limitation:** If an attacker splits function definitions or dynamically creates pointers via pointer arithmetic or string obfuscation techniques, static parsers fail to match the signatures, feeding an incomplete system call array to the LSTM engine.

---

## 🛠️ Usage Examples & Testing Run-book

Execute these validation workflows out of your terminal interface to evaluate the runtime mechanics of your codebase components:

### Example 1: Triggering Path Interception

Run the file system validation binary wrapped inside the preloader wrapper library to observe real-time path interception:

```bash
# Command execution
LD_PRELOAD=./libblocker.so ./test_blocker

# Expected Diagnostic Feedback
[libblocker] Initializing libblocker...
[libblocker] Intercepted open: /etc/passwd
[libblocker] Access Blocked to: /etc/passwd
open failed: Permission denied

```

### Example 2: Verifying Kernel Seccomp Drops

Run the command shell testing block to observe the hard termination applied by the kernel filter policies:

```bash
# Execute binary leveraging the policy.json block constraints
LD_PRELOAD=./libblocker.so ./test_execve

# Expected Diagnostic Feedback
[libblocker] Initializing libblocker...
Trying to exec /bin/ls...
Bad system call (core dumped)

```

### Example 3: Running the Command-Line Scanner

Evaluate standalone tracking patterns without booting the heavy graphics subsystem:

```bash
# Execute the Python terminal instrumentation harness
python3 cli.py test_program.c

# Expected Diagnostic Feedback
🔍 Extracting syscall sequence...
📋 Syscall sequence detected: open read close execve
🧠 Running prediction...
🔒 Verdict: MALICIOUS

```

---

## 🚀 Future Roadmap

To scale SysGuard into an enterprise cloud-native or container security engine, the following development architectures can be integrated next:

* **Transitioning to eBPF (Extended Berkeley Packet Filter):** Replace user-space checking (`LD_PRELOAD`) and basic tracking (`ptrace`) with native eBPF kernel kprobes. This allows tracing system calls directly out of ring buffers inside the kernel at native speeds, making evasion impossible.
* **Context-Aware Deep Learning Models:** Upgrade the LSTM engine into an advanced Bidirectional Transformer Encoder to analyze systemic relationship parameters across an entire runtime session, significantly lowering false-alarm rates.
* **Argument-Aware Seccomp Inspection:** Expand `seccomp_rule_add` definitions to include strict bitmask validations (`SCMP_CMP` macros) to restrict file usage to read-only flags (`O_RDONLY`).

---

## 🤝 Contributing & License

### Contributing

Contributions to extend the SysGuard framework are welcome. Please ensure that updates to system call lists are accurately mapped across both the static Python parser dictionaries (`FUNC_TO_SYSCALL`) and the underlying low-level tracking schemas (`policy.json`).

### License

This system sandbox model is distributed completely under the **MIT License**. You are free to modify, scale, and integrate this runtime harness framework across custom sandbox infrastructure deployments without constraint.

---
