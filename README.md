SysGuard: Hybrid System Call Sandbox & Behavioral AI Guard
SysGuard is an advanced, multi-layered runtime application security system that protects host environments from untrusted, potentially malicious native C code. Unlike traditional sandboxes that rely entirely on rigid kernel-level rules, or static analyzers that fail to catch obfuscated runtime vectors, SysGuard unifies Deterministic Kernel Restrictions, User-Space Hook Interception, and Behavioral Deep Learning (LSTM Sequential Modeling) into a singular host security wrap.

🎯 Project Utility & Real-World Use Cases
SysGuard mimics enterprise-grade cloud native runtime security engines like Falco or gVisor, abstracting them into an accessible host instrumentation tool.

Core Utility:
Untrusted Code Execution Engines: Safely execute student code submissions, remote compilation platforms, or user-supplied plugins without risking host compromise via recursive fork-bombs, file modifications, or shell spawns.

Automated Malware Analysis: Rapidly classify unknown binaries by executing them inside an instrumented harness, dynamically mapping out their execution footprints.

Intrusion Prevention & Containment: Terminate or restrict executing processes immediately upon detecting unauthorized sequences, preventing zero-day pivoting or file-system exfiltration.

🧠 Architectural Overview: How It Works
SysGuard protects environments through three distinct lines of defense that handle a binary from compilation to runtime teardown.

[ Target Source Code (.c) ]
           │
           ▼
┌──────────────────────────────────────┐
│  1. Static Extraction & AI Verdict    │ ──► Analyzes token sequences via LSTM
└──────────────────────────────────────┘
           │ (If safe/approved)
           ▼
┌──────────────────────────────────────┐
│  2. Dynamic Wrapper Preloading       │ ──► Hooks path references via LD_PRELOAD
└──────────────────────────────────────┘
           │ (Intercepts open / openat)
           ▼
┌──────────────────────────────────────┐
│  3. Kernel Enforcement (Seccomp)     │ ──► Drops forbidden syscalls completely
└──────────────────────────────────────┘
           │
           ▼
     [ Linux Kernel VFS / Execution Layer ]



1. Static Feature Extraction & LSTM Anomaly Prediction (cli.py, detector.py)
Before the application is ever executed on the processor, SysGuard handles the target source code.

Parsing: The extract_syscalls_from_c.py parsing engine processes the structural profile of the code, mapping standard library operations (fopen, system, execl, fork) to their native Linux kernel system call representations.

Inference Pipeline: This tokenized chain is converted to sequential numerical embeddings, padded to standard operational windows (MAX_SEQ_LEN), and run through a trained Long Short-Term Memory (LSTM) network model (lstm_syscall_model.h5).

Contextual Evaluation: Rather than blocking single calls, the model analyzes the sequence layout. While calling open -> read -> close is marked benign, a sequence of setuid -> open -> write -> chmod -> execve will flag a high-severity malicious verdict, halting execution.

2. User-Space API Interception Hook Layer (libblocker.c)
If approved for a live runtime trial, the system launches the program wrapped inside an LD_PRELOAD shared environment context.

Symbol Interception: The library hooks standard wrapper exports (open, openat). When the process attempts to interact with files, control jumps to our handler.

Path Resolution: The wrapper extracts the requested file targets and evaluates them against sensitive rules (such as blocking access to /etc/passwd or /etc/shadow).

Safe Forwarding: If benign, the wrapper leverages dlsym(RTLD_NEXT, ...) to safely resume normal execution down to the underlying standard libraries. If forbidden, it intercepts the instruction entirely, sets errno = EPERM, and returns -1 to the application without ever contacting the file-system.

3. Kernel-Enforced Sandbox Protection Layer (blocker.c, policy.json)
The deepest security tier sits inside kernel space utilizing Linux Secure Computing Mode (Seccomp) with Berkeley Packet Filters (BPF).

Policy Consumption: Upon initialization, SysGuard reads the granular configuration profile policy.json.

Filter Registration: It translates administrative strings (like execve, ptrace, fork, bpf) into internal kernel architecture integers using libseccomp.

Immediate Enforcement: The filter array is compiled and injected straight into the process block in the Linux kernel via prctl(). From this point onward, any attempt by the binary to jump around user-space library filters to drop into inline assembly system calls triggers a hardware trap, resulting in an immediate process kill (SCMP_ACT_KILL).

💻 Technical File Directory Mapping
The 25 interdependent configuration and script assets map to the following structural matrix:

Orchestration & User Access:

main.py: Graphical user interface (GUI) built with Tkinter, controlling static analysis compilation, user confirmation prompts, and safe preloaded test execution.

cli.py: Streamlined terminal pipeline for scanning and checking source inputs directly from shell prompts.

Makefile: Automates production assembly, turning raw intercept handlers into system shared objects (libblocker.so).

Machine Learning & Sequential Classification Engine:

train_lstm_model.py: Script defining network topology (Embedding -> LSTM -> Dense Softmax), building the classification model.

lstm_syscall_data_generator.py: Generates balanced synthetic training logs combining benign interactions and known malicious progression chains.

lstm_syscall_data.json: Structured training dataset populated with sequences and class vectors.

lstm_syscall_model.h5: Compiled weights and network topology for the active model.

syscall_tokenizer.json: Vocabulary state mapping system call names to unique sequential integer keys.

predict_syscall_sequence.py: Command-line interface for running independent model evaluation vectors.

Dynamic Trapping & Interception Layers:

libblocker.c / libblocker.so: Main constructor hook wrapper injecting file-system safety checks and handling the JSON-to-Seccomp initialization pipeline.

blocker.c: Independent modular component managing libseccomp translation and validation.

monitor.c / monitor.py: Lower-level debugging engines using kernel tracing mechanics (ptrace) to reconstruct system interaction behaviors for logs.

extract_syscalls_from_c.py: Regex-based static parser matching code patterns to logical system calls.

Security Testing Array & Policies:

policy.json: Master kernel seccomp configuration profile specifying forbidden actions.

denylist.json: Fine-grained configuration file used by the Python layer to classify threat levels (HIGH, MEDIUM, LOW).

input_unseen.c: Test target executing network socket creation and sleep loops.

test_blocker.c / test_blocker: Test target validating file path blocks against /etc/passwd.

test_execve.c: Test target validating kernel-level rejection of shell spawns.

test_fork.c: Test target validating process isolation by running bounded fork calls.

test_program.c: Compound verification file executing file reads alongside execution shifts.

🛠️ Step-by-Step Execution Lifecycle
When you select a target file (e.g., test_program.c) and execute SysGuard, the following real-time operations occur:

Token Generation: The application reads test_program.c, strips comments, extracts function identifiers, and normalizes them into a string array: ["open", "read", "close", "execve"].

AI Analysis: This sequence is checked by the LSTM model. If the pattern matches an exploitation chain, the system drops into an alert screen. If clear, it proceeds to compilation.

Dynamic Compilation: System GCC compiles the source securely into a sandboxed target binary layout inside /tmp/sysguard_test_binary.

Environment Wrapping: The host environment instantiates a controlled sub-shell, injecting LD_PRELOAD=./libblocker.so.

Constructor Launch: Before the target program's main() function ever receives processor focus, our shared library’s __attribute__((constructor)) void init() function takes control. It hooks the real open/openat functions and reads policy.json to load the kernel-level seccomp system filters.

Execution Enforcement: The program runs. When it safely opens a local document, it passes through libblocker.so. When it hits the execve instruction on line 10, the underlying kernel seccomp state catches the call ID, instantly neutralizing the thread before any shell execution can occur.

🚀 Future Horizons & Expansion Vector Roadmap
To scale SysGuard into an enterprise cloud-native or container security engine, the following development architectures can be integrated next:

1. Transitioning to eBPF (Extended Berkeley Packet Filter)
The Target: Replace user-space checking (LD_PRELOAD) and basic tracking (ptrace) with native eBPF kernel kprobes.

The Reason: Clever attackers can evade LD_PRELOAD by writing inline assembly, and ptrace introduces massive process scheduling performance overhead. Using eBPF allows the system to trace system calls directly out of ring buffers inside the kernel at native speeds, making evasion impossible.

2. Context-Aware Deep Learning Models
The Target: Upgrade the LSTM engine into an advanced Bidirectional Transformer Encoder.

The Reason: Standard LSTMs read sequences in one direction, occasionally dropping long-distance context dependencies. A transformer architecture can analyze systemic relationship parameters across an entire runtime session, significantly lowering false-alarm rates for sophisticated multi-threaded applications.

3. Argument-Aware Seccomp Inspection
The Target: Expand seccomp_rule_add definitions to include strict bitmask validations (SCMP_CMP macros).

The Reason: Currently, any call to open or mprotect is evaluated globally. Adding deep argument tracing allows rules like: "Allow open only if the file flags match strictly O_RDONLY, and drop execution instantly if write flags (O_RDWR or O_WRONLY) are invoked on secure directories."

4. Dynamic Live Process Mitigations
The Target: Expand python orchestration to gracefully manage running processes rather than just executing hard kills.

The Reason: Instead of crashing an entire application infrastructure via SCMP_ACT_KILL when an anomaly flag occurs, the engine can be expanded to dynamically modify container control groups (cgroups), throttle CPU allocation speeds to zero, or clone the running stack namespace directly into an isolated network honeypot for real-time forensics.     



**KEY TERMS USED:**
System Call (Syscall)
The programmatic interface used by an executing C program to request privileged hardware or kernel-space operations from the underlying Linux operating system. It transitions execution from user-space into the secure kernel-space to handle operations like disk storage or network sockets.

Sandbox
An isolated execution environment that limits the privileges, resource access, and system calls available to a running process. It prevents unverified or malicious binaries from modifying host files, spawning shells, or altering the parent operating system.

LD_PRELOAD
An environment variable in Linux that instructs the dynamic linker to load specified shared libraries (.so) before any other dependencies. It enables user-space API interception by allowing custom hooks to override standard C library functions like open or read.

Dynamic Interception Hook
A software wrapper implemented in user-space that catches calls to standard library functions before they execute their default instructions. It allows SysGuard to inspect, modify, or block parameter arguments (like specific file paths) before forwarding or rejecting them.

dlsym(RTLD_NEXT, ...)
A dynamic linking function that searches for the next available instance of a named symbol or function in the executable's memory space. It is used inside intercepted wrappers to find and invoke the original C library function pointer after passing security validation.

seccomp (Secure Computing Mode)
A Linux kernel security facility that restricts the system calls a process can make from that point forward. It compiles explicit call filters using Berkeley Packet Filters (BPF) and immediately terminates the application if an unapproved system call instruction is detected.

libseccomp
A high-level C library that provides an abstract, architecture-independent interface to generate and load complex kernel-level seccomp filters. It simplifies sandbox construction by translating human-readable syscall string names into raw, architecture-specific numerical IDs.

SCMP_ACT_KILL
A seccomp filter action that instructs the Linux kernel to immediately terminate a thread with a core dump when a forbidden system call is attempted. It acts as an absolute enforcement mechanism that stops malicious assembly execution instantly without notifying the process.

SCMP_ACT_ALLOW
The default policy action in a seccomp filter that permits any system calls to execute unless they explicitly match a restricted rule list. It provides a permissive baseline for sandbox configurations where only known high-risk actions are blacklisted.

ptrace (Process Trace)
A native Linux system call that allows one process (the tracer) to observe, control, and manipulate the execution, registers, and memory states of another process (the tracee). It is utilized in execution monitors to trap process behaviors on every system call entry and exit.

PTRACE_SYSCALL
A specific ptrace request option that commands the traced process to execute normally but pause and trigger an alert at the next system call boundary. It splits monitoring events into a pre-syscall entry check and a post-syscall exit verification trap.

PTRACE_O_TRACESYSGOOD
A diagnostic configuration option that forces ptrace to set bit 7 in the status signal number when a process trap is caused specifically by a system call. It prevents synchronization alignment errors by letting tracers easily distinguish native system calls from standard signals or breakpoints.

Static Feature Extraction
The process of parsing source code text files to identify and extract semantic function names or tokens without compiling or running the file. It produces a clean, chronological list of estimated execution behaviors that can be piped into machine learning classifiers.

LSTM (Long Short-Term Memory)
A specialized architecture of Recurrent Neural Networks (RNNs) designed to process, classify, and predict sequences of data over varying time steps. In SysGuard, it analyzes sequential trends in system call sequences to find underlying anomaly patterns that signify exploitation attempts.

Tokenization
The pre-processing pipeline that converts raw text elements (like C function name strings) into distinct numerical integer tokens based on an index dictionary. This translates human-readable source code components into mathematical sequences compatible with deep learning matrix layers.

Sequence Padding
An data formatting step that appends zeros or truncates input arrays to force variable-length system call chains into uniform matrix dimensions (MAX_SEQ_LEN). It ensures that input arrays match the fixed structural expectations of deep learning models during training and inference.

JSON-C
A lightweight, open-source C-library utilized to parse, manipulate, and generate Javascript Object Notation (JSON) configuration objects. It allows low-level security engines to read external files (like policy.json) and convert plain text into nested configuration variables.

__attribute__((constructor))
A GCC compiler directive that marks a specific function inside a shared library to execute automatically when the library is initialized into memory. It ensures that SysGuard's user-space interception arrays and kernel seccomp configurations activate before the binary's main() entry function begins.




# SysGuard

gcc -fPIC -shared -o libblocker.so libblocker.c -lseccomp -ljson-c

gcc -o test_fork test_fork.c

python3 main.py
