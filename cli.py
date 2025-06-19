import subprocess
import sys
import os

def extract_syscalls(c_file):
    try:
        result = subprocess.run(
            ["python3", "extract_syscalls_from_c.py", c_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.returncode != 0:
            print("[ERROR] Failed to extract syscalls.")
            print(result.stderr)
            return None
        return result.stdout.strip()
    except Exception as e:
        print(f"[EXCEPTION] {e}")
        return None

def predict_sequence(syscall_sequence):
    try:
        result = subprocess.run(
            ["python3", "predict_syscall_sequence.py", syscall_sequence],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.returncode != 0:
            print("[ERROR] ML prediction failed.")
            print(result.stderr)
            return None
        return result.stdout.strip()
    except Exception as e:
        print(f"[EXCEPTION] {e}")
        return None

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 cli.py <your_c_file.c>")
        return

    c_file = sys.argv[1]

    if not os.path.exists(c_file):
        print(f"[ERROR] File '{c_file}' does not exist.")
        return

    print("🔍 Extracting syscall sequence...")
    syscall_seq = extract_syscalls(c_file)

    if not syscall_seq or syscall_seq == "No known syscall-like function calls detected.":
        print("✅ No suspicious system calls detected.")
        return

    print(f"📋 Syscall sequence detected: {syscall_seq}")
    print("🧠 Running prediction...")
    result = predict_sequence(syscall_seq)

    if result:
        print(f"🔒 Verdict: {result}")
    else:
        print("❌ Could not classify the file.")

if __name__ == "__main__":
    main()
