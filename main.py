import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import subprocess
import json
import os

DENYLIST_PATH = "denylist.json"


def load_denylist():
    if not os.path.exists(DENYLIST_PATH):
        return ["execve", "fork", "clone"]
    with open(DENYLIST_PATH, "r") as f:
        return json.load(f)


def run_binary_with_preload(binary_path, preload_lib):
    """
    Runs the binary with LD_PRELOAD environment set to preload_lib,
    capturing both stdout and stderr.
    Returns combined output and a list of detected denylisted syscalls.
    """

    if not os.path.exists(binary_path):
        return f"Binary not found: {binary_path}", []

    if not os.path.exists(preload_lib):
        return f"Preload library not found: {preload_lib}", []

    env = os.environ.copy()
    env["LD_PRELOAD"] = preload_lib

    try:
        process = subprocess.Popen(
            [binary_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )

        stdout, stderr = process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        return "Process timed out.", []
    except Exception as e:
        return f"Failed to run process: {e}", []

    # Combine output for display
    combined_output = stdout + "\n" + stderr

    denylist = load_denylist()
    risky_calls = []
    # Simple heuristic: check if any denylisted syscall names appear in stderr output
    for syscall in denylist:
        if syscall in stderr:
            risky_calls.append(syscall)

    return combined_output, risky_calls


class SysGuardApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SysGuard - Syscall Blocking Tester")
        self.geometry("900x600")
        self.configure(bg="#1e1e2f")

        # Styles
        self.label_fg = "#c5c8dd"
        self.btn_bg = "#3a3f5c"
        self.btn_fg = "#e6e6e6"
        self.text_bg = "#2e2e44"
        self.text_fg = "#dcdde1"

        # Top frame for file selection and buttons
        top_frame = tk.Frame(self, bg=self["bg"])
        top_frame.pack(fill=tk.X, padx=15, pady=10)

        # C test file selection
        tk.Label(top_frame, text="Select C test file:", fg=self.label_fg, bg=self["bg"], font=("Segoe UI", 11)).pack(anchor="w")
        self.file_path_var = tk.StringVar()
        file_entry = tk.Entry(top_frame, textvariable=self.file_path_var, width=60, font=("Consolas", 11))
        file_entry.pack(side=tk.LEFT, padx=(0, 8), pady=5)

        browse_btn = tk.Button(top_frame, text="Browse", command=self.browse_file, bg=self.btn_bg, fg=self.btn_fg, font=("Segoe UI", 10), relief="flat")
        browse_btn.pack(side=tk.LEFT)

        # Run test button
        run_btn = tk.Button(top_frame, text="Run Test with LD_PRELOAD", command=self.run_test, bg="#ff5555", fg="white", font=("Segoe UI", 11, "bold"), relief="flat")
        run_btn.pack(side=tk.RIGHT, padx=(8, 0))

        # Separator
        separator = tk.Frame(self, height=2, bg="#44475a")
        separator.pack(fill=tk.X, padx=15, pady=(5, 10))

        # Output box label
        tk.Label(self, text="Output Console:", fg=self.label_fg, bg=self["bg"], font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=15)

        # Output scrolled text widget
        self.output_box = scrolledtext.ScrolledText(self, height=25, font=("Consolas", 10), bg=self.text_bg, fg=self.text_fg, insertbackground="white")
        self.output_box.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))

        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = tk.Label(self, textvariable=self.status_var, bg="#282a36", fg="#6272a4", font=("Segoe UI", 9), anchor="w")
        status_bar.pack(fill=tk.X)

    def analyze_with_lstm(self, file_path):
        """Analyze a C file with the LSTM model"""
        try:
            # Extract syscalls from C file
            result = subprocess.run(
                ['python3', 'extract_syscalls_from_c.py', file_path],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                self.output_box.insert(tk.END, f"Error extracting syscalls:\n{result.stderr}\n")
                return
            
            syscall_sequence = result.stdout.strip().split()
            if not syscall_sequence:
                self.output_box.insert(tk.END, "No syscalls detected in the file.\n")
                return
                
            # Predict with LSTM
            lstm_result = subprocess.run(
                ['python3', 'predict_syscall_sequence.py', " ".join(syscall_sequence)],
                capture_output=True,
                text=True
            )
            
            self.output_box.insert(tk.END, f"\nLSTM Analysis Results:\n")
            self.output_box.insert(tk.END, f"Syscall sequence: {' '.join(syscall_sequence)}\n")
            self.output_box.insert(tk.END, f"Prediction: {lstm_result.stdout}\n")
            
        except Exception as e:
            self.output_box.insert(tk.END, f"Error during LSTM analysis: {str(e)}\n")

    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("C source files", "*.c")])
        if file_path:
            self.file_path_var.set(file_path)

    def run_test(self):
        file_path = self.file_path_var.get()
        if not file_path:
            messagebox.showwarning("No file selected", "Please select a C test file.")
            return

        self.output_box.delete("1.0", tk.END)
        self.status_var.set("Analyzing file with LSTM...")
        self.update()
    
        # First run LSTM analysis
        self.analyze_with_lstm(file_path)
    
        # Then proceed with the original test
        self.status_var.set("Compiling the C test file...")
        self.update()
    
        # Compile the C file to a temp binary
        binary_path = "/tmp/sysguard_test_binary"
        compile_cmd = ["gcc", file_path, "-o", binary_path]
        compile_result = subprocess.run(compile_cmd, capture_output=True, text=True)

        if compile_result.returncode != 0:
            self.status_var.set("Compilation failed")
            self.output_box.insert(tk.END, f"Compilation failed:\n{compile_result.stderr}\n")
            return

        self.status_var.set("Running binary with LD_PRELOAD...")
        self.update()

        # Run the compiled binary with your LD_PRELOAD library
        preload_lib = os.path.abspath("libblocker.so")
        output, risky_calls = run_binary_with_preload(binary_path, preload_lib)

        if risky_calls:
            answer = messagebox.askyesno(
                "Risky syscalls detected",
                f"Detected risky syscalls: {', '.join(risky_calls)}.\nDo you want to continue running the test?"
            )
            if not answer:
                self.output_box.insert(tk.END, "Test aborted by user due to risky syscalls.\n")
                self.status_var.set("Test aborted")
                return

        self.output_box.insert(tk.END, output)
        self.status_var.set("Test completed.")


if __name__ == "__main__":
    app = SysGuardApp()
    app.mainloop()
