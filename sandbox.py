import subprocess
import os
import tkinter as tk
from tkinter import messagebox

def launch_sandbox():
    try:
        # Absolute path to libblocker.so (optional if script is in same dir)
        libblocker_path = os.path.abspath("./libblocker.so")
        env = os.environ.copy()
        env["LD_PRELOAD"] = libblocker_path

        subprocess.run(["bash"], env=env)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to launch sandbox bash:\n{str(e)}")

def main():
    root = tk.Tk()
    root.title("SysGuard Sandbox Launcher")

    frame = tk.Frame(root, padx=20, pady=20)
    frame.pack()

    label = tk.Label(frame, text="SysGuard Sandbox", font=("Arial", 16))
    label.pack(pady=10)

    launch_button = tk.Button(
        frame, text="Launch Sandbox Bash", font=("Arial", 12), command=launch_sandbox
    )
    launch_button.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    main()

