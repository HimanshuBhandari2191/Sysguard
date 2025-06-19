import os
import json
import subprocess
import numpy as np
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.preprocessing.text import tokenizer_from_json

# File paths
LOG_FILE = "../logs/syscall_log.txt"
ALERT_FILE = "alert_log.txt"
DENYLIST_FILE = "../config/denylist.json"
MODEL_FILE = "lstm_syscall_model.h5"
TOKENIZER_FILE = "syscall_tokenizer.json"

# Color codes for severity levels
COLORS = {
    "HIGH": "\033[1;31m",    # Red
    "MEDIUM": "\033[1;33m",  # Yellow
    "LOW": "\033[1;34m",     # Blue
    "MALICIOUS": "\033[1;35m", # Purple for LSTM predictions
    "RESET": "\033[0m"       # Reset
}

class LSTMPredictor:
    def __init__(self):
        self.model = load_model(MODEL_FILE)
        with open(TOKENIZER_FILE) as f:
            self.tokenizer = tokenizer_from_json(json.load(f))
        self.max_len = self.model.input_shape[1]  # Get sequence length from model
    
    def predict_sequence(self, sequence):
        """Predict if a sequence of syscalls is malicious"""
        X_seq = self.tokenizer.texts_to_sequences([" ".join(sequence)])
        X_pad = pad_sequences(X_seq, maxlen=self.max_len, padding='post')
        pred = self.model.predict(X_pad)[0]
        return "MALICIOUS" if np.argmax(pred) == 1 else "BENIGN", float(pred[1])

def detect_suspicious_syscalls():
    denylist = load_denylist()
    lstm_predictor = LSTMPredictor()
    
    if not os.path.exists(LOG_FILE):
        print("[❌] Log file not found:", LOG_FILE)
        return

    alerts = []
    syscall_buffer = []
    buffer_size = lstm_predictor.max_len
    
    print("\n📌 Starting syscall analysis...\n")

    with open(LOG_FILE, "r") as logfile:
        for line_number, line in enumerate(logfile, start=1):
            # Extract syscall name from log line
            if "Syscall:" in line:
                parts = line.split("Syscall:")[1].strip().split()
                syscall = parts[0] if parts else "unknown"
                
                # Add to buffer for LSTM analysis
                syscall_buffer.append(syscall)
                if len(syscall_buffer) > buffer_size:
                    syscall_buffer.pop(0)
                
                # Check denylist
                for blocked_syscall, severity in denylist.items():
                    if blocked_syscall == syscall:
                        timestamp = line.split()[0] if "[" in line else "N/A"
                        color = COLORS.get(severity.upper(), COLORS["RESET"])
                        alert_msg = f"{timestamp} {color}[{severity}] Suspicious syscall '{syscall}' on line {line_number}:{COLORS['RESET']} {line.strip()}"
                        print(alert_msg)
                        alerts.append(f"{timestamp} [{severity}] {syscall} on line {line_number}: {line.strip()}")
                
                # Run LSTM prediction when buffer is full
                if len(syscall_buffer) == buffer_size:
                    prediction, confidence = lstm_predictor.predict_sequence(syscall_buffer)
                    if prediction == "MALICIOUS":
                        timestamp = line.split()[0] if "[" in line else "N/A"
                        alert_msg = f"{timestamp} {COLORS['MALICIOUS']}[LSTM] Malicious pattern detected (confidence: {confidence:.2f}): {' '.join(syscall_buffer)}{COLORS['RESET']}"
                        print(alert_msg)
                        alerts.append(f"{timestamp} [LSTM-MALICIOUS] Confidence: {confidence:.2f} Pattern: {' '.join(syscall_buffer)}")

    if alerts:
        with open(ALERT_FILE, "w") as alert_file:
            for alert in alerts:
                alert_file.write(alert + "\n")
        print(f"\n✅ Alerts saved to: {ALERT_FILE}")
    else:
        print("\n✅ No suspicious syscalls found.")

def load_denylist():
    if not os.path.exists(DENYLIST_FILE):
        print(f"[❌] Denylist file not found: {DENYLIST_FILE}")
        return {}

    with open(DENYLIST_FILE, "r") as file:
        try:
            config = json.load(file)
            return config.get("denylist", {})
        except json.JSONDecodeError:
            print("[❌] Error parsing denylist.json")
            return {}

if __name__ == "__main__":
    detect_suspicious_syscalls()
