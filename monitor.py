import time
import subprocess
import numpy as np
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.preprocessing.text import tokenizer_from_json
import json

# Load the LSTM model and tokenizer
model = load_model("lstm_syscall_model.h5")
with open("syscall_tokenizer.json") as f:
    tokenizer = tokenizer_from_json(json.load(f))

MAX_SEQ_LEN = model.input_shape[1]  # Get sequence length from model
syscall_sequence = []

def predict_sequence(seq):
    syscall_str = " ".join(seq)
    X_seq = tokenizer.texts_to_sequences([syscall_str])
    X_pad = pad_sequences(X_seq, maxlen=MAX_SEQ_LEN, padding='post')
    pred = model.predict(X_pad)[0]
    return "MALICIOUS" if np.argmax(pred) == 1 else "BENIGN", float(pred[1])

def monitor_syscalls():
    print(f"[~] Starting syscall monitoring with LSTM (sequence length: {MAX_SEQ_LEN})...")
    
    while True:
        # This would be replaced with actual syscall monitoring
        # For now, we'll simulate syscalls
        syscall = get_next_syscall()  # Replace with your actual syscall collection
        
        print(f"[+] Syscall detected: {syscall}")
        syscall_sequence.append(syscall)

        if len(syscall_sequence) > MAX_SEQ_LEN:
            syscall_sequence.pop(0)

        if len(syscall_sequence) == MAX_SEQ_LEN:
            prediction, confidence = predict_sequence(syscall_sequence)
            if prediction == "MALICIOUS":
                print(f"\033[1;31m[!] ALERT: Malicious pattern detected (confidence: {confidence:.2f}): {' '.join(syscall_sequence)}\033[0m")
                # Take action here (block process, alert admin, etc.)
            else:
                print(f"\033[1;32m[+] Benign pattern (confidence: {1-confidence:.2f})\033[0m")

        time.sleep(0.1)  # Adjust based on your monitoring needs

def get_next_syscall():
    """Simulate syscall collection - replace with actual implementation"""
    # In a real implementation, this would get the next syscall from your monitoring system
    # For simulation, we'll use random syscalls from the training set
    import random
    syscalls = list(tokenizer.word_index.keys())
    return random.choice(syscalls)

if __name__ == "__main__":
    monitor_syscalls()
