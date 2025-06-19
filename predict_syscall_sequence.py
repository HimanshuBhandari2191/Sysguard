import sys
import json
import numpy as np
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.preprocessing.text import tokenizer_from_json

model = load_model("lstm_syscall_model.h5")
with open("syscall_tokenizer.json") as f:
    tokenizer = tokenizer_from_json(json.load(f))

input_seq = sys.argv[1].split()
X_seq = tokenizer.texts_to_sequences([" ".join(input_seq)])
X_pad = pad_sequences(X_seq, maxlen=model.input_shape[1], padding='post')

pred = model.predict(X_pad)[0]
print("MALICIOUS" if np.argmax(pred) == 1 else "BENIGN")
