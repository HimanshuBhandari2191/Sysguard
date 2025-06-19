import json
import numpy as np
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Embedding, LSTM, Dense
from tensorflow.keras.utils import to_categorical

with open("lstm_syscall_data.json") as f:
    dataset = json.load(f)
    sequences = [" ".join(seq) for seq in dataset["data"]]
    labels = dataset["labels"]

tokenizer = Tokenizer()
tokenizer.fit_on_texts(sequences)
X_seq = tokenizer.texts_to_sequences(sequences)
X_pad = pad_sequences(X_seq, padding='post')
y = to_categorical(labels, num_classes=2)

model = Sequential([
    Embedding(input_dim=len(tokenizer.word_index) + 1, output_dim=16, input_length=X_pad.shape[1]),
    LSTM(32),
    Dense(2, activation='softmax')
])
model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
model.fit(X_pad, y, epochs=10, batch_size=16, verbose=1)

model.save("lstm_syscall_model.h5")
with open("syscall_tokenizer.json", "w") as f:
    f.write(json.dumps(tokenizer.to_json()))
