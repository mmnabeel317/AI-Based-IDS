# Test script: test_prediction.py
from pathlib import Path
import numpy as np
from models.load_model_check import ModelValidator

models_path = Path("models")
validator = ModelValidator(models_path)
cnn, rf, encoder, scaler = validator.load_all_models()

# Create dummy 67 features
test_features = np.random.rand(1, 67).astype(np.float32)
scaled = scaler.transform(test_features)

# Test CNN
cnn_input = scaled.reshape(1, 67, 1)
cnn_out = cnn.predict(cnn_input, verbose=0)
print(f"CNN output shape: {cnn_out.shape}")
print(f"CNN probabilities: {cnn_out[0]}")
print(f"CNN sum: {cnn_out[0].sum()}")

# Test RF  
rf_out = rf.predict_proba(scaled)
print(f"RF output shape: {rf_out.shape}")
print(f"RF probabilities: {rf_out[0]}")
print(f"RF sum: {rf_out[0].sum()}")

print(f"Encoder classes: {encoder.classes_}")
