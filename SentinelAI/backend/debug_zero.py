import joblib
import os
import numpy as np

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'sentinel_model.pkl')
FEATURES_PATH = os.path.join(BASE_DIR, 'features_list.pkl')

def test_zero_vector():
    print("Loading model...")
    model = joblib.load(MODEL_PATH)
    features_list = joblib.load(FEATURES_PATH)
    
    print(f"Features count: {len(features_list)}")
    
    # Create all-zero input
    input_features = [0] * len(features_list)
    input_vector = np.array([input_features])
    
    # Predict
    probs = model.predict_proba(input_vector)[0]
    threat_score = int(probs[1] * 100)
    
    print(f"Zero Vector Prediction: {probs}")
    print(f"Zero Vector Threat Score: {threat_score}")

if __name__ == "__main__":
    test_zero_vector()
