import pefile
import joblib
import os
import numpy as np
import sys

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'sentinel_model.pkl')
FEATURES_PATH = os.path.join(BASE_DIR, 'features_list.pkl')
SAMPLE_PATH = os.path.join(BASE_DIR, 'samples', 'malware_simulator.exe')

def analyze_file(file_path):
    print(f"--- Analyzing: {file_path} ---")
    
    if not os.path.exists(file_path):
        print("File not found.")
        return

    # Load resources
    print("Loading model/features...")
    try:
        model = joblib.load(MODEL_PATH)
        features_list = joblib.load(FEATURES_PATH)
        print(f"Loaded {len(features_list)} features.")
    except Exception as e:
        print(f"Error loading resources: {e}")
        return

    # Extract Imports
    try:
        pe = pefile.PE(file_path)
    except Exception as e:
        print(f"Error parsing PE: {e}")
        return

    extracted_imports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    extracted_imports.append(imp.name.decode('utf-8', 'ignore'))
    
    print(f"Extracted {len(extracted_imports)} imports from file.")
    if len(extracted_imports) > 0:
        print("First 5 imports:", extracted_imports[:5])

    # Check matches
    extracted_set = set(extracted_imports)
    input_features = []
    matched_count = 0
    
    for feature in features_list:
        if feature in extracted_set:
            input_features.append(1)
            matched_count += 1
        else:
            input_features.append(0)
            
    print(f"Matched {matched_count} features against model's feature list.")
    
    # Predict
    input_vector = np.array([input_features])
    probs = model.predict_proba(input_vector)[0]
    threat_score = int(probs[1] * 100)
    is_malware = threat_score >= 50
    
    print(f"Prediction: {probs}")
    print(f"Threat Score: {threat_score}")
    print(f"Is Malware: {is_malware}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = SAMPLE_PATH
    
    analyze_file(target)
