import os
import joblib
import numpy as np
import sys
from .feature_extractor import extract_features

# To ensure AppType is accessible
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from src.types import AppType

class MLPredictor:
    def __init__(self):
        base_dir = os.path.dirname(__file__)
        model_path = os.path.join(base_dir, "model", "dpi_model.pkl")
        scaler_path = os.path.join(base_dir, "model", "scaler.pkl")
        
        if not os.path.exists(model_path) or not os.path.exists(scaler_path):
            raise FileNotFoundError("ML Models not found. Run trainer.py first.")
            
        self.scaler = joblib.load(scaler_path)
        self.model_data = joblib.load(model_path)
        
        self.rf = self.model_data['rf']
        self.xgb = self.model_data['xgb']
        self.id_to_label = self.model_data['classes']
        
    def predict(self, flow, parsed_packet=None):
        """
        Returns (AppType, confidence)
        """
        features = extract_features(flow)
        
        # Scale
        scaled_features = self.scaler.transform(features)
        
        # Ensemble Probability
        rf_prob = self.rf.predict_proba(scaled_features)[0]
        xgb_prob = self.xgb.predict_proba(scaled_features)[0]
        
        ensemble_prob = (rf_prob + xgb_prob) / 2
        best_idx = int(np.argmax(ensemble_prob))
        confidence = float(ensemble_prob[best_idx])
        
        predicted_str = self.id_to_label[best_idx]
        
        # Convert string to AppType enum
        for at in AppType:
            if at.value == predicted_str:
                return at, confidence
                
        return AppType.UNKNOWN, confidence
