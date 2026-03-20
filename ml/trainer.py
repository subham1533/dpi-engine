import pandas as pd
import numpy as np
import os
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import warnings
warnings.filterwarnings('ignore')

def main():
    base_dir = os.path.dirname(__file__)
    data_path = os.path.join(base_dir, "training_data.csv")
    model_dir = os.path.join(base_dir, "model")
    os.makedirs(model_dir, exist_ok=True)
    
    if not os.path.exists(data_path):
        print(f"Error: {data_path} not found. Run dataset_generator.py first.")
        return
        
    print("Loading dataset...")
    df = pd.read_csv(data_path)
    
    X = df.drop(columns=["label"])
    y = df["label"]
    
    # Map string labels to integers for XGBoost
    classes = sorted(y.unique())
    label_to_id = {c: i for i, c in enumerate(classes)}
    id_to_label = {i: c for c, i in label_to_id.items()}
    y_encoded = y.map(label_to_id)
    
    X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded)
    
    print("Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    print("Training RandomForest...")
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X_train_scaled, y_train)
    
    print("Training XGBoost...")
    xgb = XGBClassifier(n_estimators=100, random_state=42, use_label_encoder=False, eval_metric='mlogloss')
    xgb.fit(X_train_scaled, y_train)
    
    print("Evaluating Ensemble...")
    # Soft voting ensemble
    rf_probs = rf.predict_proba(X_test_scaled)
    xgb_probs = xgb.predict_proba(X_test_scaled)
    ensemble_probs = (rf_probs + xgb_probs) / 2
    y_pred = np.argmax(ensemble_probs, axis=1)
    
    acc = accuracy_score(y_test, y_pred)
    print(f"\nTarget Accuracy: >92%")
    print(f"Actual Accuracy: {acc * 100:.2f}%\n")
    
    print("Classification Report:")
    print(classification_report(y_test, y_pred, target_names=classes))
    
    # Save Confusion Matrix
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(10,8))
    sns.heatmap(cm, annot=True, fmt='d', xticklabels=classes, yticklabels=classes, cmap='Blues')
    plt.title('Confusion Matrix')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    plt.savefig(os.path.join(base_dir, "confusion_matrix.png"))
    plt.close()
    print(f"Saved confusion_matrix.png")
    
    # Save Feature Importance (using RF for simplicity)
    importances = rf.feature_importances_
    plt.figure(figsize=(10,6))
    sns.barplot(x=importances, y=X.columns)
    plt.title('Random Forest Feature Importance')
    plt.tight_layout()
    plt.savefig(os.path.join(base_dir, "feature_importance.png"))
    plt.close()
    print(f"Saved feature_importance.png")
    
    # Save Models and metadata
    joblib.dump(scaler, os.path.join(model_dir, "scaler.pkl"))
    joblib.dump({'rf': rf, 'xgb': xgb, 'classes': id_to_label, 'features': X.columns.tolist()}, 
                os.path.join(model_dir, "dpi_model.pkl"))
    print(f"Saved models to {model_dir}")

if __name__ == "__main__":
    main()
