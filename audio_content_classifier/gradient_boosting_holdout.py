#!/usr/bin/env python3
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import joblib

from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, ConfusionMatrixDisplay
from sklearn.ensemble import HistGradientBoostingClassifier


FEATURES_FILE = "features_v2FINAL.csv"   
MODEL_FILE = "gb_final_v2.joblib"

TEST_SIZE = 0.2
RANDOM_STATE = 42


df = pd.read_csv(FEATURES_FILE)

X = df.drop(columns=["pcap", "label"])
y = df["label"]

print(f"[i] Loaded dataset with {len(df)} samples and {X.shape[1]} features")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=TEST_SIZE,
    stratify=y,
    random_state=RANDOM_STATE
)

print(f"Train samples: {len(X_train)}")
print(f"Test samples:  {len(X_test)}")

labels = sorted(y.unique())


gb = HistGradientBoostingClassifier(
    max_depth=15,
    learning_rate=0.3,
    max_iter=200,
    random_state=RANDOM_STATE
)

gb.fit(X_train, y_train)


y_pred = gb.predict(X_test)
acc = accuracy_score(y_test, y_pred)

print("\n=== Gradient Boosting (80/20 hold-out) ===")
print(f"Accuracy: {acc:.4f}")

print("\nClassification report:")
print(classification_report(y_test, y_pred))

cm = confusion_matrix(y_test, y_pred, labels=labels)

print("Confusion matrix:")
print(cm)

disp = ConfusionMatrixDisplay(
    confusion_matrix=cm,
    display_labels=labels
)

plt.figure(figsize=(8, 7))
disp.plot(xticks_rotation=45)
plt.title("Gradient Boosting – Confusion Matrix (80/20)")
plt.tight_layout()
plt.show()


gb.fit(X, y)

joblib.dump(
    {
        "model": gb,
        "feature_columns": list(X.columns)
    },
    MODEL_FILE
)

print(f"\n[✓] Final Gradient Boosting model trained on {len(df)} samples")
print(f"[✓] Model saved to '{MODEL_FILE}'")
