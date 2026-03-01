"""
predict_bridge.py
─────────────────
A lightweight Python helper invoked by the PHP REST API (api.php).
It loads the trained model + preprocessor, runs prediction on the given
CSV file, and writes the output to prediction_output/output.csv.

Usage:
    python predict_bridge.py <input_csv_path>
"""

import os
import sys
import pandas as pd

# Ensure the project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from networksecurity.exception.exception import NetworkSecurityException
from networksecurity.logging.logger import logging
from networksecurity.utils.main_utils.utils import load_object
from networksecurity.utils.main_utils.ml_utils.model.estimator import NetworkModel

FINAL_MODEL_DIR = "final_model"
PREDICTION_OUTPUT_DIR = "prediction_output"


def run_prediction(input_csv_path: str) -> str:
    """
    Load model, run predictions on the input CSV, write output CSV.
    Returns the path to the output file.
    """
    try:
        logging.info(f"[predict_bridge] Reading input file: {input_csv_path}")
        df = pd.read_csv(input_csv_path)
        logging.info(f"[predict_bridge] Input shape: {df.shape}")

        # Drop target column if present
        if "Result" in df.columns:
            logging.info("[predict_bridge] Dropping 'Result' column from input data")
            df = df.drop(columns=["Result"])

        # Load preprocessor & model
        preprocessor_path = os.path.join(FINAL_MODEL_DIR, "preprocessor.pkl")
        model_path = os.path.join(FINAL_MODEL_DIR, "model.pkl")

        logging.info(f"[predict_bridge] Loading preprocessor from: {preprocessor_path}")
        preprocessor = load_object(preprocessor_path)

        logging.info(f"[predict_bridge] Loading model from: {model_path}")
        model = load_object(model_path)

        network_model = NetworkModel(preprocessor=preprocessor, model=model)

        # Predict
        logging.info("[predict_bridge] Running predictions")
        y_pred = network_model.predict(df)

        df["predicted_column"] = y_pred
        df["predicted_column"] = (
            df["predicted_column"]
            .map({0: "Non-Phishing", 1: "Phishing", -1: "Phishing"})
            .fillna(df["predicted_column"])
        )

        logging.info(
            f"[predict_bridge] Predictions done. Distribution:\n"
            f"{df['predicted_column'].value_counts()}"
        )

        # Save output
        os.makedirs(PREDICTION_OUTPUT_DIR, exist_ok=True)
        output_path = os.path.join(PREDICTION_OUTPUT_DIR, "output.csv")
        df.to_csv(output_path, index=False)
        logging.info(f"[predict_bridge] Output saved to: {output_path}")

        print(f"Prediction successful. Output: {output_path}")
        return output_path

    except Exception as e:
        raise NetworkSecurityException(e, sys)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python predict_bridge.py <input_csv_path>", file=sys.stderr)
        sys.exit(1)

    input_path = sys.argv[1]
    if not os.path.isfile(input_path):
        print(f"Error: File not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    run_prediction(input_path)
