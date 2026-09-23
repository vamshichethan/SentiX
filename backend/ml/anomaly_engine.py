"""
SentiX Machine Learning Anomaly Engine
Implements Isolation Forest, Neural Autoencoder, and Multi-Factor Risk Scoring
Based on SentinelX Methodology & Flowchart (Slide 9 & 10)
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler
from typing import Dict, Any, Tuple, List
from backend.config import WEIGHTS


class SimpleAutoencoder:
    """
    Lightweight 3-layer Neural Autoencoder implemented in NumPy.
    Encoder: input_dim -> hidden_dim (bottleneck)
    Decoder: hidden_dim -> input_dim (reconstruction)
    Trained on baseline benign security flow features.
    """
    def __init__(self, input_dim: int = 6, hidden_dim: int = 3, learning_rate: float = 0.01):
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.lr = learning_rate
        np.random.seed(42)
        # Weights and biases initialization
        self.W1 = np.random.randn(input_dim, hidden_dim) * 0.1
        self.b1 = np.zeros(hidden_dim)
        self.W2 = np.random.randn(hidden_dim, input_dim) * 0.1
        self.b2 = np.zeros(input_dim)
        self.fitted = False

    def _relu(self, x):
        return np.maximum(0, x)

    def _relu_grad(self, x):
        return (x > 0).astype(float)

    def fit(self, X: np.ndarray, epochs: int = 150):
        """Train autoencoder on normal baseline event telemetry."""
        m = X.shape[0]
        for _ in range(epochs):
            # Forward pass
            z1 = np.dot(X, self.W1) + self.b1
            a1 = self._relu(z1)  # Bottleneck layer
            z2 = np.dot(a1, self.W2) + self.b2
            X_hat = z2  # Linear output

            # Compute loss gradient (MSE)
            loss_grad = (2.0 / m) * (X_hat - X)

            # Backpropagation
            dW2 = np.dot(a1.T, loss_grad)
            db2 = np.sum(loss_grad, axis=0)

            da1 = np.dot(loss_grad, self.W2.T)
            dz1 = da1 * self._relu_grad(z1)
            dW1 = np.dot(X.T, dz1)
            db1 = np.sum(dz1, axis=0)

            # Update weights
            self.W1 -= self.lr * dW1
            self.b1 -= self.lr * db1
            self.W2 -= self.lr * dW2
            self.b2 -= self.lr * db2

        self.fitted = True

    def reconstruction_error(self, X: np.ndarray) -> np.ndarray:
        """Compute Mean Squared Error (MSE) between input and reconstruction."""
        z1 = np.dot(X, self.W1) + self.b1
        a1 = self._relu(z1)
        X_hat = np.dot(a1, self.W2) + self.b2
        # MSE per sample
        mse = np.mean(np.square(X - X_hat), axis=1)
        return mse


class MLAnomalyEngine:
    """
    Combined ML Anomaly Detection Engine:
    1. Isolation Forest for tree path length anomaly scoring
    2. Autoencoder for feature reconstruction loss
    3. Multi-factor weighted composite risk score calculator (Slide 10)
    """
    def __init__(self):
        self.scaler = MinMaxScaler()
        # Contamination rate tuned for cybersecurity telemetry (e.g. ~10% anomalous)
        self.if_model = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42
        )
        self.ae_model = SimpleAutoencoder(input_dim=6, hidden_dim=3)
        self.is_trained = False
        self._initialize_baseline_models()

    def _initialize_baseline_models(self):
        """Train models on baseline normal synthetic network & host log telemetry."""
        np.random.seed(42)
        # Normal baseline features:
        # [bytes_in, bytes_out, duration, failed_logins, privilege_reqs, distinct_dest_ports]
        normal_samples = 400
        normal_data = np.zeros((normal_samples, 6))
        # Normal traffic: standard packet sizes, short duration, 0-1 failed logins, standard ports
        normal_data[:, 0] = np.random.uniform(200, 4500, normal_samples)      # bytes_in
        normal_data[:, 1] = np.random.uniform(500, 15000, normal_samples)     # bytes_out
        normal_data[:, 2] = np.random.exponential(1.5, normal_samples)        # duration (sec)
        normal_data[:, 3] = np.random.choice([0, 1], size=normal_samples, p=[0.92, 0.08]) # failed_logins
        normal_data[:, 4] = np.random.choice([0, 1], size=normal_samples, p=[0.97, 0.03]) # priv_reqs
        normal_data[:, 5] = np.random.randint(1, 4, normal_samples)          # distinct_dest_ports

        # Fit Scaler
        X_scaled = self.scaler.fit_transform(normal_data)

        # Fit Isolation Forest & Autoencoder
        self.if_model.fit(X_scaled)
        self.ae_model.fit(X_scaled, epochs=120)
        self.is_trained = True

    def extract_features(self, event_data: Dict[str, Any]) -> np.ndarray:
        """
        Normalize event parameters into numerical vector:
        [bytes_in, bytes_out, duration, failed_logins, privilege_reqs, distinct_dest_ports]
        """
        bytes_in = float(event_data.get("bytes_in", 500))
        bytes_out = float(event_data.get("bytes_out", 1200))
        duration = float(event_data.get("duration", 1.0))
        failed_logins = float(event_data.get("failed_logins", 0))
        priv_reqs = float(event_data.get("privilege_reqs", 0))
        distinct_ports = float(event_data.get("distinct_dest_ports", 1))

        raw_vec = np.array([[bytes_in, bytes_out, duration, failed_logins, priv_reqs, distinct_ports]])
        scaled_vec = self.scaler.transform(raw_vec)
        return scaled_vec

    def compute_anomaly_scores(self, event_data: Dict[str, Any]) -> Tuple[float, float]:
        """
        Returns (if_anomaly_score [0..1], ae_anomaly_score [0..1])
        """
        features = self.extract_features(event_data)

        # 1. Isolation Forest Anomaly Score
        # decision_function gives negative score for outliers, positive for inliers
        # Map to 0 (normal) .. 1 (highly anomalous)
        raw_if = self.if_model.decision_function(features)[0]
        # Invert and normalize using sigmoid-like scaling
        if_score = float(1.0 / (1.0 + np.exp(raw_if * 5.0)))
        if_score = max(0.0, min(1.0, if_score))

        # 2. Autoencoder Reconstruction Error
        raw_mse = float(self.ae_model.reconstruction_error(features)[0])
        # Scale MSE to 0..1 range (MSE > 0.3 represents major anomaly in normalized space)
        ae_score = float(min(1.0, raw_mse * 3.5))

        return round(if_score, 4), round(ae_score, 4)

    def calculate_risk_score(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Implements Slide 10 Risk Scoring Algorithm:
        Risk Score = w1*IF + w2*AE + w3*Severity + w4*ThreatIntel + w5*AssetCrit + w6*Frequency
        Normalized to 0 - 100
        Classification:
          0 - 24: Low
          25 - 49: Medium
          50 - 74: High
          75 - 100: Critical
        """
        if_score, ae_score = self.compute_anomaly_scores(event_data)

        # Normalize additional risk inputs to [0..1]
        severity_map = {"LOW": 0.2, "MEDIUM": 0.5, "HIGH": 0.8, "CRITICAL": 1.0}
        raw_sev = str(event_data.get("severity", "MEDIUM")).upper()
        severity_score = severity_map.get(raw_sev, 0.5)

        # Threat Intelligence score (from VirusTotal / AbuseIPDB / NVD CVSS)
        threat_intel = float(event_data.get("threat_intel_score", 0.0))
        if threat_intel > 1.0: # e.g. CVSS 0..10 or percentage
            threat_intel = threat_intel / 10.0 if threat_intel <= 10.0 else threat_intel / 100.0
        threat_intel = max(0.0, min(1.0, threat_intel))

        # Asset Criticality (0.1 to 1.0)
        asset_crit = float(event_data.get("asset_criticality", 0.6))
        asset_crit = max(0.1, min(1.0, asset_crit))

        # Frequency factor (e.g. repeated event count)
        freq_count = float(event_data.get("frequency", 1))
        freq_score = min(1.0, freq_count / 10.0)

        # Weighted composite score
        w = WEIGHTS
        raw_weighted = (
            w["w_if"] * if_score +
            w["w_ae"] * ae_score +
            w["w_severity"] * severity_score +
            w["w_threat_intel"] * threat_intel +
            w["w_asset_crit"] * asset_crit +
            w["w_frequency"] * freq_score
        )

        # Normalization to (0 - 100)
        composite_score = int(np.clip(raw_weighted * 100, 0, 100))

        # Determine Risk Level
        if composite_score <= 24:
            risk_level = "LOW"
        elif composite_score <= 49:
            risk_level = "MEDIUM"
        elif composite_score <= 74:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"

        return {
            "composite_score": composite_score,
            "risk_level": risk_level,
            "if_score": round(if_score * 100, 1),
            "ae_score": round(ae_score * 100, 1),
            "severity_score": round(severity_score * 100, 1),
            "threat_intel_score": round(threat_intel * 100, 1),
            "asset_criticality": round(asset_crit * 100, 1),
            "frequency_score": round(freq_score * 100, 1)
        }


# Singleton engine instance
anomaly_engine = MLAnomalyEngine()
