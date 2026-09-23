"""
Tests for ML Anomaly Engine (Isolation Forest, Autoencoder, Risk Scoring)
"""

import unittest
from backend.ml.anomaly_engine import anomaly_engine, MLAnomalyEngine


class TestMLAnomalyEngine(unittest.TestCase):
    def setUp(self):
        self.engine = anomaly_engine

    def test_engine_initialization(self):
        self.assertTrue(self.engine.is_trained)
        self.assertTrue(self.engine.ae_model.fitted)

    def test_feature_extraction(self):
        sample = {
            "bytes_in": 1200,
            "bytes_out": 4500,
            "duration": 1.2,
            "failed_logins": 0,
            "privilege_reqs": 0,
            "distinct_dest_ports": 2
        }
        feats = self.engine.extract_features(sample)
        self.assertEqual(feats.shape, (1, 6))

    def test_compute_anomaly_scores(self):
        # Benign sample
        normal_sample = {
            "bytes_in": 1500,
            "bytes_out": 3000,
            "duration": 1.0,
            "failed_logins": 0,
            "privilege_reqs": 0,
            "distinct_dest_ports": 1
        }
        if_norm, ae_norm = self.engine.compute_anomaly_scores(normal_sample)
        self.assertGreaterEqual(if_norm, 0.0)
        self.assertLessEqual(if_norm, 1.0)

        # Severe attack sample
        attack_sample = {
            "bytes_in": 950000,
            "bytes_out": 2500000,
            "duration": 45.0,
            "failed_logins": 25,
            "privilege_reqs": 10,
            "distinct_dest_ports": 50
        }
        if_att, ae_att = self.engine.compute_anomaly_scores(attack_sample)
        self.assertGreater(if_att, 0.5)

    def test_calculate_risk_score_levels(self):
        attack_sample = {
            "bytes_in": 950000,
            "bytes_out": 2500000,
            "duration": 45.0,
            "failed_logins": 25,
            "privilege_reqs": 10,
            "distinct_dest_ports": 50,
            "severity": "CRITICAL",
            "threat_intel_score": 9.5,
            "asset_criticality": 1.0,
            "frequency": 8
        }
        res = self.engine.calculate_risk_score(attack_sample)
        self.assertIn("composite_score", res)
        self.assertIn("risk_level", res)
        self.assertEqual(res["risk_level"], "CRITICAL")
        self.assertGreaterEqual(res["composite_score"], 75)


if __name__ == "__main__":
    unittest.main()
