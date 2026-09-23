"""
FastAPI REST API integration tests
"""

import unittest
from fastapi.testclient import TestClient
from backend.main import app


class TestAPIEndpoints(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_health_check(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "OPERATIONAL")
        self.assertEqual(data["mesh_agents_active"], 12)

    def test_stats(self):
        response = self.client.get("/api/stats")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("critical_incidents", data)
        self.assertIn("mean_risk_score", data)

    def test_list_alerts(self):
        response = self.client.get("/api/alerts")
        self.assertEqual(response.status_code, 200)
        alerts = response.json()
        self.assertTrue(len(alerts) > 0)
        # Test severity filter
        crit_res = self.client.get("/api/alerts?severity=CRITICAL")
        self.assertEqual(crit_res.status_code, 200)

    def test_agents_status(self):
        response = self.client.get("/api/agents/status")
        self.assertEqual(response.status_code, 200)
        agents = response.json()
        self.assertEqual(len(agents), 12)

    def test_response_action_execution(self):
        payload = {
            "action": "BLOCK_IP",
            "target": "185.220.101.5",
            "severity": "CRITICAL",
            "mode": "MANUAL",
            "executed_by": "Test Suite"
        }
        response = self.client.post("/api/actions/execute", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["action"], "BLOCK_IP")

    def test_task_dispatcher_endpoint(self):
        payload = {
            "task_type": "email",
            "subject": "Wire Transfer Request",
            "body": "Urgent payroll wire transfer required immediately to avoid suspension."
        }
        response = self.client.post("/api/dispatch", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["dispatcher_status"], "ROUTED_AND_EXECUTED")
        self.assertEqual(data["task_type"], "email")

    def test_simulation_trigger(self):
        response = self.client.post("/api/simulation/run")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["simulation_status"], "COMPLETED")
        self.assertIn("correlated_incident", data)


if __name__ == "__main__":
    unittest.main()
