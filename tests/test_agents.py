"""
Tests for Domain Agents, Task Dispatcher, and Cross-Context Correlation
"""

import unittest
from backend.agents.dispatcher import dispatcher_agent
from backend.agents.email_agent import email_agent
from backend.agents.log_agent import log_agent
from backend.agents.ip_agent import ip_agent
from backend.agents.correlation_agent import correlation_system
from backend.agents.response_agent import response_agent
from backend.data.samples import SAMPLE_EMAILS, SAMPLE_LOGS


class TestSentiXAgents(unittest.TestCase):
    def test_dispatcher_classification(self):
        # Email payload
        email_task, valid1 = dispatcher_agent.classify_task({"subject": "Suspicious login alert", "body": "Click here"})
        self.assertEqual(email_task, "email")
        self.assertTrue(valid1["valid"])

        # Log payload
        log_task, valid2 = dispatcher_agent.classify_task({"entries": ["Failed password for root"]})
        self.assertEqual(log_task, "log")
        self.assertTrue(valid2["valid"])

        # IP range payload
        ip_task, valid3 = dispatcher_agent.classify_task({"range": "10.0.0.0/24"})
        self.assertEqual(ip_task, "ip_range")
        self.assertTrue(valid3["valid"])

    def test_email_agent_phishing_detection(self):
        phishing_sample = SAMPLE_EMAILS[0]
        result = email_agent.process(phishing_sample)
        self.assertEqual(result["agent"], "EmailVerificationAgent")
        self.assertEqual(result["verdict"], "PHISHING")
        self.assertGreaterEqual(result["risk_score"], 70)
        self.assertTrue(len(result["urls_detected"]) > 0)
        self.assertTrue(len(result["chain_of_thought"]) > 0)

    def test_log_agent_detection(self):
        log_sample = SAMPLE_LOGS[0]
        result = log_agent.process(log_sample)
        self.assertEqual(result["agent"], "LogAnalyzerAgent")
        self.assertEqual(result["verdict"], "ANOMALOUS_ATTACK")
        self.assertGreaterEqual(result["risk_score"], 70)
        self.assertTrue(len(result["signature_matches"]) > 0)

    def test_ip_agent_scanning(self):
        ip_payload = {"range": "192.168.14.0/24"}
        result = ip_agent.process(ip_payload)
        self.assertEqual(result["agent"], "IPRangeAnalyzerAgent")
        self.assertEqual(result["verdict"], "VULNERABLE_EXPOSURE")
        self.assertTrue(len(result["cve_findings"]) > 0)
        self.assertIn("remediation", result)

    def test_correlation_system(self):
        email_res = email_agent.process(SAMPLE_EMAILS[0])
        log_res = log_agent.process(SAMPLE_LOGS[0])
        ip_res = ip_agent.process({"range": "192.168.14.0/24"})

        correlated = correlation_system.correlate(
            email_result=email_res,
            log_result=log_res,
            ip_result=ip_res
        )
        self.assertIn("incident_id", correlated)
        self.assertEqual(correlated["agents_involved"], 3)
        self.assertGreaterEqual(correlated["correlation_confidence"], 80)
        self.assertTrue(len(correlated["priority_actions"]) > 0)

    def test_response_orchestration(self):
        res = response_agent.execute_action(
            action_type="BLOCK_IP",
            target="198.51.100.22",
            severity="CRITICAL",
            mode="MANUAL",
            executor="SOC-Lead"
        )
        self.assertTrue(res["success"])
        self.assertEqual(res["action"], "BLOCK_IP")
        self.assertEqual(res["target"], "198.51.100.22")


if __name__ == "__main__":
    unittest.main()
