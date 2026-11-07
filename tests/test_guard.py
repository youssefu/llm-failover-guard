import unittest
from pathlib import Path
from llm_failover_guard import (
    FailoverRouter,
    KeySlot,
    format_markdown_report,
    scan_text_lines,
    shannon_entropy,
)


class TestFailoverRouter(unittest.TestCase):
    def test_failover_on_rate_limit(self) -> None:
        slots = [
            KeySlot(provider="openai", name="slot-1", api_key="sk-proj-111122223333", model="gpt-5"),
            KeySlot(provider="groq", name="slot-2", api_key="gsk_111122223333", model="llama-3.3-70b"),
        ]
        router = FailoverRouter(slots)
        clock = [1000.0]

        def fake_now() -> float:
            return clock[0]

        def fake_transport(slot: KeySlot, sys_msg: str, usr_msg: str) -> str:
            if slot.name == "slot-1":
                raise RuntimeError("429 Too Many Requests")
            clock[0] += 0.045
            return "Triage OK"

        res = router.execute_with_failover("Check PR", transport=fake_transport, now_fn=fake_now)
        self.assertTrue(res["ok"])
        self.assertEqual(res["slot_name"], "slot-2")
        self.assertEqual(res["attempts"], 2)
        self.assertEqual(slots[0].fail_count, 1)
        self.assertFalse(slots[0].is_available(now=1010.0))
        self.assertTrue(slots[0].is_available(now=1035.0))
        self.assertEqual(slots[1].success_count, 1)


class TestSecurityScanner(unittest.TestCase):
    def test_detects_secrets_and_sinks(self) -> None:
        sample = [
            'API_KEY = "sk-proj-"' + '"ABCDEFGHIJKLMNOPQRSTUVWX123456"',  # nosec
            'subprocess.' + 'run(user_cmd, shell=True)',  # nosec
            'element.' + 'innerHTML = untrusted_input;',  # nosec
        ]
        sample = [s.replace('""', '') for s in sample]
        findings = scan_text_lines(sample, file_path="app.py")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("SEC001", rule_ids)
        self.assertIn("SEC002", rule_ids)
        self.assertIn("SEC004", rule_ids)
        md = format_markdown_report(findings, "app.py")
        self.assertIn("SEC001", md)
        self.assertNotIn("ABCDEFGHIJKLMNOPQRSTUVWX123456", md)

    def test_shannon_entropy(self) -> None:
        self.assertGreater(shannon_entropy("aB3$xZ9!qW2#mP8@"), 3.5)
        self.assertEqual(shannon_entropy(""), 0.0)


if __name__ == "__main__":
    unittest.main()
