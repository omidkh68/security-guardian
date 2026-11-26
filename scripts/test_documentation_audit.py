"""Regression tests for bounded human documentation inventory."""
import tempfile
from pathlib import Path
import unittest
import audit_documentation as audit


class DocumentationAuditTests(unittest.TestCase):
    def test_local_link_targets_and_fences(self):
        text = "\n".join(["[good](guide-FA.md#intro)", "[bad](missing.md)",
                          "[outside](../../outside.md)", "[remote](https://example.invalid)",
                          "```bash", "[example](fake.md)", "```",
                          "```mermaid", "flowchart LR", "A --> B", "```"])
        r = audit.inspect("docs/guide.md", text, {"docs/guide-FA.md"})
        self.assertEqual(r["local_links_checked"], 3)
        self.assertEqual(r["mermaid_blocks"], 1)
        self.assertEqual([p["kind"] for p in r["problems"]],
                         ["MISSING_LOCAL_TARGET", "OUTSIDE_REPOSITORY"])

    def test_empty_or_unclosed_mermaid(self):
        r = audit.inspect("README.md", "```mermaid\n```\n~~~mermaid\nA --> B", set())
        self.assertEqual(r["mermaid_blocks"], 2)
        self.assertEqual([p["kind"] for p in r["problems"]],
                         ["EMPTY_MERMAID", "UNCLOSED_FENCE"])

    def test_inventory_only_human_docs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for p in ("README.md", "README-FA.md", "AGENTS.md", "docs/guide.md"):
                path = root / p
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("# Example", encoding="utf-8")
            r = audit.audit(root, {"README.md", "README-FA.md", "AGENTS.md", "docs/guide.md"})
            self.assertEqual(r["documents"], 3)
            self.assertEqual(r["pairs"], 1)
            self.assertEqual(r["missing_persian"], ["docs/guide.md"])


if __name__ == "__main__":
    unittest.main()
