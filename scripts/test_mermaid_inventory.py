import unittest
from export_mermaid_inventory import extract


class MermaidInventoryTests(unittest.TestCase):
    def test_nested_examples_and_fence_length(self):
        text='~~~markdown\n```mermaid\nnot a diagram\n```\n~~~\n````mermaid\nflowchart LR\nA --> B\n````'
        self.assertEqual(extract('docs/x.md',text),[
            {'document':'docs/x.md','line':6,'source':'flowchart LR\nA --> B'}])

    def test_unclosed_fence_fails(self):
        with self.assertRaises(ValueError):
            extract('docs/x.md','```mermaid\nflowchart LR')
