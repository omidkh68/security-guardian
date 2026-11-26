import unittest
from check_workflow_hardening import inspect

class WorkflowHardeningTests(unittest.TestCase):
    def test_pin_and_checkout(self):
        sha='a'*40
        text=f'permissions:\n  contents: read\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@{sha} # v7\n        with:\n          persist-credentials: false\n'
        self.assertEqual(inspect(text),[])
        self.assertTrue(inspect(text.replace(sha,'v7')))
        self.assertTrue(inspect(text.replace('false','true')))
        self.assertTrue(inspect(text.replace('contents: read','contents: write')))
    def test_checkout_cannot_borrow_later_step_setting(self):
        sha='a'*40
        text=f'permissions:\n  contents: read\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@{sha}\n      - uses: actions/checkout@{sha}\n        with:\n          persist-credentials: false\n'
        self.assertEqual(len(inspect(text)),1)

if __name__=='__main__':unittest.main()
