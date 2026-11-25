# Synthetic indicator benchmark baseline

P0 · #78 · RFC #37 · [فارسی](benchmark-FA.md)

Run from a repository checkout:

```bash
python3 scripts/benchmark_scanner.py
```

The MIT synthetic manifest contains one positive and one negative case for each of the 17 scoped pack rule IDs. The positive denotes an expected review candidate, not a confirmed vulnerability. The negative denotes absence of that specific candidate, not safe application behavior. Each case creates a temporary selected component and an excluded sibling with a positive decoy. No fixture code is executed, no network or private customer data is used, and temporary files are removed.

The report includes TP/FP/TN/FN, precision = TP/(TP+FP), recall = TP/(TP+FN), FPR = FP/(FP+TN), FNR = FN/(FN+TP) with explicit denominators and null for undefined ratios. Metrics are grouped by framework and rule; each case scores only its designated rule, reporting other candidate IDs separately. This small deliberately selected corpus is not representative of real projects. The fixture manifest, scanner hash, commit, Python version and elapsed scanner time identify the run. Runtime is not time to first actionable finding.

CI runs this benchmark in each Python matrix job. Malformed or missing pairs, incomplete scan, wrong mapping, or scope leakage fail the job; measured accuracy is reported without an arbitrary threshold. Read actual CI logs for results. No agent evaluation, semantic vulnerability detection, verified remediation, real exploit or framework version certification is claimed. Later increments require independently labeled realistic fixtures, release thresholds, runtime and agent evaluation under authorization. Revert the benchmark PR to roll back; no runtime changes.
