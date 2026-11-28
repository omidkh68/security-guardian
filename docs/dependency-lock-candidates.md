# Dependency hash lock candidates (#159)

[فارسی](dependency-lock-candidates-FA.md)

The read-only candidate workflow downloads exact pinned binary wheels for the Linux Python 3.12 fixture without executing source distributions or resolving extra dependencies. It validates wheel metadata identities, records SHA-256 and a candidate requirements file, then tests a fresh offline environment with `--require-hashes`, `pip check`, and the existing real runtime fixture test. It does not automatically modify repository pins. The candidate must be independently compared with publisher digests and reviewed before promotion to a committed lock. Same-run matching is not independent trust or a Scorecard improvement. npm and other pip groups remain outstanding. No release or publication.
