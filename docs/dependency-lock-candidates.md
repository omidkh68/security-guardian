# Dependency hash lock candidates (#159)

[فارسی](dependency-lock-candidates-FA.md)

The read-only candidate workflow downloads exact pinned binary wheels for the Linux Python 3.12 fixture without executing source distributions or resolving extra dependencies. It validates wheel metadata identities, records SHA-256 and a candidate requirements file, then tests a fresh offline environment with `--require-hashes`, `pip check`, and the existing real runtime fixture test. It does not automatically modify repository pins. The candidate must be independently compared with publisher digests and reviewed before promotion to a committed lock. Same-run matching is not independent trust or a Scorecard improvement. npm and other pip groups remain outstanding. No release or publication.

## Promotion to a committed lock

Artifact 15239106793 from run 46085947291 was downloaded and all seven wheel SHA-256 digests matched the official PyPI release file pages: [blinker 1.9.0](https://pypi.org/project/blinker/1.9.0/), [click 8.2.1](https://pypi.org/project/click/8.2.1/), [Flask 3.1.3](https://pypi.org/project/Flask/3.1.3/), [itsdangerous 2.2.0](https://pypi.org/project/itsdangerous/2.2.0/), [Jinja2 3.1.6](https://pypi.org/project/Jinja2/3.1.6/), [MarkupSafe 3.0.3](https://pypi.org/project/MarkupSafe/3.0.3/), [Werkzeug 3.1.9](https://pypi.org/project/Werkzeug/3.1.9/). `scripts/requirements-framework-fixture-linux-py312.lock` is scoped to Linux x86_64 CPython 3.12 only. Main CI installs with `--require-hashes`, checks reference pin consistency, and runs the existing runtime fixture. Registry digest matching is not independent publisher signature verification. New CI and post-merge Scorecard pending; other npm and pip groups remain outside this lock.
