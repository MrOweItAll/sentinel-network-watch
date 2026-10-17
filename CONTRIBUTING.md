# Contributing

Use Python 3.10 or later. Runtime code uses the standard library.

```sh
python -m pip install .
python -B -m unittest discover -s tests -v
sentinel-network-watch doctor
python install.py --prefix ./staged-install
```

Tests must use synthetic identities, documentation addresses and injected
transports. Do not make live network calls, load personal configuration or operate
installed services in a test. Keep raw error responses and secrets out of logs.

Review the exact files staged for each commit. Do not add real examples, captures,
credentials, state databases, screenshots, private deployment files or vendor
source bundles. Review release archives as well as the source tree.

Keep capability claims tied to evidence: snapshots are not complete flows,
router rows are not sessions, and a listener is not proof of external access.
