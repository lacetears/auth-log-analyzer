# Development

Use a virtual environment and install `requirements.txt`. Run `python -m pytest -q` from the repository root. CI uses Python 3.12 and 3.13. Tests create temporary databases/files where they mutate data; committed datasets are explicit regression fixtures.

Keep changes small and include a failing example before fixing a bug. Verify documented commands from a clean checkout. Do not describe browser mockups as deployed Python services. The root README is the maintained setup reference; nested guides retain additional context and may describe the original exercise.

## November 2026 review

Timestamp/IP parse failures now use a fixed diagnostic rather than embedding parser exceptions, which echoed malformed field contents. Regression tests cover both strict and skip-invalid modes. Alert payloads still intentionally contain valid event identities; treat reports as sensitive.
