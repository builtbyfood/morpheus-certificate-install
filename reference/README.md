# reference/

`reference/python/` is **Morpheus Certificate Install 0.2.1**, the original Python version. It is kept here as the specification for this app, not as something to run in production:

- every file in `fixtures/` (the test corpus, `cases.json`, the goldens) is generated from it, by `fixtures/gen-corpus.sh` and `fixtures/make-cases.py`;
- the UI contract test (`npm run test:ui-contract`) runs the page against it;
- every intended difference between it and this app is listed in `docs/PARITY.md`.

It is frozen. It changes only to fix the reference itself, and then the fixtures are regenerated in the same change. Use the release builds of this app instead of the Python; the Python gets no fixes.
