<!-- What changed, and why. If it fixes a false positive, name the repository
     it came from and what the value actually was. -->

## If this adds or changes a rule

- [ ] Detection in the scanner for that format
- [ ] An entry in `rules.py`, with the **worst-case** severity
- [ ] A fixture in `tests/corpus.py` that trips it
- [ ] A row in `docs/RULES.md`
- [ ] Tests for what it should **not** match
- [ ] `python3 tools/measure.py` over a real repository or two

The suite enforces the middle four. The last one is the only way to find out
whether a heuristic survives contact with somebody else's code.

## Always

- [ ] `PYTHONPATH=src python -m unittest discover -s tests`
- [ ] `python3 tools/coverage.py`
- [ ] The tool still reports nothing on itself: `bluerayscan scan . --exclude tests`
