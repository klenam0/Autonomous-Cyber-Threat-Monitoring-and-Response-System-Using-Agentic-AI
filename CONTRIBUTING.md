# Contributing

This project started as a final-year academic research project, and its priority is correctness and reproducibility of the results described in the accompanying thesis. That said, contributions are welcome, especially in the areas listed in the [Roadmap](README.md#roadmap).

## Before you open a PR

1. Check `docs/DECISIONS.md` first, several design choices (e.g., detector evaluation order in `detection_agent.py`, the two-process architecture) are load-bearing and documented with the reasoning behind them. Please read the relevant ADR before proposing a change that touches these areas.
2. Open an issue describing the change before submitting a large PR, so we can agree on approach first.
3. Keep the rule-based detectors and the ML pipeline decoupled changes to one should not require changes to the other.

## Development setup

See [`docs/SETUP.md`](docs/SETUP.md).

## Code style

- Backend: standard PEP 8, existing files use aligned inline comments for tabular clarity in a few places (e.g., `detection_agent.py`), please match surrounding style rather than reformatting whole files.
- Frontend: functional components with hooks, Tailwind utility classes, no CSS-in-JS.

## Reporting issues

Please include:

- Whether you're running batch mode or live mode
- Full console output from `main.py` and `api.py`
- Your Python and Node versions
