# Architecture Decision Records

This document captures the significant design decisions made during development, along with the reasoning and alternatives considered. It follows a lightweight ADR (Architecture Decision Record) format.

---

### ADR-1: Unsupervised anomaly detection (Isolation Forest) over supervised classification

**Context:** The ML component needed to catch anomalous login behaviour without requiring labeled attack data at training time.

**Decision:** Use Isolation Forest, an unsupervised method, trained exclusively on normal login events.

**Consequences:** No labeled attack data is required at training time, which matches the "unsupervised anomaly detection" framing used throughout the literature on this problem. Supervised alternatives (Random Forest, XGBoost) were considered and rejected - they require labeled attack examples, which changes both the data requirements and the research framing.

---

### ADR-2: Two-phase ML architecture - offline training, runtime inference only

**Context:** The model needed to avoid circular validation (training and testing on the same live data) and mirror how production SIEM platforms operate.

**Decision:** Train the model entirely offline against a static dataset; at runtime, the model performs inference only and is never updated from live traffic.

**Consequences:** Prevents a live attacker from poisoning the model's notion of "normal" by generating traffic during the observation window. Online learning was considered and rejected for this reason.

---

### ADR-3: Isolation Forest hyperparameters - `contamination=0.15` with `StandardScaler`

**Context:** The `contamination` parameter sets the expected anomaly rate and directly affects the model's decision boundary.

**Decision:** `contamination=0.15`, selected empirically.

**Consequences:** Lower contamination values were tested and performed markedly worse on this dataset (e.g., `0.05` collapsed recall to single digits; `0.10` gave a substantially lower F1 than `0.15`). This is dataset-specific and would need re-tuning if the training distribution changes materially.

---

### ADR-4: Asynchronous LLM enrichment in the API process, not the detection pipeline

**Context:** LLM-based alert enrichment (`phi3:mini` via Ollama) can take 60–90 seconds per request on modest hardware.

**Decision:** Run enrichment as a background thread inside the persistent `api.py` process, scanning `alerts.json` for unenriched alerts every 10 seconds, rather than synchronously inside the detection pipeline (`main.py`).

**Consequences:** Detection throughput is unaffected by LLM latency. This required moving enrichment out of `main.py` specifically, since that process exits after a batch run (a daemon thread there would simply die with it) - the enrichment thread needed a long-lived host process.

---

### ADR-5: MCP (Model Context Protocol) integration deferred to future work

**Context:** MCP-based agent tool-calling was considered as a way to make the agents more dynamically composable.

**Decision:** Not implemented in the current system; documented as future work.

**Consequences:** The current architecture is still defensible as "agentic" - each agent has a distinct responsibility and the pipeline is sequential and composable - without the added implementation and evaluation surface area MCP would introduce.

---

### ADR-6: The ML detector treats FAILED and SUCCESS events differently

**Context:** If the ML detector blocked an IP on any anomalous event, it would sometimes consume an IP before the rule-based brute-force or credential-stuffing detectors had accumulated enough failures to fire themselves - masking the more specific rule-based classification behind a generic ML anomaly alert.

**Decision:** On a flagged `FAILED` event, the ML detector raises an alert but does _not_ block the IP, allowing rule-based detectors downstream to keep accumulating failures. On a flagged `SUCCESS` event, it blocks immediately, since no rule-based detector covers a suspicious successful login (e.g., account takeover from an unrecognized IP).

**Consequences:** Preserves the more specific and actionable rule-based classifications (brute force, credential stuffing) instead of having every attack scenario collapse into a single generic "ML Anomaly" label.

---

### ADR-7: Cross-process file locking via `filelock`

**Context:** `main.py` and `api.py` run as separate OS processes, both reading and writing `alerts.json`. Python's built-in `threading.Lock()` only synchronizes within a single process.

**Decision:** Use the `filelock` library for all read-modify-write cycles against shared JSON files.

**Consequences:** Prevents write corruption from concurrent access across the two processes, at the cost of occasional lock-wait latency under contention (not observed to be a practical issue at this system's throughput).

---

### ADR-8: `phi3:mini` chosen over larger models for local LLM enrichment

**Context:** Enrichment needed to run entirely locally (no external API calls) on modest consumer GPU hardware.

**Decision:** Use `phi3:mini` via Ollama rather than a larger model such as Mistral 7B.

**Consequences:** Fits comfortably within low-VRAM GPU budgets and CPU fallback scenarios where larger models would be substantially slower or simply wouldn't fit.

---

### ADR-9: Detector evaluation order is load-bearing

**Context:** Slow brute force, credential stuffing, and fast brute force all begin from the same signal - repeated `FAILED` events from one IP - and are only distinguishable by _when_ they're checked relative to each other.

**Decision:** Evaluate in this fixed order: Slow Brute Force → Credential Stuffing → Fast Brute Force.

**Consequences:** Slow brute force must be checked before the fast-brute-force threshold, because it needs a minimum time spread (5+ minutes) to distinguish it from a fast attack. Credential stuffing must be checked before fast brute force, because it needs a unique-username count to distinguish it from a single-account attack. **Reordering these checks will misclassify attacks** - this is a hard constraint on any future refactor of `detection_agent.py`, not a stylistic choice.

---

### ADR-10: RBA Dataset scale - 630,000 training rows

**Context:** Model quality was evaluated across different training set sizes.

**Decision:** Train on 630,000 normal login events rather than a smaller subset.

**Consequences:** Scale had a larger measured impact on F1 than additional feature engineering did at smaller training sizes. This dataset (Wiefling et al.) is documented by its own creators as a privacy-preserving _synthetic reconstruction_ of real production login data - ground-truth labels and statistical structure are preserved, but individual field values are regenerated, not raw real enterprise records.

---

### ADR-11: Wired a previously-dormant `failed_rate` feature at live inference time

**Context:** A runtime audit found that `AnomalyDetector`'s per-IP failure counters, used to compute one of the ten ML features (`failed_rate`), were declared and read but never incremented anywhere in the live pipeline - meaning this feature was silently constant at `0.0` for every live and batch inference call, despite being computed correctly during offline training.

**Decision:** Increment the counters once per real event, inside `score_event()` (not inside the feature-extraction method, which is also called a second time for explanation generation on flagged events - incrementing there would have double-counted).

**Consequences:** The model now scores on all ten intended features at inference time instead of nine. Offline training/evaluation metrics were unaffected (the training pipeline always computed this feature correctly via a full pass over the dataset); this fix specifically corrected live single-event scoring accuracy. Caught and fixed before any dashboard screenshots or evaluation results had been captured for this project, so no previously-reported results needed revision.

---

### ADR-12: `AlertExplainer` dormant-code defect

**Context:** A code audit found that feature-level ML explainability (`AlertExplainer` in `ml/explainer.py`) was fully implemented but never instantiated in `anomaly_model.py` due to a commented-out initialization line - meaning `feature_explanation` silently returned `None` on every alert, despite the explainability module being complete and correct.

**Decision:** Uncommented the instantiation and added the corresponding import. This required a full pipeline re-run, since previously generated alerts had `feature_explanation: None` baked in.

**Consequences:** All post-fix alerts now carry a genuine per-feature standard-deviation breakdown rather than a null field. Any results or screenshots referencing feature explainability must be drawn from the corrected, post-fix run.
