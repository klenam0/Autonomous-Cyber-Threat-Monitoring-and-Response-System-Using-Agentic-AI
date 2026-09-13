# Publication Checklist

Work through this before making the repository public. Nothing here has been applied automatically - these are flagged for your review since some involve behavior or trade-off decisions only you should make.

## 1. Code changes to make

### 1a. Hardcoded local path in `backend/ml/train_from_dataset.py`

Currently:

```python
DATASET_PATH = r"C:\Users\Dell\Downloads\rbadataset\rba-dataset.csv"
```

This is a personal local path and won't work for anyone else who clones the repo. Replace with an environment variable or CLI argument, e.g.:

```python
import os
DATASET_PATH = os.environ.get(
    "RBA_DATASET_PATH",
    os.path.join(os.path.dirname(__file__), "..", "data", "rba-dataset.csv"),
)
```

Document the expected path in `docs/SETUP.md` (already noted there as a placeholder - update once you decide on the final convention).

### 1b. `CLEAR_TOKEN` fallback default in `backend/api.py`

Currently, three endpoints fall back to a hardcoded default if `CLEAR_TOKEN` isn't set:

```python
expected_token = os.environ.get("CLEAR_TOKEN", "soc-clear-2026")
```

For a public repo, consider changing the fallback to **fail closed** rather than fail open to a known string:

```python
expected_token = os.environ.get("CLEAR_TOKEN")
if not expected_token or token != expected_token:
    return jsonify({"error": "Unauthorized"}), 401
```

This means the clear/restore/queue-clear endpoints simply refuse all requests until `CLEAR_TOKEN` is explicitly set in `.env` - safer default for code anyone can read on GitHub. This is a deliberate behavior change (fail-closed vs. fail-open), which is why it's listed here rather than applied silently.

### 1c. Confirm `.env` is not present anywhere in the new repo

```bash
find . -name ".env" -not -path "*/node_modules/*"
```

Should return nothing. Only `.env.example` files should exist.

## 2. Files to exclude entirely

Do not copy these into the new repo as-is:

- `CONTEXT.md` - internal working notes; the useful technical content has already been extracted into `docs/DECISIONS.md` and `docs/ARCHITECTURE.md`.
- Any `__pycache__/`, `.pyc`, `node_modules/`, `venv/` - covered by the provided `.gitignore`.
- `backend/data/alerts.json`, `alerts.json.bak`, `live_queue.jsonl`, `live_queue.jsonl.cursor`, `pipeline_stats.json`, `raw_logs.txt`, `parsed_logs.json`, `training_logs.json`, `training_sample.csv`, `eval_sample.csv` - all regenerated at runtime, already covered by `.gitignore`.

## 3. `model.pkl` - a decision point

Check its size first:

```bash
du -h backend/data/model.pkl
```

- **If it's a few MB or less:** fine to commit directly, as originally intended (per your existing `.gitignore` comment exempting it).
- **If it's large (tens of MB+):** GitHub will warn on push past 50MB and hard-block past 100MB. Options:
  - Use [Git LFS](https://git-lfs.com/) for this one file.
  - Exclude it from the repo and document that `python ml/train_from_dataset.py` regenerates it (requires the RBA Dataset CSV, which is not redistributed here - link to the original source instead).

## 4. Screenshots to capture

Run the system locally (batch mode is enough) and capture:

1. **Dashboard overview** (`/dashboard`) - with all 6 attack scenarios represented
2. **Live Alert Feed** (`/live-alerts`) - showing severity badges and MITRE columns
3. **An expanded alert card** in Alert Log, showing both the LLM explanation and the ML feature-explanation panel (requires Ollama running)
4. **MITRE ATT&CK Mapping** page
5. **Detection Engine** page, showing the hybrid rule/ML architecture cards

Save them as PNGs into `docs/screenshots/` using the filenames already referenced in `README.md`, or update the README's paths to match whatever you name them.

## 5. Personal / contact details to review

- `backend/.env.example` and `frontend/.env.example` - confirm no real values slipped in when you copied from your working `.env`.
- Any test email addresses used during development (e.g., in commit history or old test runs) - not present in tracked source, but worth a final `grep -ri "@.*\.com" -r backend/ frontend/src/` pass to be sure.
- `CITATION.cff` and the README's citation block - fill in your actual name, institution, and final GitHub URL.

## 6. Creating and pushing the new repository

```bash
# 1. Create a new, empty repository on GitHub first (github.com/new),
#    do NOT initialize it with a README/license/gitignore - you already have those.

# 2. From your local machine, set up a clean working copy:
mkdir agentic-cyber-ids && cd agentic-cyber-ids
git init
git branch -M main

# 3. Copy in your actual backend/ and frontend/ source (with the fixes from
#    section 1 applied), plus everything from this repo-ready/ bundle:
#    README.md, LICENSE, .gitignore, CITATION.cff, CONTRIBUTING.md,
#    docs/, backend/.env.example, frontend/.env.example

# 4. Verify nothing sensitive is staged before the first commit:
git add -A
git status
git diff --cached --stat   # eyeball the full file list

# 5. First commit:
git commit -m "Initial commit: agentic cyber threat detection system"

# 6. Point at your new GitHub remote and push:
git remote add origin https://github.com/klenam0/Autonomous-Cyber-Threat-Monitoring-and-Response-System-Using-Agentic-AI.git
git push -u origin main
```

## 7. After pushing

- Add repository topics on GitHub (e.g., `intrusion-detection`, `isolation-forest`, `agentic-ai`, `mitre-attack`, `llm`, `cybersecurity`) for discoverability.
- Add a repository description and the deployed dashboard URL (if/when you do the split deploy).
- Confirm the "Cite this repository" button appears on the repo's main page - it should, automatically, once `CITATION.cff` is present and valid.
- Double check the Mermaid diagrams in `README.md` and `docs/ARCHITECTURE.md` render correctly on GitHub's web UI (they use GitHub's native Mermaid support - no image generation required, but syntax errors will show as raw text instead of a diagram).
