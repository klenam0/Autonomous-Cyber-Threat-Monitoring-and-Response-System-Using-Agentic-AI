# backend/ml/train_from_dataset.py
"""
RBA Dataset training - clean targeted improvement.
Base: best working model (F1 58.4%, Precision 74.6%, Recall 47.9%)
Additions: cyclic hour encoding + is_new_ip + is_new_country flags
Everything else unchanged from the best working version.
"""

import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import roc_auc_score, average_precision_score
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── Configuration ──────────────────────────────────────────────────────────────
DATASET_PATH   = os.environ.get(
    "RBA_DATASET_PATH",
    os.path.join(os.path.dirname(__file__), "..", "data", "rba-dataset.csv"),
)
MODEL_PATH     = os.path.join(os.path.dirname(__file__), "..", "data", "model.pkl")
SAMPLE_PATH    = os.path.join(os.path.dirname(__file__), "..", "data", "training_sample.csv")
EVAL_PATH      = os.path.join(os.path.dirname(__file__), "..", "data", "eval_sample.csv")

CHUNK_SIZE     = 100_000
NORMAL_TARGET  = 700_000
ATTACK_TARGET  = 70_000
NORMAL_EVAL    = 70_000
CONTAMINATION  = 0.15   # proven best value

USECOLS = [
    "Login Timestamp",
    "User ID",
    "IP Address",
    "Country",
    "Device Type",
    "Login Successful",
    "Is Attack IP",
    "Is Account Takeover",
]


# ── Step 1: Sample dataset ─────────────────────────────────────────────────────

def sample_dataset():
    print("=" * 60)
    print("  RBA DATASET SAMPLER")
    print("=" * 60)
    print(f"\n📂 Reading: {DATASET_PATH}")
    print(f"⏳ Streaming dataset...\n")

    normal_chunks = []
    attack_chunks = []
    normal_count  = 0
    attack_count  = 0
    total_read    = 0

    try:
        reader = pd.read_csv(
            DATASET_PATH,
            usecols=USECOLS,
            chunksize=CHUNK_SIZE,
            low_memory=True,
        )
    except FileNotFoundError:
        print(f"❌ Dataset not found: {DATASET_PATH}")
        sys.exit(1)

    for chunk in reader:
        total_read += len(chunk)
        chunk.columns = chunk.columns.str.strip()

        def col_to_bool(col):
            if chunk[col].dtype == bool:
                return chunk[col]
            return chunk[col].astype(str).str.strip().str.lower().isin(
                ["true","1","yes"]
            )

        chunk["is_attack"]     = col_to_bool("Is Attack IP")
        chunk["is_takeover"]   = col_to_bool("Is Account Takeover")
        chunk["is_any_attack"] = chunk["is_attack"] | chunk["is_takeover"]

        if normal_count < NORMAL_TARGET:
            normal = chunk[~chunk["is_any_attack"]].copy()
            needed = NORMAL_TARGET - normal_count
            normal = normal.head(needed)
            normal_chunks.append(normal)
            normal_count += len(normal)

        if attack_count < ATTACK_TARGET:
            attacks = chunk[chunk["is_any_attack"]].copy()
            needed  = ATTACK_TARGET - attack_count
            attacks = attacks.head(needed)
            attack_chunks.append(attacks)
            attack_count += len(attacks)

        print(
            f"   Read {total_read:>8,} | "
            f"Normal: {normal_count:>6,}/{NORMAL_TARGET:,} | "
            f"Attack: {attack_count:>5,}/{ATTACK_TARGET:,}",
            end="\r"
        )

        if normal_count >= NORMAL_TARGET and attack_count >= ATTACK_TARGET:
            break

    print(f"\n\n✅ Sampling complete - {total_read:,} rows read")

    normal_df = pd.concat(normal_chunks, ignore_index=True)
    attack_df = pd.concat(attack_chunks, ignore_index=True) \
        if attack_chunks else pd.DataFrame()

    eval_normal = normal_df.sample(
        n=min(NORMAL_EVAL, len(normal_df)), random_state=42
    )
    eval_df  = pd.concat(
        [eval_normal, attack_df], ignore_index=True
    ).sample(frac=1, random_state=42)
    train_df = normal_df.drop(eval_normal.index).reset_index(drop=True)

    print(f"   Training set: {len(train_df):,} normal rows")
    print(f"   Eval set:     {len(eval_df):,} rows "
          f"({len(attack_df):,} attacks + {len(eval_normal):,} normal)")

    os.makedirs(os.path.dirname(SAMPLE_PATH), exist_ok=True)
    train_df.to_csv(SAMPLE_PATH, index=False)
    eval_df.to_csv(EVAL_PATH,   index=False)

    return train_df, eval_df


# ── Step 2: Parse boolean columns ─────────────────────────────────────────────

def parse_bool_col(series):
    if series.dtype == bool:
        return series
    return series.astype(str).str.strip().str.lower().isin(["true","1","yes"])


# ── Step 3: Feature extraction ────────────────────────────────────────────────

def extract_features(df, ip_enc, user_enc, country_enc, device_enc,
                     known_ips_set=None, known_countries_set=None):
    """
    9-feature extraction - proven 7 features + 2 targeted additions.

    Features:
      [0]  hour_sin       - cyclic hour encoding (sine)
      [1]  hour_cos       - cyclic hour encoding (cosine)
      [2]  is_failed      - 1 if login failed, 0 if success
      [3]  ip_encoded     - LabelEncoder ID for IP (proven effective)
      [4]  user_encoded   - LabelEncoder ID for user
      [5]  failed_rate    - rolling cumulative failure rate per IP
      [6]  country_encoded - LabelEncoder ID for country
      [7]  device_encoded - LabelEncoder ID for device type
      [8]  is_new_ip      - 1 if IP never seen in training data (NEW)
      [9]  is_new_country - 1 if country never seen in training (NEW)

    Changes from best working model:
      - raw hour replaced with hour_sin + hour_cos (fixes 23/0 boundary)
      - is_new_ip added (direct unknown external IP signal)
      - is_new_country added (direct unknown country signal)
      Total: 7 → 9 features (+2 targeted additions)
    """
    df = df.copy().reset_index(drop=True)

    # ── Parse timestamp ────────────────────────────────────────────────────
    dt_parsed = pd.to_datetime(df["Login Timestamp"], errors="coerce")
    hour      = dt_parsed.dt.hour.fillna(12)

    # ── Cyclic hour encoding ───────────────────────────────────────────────
    df["hour_sin"] = np.sin(2 * np.pi * hour / 24)
    df["hour_cos"] = np.cos(2 * np.pi * hour / 24)

    # ── Is failed ─────────────────────────────────────────────────────────
    if "login_success" in df.columns:
        df["is_failed"] = (~df["login_success"].astype(bool)).astype(int)
    else:
        df["is_failed"] = (~parse_bool_col(df["Login Successful"])).astype(int)

    # ── Sort chronologically for rolling failure rate ──────────────────────
    df["_orig_idx"] = df.index
    df = df.sort_values("Login Timestamp").reset_index(drop=True)

    df["fail_cumsum"]  = df.groupby("IP Address")["is_failed"].cumsum()
    df["total_cumsum"] = df.groupby("IP Address").cumcount() + 1
    df["failed_rate"]  = df["fail_cumsum"] / df["total_cumsum"]

    # ── LabelEncoder mappings (same as best working model) ─────────────────
    def encode_col(series, encoder):
        mapping = {cls: idx for idx, cls in enumerate(encoder.classes_)}
        return series.astype(str).str.strip().map(mapping).fillna(-1).astype(int)

    df["ip_enc"]      = encode_col(df["IP Address"],             ip_enc)
    df["user_enc"]    = encode_col(df["User ID"],                user_enc)
    df["country_enc"] = encode_col(df["Country"].fillna("XX"),   country_enc)
    df["device_enc"]  = encode_col(
        df["Device Type"].fillna("Unknown"), device_enc
    )

    # ── NEW: is_new_ip flag ────────────────────────────────────────────────
    # 1 if IP was never seen in training data - strong anomaly signal
    if known_ips_set is not None:
        df["is_new_ip"] = (~df["IP Address"].astype(str)
                            .isin(known_ips_set)).astype(int)
    else:
        # At training time: ip_enc == -1 means unseen
        df["is_new_ip"] = (df["ip_enc"] == -1).astype(int)

   # ── NEW: is_new_country flag ───────────────────────────────────────────
    # Use known_countries_set if provided (inference path)
    # Fall back to country_enc == -1 (training path - same result)
    if known_countries_set is not None:
        df["is_new_country"] = (~df["Country"].fillna("XX").astype(str)
                                .isin(known_countries_set)).astype(int)
    else:
        df["is_new_country"] = (df["country_enc"] == -1).astype(int)

    # ── Restore original order ─────────────────────────────────────────────
    df = df.sort_values("_orig_idx").reset_index(drop=True)

    feature_cols = [
        "hour_sin", "hour_cos",
        "is_failed",
        "ip_enc",
        "user_enc",
        "failed_rate",
        "country_enc",
        "device_enc",
        "is_new_ip",
        "is_new_country",
    ]
    return df[feature_cols].values.astype(float)


# ── Step 4: Train ──────────────────────────────────────────────────────────────

def train_model(train_df):
    print("\n" + "=" * 60)
    print("  TRAINING ISOLATION FOREST")
    print("=" * 60)
    print(f"\n🏋️  Training on {len(train_df):,} normal login events...")

    train_df = train_df.copy()
    train_df["login_success"] = parse_bool_col(train_df["Login Successful"])

    # Fit encoders - identical to best working model
    ip_enc      = LabelEncoder()
    user_enc    = LabelEncoder()
    country_enc = LabelEncoder()
    device_enc  = LabelEncoder()

    ip_enc.fit(train_df["IP Address"].astype(str).str.strip())
    user_enc.fit(train_df["User ID"].astype(str).str.strip())
    country_enc.fit(train_df["Country"].fillna("XX").astype(str).str.strip())
    device_enc.fit(train_df["Device Type"].fillna("Unknown").astype(str).str.strip())

    # Build known sets for is_new_ip and is_new_country
    known_ips_set       = set(train_df["IP Address"].astype(str))
    known_countries_set = set(train_df["Country"].fillna("XX").astype(str))

    print(f"   Known IPs:       {len(ip_enc.classes_):,}")
    print(f"   Known users:     {len(user_enc.classes_):,}")
    print(f"   Known countries: {len(country_enc.classes_)}")
    print(f"   Known devices:   {list(device_enc.classes_)}")

    print("\n⚙️  Extracting features (9-feature improved pipeline)...")
    t0 = datetime.now()
    X  = extract_features(
        train_df, ip_enc, user_enc, country_enc, device_enc,
        known_ips_set=known_ips_set,
        known_countries_set=known_countries_set,
    )
    print(f"   Feature matrix: {X.shape} - done in {(datetime.now()-t0).seconds}s")
    print(f"   Features: hour_sin, hour_cos, is_failed, ip_enc, user_enc,")
    print(f"             failed_rate, country_enc, device_enc,")
    print(f"             is_new_ip, is_new_country")

    print("\n⚙️  Scaling features...")
    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    print(f"   Means:  {scaler.mean_.round(3)}")
    print(f"   Stds:   {scaler.scale_.round(3)}")

    print("\n🌲 Fitting Isolation Forest...")
    t0    = datetime.now()
    model = IsolationForest(
        contamination=CONTAMINATION,
        n_estimators=200,          # proven value
        random_state=42,
        n_jobs=-1,
        max_samples=100000,          # proven value
        max_features=1.0,          # use all features - no subsampling
    )
    model.fit(X_scaled)
    print(f"✅ Model fitted in {(datetime.now()-t0).seconds}s")

    return model, ip_enc, user_enc, country_enc, device_enc, scaler, \
           known_ips_set, known_countries_set


# ── Step 5: Evaluate ───────────────────────────────────────────────────────────

def evaluate(model, eval_df, ip_enc, user_enc, country_enc, device_enc,
             scaler, known_ips_set, known_countries_set):
    print("\n" + "=" * 60)
    print("  EVALUATION")
    print("=" * 60)
    print(f"\n📊 Evaluating on {len(eval_df):,} events...")

    eval_df = eval_df.copy()
    eval_df["login_success"] = parse_bool_col(eval_df["Login Successful"])
    eval_df["is_any_attack"] = (
        parse_bool_col(eval_df["Is Attack IP"]) |
        parse_bool_col(eval_df["Is Account Takeover"])
    )

    print("⚙️  Extracting eval features...")
    t0     = datetime.now()
    X_eval = extract_features(
        eval_df, ip_enc, user_enc, country_enc, device_enc,
        known_ips_set=known_ips_set,
        known_countries_set=known_countries_set,
    )
    X_eval = scaler.transform(X_eval)
    print(f"   Done in {(datetime.now()-t0).seconds}s")

    preds       = model.predict(X_eval)
    scores      = model.decision_function(X_eval)
    true_attack = eval_df["is_any_attack"].values.astype(int)
    pred_attack = (preds == -1).astype(int)

    TP = int(((pred_attack == 1) & (true_attack == 1)).sum())
    FP = int(((pred_attack == 1) & (true_attack == 0)).sum())
    TN = int(((pred_attack == 0) & (true_attack == 0)).sum())
    FN = int(((pred_attack == 0) & (true_attack == 1)).sum())

    precision = TP / (TP + FP) if (TP + FP) > 0 else 0
    recall    = TP / (TP + FN) if (TP + FN) > 0 else 0
    f1        = 2 * precision * recall / (precision + recall) \
                if (precision + recall) > 0 else 0
    accuracy  = (TP + TN) / len(true_attack)

    # ROC-AUC and PR-AUC
    anomaly_scores = -scores  # negate: higher = more anomalous
    try:
        roc_auc = roc_auc_score(true_attack, anomaly_scores)
        pr_auc  = average_precision_score(true_attack, anomaly_scores)
    except Exception:
        roc_auc = 0.0
        pr_auc  = 0.0

    print(f"\n   ┌─────────────────┬──────────────┬──────────────┐")
    print(f"   │                 │ Pred Normal  │ Pred Attack  │")
    print(f"   ├─────────────────┼──────────────┼──────────────┤")
    print(f"   │ Actual Normal   │ TN: {TN:>6,}  │ FP: {FP:>6,}  │")
    print(f"   │ Actual Attack   │ FN: {FN:>6,}  │ TP: {TP:>6,}  │")
    print(f"   └─────────────────┴──────────────┴──────────────┘")
    print(f"\n   Precision: {precision:.1%}")
    print(f"   Recall:    {recall:.1%}")
    print(f"   F1-Score:  {f1:.1%}")
    print(f"   Accuracy:  {accuracy:.1%}")
    print(f"   ROC-AUC:   {roc_auc:.3f}")
    print(f"   PR-AUC:    {pr_auc:.3f}")

    return {
        "precision": round(precision, 4),
        "recall":    round(recall, 4),
        "f1":        round(f1, 4),
        "accuracy":  round(accuracy, 4),
        "roc_auc":   round(roc_auc, 4),
        "pr_auc":    round(pr_auc, 4),
        "TP": TP, "FP": FP, "TN": TN, "FN": FN,
        "test_size":    len(true_attack),
        "attack_count": int(true_attack.sum()),
    }


# ── Step 6: Save ───────────────────────────────────────────────────────────────

def save_model(model, ip_enc, user_enc, country_enc, device_enc,
               scaler, known_ips_set, known_countries_set, metrics):
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)

    payload = {
        "model":           model,
        "scaler":          scaler,
        "ip_encoder":      ip_enc,
        "user_encoder":    user_enc,
        "country_encoder": country_enc,
        "device_encoder":  device_enc,
        "known_ips":       list(ip_enc.classes_),
        "known_users":     list(user_enc.classes_),
        "known_countries": list(country_enc.classes_),
        "known_devices":   list(device_enc.classes_),
        # NEW: sets for is_new_ip and is_new_country at inference
        "known_ips_set":       known_ips_set,
        "known_countries_set": known_countries_set,
        "contamination":   CONTAMINATION,
        "feature_count":   10,
        "feature_names": [
            "hour_sin","hour_cos",
            "is_failed","ip_enc","user_enc",
            "failed_rate","country_enc","device_enc",
            "is_new_ip","is_new_country",
        ],
        "trained_on":    "RBA Dataset (Kaggle) - real enterprise login events",
        "training_size": "630,000 normal login events",
        "metrics":       metrics,
        "trained_at":    datetime.now().isoformat(),
    }

    joblib.dump(payload, MODEL_PATH)
    print(f"\n💾 Model saved → {MODEL_PATH}")

    metrics_path = os.path.join(os.path.dirname(MODEL_PATH), "model_metrics.json")
    with open(metrics_path, "w") as f:
        json.dump({
            **metrics,
            "trained_on":    payload["trained_on"],
            "training_size": payload["training_size"],
            "trained_at":    payload["trained_at"],
            "feature_count": payload["feature_count"],
        }, f, indent=2)
    print(f"📊 Metrics saved → {metrics_path}")


# ── Main ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n🚀 Starting targeted improvement training pipeline...\n")
    start = datetime.now()

    train_df, eval_df = sample_dataset()

    (model, ip_enc, user_enc, country_enc, device_enc,
     scaler, known_ips_set, known_countries_set) = train_model(train_df)

    metrics = evaluate(
        model, eval_df,
        ip_enc, user_enc, country_enc, device_enc,
        scaler, known_ips_set, known_countries_set
    )

    save_model(
        model, ip_enc, user_enc, country_enc, device_enc,
        scaler, known_ips_set, known_countries_set, metrics
    )

    elapsed = (datetime.now() - start).seconds
    print(f"\n✅ Complete in {elapsed}s")
    print(f"\n   Precision: {metrics['precision']:.1%}")
    print(f"   Recall:    {metrics['recall']:.1%}")
    print(f"   F1-Score:  {metrics['f1']:.1%}")
    print(f"   ROC-AUC:   {metrics.get('roc_auc', 0):.3f}")
    print(f"\n   Run: python main.py\n")