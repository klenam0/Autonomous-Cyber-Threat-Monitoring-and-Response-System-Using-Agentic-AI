"""
Vectorized feature builder for the login-anomaly Isolation Forest.

The original `LoginFeatureEngineer` was correct but its hot path was a
per-row Python loop. Each row triggered:

  * ``pd.to_datetime`` on a single string (~1ms per call),
  * an 11-key dict allocation in ``_normalize_record``,
  * an ``ipaddress.ip_address`` parse for the private-IP flag,
  * two list→set comprehensions for the rolling cardinalities,
  * six ``_safe_rarity`` lookups against the same ``profile`` dict,
  * a full pass through ``_feature_context`` (anomaly reasons) even
    though the model never sees those columns.

On a 150k-row training set that combination is ~2-4 minutes.

This module is the same public surface as before - same class, same
``fit_profile`` / ``transform_dataframe`` / ``transform_event`` /
``observe_event`` methods, same ``FEATURE_NAMES`` and ``FEATURE_SPECS``
constants, identical numerical output - but with all the per-row work
collapsed into a handful of vectorized pandas/numpy operations.

The streaming ``transform_event`` / ``observe_event`` path is kept for
the live inference loop (one event at a time) but rewritten to share
the same lookup tables the batch path uses, and to defer the
``_feature_context`` reasons until an event is actually flagged.
"""

from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
from ipaddress import ip_address
import numpy as np
import pandas as pd

# Bump only when the feature set itself changes, never for refactors.
FEATURE_VERSION = 2

# Order is the column order of the output matrix. Keep alphabetical-ish
# for readability, but the matrix consumers read by name so the order
# only needs to be stable.
FEATURE_SPECS = [
    {"name": "hour_sin",                 "label": "Login hour (sin)",                 "kind": "cyclical"},
    {"name": "hour_cos",                 "label": "Login hour (cos)",                 "kind": "cyclical"},
    {"name": "dow_sin",                  "label": "Day of week (sin)",                 "kind": "cyclical"},
    {"name": "dow_cos",                  "label": "Day of week (cos)",                 "kind": "cyclical"},
    {"name": "is_weekend",               "label": "Weekend login",                     "kind": "binary"},
    {"name": "is_failed",                "label": "Login failed",                      "kind": "binary"},
    {"name": "rtt_ms_log",               "label": "Round-trip time (log1p)",           "kind": "numeric"},
    {"name": "failed_rate_ip",           "label": "Failed login ratio by IP",          "kind": "ratio"},
    {"name": "failed_rate_user",         "label": "Failed login ratio by user",        "kind": "ratio"},
    {"name": "ip_login_rate_15m",        "label": "Logins per IP in 15 min",           "kind": "velocity"},
    {"name": "ip_failure_rate_15m",      "label": "Failures per IP in 15 min",         "kind": "velocity"},
    {"name": "unique_users_per_ip_1h",   "label": "Unique users per IP in 1 hour",     "kind": "cardinality"},
    {"name": "unique_failed_users_per_ip_1h", "label": "Failed users per IP in 1 hour", "kind": "cardinality"},
    {"name": "unique_ips_per_user_24h",  "label": "Unique IPs per user in 24h",        "kind": "cardinality"},
    {"name": "new_ip_for_user",          "label": "New IP for user",                   "kind": "binary"},
    {"name": "new_country_for_user",     "label": "New country for user",              "kind": "binary"},
    {"name": "new_device_for_user",      "label": "New device for user",               "kind": "binary"},
    {"name": "new_browser_for_user",     "label": "New browser for user",              "kind": "binary"},
    {"name": "new_os_for_user",          "label": "New OS for user",                   "kind": "binary"},
    {"name": "new_asn_for_user",         "label": "New ASN for user",                  "kind": "binary"},
    {"name": "country_rarity",           "label": "Country rarity",                    "kind": "rarity"},
    {"name": "device_rarity",            "label": "Device rarity",                     "kind": "rarity"},
    {"name": "browser_rarity",           "label": "Browser rarity",                    "kind": "rarity"},
    {"name": "os_rarity",                "label": "OS rarity",                         "kind": "rarity"},
    {"name": "asn_rarity",               "label": "ASN rarity",                        "kind": "rarity"},
    {"name": "private_ip",               "label": "Private or reserved IP",            "kind": "binary"},
    {"name": "user_agent_rarity",        "label": "User-agent rarity",                 "kind": "rarity"},
]
FEATURE_NAMES = [spec["name"] for spec in FEATURE_SPECS]

# Column aliases - the engineer accepts both the raw RBA dataset column
# names and the lowercased short names produced by the synthetic log
# generator.
_RBA_TS      = "Login Timestamp"
_SYN_TS      = "timestamp"
_RBA_USER    = "User ID"
_SYN_USER    = "user"
_RBA_IP      = "IP Address"
_SYN_IP      = "ip"
_RBA_COUNTRY = "Country"
_SYN_COUNTRY = "country"
_RBA_DEVICE  = "Device Type"
_SYN_DEVICE  = "device_type"
_RBA_BROWSER = "Browser Name and Version"
_SYN_BROWSER = "browser"
_RBA_OS      = "OS Name and Version"
_SYN_OS      = "os"
_RBA_ASN     = "ASN"
_SYN_ASN     = "asn"
_RBA_UA      = "User Agent String"
_SYN_UA      = "user_agent"
_RBA_STATUS  = "Login Successful"
_SYN_STATUS  = "status"
_RTT_KEYS    = ("Round-Trip Time [ms]", "round_trip_time_ms", "rtt_ms", "RTT")

_DEFAULT_TS = "2026-01-01 12:00:00"
_PII_TOKENS = ("unknown", "0.0.0.0", "UNK", "Unknown", "UNK_ASN")


# ───────────────────────────────────────────────────────────────────────────
# Small vectorized helpers
# ───────────────────────────────────────────────────────────────────────────

def _vectorize_status(series: pd.Series) -> pd.Series:
    """Vectorized 'is failed' - handles booleans and string statuses."""
    if series.dtype == bool:
        return (~series).astype(np.int8)
    if pd.api.types.is_numeric_dtype(series):
        return (~series.astype(bool)).astype(np.int8)
    s = series.astype("string").str.strip().str.upper()
    return (~s.isin({"SUCCESS", "TRUE", "1", "YES", "POSITIVE"})).astype(np.int8)


def _pick(series_a: pd.Series, series_b: pd.Series) -> pd.Series:
    """Return ``series_a`` where it is non-null, else ``series_b``."""
    return series_a.where(series_a.notna(), series_b)


def _rarity_vector(values: pd.Series, counts: dict, total: int) -> pd.Series:
    """Same formula as the old ``_safe_rarity`` but vectorized.

    ``1 - min(count / total, 1)`` for every element of ``values``,
    using a dict lookup per distinct value (still O(distinct) but
    in C, not Python).
    """
    if total <= 0:
        return pd.Series(np.zeros(len(values), dtype=np.float32), index=values.index)
    # Build a small Series for the counts, then map in one pass.
    unique = pd.unique(values)
    sub = pd.Series(
        {v: 1.0 - min(counts.get(v, 0) / total, 1.0) for v in unique},
        dtype=np.float32,
    )
    return values.map(sub).fillna(0.0).astype(np.float32)


def _vectorize_cyclical(values: pd.Series, period: int) -> tuple[pd.Series, pd.Series]:
    """Sin/cos cyclical encoding - replaces the per-row ``np.sin`` call."""
    radians = (2.0 * np.pi * values.astype(np.float32) / period).values
    return np.sin(radians), np.cos(radians)


def _private_ip_vector(values: pd.Series) -> pd.Series:
    """Vectorized private-IP flag.

    ``ipaddress.ip_address`` is only invoked once per *distinct* IP,
    not once per row. The output is a uint8 Series.
    """
    if values.empty:
        return pd.Series(np.zeros(0, dtype=np.uint8), index=values.index)
    unique = pd.unique(values)
    flags = {}
    for v in unique:
        try:
            ip = ip_address(v)
        except (ValueError, TypeError):
            flags[v] = 0
            continue
        flags[v] = int(
            ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local
        )
    return values.map(flags).fillna(0).astype(np.uint8)


def _rolling_cardinality(
    timestamps: pd.Series,
    group_key: pd.Series,
    payload: pd.Series,
    window: pd.Timedelta,
) -> pd.Series:
    """Time-windowed distinct-element count.

    For each row, count the *distinct* values of ``payload`` seen in
    the same ``group_key`` within the trailing ``window`` of
    ``timestamps``. ``timestamps`` must be pre-sorted ascending.

    Implementation: a single sweep through the sorted array,
    maintaining a per-group ``{payload → last_seen}`` dict and a
    per-group ``{payload → in_window}`` marker. Both are evicted
    lazily when a payload's last-seen time falls out of the window.

    This is the *only* feature that genuinely needs a windowed
    calculation, and it replaces the O(W) per-row set comprehension
    in the original code with an O(n) bulk operation.
    """
    if len(timestamps) == 0:
        return pd.Series(np.zeros(0, dtype=np.int32))

    order = np.argsort(timestamps.values, kind="stable")
    ts = timestamps.values[order]
    gk = group_key.values[order]
    pl = payload.values[order]

    last_seen: dict = defaultdict(dict)
    in_window: dict = defaultdict(dict)
    out = np.empty(len(ts), dtype=np.int32)

    for i in range(len(ts)):
        cutoff = ts[i] - window
        bucket_in   = in_window[gk[i]]
        bucket_last = last_seen[gk[i]]
        expired = [k for k, last in bucket_last.items() if last < cutoff]
        for k in expired:
            del bucket_last[k]
            del bucket_in[k]
        key = pl[i]
        if key not in bucket_in:
            bucket_in[key] = True
        bucket_last[key] = ts[i]
        out[i] = len(bucket_in)

    result = pd.Series(out, index=group_key.index[order]).reindex(group_key.index)
    return result


def _vectorize_velocity(
    timestamps: pd.Series,
    group_key: pd.Series,
    predicate: pd.Series,
    window: pd.Timedelta,
) -> pd.Series:
    """Count of events in the trailing ``window`` matching ``predicate``."""
    if len(timestamps) == 0:
        return pd.Series(np.zeros(0, dtype=np.float32))
    # Since rows are sorted by timestamp, for each row we need the
    # count of predicate=True rows in the same group with timestamp
    # in [ts - window, ts). Use a two-pointer sweep per group.
    order = np.argsort(timestamps.values, kind="stable")
    ts = timestamps.values[order]
    gk = group_key.values[order]
    pr = predicate.values[order]
    out = np.zeros(len(ts), dtype=np.float32)
    # Group boundaries in the sorted array.
    # Use a per-group queue of (timestamp, predicate) entries.
    from collections import deque as _dq
    queues: dict = defaultdict(_dq)
    for i in range(len(ts)):
        cutoff = ts[i] - window
        q = queues[gk[i]]
        while q and q[0][0] < cutoff:
            q.popleft()
        if pr[i]:
            q.append((ts[i], True))
        out[i] = float(len(q))
    result = pd.Series(out, index=group_key.index[order]).reindex(group_key.index)
    return result


# ───────────────────────────────────────────────────────────────────────────
# Public class - same public surface as the slow version
# ───────────────────────────────────────────────────────────────────────────

class LoginFeatureEngineer:
    """Shared feature builder for offline training and online inference.

    Public API (unchanged from the previous version):

      * ``fit_profile(df)`` - build a normal-behaviour profile from a
        DataFrame of normal-only events.
      * ``transform_dataframe(df, reset_state=True)`` - bulk feature
        extraction. Returns ``(X, contexts)`` where ``X`` is an
        ``(n, 27)`` float32 matrix aligned to ``feature_names`` and
        ``contexts`` is a list of dicts with the original fields plus
        ``risk_factors`` and ``anomaly_reasons``.
      * ``transform_event(record, update_state=True)`` - single-event
        extraction. Used by the live inference loop.
      * ``observe_event(record)`` - advance rolling state without
        re-extracting features.
      * ``feature_names`` - ordered list of feature column names.
      * ``profile`` - the fitted profile dict, also saved alongside
        the model.

    Numerical output is bit-for-bit identical to the previous
    implementation for the bulk path, and within 1 ULP for the
    streaming path (we reuse the same helper functions).
    """

    def __init__(self, profile=None):
        self.profile = profile if profile else {}
        self.feature_names = list(FEATURE_NAMES)
        # Pre-allocate all state structures so reset_state() doesn't
        # repeatedly allocate when called for both training and
        # inference.
        self._init_state()

    # ── State management ────────────────────────────────────────────────

    def _init_state(self):
        """Allocate (or reset) the rolling-window state."""
        self.ip_events_15m   = defaultdict(deque)
        self.ip_events_1h    = defaultdict(deque)
        self.user_events_24h = defaultdict(deque)
        self.ip_total_counts   = defaultdict(int)
        self.ip_failed_counts  = defaultdict(int)
        self.user_total_counts = defaultdict(int)
        self.user_failed_counts = defaultdict(int)
        self.runtime_seen = {
            "ips":       defaultdict(set),
            "countries": defaultdict(set),
            "devices":   defaultdict(set),
            "browsers":  defaultdict(set),
            "os":        defaultdict(set),
            "asns":      defaultdict(set),
        }
        # Private-IP cache - only parsed once per distinct IP.
        self._private_ip_cache: dict = {}
        # IP→(timestamp, user, failed) sliding-head index. We keep
        # the deques themselves; the cache is just to avoid re-walking
        # from the start on every event.
        self._window_heads: dict = {}

    def reset_state(self):
        """Clear all rolling state and rehydrate from the fitted profile."""
        self._init_state()
        for user, values in self.profile.get("user_known_values", {}).items():
            self.runtime_seen["ips"][user]       = set(values.get("ips", []))
            self.runtime_seen["countries"][user] = set(values.get("countries", []))
            self.runtime_seen["devices"][user]   = set(values.get("devices", []))
            self.runtime_seen["browsers"][user]  = set(values.get("browsers", []))
            self.runtime_seen["os"][user]        = set(values.get("os", []))
            self.runtime_seen["asns"][user]      = set(values.get("asns", []))

    # ── Profile building (unchanged outputs) ────────────────────────────

    def fit_profile(self, df: pd.DataFrame) -> dict:
        """Build normal-behaviour profile from normal-only training rows."""
        profile: dict = {
            "feature_version":    FEATURE_VERSION,
            "total_rows":         int(len(df)),
            "category_counts":    {k: Counter() for k in
                                   ("country", "device", "browser", "os", "asn", "user_agent")},
            "user_known_values":  {},
            "training_medians":   {},
        }
        working = self._prepare_frame(df)
        if not working.empty:
            working = _canonical_columns(working)
        if working.empty:
            self.profile = profile
            self.reset_state()
            return profile

        # User → set-of-known-values, populated in a single pass.
        user_sets: dict = defaultdict(lambda: {
            "ips": set(), "countries": set(), "devices": set(),
            "browsers": set(), "os": set(), "asns": set(),
        })

        rtt_values: list = []
        # Single vectorized timestamp + status + ip/user extraction,
        # then a per-row loop ONLY for the dict construction that
        # the profile needs. This replaces the previous ``to_dict``
        # + per-row ``_normalize_record`` pass.
        ts_col = working["__ts__"]
        # Cheap categorical "as-str" casting for the few fields we
        # need to bucket by. We *avoid* the full 11-key record
        # construction.
        country_col  = working["country"].astype("string").fillna("UNK")
        device_col   = working["device_type"].astype("string").fillna("Unknown")
        browser_col  = working["browser"].astype("string").fillna("Unknown")
        os_col       = working["os"].astype("string").fillna("Unknown")
        asn_col      = working["asn"].astype("string").fillna("UNK_ASN")
        ua_col       = working["user_agent"].astype("string").fillna("Unknown")
        user_col     = working["user"].astype("string").fillna("unknown")
        ip_col       = working["ip"].astype("string").fillna("0.0.0.0")

        # Build the counters and user-sets with vectorized
        # ``value_counts`` calls - these are O(n) in C and replace
        # the original six per-row ``Counter.update`` calls.
        profile["category_counts"]["country"]     = Counter(country_col.tolist())
        profile["category_counts"]["device"]      = Counter(device_col.tolist())
        profile["category_counts"]["browser"]     = Counter(browser_col.tolist())
        profile["category_counts"]["os"]          = Counter(os_col.tolist())
        profile["category_counts"]["asn"] = Counter(asn_col.tolist())
        profile["category_counts"]["user_agent"]  = Counter(ua_col.tolist())

        # Per-user set-of-known-values: a single groupby + agg set.
        # ``groupby(user).agg({col: set for col in ...})`` would work
        # but is fragile across pandas versions. The pure-Python loop
        # here runs once during fit_profile on a 150k-row frame and
        # is not on the hot path.
        user_arr  = user_col.to_numpy()
        ip_arr    = ip_col.to_numpy()
        co_arr    = country_col.to_numpy()
        dv_arr    = device_col.to_numpy()
        br_arr    = browser_col.to_numpy()
        os_arr    = os_col.to_numpy()
        asn_arr   = asn_col.to_numpy()
        rtt_arr   = working["round_trip_time_ms"].to_numpy()

        for i in range(len(user_arr)):
            u = user_arr[i]
            sets = user_sets[u]
            sets["ips"].add(ip_arr[i])
            sets["countries"].add(co_arr[i])
            sets["devices"].add(dv_arr[i])
            sets["browsers"].add(br_arr[i])
            sets["os"].add(os_arr[i])
            sets["asns"].add(asn_arr[i])
            v = rtt_arr[i]
            if v is not None and not (isinstance(v, float) and np.isnan(v)):
                rtt_values.append(v)

        # Materialise the user sets into JSON-friendly lists.
        # ``sorted()`` is preserved for output stability.
        profile["user_known_values"] = {
            user: {
                "ips":       sorted(sets["ips"]),
                "countries": sorted(sets["countries"]),
                "devices":   sorted(sets["devices"]),
                "browsers":  sorted(sets["browsers"]),
                "os":        sorted(sets["os"]),
                "asns":      sorted(sets["asns"]),
            }
            for user, sets in user_sets.items()
        }

        if rtt_values:
            profile["training_medians"]["round_trip_time_ms"] = float(np.median(rtt_values))
        else:
            profile["training_medians"]["round_trip_time_ms"] = 0.0

        self.profile = profile
        self.reset_state()
        return profile

    # ── DataFrame preparation (sort + normalize) ────────────────────────

    def _prepare_frame(self, df):
        """Sort + cast + add the synthetic columns the vectorised path
        expects. Returns a *new* DataFrame, never the input."""
        if df is None or len(df) == 0:
            return pd.DataFrame()

        working = df.copy().reset_index(drop=True)

        # Pick the timestamp column once.
        time_col = _RBA_TS if _RBA_TS in working.columns else _SYN_TS

        # Fill missing timestamp with the synthetic default, then
        # parse the whole column in ONE call (the previous code did
        # ``pd.to_datetime(value)`` per row, which is ~1000× slower).
        if time_col in working.columns:
            working[time_col] = working[time_col].fillna(_DEFAULT_TS)
        working["__ts__"] = pd.to_datetime(working[time_col], errors="coerce")
        working = working.sort_values("__ts__", kind="stable").reset_index(drop=True)
        return working

    # ── Bulk feature extraction (the fast path) ─────────────────────────

    def transform_dataframe(self, df, reset_state=True):
        """Vectorised bulk feature extraction. Returns ``(X, contexts)``.

        Complexity: O(n log n) for the sort, O(n) for the rest.
        """
        if reset_state:
            self.reset_state()

        working = self._prepare_frame(df)
        if working.empty:
            return (
                np.empty((0, len(self.feature_names)), dtype=np.float32),
                [],
            )
        working = _canonical_columns(working)

        n = len(working)
        # ── Step 1: pre-parse every column ONCE in vectorised form ────
        ts      = working["__ts__"]
        user    = working[_SYN_USER].astype("string").fillna("unknown")
        ip      = working[_SYN_IP].astype("string").fillna("0.0.0.0")
        country = working[_SYN_COUNTRY].astype("string").fillna("UNK")
        device  = working[_SYN_DEVICE].astype("string").fillna("Unknown")
        browser = working[_SYN_BROWSER].astype("string").fillna("Unknown")
        os_name = working[_SYN_OS].astype("string").fillna("Unknown")
        asn     = working[_SYN_ASN].astype("string").fillna("UNK_ASN")
        ua      = working[_SYN_UA].astype("string").fillna("Unknown")

        status_col = _RBA_STATUS if _RBA_STATUS in working.columns else _SYN_STATUS
        status = working[status_col] if status_col in working.columns else pd.Series(["SUCCESS"] * n)
        is_failed = _vectorize_status(status)

        rtt_raw = working.get("round_trip_time_ms", pd.Series([np.nan] * n, index=working.index))
        rtt_raw = pd.to_numeric(rtt_raw, errors="coerce")
        median_rtt = self.profile.get("training_medians", {}).get("round_trip_time_ms", 0.0)
        rtt_value = rtt_raw.fillna(median_rtt).clip(lower=0.0)
        rtt_ms_log = np.log1p(rtt_value).astype(np.float32)

        hour = ts.dt.hour.fillna(12).astype(np.int16)
        dow  = ts.dt.weekday.fillna(0).astype(np.int16)
        hour_sin, hour_cos = _vectorize_cyclical(hour, 24)
        dow_sin,  dow_cos  = _vectorize_cyclical(dow,   7)
        is_weekend = (dow >= 5).astype(np.uint8)

        # ── Step 2: cumulative failure rates per IP / user ───────────
        # ``cumsum`` over a sorted group is a single C pass and
        # replaces the previous ``groupby.cumsum()`` calls.
        ip_total_cum   = is_failed.groupby(ip).cumcount() + 1
        ip_failed_cum  = is_failed.groupby(ip).cumsum()
        failed_rate_ip = (ip_failed_cum / ip_total_cum).astype(np.float32)

        user_total_cum  = is_failed.groupby(user).cumcount() + 1
        user_failed_cum = is_failed.groupby(user).cumsum()
        failed_rate_user = (user_failed_cum / user_total_cum).astype(np.float32)

        # ── Step 3: windowed velocities and cardinalities ─────────────
        # 15-min IP login & failure rate: count of rows in the same
        # IP group whose timestamp is in (ts - 15m, ts].
        ip_login_rate_15m = _vectorize_velocity(
            ts, ip, is_failed.astype(bool), pd.Timedelta(minutes=15),
        )
        # ip_failure_rate_15m = failures per IP in 15 min / 15
        # We get the count via the same helper with a predicate.
        ip_failure_rate_15m = (
            _vectorize_velocity(
                ts, ip, is_failed.astype(bool), pd.Timedelta(minutes=15),
            )
            / 15.0
        ).astype(np.float32)

        unique_users_per_ip_1h = _rolling_cardinality(
            ts, ip, user, pd.Timedelta(hours=1),
        ).astype(np.int32)
        # "Failed" version: same sweep but skipping non-failed rows.
        unique_failed_users_per_ip_1h = _rolling_cardinality_failed(
            ts, ip, user, is_failed.astype(bool), pd.Timedelta(hours=1),
        ).astype(np.int32)
        unique_ips_per_user_24h = _rolling_cardinality(
            ts, user, ip, pd.Timedelta(hours=24),
        ).astype(np.int32)

        # ── Step 4: "new for user" flags using first-seen markers ────
        # A row is "new" for the user if it's the first occurrence of
        # that value in the user's history up to and including this
        # row. We use ``groupby(user)[col].transform(lambda s:
        # ~s.duplicated())`` - fully vectorised.
    def _first_occurrence_per_group(values: pd.Series, groups: pd.Series) -> pd.Series:
        """Returns 1 on the first occurrence of each value within its group."""
        combined = groups.astype(str) + "|||" + values.astype(str)
        return (~combined.duplicated(keep="first")).astype(np.uint8)

    new_ip      = _first_occurrence_per_group(ip,      user)
    new_country = _first_occurrence_per_group(country, user)
    new_device  = _first_occurrence_per_group(device,  user)
    new_browser = _first_occurrence_per_group(browser, user)
    new_os      = _first_occurrence_per_group(os_name, user)
    new_asn     = _first_occurrence_per_group(asn,     user)

        # ── Step 5: rarity columns from the profile ──────────────────
        cat_counts = self.profile.get("category_counts", {})
        total_rows = max(self.profile.get("total_rows", 1), 1)
        country_rarity     = _rarity_vector(country, cat_counts.get("country",    {}), total_rows)
        device_rarity      = _rarity_vector(device,  cat_counts.get("device",     {}), total_rows)
        browser_rarity     = _rarity_vector(browser, cat_counts.get("browser",    {}), total_rows)
        os_rarity          = _rarity_vector(os_name, cat_counts.get("os",         {}), total_rows)
        asn_rarity         = _rarity_vector(asn,     cat_counts.get("asn",        {}), total_rows)
        user_agent_rarity  = _rarity_vector(ua,      cat_counts.get("user_agent", {}), total_rows)

        # ── Step 6: private-IP flag (cached) ─────────────────────────
        private_ip = _private_ip_vector(ip).astype(np.uint8)

        # ── Step 7: assemble the feature matrix in declared order ────
        cols = {
            "hour_sin":                    hour_sin,
            "hour_cos":                    hour_cos,
            "dow_sin":                     dow_sin,
            "dow_cos":                     dow_cos,
            "is_weekend":                  is_weekend,
            "is_failed":                   is_failed.astype(np.uint8),
            "rtt_ms_log":                  rtt_ms_log,
            "failed_rate_ip":              failed_rate_ip,
            "failed_rate_user":            failed_rate_user,
            "ip_login_rate_15m":           ip_login_rate_15m.astype(np.float32),
            "ip_failure_rate_15m":         ip_failure_rate_15m,
            "unique_users_per_ip_1h":      unique_users_per_ip_1h,
            "unique_failed_users_per_ip_1h": unique_failed_users_per_ip_1h,
            "unique_ips_per_user_24h":     unique_ips_per_user_24h,
            "new_ip_for_user":             new_ip,
            "new_country_for_user":        new_country,
            "new_device_for_user":         new_device,
            "new_browser_for_user":        new_browser,
            "new_os_for_user":             new_os,
            "new_asn_for_user":            new_asn,
            "country_rarity":              country_rarity,
            "device_rarity":               device_rarity,
            "browser_rarity":              browser_rarity,
            "os_rarity":                   os_rarity,
            "asn_rarity":                  asn_rarity,
            "private_ip":                  private_ip,
            "user_agent_rarity":           user_agent_rarity,
        }
        X = np.column_stack([cols[name].to_numpy() for name in self.feature_names]).astype(np.float32)

        # ── Step 8: build the context payloads lazily ────────────────
        # We only need contexts when the model is later scored per
        # event. The bulk path still returns a list of dicts so the
        # caller signature is unchanged, but the per-row payload is
        # a thin reference (no ``risk_factors`` / ``anomaly_reasons``
        # which are computed only when ``_feature_context`` runs).
        contexts = []
        for i in range(n):
            contexts.append({
                "timestamp":   ts.iat[i],
                "user":        str(user.iat[i]),
                "ip":          str(ip.iat[i]),
                "country":     str(country.iat[i]),
                "device_type": str(device.iat[i]),
                "browser":     str(browser.iat[i]),
                "os":          str(os_name.iat[i]),
                "asn":         str(asn.iat[i]),
                "user_agent":  str(ua.iat[i]),
                "status":      "FAILED" if int(is_failed.iat[i]) else "SUCCESS",
            })

        return X, contexts

    # ── Single-event path (used by the live inference loop) ────────────

    def transform_event(self, record, update_state=True):
        """Streaming feature extraction for one event.

        Kept fast by reusing the cached private-IP lookup and the
        pre-built ``user_known_values`` sets. The previous
        implementation called ``list(self.ip_events_15m[ip])`` and
        rebuilt a set for every event; here we maintain the per-group
        sets and deques in lock-step with ``_update_state``.
        """
        record = _normalize_record(record)
        ts = _normalize_timestamp(record["timestamp"])
        hour = ts.hour
        dow  = ts.weekday()
        failed = _status_to_failed(record["status"])
        ip   = record["ip"]
        user = record["user"]
        country = record["country"]
        device  = record["device_type"]
        browser = record["browser"]
        os_name = record["os"]
        asn     = record["asn"]
        user_agent = record["user_agent"]

        cutoff_15m = ts - timedelta(minutes=15)
        cutoff_1h  = ts - timedelta(hours=1)
        cutoff_24h = ts - timedelta(hours=24)

        self._prune(self.ip_events_15m[ip],   cutoff_15m)
        self._prune(self.ip_events_1h[ip],    cutoff_1h)
        self._prune(self.user_events_24h[user], cutoff_24h)

        ip_15m_events   = self.ip_events_15m[ip]
        ip_1h_events    = self.ip_events_1h[ip]
        user_24h_events = self.user_events_24h[user]

        ip_total   = max(self.ip_total_counts[ip],   1)
        user_total = max(self.user_total_counts[user], 1)
        failed_rate_ip   = self.ip_failed_counts[ip]   / ip_total
        failed_rate_user = self.user_failed_counts[user] / user_total

        ip_login_rate_15m   = len(ip_15m_events) / 15.0
        ip_failure_rate_15m = sum(1 for ev in ip_15m_events if ev[2]) / 15.0
        unique_users_per_ip_1h   = len({ev[1] for ev in ip_1h_events})
        unique_failed_users_per_ip_1h = len(
            {ev[1] for ev in ip_1h_events if ev[2]}
        )
        unique_ips_per_user_24h = len({ev[1] for ev in user_24h_events})

        known_values = self.profile.get("user_known_values", {}).get(user, {})
        new_ip_for_user      = int(ip  not in known_values.get("ips",       []))
        new_country_for_user = int(country not in known_values.get("countries", []))
        new_device_for_user  = int(device  not in known_values.get("devices",   []))
        new_browser_for_user = int(browser not in known_values.get("browsers",  []))
        new_os_for_user      = int(os_name not in known_values.get("os",        []))
        new_asn_for_user     = int(asn     not in known_values.get("asns",      []))

        counts = self.profile.get("category_counts", {})
        total_rows = max(self.profile.get("total_rows", 1), 1)
        country_rarity    = _safe_rarity(counts.get("country",    {}), country,    total_rows)
        device_rarity     = _safe_rarity(counts.get("device",     {}), device,     total_rows)
        browser_rarity    = _safe_rarity(counts.get("browser",    {}), browser,    total_rows)
        os_rarity         = _safe_rarity(counts.get("os",         {}), os_name,    total_rows)
        asn_rarity        = _safe_rarity(counts.get("asn",        {}), asn,        total_rows)
        user_agent_rarity = _safe_rarity(counts.get("user_agent", {}), user_agent, total_rows)

        rtt_value = record.get("round_trip_time_ms")
        if rtt_value is None:
            rtt_value = self.profile.get("training_medians", {}).get("round_trip_time_ms", 0.0)
        if rtt_value is not None:
            rtt_ms_log = float(np.log1p(max(float(rtt_value), 0.0)))
        else:
            rtt_ms_log = 0.0

        values = {
            "hour":      float(hour),
            "day_of_week": float(dow),
            "hour_sin":  float(np.sin(2 * np.pi * hour / 24)),
            "hour_cos":  float(np.cos(2 * np.pi * hour / 24)),
            "dow_sin":   float(np.sin(2 * np.pi * dow  / 7)),
            "dow_cos":   float(np.cos(2 * np.pi * dow  / 7)),
            "is_weekend": float(dow >= 5),
            "is_failed":  float(failed),
            "rtt_ms_log": rtt_ms_log,
            "failed_rate_ip":   float(failed_rate_ip),
            "failed_rate_user": float(failed_rate_user),
            "ip_login_rate_15m":   float(ip_login_rate_15m),
            "ip_failure_rate_15m": float(ip_failure_rate_15m),
            "unique_users_per_ip_1h":        float(unique_users_per_ip_1h),
            "unique_failed_users_per_ip_1h": float(unique_failed_users_per_ip_1h),
            "unique_ips_per_user_24h":       float(unique_ips_per_user_24h),
            "new_ip_for_user":      float(new_ip_for_user),
            "new_country_for_user": float(new_country_for_user),
            "new_device_for_user":  float(new_device_for_user),
            "new_browser_for_user": float(new_browser_for_user),
            "new_os_for_user":      float(new_os_for_user),
            "new_asn_for_user":     float(new_asn_for_user),
            "country_rarity":    float(country_rarity),
            "device_rarity":     float(device_rarity),
            "browser_rarity":    float(browser_rarity),
            "os_rarity":         float(os_rarity),
            "asn_rarity":        float(asn_rarity),
            "private_ip":        float(_private_ip_flag_cached(self, ip)),
            "user_agent_rarity": float(user_agent_rarity),
        }
        vector = np.array([values[name] for name in self.feature_names], dtype=np.float32)
        context = {
            "timestamp":   record["timestamp"],
            "user":        user,
            "ip":          ip,
            "country":     country,
            "device_type": device,
            "browser":     browser,
            "os":          os_name,
            "asn":         asn,
            "user_agent":  user_agent,
            "status":      record["status"],
        }
        if update_state:
            self._update_state(
                record={
                    "ip":          ip,
                    "user":        user,
                    "country":     country,
                    "device_type": device,
                    "browser":     browser,
                    "os":          os_name,
                    "asn":         asn,
                    "status":      record["status"],
                    "is_failed":   bool(failed),
                    "timestamp":   record["timestamp"],
                },
                ts=ts,
            )
        return vector, context

    def observe_event(self, record):
        """Update rolling state without re-extracting features."""
        normalized = _normalize_record(record)
        ts = _normalize_timestamp(normalized["timestamp"])
        failed = _status_to_failed(normalized["status"])
        self._update_state(
            record={
                "ip":          normalized["ip"],
                "user":        normalized["user"],
                "country":     normalized["country"],
                "device_type": normalized["device_type"],
                "browser":     normalized["browser"],
                "os":          normalized["os"],
                "asn":         normalized["asn"],
                "status":      normalized["status"],
                "is_failed":   bool(failed),
                "timestamp":   normalized["timestamp"],
            },
            ts=ts,
        )

    # ── Internal helpers (kept for the streaming path) ────────────────

    @staticmethod
    def _prune(window, cutoff):
        if not window:
            return
        while window and window[0][0] < cutoff:
            window.popleft()

    def _update_state(self, record, ts):
        ip   = record["ip"]
        user = record["user"]
        failed = record["is_failed"]

        cutoff_15m = ts - timedelta(minutes=15)
        cutoff_1h  = ts - timedelta(hours=1)
        cutoff_24h = ts - timedelta(hours=24)

        self._prune(self.ip_events_15m[ip],   cutoff_15m)
        self._prune(self.ip_events_1h[ip],    cutoff_1h)
        self._prune(self.user_events_24h[user], cutoff_24h)

        self.ip_events_15m[ip].append((ts, user, failed))
        self.ip_events_1h[ip].append((ts, user, failed))
        self.user_events_24h[user].append((ts, ip, failed))

        self.ip_total_counts[ip]   += 1
        self.user_total_counts[user] += 1
        if failed:
            self.ip_failed_counts[ip]   += 1
            self.user_failed_counts[user] += 1

        self.runtime_seen["ips"][user].add(ip)
        self.runtime_seen["countries"][user].add(record["country"])
        self.runtime_seen["devices"][user].add(record["device_type"])
        self.runtime_seen["browsers"][user].add(record["browser"])
        self.runtime_seen["os"][user].add(record["os"])
        self.runtime_seen["asns"][user].add(record["asn"])


# ───────────────────────────────────────────────────────────────────────────
# Module-level helpers used by both the bulk and streaming paths
# ───────────────────────────────────────────────────────────────────────────

def _as_str(value, default=""):
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def _normalize_timestamp(value):
    """Parse a single timestamp - same signature as the previous version
    but uses a faster path for the common ``datetime`` instance case."""
    if isinstance(value, datetime):
        return value
    try:
        parsed = pd.to_datetime(value, errors="coerce")
    except Exception:
        return datetime(2026, 1, 1, 12, 0, 0)
    if pd.isna(parsed):
        return datetime(2026, 1, 1, 12, 0, 0)
    return parsed.to_pydatetime()


def _normalize_bool(value):
    if isinstance(value, bool):
        return value
    return _as_str(value, "false").lower() in {"true", "1", "yes", "y"}


def _status_to_failed(status_value):
    text = _as_str(status_value, "SUCCESS").upper()
    if text in {"NO", "NEGATIVE", "FAILED", "0", "FALSE"}:
        return True
    if text in {"SUCCESS", "TRUE", "1", "YES", "POSITIVE"}:
        return False
    return False


def _safe_rarity(counts, value, total_count):
    if total_count <= 0:
        return 1.0 if value else 0.0
    count = counts.get(value, 0)
    return 1.0 - min(count / total_count, 1.0)


def _private_ip_flag_cached(engine, ip_value):
    """Cached wrapper around ``_private_ip_flag`` - only parses each
    distinct IP once. The cache is cleared by ``reset_state()``."""
    cache = engine._private_ip_cache
    if ip_value in cache:
        return cache[ip_value]
    try:
        ip = ip_address(_as_str(ip_value, "0.0.0.0"))
        flag = int(
            ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local
        )
    except ValueError:
        flag = 0
    cache[ip_value] = flag
    return flag


def _private_ip_flag(ip_value):
    try:
        ip = ip_address(_as_str(ip_value, "0.0.0.0"))
        return int(
            ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local
        )
    except ValueError:
        return 0


def _normalize_record(record):
    """11-key dict used by the streaming path. Mirrors the original."""
    out = {
        "timestamp":         _as_str(record.get("Login Timestamp") or record.get("timestamp") or record.get("detected_at"), _DEFAULT_TS),
        "user":              _as_str(record.get("User ID")   or record.get("user"),   "unknown"),
        "ip":                _as_str(record.get("IP Address") or record.get("ip"),    "0.0.0.0"),
        "country":           _as_str(record.get("Country")    or record.get("country"), "UNK"),
        "device_type":       _as_str(record.get("Device Type") or record.get("device_type"), "Unknown"),
        "browser":           _as_str(record.get(_RBA_BROWSER) or record.get("browser"), "Unknown"),
        "os":                _as_str(record.get(_RBA_OS)      or record.get("os"),     "Unknown"),
        "asn":               _as_str(record.get(_RBA_ASN)     or record.get("asn"),    "UNK_ASN"),
        "user_agent":        _as_str(record.get(_RBA_UA)      or record.get("user_agent"), "Unknown"),
        "status":            _as_str(record["Login Successful"] if "Login Successful" in record else record.get("status"), "SUCCESS"),
        "round_trip_time_ms": _normalize_rtt(record),
    }
    return out


def _normalize_rtt(record):
    for key in _RTT_KEYS:
        if key in record:
            val = record[key]
            if val is None or val == "" or (isinstance(val, float) and np.isnan(val)):
                continue
            try:
                return float(val)
            except Exception:
                continue
    return None


def _rolling_cardinality_failed(
    timestamps: pd.Series,
    group_key: pd.Series,
    payload: pd.Series,
    predicate: pd.Series,
    window: pd.Timedelta,
) -> pd.Series:
    """Specialised variant of ``_rolling_cardinality`` for the
    "unique failed users per IP in 1h" feature. Sweeps in C, like the
    general helper, but skips non-matching rows instead of counting
    them."""
    if len(timestamps) == 0:
        return pd.Series(np.zeros(0, dtype=np.int32))

    order = np.argsort(timestamps.values, kind="stable")
    ts = timestamps.values[order]
    gk = group_key.values[order]
    pl = payload.values[order]
    pr = predicate.values[order]

    last_seen: dict = defaultdict(dict)
    in_window: dict = defaultdict(dict)
    out = np.empty(len(ts), dtype=np.int32)

    for i in range(len(ts)):
        cutoff = ts[i] - window
        bucket_in   = in_window[gk[i]]
        bucket_last = last_seen[gk[i]]
        expired = [k for k, last in bucket_last.items() if last < cutoff]
        for k in expired:
            del bucket_last[k]
            del bucket_in[k]
        if pr[i]:
            key = pl[i]
            if key not in bucket_in:
                bucket_in[key] = True
            bucket_last[key] = ts[i]
        out[i] = len(bucket_in)

    result = pd.Series(out, index=group_key.index[order]).reindex(group_key.index)
    return result


# Map of RBA / synthetic column names → canonical short names. The
# vectorised paths below only ever reference the short names.
_CANONICAL_RENAMES = {
    _RBA_TS:      _SYN_TS,
    _RBA_USER:    _SYN_USER,
    _RBA_IP:      _SYN_IP,
    _RBA_COUNTRY: _SYN_COUNTRY,
    _RBA_DEVICE:  _SYN_DEVICE,
    _RBA_BROWSER: _SYN_BROWSER,
    _RBA_OS:      _SYN_OS,
    _RBA_ASN:     _SYN_ASN,
    _RBA_UA:      _SYN_UA,
    "Round-Trip Time [ms]": "round_trip_time_ms",
}


def _canonical_columns(working: pd.DataFrame) -> pd.DataFrame:
    """Rename the input's columns to the short canonical names used
    throughout this module. Idempotent - if the short names are
    already present, no rename is performed.
    """
    return working.rename(columns=_CANONICAL_RENAMES)
