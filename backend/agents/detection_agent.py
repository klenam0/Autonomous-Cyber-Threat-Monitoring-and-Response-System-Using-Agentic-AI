# backend/agents/detection_agent.py
from collections import defaultdict
from datetime import datetime


class DetectionAgent:
    def __init__(self, threshold=5, anomaly_detector=None):
        self.failed_attempts = defaultdict(int)
        self.threshold = threshold
        self.blocked_ips = set()
        self.user_last_login = {}
        self.ip_attempt_times = defaultdict(list)
        self.anomaly_detector = anomaly_detector
        self.ip_users_tried = defaultdict(set)
        self.internal_ip_prefixes = ("192.168.", "10.0.", "172.16.")
        self.suspicious_last_fired = {}  # ip → last datetime it triggered suspicious time
        self.ml_alerted_ips = set()  # IPs that triggered ML alert but aren't blocked

    def analyze_event(self, log_event):
        ip        = log_event["ip"]
        user      = log_event["user"]
        timestamp = datetime.strptime(log_event["timestamp"], "%Y-%m-%d %H:%M:%S")
        hour      = timestamp.hour

        self.ip_users_tried[ip].add(user)

        # ── 1. Suspicious Login Time ───────────────────────────────────────
        if log_event["status"] == "SUCCESS" and 0 <= hour <= 5:
            last_fired = self.suspicious_last_fired.get(ip)
            cooldown   = 600  # 10 minutes between alerts from same IP
            if last_fired is None or (timestamp - last_fired).total_seconds() > cooldown:
                self.suspicious_last_fired[ip] = timestamp
                return {
                    "type": "Suspicious Login Time",
                    "ip":   ip,
                    "user": user,
                    "description": f"User {user} logged in at unusual hour ({timestamp.strftime('%H:%M')})",
                    "trigger_details": {
                        "rule":      "Off-hours login detected",
                        "threshold": "Logins between 00:00–05:59 flagged",
                        "actual":    f"Login at {timestamp.strftime('%H:%M')} (hour {hour})",
                        "values":    {"login_hour": hour, "restricted_window": "00:00–05:59"},
                    }
                }

        # ── 2. Multiple IP Login ───────────────────────────────────────────
        if log_event["status"] == "SUCCESS":
            prev = self.user_last_login.get(user)
            # Update FIRST so chain breaks after one alert fires
            self.user_last_login[user] = (ip, timestamp)

            if prev is not None:
                last_ip, last_time = prev
                time_diff = abs((timestamp - last_time).total_seconds())
                if ip != last_ip and time_diff < 120:
                    return {
                        "type": "Multiple IP Login",
                        "ip":   ip,
                        "user": user,
                        "description": (
                            f"User {user} logged in from {last_ip} and {ip} "
                            f"within {int(time_diff)} seconds"
                        ),
                        "trigger_details": {
                            "rule":      "Same user authenticated from two IPs within 2 minutes",
                            "threshold": "Maximum 120 seconds between logins from different IPs",
                            "actual":    f"{user} logged from {last_ip} then {ip} within {int(time_diff)}s",
                            "values": {
                                "first_ip":    last_ip,
                                "second_ip":   ip,
                                "time_diff_s": int(time_diff),
                                "threshold_s": 120,
                            },
                        }
                    }
           

        # ── 3, 4, 5 all inside one FAILED block ───────────────────────────
        # ── FAILED event processing - ORDER MATTERS ────────────────────────
        # Detectors run in this specific sequence:
        #   1. Slow Brute Force  - checked BEFORE fast brute force
        #      (needs time_spread_minutes >= 5 to distinguish from fast)
        #   2. Credential Stuffing - checked BEFORE fast brute force
        #      (needs unique_users >= 5 to distinguish from single-account BF)
        #   3. Fast Brute Force - catches anything remaining above threshold
        #
        # Changing this order will cause misclassification:
        #   - Credential stuffing will be caught as brute force
        #   - Slow brute force will fire on rapid attacks
        if log_event["status"] == "FAILED":
            if ip in self.blocked_ips:
                return None

            # Track failure timestamps for slow brute force
            self.ip_attempt_times[ip].append(timestamp)
            self.failed_attempts[ip] += 1
            unique_users = len(self.ip_users_tried[ip])
            print(f"⚠ FAILED count for {ip}: {self.failed_attempts[ip]} | unique users: {unique_users}")

           # ── 3. Slow Brute Force ────────────────────────────────────────
            # Checked BEFORE fast brute force and credential stuffing guards
            # unique_users_for_ip < 3 prevents misfiring on credential stuffing
            self.ip_attempt_times[ip].append(timestamp)

            recent_failures = [
                t for t in self.ip_attempt_times[ip]
                if abs((timestamp - t).total_seconds()) <= 3600
            ]

            unique_users_for_ip = len(self.ip_users_tried[ip])

            time_spread_minutes = (
                (timestamp - recent_failures[0]).total_seconds() / 60
            ) if recent_failures else 0

            if (
                len(recent_failures) >= 4
                and self.failed_attempts[ip] < self.threshold
                and time_spread_minutes >= 5
                and unique_users_for_ip < 3
            ):
                self.blocked_ips.add(ip)
                return {
                    "type": "Slow Brute Force",
                    "ip":   ip,
                    "user": user,
                    "description": (
                        f"{len(recent_failures)} failed attempts from {ip} "
                        f"spread over {int(time_spread_minutes)} minutes - "
                        f"evasive brute force pattern"
                    ),
                    "trigger_details": {
                        "rule":      "Slow brute force evasion pattern",
                        "threshold": "4+ failures within 60 min, spread over 5+ min",
                        "actual":    f"{len(recent_failures)} failures over {int(time_spread_minutes)} minutes from {ip}",
                        "values": {
                            "failure_count":        len(recent_failures),
                            "spread_minutes":       int(time_spread_minutes),
                            "min_spread_threshold": 5,
                            "window_minutes":       60,
                            "unique_users":         unique_users_for_ip,
                        },
                    }
                }

            # ── 4. Credential Stuffing ─────────────────────────────────────
            # Many different usernames from one IP
            if unique_users >= 5 and self.failed_attempts[ip] >= 5:
                self.blocked_ips.add(ip)
                total_ip  = self.failed_attempts[ip]
                fail_rate = round(total_ip / max(total_ip, 1), 2)
                return {
                    "type": "Credential Stuffing",
                    "ip": ip,
                    "user": user,
                    "description": (
                        f"IP {ip} attempted {unique_users} different usernames - "
                        f"consistent with automated credential stuffing"
                    ),
                    "trigger_details": {
                        "rule":      "Multiple unique usernames from single IP",
                        "threshold": "5+ unique usernames with high failure rate",
                        "actual":    f"{unique_users} unique usernames tried from {ip}, {total_ip} total attempts",
                        "values":    {
                            "unique_usernames":    unique_users,
                            "total_attempts":      total_ip,
                            "unique_threshold":    5,
                        },
                    }
                }

            # ── 5. Fast Brute Force ────────────────────────────────────────
            if self.failed_attempts[ip] >= self.threshold:
                self.blocked_ips.add(ip)
                return {
                    "type": "Brute Force Attack",
                    "ip": ip,
                    "user": user,
                    "description": (
                        f"{self.failed_attempts[ip]} failed login attempts "
                        f"detected from {ip}"
                    ),
                    "trigger_details": {
                        "rule":      "Rapid failed login threshold exceeded",
                        "threshold": f"{self.threshold} failed attempts triggers alert",
                        "actual":    f"{self.failed_attempts[ip]} failed attempts from {ip}",
                        "values":    {
                            "failed_count": self.failed_attempts[ip],
                            "threshold":    self.threshold,
                            "excess":       self.failed_attempts[ip] - self.threshold,
                        },
                    }
                }

        # ── 6. ML Anomaly ─────────────────────────────────────────────────
        if self.anomaly_detector:
            is_internal = ip.startswith(self.internal_ip_prefixes)
            if not is_internal:
                result = self.anomaly_detector.score_event(log_event)
                if result and result["is_anomaly"]:
                    is_failed_event = log_event.get("status") == "FAILED"

                    if is_failed_event:
                        # FAILED events: alert once but DO NOT block.
                        # Blocking would prevent rule-based detectors from
                        # accumulating the failure count they need to fire.
                        # ml_alerted_ips prevents duplicate ML alerts from
                        # the same IP while still letting rules run.
                        if ip in self.ml_alerted_ips:
                            return None   # already alerted, let rules handle it
                        self.ml_alerted_ips.add(ip)
                        # Note: NOT adding to blocked_ips here
                    else:
                        # SUCCESS events: block immediately.
                        # No rule-based detector covers suspicious SUCCESS logins
                        # (account takeover from unknown IP).
                        if ip in self.blocked_ips:
                            return None
                        self.blocked_ips.add(ip)

                    feature_explanation = None
                    if hasattr(self.anomaly_detector, "explain_event"):
                        feature_explanation = self.anomaly_detector.explain_event(
                            log_event,
                            result["anomaly_score"],
                            result["confidence"]
                        )

                    return {
                        "type":                "ML Anomaly Detected",
                        "ip":                  ip,
                        "user":                user,
                        "anomaly_score":       result["anomaly_score"],
                        "confidence":          result["confidence"],
                        "feature_explanation": feature_explanation,
                        "description": (
                            f"Unusual login behaviour detected for user {user} "
                            f"from {ip}. "
                            f"Anomaly score: {result['anomaly_score']} "
                            f"(confidence: {result['confidence']}). "
                            + (feature_explanation["summary"]
                               if feature_explanation else "")
                        ),
                        "trigger_details": {
                            "rule": (
                                "Isolation Forest - FAILED event, IP not blocked (rules still accumulate)"
                                if is_failed_event else
                                "Isolation Forest - SUCCESS event from suspicious IP, blocked immediately"
                            ),
                            "threshold": "Score < -0.10 = High, < -0.02 = Medium confidence",
                            "actual":    f"Score {result['anomaly_score']} ({result['confidence']} confidence)",
                            "values": {
                                "anomaly_score":   result["anomaly_score"],
                                "confidence":      result["confidence"],
                                "is_failed_event": is_failed_event,
                                "blocked":         not is_failed_event,
                            },
                        }
                    }

        return None