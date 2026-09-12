# backend/utils/alert_manager.py

import json
import os
from datetime import datetime
from filelock import FileLock

DEFAULT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "alerts.json"
)

class AlertManager:

    def __init__(self, file_path=None):
        self.file_path = file_path or DEFAULT_PATH
        self.lock_path = self.file_path + ".lock"
        self._ensure_file()

    def _ensure_file(self):
        os.makedirs(os.path.dirname(self.file_path), exist_ok=True)
        if not os.path.exists(self.file_path):
            with open(self.file_path, "w") as f:
                json.dump([], f)

    def save_alert(self, alert):
        """Save alert immediately - protected by file lock."""
        if "llm_explanation" not in alert:
            alert["llm_explanation"] = None
            alert["enriched"]        = False

        with FileLock(self.lock_path, timeout=10):
            try:
                with open(self.file_path, "r", encoding="utf-8") as f:
                    alerts = json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                alerts = []

            alerts.append(alert)

            with open(self.file_path, "w", encoding="utf-8") as f:
                json.dump(alerts, f, indent=4, ensure_ascii=False)

        print("💾 Alert saved to alerts.json")

    def update_explanation(self, alert_id, llm_explanation):
        """Update a saved alert with LLM explanation - protected by file lock."""
        with FileLock(self.lock_path, timeout=10):
            try:
                with open(self.file_path, "r", encoding="utf-8") as f:
                    alerts = json.load(f)

                updated = False
                for alert in alerts:
                    if alert.get("alert_id") == alert_id:
                        alert["llm_explanation"] = llm_explanation
                        alert["enriched"]        = True
                        alert["enriched_at"]     = datetime.now().strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                        updated = True
                        break

                if updated:
                    with open(self.file_path, "w", encoding="utf-8") as f:
                        json.dump(alerts, f, indent=4, ensure_ascii=False)
                    print(f"✅ Alert #{alert_id} updated with LLM explanation")

            except Exception as e:
                print(f"⚠ Could not update alert #{alert_id}: {e}")

    def load_alerts(self):
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []