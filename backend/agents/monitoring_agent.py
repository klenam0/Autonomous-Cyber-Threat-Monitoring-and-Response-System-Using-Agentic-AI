# backend/agents/monitoring_agent.py
import json
import os
import time
from datetime import datetime
from .detection_agent import DetectionAgent
from .analysis_agent  import AnalysisAgent
from .response_agent  import ResponseAgent
from utils.alert_manager import AlertManager

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class MonitoringAgent:

    def __init__(self, log_file=None, threshold=5, anomaly_detector=None):
        self.log_file        = log_file
        self.detector        = DetectionAgent(
            threshold=threshold,
            anomaly_detector=anomaly_detector
        )
        self.analyzer        = AnalysisAgent()
        self.responder       = ResponseAgent()
        self.alert_manager   = AlertManager()
        self.alerts_generated = 0
        self.events_processed = 0
        self.start_time       = None

        self._stats_path = os.path.join(BASE, "data", "pipeline_stats.json")
        self._queue_path = os.path.join(BASE, "data", "live_queue.jsonl")
        self._cursor_path = self._queue_path + ".cursor"

    # ── Shared event processor ────────────────────────────────────────────────

    def _process_event(self, log):
        """Run a single log event through the full detection pipeline."""
        alert = self.detector.analyze_event(log)
        self.events_processed += 1

        ts   = log.get("timestamp", "")
        user = log.get("user", "?")
        ip   = log.get("ip", "?")
        st   = log.get("status", "?")
        print(f"🟢 {ts} | {user} @ {ip} | {st}")

        if alert:
            alert["timestamp"] = log.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            analyzed = self.analyzer.evaluate_alert(alert)
            print(f"🚨 ALERT: {analyzed.get('type')} | {analyzed.get('severity')} | #{analyzed.get('alert_id','?')}")
            self.alert_manager.save_alert(analyzed)
            self.responder.take_action(analyzed)
            self.alerts_generated += 1

    # ── Batch mode ────────────────────────────────────────────────────────────

    def stream_logs(self, delay=1):
        """
        Batch mode: read parsed_logs.json once and process all events.
        Used by: python main.py
        """
        # Backup alerts before run
        alerts_path = os.path.join(BASE, "data", "alerts.json")
        backup_path = alerts_path + ".bak"
        try:
            if os.path.exists(alerts_path):
                import shutil
                shutil.copy2(alerts_path, backup_path)
        except Exception as e:
            print(f"⚠ Could not backup alerts.json: {e}")

        with open(self.log_file, "r") as f:
            logs = json.load(f)

        self.start_time = datetime.now()
        print(f"📡 MonitoringAgent: Streaming {len(logs)} log events...\n")

        for log in logs:
            time.sleep(delay)
            self._process_event(log)

        self._save_stats()
        print(f"\n📊 Processed {self.events_processed} events → {self.alerts_generated} alerts")

    # ── Live streaming mode ───────────────────────────────────────────────────

    def stream_live(self, poll_interval=1.0):
        """
        Live mode: continuously read new events from live_queue.jsonl.
        Runs indefinitely until Ctrl+C.
        Used by: python main.py --live
        """
        # Load cursor (how many lines have been processed)
        cursor = self._load_cursor()

        self.start_time = datetime.now()
        print("📡 Live streaming mode active")
        print(f"   Queue file: {self._queue_path}")
        print(f"   Resumed from event #{cursor}")
        print("   Press Ctrl+C to stop\n")
        print("-" * 55)

        try:
            while True:
                new_events, cursor = self._read_queue(cursor)

                if new_events:
                    for event in new_events:
                        self._process_event(event)
                        cursor += 1
                    self._save_cursor(cursor)
                else:
                    # No new events - wait before polling again
                    time.sleep(poll_interval)

        except KeyboardInterrupt:
            elapsed = (datetime.now() - self.start_time).seconds
            print(f"\n\n⏹ Live streaming stopped after {elapsed}s")
            print(f"   Events processed: {self.events_processed:,}")
            print(f"   Alerts generated: {self.alerts_generated}")
            self._save_stats()

    def _read_queue(self, cursor):
        """Read unprocessed events from the queue file.
        Returns (new_events, cursor) — cursor is echoed back unchanged
        unless a mismatch was detected and corrected.
        """
        try:
            with open(self._queue_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            # Guard: if the queue file is shorter than our cursor, the file
            # was reset externally (e.g. manual edit) without the cursor
            # being reset in step. Recover instead of silently idling
            # forever waiting for the file to grow back past the old cursor.
            if cursor > len(lines):
                print(
                    f"⚠ Queue shorter than cursor ({len(lines)} < {cursor}) "
                    f"— resetting cursor to 0"
                )
                cursor = 0
                self._save_cursor(0)

            new_events = []
            for line in lines[cursor:]:
                line = line.strip()
                if not line:
                    continue
                try:
                    new_events.append(json.loads(line))
                except json.JSONDecodeError:
                    print(f"⚠ Skipping malformed queue entry")
            return new_events, cursor

        except FileNotFoundError:
            return [], cursor

    def _load_cursor(self):
        try:
            with open(self._cursor_path, "r") as f:
                return int(f.read().strip())
        except Exception:
            return 0

    def _save_cursor(self, cursor):
        try:
            with open(self._cursor_path, "w") as f:
                f.write(str(cursor))
        except Exception:
            pass

    # ── Stats ─────────────────────────────────────────────────────────────────

    def _save_stats(self):
        if not self.start_time:
            return
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()

        stats = {
            "events_processed":   self.events_processed,
            "alerts_generated":   self.alerts_generated,
            "start_time":         self.start_time.isoformat(),
            "end_time":           end_time.isoformat(),
            "duration_seconds":   round(duration, 2),
            "last_run":           end_time.strftime("%Y-%m-%d %H:%M:%S"),
            "avg_event_time_ms":  round(
                (duration / self.events_processed) * 1000, 1
            ) if self.events_processed > 0 else 0,
        }

        os.makedirs(os.path.dirname(self._stats_path), exist_ok=True)
        with open(self._stats_path, "w") as f:
            json.dump(stats, f, indent=2)
        print(f"📊 Pipeline stats saved")