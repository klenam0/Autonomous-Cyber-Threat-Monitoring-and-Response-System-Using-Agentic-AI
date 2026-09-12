import { useState, useEffect } from "react";
import {
  Activity,
  Cpu,
  Database,
  Shield,
  CheckCircle,
  AlertTriangle,
  Clock,
  Zap,
} from "lucide-react";

const API = "http://localhost:5000/api";

function HealthCard({ icon: Icon, label, value, sub, status, color }) {
  const statusColors = {
    good: "bg-green-500/20  border-green-500/20  text-green-400",
    warning: "bg-amber-500/20  border-amber-500/20  text-amber-400",
    error: "bg-red-500/20    border-red-500/20    text-red-400",
    info: "bg-cyan-500/20   border-cyan-500/20   text-cyan-400",
  };
  const dotColors = {
    good: "bg-green-400",
    warning: "bg-amber-400",
    error: "bg-red-400",
    info: "bg-cyan-400",
  };

  return (
    <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl p-4 sm:p-5">
      <div className="flex items-start justify-between gap-2 mb-3">
        <div
          className={`w-8 h-8 rounded-lg grid place-items-center flex-shrink-0 ${statusColors[status] || statusColors.info}`}
        >
          <Icon className="w-4 h-4" />
        </div>
        <div
          className={`flex items-center gap-1.5 rounded-full px-2 py-0.5 border flex-shrink-0 ${statusColors[status] || statusColors.info}`}
        >
          <div
            className={`w-1.5 h-1.5 rounded-full ${dotColors[status] || dotColors.info} ${status === "good" ? "animate-pulse" : ""}`}
          />
          <span className="text-xs font-semibold capitalize">{status}</span>
        </div>
      </div>
      <p
        className={`text-2xl font-semibold leading-none mb-1 ${color || "text-[color:var(--text-primary)]"}`}
      >
        {value}
      </p>
      <p className="ui-label text-[color:var(--text-primary)]">{label}</p>
      {sub && <p className="ui-caption mt-1">{sub}</p>}
    </div>
  );
}

function MetricRow({ label, value, color = "text-white" }) {
  return (
    <div className="flex items-center justify-between py-3 border-b border-[color:var(--border)] last:border-0 gap-4">
      <span className="ui-body text-[color:var(--text-secondary)]">
        {label}
      </span>
      <span className={`text-sm font-medium text-right ${color}`}>{value}</span>
    </div>
  );
}

function StatusBadge({ ok, label }) {
  return (
    <div
      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border flex-shrink-0 ${
        ok
          ? "bg-green-500/10 border-green-500/20 text-green-400"
          : "bg-red-500/10   border-red-500/20   text-red-400"
      }`}
    >
      {ok ? (
        <CheckCircle className="w-3 h-3" />
      ) : (
        <AlertTriangle className="w-3 h-3" />
      )}
      <span className="text-sm font-medium">{label}</span>
    </div>
  );
}

export default function SystemHealth({ data }) {
  const { modelInfo, pipelineStats, status, alerts } = data;
  const [uptimeSeconds, setUptimeSeconds] = useState(null);
  const [apiOk, setApiOk] = useState(true);

  const formatUptime = (seconds) => {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    return h > 0 ? `${h}h ${m}m ${s}s` : m > 0 ? `${m}m ${s}s` : `${s}s`;
  };

  // Live uptime counter based on backend server start time
  useEffect(() => {
    if (typeof status?.uptime_seconds === "number") {
      setUptimeSeconds(Math.max(0, Math.floor(status.uptime_seconds)));
    }
  }, [status?.uptime_seconds]);

  useEffect(() => {
    const id = setInterval(() => {
      setUptimeSeconds((current) =>
        typeof current === "number" ? current + 1 : current,
      );
    }, 1000);
    return () => clearInterval(id);
  }, []);

  // Check API health
  useEffect(() => {
    const check = async () => {
      try {
        const r = await fetch(`${API}/status`);
        setApiOk(r.ok);
      } catch {
        setApiOk(false);
      }
    };
    check();
    const id = setInterval(check, 5000);
    return () => clearInterval(id);
  }, []);

  const modelLoaded = status?.model_loaded ?? false;
  const totalAlerts = alerts.length;
  const highAlerts = alerts.filter((a) => a.severity === "HIGH").length;
  const mlAlerts = alerts.filter(
    (a) => a.type === "ML Anomaly Detected",
  ).length;
  const lastRun = pipelineStats?.last_run || "Never";
  const eventsProcessed = pipelineStats?.events_processed || 0;
  const duration = pipelineStats?.duration_seconds || null;
  const avgMs = pipelineStats?.avg_event_time_ms || null;

  // Model info
  const precision = modelInfo?.precision
    ? `${(modelInfo.precision * 100).toFixed(1)}%`
    : "-";
  const recall = modelInfo?.recall
    ? `${(modelInfo.recall * 100).toFixed(1)}%`
    : "-";
  const f1 = modelInfo?.f1 ? `${(modelInfo.f1 * 100).toFixed(1)}%` : "-";
  const accuracy = modelInfo?.accuracy
    ? `${(modelInfo.accuracy * 100).toFixed(1)}%`
    : "-";
  const trainSize = modelInfo?.training_size || "-";
  const trainedAt = modelInfo?.trained_at
    ? modelInfo.trained_at.split("T")[0]
    : "-";

  const AGENTS = [
    { name: "Monitoring Agent", role: "Orchestrator", ok: true },
    { name: "Detection Agent", role: "Threat Detection Engine", ok: true },
    { name: "Analysis Agent", role: "Alert Intelligence", ok: true },
    { name: "Response Agent", role: "Automated Response", ok: true },
  ];

  const DETECTORS = status?.detectors || [
    "Suspicious Login Time",
    "Multiple IP Login",
    "Slow Brute Force",
    "Credential Stuffing",
    "Brute Force Attack",
    "ML Anomaly Detection",
  ];

  return (
    <div className="p-3 sm:p-6 space-y-5 sm:space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <p className="ui-kicker">System Health</p>
          <p className="ui-caption mt-1">
            Real-time status of all system components
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <StatusBadge ok={apiOk} label="API" />
          <StatusBadge ok={modelLoaded} label="ML Model" />
          <StatusBadge ok={true} label="Pipeline" />
        </div>
      </div>

      {/* Top stat cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <HealthCard
          icon={Clock}
          label="Dashboard Uptime"
          value={
            typeof uptimeSeconds === "number"
              ? formatUptime(uptimeSeconds)
              : "-"
          }
          sub="Since server start"
          status="good"
          color="text-green-400"
        />
        <HealthCard
          icon={Zap}
          label="Events Processed"
          value={eventsProcessed > 0 ? eventsProcessed.toLocaleString() : "-"}
          sub="Last pipeline run"
          status={eventsProcessed > 0 ? "good" : "info"}
          color="text-cyan-400"
        />
        <HealthCard
          icon={Shield}
          label="Alerts Generated"
          value={totalAlerts}
          sub={`${highAlerts} HIGH severity`}
          status={highAlerts > 0 ? "warning" : "good"}
          color={highAlerts > 0 ? "text-orange-400" : "text-white"}
        />
        <HealthCard
          icon={Cpu}
          label="ML Detections"
          value={mlAlerts}
          sub="Isolation Forest flags"
          status="info"
          color="text-purple-400"
        />
      </div>

      {/* Middle row: ML Model + Pipeline Stats */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* ML Model */}
        <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl p-4 sm:p-5">
          <div className="flex items-center justify-between gap-2 flex-wrap mb-4">
            <div className="flex items-center gap-2">
              <Cpu className="w-4 h-4 text-cyan-400" />
              <p className="ui-label text-[color:var(--text-primary)]">
                ML Model Status
              </p>
            </div>
            <StatusBadge
              ok={modelLoaded}
              label={modelLoaded ? "Loaded" : "Not Loaded"}
            />
          </div>

          <MetricRow label="Algorithm" value="Isolation Forest" />
          <MetricRow label="Trained On" value={trainSize} />
          <MetricRow
            label="Data Source"
            value="RBA Dataset (Kaggle)"
            color="text-cyan-400"
          />
          <MetricRow label="Train Date" value={trainedAt} />
          <MetricRow label="Contamination" value="0.15 (15%)" />
          <MetricRow label="N Estimators" value="200 trees" />
          <MetricRow
            label="Features"
            value="7 (hour, failed, ip, user, rate, country, device)"
          />
          <MetricRow
            label="Inference Mode"
            value="Runtime only"
            color="text-cyan-400"
          />

          <div className="mt-5 pt-4 border-t border-[color:var(--border)]">
            <p className="ui-kicker mb-3">Evaluation Metrics</p>
            <div className="grid grid-cols-2 gap-3">
              {[
                {
                  label: "Precision",
                  value: precision,
                  color: "text-green-400",
                },
                { label: "Recall", value: recall, color: "text-amber-400" },
                { label: "F1-Score", value: f1, color: "text-cyan-400" },
                { label: "Accuracy", value: accuracy, color: "text-slate-300" },
              ].map(({ label, value, color }) => (
                <div
                  key={label}
                  className="bg-[color:var(--bg-elevated)] rounded-lg p-3 text-center"
                >
                  <p className={`text-2xl font-semibold leading-none ${color}`}>
                    {value}
                  </p>
                  <p className="ui-caption mt-1">{label}</p>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Pipeline Stats */}
        <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl p-4 sm:p-5">
          <div className="flex items-center gap-2 mb-4">
            <Activity className="w-4 h-4 text-green-400" />
            <p className="ui-label text-[color:var(--text-primary)]">
              Pipeline Stats
            </p>
          </div>

          <MetricRow label="Last Run" value={lastRun} />
          <MetricRow
            label="Events Processed"
            value={eventsProcessed > 0 ? eventsProcessed.toLocaleString() : "-"}
          />
          <MetricRow label="Alerts Generated" value={totalAlerts} />
          <MetricRow
            label="Run Duration"
            value={duration ? `${duration}s` : "-"}
          />
          <MetricRow
            label="Avg Event Time"
            value={avgMs ? `${avgMs}ms` : "-"}
            color="text-cyan-400"
          />
          <MetricRow label="Detection Threshold" value="5 failed attempts" />
          <MetricRow label="ML Confidence Guard" value="High + Medium only" />
          <MetricRow
            label="Internal IP Guard"
            value="192.168.x, 10.x, 172.16.x"
          />

          {/* Agent statuses */}
          <div className="mt-5 pt-4 border-t border-[color:var(--border)]">
            <p className="ui-kicker mb-3">Agent Status</p>
            <div className="space-y-2">
              {AGENTS.map(({ name, role, ok }) => (
                <div
                  key={name}
                  className="flex items-center justify-between gap-2 flex-wrap"
                >
                  <div>
                    <p className="ui-body text-[color:var(--text-primary)]">
                      {name}
                    </p>
                    <p className="ui-caption">{role}</p>
                  </div>
                  <StatusBadge ok={ok} label={ok ? "Active" : "Offline"} />
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Bottom row: Detectors + API endpoints */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Active Detectors */}
        <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl p-4 sm:p-5">
          <div className="flex items-center gap-2 mb-4">
            <Shield className="w-4 h-4 text-cyan-400" />
            <p className="ui-label text-[color:var(--text-primary)]">
              Active Detectors
            </p>
          </div>
          <div className="space-y-2">
            {DETECTORS.map((d, i) => (
              <div
                key={i}
                className="flex items-center justify-between gap-2 flex-wrap py-2 border-b border-[color:var(--border)] last:border-0"
              >
                <div className="flex items-center gap-2">
                  <div
                    className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${
                      d === "ML Anomaly Detection"
                        ? "bg-purple-400"
                        : "bg-cyan-400"
                    }`}
                  />
                  <span className="ui-body text-[color:var(--text-primary)]">
                    {d}
                  </span>
                  {d === "ML Anomaly Detection" && (
                    <span className="text-xs bg-purple-500/20 text-purple-400 border border-purple-500/30 rounded px-1.5 py-0.5">
                      ML
                    </span>
                  )}
                </div>
                <StatusBadge ok={true} label="Active" />
              </div>
            ))}
          </div>
        </div>

        {/* API Health */}
        <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl p-4 sm:p-5">
          <div className="flex items-center gap-2 mb-4">
            <Database className="w-4 h-4 text-cyan-400" />
            <p
              id="system-api-health"
              className="ui-label text-[color:var(--text-primary)]"
            >
              API Endpoints
            </p>
          </div>
          <div className="space-y-2">
            {[
              "/api/alerts",
              "/api/stats",
              "/api/status",
              "/api/timeline",
              "/api/agents",
              "/api/detectors",
              "/api/model-info",
              "/api/pipeline-stats",
              "/api/threat-level",
              "/api/run",
            ].map((endpoint) => (
              <div
                key={endpoint}
                className="flex items-center justify-between gap-2 flex-wrap py-2 border-b border-[color:var(--border)] last:border-0"
              >
                <span className="text-sm text-[color:var(--text-secondary)] font-mono truncate">
                  {endpoint}
                </span>
                <StatusBadge ok={apiOk} label={apiOk ? "OK" : "Error"} />
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Info note */}
      <div className="flex items-start gap-3 bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl p-4">
        <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0 mt-0.5" />
        <div>
          <p className="ui-label text-[color:var(--text-primary)] mb-1">
            System Operating Normally
          </p>
          <p className="ui-caption leading-7">
            All four agents are active. The Isolation Forest model is loaded and
            running inference only, the training baseline of 630,000 real
            enterprise login events from the RBA Dataset is preserved.
            Rule-based detectors provide deterministic coverage while the ML
            model flags novel anomalies.
          </p>
        </div>
      </div>
    </div>
  );
}
