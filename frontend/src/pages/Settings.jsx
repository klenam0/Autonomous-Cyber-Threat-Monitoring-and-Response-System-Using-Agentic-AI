import { useState } from "react";
import {
  Save,
  Download,
  Trash2,
  Shield,
  Cpu,
  Mail,
  Activity,
  AlertTriangle,
} from "lucide-react";

const API = "http://localhost:5000/api";

function SettingRow({ label, description, children }) {
  return (
    <div className="flex items-start justify-between gap-3 py-3 border-b border-[#1e2a3d] last:border-0">
      <div className="flex-1 mr-2 sm:mr-6">
        <p className="text-[12px] font-semibold text-slate-200">{label}</p>
        <p className="text-[10px] text-slate-600 mt-0.5">{description}</p>
      </div>
      <div className="flex-shrink-0">{children}</div>
    </div>
  );
}

function SectionCard({ title, icon: Icon, iconColor, children }) {
  return (
    <div className="bg-[#0f1629] border border-[#1e2a3d] rounded-xl p-4">
      <div className="flex items-center gap-2 mb-4 pb-3 border-b border-[#1e2a3d]">
        <Icon className={`w-4 h-4 ${iconColor}`} />
        <p className="text-[12px] font-bold text-white">{title}</p>
      </div>
      {children}
    </div>
  );
}

function Toggle({ value, onChange }) {
  return (
    <button
      onClick={() => onChange(!value)}
      className={`relative w-10 h-5 rounded-full transition-colors ${
        value ? "bg-cyan-500" : "bg-slate-700"
      }`}
    >
      <div
        className={`absolute top-0.5 left-0.5 w-4 h-4 bg-white rounded-full transition-transform ${
          value ? "translate-x-5" : "translate-x-0"
        }`}
      />
    </button>
  );
}

function ValueBadge({ value, unit = "" }) {
  return (
    <span className="bg-[#0b1120] border border-[#1e2a3d] text-cyan-400 font-mono text-[11px] px-3 py-1 rounded-lg whitespace-nowrap">
      {value}
      {unit}
    </span>
  );
}

export default function Settings({ data }) {
  const { modelInfo } = data;

  const [emailEnabled, setEmailEnabled] = useState(true);
  const [emailHigh, setEmailHigh] = useState(true);
  const [emailMedium, setEmailMedium] = useState(false);
  const [mlEnabled, setMlEnabled] = useState(true);
  const [internalGuard, setInternalGuard] = useState(true);
  const [saved, setSaved] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [exporting, setExporting] = useState(false);

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const handleClearAlerts = async () => {
    if (!window.confirm("Clear all alerts? This cannot be undone.")) return;
    setClearing(true);
    try {
      await fetch(`${API}/clear-alerts`, {
        method: "POST",
        headers: {
          "X-Clear-Token":
            process.env.REACT_APP_CLEAR_TOKEN || "soc-clear-2026",
        },
      });
    } catch {}
    setClearing(false);
    window.location.reload();
  };

  const handleExport = async () => {
    setExporting(true);
    try {
      const r = await fetch(`${API}/alerts`);
      const alerts = await r.json();
      const csv = [
        [
          "Alert ID",
          "Type",
          "Severity",
          "IP",
          "User",
          "Detected At",
          "MITRE ID",
        ].join(","),
        ...alerts.map((a) =>
          [
            a.alert_id || "",
            a.type || "",
            a.severity || "",
            a.ip || "",
            a.user || "",
            a.detected_at || "",
            a.mitre?.technique_id || "",
          ].join(","),
        ),
      ].join("\n");

      const blob = new Blob([csv], { type: "text/csv" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `soc-alerts-${new Date().toISOString().split("T")[0]}.csv`;
      link.click();
      URL.revokeObjectURL(url);
    } catch {}
    setExporting(false);
  };

  const precision = modelInfo?.precision
    ? `${(modelInfo.precision * 100).toFixed(1)}%`
    : "-";
  const recall = modelInfo?.recall
    ? `${(modelInfo.recall * 100).toFixed(1)}%`
    : "-";
  const f1 = modelInfo?.f1 ? `${(modelInfo.f1 * 100).toFixed(1)}%` : "-";
  const rocAuc = modelInfo?.roc_auc ? modelInfo.roc_auc.toFixed(3) : "-";

  return (
    <div className="p-3 sm:p-5 space-y-4 sm:space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <p className="text-[11px] font-semibold text-slate-500 uppercase tracking-widest">
            Settings
          </p>
          <p className="text-[10px] text-slate-700 mt-0.5">
            System configuration and controls
          </p>
        </div>
        <button
          onClick={handleSave}
          className={`flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-[11px] font-bold transition-colors w-full sm:w-auto ${
            saved
              ? "bg-green-500/20 text-green-400 border border-green-500/30"
              : "bg-cyan-600 hover:bg-cyan-500 text-white"
          }`}
        >
          <Save className="w-3.5 h-3.5" />
          {saved ? "Saved!" : "Save Changes"}
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Detection Settings */}
        <SectionCard
          title="Detection Settings"
          icon={Shield}
          iconColor="text-cyan-400"
        >
          <SettingRow
            label="Brute Force Threshold"
            description="Number of failed logins before alert triggers"
          >
            <ValueBadge value="5" unit=" attempts" />
          </SettingRow>
          <SettingRow
            label="Slow Brute Force Window"
            description="Time window for slow brute force detection"
          >
            <ValueBadge value="60" unit=" minutes" />
          </SettingRow>
          <SettingRow
            label="Multiple IP Window"
            description="Time window for same-user multiple IP detection"
          >
            <ValueBadge value="120" unit=" seconds" />
          </SettingRow>
          <SettingRow
            label="Credential Stuffing Threshold"
            description="Unique usernames from one IP to trigger alert"
          >
            <ValueBadge value="5" unit=" usernames" />
          </SettingRow>
          <SettingRow
            label="Off-Hours Window"
            description="Hours considered suspicious for login activity"
          >
            <ValueBadge value="00:00 – 05:59" />
          </SettingRow>
          <SettingRow
            label="Internal IP Guard"
            description="Exclude internal IPs from ML scoring"
          >
            <Toggle value={internalGuard} onChange={setInternalGuard} />
          </SettingRow>
          <SettingRow
            label="Internal IP Ranges"
            description="Subnets treated as internal"
          >
            <ValueBadge value="192.168.x, 10.x, 172.16.x" />
          </SettingRow>
        </SectionCard>

        {/* ML Settings */}
        <SectionCard
          title="ML Model Settings"
          icon={Cpu}
          iconColor="text-purple-400"
        >
          <SettingRow
            label="ML Detection"
            description="Enable Isolation Forest anomaly detection"
          >
            <Toggle value={mlEnabled} onChange={setMlEnabled} />
          </SettingRow>
          <SettingRow
            label="Algorithm"
            description="Anomaly detection algorithm"
          >
            <ValueBadge value="Isolation Forest" />
          </SettingRow>
          <SettingRow
            label="Contamination"
            description="Expected anomaly rate in training data"
          >
            <ValueBadge value="0.15" />
          </SettingRow>
          <SettingRow
            label="N Estimators"
            description="Number of trees in the forest"
          >
            <ValueBadge value="200" unit=" trees" />
          </SettingRow>
          <SettingRow
            label="Feature Count"
            description="Input features used per event"
          >
            <ValueBadge
              value={modelInfo?.feature_count || "10"}
              unit=" features"
            />
          </SettingRow>
          <SettingRow
            label="Training Set"
            description="Events used to train the model"
          >
            <ValueBadge value="630,000" unit=" events" />
          </SettingRow>
          <SettingRow
            label="Inference Mode"
            description="Model never retrains on live data"
          >
            <ValueBadge value="Runtime only" />
          </SettingRow>

          {/* Eval metrics */}
          <div className="mt-3 pt-3 border-t border-[#1e2a3d]">
            <p className="text-[10px] text-slate-600 mb-2">
              Evaluation Metrics (RBA Dataset)
            </p>
            <div className="grid grid-cols-2 gap-2">
              {[
                {
                  label: "Precision",
                  value: precision,
                  color: "text-green-400",
                },
                { label: "Recall", value: recall, color: "text-amber-400" },
                { label: "F1-Score", value: f1, color: "text-cyan-400" },
                { label: "ROC-AUC", value: rocAuc, color: "text-purple-400" },
              ].map(({ label, value, color }) => (
                <div
                  key={label}
                  className="bg-[#0b1120] rounded-lg p-2 text-center"
                >
                  <p className={`text-sm font-bold ${color}`}>{value}</p>
                  <p className="text-[9px] text-slate-600">{label}</p>
                </div>
              ))}
            </div>
          </div>
        </SectionCard>

        {/* Email Settings */}
        <SectionCard
          title="Email Alerting"
          icon={Mail}
          iconColor="text-green-400"
        >
          <SettingRow
            label="Email Notifications"
            description="Send email alerts for detected threats"
          >
            <Toggle value={emailEnabled} onChange={setEmailEnabled} />
          </SettingRow>
          <SettingRow
            label="HIGH Severity Alerts"
            description="Email on HIGH severity detections"
          >
            <Toggle value={emailHigh} onChange={setEmailHigh} />
          </SettingRow>
          <SettingRow
            label="MEDIUM Severity Alerts"
            description="Email on MEDIUM severity detections"
          >
            <Toggle value={emailMedium} onChange={setEmailMedium} />
          </SettingRow>
          <SettingRow
            label="SMTP Provider"
            description="Email delivery service"
          >
            <ValueBadge value="Gmail SMTP" />
          </SettingRow>
          <SettingRow label="Port" description="SMTP connection port">
            <ValueBadge value="465 (SSL)" />
          </SettingRow>
          <SettingRow
            label="Credentials"
            description="Stored in backend .env file"
          >
            <ValueBadge value="App password" />
          </SettingRow>
        </SectionCard>

        {/* Pipeline Settings + Data Management */}
        <div className="space-y-4">
          <SectionCard
            title="Pipeline Settings"
            icon={Activity}
            iconColor="text-blue-400"
          >
            <SettingRow
              label="Event Delay"
              description="Seconds between processing each log event"
            >
              <ValueBadge value="0.1 – 1.0" unit="s" />
            </SettingRow>
            <SettingRow
              label="Log Source"
              description="Current log input format"
            >
              <ValueBadge value="Authentication logs" />
            </SettingRow>
            <SettingRow
              label="Pipeline Mode"
              description="How the system processes events"
            >
              <ValueBadge value="Sequential stream" />
            </SettingRow>
          </SectionCard>

          <SectionCard
            title="Data Management"
            icon={AlertTriangle}
            iconColor="text-amber-400"
          >
            <div className="space-y-3">
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <div>
                  <p className="text-[12px] font-semibold text-slate-200">
                    Export Alerts
                  </p>
                  <p className="text-[10px] text-slate-600 mt-0.5">
                    Download all alerts as CSV
                  </p>
                </div>
                <button
                  onClick={handleExport}
                  disabled={exporting}
                  className="flex items-center gap-1.5 bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-400 border border-cyan-500/30 text-[11px] font-semibold px-3 py-1.5 rounded-lg transition-colors disabled:opacity-50"
                >
                  <Download className="w-3.5 h-3.5" />
                  {exporting ? "Exporting..." : "Export CSV"}
                </button>
              </div>

              <div className="flex items-center justify-between gap-2 flex-wrap pt-2 border-t border-[#1e2a3d]">
                <div>
                  <p className="text-[12px] font-semibold text-red-400">
                    Clear All Alerts
                  </p>
                  <p className="text-[10px] text-slate-600 mt-0.5">
                    Permanently delete all saved alerts
                  </p>
                </div>
                <button
                  onClick={handleClearAlerts}
                  disabled={clearing}
                  className="flex items-center gap-1.5 bg-red-500/20 hover:bg-red-500/30 text-red-400 border border-red-500/30 text-[11px] font-semibold px-3 py-1.5 rounded-lg transition-colors disabled:opacity-50"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  {clearing ? "Clearing..." : "Clear Alerts"}
                </button>
              </div>
            </div>
          </SectionCard>
        </div>
      </div>

      {/* Note */}
      <div className="bg-[#0f1629] border border-amber-500/20 rounded-xl p-4">
        <div className="flex items-start gap-3">
          <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-[11px] font-semibold text-slate-300 mb-1">
              Configuration Note
            </p>
            <p className="text-[10px] text-slate-600 leading-relaxed">
              Detection thresholds and ML parameters shown here reflect the
              current system configuration. In this prototype, changes to these
              values require updating the Python source files and restarting the
              pipeline. A production system would persist these to a
              configuration database with live hot-reload capability. Email
              credentials are stored securely in the backend environment file
              and are never exposed to the frontend.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
