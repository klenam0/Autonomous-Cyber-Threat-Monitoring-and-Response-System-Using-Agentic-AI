import {
  Activity,
  AlertTriangle,
  Circle,
  XCircle,
  TrendingUp,
  Zap,
  Clock,
  Cpu,
} from "lucide-react";

function StatCard({ Icon, label, value, sub, trend, bg, iconColor }) {
  return (
    <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl p-3 min-w-0 shadow-[0_1px_0_rgba(15,23,42,0.02)]">
      <div className={`w-6 h-6 rounded-lg ${bg} grid place-items-center mb-2`}>
        <Icon className={`w-3.5 h-3.5 ${iconColor}`} />
      </div>
      <p className="text-xl font-bold text-[color:var(--text-primary)] leading-none mb-1">
        {value ?? "-"}
      </p>
      <p className="text-[10px] font-semibold text-[color:var(--text-secondary)] uppercase tracking-wide">
        {label}
      </p>
      <p className="text-[9px] text-[color:var(--text-muted)] mt-0.5">{sub}</p>
      {trend && (
        <p className="text-[9px] text-[color:var(--active)] mt-1">{trend}</p>
      )}
    </div>
  );
}

function AgentCard({
  name,
  role,
  processed,
  alerts: alertCount,
  queue,
  success,
}) {
  return (
    <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl p-4 shadow-[0_1px_0_rgba(15,23,42,0.02)]">
      <div className="flex items-start justify-between mb-3">
        <div>
          <p className="text-[12px] font-semibold text-[color:var(--text-primary)]">
            {name}
          </p>
          <p className="text-[10px] text-[color:var(--text-muted)]">{role}</p>
        </div>
        <div className="flex items-center gap-1.5 bg-[color:var(--accent-dim)] border border-green-500/20 rounded-full px-2 py-0.5">
          <div className="w-1.5 h-1.5 rounded-full bg-[color:var(--active)] animate-pulse" />
          <span className="text-[9px] text-[color:var(--active)] font-semibold">
            Active
          </span>
        </div>
      </div>
      <div className="grid grid-cols-2 gap-2">
        <div>
          <p className="text-[9px] text-[color:var(--text-muted)]">Processed</p>
          <p className="text-sm font-bold text-[color:var(--text-primary)]">
            {processed > 0 ? processed.toLocaleString() : "-"}
          </p>
        </div>
        <div>
          <p className="text-[9px] text-[color:var(--text-muted)]">Alerts</p>
          <p className="text-sm font-bold text-[color:var(--accent)]">
            {alertCount}
          </p>
        </div>
        <div>
          <p className="text-[9px] text-[color:var(--text-muted)]">Queue</p>
          <p className="text-sm font-bold text-[color:var(--text-primary)]">
            {queue}
          </p>
        </div>
        <div>
          <p className="text-[9px] text-[color:var(--text-muted)]">Success</p>
          <p className="text-sm font-bold text-[color:var(--active)]">
            {success}%
          </p>
        </div>
      </div>
    </div>
  );
}

function DetectorRow({ name, alerts: alertCount, last, isML }) {
  const label = name === "ML Anomaly Detected" ? "Isolation Forest ML" : name;
  return (
    <div className="flex items-center gap-3 py-2.5 border-b border-[color:var(--border)] last:border-0">
      <div
        className={`w-6 h-6 rounded-lg grid place-items-center flex-shrink-0 ${
          isML ? "bg-purple-500/20" : "bg-cyan-500/20"
        }`}
      >
        {isML ? (
          <span className="text-purple-400 text-[8px] font-black">ML</span>
        ) : (
          <div className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
        )}
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-1.5">
          <p className="text-[11px] font-medium text-[color:var(--text-primary)] truncate">
            {label}
          </p>
          {isML && (
            <span className="text-[8px] bg-purple-500/20 text-purple-400 border border-purple-500/30 rounded px-1 flex-shrink-0">
              ML
            </span>
          )}
        </div>
        <p className="text-[9px] text-[color:var(--text-muted)]">
          Last: {last}
        </p>
      </div>
      <div className="text-right flex-shrink-0">
        <p className="text-[11px] font-bold text-[color:var(--text-primary)]">
          {alertCount}
        </p>
        <p className="text-[9px] text-[color:var(--text-muted)]">alerts</p>
      </div>
    </div>
  );
}

function EventDot({ color }) {
  const c = {
    orange: "bg-orange-400",
    amber: "bg-amber-400",
    cyan: "bg-cyan-400",
    green: "bg-green-400",
    slate: "bg-slate-600",
  };
  return (
    <div
      className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${c[color] || c.slate}`}
    />
  );
}

function EventText({ color, children }) {
  const c = {
    orange: "text-orange-400",
    amber: "text-amber-400",
    cyan: "text-cyan-400",
    green: "text-green-400",
    slate: "text-slate-500",
  };
  return (
    <span className={`text-[11px] ${c[color] || c.slate}`}>{children}</span>
  );
}

export default function Dashboard({ data }) {
  const { alerts, stats, agentsData, detectors, modelInfo } = data;

  const total = stats?.total_alerts || 0;
  const high = stats?.severity_counts?.HIGH || 0;
  const medium = stats?.severity_counts?.MEDIUM || 0;
  const blocked = stats?.blocked_ips?.length || 0;
  const mlCount = alerts.filter((a) => a.type === "ML Anomaly Detected").length;

  const pipelineEvents = alerts
    .slice(0, 8)
    .flatMap((a) => [
      { color: "slate", text: `Event received: ${a.user} @ ${a.ip}` },
      { color: "orange", text: `${a.type} detected` },
      {
        color: "amber",
        text: `MITRE ${a.mitre?.technique_id || "-"} Severity: ${a.severity}`,
      },
      { color: "cyan", text: "Automated response triggered" },
    ])
    .slice(0, 10);

  const statCards = [
    {
      Icon: Activity,
      label: "Total Alerts",
      value: total,
      sub: "All severity levels",
      trend: total > 0 ? `↑ ${total} detected` : null,
      bg: "bg-blue-500/20",
      iconColor: "text-blue-400",
    },
    {
      Icon: AlertTriangle,
      label: "High Severity",
      value: high,
      sub: "Needs attention",
      trend: high > 0 ? "↑ Requires action" : "- Stable",
      bg: "bg-orange-500/20",
      iconColor: "text-orange-400",
    },
    {
      Icon: Circle,
      label: "Medium",
      value: medium,
      sub: "Under review",
      trend: "- Stable",
      bg: "bg-amber-500/20",
      iconColor: "text-amber-400",
    },
    {
      Icon: XCircle,
      label: "Blocked IPs",
      value: blocked,
      sub: "Auto-mitigated",
      trend: blocked > 0 ? `↑ ${blocked} blocked` : null,
      bg: "bg-red-500/20",
      iconColor: "text-red-400",
    },
    {
      Icon: TrendingUp,
      label: "Precision",
      value: modelInfo?.precision
        ? `${(modelInfo.precision * 100).toFixed(1)}%`
        : "-",
      sub: "ML true positive rate",
      trend: modelInfo
        ? `Recall: ${(modelInfo.recall * 100).toFixed(1)}%`
        : null,
      bg: "bg-green-500/20",
      iconColor: "text-green-400",
    },
    {
      Icon: Zap,
      label: "Responses",
      value: total,
      sub: "Auto-executed",
      trend: null,
      bg: "bg-cyan-500/20",
      iconColor: "text-cyan-400",
    },
    {
      Icon: Clock,
      label: "Last 24h",
      value: alerts.length,
      sub: "Rolling window",
      trend: null,
      bg: "bg-purple-500/20",
      iconColor: "text-purple-400",
    },
    {
      Icon: Cpu,
      label: "ML Anomalies",
      value: mlCount,
      sub: "Isolation Forest",
      trend: null,
      bg: "bg-pink-500/20",
      iconColor: "text-pink-400",
    },
  ];

  return (
    <div className="p-3 sm:p-5 space-y-4 sm:space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <p className="text-[11px] font-semibold text-[color:var(--text-secondary)] uppercase tracking-widest">
          SOC Overview
        </p>
        <div className="flex items-center gap-1.5">
          <div className="w-1.5 h-1.5 rounded-full bg-[color:var(--active)] animate-pulse" />
          <span className="text-[10px] text-[color:var(--active)]">Live</span>
        </div>
      </div>

      {/* Stat cards
          Mobile:  2 columns
          Tablet:  4 columns
          Desktop: 8 columns */}
      <div
        id="dashboard-metrics"
        className="grid grid-cols-2 sm:grid-cols-4 xl:grid-cols-8 gap-2"
      >
        {statCards.map((c) => (
          <StatCard key={c.label} {...c} />
        ))}
      </div>

      {/* Agent Pipeline + Detection Engine
          Mobile:  single column (stacked)
          Desktop: two columns side by side */}
      <div
        id="dashboard-pipeline"
        className="grid grid-cols-1 lg:grid-cols-2 gap-4 sm:gap-5"
      >
        {/* AI Agent Pipeline */}
        <div>
          <p className="text-[10px] font-semibold text-[color:var(--text-muted)] uppercase tracking-widest mb-3">
            AI Agent Pipeline
          </p>
          {agentsData.length === 0 ? (
            <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl p-8 text-center">
              <p className="text-[color:var(--text-muted)] text-sm">
                Run detection to see agent stats
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {agentsData.map((a) => (
                <AgentCard key={a.name} {...a} alertCount={a.alerts} />
              ))}
            </div>
          )}
        </div>

        {/* Detection Engine + Live Events */}
        <div className="space-y-3">
          <p className="text-[10px] font-semibold text-[color:var(--text-muted)] uppercase tracking-widest">
            Detection Engine
          </p>

          <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl px-4 py-2">
            {detectors.length === 0 ? (
              <p className="text-[11px] text-[color:var(--text-muted)] py-4 text-center">
                Run detection to see detector stats
              </p>
            ) : (
              detectors.map((d) => (
                <DetectorRow
                  key={d.name}
                  {...d}
                  isML={d.is_ml}
                  alertCount={d.alerts}
                />
              ))
            )}
          </div>

          {/* Live Pipeline Events */}
          <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl p-4">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-1.5 h-1.5 rounded-full bg-[color:var(--active)] animate-pulse" />
              <p className="text-[10px] font-semibold text-[color:var(--text-secondary)] uppercase tracking-widest">
                Live Pipeline Events
              </p>
            </div>
            {pipelineEvents.length === 0 ? (
              <p className="text-[11px] text-[color:var(--text-muted)]">
                No events yet - click ▶ Run to start
              </p>
            ) : (
              <div className="space-y-2">
                {pipelineEvents.map((e, i) => (
                  <div key={i} className="flex items-center gap-2">
                    <EventDot color={e.color} />
                    <EventText color={e.color}>{e.text}</EventText>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
