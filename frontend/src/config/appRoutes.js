import {
  Activity,
  BarChart3,
  Ban,
  Bell,
  FileText,
  LayoutDashboard,
  Mail,
  Settings,
  Shield,
  Target,
  Zap,
} from "lucide-react";

// This registry is the application's route configuration. Add a page or a
// searchable section here once; navigation and global search pick it up
// automatically.
export const appRoutes = [
  {
    id: "dashboard",
    title: "Dashboard",
    Icon: LayoutDashboard,
    description:
      "SOC overview, security metrics, agent pipeline, and detection status.",
    keywords: ["home", "overview", "metrics", "summary", "monitoring"],
    sections: [
      {
        id: "dashboard-metrics",
        title: "Security Metrics",
        description:
          "Alert totals, severity, blocked IPs, precision, and responses.",
        keywords: ["stats", "kpis", "total alerts"],
      },
      {
        id: "dashboard-pipeline",
        title: "AI Agent Pipeline",
        description: "Agent processing, queues, and live pipeline events.",
        keywords: ["agents", "detection engine", "events"],
      },
    ],
  },
  {
    id: "live-alerts",
    title: "Live Alerts",
    Icon: Bell,
    description:
      "Monitor current alerts, severity, MITRE techniques, and automated actions.",
    keywords: ["alerts", "incidents", "notifications", "threats", "real time"],
    sections: [
      {
        id: "live-alerts-feed",
        title: "Alert Feed",
        description: "Real-time alert list with severity filters.",
        keywords: ["high", "medium", "low", "filter"],
      },
      {
        id: "live-alerts-actions",
        title: "Recent Automated Actions",
        description: "Recently blocked IPs and notification actions.",
        keywords: ["response", "block", "email"],
      },
    ],
  },
  {
    id: "detection-engine",
    title: "Detection Engine",
    Icon: Shield,
    description: "Detection engine controls and detector configuration.",
    keywords: [
      "detectors",
      "rules",
      "anomaly detection",
      "machine learning",
      "ml",
    ],
  },
  {
    id: "mitre-mapping",
    title: "MITRE Mapping",
    Icon: Target,
    description: "Map detected threats to the MITRE ATT&CK framework.",
    keywords: ["attack", "techniques", "tactics", "framework", "mitre"],
    sections: [
      {
        id: "mitre-matrix",
        title: "MITRE ATT&CK Matrix",
        description: "Technique and tactic coverage for detected threats.",
        keywords: ["matrix", "coverage", "technique"],
      },
    ],
  },
  {
    id: "threat-analytics",
    title: "Threat Analytics",
    Icon: BarChart3,
    description: "Analyze threat patterns, trends, and security intelligence.",
    keywords: ["analytics", "reports", "trends", "reporting"],
  },
  {
    id: "response-actions",
    title: "Response Actions",
    Icon: Zap,
    description: "Review automated response activity and remediation actions.",
    keywords: [
      "respond",
      "remediation",
      "automation",
      "actions",
      "containment",
    ],
    sections: [
      {
        id: "response-timeline",
        title: "Response Timeline",
        description: "Timeline of detection and automated remediation.",
        keywords: ["history", "events", "activity"],
      },
    ],
  },
  {
    id: "blocked-ips",
    title: "Blocked IPs",
    Icon: Ban,
    description:
      "View and manage IP addresses automatically blocked by the platform.",
    keywords: ["blocked", "ip", "blacklist", "denylist", "firewall", "ban"],
    sections: [
      {
        id: "blocked-ip-list",
        title: "Blocked Address List",
        description: "IP addresses, block reasons, and enforcement status.",
        keywords: ["addresses", "blacklist", "rules"],
      },
    ],
  },
  {
    id: "email-alerts",
    title: "Email Alerts",
    Icon: Mail,
    description:
      "Configure and review email notifications for security events.",
    keywords: ["email", "notifications", "messages", "recipients"],
  },
  {
    id: "alert-log",
    title: "Alert Log",
    Icon: FileText,
    description:
      "Search the complete history of detected threats and analyses.",
    keywords: ["logs", "history", "records", "incidents", "audit"],
    sections: [
      {
        id: "alert-log-search",
        title: "Alert Log Search",
        description: "Search, filter, sort, and expand historical alerts.",
        keywords: ["find alert", "filter", "sort", "records"],
      },
    ],
  },
  {
    id: "system-health",
    title: "System Health",
    Icon: Activity,
    description: "Inspect agent, API, model, and pipeline health.",
    keywords: ["health", "status", "api", "uptime", "diagnostics"],
    sections: [
      {
        id: "system-api-health",
        title: "API Endpoints",
        description: "Health status for backend API endpoints.",
        keywords: ["api", "endpoints", "backend"],
      },
    ],
  },
  {
    id: "settings",
    title: "Settings",
    Icon: Settings,
    description: "Manage application preferences and configuration.",
    keywords: ["preferences", "configuration", "options", "theme"],
  },
];

export const searchableIndex = appRoutes.flatMap((route) => [
  { ...route, routeId: route.id, type: "page" },
  ...(route.sections || []).map((section) => ({
    ...route,
    ...section,
    routeId: route.id,
    pageTitle: route.title,
    type: "section",
  })),
]);
