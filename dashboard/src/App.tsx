import { useState, useEffect, useCallback } from "react";
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
  LineChart,
  Line,
} from "recharts";
import {
  Shield,
  Activity,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  ExternalLink,
  RefreshCw,
  LayoutDashboard,
  ListChecks,
  Play,
  Zap,
  Loader2,
  Terminal,
  X,
} from "lucide-react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Overview {
  total_scans: number;
  total_findings: number;
  open_issues: number;
  closed_issues: number;
  active_sessions: number;
  success_rate: number;
}

interface Metrics {
  overview: Overview;
  severity_breakdown: Record<string, number>;
  remediation_status: Record<string, number>;
  scan_history: ScanHistoryEntry[];
  recent_remediations: RemediationEntry[];
}

interface ScanHistoryEntry {
  scan_id: string;
  timestamp: string;
  total_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

interface RemediationEntry {
  finding_id: string;
  issue_number: number;
  issue_url: string;
  status: string;
  pr_url: string;
  fix_description: string;
  updated_at: string;
}

interface Issue {
  number: number;
  title: string;
  state: string;
  severity: string;
  scan_type: string;
  labels: string[];
  created_at: string;
  closed_at: string | null;
  url: string;
  has_remediation: boolean;
  remediation_failed: boolean;
}

interface Job {
  id: string;
  type: string;
  status: string;
  started_at: string;
  finished_at: string | null;
  result: Record<string, any> | null;
  error: string | null;
  logs: { time: string; message: string }[];
}

interface SimulateCategory {
  id: string;
  name: string;
  cwe_id: string;
  severity: string;
  pattern_count: number;
}

interface SimulateSession {
  bug_id: string;
  category: string;
  cwe_id: string;
  pattern_name: string;
  session_id: string;
  session_url: string;
  status: string;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
};

const REMEDIATION_COLORS: Record<string, string> = {
  fixed: "#22c55e",
  partial: "#3b82f6",
  failed: "#ef4444",
  in_progress: "#f97316",
  pending: "#6b7280",
};

const REFRESH_INTERVAL = 15_000;

type Tab = "overview" | "issues";

// ---------------------------------------------------------------------------
// Action button helper
// ---------------------------------------------------------------------------

async function triggerAction(endpoint: string): Promise<{ job_id: string } | null> {
  try {
    const res = await fetch(endpoint, { method: "POST" });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      alert(err.error || `Request failed: ${res.status}`);
      return null;
    }
    return await res.json();
  } catch (e) {
    alert(`Network error: ${e}`);
    return null;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function severityBadge(severity: string) {
  const colors: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border-red-500/30",
    high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    low: "bg-green-500/20 text-green-400 border-green-500/30",
  };
  return (
    <span
      className={`inline-block px-2 py-0.5 rounded text-xs font-semibold border ${colors[severity] ?? "bg-gray-700 text-gray-300 border-gray-600"}`}
    >
      {severity.toUpperCase()}
    </span>
  );
}

function formatDate(iso: string) {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

function statusIcon(status: string) {
  switch (status) {
    case "fixed":
      return <CheckCircle size={14} className="text-green-400" />;
    case "failed":
      return <XCircle size={14} className="text-red-400" />;
    case "in_progress":
      return <RefreshCw size={14} className="text-orange-400 animate-spin" />;
    case "partial":
      return <AlertTriangle size={14} className="text-blue-400" />;
    default:
      return <Clock size={14} className="text-gray-400" />;
  }
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

export default function App() {
  const [tab, setTab] = useState<Tab>("overview");
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [issues, setIssues] = useState<Issue[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const fetchData = useCallback(async () => {
    try {
      const [mRes, iRes, jRes] = await Promise.all([
        fetch("/api/metrics"),
        fetch("/api/issues"),
        fetch("/api/jobs"),
      ]);
      const mData = await mRes.json();
      const iData = await iRes.json();
      const jData = await jRes.json();
      setMetrics(mData);
      setIssues(iData.issues ?? []);
      setJobs(jData.jobs ?? []);
      setLastUpdated(new Date());
    } catch (err) {
      console.error("Failed to fetch dashboard data", err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const id = setInterval(fetchData, REFRESH_INTERVAL);
    return () => clearInterval(id);
  }, [fetchData]);

  // -- Simulate (Test Buggy PRs) state --------------------------------------
  const [showSimulate, setShowSimulate] = useState(false);
  const [simCategories, setSimCategories] = useState<SimulateCategory[]>([]);
  const [simSelected, setSimSelected] = useState<string[]>([]);
  const [simCount, setSimCount] = useState(1);
  const [simLoading, setSimLoading] = useState(false);
  const [simResult, setSimResult] = useState<{
    message: string;
    sessions: SimulateSession[];
  } | null>(null);

  const openSimulateModal = async () => {
    setShowSimulate(true);
    setSimResult(null);
    setSimLoading(false);
    try {
      const res = await fetch("/api/simulate/categories");
      const data = await res.json();
      setSimCategories(data.categories ?? []);
    } catch {
      setSimCategories([]);
    }
  };

  const runSimulation = async () => {
    setSimLoading(true);
    setSimResult(null);
    try {
      const res = await fetch("/api/simulate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          count: simCount,
          categories: simSelected.length > 0 ? simSelected : undefined,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setSimResult({ message: data.error || "Failed", sessions: [] });
      } else {
        setSimResult({ message: data.message, sessions: data.sessions ?? [] });
      }
    } catch (e) {
      setSimResult({ message: `Network error: ${e}`, sessions: [] });
    } finally {
      setSimLoading(false);
    }
  };

  const handleScan = async () => {
    await triggerAction("/api/scan");
    setTimeout(fetchData, 1000);
  };

  const handleOrchestrate = async () => {
    await triggerAction("/api/orchestrate");
    setTimeout(fetchData, 1000);
  };

  // -- Tab buttons ----------------------------------------------------------

  const tabButton = (t: Tab, label: string, Icon: React.ElementType) => (
    <button
      key={t}
      onClick={() => setTab(t)}
      className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
        tab === t
          ? "bg-indigo-600 text-white shadow-lg shadow-indigo-500/20"
          : "text-gray-400 hover:text-gray-200 hover:bg-gray-800"
      }`}
    >
      <Icon size={16} />
      {label}
    </button>
  );

  // =========================================================================
  // RENDER
  // =========================================================================

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      {/* Header */}
      <header className="border-b border-gray-800 bg-gray-900/80 backdrop-blur sticky top-0 z-30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="text-indigo-400" size={28} />
            <div>
              <h1 className="text-lg font-bold tracking-tight">
                Vulnerability Remediation System
              </h1>
              <p className="text-xs text-gray-500">
                Observability Dashboard &mdash; ishi-gupta/superset
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <ActionButton
              label="Run Scanner"
              icon={<Play size={14} />}
              onClick={handleScan}
              color="emerald"
              jobs={jobs}
              jobType="scan"
            />
            <ActionButton
              label="Trigger Remediation"
              icon={<Zap size={14} />}
              onClick={handleOrchestrate}
              color="blue"
              jobs={jobs}
              jobType="orchestrate"
            />

            <button
              onClick={openSimulateModal}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white text-sm font-medium transition-colors shadow-lg shadow-red-500/20"
            >
              <Zap size={16} />
              Test Buggy PRs
            </button>

            <div className="w-px h-6 bg-gray-700 mx-1" />
            {lastUpdated && (
              <span className="text-xs text-gray-500">
                Updated {lastUpdated.toLocaleTimeString()}
              </span>
            )}
            <button
              onClick={fetchData}
              className="p-2 rounded-lg hover:bg-gray-800 text-gray-400 hover:text-gray-200 transition-colors"
              title="Refresh now"
            >
              <RefreshCw size={16} />
            </button>
          </div>
        </div>
      </header>

      {/* Tabs */}
      <nav className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-6 flex gap-2">
        {tabButton("overview", "Overview", LayoutDashboard)}
        {tabButton("issues", "Issues", ListChecks)}

      </nav>

      {/* Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {loading ? (
          <div className="flex items-center justify-center h-64">
            <RefreshCw className="animate-spin text-indigo-400" size={32} />
          </div>
        ) : (
          <>
            {/* Active Jobs Panel */}
            {jobs.length > 0 && <JobsPanel jobs={jobs} />}

            {tab === "overview" && metrics && <OverviewTab metrics={metrics} />}
            {tab === "issues" && <IssuesTab issues={issues} />}

          </>
        )}
      </main>

      {/* Simulate Modal */}
      {showSimulate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-gray-900 border border-gray-700 rounded-2xl shadow-2xl w-full max-w-lg mx-4 p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-bold">Test Buggy PRs</h2>
              <button
                onClick={() => setShowSimulate(false)}
                className="p-1 rounded hover:bg-gray-800 text-gray-400 hover:text-gray-200"
              >
                <X size={18} />
              </button>
            </div>
            <p className="text-sm text-gray-400 mb-4">
              Spawn baby Devin sessions that act as careless engineers, pushing
              intentionally vulnerable code to trigger the scan → issue → remediation cycle.
            </p>

            {/* Category selector */}
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Vulnerability Categories
              </label>
              <div className="flex flex-wrap gap-2">
                {simCategories.map((cat) => (
                  <button
                    key={cat.id}
                    onClick={() =>
                      setSimSelected((prev) =>
                        prev.includes(cat.id)
                          ? prev.filter((c) => c !== cat.id)
                          : [...prev, cat.id]
                      )
                    }
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                      simSelected.includes(cat.id)
                        ? "bg-indigo-600 border-indigo-500 text-white"
                        : "bg-gray-800 border-gray-700 text-gray-300 hover:border-gray-500"
                    }`}
                  >
                    {cat.name} ({cat.cwe_id})
                  </button>
                ))}
              </div>
              {simSelected.length === 0 && (
                <p className="text-xs text-gray-500 mt-1">
                  None selected — a random category will be chosen
                </p>
              )}
            </div>

            {/* Count */}
            <div className="mb-5">
              <label className="block text-sm font-medium text-gray-300 mb-1">
                Number of buggy PRs
              </label>
              <input
                type="number"
                min={1}
                max={5}
                value={simCount}
                onChange={(e) => setSimCount(Number(e.target.value) || 1)}
                className="w-20 px-3 py-1.5 rounded-lg bg-gray-800 border border-gray-700 text-gray-100 text-sm"
              />
            </div>

            {/* Launch */}
            <button
              disabled={simLoading}
              onClick={runSimulation}
              className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white text-sm font-medium transition-colors"
            >
              {simLoading ? (
                <>
                  <Loader2 size={16} className="animate-spin" /> Spawning…
                </>
              ) : (
                <>
                  <Zap size={16} /> Launch Buggy PRs
                </>
              )}
            </button>

            {/* Result */}
            {simResult && (
              <div className="mt-4 p-3 rounded-lg bg-gray-800 border border-gray-700">
                <p className="text-sm font-medium text-gray-200 mb-2">
                  {simResult.message}
                </p>
                {simResult.sessions.length > 0 && (
                  <ul className="space-y-1">
                    {simResult.sessions.map((s) => (
                      <li
                        key={s.bug_id}
                        className="text-xs text-gray-400 flex items-center gap-2"
                      >
                        <span
                          className={`w-2 h-2 rounded-full ${
                            s.status === "spawned"
                              ? "bg-green-400"
                              : "bg-red-400"
                          }`}
                        />
                        <span className="text-gray-300">{s.pattern_name}</span>
                        {s.session_url && (
                          <a
                            href={s.session_url}
                            target="_blank"
                            rel="noreferrer"
                            className="text-indigo-400 hover:underline ml-auto"
                          >
                            View session
                          </a>
                        )}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ===========================================================================
// OVERVIEW TAB
// ===========================================================================

function OverviewTab({ metrics }: { metrics: Metrics }) {
  const { overview, severity_breakdown, remediation_status, scan_history, recent_remediations } =
    metrics;

  const sevData = Object.entries(severity_breakdown).map(([name, value]) => ({
    name: name.charAt(0).toUpperCase() + name.slice(1),
    value,
    fill: SEVERITY_COLORS[name],
  }));

  const remData = Object.entries(remediation_status).map(([name, value]) => ({
    name: name.replace("_", " ").replace(/\b\w/g, (c) => c.toUpperCase()),
    value,
    fill: REMEDIATION_COLORS[name],
  }));

  return (
    <div className="space-y-6">
      {/* Stat cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <StatCard
          title="Total Discovered"
          value={overview.total_findings}
          icon={<Shield size={20} className="text-purple-400" />}
          accent="border-purple-500/40"
        />
        <StatCard
          title="Open Issues"
          value={overview.open_issues}
          icon={<AlertTriangle size={20} className="text-red-400" />}
          accent="border-red-500/40"
        />
        <StatCard
          title="Closed (Fixed)"
          value={overview.closed_issues}
          icon={<CheckCircle size={20} className="text-green-400" />}
          accent="border-green-500/40"
        />
        <StatCard
          title="Active Sessions"
          value={overview.active_sessions}
          icon={<Activity size={20} className="text-blue-400" />}
          accent="border-blue-500/40"
        />
        <StatCard
          title="Success Rate"
          value={`${overview.success_rate}%`}
          icon={<CheckCircle size={20} className="text-emerald-400" />}
          accent="border-emerald-500/40"
        />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity pie */}
        <Card title="Severity Breakdown">
          {sevData.every((d) => d.value === 0) ? (
            <EmptyState message="No findings recorded yet" />
          ) : (
            <ResponsiveContainer width="100%" height={260}>
              <PieChart>
                <Pie
                  data={sevData}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={95}
                  paddingAngle={3}
                  dataKey="value"
                  label={({ name, value }) => `${name}: ${value}`}
                  labelLine={false}
                >
                  {sevData.map((entry, i) => (
                    <Cell key={i} fill={entry.fill} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#1f2937",
                    border: "1px solid #374151",
                    borderRadius: "8px",
                  }}
                />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          )}
        </Card>

        {/* Remediation bar */}
        <Card title="Remediation Status">
          {remData.every((d) => d.value === 0) ? (
            <EmptyState message="No remediations tracked yet" />
          ) : (
            <ResponsiveContainer width="100%" height={260}>
              <BarChart data={remData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="name" tick={{ fill: "#9ca3af", fontSize: 12 }} />
                <YAxis tick={{ fill: "#9ca3af", fontSize: 12 }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#1f2937",
                    border: "1px solid #374151",
                    borderRadius: "8px",
                  }}
                />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {remData.map((entry, i) => (
                    <Cell key={i} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </Card>
      </div>

      {/* Scan history */}
      <Card title="Scan History">
        {scan_history.length === 0 ? (
          <EmptyState message="No scans have been run yet" />
        ) : (
          <ResponsiveContainer width="100%" height={260}>
            <LineChart data={scan_history}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis
                dataKey="timestamp"
                tick={{ fill: "#9ca3af", fontSize: 12 }}
                tickFormatter={(v: string) =>
                  new Date(v).toLocaleDateString("en-US", { month: "short", day: "numeric" })
                }
              />
              <YAxis tick={{ fill: "#9ca3af", fontSize: 12 }} />
              <Tooltip
                contentStyle={{
                  backgroundColor: "#1f2937",
                  border: "1px solid #374151",
                  borderRadius: "8px",
                }}
                labelFormatter={(v: string) => new Date(v).toLocaleString()}
              />
              <Legend />
              <Line type="monotone" dataKey="critical" stroke="#ef4444" strokeWidth={2} dot={{ r: 3 }} />
              <Line type="monotone" dataKey="high" stroke="#f97316" strokeWidth={2} dot={{ r: 3 }} />
              <Line type="monotone" dataKey="medium" stroke="#eab308" strokeWidth={2} dot={{ r: 3 }} />
              <Line type="monotone" dataKey="low" stroke="#22c55e" strokeWidth={2} dot={{ r: 3 }} />
            </LineChart>
          </ResponsiveContainer>
        )}
      </Card>

      {/* Recent remediations table */}
      <Card title="Recent Remediations">
        {recent_remediations.length === 0 ? (
          <EmptyState message="No remediations recorded yet" />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-gray-400 border-b border-gray-800">
                  <th className="text-left py-2 px-3 font-medium">Issue</th>
                  <th className="text-left py-2 px-3 font-medium">Status</th>
                  <th className="text-left py-2 px-3 font-medium">Description</th>
                  <th className="text-left py-2 px-3 font-medium">PR</th>
                  <th className="text-left py-2 px-3 font-medium">Updated</th>
                </tr>
              </thead>
              <tbody>
                {recent_remediations.map((r, i) => (
                  <tr key={i} className="border-b border-gray-800/50 hover:bg-gray-900/50">
                    <td className="py-2 px-3">
                      {r.issue_url ? (
                        <a
                          href={r.issue_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-indigo-400 hover:underline"
                        >
                          #{r.issue_number}
                        </a>
                      ) : (
                        `#${r.issue_number}`
                      )}
                    </td>
                    <td className="py-2 px-3">
                      <span className="flex items-center gap-1.5">
                        {statusIcon(r.status)}
                        {r.status.replace("_", " ")}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-gray-400 max-w-xs truncate">
                      {r.fix_description || "—"}
                    </td>
                    <td className="py-2 px-3">
                      {r.pr_url ? (
                        <a
                          href={r.pr_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-indigo-400 hover:underline flex items-center gap-1"
                        >
                          PR <ExternalLink size={12} />
                        </a>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td className="py-2 px-3 text-gray-500">{formatDate(r.updated_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}

// ===========================================================================
// ISSUES TAB
// ===========================================================================

function IssuesTab({ issues }: { issues: Issue[] }) {
  return (
    <Card title={`GitHub Issues (${issues.length})`}>
      {issues.length === 0 ? (
        <EmptyState message="No security issues found. Run a scan or check your GITHUB_TOKEN." />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-400 border-b border-gray-800">
                <th className="text-left py-2 px-3 font-medium">#</th>
                <th className="text-left py-2 px-3 font-medium">Title</th>
                <th className="text-left py-2 px-3 font-medium">Severity</th>
                <th className="text-left py-2 px-3 font-medium">Type</th>
                <th className="text-left py-2 px-3 font-medium">Status</th>
                <th className="text-left py-2 px-3 font-medium">Remediation</th>
                <th className="text-left py-2 px-3 font-medium">Created</th>
              </tr>
            </thead>
            <tbody>
              {issues.map((issue) => (
                <tr
                  key={issue.number}
                  className="border-b border-gray-800/50 hover:bg-gray-900/50"
                >
                  <td className="py-2 px-3">
                    <a
                      href={issue.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-indigo-400 hover:underline font-medium"
                    >
                      {issue.number}
                    </a>
                  </td>
                  <td className="py-2 px-3 max-w-md truncate" title={issue.title}>
                    {issue.title}
                  </td>
                  <td className="py-2 px-3">{severityBadge(issue.severity)}</td>
                  <td className="py-2 px-3">
                    <span className="text-xs text-gray-400 bg-gray-800 px-2 py-0.5 rounded">
                      {issue.scan_type}
                    </span>
                  </td>
                  <td className="py-2 px-3">
                    <span
                      className={`inline-flex items-center gap-1 text-xs font-medium ${
                        issue.state === "open" ? "text-green-400" : "text-gray-500"
                      }`}
                    >
                      <span
                        className={`w-2 h-2 rounded-full ${
                          issue.state === "open" ? "bg-green-400" : "bg-gray-500"
                        }`}
                      />
                      {issue.state}
                    </span>
                  </td>
                  <td className="py-2 px-3">
                    {issue.remediation_failed ? (
                      <span className="text-red-400 text-xs flex items-center gap-1">
                        <XCircle size={12} /> Failed
                      </span>
                    ) : issue.has_remediation ? (
                      <span className="text-blue-400 text-xs flex items-center gap-1">
                        <RefreshCw size={12} /> In progress
                      </span>
                    ) : (
                      <span className="text-gray-500 text-xs">—</span>
                    )}
                  </td>
                  <td className="py-2 px-3 text-gray-500 text-xs whitespace-nowrap">
                    {formatDate(issue.created_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

// ===========================================================================
// Shared Components
// ===========================================================================

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
      <div className="px-5 py-3 border-b border-gray-800">
        <h3 className="text-sm font-semibold text-gray-300">{title}</h3>
      </div>
      <div className="p-5">{children}</div>
    </div>
  );
}

function StatCard({
  title,
  value,
  icon,
  accent,
}: {
  title: string;
  value: string | number;
  icon: React.ReactNode;
  accent: string;
}) {
  return (
    <div
      className={`bg-gray-900 border border-gray-800 rounded-xl p-5 flex items-center gap-4 border-l-4 ${accent}`}
    >
      <div className="p-2 rounded-lg bg-gray-800/60">{icon}</div>
      <div>
        <p className="text-2xl font-bold">{value}</p>
        <p className="text-xs text-gray-500">{title}</p>
      </div>
    </div>
  );
}

function EmptyState({ message }: { message: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-12 text-gray-500">
      <Activity size={32} className="mb-3 text-gray-600" />
      <p className="text-sm">{message}</p>
    </div>
  );
}

// ===========================================================================
// ACTION BUTTON
// ===========================================================================

function ActionButton({
  label,
  icon,
  onClick,
  color,
  jobs,
  jobType,
}: {
  label: string;
  icon: React.ReactNode;
  onClick: () => void;
  color: "emerald" | "blue" | "orange";
  jobs: Job[];
  jobType: string;
}) {
  const running = jobs.some((j) => j.type === jobType && j.status === "running");

  const colorClasses: Record<string, string> = {
    emerald: "bg-emerald-600 hover:bg-emerald-500 shadow-emerald-500/20",
    blue: "bg-blue-600 hover:bg-blue-500 shadow-blue-500/20",
    orange: "bg-orange-600 hover:bg-orange-500 shadow-orange-500/20",
  };

  return (
    <button
      onClick={onClick}
      disabled={running}
      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-white transition-all shadow-lg ${
        running
          ? "bg-gray-700 cursor-not-allowed opacity-60"
          : colorClasses[color]
      }`}
    >
      {running ? <Loader2 size={14} className="animate-spin" /> : icon}
      {running ? `${label}...` : label}
    </button>
  );
}

// ===========================================================================
// JOBS PANEL
// ===========================================================================

function JobsPanel({ jobs }: { jobs: Job[] }) {
  const [expanded, setExpanded] = useState<string | null>(null);

  const sortedJobs = [...jobs].sort(
    (a, b) => new Date(b.started_at).getTime() - new Date(a.started_at).getTime()
  );

  const jobTypeLabel: Record<string, string> = {
    scan: "Scanner",
    orchestrate: "Remediation",

  };

  const jobStatusBadge = (status: string) => {
    const styles: Record<string, string> = {
      running: "bg-blue-500/20 text-blue-400 border-blue-500/30",
      completed: "bg-green-500/20 text-green-400 border-green-500/30",
      failed: "bg-red-500/20 text-red-400 border-red-500/30",
    };
    return (
      <span
        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold border ${
          styles[status] ?? "bg-gray-700 text-gray-300 border-gray-600"
        }`}
      >
        {status === "running" && <Loader2 size={10} className="animate-spin" />}
        {status === "completed" && <CheckCircle size={10} />}
        {status === "failed" && <XCircle size={10} />}
        {status}
      </span>
    );
  };

  return (
    <div className="mb-6">
      <Card title="Background Jobs">
        <div className="space-y-2">
          {sortedJobs.map((job) => (
            <div
              key={job.id}
              className="border border-gray-800 rounded-lg overflow-hidden"
            >
              <button
                className="w-full flex items-center justify-between px-4 py-2.5 hover:bg-gray-800/50 transition-colors text-left"
                onClick={() => setExpanded(expanded === job.id ? null : job.id)}
              >
                <div className="flex items-center gap-3">
                  <Terminal size={14} className="text-gray-500" />
                  <span className="text-sm font-medium">
                    {jobTypeLabel[job.type] ?? job.type}
                  </span>
                  {jobStatusBadge(job.status)}
                </div>
                <span className="text-xs text-gray-500">
                  {new Date(job.started_at).toLocaleTimeString()}
                </span>
              </button>

              {expanded === job.id && (
                <div className="border-t border-gray-800 bg-gray-950 px-4 py-3 space-y-2">
                  {/* Result summary */}
                  {job.result && (
                    <div className="flex flex-wrap gap-2">
                      {Object.entries(job.result).map(([k, v]) => (
                        <span
                          key={k}
                          className="text-xs bg-gray-800 px-2 py-1 rounded text-gray-300"
                        >
                          <span className="text-gray-500">
                            {k.replace(/_/g, " ")}:
                          </span>{" "}
                          {typeof v === "string" && v.startsWith("http") ? (
                            <a
                              href={v}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-indigo-400 hover:underline"
                            >
                              link
                            </a>
                          ) : (
                            String(v)
                          )}
                        </span>
                      ))}
                    </div>
                  )}

                  {/* Error */}
                  {job.error && (
                    <div className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded px-3 py-2">
                      {job.error}
                    </div>
                  )}

                  {/* Logs */}
                  {job.logs.length > 0 && (
                    <div className="bg-gray-900 rounded border border-gray-800 p-3 max-h-48 overflow-y-auto font-mono text-xs space-y-0.5">
                      {job.logs.map((log, i) => (
                        <div key={i} className="flex gap-2">
                          <span className="text-gray-600 shrink-0">
                            {new Date(log.time).toLocaleTimeString()}
                          </span>
                          <span className="text-gray-300">{log.message}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
