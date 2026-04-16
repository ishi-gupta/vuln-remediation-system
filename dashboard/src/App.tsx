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
  Bug,
  FlaskConical,
  LayoutDashboard,
  ListChecks,
  Zap,
  Loader2,
  X,
} from "lucide-react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Overview {
  total_scans: number;
  total_findings: number;
  issues_created: number;
  active_sessions: number;
  success_rate: number;
}

interface Metrics {
  overview: Overview;
  severity_breakdown: Record<string, number>;
  remediation_status: Record<string, number>;
  scan_history: ScanHistoryEntry[];
  recent_remediations: RemediationEntry[];
  adversarial_results: AdversarialResults | Record<string, never>;
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

interface AdversarialCategory {
  name: string;
  total: number;
  detected: number;
  missed: number;
  rate: number;
}

interface AdversarialResults {
  overall_detection_rate?: number;
  categories?: AdversarialCategory[];
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

type Tab = "overview" | "issues" | "adversarial";

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
  const [adversarial, setAdversarial] = useState<{
    message?: string;
    results: AdversarialResults | Record<string, never>;
  } | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  // Simulate modal state
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
    setSimSelected([]);
    setSimCount(1);
    try {
      const res = await fetch("/api/simulate/categories");
      const data = await res.json();
      setSimCategories(data.categories ?? []);
    } catch (err) {
      console.error("Failed to fetch categories", err);
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
          categories: simSelected.length > 0 ? simSelected : null,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setSimResult({ message: data.error || "Failed to simulate", sessions: [] });
      } else {
        setSimResult({ message: data.message, sessions: data.sessions ?? [] });
      }
    } catch (err) {
      setSimResult({ message: "Network error — is the backend running?", sessions: [] });
    } finally {
      setSimLoading(false);
    }
  };

  const fetchData = useCallback(async () => {
    try {
      const [mRes, iRes, aRes] = await Promise.all([
        fetch("/api/metrics"),
        fetch("/api/issues"),
        fetch("/api/adversarial"),
      ]);
      const mData = await mRes.json();
      const iData = await iRes.json();
      const aData = await aRes.json();
      setMetrics(mData);
      setIssues(iData.issues ?? []);
      setAdversarial(aData);
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

          <div className="flex items-center gap-4">
            <button
              onClick={openSimulateModal}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white text-sm font-medium transition-colors shadow-lg shadow-red-500/20"
            >
              <Zap size={16} />
              Test Buggy PRs
            </button>
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
        {tabButton("adversarial", "Adversarial Testing", FlaskConical)}
      </nav>

      {/* Simulate Modal */}
      {showSimulate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-gray-900 border border-gray-700 rounded-2xl shadow-2xl w-full max-w-lg mx-4 overflow-hidden">
            {/* Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800">
              <div className="flex items-center gap-2">
                <Zap size={20} className="text-red-400" />
                <h2 className="text-lg font-bold">Test Buggy PRs</h2>
              </div>
              <button
                onClick={() => setShowSimulate(false)}
                className="p-1 rounded hover:bg-gray-800 text-gray-400 hover:text-gray-200"
              >
                <X size={18} />
              </button>
            </div>

            <div className="px-6 py-5 space-y-5">
              <p className="text-sm text-gray-400">
                Spawn baby Devin sessions that act as careless engineers, pushing
                intentionally vulnerable code to Superset. This triggers the full
                cycle: scan &rarr; issues &rarr; remediation.
              </p>

              {/* Count */}
              <div>
                <label className="block text-xs font-medium text-gray-400 mb-1">
                  Number of buggy PRs
                </label>
                <input
                  type="number"
                  min={1}
                  max={5}
                  value={simCount}
                  onChange={(e) => setSimCount(Math.max(1, Math.min(10, Number(e.target.value))))}
                  className="w-24 px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm focus:outline-none focus:border-indigo-500"
                />
              </div>

              {/* Categories */}
              <div>
                <label className="block text-xs font-medium text-gray-400 mb-2">
                  Vulnerability categories{" "}
                  <span className="text-gray-600">(leave empty for random mix)</span>
                </label>
                <div className="flex flex-wrap gap-2">
                  {simCategories.map((cat) => {
                    const selected = simSelected.includes(cat.id);
                    return (
                      <button
                        key={cat.id}
                        onClick={() =>
                          setSimSelected((prev) =>
                            selected
                              ? prev.filter((c) => c !== cat.id)
                              : [...prev, cat.id]
                          )
                        }
                        className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                          selected
                            ? "bg-indigo-600/30 border-indigo-500 text-indigo-300"
                            : "bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-600"
                        }`}
                      >
                        {cat.name} ({cat.cwe_id})
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Result */}
              {simResult && (
                <div className="bg-gray-800/60 border border-gray-700 rounded-lg p-4">
                  <p className="text-sm font-medium mb-2">{simResult.message}</p>
                  {simResult.sessions.length > 0 && (
                    <div className="space-y-1.5 max-h-48 overflow-y-auto">
                      {simResult.sessions.map((s, i) => (
                        <div
                          key={i}
                          className="flex items-center justify-between text-xs"
                        >
                          <span className="text-gray-400">
                            {s.category.replace("_", " ")} &middot;{" "}
                            {s.pattern_name}
                          </span>
                          {s.session_url ? (
                            <a
                              href={s.session_url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-indigo-400 hover:underline flex items-center gap-1"
                            >
                              Session <ExternalLink size={10} />
                            </a>
                          ) : (
                            <span className="text-red-400">failed</span>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Actions */}
              <div className="flex justify-end gap-3">
                <button
                  onClick={() => setShowSimulate(false)}
                  className="px-4 py-2 text-sm text-gray-400 hover:text-gray-200 transition-colors"
                >
                  Close
                </button>
                <button
                  onClick={runSimulation}
                  disabled={simLoading}
                  className="flex items-center gap-2 px-5 py-2 rounded-lg bg-red-600 hover:bg-red-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium transition-colors"
                >
                  {simLoading ? (
                    <>
                      <Loader2 size={14} className="animate-spin" />
                      Spawning&hellip;
                    </>
                  ) : (
                    <>
                      <Bug size={14} />
                      Launch Buggy PRs
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {loading ? (
          <div className="flex items-center justify-center h-64">
            <RefreshCw className="animate-spin text-indigo-400" size={32} />
          </div>
        ) : (
          <>
            {tab === "overview" && metrics && <OverviewTab metrics={metrics} />}
            {tab === "issues" && <IssuesTab issues={issues} />}
            {tab === "adversarial" && (
              <AdversarialTab data={adversarial} />
            )}
          </>
        )}
      </main>
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
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Findings"
          value={overview.total_findings}
          icon={<Bug size={20} className="text-red-400" />}
          accent="border-red-500/40"
        />
        <StatCard
          title="Issues Created"
          value={overview.issues_created}
          icon={<AlertTriangle size={20} className="text-orange-400" />}
          accent="border-orange-500/40"
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
          icon={<CheckCircle size={20} className="text-green-400" />}
          accent="border-green-500/40"
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
// ADVERSARIAL TAB
// ===========================================================================

function AdversarialTab({
  data,
}: {
  data: { message?: string; results: AdversarialResults | Record<string, never> } | null;
}) {
  if (!data) return null;

  const results = data.results as AdversarialResults;
  const hasResults =
    results &&
    typeof results.overall_detection_rate === "number" &&
    Array.isArray(results.categories);

  if (!hasResults) {
    return (
      <Card title="Adversarial Testing">
        <div className="flex flex-col items-center justify-center py-16 text-gray-500">
          <FlaskConical size={48} className="mb-4 text-gray-600" />
          <p className="text-lg font-medium text-gray-400">No Results Yet</p>
          <p className="mt-1 text-sm">
            {data.message ||
              "Run the adversarial test suite (ishi-gupta/vuln-test-suite) to generate detection results."}
          </p>
        </div>
      </Card>
    );
  }

  const rate = results.overall_detection_rate! * 100;
  const categories = results.categories!;

  const chartData = categories.map((c) => ({
    name: c.name,
    "Detection %": Math.round(c.rate * 100),
    Detected: c.detected,
    Missed: c.missed,
  }));

  return (
    <div className="space-y-6">
      {/* Big detection rate */}
      <Card title="Overall Detection Rate">
        <div className="flex items-center justify-center py-8">
          <div className="text-center">
            <div
              className={`text-6xl font-bold ${
                rate >= 80 ? "text-green-400" : rate >= 60 ? "text-yellow-400" : "text-red-400"
              }`}
            >
              {rate.toFixed(0)}%
            </div>
            <p className="text-gray-400 mt-2 text-sm">
              of planted vulnerabilities were detected by the scanner
            </p>
          </div>
        </div>
      </Card>

      {/* Detection by category chart */}
      <Card title="Detection Rate by Category">
        <ResponsiveContainer width="100%" height={320}>
          <BarChart data={chartData} layout="vertical">
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
            <XAxis
              type="number"
              domain={[0, 100]}
              tick={{ fill: "#9ca3af", fontSize: 12 }}
              tickFormatter={(v: number) => `${v}%`}
            />
            <YAxis
              type="category"
              dataKey="name"
              tick={{ fill: "#9ca3af", fontSize: 12 }}
              width={150}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: "#1f2937",
                border: "1px solid #374151",
                borderRadius: "8px",
              }}
              formatter={(value: number, name: string) =>
                name === "Detection %" ? `${value}%` : value
              }
            />
            <Bar dataKey="Detection %" radius={[0, 4, 4, 0]} fill="#6366f1" />
          </BarChart>
        </ResponsiveContainer>
      </Card>

      {/* Detail table */}
      <Card title="Category Breakdown">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-400 border-b border-gray-800">
                <th className="text-left py-2 px-3 font-medium">Category</th>
                <th className="text-right py-2 px-3 font-medium">Total Planted</th>
                <th className="text-right py-2 px-3 font-medium">Detected</th>
                <th className="text-right py-2 px-3 font-medium">Missed</th>
                <th className="text-right py-2 px-3 font-medium">Detection %</th>
              </tr>
            </thead>
            <tbody>
              {categories.map((c, i) => {
                const pct = Math.round(c.rate * 100);
                return (
                  <tr key={i} className="border-b border-gray-800/50 hover:bg-gray-900/50">
                    <td className="py-2 px-3 font-medium">{c.name}</td>
                    <td className="py-2 px-3 text-right text-gray-400">{c.total}</td>
                    <td className="py-2 px-3 text-right text-green-400">{c.detected}</td>
                    <td className="py-2 px-3 text-right text-red-400">{c.missed}</td>
                    <td className="py-2 px-3 text-right">
                      <span
                        className={`font-semibold ${
                          pct >= 80
                            ? "text-green-400"
                            : pct >= 60
                              ? "text-yellow-400"
                              : "text-red-400"
                        }`}
                      >
                        {pct}%
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
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
