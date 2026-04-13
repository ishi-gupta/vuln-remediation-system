import { useState, useEffect, useCallback } from 'react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend, LineChart, Line, CartesianGrid,
} from 'recharts'

const API_BASE = import.meta.env.VITE_API_URL || ''

interface Metrics {
  overview: {
    total_scans: number
    total_findings: number
    issues_created: number
    active_sessions: number
    success_rate: number
  }
  severity_breakdown: {
    critical: number
    high: number
    medium: number
    low: number
  }
  remediation_status: {
    fixed: number
    partial: number
    failed: number
    in_progress: number
    pending: number
  }
  scan_history: Array<{
    scan_id: string
    timestamp: string
    total_findings: number
    critical: number
    high: number
    medium: number
    low: number
    duration_seconds: number
  }>
  recent_remediations: Array<{
    issue_number: number
    status: string
    pr_url?: string
    devin_session_id?: string
    updated_at?: string
  }>
  adversarial_results: {
    total_planted: number
    total_detected: number
    detection_rate: number
    by_category: Record<string, { planted: number; detected: number; rate: number }>
  } | null
}

interface Issue {
  number: number
  title: string
  state: string
  severity: string
  scan_type: string
  labels: string[]
  created_at: string
  closed_at: string | null
  url: string
  has_remediation: boolean
  remediation_failed: boolean
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
}

const STATUS_COLORS: Record<string, string> = {
  fixed: '#22c55e',
  partial: '#eab308',
  failed: '#ef4444',
  in_progress: '#3b82f6',
  pending: '#64748b',
}

function StatCard({ label, value, sub, color }: { label: string; value: string | number; sub?: string; color?: string }) {
  return (
    <div className="bg-slate-800 rounded-xl p-5 border border-slate-700 hover:border-slate-600 transition-colors">
      <p className="text-slate-400 text-sm font-medium uppercase tracking-wide">{label}</p>
      <p className="text-3xl font-bold mt-1" style={{ color: color || '#e2e8f0' }}>{value}</p>
      {sub && <p className="text-slate-500 text-sm mt-1">{sub}</p>}
    </div>
  )
}

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/30',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    low: 'bg-green-500/20 text-green-400 border-green-500/30',
  }
  return (
    <span className={`inline-block px-2 py-0.5 rounded-full text-xs font-medium border ${colors[severity] || 'bg-slate-700 text-slate-300'}`}>
      {severity.toUpperCase()}
    </span>
  )
}

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    fixed: 'bg-green-500/20 text-green-400',
    partial: 'bg-yellow-500/20 text-yellow-400',
    failed: 'bg-red-500/20 text-red-400',
    in_progress: 'bg-blue-500/20 text-blue-400',
    pending: 'bg-slate-600/40 text-slate-400',
    open: 'bg-blue-500/20 text-blue-400',
    closed: 'bg-green-500/20 text-green-400',
  }
  return (
    <span className={`inline-block px-2 py-0.5 rounded-full text-xs font-medium ${colors[status] || 'bg-slate-700 text-slate-300'}`}>
      {status.replace('_', ' ').toUpperCase()}
    </span>
  )
}

export default function App() {
  const [metrics, setMetrics] = useState<Metrics | null>(null)
  const [issues, setIssues] = useState<Issue[]>([])
  const [activeTab, setActiveTab] = useState<'overview' | 'issues' | 'adversarial'>('overview')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [lastUpdated, setLastUpdated] = useState<string>('')

  const fetchData = useCallback(async () => {
    try {
      const [metricsRes, issuesRes] = await Promise.all([
        fetch(`${API_BASE}/api/metrics`),
        fetch(`${API_BASE}/api/issues`),
      ])
      if (metricsRes.ok) {
        setMetrics(await metricsRes.json())
      }
      if (issuesRes.ok) {
        const issueData = await issuesRes.json()
        setIssues(issueData.issues || [])
      }
      setLastUpdated(new Date().toLocaleTimeString())
      setError(null)
    } catch (err) {
      setError('Failed to connect to dashboard API. Is the backend running?')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 15000)
    return () => clearInterval(interval)
  }, [fetchData])

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-900 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto"></div>
          <p className="text-slate-400 mt-4">Loading dashboard...</p>
        </div>
      </div>
    )
  }

  const severityData = metrics ? [
    { name: 'Critical', value: metrics.severity_breakdown.critical, fill: SEVERITY_COLORS.critical },
    { name: 'High', value: metrics.severity_breakdown.high, fill: SEVERITY_COLORS.high },
    { name: 'Medium', value: metrics.severity_breakdown.medium, fill: SEVERITY_COLORS.medium },
    { name: 'Low', value: metrics.severity_breakdown.low, fill: SEVERITY_COLORS.low },
  ].filter(d => d.value > 0) : []

  const remediationData = metrics ? [
    { name: 'Fixed', value: metrics.remediation_status.fixed, fill: STATUS_COLORS.fixed },
    { name: 'Partial', value: metrics.remediation_status.partial, fill: STATUS_COLORS.partial },
    { name: 'Failed', value: metrics.remediation_status.failed, fill: STATUS_COLORS.failed },
    { name: 'In Progress', value: metrics.remediation_status.in_progress, fill: STATUS_COLORS.in_progress },
    { name: 'Pending', value: metrics.remediation_status.pending, fill: STATUS_COLORS.pending },
  ].filter(d => d.value > 0) : []

  const scanHistory = metrics?.scan_history.map(s => ({
    ...s,
    date: new Date(s.timestamp).toLocaleDateString(),
  })) || []

  const adversarial = metrics?.adversarial_results
  const adversarialByCategory = adversarial?.by_category
    ? Object.entries(adversarial.by_category).map(([cat, data]) => ({
        category: cat,
        planted: data.planted,
        detected: data.detected,
        rate: Math.round(data.rate * 100),
      }))
    : []

  return (
    <div className="min-h-screen bg-slate-900">
      {/* Header */}
      <header className="bg-slate-800 border-b border-slate-700 px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="h-8 w-8 rounded-lg bg-blue-600 flex items-center justify-center">
              <svg className="h-5 w-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">Vulnerability Remediation System</h1>
              <p className="text-xs text-slate-400">AI-Assisted Security Automation</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            {lastUpdated && (
              <span className="text-xs text-slate-500">Updated {lastUpdated}</span>
            )}
            <button
              onClick={fetchData}
              className="px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg text-sm transition-colors"
            >
              Refresh
            </button>
          </div>
        </div>
      </header>

      {/* Tabs */}
      <div className="max-w-7xl mx-auto px-6 mt-4">
        <div className="flex gap-1 bg-slate-800 rounded-lg p-1 w-fit">
          {(['overview', 'issues', 'adversarial'] as const).map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                activeTab === tab
                  ? 'bg-blue-600 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {tab === 'adversarial' ? 'Adversarial Testing' : tab.charAt(0).toUpperCase() + tab.slice(1)}
            </button>
          ))}
        </div>
      </div>

      <main className="max-w-7xl mx-auto px-6 py-6">
        {error && (
          <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 mb-6">
            <p className="text-red-400 text-sm">{error}</p>
          </div>
        )}

        {/* Overview Tab */}
        {activeTab === 'overview' && metrics && (
          <div className="space-y-6">
            {/* Stat Cards */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              <StatCard label="Total Scans" value={metrics.overview.total_scans} />
              <StatCard label="Findings" value={metrics.overview.total_findings} color="#f97316" />
              <StatCard label="Issues Created" value={metrics.overview.issues_created} color="#3b82f6" />
              <StatCard label="Active Sessions" value={metrics.overview.active_sessions} color="#8b5cf6" />
              <StatCard
                label="Success Rate"
                value={`${metrics.overview.success_rate}%`}
                color={metrics.overview.success_rate >= 70 ? '#22c55e' : metrics.overview.success_rate >= 40 ? '#eab308' : '#ef4444'}
              />
            </div>

            {/* Charts Row */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Severity Breakdown */}
              <div className="bg-slate-800 rounded-xl p-5 border border-slate-700">
                <h3 className="text-lg font-semibold text-white mb-4">Severity Breakdown</h3>
                {severityData.length > 0 ? (
                  <ResponsiveContainer width="100%" height={250}>
                    <PieChart>
                      <Pie
                        data={severityData}
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={90}
                        paddingAngle={4}
                        dataKey="value"
                        label={({ name, value }) => `${name}: ${value}`}
                      >
                        {severityData.map((entry, index) => (
                          <Cell key={index} fill={entry.fill} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
                        labelStyle={{ color: '#e2e8f0' }}
                      />
                      <Legend />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="h-64 flex items-center justify-center text-slate-500">No findings yet</div>
                )}
              </div>

              {/* Remediation Status */}
              <div className="bg-slate-800 rounded-xl p-5 border border-slate-700">
                <h3 className="text-lg font-semibold text-white mb-4">Remediation Progress</h3>
                {remediationData.length > 0 ? (
                  <ResponsiveContainer width="100%" height={250}>
                    <PieChart>
                      <Pie
                        data={remediationData}
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={90}
                        paddingAngle={4}
                        dataKey="value"
                        label={({ name, value }) => `${name}: ${value}`}
                      >
                        {remediationData.map((entry, index) => (
                          <Cell key={index} fill={entry.fill} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
                        labelStyle={{ color: '#e2e8f0' }}
                      />
                      <Legend />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="h-64 flex items-center justify-center text-slate-500">No remediations yet</div>
                )}
              </div>
            </div>

            {/* Scan History */}
            {scanHistory.length > 0 && (
              <div className="bg-slate-800 rounded-xl p-5 border border-slate-700">
                <h3 className="text-lg font-semibold text-white mb-4">Scan History</h3>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={scanHistory}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                    <XAxis dataKey="date" stroke="#64748b" fontSize={12} />
                    <YAxis stroke="#64748b" fontSize={12} />
                    <Tooltip
                      contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
                      labelStyle={{ color: '#e2e8f0' }}
                    />
                    <Bar dataKey="critical" stackId="a" fill={SEVERITY_COLORS.critical} name="Critical" />
                    <Bar dataKey="high" stackId="a" fill={SEVERITY_COLORS.high} name="High" />
                    <Bar dataKey="medium" stackId="a" fill={SEVERITY_COLORS.medium} name="Medium" />
                    <Bar dataKey="low" stackId="a" fill={SEVERITY_COLORS.low} name="Low" />
                    <Legend />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}

            {/* Recent Remediations Table */}
            {metrics.recent_remediations.length > 0 && (
              <div className="bg-slate-800 rounded-xl p-5 border border-slate-700">
                <h3 className="text-lg font-semibold text-white mb-4">Recent Remediation Sessions</h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-slate-400 border-b border-slate-700">
                        <th className="text-left py-2 px-3">Issue</th>
                        <th className="text-left py-2 px-3">Status</th>
                        <th className="text-left py-2 px-3">PR</th>
                        <th className="text-left py-2 px-3">Updated</th>
                      </tr>
                    </thead>
                    <tbody>
                      {metrics.recent_remediations.map((r, i) => (
                        <tr key={i} className="border-b border-slate-700/50 hover:bg-slate-700/30">
                          <td className="py-2 px-3">#{r.issue_number}</td>
                          <td className="py-2 px-3"><StatusBadge status={r.status} /></td>
                          <td className="py-2 px-3">
                            {r.pr_url ? (
                              <a href={r.pr_url} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                                View PR
                              </a>
                            ) : '—'}
                          </td>
                          <td className="py-2 px-3 text-slate-400">
                            {r.updated_at ? new Date(r.updated_at).toLocaleString() : '—'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Issues Tab */}
        {activeTab === 'issues' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold text-white">Security Issues ({issues.length})</h2>
              <div className="flex gap-2">
                {['all', 'open', 'closed'].map(filter => (
                  <button
                    key={filter}
                    className="px-3 py-1 rounded-md text-xs font-medium bg-slate-800 text-slate-400 hover:text-white transition-colors border border-slate-700"
                  >
                    {filter.charAt(0).toUpperCase() + filter.slice(1)}
                  </button>
                ))}
              </div>
            </div>

            {issues.length > 0 ? (
              <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-slate-400 border-b border-slate-700 bg-slate-800/80">
                      <th className="text-left py-3 px-4">#</th>
                      <th className="text-left py-3 px-4">Title</th>
                      <th className="text-left py-3 px-4">Severity</th>
                      <th className="text-left py-3 px-4">Type</th>
                      <th className="text-left py-3 px-4">State</th>
                      <th className="text-left py-3 px-4">Remediation</th>
                      <th className="text-left py-3 px-4">Created</th>
                    </tr>
                  </thead>
                  <tbody>
                    {issues.map(issue => (
                      <tr key={issue.number} className="border-b border-slate-700/50 hover:bg-slate-700/30">
                        <td className="py-3 px-4 text-slate-400">{issue.number}</td>
                        <td className="py-3 px-4">
                          <a href={issue.url} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                            {issue.title.length > 80 ? issue.title.slice(0, 80) + '...' : issue.title}
                          </a>
                        </td>
                        <td className="py-3 px-4"><SeverityBadge severity={issue.severity} /></td>
                        <td className="py-3 px-4">
                          <span className="text-xs text-slate-400 bg-slate-700 px-2 py-0.5 rounded">
                            {issue.scan_type}
                          </span>
                        </td>
                        <td className="py-3 px-4"><StatusBadge status={issue.state} /></td>
                        <td className="py-3 px-4">
                          {issue.has_remediation ? (
                            issue.remediation_failed ? (
                              <span className="text-red-400 text-xs">Failed</span>
                            ) : (
                              <span className="text-blue-400 text-xs">In Progress</span>
                            )
                          ) : (
                            <span className="text-slate-500 text-xs">Pending</span>
                          )}
                        </td>
                        <td className="py-3 px-4 text-slate-400 text-xs">
                          {new Date(issue.created_at).toLocaleDateString()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="bg-slate-800 rounded-xl p-12 border border-slate-700 text-center">
                <p className="text-slate-500">No security issues found yet. Run a scan to get started.</p>
              </div>
            )}
          </div>
        )}

        {/* Adversarial Testing Tab */}
        {activeTab === 'adversarial' && (
          <div className="space-y-6">
            {adversarial ? (
              <>
                {/* Detection Rate Overview */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <StatCard
                    label="Detection Rate"
                    value={`${Math.round(adversarial.detection_rate * 100)}%`}
                    color={adversarial.detection_rate >= 0.8 ? '#22c55e' : adversarial.detection_rate >= 0.5 ? '#eab308' : '#ef4444'}
                    sub={`${adversarial.total_detected} of ${adversarial.total_planted} vulnerabilities detected`}
                  />
                  <StatCard label="Total Planted" value={adversarial.total_planted} color="#8b5cf6" />
                  <StatCard label="Total Detected" value={adversarial.total_detected} color="#3b82f6" />
                </div>

                {/* Detection by Category */}
                {adversarialByCategory.length > 0 && (
                  <div className="bg-slate-800 rounded-xl p-5 border border-slate-700">
                    <h3 className="text-lg font-semibold text-white mb-4">Detection Rate by Vulnerability Category</h3>
                    <ResponsiveContainer width="100%" height={350}>
                      <BarChart data={adversarialByCategory} layout="vertical">
                        <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                        <XAxis type="number" domain={[0, 100]} stroke="#64748b" fontSize={12} unit="%" />
                        <YAxis type="category" dataKey="category" stroke="#64748b" fontSize={12} width={140} />
                        <Tooltip
                          contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
                          labelStyle={{ color: '#e2e8f0' }}
                          formatter={(value: number) => [`${value}%`, 'Detection Rate']}
                        />
                        <Bar
                          dataKey="rate"
                          fill="#3b82f6"
                          radius={[0, 4, 4, 0]}
                          label={{ position: 'right', fill: '#94a3b8', fontSize: 12, formatter: (v: number) => `${v}%` }}
                        />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                )}

                {/* Detailed Category Table */}
                <div className="bg-slate-800 rounded-xl p-5 border border-slate-700">
                  <h3 className="text-lg font-semibold text-white mb-4">Detailed Results</h3>
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-slate-400 border-b border-slate-700">
                        <th className="text-left py-2 px-3">Category</th>
                        <th className="text-center py-2 px-3">Planted</th>
                        <th className="text-center py-2 px-3">Detected</th>
                        <th className="text-center py-2 px-3">Missed</th>
                        <th className="text-center py-2 px-3">Rate</th>
                      </tr>
                    </thead>
                    <tbody>
                      {adversarialByCategory.map(cat => (
                        <tr key={cat.category} className="border-b border-slate-700/50 hover:bg-slate-700/30">
                          <td className="py-2 px-3 font-medium">{cat.category}</td>
                          <td className="py-2 px-3 text-center">{cat.planted}</td>
                          <td className="py-2 px-3 text-center text-green-400">{cat.detected}</td>
                          <td className="py-2 px-3 text-center text-red-400">{cat.planted - cat.detected}</td>
                          <td className="py-2 px-3 text-center">
                            <span className={`font-medium ${cat.rate >= 80 ? 'text-green-400' : cat.rate >= 50 ? 'text-yellow-400' : 'text-red-400'}`}>
                              {cat.rate}%
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            ) : (
              <div className="bg-slate-800 rounded-xl p-12 border border-slate-700 text-center">
                <div className="max-w-md mx-auto">
                  <svg className="h-16 w-16 text-slate-600 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                  </svg>
                  <h3 className="text-lg font-semibold text-white mb-2">No Adversarial Test Results</h3>
                  <p className="text-slate-500 text-sm">
                    Run the adversarial test suite to measure scanner detection rates.
                    This plants known vulnerabilities and measures how many the scanner catches.
                  </p>
                  <code className="block mt-4 bg-slate-900 text-slate-300 p-3 rounded-lg text-xs text-left">
                    python -m automation.evaluate --test-suite ../vuln-test-suite
                  </code>
                </div>
              </div>
            )}
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 py-4 mt-8">
        <p className="text-center text-xs text-slate-600">
          Vulnerability Remediation System &mdash; AI-Assisted Security Automation
        </p>
      </footer>
    </div>
  )
}
