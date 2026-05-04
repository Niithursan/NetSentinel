import { useQuery } from '@tanstack/react-query';
import {
  Monitor,
  Wifi,
  AlertTriangle,
  ShieldAlert,
  ArrowUpRight,
  Radar,
  Clock,
} from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell,
} from 'recharts';
import { fetchDashboardStats, type DashboardStats, type ScanSummary } from '../api';

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
};

function StatCard({
  icon: Icon,
  label,
  value,
  color,
}: {
  icon: React.ComponentType<{ size?: number }>;
  label: string;
  value: number;
  color: string;
}) {
  return (
    <div className="stat-card" style={{ '--stat-color': color } as React.CSSProperties}>
      <div
        className="stat-icon"
        style={{ background: `${color}15`, color }}
      >
        <Icon size={22} />
      </div>
      <div>
        <div className="stat-value" style={{ color }}>{value.toLocaleString()}</div>
        <div className="stat-label">{label}</div>
      </div>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  return <span className={`badge badge-${status}`}>{status}</span>;
}

function RecentScansTable({ scans }: { scans: ScanSummary[] }) {
  if (!scans.length) {
    return (
      <div className="empty-state">
        <Radar size={40} />
        <h3>No scans yet</h3>
        <p>Launch your first scan to start discovering your network.</p>
      </div>
    );
  }

  return (
    <div className="table-container">
      <table>
        <thead>
          <tr>
            <th>Target</th>
            <th>Type</th>
            <th>Status</th>
            <th>Hosts</th>
            <th>Ports</th>
            <th>Vulns</th>
            <th>Time</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr key={scan.id}>
              <td style={{ fontFamily: 'var(--font-mono)', fontSize: '13px' }}>
                {scan.target}
              </td>
              <td>
                <span className="badge badge-info">{scan.scan_type}</span>
              </td>
              <td>
                <StatusBadge status={scan.status} />
              </td>
              <td>{scan.total_hosts}</td>
              <td>{scan.total_open_ports}</td>
              <td>
                <span style={{
                  color: scan.total_vulnerabilities > 0 ? 'var(--critical)' : 'var(--text-secondary)'
                }}>
                  {scan.total_vulnerabilities}
                </span>
              </td>
              <td style={{ color: 'var(--text-tertiary)', fontSize: '13px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <Clock size={12} />
                  {new Date(scan.created_at).toLocaleDateString()}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function Dashboard() {
  const { data: stats, isLoading, error } = useQuery<DashboardStats>({
    queryKey: ['dashboardStats'],
    queryFn: fetchDashboardStats,
    refetchInterval: 10000,
  });

  if (isLoading) {
    return (
      <div>
        <div className="page-header">
          <div>
            <h1 className="page-title">Dashboard</h1>
            <p className="page-description">Network security overview at a glance</p>
          </div>
        </div>
        <div className="stats-grid">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="skeleton" style={{ height: '100px', borderRadius: 'var(--radius-lg)' }} />
          ))}
        </div>
      </div>
    );
  }

  if (error || !stats) {
    // Show demo data when backend is unavailable
    const demoStats: DashboardStats = {
      total_scans: 0,
      total_hosts_discovered: 0,
      total_open_ports: 0,
      total_vulnerabilities: 0,
      critical_count: 0,
      high_count: 0,
      medium_count: 0,
      low_count: 0,
      recent_scans: [],
    };
    return <DashboardContent stats={demoStats} />;
  }

  return <DashboardContent stats={stats} />;
}

function DashboardContent({ stats }: { stats: DashboardStats }) {
  const severityData = [
    { name: 'Critical', value: stats.critical_count, color: SEVERITY_COLORS.critical },
    { name: 'High', value: stats.high_count, color: SEVERITY_COLORS.high },
    { name: 'Medium', value: stats.medium_count, color: SEVERITY_COLORS.medium },
    { name: 'Low', value: stats.low_count, color: SEVERITY_COLORS.low },
  ].filter(d => d.value > 0);

  const barData = stats.recent_scans.map((s) => ({
    name: s.target.length > 15 ? s.target.slice(0, 15) + '…' : s.target,
    hosts: s.total_hosts,
    ports: s.total_open_ports,
    vulns: s.total_vulnerabilities,
  }));

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Dashboard</h1>
          <p className="page-description">Network security overview at a glance</p>
        </div>
        <a href="/scans" className="btn btn-primary">
          <Radar size={16} />
          New Scan
          <ArrowUpRight size={14} />
        </a>
      </div>

      {/* Stat Cards */}
      <div className="stats-grid">
        <StatCard icon={Radar} label="Total Scans" value={stats.total_scans} color="var(--accent-cyan)" />
        <StatCard icon={Monitor} label="Hosts Discovered" value={stats.total_hosts_discovered} color="var(--accent-blue)" />
        <StatCard icon={Wifi} label="Open Ports" value={stats.total_open_ports} color="var(--accent-purple)" />
        <StatCard icon={ShieldAlert} label="Vulnerabilities" value={stats.total_vulnerabilities} color="var(--critical)" />
      </div>

      {/* Charts Row */}
      <div className="grid-2" style={{ marginBottom: '24px' }}>
        {/* Severity Breakdown */}
        <div className="card">
          <div className="card-header">
            <div>
              <h3 className="card-title">Severity Breakdown</h3>
              <p className="card-subtitle">Vulnerability distribution</p>
            </div>
            <AlertTriangle size={18} style={{ color: 'var(--text-tertiary)' }} />
          </div>
          {severityData.length > 0 ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: '32px' }}>
              <ResponsiveContainer width="50%" height={180}>
                <PieChart>
                  <Pie
                    data={severityData}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={75}
                    paddingAngle={4}
                    dataKey="value"
                    strokeWidth={0}
                  >
                    {severityData.map((entry, index) => (
                      <Cell key={index} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      background: 'var(--bg-secondary)',
                      border: '1px solid var(--border-default)',
                      borderRadius: 'var(--radius-md)',
                      fontSize: '13px',
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {severityData.map((item) => (
                  <div key={item.name} style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <div style={{
                      width: '10px', height: '10px', borderRadius: '3px',
                      background: item.color,
                    }} />
                    <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                      {item.name}
                    </span>
                    <span style={{
                      fontSize: '14px', fontWeight: 600,
                      fontFamily: 'var(--font-mono)',
                      color: 'var(--text-primary)',
                    }}>
                      {item.value}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="empty-state" style={{ padding: '30px' }}>
              <ShieldAlert size={32} />
              <h3>No vulnerabilities</h3>
              <p>Run a scan to detect potential issues</p>
            </div>
          )}
        </div>

        {/* Scan History */}
        <div className="card">
          <div className="card-header">
            <div>
              <h3 className="card-title">Scan Activity</h3>
              <p className="card-subtitle">Hosts, ports & vulns per scan</p>
            </div>
          </div>
          {barData.length > 0 ? (
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={barData}>
                <XAxis dataKey="name" tick={{ fontSize: 11, fill: '#64748b' }} />
                <YAxis tick={{ fontSize: 11, fill: '#64748b' }} />
                <Tooltip
                  contentStyle={{
                    background: 'var(--bg-secondary)',
                    border: '1px solid var(--border-default)',
                    borderRadius: 'var(--radius-md)',
                    fontSize: '13px',
                  }}
                />
                <Bar dataKey="hosts" fill="#3b82f6" radius={[4, 4, 0, 0]} />
                <Bar dataKey="ports" fill="#8b5cf6" radius={[4, 4, 0, 0]} />
                <Bar dataKey="vulns" fill="#ef4444" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state" style={{ padding: '30px' }}>
              <Radar size={32} />
              <h3>No scan data</h3>
              <p>Complete a scan to see activity charts</p>
            </div>
          )}
        </div>
      </div>

      {/* Recent Scans */}
      <div className="card">
        <div className="card-header">
          <div>
            <h3 className="card-title">Recent Scans</h3>
            <p className="card-subtitle">Latest scan results</p>
          </div>
        </div>
        <RecentScansTable scans={stats.recent_scans} />
      </div>
    </div>
  );
}
