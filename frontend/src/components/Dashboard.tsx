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
  PieChart, Pie, Cell, AreaChart, Area, CartesianGrid,
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
    return (
      <>
        <div style={{
          background: 'var(--critical-dim)',
          color: 'var(--critical)',
          padding: '12px 20px',
          borderRadius: 'var(--radius-lg)',
          marginBottom: '20px',
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
          border: '1px solid var(--critical)',
          fontSize: '14px',
          fontWeight: 500
        }}>
          <AlertTriangle size={20} />
          <span>Backend Offline: Cannot connect to http://localhost:8000. Please ensure the backend server is running.</span>
        </div>
        <DashboardContent stats={demoStats} />
      </>
    );
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
            <ShieldAlert size={18} style={{ color: 'var(--text-tertiary)' }} />
          </div>
          <div style={{ height: '220px', display: 'flex', alignItems: 'center' }}>
            {severityData.length > 0 ? (
              <>
                <ResponsiveContainer width="50%" height="100%">
                  <PieChart>
                    <Pie
                      data={severityData}
                      cx="50%"
                      cy="50%"
                      innerRadius={50}
                      outerRadius={80}
                      paddingAngle={5}
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
                        fontSize: '12px',
                        color: 'var(--text-primary)'
                      }}
                      itemStyle={{ color: 'var(--text-primary)' }}
                    />
                  </PieChart>
                </ResponsiveContainer>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', flex: 1 }}>
                  {severityData.map((item) => (
                    <div key={item.name} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingRight: '20px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: item.color }} />
                        <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>{item.name}</span>
                      </div>
                      <span style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>{item.value}</span>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <div className="empty-state" style={{ width: '100%' }}>
                <ShieldAlert size={32} />
                <p>No vulnerabilities detected</p>
              </div>
            )}
          </div>
        </div>

        {/* Activity Timeline */}
        <div className="card">
          <div className="card-header">
            <div>
              <h3 className="card-title">Scan Activity History</h3>
              <p className="card-subtitle">Total scans over last 7 days</p>
            </div>
            <Clock size={18} style={{ color: 'var(--text-tertiary)' }} />
          </div>
          <div style={{ height: '220px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={stats.activity_history} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--accent-blue)" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="var(--accent-blue)" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--border-default)" opacity={0.5} />
                <XAxis 
                  dataKey="date" 
                  tick={{ fontSize: 10, fill: 'var(--text-tertiary)' }} 
                  axisLine={false}
                  tickLine={false}
                  tickFormatter={(val) => val.split('-').slice(1).join('/')}
                />
                <YAxis 
                  tick={{ fontSize: 10, fill: 'var(--text-tertiary)' }} 
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  contentStyle={{
                    background: 'var(--bg-secondary)',
                    border: '1px solid var(--border-default)',
                    borderRadius: 'var(--radius-md)',
                    fontSize: '12px',
                    color: 'var(--text-primary)'
                  }}
                />
                <Area 
                  type="monotone" 
                  dataKey="count" 
                  stroke="var(--accent-blue)" 
                  fillOpacity={1} 
                  fill="url(#colorCount)" 
                  strokeWidth={2}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Comparison Chart */}
      <div className="card" style={{ marginBottom: '24px' }}>
        <div className="card-header">
          <div>
            <h3 className="card-title">Scan Comparison</h3>
            <p className="card-subtitle">Metric comparison across recent scan targets</p>
          </div>
        </div>
        <div style={{ height: '280px' }}>
          {barData.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={barData} margin={{ top: 10, right: 30, left: 0, bottom: 20 }}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--border-default)" opacity={0.3} />
                <XAxis dataKey="name" tick={{ fontSize: 11, fill: 'var(--text-tertiary)' }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fontSize: 11, fill: 'var(--text-tertiary)' }} axisLine={false} tickLine={false} />
                <Tooltip
                  cursor={{ fill: 'rgba(255, 255, 255, 0.05)' }}
                  contentStyle={{
                    background: 'var(--bg-secondary)',
                    border: '1px solid var(--border-default)',
                    borderRadius: 'var(--radius-md)',
                    fontSize: '12px',
                    color: 'var(--text-primary)'
                  }}
                />
                <Bar dataKey="hosts" name="Hosts" fill="#3b82f6" radius={[4, 4, 0, 0]} barSize={20} />
                <Bar dataKey="ports" name="Open Ports" fill="#8b5cf6" radius={[4, 4, 0, 0]} barSize={20} />
                <Bar dataKey="vulns" name="Vulnerabilities" fill="#ef4444" radius={[4, 4, 0, 0]} barSize={20} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state">
              <Radar size={32} />
              <p>Insufficient scan data for comparison</p>
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
