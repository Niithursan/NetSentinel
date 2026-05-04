import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation } from '@tanstack/react-query';
import {
  ArrowLeft,
  Monitor,
  Wifi,
  Shield,
  ShieldAlert,
  Globe,
  Clock,
  Cpu,
  Sparkles,
  Loader2,
} from 'lucide-react';
import { fetchScan, fetchRemediation, type ScanDetail, type HostInfo, type VulnerabilityInfo } from '../api';
import { useState } from 'react';

function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`badge badge-${severity}`}>{severity}</span>;
}

function HostCard({ host }: { host: HostInfo }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="card" style={{ marginBottom: '12px', cursor: 'pointer' }} onClick={() => setExpanded(!expanded)}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div
            style={{
              width: '40px',
              height: '40px',
              borderRadius: 'var(--radius-md)',
              background: host.is_up ? 'var(--accent-cyan-dim)' : 'var(--critical-dim)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: host.is_up ? 'var(--accent-cyan)' : 'var(--critical)',
            }}
          >
            <Monitor size={20} />
          </div>
          <div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '15px', fontWeight: 600 }}>
              {host.ip_address}
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-tertiary)', display: 'flex', gap: '12px', marginTop: '2px' }}>
              {host.hostname && <span>{host.hostname}</span>}
              {host.mac_address && <span>{host.mac_address}</span>}
              {host.os_guess && (
                <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <Cpu size={11} /> {host.os_guess}
                </span>
              )}
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
              <Wifi size={12} style={{ marginRight: '4px', verticalAlign: 'middle' }} />
              {host.ports.length} port{host.ports.length !== 1 ? 's' : ''}
            </div>
            {host.vulnerabilities.length > 0 && (
              <div style={{ fontSize: '13px', color: 'var(--critical)', marginTop: '2px' }}>
                <ShieldAlert size={12} style={{ marginRight: '4px', verticalAlign: 'middle' }} />
                {host.vulnerabilities.length} vuln{host.vulnerabilities.length !== 1 ? 's' : ''}
              </div>
            )}
          </div>
        </div>
      </div>

      {expanded && (
        <div style={{ marginTop: '20px', borderTop: '1px solid var(--border-subtle)', paddingTop: '16px' }}>
          {/* Ports */}
          {host.ports.length > 0 && (
            <div style={{ marginBottom: '16px' }}>
              <h4 style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px' }}>
                Open Ports
              </h4>
              <div className="table-container">
                <table>
                  <thead>
                    <tr>
                      <th>Port</th>
                      <th>Protocol</th>
                      <th>State</th>
                      <th>Service</th>
                      <th>Version</th>
                      <th>Banner</th>
                    </tr>
                  </thead>
                  <tbody>
                    {host.ports.map((port) => (
                      <tr key={port.id}>
                        <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{port.port_number}</td>
                        <td>{port.protocol.toUpperCase()}</td>
                        <td>
                          <span className={`badge badge-${port.state === 'open' ? 'success' : port.state === 'filtered' ? 'warning' : 'error'}`}>
                            {port.state}
                          </span>
                        </td>
                        <td>{port.service_name || '—'}</td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}>{port.service_version || '—'}</td>
                        <td style={{ maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: '12px', color: 'var(--text-tertiary)' }}>
                          {port.banner || '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Vulnerabilities */}
          {host.vulnerabilities.length > 0 && (
            <div>
              <h4 style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px' }}>
                Vulnerabilities
              </h4>
              {host.vulnerabilities.map((vuln) => (
                <VulnItem key={vuln.id} vuln={vuln} />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function VulnItem({ vuln }: { vuln: VulnerabilityInfo }) {
  return (
    <div
      style={{
        padding: '12px 16px',
        background: 'var(--bg-elevated)',
        borderRadius: 'var(--radius-md)',
        marginBottom: '8px',
        borderLeft: `3px solid var(--${vuln.severity})`,
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div style={{ fontWeight: 600, fontSize: '14px', marginBottom: '4px' }}>{vuln.title}</div>
          <div style={{ fontSize: '13px', color: 'var(--text-tertiary)' }}>{vuln.description}</div>
          {vuln.cve_id && (
            <span
              className="badge badge-info"
              style={{ marginTop: '6px' }}
            >
              {vuln.cve_id}
            </span>
          )}
        </div>
        <SeverityBadge severity={vuln.severity} />
      </div>
    </div>
  );
}

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const scanId = Number(id);

  const { data: scan, isLoading } = useQuery<ScanDetail>({
    queryKey: ['scan', scanId],
    queryFn: () => fetchScan(scanId),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === 'running' || status === 'pending' ? 3000 : false;
    },
  });

  const remediationMutation = useMutation({
    mutationFn: ({ host_ip, findings }: { host_ip: string; findings: Record<string, unknown>[] }) =>
      fetchRemediation(host_ip, findings),
  });

  if (isLoading) {
    return (
      <div>
        <div className="skeleton" style={{ height: '32px', width: '200px', marginBottom: '24px' }} />
        <div className="skeleton" style={{ height: '200px', marginBottom: '16px' }} />
        <div className="skeleton" style={{ height: '150px' }} />
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="empty-state">
        <Shield size={48} />
        <h3>Scan not found</h3>
        <button className="btn btn-secondary" onClick={() => navigate('/scans')}>
          <ArrowLeft size={16} /> Back to Scans
        </button>
      </div>
    );
  }

  const getStatusColor = (status: string) => {
    const map: Record<string, string> = {
      pending: 'var(--accent-blue)',
      running: 'var(--accent-cyan)',
      completed: 'var(--success)',
      failed: 'var(--error)',
    };
    return map[status] || 'var(--text-secondary)';
  };

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: '28px' }}>
        <button
          className="btn btn-secondary btn-sm"
          onClick={() => navigate('/scans')}
          style={{ marginBottom: '16px' }}
        >
          <ArrowLeft size={14} /> Back to Scans
        </button>

        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
          <div>
            <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <Globe size={26} style={{ color: getStatusColor(scan.status) }} />
              {scan.target}
            </h1>
            <div style={{ display: 'flex', gap: '16px', marginTop: '8px', fontSize: '13px', color: 'var(--text-tertiary)' }}>
              <span className={`badge badge-${scan.status === 'completed' ? 'success' : scan.status === 'running' ? 'running' : scan.status === 'failed' ? 'error' : 'pending'}`}>
                {scan.status === 'running' && <Loader2 size={12} style={{ animation: 'spin 1s linear infinite' }} />}
                {scan.status}
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <Clock size={13} />
                {new Date(scan.created_at).toLocaleString()}
              </span>
              <span className="badge badge-info">{scan.scan_type}</span>
            </div>
          </div>

          {scan.hosts.length > 0 && (
            <button
              className="btn btn-primary btn-sm"
              onClick={() => {
                const allFindings = scan.hosts.flatMap((h) =>
                  h.vulnerabilities.map((v) => ({
                    title: v.title,
                    severity: v.severity,
                    description: v.description,
                    port: v.port_number,
                    service: v.service,
                  }))
                );
                if (allFindings.length > 0) {
                  remediationMutation.mutate({
                    host_ip: scan.target,
                    findings: allFindings,
                  });
                }
              }}
              disabled={remediationMutation.isPending}
            >
              {remediationMutation.isPending ? (
                <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} />
              ) : (
                <Sparkles size={14} />
              )}
              AI Remediation
            </button>
          )}
        </div>
      </div>

      {/* Stats */}
      <div className="stats-grid" style={{ marginBottom: '24px' }}>
        <div className="stat-card" style={{ '--stat-color': 'var(--accent-blue)' } as React.CSSProperties}>
          <div className="stat-icon" style={{ background: 'var(--accent-blue-dim)', color: 'var(--accent-blue)' }}>
            <Monitor size={20} />
          </div>
          <div>
            <div className="stat-value" style={{ color: 'var(--accent-blue)' }}>{scan.total_hosts}</div>
            <div className="stat-label">Hosts Found</div>
          </div>
        </div>
        <div className="stat-card" style={{ '--stat-color': 'var(--accent-purple)' } as React.CSSProperties}>
          <div className="stat-icon" style={{ background: 'var(--accent-purple-dim)', color: 'var(--accent-purple)' }}>
            <Wifi size={20} />
          </div>
          <div>
            <div className="stat-value" style={{ color: 'var(--accent-purple)' }}>{scan.total_open_ports}</div>
            <div className="stat-label">Open Ports</div>
          </div>
        </div>
        <div className="stat-card" style={{ '--stat-color': 'var(--critical)' } as React.CSSProperties}>
          <div className="stat-icon" style={{ background: 'var(--critical-dim)', color: 'var(--critical)' }}>
            <ShieldAlert size={20} />
          </div>
          <div>
            <div className="stat-value" style={{ color: 'var(--critical)' }}>{scan.total_vulnerabilities}</div>
            <div className="stat-label">Vulnerabilities</div>
          </div>
        </div>
      </div>

      {/* AI Remediation Result */}
      {remediationMutation.data && (
        <div className="card" style={{ marginBottom: '24px', borderColor: 'var(--accent-cyan)', borderLeftWidth: '3px' }}>
          <div className="card-header">
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Sparkles size={18} style={{ color: 'var(--accent-cyan)' }} />
              <h3 className="card-title">AI Remediation Advisory</h3>
            </div>
          </div>
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: '13px',
              lineHeight: '1.7',
              color: 'var(--text-secondary)',
              whiteSpace: 'pre-wrap',
            }}
          >
            {remediationMutation.data.remediation_steps}
          </div>
        </div>
      )}

      {/* Error */}
      {scan.error_message && (
        <div className="card" style={{ marginBottom: '24px', borderColor: 'var(--critical)' }}>
          <div style={{ color: 'var(--critical)', fontFamily: 'var(--font-mono)', fontSize: '13px' }}>
            Error: {scan.error_message}
          </div>
        </div>
      )}

      {/* Hosts */}
      <div style={{ marginBottom: '16px' }}>
        <h2 style={{ fontSize: '18px', fontWeight: 600, marginBottom: '12px' }}>
          Discovered Hosts ({scan.hosts.length})
        </h2>
        {scan.hosts.length === 0 ? (
          <div className="card">
            <div className="empty-state">
              <Monitor size={40} />
              <h3>{scan.status === 'running' ? 'Scanning in progress…' : 'No hosts discovered'}</h3>
              <p>
                {scan.status === 'running'
                  ? 'Results will appear here as hosts are found.'
                  : 'The scan did not find any live hosts on the target network.'}
              </p>
            </div>
          </div>
        ) : (
          scan.hosts.map((host) => <HostCard key={host.id} host={host} />)
        )}
      </div>
    </div>
  );
}
