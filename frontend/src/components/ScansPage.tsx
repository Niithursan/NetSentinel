import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import {
  Radar,
  Plus,
  Trash2,
  Eye,
  Clock,
  X,
  Loader2,
  AlertTriangle,
} from 'lucide-react';
import { fetchScans, createScan, deleteScan, type ScanSummary } from '../api';

function NewScanModal({
  onClose,
  onSubmit,
  isLoading,
}: {
  onClose: () => void;
  onSubmit: (data: { target: string; scan_type: string; ports?: string; timeout?: number }) => void;
  isLoading: boolean;
  error: Error | null;
}) {
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('full');
  const [ports, setPorts] = useState('');
  const [timeout, setTimeout] = useState(5);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit({
      target,
      scan_type: scanType,
      ports: ports || undefined,
      timeout,
    });
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2 className="modal-title">Launch New Scan</h2>
          <button className="btn btn-icon btn-secondary" onClick={onClose}>
            <X size={16} />
          </button>
        </div>
        <form onSubmit={handleSubmit}>
          <div className="modal-body">
            <div className="input-group">
              <label htmlFor="target">Target Network</label>
              <input
                id="target"
                className="input"
                type="text"
                placeholder="e.g. 192.168.1.0/24 or 10.0.0.1"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                required
              />
            </div>

            <div className="input-group">
              <label htmlFor="scan-type">Scan Type</label>
              <select
                id="scan-type"
                className="input"
                value={scanType}
                onChange={(e) => setScanType(e.target.value)}
              >
                <option value="full">Full Scan (ARP + TCP + UDP)</option>
                <option value="quick">Quick Scan (Top 5 Ports)</option>
                <option value="arp_only">ARP Discovery Only</option>
                <option value="port_only">Port Scan Only</option>
              </select>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
              <div className="input-group">
                <label htmlFor="ports">Custom Ports (optional)</label>
                <input
                  id="ports"
                  className="input"
                  type="text"
                  placeholder="e.g. 22,80,443"
                  value={ports}
                  onChange={(e) => setPorts(e.target.value)}
                />
              </div>
              <div className="input-group">
                <label htmlFor="timeout">Timeout (seconds)</label>
                <input
                  id="timeout"
                  className="input"
                  type="number"
                  min={1}
                  max={30}
                  value={timeout}
                  onChange={(e) => setTimeout(Number(e.target.value))}
                />
              </div>
            </div>

            {error && (
              <div style={{
                marginTop: '16px',
                padding: '12px',
                background: 'var(--critical-dim)',
                color: 'var(--critical)',
                borderRadius: 'var(--radius-md)',
                fontSize: '13px',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                border: '1px solid var(--critical)',
              }}>
                <AlertTriangle size={16} />
                <span>{error.message.includes('Failed to fetch') ? 'Cannot connect to backend server. Is it running?' : error.message}</span>
              </div>
            )}
          </div>

          <div className="modal-footer">
            <button type="button" className="btn btn-secondary" onClick={onClose}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={!target || isLoading}>
              {isLoading ? (
                <>
                  <Loader2 size={16} className="loading-spinner" />
                  Launching…
                </>
              ) : (
                <>
                  <Radar size={16} />
                  Launch Scan
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default function ScansPage() {
  const [showModal, setShowModal] = useState(false);
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const { data: scans, isLoading } = useQuery<ScanSummary[]>({
    queryKey: ['scans'],
    queryFn: fetchScans,
    refetchInterval: 5000,
  });

  const createMutation = useMutation({
    mutationFn: createScan,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      queryClient.invalidateQueries({ queryKey: ['dashboardStats'] });
      setShowModal(false);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: deleteScan,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      queryClient.invalidateQueries({ queryKey: ['dashboardStats'] });
    },
  });

  const getStatusBadge = (status: string) => {
    const map: Record<string, string> = {
      pending: 'badge-pending',
      running: 'badge-running',
      completed: 'badge-success',
      failed: 'badge-error',
      cancelled: 'badge-warning',
    };
    return `badge ${map[status] || 'badge-info'}`;
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Network Scans</h1>
          <p className="page-description">Manage and launch network discovery scans</p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowModal(true)}>
          <Plus size={16} />
          New Scan
        </button>
      </div>

      <div className="card">
        {isLoading ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {[1, 2, 3].map((i) => (
              <div key={i} className="skeleton" style={{ height: '52px' }} />
            ))}
          </div>
        ) : !scans?.length ? (
          <div className="empty-state">
            <Radar size={48} />
            <h3>No scans found</h3>
            <p>Click "New Scan" to discover hosts and services on your network.</p>
          </div>
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Target</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Hosts</th>
                  <th>Open Ports</th>
                  <th>Vulns</th>
                  <th>Created</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr key={scan.id}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', color: 'var(--text-tertiary)' }}>
                      #{scan.id}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', fontWeight: 500 }}>
                      {scan.target}
                    </td>
                    <td>
                      <span className="badge badge-info">{scan.scan_type}</span>
                    </td>
                    <td>
                      <span className={getStatusBadge(scan.status)}>
                        {scan.status === 'running' && (
                          <span className="scan-pulse" style={{ marginRight: '4px' }} />
                        )}
                        {scan.status}
                      </span>
                    </td>
                    <td>{scan.total_hosts}</td>
                    <td>{scan.total_open_ports}</td>
                    <td>
                      <span style={{
                        color: scan.total_vulnerabilities > 0 ? 'var(--critical)' : 'inherit',
                        fontWeight: scan.total_vulnerabilities > 0 ? 600 : 400,
                      }}>
                        {scan.total_vulnerabilities}
                      </span>
                    </td>
                    <td style={{ fontSize: '13px', color: 'var(--text-tertiary)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                        <Clock size={12} />
                        {new Date(scan.created_at).toLocaleString()}
                      </div>
                    </td>
                    <td>
                      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '6px' }}>
                        <button
                          className="btn btn-sm btn-secondary"
                          onClick={() => navigate(`/scans/${scan.id}`)}
                          title="View Details"
                        >
                          <Eye size={14} />
                        </button>
                        <button
                          className="btn btn-sm btn-danger"
                          onClick={() => {
                            if (confirm('Delete this scan and all its data?')) {
                              deleteMutation.mutate(scan.id);
                            }
                          }}
                          title="Delete Scan"
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {showModal && (
        <NewScanModal
          onClose={() => setShowModal(false)}
          onSubmit={(data) => createMutation.mutate(data)}
          isLoading={createMutation.isPending}
          error={createMutation.error as Error}
        />
      )}
    </div>
  );
}
