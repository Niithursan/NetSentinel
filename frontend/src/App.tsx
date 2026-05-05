import React, { useState } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider, useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Loader2, Plus, X, Radar } from 'lucide-react';
import { fetchScans, createScan, deleteScan, fetchVulnerabilities, fetchActivityLog, fetchBaselines, createBaseline, checkCompliance, type ScanSummary } from './api';
import Sidebar from './components/Sidebar';
import Dashboard from './components/Dashboard';
import ScansPage from './components/ScansPage';
import ScanDetail from './components/ScanDetail';
import './index.css';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 5000,
    },
  },
});

function VulnerabilitiesPage() {
  const [expandedVulns, setExpandedVulns] = useState<Set<number>>(new Set());
  const { data: vulns, isLoading } = useQuery({
    queryKey: ['vulnerabilities'],
    queryFn: fetchVulnerabilities,
  });

  const toggleExpand = (id: number) => {
    setExpandedVulns(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'badge-error';
      case 'high': return 'badge-warning';
      case 'medium': return 'badge-info';
      case 'low': return 'badge-success';
      default: return 'badge-secondary';
    }
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Vulnerabilities</h1>
          <p className="page-description">Aggregated vulnerability findings across all scans</p>
        </div>
      </div>
      
      {isLoading ? (
        <div style={{ display: 'flex', justifyContent: 'center', padding: '48px' }}>
          <Loader2 className="loading-spinner" size={32} />
        </div>
      ) : vulns && vulns.length > 0 ? (
        <div className="card">
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th style={{ width: '40px' }}></th>
                  <th>Severity</th>
                  <th>Title</th>
                  <th>Host</th>
                  <th>Port</th>
                  <th>Service</th>
                  <th>CVE</th>
                  <th>Scan Target</th>
                </tr>
              </thead>
              <tbody>
                {vulns.map((vuln) => (
                  <React.Fragment key={vuln.id}>
                    <tr 
                      onClick={() => toggleExpand(vuln.id)} 
                      style={{ cursor: 'pointer', transition: 'background-color 0.2s' }}
                      className="hover-row"
                    >
                      <td style={{ color: 'var(--text-tertiary)', textAlign: 'center' }}>
                        {expandedVulns.has(vuln.id) ? '▼' : '▶'}
                      </td>
                      <td>
                        <span className={`badge ${getSeverityBadge(vuln.severity)}`}>
                          {vuln.severity.toUpperCase()}
                        </span>
                      </td>
                      <td style={{ fontWeight: 500 }}>{vuln.title}</td>
                      <td style={{ fontFamily: 'var(--font-mono)' }}>{vuln.host_ip}</td>
                      <td>{vuln.port_number || 'N/A'}</td>
                      <td>{vuln.service || 'N/A'}</td>
                      <td>{vuln.cve_id || 'N/A'}</td>
                      <td style={{ color: 'var(--text-tertiary)' }}>{vuln.scan_target}</td>
                    </tr>
                    {expandedVulns.has(vuln.id) && (
                      <tr style={{ background: 'var(--surface-active)' }}>
                        <td></td>
                        <td colSpan={7} style={{ padding: '16px 24px' }}>
                          <h4 style={{ margin: '0 0 8px 0', color: 'var(--text-primary)', fontSize: '14px' }}>Description</h4>
                          <p style={{ margin: 0, color: 'var(--text-secondary)', lineHeight: 1.5, whiteSpace: 'pre-wrap', fontSize: '14px' }}>
                            {vuln.description || 'No description provided.'}
                          </p>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <div className="card">
          <div className="empty-state">
            <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            <h3>No vulnerabilities found</h3>
            <p>Your network is currently clean or no scans have detected issues.</p>
          </div>
        </div>
      )}
    </div>
  );
}

function NewBaselineModal({ onClose, onSuccess }: { onClose: () => void, onSuccess: () => void }) {
  const [name, setName] = useState('');
  const [desc, setDesc] = useState('');
  const [framework, setFramework] = useState('Custom');
  const [rules, setRules] = useState('[\n  {"port": 22, "state": "closed", "description": "SSH should be closed on external interfaces"}\n]');
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: createBaseline,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['baselines'] });
      onSuccess();
    },
    onError: (e) => alert(e.message)
  });

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h3>Create Golden Baseline</h3>
          <button className="btn btn-sm btn-secondary" onClick={onClose}><X size={16} /></button>
        </div>
        <form onSubmit={(e) => {
          e.preventDefault();
          try {
            mutation.mutate({ name, description: desc, framework, rules: JSON.parse(rules) });
          } catch(err) {
            alert("Invalid JSON in rules!");
          }
        }}>
          <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div className="input-group">
              <label>Name</label>
              <input className="input" required value={name} onChange={e => setName(e.target.value)} />
            </div>
            <div className="input-group">
              <label>Framework</label>
              <input className="input" value={framework} onChange={e => setFramework(e.target.value)} />
            </div>
            <div className="input-group">
              <label>Rules (JSON Array)</label>
              <textarea className="input" style={{ minHeight: '150px', fontFamily: 'monospace' }} required value={rules} onChange={e => setRules(e.target.value)} />
            </div>
          </div>
          <div className="modal-footer">
            <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn btn-primary" disabled={mutation.isPending}>
              {mutation.isPending ? 'Saving...' : 'Save Baseline'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

function CompliancePage() {
  const [showModal, setShowModal] = useState(false);
  const [selectedScan, setSelectedScan] = useState('');
  const [selectedBaseline, setSelectedBaseline] = useState('');
  const [report, setReport] = useState<any>(null);

  const { data: baselines } = useQuery({ queryKey: ['baselines'], queryFn: fetchBaselines });
  const { data: scans } = useQuery({ queryKey: ['scans'], queryFn: fetchScans });

  const checkMutation = useMutation({
    mutationFn: () => checkCompliance(Number(selectedScan), Number(selectedBaseline)),
    onSuccess: (data) => setReport(data),
    onError: (e) => alert(e.message)
  });

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Compliance</h1>
          <p className="page-description">Golden baseline configuration & compliance checks</p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowModal(true)}>
          <Plus size={16} /> New Baseline
        </button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr', gap: '24px' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          <div className="card">
            <div className="card-header"><h3 className="card-title">Run Check</h3></div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div className="input-group">
                <label>Select Baseline</label>
                <select className="input" value={selectedBaseline} onChange={e => setSelectedBaseline(e.target.value)}>
                  <option value="">-- Choose Baseline --</option>
                  {baselines?.map(b => <option key={b.id} value={b.id}>{b.name}</option>)}
                </select>
              </div>
              <div className="input-group">
                <label>Select Scan</label>
                <select className="input" value={selectedScan} onChange={e => setSelectedScan(e.target.value)}>
                  <option value="">-- Choose Completed Scan --</option>
                  {scans?.filter(s => s.status === 'completed').map(s => (
                    <option key={s.id} value={s.id}>#{s.id} - {s.target}</option>
                  ))}
                </select>
              </div>
              <button 
                className="btn btn-primary" 
                disabled={!selectedBaseline || !selectedScan || checkMutation.isPending}
                onClick={() => checkMutation.mutate()}
                style={{ width: '100%', justifyContent: 'center' }}
              >
                {checkMutation.isPending ? <Loader2 className="loading-spinner" size={16} /> : 'Run Compliance Check'}
              </button>
            </div>
          </div>
          
          <div className="card">
            <div className="card-header"><h3 className="card-title">Configured Baselines</h3></div>
            {baselines && baselines.length > 0 ? (
              <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {baselines.map(b => (
                  <li key={b.id} style={{ padding: '12px', background: 'var(--surface-active)', borderRadius: 'var(--radius-sm)' }}>
                    <div style={{ fontWeight: 500, marginBottom: '4px' }}>{b.name}</div>
                    <div style={{ fontSize: '12px', color: 'var(--text-tertiary)' }}>Framework: {b.framework || 'Custom'}</div>
                  </li>
                ))}
              </ul>
            ) : (
              <div style={{ fontSize: '13px', color: 'var(--text-tertiary)' }}>No baselines configured yet.</div>
            )}
          </div>
        </div>

        <div className="card" style={{ minHeight: '400px' }}>
          <div className="card-header"><h3 className="card-title">Compliance Report</h3></div>
          {report ? (
             <div style={{ padding: '24px' }}>
                {report.compliance_summary ? (
                  <div style={{ marginBottom: '24px', padding: '16px', background: 'var(--surface-active)', borderRadius: '8px' }}>
                    <div style={{ fontSize: '24px', fontWeight: 'bold', color: report.compliance_summary.includes('100%') ? 'var(--success)' : 'var(--warning)' }}>
                      {report.compliance_summary}
                    </div>
                  </div>
                ) : null}
                <div style={{ whiteSpace: 'pre-wrap', lineHeight: 1.6, color: 'var(--text-secondary)' }}>
                  {report.detailed_report || JSON.stringify(report, null, 2)}
                </div>
             </div>
          ) : (
            <div className="empty-state">
              <Radar size={48} />
              <h3>Ready to verify</h3>
              <p>Select a baseline and a scan to generate an AI compliance report.</p>
            </div>
          )}
        </div>
      </div>

      {showModal && <NewBaselineModal onClose={() => setShowModal(false)} onSuccess={() => setShowModal(false)} />}
    </div>
  );
}

function SettingsPage() {
  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Settings</h1>
          <p className="page-description">Application configuration</p>
        </div>
      </div>
      <div className="card" style={{ maxWidth: '600px' }}>
        <div className="card-header">
          <h3 className="card-title">API Configuration</h3>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div className="input-group">
            <label>Backend API URL</label>
            <input className="input" type="text" value="http://localhost:8000" readOnly />
          </div>
          <div className="input-group">
            <label>Gemini API Key</label>
            <input className="input" type="password" placeholder="Set via .env file" readOnly />
          </div>
          <div className="input-group">
            <label>Default Scan Timeout</label>
            <input className="input" type="number" value={5} readOnly />
          </div>
        </div>
      </div>
    </div>
  );
}

function ActivityPage() {
  const { data: activities, isLoading } = useQuery({
    queryKey: ['activity'],
    queryFn: fetchActivityLog,
    refetchInterval: 5000,
  });

  const getSeverityStyle = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'error': return { color: 'var(--critical)', background: 'var(--critical-dim)' };
      case 'warning': return { color: '#FFAB00', background: 'rgba(255, 171, 0, 0.1)' };
      case 'info': return { color: 'var(--accent)', background: 'var(--accent-dim)' };
      default: return { color: 'var(--text-secondary)', background: 'var(--surface-active)' };
    }
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">System Activity</h1>
          <p className="page-description">Real-time system events and scan logs</p>
        </div>
      </div>
      
      {isLoading ? (
        <div style={{ display: 'flex', justifyContent: 'center', padding: '48px' }}>
          <Loader2 className="loading-spinner" size={32} />
        </div>
      ) : activities && activities.length > 0 ? (
        <div className="card" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {activities.map((activity) => (
              <div key={activity.id} style={{ 
                display: 'flex', 
                gap: '16px', 
                padding: '16px', 
                background: 'var(--surface)', 
                borderRadius: 'var(--radius-md)',
                borderLeft: `4px solid ${getSeverityStyle(activity.severity).color}`
              }}>
                <div style={{ minWidth: '150px', fontSize: '13px', color: 'var(--text-tertiary)' }}>
                  {new Date(activity.created_at).toLocaleString()}
                </div>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                    <span style={{ 
                      fontSize: '11px', 
                      fontWeight: 600, 
                      textTransform: 'uppercase',
                      padding: '2px 6px',
                      borderRadius: '4px',
                      ...getSeverityStyle(activity.severity)
                    }}>
                      {activity.event_type.replace('_', ' ')}
                    </span>
                  </div>
                  <div style={{ fontSize: '14px', color: 'var(--text-primary)', lineHeight: 1.5 }}>
                    {activity.description}
                  </div>
                  {activity.metadata_json && Object.keys(activity.metadata_json).length > 0 && (
                    <pre style={{ 
                      marginTop: '8px', 
                      padding: '8px', 
                      background: 'var(--surface-active)', 
                      borderRadius: '4px',
                      fontSize: '12px',
                      color: 'var(--text-secondary)'
                    }}>
                      {JSON.stringify(activity.metadata_json, null, 2)}
                    </pre>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div className="card">
          <div className="empty-state">
            <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
            </svg>
            <h3>No activity yet</h3>
            <p>System events will appear here once scans are initiated.</p>
          </div>
        </div>
      )}
    </div>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <div className="app-layout">
          <Sidebar />
          <main className="main-content">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/scans" element={<ScansPage />} />
              <Route path="/scans/:id" element={<ScanDetail />} />
              <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
              <Route path="/compliance" element={<CompliancePage />} />
              <Route path="/activity" element={<ActivityPage />} />
              <Route path="/settings" element={<SettingsPage />} />
            </Routes>
          </main>
        </div>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
