import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
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
  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Vulnerabilities</h1>
          <p className="page-description">Aggregated vulnerability findings across all scans</p>
        </div>
      </div>
      <div className="card">
        <div className="empty-state">
          <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
          <h3>Run a scan first</h3>
          <p>Vulnerabilities will appear here once scans have been completed.</p>
        </div>
      </div>
    </div>
  );
}

function CompliancePage() {
  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Compliance</h1>
          <p className="page-description">Golden baseline configuration & compliance checks</p>
        </div>
      </div>
      <div className="card">
        <div className="empty-state">
          <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/>
          </svg>
          <h3>No baselines configured</h3>
          <p>Create a golden configuration baseline to start checking compliance.</p>
        </div>
      </div>
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
  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Activity Log</h1>
          <p className="page-description">Scan events and system activity</p>
        </div>
      </div>
      <div className="card">
        <div className="empty-state">
          <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
          </svg>
          <h3>No activity yet</h3>
          <p>Scan events and system logs will appear here.</p>
        </div>
      </div>
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
