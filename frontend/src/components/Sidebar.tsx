import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Radar,
  Shield,
  FileCheck,
  Settings,
  Activity,
} from 'lucide-react';

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div className="logo-icon">NS</div>
        <div>
          <h1>NetSentinel</h1>
          <span>v1.0.0</span>
        </div>
      </div>

      <nav className="sidebar-nav">
        <div className="nav-section-label">Overview</div>

        <NavLink
          to="/"
          end
          className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
        >
          <LayoutDashboard />
          <span>Dashboard</span>
        </NavLink>

        <NavLink
          to="/scans"
          className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
        >
          <Radar />
          <span>Scans</span>
        </NavLink>

        <div className="nav-section-label">Security</div>

        <NavLink
          to="/vulnerabilities"
          className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
        >
          <Shield />
          <span>Vulnerabilities</span>
        </NavLink>

        <NavLink
          to="/compliance"
          className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
        >
          <FileCheck />
          <span>Compliance</span>
        </NavLink>

        <div className="nav-section-label">System</div>

        <NavLink
          to="/activity"
          className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
        >
          <Activity />
          <span>Activity Log</span>
        </NavLink>

        <NavLink
          to="/settings"
          className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
        >
          <Settings />
          <span>Settings</span>
        </NavLink>
      </nav>

      <div style={{
        padding: '16px 20px',
        borderTop: '1px solid var(--border-subtle)',
        fontSize: '11px',
        color: 'var(--text-muted)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <div style={{
            width: '8px',
            height: '8px',
            borderRadius: '50%',
            background: 'var(--success)',
            boxShadow: '0 0 6px var(--success)',
          }} />
          Engine Online
        </div>
      </div>
    </aside>
  );
}
