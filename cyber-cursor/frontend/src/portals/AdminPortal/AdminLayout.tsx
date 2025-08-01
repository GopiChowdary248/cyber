import React, { useState } from 'react';
import { Link, useLocation, Outlet } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';

const AdminLayout: React.FC = () => {
  const { user, logout } = useAuth();
  const location = useLocation();
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  const adminNavigation = [
    {
      name: 'Dashboard',
      href: '/admin',
      icon: '📊',
      description: 'System overview and metrics'
    },
    {
      name: 'User Management',
      href: '/admin/users',
      icon: '👥',
      description: 'Manage users and permissions'
    },
    {
      name: 'Incident Management',
      href: '/admin/incidents',
      icon: '🚨',
      description: 'Handle security incidents'
    },
    {
      name: 'Cloud Security',
      href: '/admin/cloud-security',
      icon: '☁️',
      description: 'Cloud infrastructure monitoring'
    },
    {
      name: 'Network Security',
      href: '/admin/network-security',
      icon: '🛡️',
      description: 'Firewall, IDS/IPS, VPN, NAC management'
    },
    {
      name: 'Endpoint Security',
      href: '/admin/endpoint-security',
      icon: '💻',
      description: 'Antivirus, EDR, Application Whitelisting'
    },
    {
      name: 'Application Security',
      href: '/admin/application-security',
      icon: '🔒',
      description: 'SAST, DAST, SCA, WAF management'
    },
    {
      name: 'Data Protection',
      href: '/admin/data-protection',
      icon: '🔐',
      description: 'Encryption, DLP, Database Monitoring'
    },
    {
      name: 'Monitoring & SIEM',
      href: '/admin/monitoring-siem-soar',
      icon: '📊',
      description: 'Centralized logging, incident response, anomaly detection'
    },
    {
      name: 'Threat Intelligence',
      href: '/admin/threat-intelligence',
      icon: '🔍',
      description: 'Threat intelligence and hunting capabilities'
    },
    {
      name: 'System Monitoring',
      href: '/admin/monitoring',
      icon: '📈',
      description: 'System performance and logs'
    },
    {
      name: 'Compliance',
      href: '/admin/compliance',
      icon: '📋',
      description: 'Compliance and audit reports'
    },
    {
      name: 'Settings',
      href: '/admin/settings',
      icon: '⚙️',
      description: 'System configuration'
    }
  ];

  const isActive = (path: string) => {
    return location.pathname === path;
  };

  return (
    <div className="min-h-screen bg-cyber-dark">
      <div className="flex">
        {/* Admin Sidebar */}
        <div className={`bg-cyber-darker border-r border-cyber-accent/30 transition-all duration-300 ${
          sidebarCollapsed ? 'w-16' : 'w-64'
        }`}>
          <div className="flex flex-col h-screen">
            {/* Admin Header */}
            <div className="p-4 border-b border-cyber-accent/30">
              <div className="flex items-center justify-between">
                {!sidebarCollapsed && (
                  <div>
                    <h1 className="text-xl font-bold text-red-400">🛡️ Admin Portal</h1>
                    <p className="text-xs text-gray-400">System Administration</p>
                  </div>
                )}
                <button
                  onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
                  className="p-2 rounded-lg bg-cyber-dark hover:bg-cyber-accent/20 transition-colors"
                >
                  <span className="text-cyber-accent">
                    {sidebarCollapsed ? '→' : '←'}
                  </span>
                </button>
              </div>
            </div>

            {/* Admin Navigation */}
            <nav className="flex-1 p-4 space-y-2 overflow-y-auto">
              {adminNavigation.map((item) => (
                <Link
                  key={item.name}
                  to={item.href}
                  className={`flex items-center p-3 rounded-lg transition-all duration-200 group ${
                    isActive(item.href)
                      ? 'bg-red-600 text-white'
                      : 'text-gray-300 hover:bg-cyber-dark hover:text-white'
                  }`}
                  title={sidebarCollapsed ? item.description : undefined}
                >
                  <span className="text-lg mr-3">{item.icon}</span>
                  {!sidebarCollapsed && (
                    <div>
                      <span className="font-medium">{item.name}</span>
                      <p className="text-xs text-gray-400 group-hover:text-gray-300">
                        {item.description}
                      </p>
                    </div>
                  )}
                </Link>
              ))}
            </nav>

            {/* Admin User Profile */}
            <div className="p-4 border-t border-cyber-accent/30">
              <div className="flex items-center">
                <div className="w-8 h-8 bg-red-600 rounded-full flex items-center justify-center">
                  <span className="text-white text-sm font-semibold">
                    {user?.username?.charAt(0).toUpperCase() || 'A'}
                  </span>
                </div>
                {!sidebarCollapsed && (
                  <div className="ml-3 flex-1">
                    <p className="text-sm font-medium text-white">
                      {user?.full_name || user?.username || 'Admin'}
                    </p>
                    <p className="text-xs text-red-400 font-semibold">
                      ADMINISTRATOR
                    </p>
                  </div>
                )}
                {!sidebarCollapsed && (
                  <button
                    onClick={logout}
                    className="p-2 rounded-lg bg-red-900/20 hover:bg-red-900/40 transition-colors"
                    title="Logout"
                  >
                    <span className="text-red-400">🚪</span>
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Main Content */}
        <div className="flex-1">
          {/* Admin Top Bar */}
          <div className="bg-cyber-darker border-b border-cyber-accent/30 p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-4">
                <h2 className="text-lg font-semibold text-white">
                  {adminNavigation.find(item => isActive(item.href))?.name || 'Admin Portal'}
                </h2>
                <span className="px-2 py-1 bg-red-900/20 text-red-400 text-xs font-medium rounded">
                  ADMIN MODE
                </span>
              </div>
              <div className="flex items-center space-x-4">
                <button className="p-2 rounded-lg bg-cyber-dark hover:bg-cyber-accent/20 transition-colors">
                  <span className="text-cyber-accent">🔔</span>
                </button>
                <button className="p-2 rounded-lg bg-cyber-dark hover:bg-cyber-accent/20 transition-colors">
                  <span className="text-cyber-accent">⚡</span>
                </button>
              </div>
            </div>
          </div>

          {/* Page Content */}
          <main className="h-screen overflow-y-auto">
            <Outlet />
          </main>
        </div>
      </div>
    </div>
  );
};

export default AdminLayout; 