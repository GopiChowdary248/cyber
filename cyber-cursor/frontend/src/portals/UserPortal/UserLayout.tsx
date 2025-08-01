import React, { useState } from 'react';
import { Link, useLocation, Outlet } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';

const UserLayout: React.FC = () => {
  const { user, logout } = useAuth();
  const location = useLocation();
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  const userNavigation = [
    {
      name: 'Dashboard',
      href: '/user',
      icon: '🏠',
      description: 'Security overview and alerts'
    },
    {
      name: 'Report Incident',
      href: '/user/report-incident',
      icon: '🚨',
      description: 'Report security issues'
    },
    {
      name: 'My Incidents',
      href: '/user/my-incidents',
      icon: '📋',
      description: 'View your reported incidents'
    },
    {
      name: 'Security Training',
      href: '/user/training',
      icon: '📚',
      description: 'Complete security training'
    },
    {
      name: 'Security Tips',
      href: '/user/tips',
      icon: '💡',
      description: 'Security best practices'
    },
    {
      name: 'Request Access',
      href: '/user/request-access',
      icon: '🔐',
      description: 'Request system access'
    },
    {
      name: 'Resources',
      href: '/user/resources',
      icon: '📖',
      description: 'Security resources and policies'
    },
    {
      name: 'Profile',
      href: '/user/profile',
      icon: '👤',
      description: 'Manage your profile'
    }
  ];

  const isActive = (path: string) => {
    return location.pathname === path;
  };

  return (
    <div className="min-h-screen bg-cyber-dark">
      <div className="flex">
        {/* User Sidebar */}
        <div className={`bg-cyber-darker border-r border-cyber-accent/30 transition-all duration-300 ${
          sidebarCollapsed ? 'w-16' : 'w-64'
        }`}>
          <div className="flex flex-col h-screen">
            {/* User Header */}
            <div className="p-4 border-b border-cyber-accent/30">
              <div className="flex items-center justify-between">
                {!sidebarCollapsed && (
                  <div>
                    <h1 className="text-xl font-bold text-blue-400">🛡️ Security Portal</h1>
                    <p className="text-xs text-gray-400">Stay Secure</p>
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

            {/* User Navigation */}
            <nav className="flex-1 p-4 space-y-2 overflow-y-auto">
              {userNavigation.map((item) => (
                <Link
                  key={item.name}
                  to={item.href}
                  className={`flex items-center p-3 rounded-lg transition-all duration-200 group ${
                    isActive(item.href)
                      ? 'bg-blue-600 text-white'
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

            {/* User Profile */}
            <div className="p-4 border-t border-cyber-accent/30">
              <div className="flex items-center">
                <div className="w-8 h-8 bg-blue-600 rounded-full flex items-center justify-center">
                  <span className="text-white text-sm font-semibold">
                    {user?.username?.charAt(0).toUpperCase() || 'U'}
                  </span>
                </div>
                {!sidebarCollapsed && (
                  <div className="ml-3 flex-1">
                    <p className="text-sm font-medium text-white">
                      {user?.full_name || user?.username || 'User'}
                    </p>
                    <p className="text-xs text-blue-400 font-semibold">
                      {user?.role?.toUpperCase() || 'USER'}
                    </p>
                  </div>
                )}
                {!sidebarCollapsed && (
                  <button
                    onClick={logout}
                    className="p-2 rounded-lg bg-blue-900/20 hover:bg-blue-900/40 transition-colors"
                    title="Logout"
                  >
                    <span className="text-blue-400">🚪</span>
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Main Content */}
        <div className="flex-1">
          {/* User Top Bar */}
          <div className="bg-cyber-darker border-b border-cyber-accent/30 p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-4">
                <h2 className="text-lg font-semibold text-white">
                  {userNavigation.find(item => isActive(item.href))?.name || 'Security Portal'}
                </h2>
                <span className="px-2 py-1 bg-blue-900/20 text-blue-400 text-xs font-medium rounded">
                  USER MODE
                </span>
              </div>
              <div className="flex items-center space-x-4">
                <button className="p-2 rounded-lg bg-cyber-dark hover:bg-cyber-accent/20 transition-colors">
                  <span className="text-cyber-accent">🔔</span>
                </button>
                <button className="p-2 rounded-lg bg-cyber-dark hover:bg-cyber-accent/20 transition-colors">
                  <span className="text-cyber-accent">❓</span>
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

export default UserLayout; 