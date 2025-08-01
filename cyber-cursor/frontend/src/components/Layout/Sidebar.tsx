import React, { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';

const Sidebar: React.FC = () => {
  const { user, logout } = useAuth();
  const location = useLocation();
  const [isCollapsed, setIsCollapsed] = useState(false);

  const navigation = [
    {
      name: 'Dashboard',
      href: '/dashboard',
      icon: '📊',
      description: 'Security overview and metrics'
    },
    {
      name: 'Incidents',
      href: '/incidents',
      icon: '🚨',
      description: 'Manage security incidents'
    },
    {
      name: 'Cloud Security',
      href: '/cloud-security',
      icon: '☁️',
      description: 'Cloud infrastructure scanning'
    },
    {
      name: 'Phishing Detection',
      href: '/phishing',
      icon: '🎣',
      description: 'Email threat analysis'
    },
    {
      name: 'Threat Intelligence',
      href: '/threat-intel',
      icon: '🔍',
      description: 'Threat intelligence feeds'
    },
    {
      name: 'Reports',
      href: '/reports',
      icon: '📈',
      description: 'Security reports and analytics'
    }
  ];

  const adminNavigation = [
    {
      name: 'Users',
      href: '/users',
      icon: '👥',
      description: 'User management'
    },
    {
      name: 'Settings',
      href: '/settings',
      icon: '⚙️',
      description: 'System configuration'
    }
  ];

  const isActive = (path: string) => {
    return location.pathname === path;
  };

  return (
    <div className={`bg-cyber-darker border-r border-cyber-accent/30 transition-all duration-300 ${
      isCollapsed ? 'w-16' : 'w-64'
    }`}>
      <div className="flex flex-col h-full">
        {/* Header */}
        <div className="p-4 border-b border-cyber-accent/30">
          <div className="flex items-center justify-between">
            {!isCollapsed && (
              <div>
                <h1 className="text-xl font-bold text-cyber-accent">CyberShield</h1>
                <p className="text-xs text-gray-400">Security Platform</p>
              </div>
            )}
            <button
              onClick={() => setIsCollapsed(!isCollapsed)}
              className="p-2 rounded-lg bg-cyber-dark hover:bg-cyber-accent/20 transition-colors"
            >
              <span className="text-cyber-accent">
                {isCollapsed ? '→' : '←'}
              </span>
            </button>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-4 space-y-2">
          {navigation.map((item) => (
            <Link
              key={item.name}
              to={item.href}
              className={`flex items-center p-3 rounded-lg transition-all duration-200 group ${
                isActive(item.href)
                  ? 'bg-cyber-accent text-white'
                  : 'text-gray-300 hover:bg-cyber-dark hover:text-white'
              }`}
              title={isCollapsed ? item.description : undefined}
            >
              <span className="text-lg mr-3">{item.icon}</span>
              {!isCollapsed && (
                <div>
                  <span className="font-medium">{item.name}</span>
                  {!isCollapsed && (
                    <p className="text-xs text-gray-400 group-hover:text-gray-300">
                      {item.description}
                    </p>
                  )}
                </div>
              )}
            </Link>
          ))}
        </nav>

        {/* Admin Section */}
        {user?.role === 'admin' && (
          <div className="p-4 border-t border-cyber-accent/30">
            <div className="mb-2">
              {!isCollapsed && (
                <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
                  Administration
                </h3>
              )}
            </div>
            <nav className="space-y-2">
              {adminNavigation.map((item) => (
                <Link
                  key={item.name}
                  to={item.href}
                  className={`flex items-center p-3 rounded-lg transition-all duration-200 group ${
                    isActive(item.href)
                      ? 'bg-cyber-accent text-white'
                      : 'text-gray-300 hover:bg-cyber-dark hover:text-white'
                  }`}
                  title={isCollapsed ? item.description : undefined}
                >
                  <span className="text-lg mr-3">{item.icon}</span>
                  {!isCollapsed && (
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
          </div>
        )}

        {/* User Profile */}
        <div className="p-4 border-t border-cyber-accent/30">
          <div className="flex items-center">
            <div className="w-8 h-8 bg-cyber-accent rounded-full flex items-center justify-center">
              <span className="text-white text-sm font-semibold">
                {user?.username?.charAt(0).toUpperCase() || 'U'}
              </span>
            </div>
            {!isCollapsed && (
              <div className="ml-3 flex-1">
                <p className="text-sm font-medium text-white">
                  {user?.full_name || user?.username || 'User'}
                </p>
                <p className="text-xs text-gray-400 capitalize">
                  {user?.role || 'user'}
                </p>
              </div>
            )}
            {!isCollapsed && (
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
  );
};

export default Sidebar; 