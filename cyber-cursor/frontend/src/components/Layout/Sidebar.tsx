import React, { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import RoleBasedNavigation from './RoleBasedNavigation';

const Sidebar: React.FC = () => {
  const { user, logout } = useAuth();
  const location = useLocation();
  const [isCollapsed, setIsCollapsed] = useState(false);

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
        <div className="flex-1 p-4">
          <RoleBasedNavigation />
        </div>

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