import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';

interface UserDashboardData {
  my_incidents: {
    total: number;
    open: number;
    resolved: number;
    recent: any[];
  };
  security_alerts: {
    total: number;
    high_priority: number;
    recent: any[];
  };
  training_progress: {
    completed_modules: number;
    total_modules: number;
    next_training: string;
    score: number;
  };
  quick_actions: {
    report_incident: boolean;
    request_access: boolean;
    view_policies: boolean;
  };
}

const UserDashboard: React.FC = () => {
  const { user } = useAuth();
  const [dashboardData, setDashboardData] = useState<UserDashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');

  const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

  useEffect(() => {
    fetchUserDashboardData();
  }, []);

  const fetchUserDashboardData = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('access_token');
      
      const response = await fetch(`${API_URL}/api/v1/user/dashboard`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error('Failed to fetch user dashboard data');
      }

      const data = await response.json();
      setDashboardData(data);
    } catch (err) {
      console.error('Error fetching user dashboard:', err);
      // Use mock data for development
      setDashboardData({
        my_incidents: {
          total: 3,
          open: 1,
          resolved: 2,
          recent: [
            { id: 1, title: 'Suspicious Email Report', status: 'open', created_at: '2024-01-15T10:30:00Z' },
            { id: 2, title: 'Access Request', status: 'resolved', created_at: '2024-01-10T14:20:00Z' }
          ]
        },
        security_alerts: {
          total: 2,
          high_priority: 1,
          recent: [
            { id: 1, title: 'Phishing Email Detected', priority: 'high', created_at: '2024-01-15T09:15:00Z' },
            { id: 2, title: 'Password Policy Update', priority: 'medium', created_at: '2024-01-14T16:45:00Z' }
          ]
        },
        training_progress: {
          completed_modules: 8,
          total_modules: 12,
          next_training: '2024-01-20T10:00:00Z',
          score: 85
        },
        quick_actions: {
          report_incident: true,
          request_access: true,
          view_policies: true
        }
      });
    } finally {
      setLoading(false);
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority.toLowerCase()) {
      case 'high': return 'text-red-400 bg-red-900/20';
      case 'medium': return 'text-yellow-400 bg-yellow-900/20';
      case 'low': return 'text-green-400 bg-green-900/20';
      default: return 'text-gray-400 bg-gray-900/20';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'open': return 'text-orange-400 bg-orange-900/20';
      case 'resolved': return 'text-green-400 bg-green-900/20';
      case 'pending': return 'text-yellow-400 bg-yellow-900/20';
      default: return 'text-gray-400 bg-gray-900/20';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyber-accent"></div>
      </div>
    );
  }

  if (!dashboardData) {
    return (
      <div className="bg-red-900/20 border border-red-500/50 rounded-lg p-4">
        <p className="text-red-400">Failed to load user dashboard data</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* User Header */}
      <div className="bg-gradient-to-r from-blue-900/20 to-green-900/20 border border-cyber-accent/30 rounded-lg p-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">
              🛡️ Security Portal
            </h1>
            <p className="text-gray-400">
              Welcome back, {user?.full_name || user?.username}. Stay secure and report any suspicious activities.
            </p>
          </div>
          <div className="text-right">
            <p className="text-sm text-gray-400">Training Progress</p>
            <p className="text-2xl font-bold text-green-400">
              {Math.round((dashboardData.training_progress.completed_modules / dashboardData.training_progress.total_modules) * 100)}%
            </p>
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <button className="bg-red-600 hover:bg-red-700 text-white p-4 rounded-lg transition-colors">
          <div className="text-2xl mb-2">🚨</div>
          <div className="font-semibold">Report Incident</div>
          <div className="text-sm opacity-75">Report security issues</div>
        </button>
        
        <button className="bg-blue-600 hover:bg-blue-700 text-white p-4 rounded-lg transition-colors">
          <div className="text-2xl mb-2">🔐</div>
          <div className="font-semibold">Request Access</div>
          <div className="text-sm opacity-75">Request system access</div>
        </button>
        
        <button className="bg-green-600 hover:bg-green-700 text-white p-4 rounded-lg transition-colors">
          <div className="text-2xl mb-2">📚</div>
          <div className="font-semibold">Security Training</div>
          <div className="text-sm opacity-75">Complete training modules</div>
        </button>
      </div>

      {/* Main Content Tabs */}
      <div className="bg-cyber-dark border border-cyber-accent/30 rounded-lg">
        {/* Tab Navigation */}
        <div className="border-b border-cyber-accent/30">
          <nav className="flex space-x-8 px-6">
            {[
              { id: 'overview', name: 'Overview', icon: '📊' },
              { id: 'incidents', name: 'My Incidents', icon: '🚨' },
              { id: 'alerts', name: 'Security Alerts', icon: '🔔' },
              { id: 'training', name: 'Training', icon: '📚' },
              { id: 'resources', name: 'Resources', icon: '📖' }
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center py-4 px-2 border-b-2 font-medium text-sm transition-colors ${
                  activeTab === tab.id
                    ? 'border-cyber-accent text-cyber-accent'
                    : 'border-transparent text-gray-400 hover:text-gray-300'
                }`}
              >
                <span className="mr-2">{tab.icon}</span>
                {tab.name}
              </button>
            ))}
          </nav>
        </div>

        {/* Tab Content */}
        <div className="p-6">
          {activeTab === 'overview' && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* My Incidents Summary */}
              <div className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-6">
                <h3 className="text-lg font-semibold text-white mb-4">My Incidents</h3>
                <div className="space-y-4">
                  <div className="flex justify-between">
                    <span className="text-gray-400">Total Incidents</span>
                    <span className="text-white">{dashboardData.my_incidents.total}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Open Incidents</span>
                    <span className="text-orange-400">{dashboardData.my_incidents.open}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Resolved</span>
                    <span className="text-green-400">{dashboardData.my_incidents.resolved}</span>
                  </div>
                </div>
              </div>

              {/* Security Alerts */}
              <div className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-6">
                <h3 className="text-lg font-semibold text-white mb-4">Security Alerts</h3>
                <div className="space-y-4">
                  <div className="flex justify-between">
                    <span className="text-gray-400">Total Alerts</span>
                    <span className="text-white">{dashboardData.security_alerts.total}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">High Priority</span>
                    <span className="text-red-400">{dashboardData.security_alerts.high_priority}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Training Score</span>
                    <span className="text-green-400">{dashboardData.training_progress.score}%</span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'incidents' && (
            <div className="space-y-6">
              <div className="flex justify-between items-center">
                <h3 className="text-lg font-semibold text-white">My Incidents</h3>
                <button className="bg-cyber-accent hover:bg-cyber-accent/80 text-white px-4 py-2 rounded-lg">
                  Report New Incident
                </button>
              </div>
              
              <div className="space-y-4">
                {dashboardData.my_incidents.recent.map((incident: any) => (
                  <div key={incident.id} className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <h4 className="text-white font-medium">{incident.title}</h4>
                        <p className="text-gray-400 text-sm">
                          Reported on {new Date(incident.created_at).toLocaleDateString()}
                        </p>
                      </div>
                      <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(incident.status)}`}>
                        {incident.status}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'alerts' && (
            <div className="space-y-6">
              <h3 className="text-lg font-semibold text-white">Security Alerts</h3>
              <div className="space-y-4">
                {dashboardData.security_alerts.recent.map((alert: any) => (
                  <div key={alert.id} className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <h4 className="text-white font-medium">{alert.title}</h4>
                        <p className="text-gray-400 text-sm">
                          {new Date(alert.created_at).toLocaleDateString()}
                        </p>
                      </div>
                      <span className={`px-3 py-1 rounded-full text-xs font-medium ${getPriorityColor(alert.priority)}`}>
                        {alert.priority}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'training' && (
            <div className="space-y-6">
              <h3 className="text-lg font-semibold text-white">Security Training</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-6">
                  <h4 className="text-white font-semibold mb-4">Progress Overview</h4>
                  <div className="space-y-4">
                    <div className="flex justify-between">
                      <span className="text-gray-400">Completed Modules</span>
                      <span className="text-green-400">{dashboardData.training_progress.completed_modules}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Total Modules</span>
                      <span className="text-white">{dashboardData.training_progress.total_modules}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Overall Score</span>
                      <span className="text-blue-400">{dashboardData.training_progress.score}%</span>
                    </div>
                  </div>
                </div>
                
                <div className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-6">
                  <h4 className="text-white font-semibold mb-4">Next Training</h4>
                  <div className="space-y-4">
                    <div className="text-center">
                      <div className="text-2xl font-bold text-cyber-accent mb-2">
                        {new Date(dashboardData.training_progress.next_training).toLocaleDateString()}
                      </div>
                      <p className="text-gray-400">Next scheduled training session</p>
                    </div>
                    <button className="w-full bg-cyber-accent hover:bg-cyber-accent/80 text-white py-2 px-4 rounded-lg transition-colors">
                      Start Training
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'resources' && (
            <div className="space-y-6">
              <h3 className="text-lg font-semibold text-white">Security Resources</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-6">
                  <h4 className="text-white font-semibold mb-4">Security Policies</h4>
                  <div className="space-y-3">
                    <button className="w-full text-left p-3 bg-cyber-dark rounded hover:bg-cyber-accent/20 transition-colors">
                      <div className="text-white font-medium">Password Policy</div>
                      <div className="text-gray-400 text-sm">Learn about password requirements</div>
                    </button>
                    <button className="w-full text-left p-3 bg-cyber-dark rounded hover:bg-cyber-accent/20 transition-colors">
                      <div className="text-white font-medium">Data Protection</div>
                      <div className="text-gray-400 text-sm">Understand data handling procedures</div>
                    </button>
                    <button className="w-full text-left p-3 bg-cyber-dark rounded hover:bg-cyber-accent/20 transition-colors">
                      <div className="text-white font-medium">Incident Response</div>
                      <div className="text-gray-400 text-sm">What to do during security incidents</div>
                    </button>
                  </div>
                </div>
                
                <div className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-6">
                  <h4 className="text-white font-semibold mb-4">Quick Links</h4>
                  <div className="space-y-3">
                    <button className="w-full text-left p-3 bg-cyber-dark rounded hover:bg-cyber-accent/20 transition-colors">
                      <div className="text-white font-medium">IT Support</div>
                      <div className="text-gray-400 text-sm">Contact IT support team</div>
                    </button>
                    <button className="w-full text-left p-3 bg-cyber-dark rounded hover:bg-cyber-accent/20 transition-colors">
                      <div className="text-white font-medium">Security Tips</div>
                      <div className="text-gray-400 text-sm">Daily security best practices</div>
                    </button>
                    <button className="w-full text-left p-3 bg-cyber-dark rounded hover:bg-cyber-accent/20 transition-colors">
                      <div className="text-white font-medium">FAQ</div>
                      <div className="text-gray-400 text-sm">Frequently asked questions</div>
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default UserDashboard; 