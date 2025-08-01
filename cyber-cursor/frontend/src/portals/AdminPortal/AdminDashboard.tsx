import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';

interface DashboardMetrics {
  user_stats: {
    total_users: number;
    active_users: number;
    new_users_last_30_days: number;
  };
  incident_stats: {
    total_incidents: number;
    open_incidents: number;
    critical_incidents: number;
    avg_resolution_time_hours: number;
  };
  cloud_security_stats: {
    total_misconfigurations: number;
    high_severity_misconfigurations: number;
    scans_completed_last_7_days: number;
  };
  phishing_stats: {
    total_emails_analyzed: number;
    phishing_emails_detected: number;
    auto_responses_sent: number;
  };
  system_health: {
    database_status: string;
    redis_status: string;
    ai_service_status: string;
    uptime_seconds: number;
    cpu_usage_percent: number;
    memory_usage_percent: number;
  };
}

interface TrendData {
  date: string;
  incidents: number;
  phishing: number;
  users: number;
}

const AdminDashboard: React.FC = () => {
  const { user } = useAuth();
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [trends, setTrends] = useState<TrendData[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedTimeRange, setSelectedTimeRange] = useState('7d');
  const [activeTab, setActiveTab] = useState('overview');

  const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, [selectedTimeRange]);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('access_token');
      
      const [metricsResponse, trendsResponse] = await Promise.all([
        fetch(`${API_URL}/api/v1/admin/dashboard`, {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        }),
        fetch(`${API_URL}/api/v1/admin/analytics/trends?days=${selectedTimeRange}`, {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        })
      ]);

      if (metricsResponse.ok) {
        const metricsData = await metricsResponse.json();
        setMetrics(metricsData || getMockMetrics());
      }

      if (trendsResponse.ok) {
        const trendsData = await trendsResponse.json();
        setTrends(trendsData || getMockTrends());
      }
    } catch (err) {
      console.error('Error fetching dashboard data:', err);
      setMetrics(getMockMetrics());
      setTrends(getMockTrends());
    } finally {
      setLoading(false);
    }
  };

  const getMockMetrics = (): DashboardMetrics => ({
    user_stats: {
      total_users: 156,
      active_users: 142,
      new_users_last_30_days: 15
    },
    incident_stats: {
      total_incidents: 45,
      open_incidents: 8,
      critical_incidents: 3,
      avg_resolution_time_hours: 4.2
    },
    cloud_security_stats: {
      total_misconfigurations: 23,
      high_severity_misconfigurations: 7,
      scans_completed_last_7_days: 12
    },
    phishing_stats: {
      total_emails_analyzed: 89,
      phishing_emails_detected: 23,
      auto_responses_sent: 120
    },
    system_health: {
      database_status: "operational",
      redis_status: "operational",
      ai_service_status: "operational",
      uptime_seconds: 36000,
      cpu_usage_percent: 25,
      memory_usage_percent: 60
    }
  });

  const getMockTrends = (): TrendData[] => {
    const days = selectedTimeRange === '7d' ? 7 : selectedTimeRange === '30d' ? 30 : 90;
    return Array.from({ length: days }, (_, i) => ({
      date: new Date(Date.now() - (days - i - 1) * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
      incidents: Math.floor(Math.random() * 5) + 1,
      phishing: Math.floor(Math.random() * 3) + 1,
      users: Math.floor(Math.random() * 3) + 1
    }));
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'operational': return 'text-green-400 bg-green-900/20';
      case 'warning': return 'text-yellow-400 bg-yellow-900/20';
      case 'critical': return 'text-red-400 bg-red-900/20';
      default: return 'text-gray-400 bg-gray-900/20';
    }
  };

  const getUptimeFormatted = (seconds: number) => {
    const hours = Math.floor(seconds / 3600);
    const days = Math.floor(hours / 24);
    if (days > 0) return `${days}d ${hours % 24}h`;
    return `${hours}h`;
  };

  const getUsageColor = (percentage: number) => {
    if (percentage < 50) return 'text-green-400';
    if (percentage < 80) return 'text-yellow-400';
    return 'text-red-400';
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-400"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gradient-to-r from-red-900/20 to-orange-900/20 border border-red-700/30 rounded-lg p-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">⚙️ Admin Dashboard</h1>
            <p className="text-gray-400">System overview and key metrics</p>
          </div>
          <div className="flex items-center space-x-4">
            <select
              value={selectedTimeRange}
              onChange={(e) => setSelectedTimeRange(e.target.value)}
              className="bg-cyber-dark border border-red-700/30 rounded-lg px-3 py-2 text-white"
            >
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
              <option value="90d">Last 90 Days</option>
            </select>
            <button
              onClick={fetchDashboardData}
              className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg transition-colors"
            >
              🔄 Refresh
            </button>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="bg-cyber-darker border border-red-700/30 rounded-lg p-4">
        <div className="flex space-x-4">
          {[
            { id: 'overview', name: 'Overview', icon: '📊' },
            { id: 'incidents', name: 'Incidents', icon: '🚨' },
            { id: 'security', name: 'Security', icon: '🛡️' },
            { id: 'users', name: 'Users', icon: '👥' },
            { id: 'system', name: 'System', icon: '⚙️' }
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center space-x-2 px-4 py-2 rounded-lg transition-colors ${
                activeTab === tab.id
                  ? 'bg-red-600 text-white'
                  : 'text-gray-400 hover:text-white hover:bg-red-700/20'
              }`}
            >
              <span>{tab.icon}</span>
              <span>{tab.name}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Overview Tab */}
      {activeTab === 'overview' && metrics && (
        <div className="space-y-6">
          {/* Key Metrics */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <div className="bg-cyber-darker border border-red-700/30 rounded-lg p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="text-2xl">👥</div>
                <div className="text-green-400 text-sm">+12%</div>
              </div>
              <div className="text-3xl font-bold text-white mb-2">{metrics.user_stats.total_users}</div>
              <div className="text-gray-400">Total Users</div>
              <div className="text-sm text-gray-500 mt-2">
                {metrics.user_stats.active_users} active • {metrics.user_stats.new_users_last_30_days} new this month
              </div>
            </div>

            <div className="bg-cyber-darker border border-red-700/30 rounded-lg p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="text-2xl">🚨</div>
                <div className="text-red-400 text-sm">+5</div>
              </div>
              <div className="text-3xl font-bold text-white mb-2">{metrics.incident_stats.total_incidents}</div>
              <div className="text-gray-400">Total Incidents</div>
              <div className="text-sm text-gray-500 mt-2">
                {metrics.incident_stats.open_incidents} open • {metrics.incident_stats.critical_incidents} critical
              </div>
            </div>

            <div className="bg-cyber-darker border border-red-700/30 rounded-lg p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="text-2xl">🛡️</div>
                <div className="text-yellow-400 text-sm">-3</div>
              </div>
              <div className="text-3xl font-bold text-white mb-2">{metrics.cloud_security_stats.total_misconfigurations}</div>
              <div className="text-gray-400">Misconfigurations</div>
              <div className="text-sm text-gray-500 mt-2">
                {metrics.cloud_security_stats.high_severity_misconfigurations} high severity
              </div>
            </div>

            <div className="bg-cyber-darker border border-red-700/30 rounded-lg p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="text-2xl">🎣</div>
                <div className="text-green-400 text-sm">+8</div>
              </div>
              <div className="text-3xl font-bold text-white mb-2">{metrics.phishing_stats.phishing_emails_detected}</div>
              <div className="text-gray-400">Phishing Detected</div>
              <div className="text-sm text-gray-500 mt-2">
                {metrics.phishing_stats.total_emails_analyzed} emails analyzed
              </div>
            </div>
          </div>

          {/* Trends Chart */}
          <div className="bg-cyber-darker border border-red-700/30 rounded-lg p-6">
            <h3 className="text-xl font-semibold text-white mb-4">📈 Activity Trends</h3>
            <div className="h-64 flex items-end justify-between space-x-2">
              {trends.slice(-7).map((trend, index) => (
                <div key={index} className="flex-1 flex flex-col items-center space-y-2">
                  <div className="w-full bg-red-900/20 rounded-t">
                    <div 
                      className="bg-red-600 rounded-t transition-all duration-300"
                      style={{ height: `${(trend.incidents / 5) * 100}%` }}
                    ></div>
                  </div>
                  <div className="text-xs text-gray-400">{trend.date.split('-')[2]}</div>
                </div>
              ))}
            </div>
            <div className="flex justify-center space-x-6 mt-4 text-sm">
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-red-600 rounded"></div>
                <span className="text-gray-400">Incidents</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-blue-600 rounded"></div>
                <span className="text-gray-400">Phishing</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-green-600 rounded"></div>
                <span className="text-gray-400">Users</span>
              </div>
            </div>
          </div>

          {/* Quick Actions */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-cyber-darker border border-red-700/30 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-white mb-4">⚡ Quick Actions</h3>
              <div className="space-y-3">
                <button className="w-full bg-red-600 hover:bg-red-700 text-white py-2 rounded-lg transition-colors">
                  🚨 View Critical Incidents
                </button>
                <button className="w-full bg-orange-600 hover:bg-orange-700 text-white py-2 rounded-lg transition-colors">
                  👥 Manage Users
                </button>
                <button className="w-full bg-blue-600 hover:bg-blue-700 text-white py-2 rounded-lg transition-colors">
                  📊 Generate Report
                </button>
              </div>
            </div>

            <div className="bg-cyber-darker border border-red-700/30 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-white mb-4">🔔 Recent Alerts</h3>
              <div className="space-y-3">
                <div className="flex items-center space-x-3 p-3 bg-red-900/20 rounded-lg">
                  <div className="w-2 h-2 bg-red-400 rounded-full"></div>
                  <div>
                    <div className="text-white text-sm">Critical incident reported</div>
                    <div className="text-gray-400 text-xs">2 minutes ago</div>
                  </div>
                </div>
                <div className="flex items-center space-x-3 p-3 bg-yellow-900/20 rounded-lg">
                  <div className="w-2 h-2 bg-yellow-400 rounded-full"></div>
                  <div>
                    <div className="text-white text-sm">High severity misconfiguration detected</div>
                    <div className="text-gray-400 text-xs">15 minutes ago</div>
                  </div>
                </div>
                <div className="flex items-center space-x-3 p-3 bg-blue-900/20 rounded-lg">
                  <div className="w-2 h-2 bg-blue-400 rounded-full"></div>
                  <div>
                    <div className="text-white text-sm">New user registration</div>
                    <div className="text-gray-400 text-xs">1 hour ago</div>
                  </div>
                </div>
              </div>
            </div>

            <div className="bg-cyber-darker border border-red-700/30 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-white mb-4">📋 System Status</h3>
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Database</span>
                  <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(metrics.system_health.database_status)}`}>
                    {metrics.system_health.database_status}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Redis</span>
                  <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(metrics.system_health.redis_status)}`}>
                    {metrics.system_health.redis_status}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">AI Service</span>
                  <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(metrics.system_health.ai_service_status)}`}>
                    {metrics.system_health.ai_service_status}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Uptime</span>
                  <span className="text-white text-sm">{getUptimeFormatted(metrics.system_health.uptime_seconds)}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">CPU</span>
                  <span className={`text-sm ${getUsageColor(metrics.system_health.cpu_usage_percent)}`}>
                    {metrics.system_health.cpu_usage_percent}%
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Memory</span>
                  <span className={`text-sm ${getUsageColor(metrics.system_health.memory_usage_percent)}`}>
                    {metrics.system_health.memory_usage_percent}%
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Incidents Tab */}
      {activeTab === 'incidents' && (
        <div className="bg-cyber-darker border border-red-700/30 rounded-lg p-6">
          <h2 className="text-2xl font-bold text-white mb-6">🚨 Incident Management</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
            <div className="bg-red-900/20 border border-red-700/30 rounded-lg p-4">
              <div className="text-2xl font-bold text-red-400">{metrics?.incident_stats.critical_incidents || 0}</div>
              <div className="text-gray-400">Critical Incidents</div>
            </div>
            <div className="bg-orange-900/20 border border-orange-700/30 rounded-lg p-4">
              <div className="text-2xl font-bold text-orange-400">{metrics?.incident_stats.open_incidents || 0}</div>
              <div className="text-gray-400">Open Incidents</div>
            </div>
            <div className="bg-green-900/20 border border-green-700/30 rounded-lg p-4">
              <div className="text-2xl font-bold text-green-400">{metrics?.incident_stats.avg_resolution_time_hours || 0}h</div>
              <div className="text-gray-400">Avg Resolution Time</div>
            </div>
          </div>
          <p className="text-gray-400">Detailed incident analytics and management interface coming soon...</p>
        </div>
      )}

      {/* Security Tab */}
      {activeTab === 'security' && (
        <div className="bg-cyber-darker border border-red-700/30 rounded-lg p-6">
          <h2 className="text-2xl font-bold text-white mb-6">🛡️ Security Overview</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="bg-cyber-dark border border-red-700/30 rounded-lg p-4">
              <h3 className="text-lg font-semibold text-white mb-4">☁️ Cloud Security</h3>
              <div className="space-y-3">
                <div className="flex justify-between">
                  <span className="text-gray-400">Total Misconfigurations</span>
                  <span className="text-white">{metrics?.cloud_security_stats.total_misconfigurations || 0}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">High Severity</span>
                  <span className="text-red-400">{metrics?.cloud_security_stats.high_severity_misconfigurations || 0}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Scans Completed</span>
                  <span className="text-green-400">{metrics?.cloud_security_stats.scans_completed_last_7_days || 0}</span>
                </div>
              </div>
            </div>
            <div className="bg-cyber-dark border border-red-700/30 rounded-lg p-4">
              <h3 className="text-lg font-semibold text-white mb-4">🎣 Phishing Protection</h3>
              <div className="space-y-3">
                <div className="flex justify-between">
                  <span className="text-gray-400">Emails Analyzed</span>
                  <span className="text-white">{metrics?.phishing_stats.total_emails_analyzed || 0}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Phishing Detected</span>
                  <span className="text-red-400">{metrics?.phishing_stats.phishing_emails_detected || 0}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Auto Responses</span>
                  <span className="text-green-400">{metrics?.phishing_stats.auto_responses_sent || 0}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Users Tab */}
      {activeTab === 'users' && (
        <div className="bg-cyber-darker border border-red-700/30 rounded-lg p-6">
          <h2 className="text-2xl font-bold text-white mb-6">👥 User Management</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-blue-900/20 border border-blue-700/30 rounded-lg p-4">
              <div className="text-2xl font-bold text-blue-400">{metrics?.user_stats.total_users || 0}</div>
              <div className="text-gray-400">Total Users</div>
            </div>
            <div className="bg-green-900/20 border border-green-700/30 rounded-lg p-4">
              <div className="text-2xl font-bold text-green-400">{metrics?.user_stats.active_users || 0}</div>
              <div className="text-gray-400">Active Users</div>
            </div>
            <div className="bg-purple-900/20 border border-purple-700/30 rounded-lg p-4">
              <div className="text-2xl font-bold text-purple-400">{metrics?.user_stats.new_users_last_30_days || 0}</div>
              <div className="text-gray-400">New This Month</div>
            </div>
          </div>
          <p className="text-gray-400 mt-6">User management interface coming soon...</p>
        </div>
      )}

      {/* System Tab */}
      {activeTab === 'system' && (
        <div className="bg-cyber-darker border border-red-700/30 rounded-lg p-6">
          <h2 className="text-2xl font-bold text-white mb-6">⚙️ System Health</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-4">
              <h3 className="text-lg font-semibold text-white">System Status</h3>
              <div className="space-y-3">
                <div className="flex items-center justify-between p-3 bg-cyber-dark rounded-lg">
                  <span className="text-gray-400">Database</span>
                  <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(metrics?.system_health.database_status || 'operational')}`}>
                    {metrics?.system_health.database_status || 'operational'}
                  </span>
                </div>
                <div className="flex items-center justify-between p-3 bg-cyber-dark rounded-lg">
                  <span className="text-gray-400">Redis Cache</span>
                  <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(metrics?.system_health.redis_status || 'operational')}`}>
                    {metrics?.system_health.redis_status || 'operational'}
                  </span>
                </div>
                <div className="flex items-center justify-between p-3 bg-cyber-dark rounded-lg">
                  <span className="text-gray-400">AI Service</span>
                  <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(metrics?.system_health.ai_service_status || 'operational')}`}>
                    {metrics?.system_health.ai_service_status || 'operational'}
                  </span>
                </div>
              </div>
            </div>
            <div className="space-y-4">
              <h3 className="text-lg font-semibold text-white">Performance Metrics</h3>
              <div className="space-y-3">
                <div className="flex items-center justify-between p-3 bg-cyber-dark rounded-lg">
                  <span className="text-gray-400">Uptime</span>
                  <span className="text-white">{getUptimeFormatted(metrics?.system_health.uptime_seconds || 0)}</span>
                </div>
                <div className="flex items-center justify-between p-3 bg-cyber-dark rounded-lg">
                  <span className="text-gray-400">CPU Usage</span>
                  <span className={`${getUsageColor(metrics?.system_health.cpu_usage_percent || 0)}`}>
                    {metrics?.system_health.cpu_usage_percent || 0}%
                  </span>
                </div>
                <div className="flex items-center justify-between p-3 bg-cyber-dark rounded-lg">
                  <span className="text-gray-400">Memory Usage</span>
                  <span className={`${getUsageColor(metrics?.system_health.memory_usage_percent || 0)}`}>
                    {metrics?.system_health.memory_usage_percent || 0}%
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AdminDashboard; 