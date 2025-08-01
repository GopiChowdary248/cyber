import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';

interface DashboardData {
  incidents: {
    total: number;
    active: number;
    resolved: number;
    high_severity: number;
    critical_severity: number;
    recent: any[];
  };
  cloud_security: {
    total_misconfigurations: number;
    high_severity: number;
    total_scans: number;
    recent_scans: number;
    recent_misconfigs: any[];
  };
  phishing_detection: {
    total_analyses: number;
    high_threat: number;
    critical_threat: number;
    phishing_detected: number;
    recent_analyses: any[];
  };
  security_score: number;
}

const DashboardOverview: React.FC = () => {
  const { user } = useAuth();
  const [dashboardData, setDashboardData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('access_token');
      
      const response = await fetch(`${API_URL}/api/v1/dashboard/overview`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error('Failed to fetch dashboard data');
      }

      const data = await response.json();
      setDashboardData(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyber-accent"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-900/20 border border-red-500/50 rounded-lg p-4">
        <p className="text-red-400">Error: {error}</p>
      </div>
    );
  }

  if (!dashboardData) {
    return (
      <div className="bg-yellow-900/20 border border-yellow-500/50 rounded-lg p-4">
        <p className="text-yellow-400">No dashboard data available</p>
      </div>
    );
  }

  const getSecurityScoreColor = (score: number) => {
    if (score >= 80) return 'text-green-400';
    if (score >= 60) return 'text-yellow-400';
    return 'text-red-400';
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'text-red-400 bg-red-900/20';
      case 'high': return 'text-orange-400 bg-orange-900/20';
      case 'medium': return 'text-yellow-400 bg-yellow-900/20';
      case 'low': return 'text-green-400 bg-green-900/20';
      default: return 'text-gray-400 bg-gray-900/20';
    }
  };

  return (
    <div className="space-y-6">
      {/* Welcome Section */}
      <div className="bg-gradient-to-r from-cyber-dark to-cyber-darker border border-cyber-accent/30 rounded-lg p-6">
        <h1 className="text-2xl font-bold text-white mb-2">
          Welcome back, {user?.full_name || user?.username || 'Security Analyst'}!
        </h1>
        <p className="text-gray-400">
          Here's your cybersecurity overview for today
        </p>
      </div>

      {/* Security Score */}
      <div className="bg-cyber-dark border border-cyber-accent/30 rounded-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-semibold text-white">Security Score</h2>
          <span className={`text-3xl font-bold ${getSecurityScoreColor(dashboardData.security_score)}`}>
            {dashboardData.security_score}%
          </span>
        </div>
        <div className="w-full bg-gray-700 rounded-full h-3">
          <div 
            className="bg-gradient-to-r from-cyber-accent to-cyber-accent/70 h-3 rounded-full transition-all duration-500"
            style={{ width: `${dashboardData.security_score}%` }}
          ></div>
        </div>
      </div>

      {/* Key Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* Incidents Card */}
        <div className="bg-cyber-dark border border-cyber-accent/30 rounded-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white">Incidents</h3>
            <div className="w-8 h-8 bg-red-900/20 rounded-lg flex items-center justify-center">
              <span className="text-red-400 text-sm">🚨</span>
            </div>
          </div>
          <div className="space-y-3">
            <div className="flex justify-between">
              <span className="text-gray-400">Total</span>
              <span className="text-white font-semibold">{dashboardData.incidents.total}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Active</span>
              <span className="text-orange-400 font-semibold">{dashboardData.incidents.active}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Critical</span>
              <span className="text-red-400 font-semibold">{dashboardData.incidents.critical_severity}</span>
            </div>
          </div>
        </div>

        {/* Cloud Security Card */}
        <div className="bg-cyber-dark border border-cyber-accent/30 rounded-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white">Cloud Security</h3>
            <div className="w-8 h-8 bg-blue-900/20 rounded-lg flex items-center justify-center">
              <span className="text-blue-400 text-sm">☁️</span>
            </div>
          </div>
          <div className="space-y-3">
            <div className="flex justify-between">
              <span className="text-gray-400">Misconfigurations</span>
              <span className="text-white font-semibold">{dashboardData.cloud_security.total_misconfigurations}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">High Severity</span>
              <span className="text-orange-400 font-semibold">{dashboardData.cloud_security.high_severity}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Scans</span>
              <span className="text-blue-400 font-semibold">{dashboardData.cloud_security.total_scans}</span>
            </div>
          </div>
        </div>

        {/* Phishing Detection Card */}
        <div className="bg-cyber-dark border border-cyber-accent/30 rounded-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white">Phishing Detection</h3>
            <div className="w-8 h-8 bg-purple-900/20 rounded-lg flex items-center justify-center">
              <span className="text-purple-400 text-sm">🎣</span>
            </div>
          </div>
          <div className="space-y-3">
            <div className="flex justify-between">
              <span className="text-gray-400">Analyses</span>
              <span className="text-white font-semibold">{dashboardData.phishing_detection.total_analyses}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Phishing Detected</span>
              <span className="text-red-400 font-semibold">{dashboardData.phishing_detection.phishing_detected}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Critical Threats</span>
              <span className="text-red-400 font-semibold">{dashboardData.phishing_detection.critical_threat}</span>
            </div>
          </div>
        </div>

        {/* Quick Actions Card */}
        <div className="bg-cyber-dark border border-cyber-accent/30 rounded-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white">Quick Actions</h3>
            <div className="w-8 h-8 bg-green-900/20 rounded-lg flex items-center justify-center">
              <span className="text-green-400 text-sm">⚡</span>
            </div>
          </div>
          <div className="space-y-3">
            <button className="w-full bg-cyber-accent hover:bg-cyber-accent/80 text-white py-2 px-4 rounded-lg transition-colors">
              New Incident
            </button>
            <button className="w-full bg-blue-600 hover:bg-blue-700 text-white py-2 px-4 rounded-lg transition-colors">
              Cloud Scan
            </button>
            <button className="w-full bg-purple-600 hover:bg-purple-700 text-white py-2 px-4 rounded-lg transition-colors">
              Analyze Email
            </button>
          </div>
        </div>
      </div>

      {/* Recent Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Incidents */}
        <div className="bg-cyber-dark border border-cyber-accent/30 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4">Recent Incidents</h3>
          <div className="space-y-3">
            {dashboardData.incidents.recent.length > 0 ? (
              dashboardData.incidents.recent.map((incident: any, index: number) => (
                <div key={index} className="flex items-center justify-between p-3 bg-cyber-darker rounded-lg">
                  <div>
                    <p className="text-white font-medium">{incident.title}</p>
                    <p className="text-gray-400 text-sm">{incident.incident_type}</p>
                  </div>
                  <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(incident.severity)}`}>
                    {incident.severity}
                  </span>
                </div>
              ))
            ) : (
              <p className="text-gray-400 text-center py-4">No recent incidents</p>
            )}
          </div>
        </div>

        {/* Recent Alerts */}
        <div className="bg-cyber-dark border border-cyber-accent/30 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4">Recent Alerts</h3>
          <div className="space-y-3">
            {dashboardData.cloud_security.recent_misconfigs.length > 0 ? (
              dashboardData.cloud_security.recent_misconfigs.map((misconfig: any, index: number) => (
                <div key={index} className="flex items-center justify-between p-3 bg-cyber-darker rounded-lg">
                  <div>
                    <p className="text-white font-medium">{misconfig.title}</p>
                    <p className="text-gray-400 text-sm">{misconfig.provider}</p>
                  </div>
                  <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(misconfig.severity)}`}>
                    {misconfig.severity}
                  </span>
                </div>
              ))
            ) : (
              <p className="text-gray-400 text-center py-4">No recent alerts</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default DashboardOverview; 