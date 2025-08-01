import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';

interface ThreatLandscape {
  overall_risk_level: string;
  threat_distribution: Record<string, number>;
  trending_threats: Array<{
    name: string;
    trend: string;
    severity: string;
    description: string;
  }>;
  top_attack_vectors: string[];
  geographic_hotspots: Array<{
    region: string;
    threat_level: string;
  }>;
}

interface SecurityMetrics {
  incident_metrics: {
    total_incidents: number;
    resolved_incidents: number;
    open_incidents: number;
    critical_incidents: number;
    incident_trend: string;
  };
  response_metrics: {
    mean_time_to_detect: string;
    mean_time_to_respond: string;
    mean_time_to_resolve: string;
    response_trend: string;
  };
  detection_metrics: {
    detection_rate: number;
    false_positive_rate: number;
    true_positive_rate: number;
    detection_accuracy: string;
  };
  threat_metrics: {
    threats_blocked: number;
    threats_detected: number;
    threat_prevention_rate: number;
    threat_trend: string;
  };
}

interface SecurityTrends {
  incident_trends: {
    daily: number[];
    weekly: number[];
    monthly: number[];
  };
  threat_trends: {
    malware_incidents: number[];
    phishing_attempts: number[];
    data_breaches: number[];
  };
  response_trends: {
    detection_time: number[];
    resolution_time: number[];
  };
}

interface AIMLHealth {
  status: string;
  models_loaded: number;
  service_uptime: string;
  last_training: string;
  model_accuracy: Record<string, number>;
  performance_metrics: {
    average_response_time: string;
    requests_per_minute: number;
    error_rate: number;
  };
}

const AIMLAnalytics: React.FC = () => {
  const { user } = useAuth();
  const [threatLandscape, setThreatLandscape] = useState<ThreatLandscape | null>(null);
  const [securityMetrics, setSecurityMetrics] = useState<SecurityMetrics | null>(null);
  const [securityTrends, setSecurityTrends] = useState<SecurityTrends | null>(null);
  const [aiMLHealth, setAIMLHealth] = useState<AIMLHealth | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');
  const [selectedTimeframe, setSelectedTimeframe] = useState('30d');
  const [error, setError] = useState('');

  const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

  useEffect(() => {
    fetchAIMLAnalytics();
  }, [selectedTimeframe]);

  const fetchAIMLAnalytics = async () => {
    try {
      setLoading(true);
      setError('');
      
      const token = localStorage.getItem('access_token');
      
      const [landscapeResponse, metricsResponse, trendsResponse, healthResponse] = await Promise.all([
        fetch(`${API_URL}/api/v1/ai-ml/analytics/threat-landscape`, {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        }),
        fetch(`${API_URL}/api/v1/ai-ml/analytics/security-metrics`, {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        }),
        fetch(`${API_URL}/api/v1/ai-ml/analytics/trends?timeframe=${selectedTimeframe}`, {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        }),
        fetch(`${API_URL}/api/v1/ai-ml/health`, {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        })
      ]);

      if (landscapeResponse.ok) {
        const landscapeData = await landscapeResponse.json();
        setThreatLandscape(landscapeData.threat_landscape);
      }

      if (metricsResponse.ok) {
        const metricsData = await metricsResponse.json();
        setSecurityMetrics(metricsData.security_metrics);
      }

      if (trendsResponse.ok) {
        const trendsData = await trendsResponse.json();
        setSecurityTrends(trendsData.trends);
      }

      if (healthResponse.ok) {
        const healthData = await healthResponse.json();
        setAIMLHealth(healthData.health);
      }
    } catch (err) {
      console.error('Error fetching AI/ML analytics:', err);
      setError('Failed to load AI/ML analytics data');
    } finally {
      setLoading(false);
    }
  };

  const getRiskLevelColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'low': return 'text-green-400 bg-green-900/20';
      case 'medium': return 'text-yellow-400 bg-yellow-900/20';
      case 'high': return 'text-orange-400 bg-orange-900/20';
      case 'critical': return 'text-red-400 bg-red-900/20';
      default: return 'text-gray-400 bg-gray-900/20';
    }
  };

  const getTrendIcon = (trend: string) => {
    switch (trend.toLowerCase()) {
      case 'increasing': return '📈';
      case 'decreasing': return '📉';
      case 'stable': return '➡️';
      default: return '❓';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'low': return 'text-green-400';
      case 'medium': return 'text-yellow-400';
      case 'high': return 'text-orange-400';
      case 'critical': return 'text-red-400';
      default: return 'text-gray-400';
    }
  };

  const formatPercentage = (value: number) => {
    return `${(value * 100).toFixed(1)}%`;
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
      <div className="bg-gradient-to-r from-purple-900/20 to-blue-900/20 border border-purple-700/30 rounded-lg p-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">🤖 AI/ML Analytics</h1>
            <p className="text-gray-400">Advanced threat detection and predictive analytics</p>
          </div>
          <div className="flex items-center space-x-4">
            <select
              value={selectedTimeframe}
              onChange={(e) => setSelectedTimeframe(e.target.value)}
              className="bg-cyber-dark border border-purple-700/30 rounded-lg px-3 py-2 text-white"
            >
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
              <option value="90d">Last 90 Days</option>
            </select>
            <button
              onClick={fetchAIMLAnalytics}
              className="bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg transition-colors"
            >
              🔄 Refresh
            </button>
          </div>
        </div>
      </div>

      {/* Error Message */}
      {error && (
        <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-4">
          <p className="text-red-400">{error}</p>
        </div>
      )}

      {/* Navigation Tabs */}
      <div className="bg-cyber-darker border border-purple-700/30 rounded-lg p-4">
        <div className="flex space-x-4">
          {[
            { id: 'overview', name: 'Overview', icon: '📊' },
            { id: 'threats', name: 'Threat Landscape', icon: '🛡️' },
            { id: 'metrics', name: 'Security Metrics', icon: '📈' },
            { id: 'trends', name: 'Trends', icon: '📉' },
            { id: 'ai-health', name: 'AI Health', icon: '🤖' }
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center space-x-2 px-4 py-2 rounded-lg transition-colors ${
                activeTab === tab.id
                  ? 'bg-purple-600 text-white'
                  : 'text-gray-400 hover:text-white hover:bg-purple-700/20'
              }`}
            >
              <span>{tab.icon}</span>
              <span>{tab.name}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Overview Tab */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* AI/ML Status Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            <div className="bg-cyber-darker border border-purple-700/30 rounded-lg p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="text-2xl">🤖</div>
                <div className={`px-2 py-1 rounded text-xs font-medium ${getRiskLevelColor(aiMLHealth?.status || 'unknown')}`}>
                  {aiMLHealth?.status || 'Unknown'}
                </div>
              </div>
              <div className="text-3xl font-bold text-white mb-2">{aiMLHealth?.models_loaded || 0}</div>
              <div className="text-gray-400">AI Models Loaded</div>
            </div>

            <div className="bg-cyber-darker border border-purple-700/30 rounded-lg p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="text-2xl">🎯</div>
                <div className="text-green-400 text-sm">+5%</div>
              </div>
              <div className="text-3xl font-bold text-white mb-2">
                {securityMetrics?.detection_metrics.detection_rate ? formatPercentage(securityMetrics.detection_metrics.detection_rate) : 'N/A'}
              </div>
              <div className="text-gray-400">Detection Rate</div>
            </div>

            <div className="bg-cyber-darker border border-purple-700/30 rounded-lg p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="text-2xl">⚡</div>
                <div className="text-blue-400 text-sm">-12%</div>
              </div>
              <div className="text-3xl font-bold text-white mb-2">
                {securityMetrics?.response_metrics.mean_time_to_detect || 'N/A'}
              </div>
              <div className="text-gray-400">Mean Time to Detect</div>
            </div>

            <div className="bg-cyber-darker border border-purple-700/30 rounded-lg p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="text-2xl">🛡️</div>
                <div className="text-green-400 text-sm">+8%</div>
              </div>
              <div className="text-3xl font-bold text-white mb-2">
                {securityMetrics?.threat_metrics.threats_blocked || 0}
              </div>
              <div className="text-gray-400">Threats Blocked</div>
            </div>
          </div>

          {/* Threat Landscape Summary */}
          {threatLandscape && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="bg-cyber-darker border border-purple-700/30 rounded-lg p-6">
                <h3 className="text-lg font-semibold text-white mb-4">🌍 Threat Distribution</h3>
                <div className="space-y-3">
                  {Object.entries(threatLandscape.threat_distribution).map(([threat, percentage]) => (
                    <div key={threat} className="flex items-center justify-between">
                      <span className="text-gray-400 capitalize">{threat.replace('_', ' ')}</span>
                      <div className="flex items-center space-x-3">
                        <div className="w-24 bg-gray-700 rounded-full h-2">
                          <div 
                            className="bg-purple-600 h-2 rounded-full" 
                            style={{ width: `${percentage * 100}%` }}
                          ></div>
                        </div>
                        <span className="text-white text-sm">{formatPercentage(percentage)}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="bg-cyber-darker border border-purple-700/30 rounded-lg p-6">
                <h3 className="text-lg font-semibold text-white mb-4">🔥 Trending Threats</h3>
                <div className="space-y-3">
                  {threatLandscape.trending_threats.slice(0, 3).map((threat, index) => (
                    <div key={index} className="flex items-center space-x-3 p-3 bg-cyber-dark rounded-lg">
                      <div className="text-lg">{getTrendIcon(threat.trend)}</div>
                      <div className="flex-1">
                        <div className="flex items-center space-x-2">
                          <span className="text-white font-medium">{threat.name}</span>
                          <span className={`text-xs px-2 py-1 rounded ${getRiskLevelColor(threat.severity)}`}>
                            {threat.severity}
                          </span>
                        </div>
                        <p className="text-gray-400 text-sm">{threat.description}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* AI/ML Performance */}
          {aiMLHealth && (
            <div className="bg-cyber-darker border border-purple-700/30 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-white mb-4">🤖 AI/ML Performance</h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div>
                  <h4 className="text-gray-400 mb-3">Model Accuracy</h4>
                  <div className="space-y-2">
                    {Object.entries(aiMLHealth.model_accuracy).map(([model, accuracy]) => (
                      <div key={model} className="flex items-center justify-between">
                        <span className="text-gray-400 capitalize">{model.replace('_', ' ')}</span>
                        <span className="text-white">{formatPercentage(accuracy)}</span>
                      </div>
                    ))}
                  </div>
                </div>
                
                <div>
                  <h4 className="text-gray-400 mb-3">Performance Metrics</h4>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-gray-400">Response Time</span>
                      <span className="text-white">{aiMLHealth.performance_metrics.average_response_time}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-400">Requests/min</span>
                      <span className="text-white">{aiMLHealth.performance_metrics.requests_per_minute}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-400">Error Rate</span>
                      <span className="text-white">{formatPercentage(aiMLHealth.performance_metrics.error_rate)}</span>
                    </div>
                  </div>
                </div>
                
                <div>
                  <h4 className="text-gray-400 mb-3">Service Status</h4>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-gray-400">Uptime</span>
                      <span className="text-white">{aiMLHealth.service_uptime}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-400">Last Training</span>
                      <span className="text-white">{new Date(aiMLHealth.last_training).toLocaleDateString()}</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Threat Landscape Tab */}
      {activeTab === 'threats' && threatLandscape && (
        <div className="space-y-6">
          <div className="bg-cyber-darker border border-purple-700/30 rounded-lg p-6">
            <h2 className="text-xl font-bold text-white mb-6">🛡️ Threat Landscape Analysis</h2>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
              <div>
                <h3 className="text-lg font-semibold text-white mb-4">Overall Risk Level</h3>
                <div className="flex items-center space-x-4">
                  <div className={`text-4xl px-4 py-2 rounded-lg ${getRiskLevelColor(threatLandscape.overall_risk_level)}`}>
                    {threatLandscape.overall_risk_level.toUpperCase()}
                  </div>
                  <div>
                    <p className="text-gray-400">Current threat landscape assessment</p>
                    <p className="text-sm text-gray-500">Updated every 15 minutes</p>
                  </div>
                </div>
              </div>
              
              <div>
                <h3 className="text-lg font-semibold text-white mb-4">Top Attack Vectors</h3>
                <div className="space-y-2">
                  {threatLandscape.top_attack_vectors.map((vector, index) => (
                    <div key={index} className="flex items-center space-x-3 p-2 bg-cyber-dark rounded">
                      <span className="text-purple-400">#{index + 1}</span>
                      <span className="text-white">{vector}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <h3 className="text-lg font-semibold text-white mb-4">Geographic Hotspots</h3>
                <div className="space-y-3">
                  {threatLandscape.geographic_hotspots.map((hotspot, index) => (
                    <div key={index} className="flex items-center justify-between p-3 bg-cyber-dark rounded-lg">
                      <span className="text-white">{hotspot.region}</span>
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getRiskLevelColor(hotspot.threat_level)}`}>
                        {hotspot.threat_level}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
              
              <div>
                <h3 className="text-lg font-semibold text-white mb-4">Trending Threats</h3>
                <div className="space-y-3">
                  {threatLandscape.trending_threats.map((threat, index) => (
                    <div key={index} className="p-3 bg-cyber-dark rounded-lg">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-white font-medium">{threat.name}</span>
                        <div className="flex items-center space-x-2">
                          <span className={`text-xs px-2 py-1 rounded ${getRiskLevelColor(threat.severity)}`}>
                            {threat.severity}
                          </span>
                          <span className="text-lg">{getTrendIcon(threat.trend)}</span>
                        </div>
                      </div>
                      <p className="text-gray-400 text-sm">{threat.description}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Security Metrics Tab */}
      {activeTab === 'metrics' && securityMetrics && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="bg-cyber-darker border border-purple-700/30 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-white mb-4">📊 Incident Metrics</h3>
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Total Incidents</span>
                  <span className="text-white font-bold">{securityMetrics.incident_metrics.total_incidents}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Resolved</span>
                  <span className="text-green-400 font-bold">{securityMetrics.incident_metrics.resolved_incidents}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Open</span>
                  <span className="text-orange-400 font-bold">{securityMetrics.incident_metrics.open_incidents}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Critical</span>
                  <span className="text-red-400 font-bold">{securityMetrics.incident_metrics.critical_incidents}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Trend</span>
                  <span className={`font-bold ${securityMetrics.incident_metrics.incident_trend === 'decreasing' ? 'text-green-400' : 'text-red-400'}`}>
                    {securityMetrics.incident_metrics.incident_trend}
                  </span>
                </div>
              </div>
            </div>

            <div className="bg-cyber-darker border border-purple-700/30 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-white mb-4">⚡ Response Metrics</h3>
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Mean Time to Detect</span>
                  <span className="text-white font-bold">{securityMetrics.response_metrics.mean_time_to_detect}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Mean Time to Respond</span>
                  <span className="text-white font-bold">{securityMetrics.response_metrics.mean_time_to_respond}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Mean Time to Resolve</span>
                  <span className="text-white font-bold">{securityMetrics.response_metrics.mean_time_to_resolve}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Response Trend</span>
                  <span className={`font-bold ${securityMetrics.response_metrics.response_trend === 'improving' ? 'text-green-400' : 'text-red-400'}`}>
                    {securityMetrics.response_metrics.response_trend}
                  </span>
                </div>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="bg-cyber-darker border border-purple-700/30 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-white mb-4">🎯 Detection Metrics</h3>
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Detection Rate</span>
                  <span className="text-green-400 font-bold">{formatPercentage(securityMetrics.detection_metrics.detection_rate)}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">False Positive Rate</span>
                  <span className="text-orange-400 font-bold">{formatPercentage(securityMetrics.detection_metrics.false_positive_rate)}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">True Positive Rate</span>
                  <span className="text-green-400 font-bold">{formatPercentage(securityMetrics.detection_metrics.true_positive_rate)}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Detection Accuracy</span>
                  <span className="text-blue-400 font-bold capitalize">{securityMetrics.detection_metrics.detection_accuracy}</span>
                </div>
              </div>
            </div>

            <div className="bg-cyber-darker border border-purple-700/30 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-white mb-4">🛡️ Threat Metrics</h3>
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Threats Blocked</span>
                  <span className="text-green-400 font-bold">{securityMetrics.threat_metrics.threats_blocked}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Threats Detected</span>
                  <span className="text-blue-400 font-bold">{securityMetrics.threat_metrics.threats_detected}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Prevention Rate</span>
                  <span className="text-green-400 font-bold">{formatPercentage(securityMetrics.threat_metrics.threat_prevention_rate)}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Threat Trend</span>
                  <span className={`font-bold ${securityMetrics.threat_metrics.threat_trend === 'stable' ? 'text-green-400' : 'text-orange-400'}`}>
                    {securityMetrics.threat_metrics.threat_trend}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Trends Tab */}
      {activeTab === 'trends' && securityTrends && (
        <div className="space-y-6">
          <div className="bg-cyber-darker border border-purple-700/30 rounded-lg p-6">
            <h2 className="text-xl font-bold text-white mb-6">📉 Security Trends</h2>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <h3 className="text-lg font-semibold text-white mb-4">Incident Trends</h3>
                <div className="space-y-4">
                  <div>
                    <h4 className="text-gray-400 mb-2">Daily Incidents (Last 10 Days)</h4>
                    <div className="h-32 flex items-end justify-between space-x-1">
                      {securityTrends.incident_trends.daily.map((value, index) => (
                        <div key={index} className="flex-1 flex flex-col items-center space-y-1">
                          <div 
                            className="w-full bg-purple-600 rounded-t transition-all duration-300"
                            style={{ height: `${(value / 25) * 100}%` }}
                          ></div>
                          <span className="text-xs text-gray-400">{index + 1}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
              
              <div>
                <h3 className="text-lg font-semibold text-white mb-4">Threat Trends</h3>
                <div className="space-y-4">
                  <div>
                    <h4 className="text-gray-400 mb-2">Malware Incidents</h4>
                    <div className="h-16 flex items-end justify-between space-x-1">
                      {securityTrends.threat_trends.malware_incidents.map((value, index) => (
                        <div key={index} className="flex-1 bg-red-600 rounded-t" style={{ height: `${(value / 15) * 100}%` }}></div>
                      ))}
                    </div>
                  </div>
                  <div>
                    <h4 className="text-gray-400 mb-2">Phishing Attempts</h4>
                    <div className="h-16 flex items-end justify-between space-x-1">
                      {securityTrends.threat_trends.phishing_attempts.map((value, index) => (
                        <div key={index} className="flex-1 bg-orange-600 rounded-t" style={{ height: `${(value / 50) * 100}%` }}></div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* AI Health Tab */}
      {activeTab === 'ai-health' && aiMLHealth && (
        <div className="space-y-6">
          <div className="bg-cyber-darker border border-purple-700/30 rounded-lg p-6">
            <h2 className="text-xl font-bold text-white mb-6">🤖 AI/ML Service Health</h2>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div>
                <h3 className="text-lg font-semibold text-white mb-4">Service Status</h3>
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Status</span>
                    <span className={`px-2 py-1 rounded text-xs font-medium ${getRiskLevelColor(aiMLHealth.status)}`}>
                      {aiMLHealth.status}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Models Loaded</span>
                    <span className="text-white font-bold">{aiMLHealth.models_loaded}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Uptime</span>
                    <span className="text-white">{aiMLHealth.service_uptime}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Last Training</span>
                    <span className="text-white">{new Date(aiMLHealth.last_training).toLocaleDateString()}</span>
                  </div>
                </div>
              </div>
              
              <div>
                <h3 className="text-lg font-semibold text-white mb-4">Model Accuracy</h3>
                <div className="space-y-4">
                  {Object.entries(aiMLHealth.model_accuracy).map(([model, accuracy]) => (
                    <div key={model} className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-gray-400 capitalize">{model.replace('_', ' ')}</span>
                        <span className="text-white font-bold">{formatPercentage(accuracy)}</span>
                      </div>
                      <div className="w-full bg-gray-700 rounded-full h-2">
                        <div 
                          className="bg-purple-600 h-2 rounded-full transition-all duration-300" 
                          style={{ width: `${accuracy * 100}%` }}
                        ></div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
              
              <div>
                <h3 className="text-lg font-semibold text-white mb-4">Performance Metrics</h3>
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Response Time</span>
                    <span className="text-white">{aiMLHealth.performance_metrics.average_response_time}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Requests/min</span>
                    <span className="text-white">{aiMLHealth.performance_metrics.requests_per_minute}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Error Rate</span>
                    <span className="text-white">{formatPercentage(aiMLHealth.performance_metrics.error_rate)}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AIMLAnalytics; 