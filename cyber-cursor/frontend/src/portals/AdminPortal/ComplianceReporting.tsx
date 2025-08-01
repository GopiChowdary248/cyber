import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';

interface ComplianceFramework {
  name: string;
  description: string;
  controls: string[];
}

interface ComplianceDashboard {
  compliance_status: Record<string, {
    status: string;
    score: number;
    last_assessed: string;
    next_assessment: string;
  }>;
  recent_audit_findings: Array<{
    id: string;
    category: string;
    severity: string;
    status: string;
    created_at: string;
  }>;
  upcoming_assessments: Array<{
    framework: string;
    due_date: string;
    days_remaining: number;
  }>;
  compliance_metrics: {
    total_requirements: number;
    compliant_requirements: number;
    non_compliant_requirements: number;
    partially_compliant_requirements: number;
    overall_compliance_score: number;
  };
}

interface ComplianceMetrics {
  overall_compliance_score: number;
  framework_scores: Record<string, number>;
  requirement_status: {
    compliant: number;
    partially_compliant: number;
    non_compliant: number;
    not_assessed: number;
  };
  trends: {
    last_month: number;
    current_month: number;
    trend: string;
  };
}

const ComplianceReporting: React.FC = () => {
  const { user } = useAuth();
  const [complianceFrameworks, setComplianceFrameworks] = useState<Record<string, ComplianceFramework>>({});
  const [dashboard, setDashboard] = useState<ComplianceDashboard | null>(null);
  const [metrics, setMetrics] = useState<ComplianceMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');
  const [selectedFramework, setSelectedFramework] = useState<string>('');
  const [reportType, setReportType] = useState('security_report');
  const [reportFormat, setReportFormat] = useState('json');
  const [showReportModal, setShowReportModal] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

  useEffect(() => {
    fetchComplianceData();
  }, []);

  const fetchComplianceData = async () => {
    try {
      setLoading(true);
      setError('');
      
      const token = localStorage.getItem('access_token');
      
      const [frameworksResponse, dashboardResponse, metricsResponse] = await Promise.all([
        fetch(`${API_URL}/api/v1/compliance/frameworks`, {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        }),
        fetch(`${API_URL}/api/v1/compliance/dashboard/overview`, {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        }),
        fetch(`${API_URL}/api/v1/compliance/metrics/compliance`, {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        })
      ]);

      if (frameworksResponse.ok) {
        const frameworksData = await frameworksResponse.json();
        setComplianceFrameworks(frameworksData.frameworks);
      }

      if (dashboardResponse.ok) {
        const dashboardData = await dashboardResponse.json();
        setDashboard(dashboardData.dashboard);
      }

      if (metricsResponse.ok) {
        const metricsData = await metricsResponse.json();
        setMetrics(metricsData.metrics);
      }
    } catch (err) {
      console.error('Error fetching compliance data:', err);
      setError('Failed to load compliance data');
    } finally {
      setLoading(false);
    }
  };

  const generateReport = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('access_token');
      
      const requestBody = {
        report_type: reportType,
        period_start: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(), // 30 days ago
        period_end: new Date().toISOString(),
        format: reportFormat
      };
      
      const response = await fetch(`${API_URL}/api/v1/compliance/reports/security`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestBody)
      });

      if (response.ok) {
        const reportData = await response.json();
        setSuccess('Report generated successfully');
        setShowReportModal(false);
        // In a real implementation, you might want to download the report or show it in a modal
      } else {
        throw new Error('Failed to generate report');
      }
    } catch (err) {
      console.error('Error generating report:', err);
      setError('Failed to generate report');
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'compliant': return 'text-green-400 bg-green-900/20';
      case 'partially_compliant': return 'text-yellow-400 bg-yellow-900/20';
      case 'non_compliant': return 'text-red-400 bg-red-900/20';
      case 'open': return 'text-orange-400 bg-orange-900/20';
      case 'resolved': return 'text-green-400 bg-green-900/20';
      default: return 'text-gray-400 bg-gray-900/20';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'text-red-400';
      case 'high': return 'text-orange-400';
      case 'medium': return 'text-yellow-400';
      case 'low': return 'text-green-400';
      default: return 'text-gray-400';
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  };

  const getComplianceScoreColor = (score: number) => {
    if (score >= 90) return 'text-green-400';
    if (score >= 70) return 'text-yellow-400';
    return 'text-red-400';
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-400"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gradient-to-r from-blue-900/20 to-purple-900/20 border border-blue-700/30 rounded-lg p-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">📊 Compliance & Reporting</h1>
            <p className="text-gray-400">Manage compliance frameworks and generate comprehensive reports</p>
          </div>
          <button
            onClick={() => setShowReportModal(true)}
            className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded-lg transition-colors"
          >
            📋 Generate Report
          </button>
        </div>
      </div>

      {/* Success/Error Messages */}
      {success && (
        <div className="bg-green-900/20 border border-green-500/30 rounded-lg p-4">
          <p className="text-green-400">{success}</p>
        </div>
      )}

      {error && (
        <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-4">
          <p className="text-red-400">{error}</p>
        </div>
      )}

      {/* Navigation Tabs */}
      <div className="bg-cyber-darker border border-blue-700/30 rounded-lg p-4">
        <div className="flex space-x-4">
          {[
            { id: 'overview', name: 'Overview', icon: '📊' },
            { id: 'frameworks', name: 'Frameworks', icon: '🛡️' },
            { id: 'reports', name: 'Reports', icon: '📋' },
            { id: 'audit', name: 'Audit', icon: '🔍' },
            { id: 'metrics', name: 'Metrics', icon: '📈' }
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center space-x-2 px-4 py-2 rounded-lg transition-colors ${
                activeTab === tab.id
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-400 hover:text-white hover:bg-blue-700/20'
              }`}
            >
              <span>{tab.icon}</span>
              <span>{tab.name}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Overview Tab */}
      {activeTab === 'overview' && dashboard && (
        <div className="space-y-6">
          {/* Compliance Status Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            <div className="bg-cyber-darker border border-blue-700/30 rounded-lg p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="text-2xl">📊</div>
                <div className={`text-2xl font-bold ${getComplianceScoreColor(dashboard.compliance_metrics.overall_compliance_score)}`}>
                  {dashboard.compliance_metrics.overall_compliance_score}%
                </div>
              </div>
              <div className="text-gray-400">Overall Compliance Score</div>
            </div>

            <div className="bg-cyber-darker border border-blue-700/30 rounded-lg p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="text-2xl">✅</div>
                <div className="text-2xl font-bold text-green-400">
                  {dashboard.compliance_metrics.compliant_requirements}
                </div>
              </div>
              <div className="text-gray-400">Compliant Requirements</div>
            </div>

            <div className="bg-cyber-darker border border-blue-700/30 rounded-lg p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="text-2xl">⚠️</div>
                <div className="text-2xl font-bold text-orange-400">
                  {dashboard.compliance_metrics.non_compliant_requirements}
                </div>
              </div>
              <div className="text-gray-400">Non-Compliant Requirements</div>
            </div>

            <div className="bg-cyber-darker border border-blue-700/30 rounded-lg p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="text-2xl">📅</div>
                <div className="text-2xl font-bold text-blue-400">
                  {dashboard.upcoming_assessments.length}
                </div>
              </div>
              <div className="text-gray-400">Upcoming Assessments</div>
            </div>
          </div>

          {/* Framework Status */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="bg-cyber-darker border border-blue-700/30 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-white mb-4">🛡️ Framework Status</h3>
              <div className="space-y-4">
                {Object.entries(dashboard.compliance_status).map(([framework, status]) => (
                  <div key={framework} className="flex items-center justify-between p-3 bg-cyber-dark rounded-lg">
                    <div>
                      <div className="text-white font-medium">{framework.toUpperCase()}</div>
                      <div className="text-gray-400 text-sm">
                        Last assessed: {formatDate(status.last_assessed)}
                      </div>
                    </div>
                    <div className="flex items-center space-x-3">
                      <div className={`text-lg font-bold ${getComplianceScoreColor(status.score)}`}>
                        {status.score}%
                      </div>
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(status.status)}`}>
                        {status.status}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="bg-cyber-darker border border-blue-700/30 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-white mb-4">🔍 Recent Audit Findings</h3>
              <div className="space-y-3">
                {dashboard.recent_audit_findings.slice(0, 5).map((finding) => (
                  <div key={finding.id} className="flex items-center justify-between p-3 bg-cyber-dark rounded-lg">
                    <div>
                      <div className="text-white font-medium">{finding.category}</div>
                      <div className="text-gray-400 text-sm">
                        {formatDate(finding.created_at)}
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className={`text-sm ${getSeverityColor(finding.severity)}`}>
                        {finding.severity}
                      </span>
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(finding.status)}`}>
                        {finding.status}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Upcoming Assessments */}
          <div className="bg-cyber-darker border border-blue-700/30 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-white mb-4">📅 Upcoming Assessments</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {dashboard.upcoming_assessments.map((assessment, index) => (
                <div key={index} className="p-4 bg-cyber-dark rounded-lg">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-white font-medium">{assessment.framework}</span>
                    <span className={`px-2 py-1 rounded text-xs font-medium ${
                      assessment.days_remaining <= 30 ? 'text-red-400 bg-red-900/20' : 'text-yellow-400 bg-yellow-900/20'
                    }`}>
                      {assessment.days_remaining} days
                    </span>
                  </div>
                  <div className="text-gray-400 text-sm">
                    Due: {formatDate(assessment.due_date)}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Frameworks Tab */}
      {activeTab === 'frameworks' && (
        <div className="space-y-6">
          <div className="bg-cyber-darker border border-blue-700/30 rounded-lg p-6">
            <h2 className="text-xl font-bold text-white mb-6">🛡️ Compliance Frameworks</h2>
            
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {Object.entries(complianceFrameworks).map(([key, framework]) => (
                <div key={key} className="bg-cyber-dark border border-blue-700/20 rounded-lg p-6">
                  <h3 className="text-lg font-semibold text-white mb-2">{framework.name}</h3>
                  <p className="text-gray-400 text-sm mb-4">{framework.description}</p>
                  
                  <div className="space-y-2">
                    <h4 className="text-gray-300 text-sm font-semibold">Controls:</h4>
                    <div className="space-y-1">
                      {framework.controls.slice(0, 3).map((control, index) => (
                        <div key={index} className="text-gray-400 text-xs">
                          • {control}
                        </div>
                      ))}
                      {framework.controls.length > 3 && (
                        <div className="text-blue-400 text-xs">
                          +{framework.controls.length - 3} more controls
                        </div>
                      )}
                    </div>
                  </div>
                  
                  <div className="mt-4 flex space-x-2">
                    <button
                      onClick={() => setSelectedFramework(key)}
                      className="flex-1 bg-blue-600 hover:bg-blue-700 text-white py-2 rounded-lg transition-colors text-sm"
                    >
                      View Details
                    </button>
                    <button
                      onClick={() => {
                        setSelectedFramework(key);
                        setReportType('compliance_report');
                        setShowReportModal(true);
                      }}
                      className="flex-1 bg-green-600 hover:bg-green-700 text-white py-2 rounded-lg transition-colors text-sm"
                    >
                      Generate Report
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Reports Tab */}
      {activeTab === 'reports' && (
        <div className="space-y-6">
          <div className="bg-cyber-darker border border-blue-700/30 rounded-lg p-6">
            <h2 className="text-xl font-bold text-white mb-6">📋 Report Generation</h2>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <h3 className="text-lg font-semibold text-white mb-4">Report Types</h3>
                <div className="space-y-3">
                  {[
                    { id: 'security_report', name: 'Security Report', icon: '🛡️', description: 'Comprehensive security analysis' },
                    { id: 'compliance_report', name: 'Compliance Report', icon: '📊', description: 'Framework compliance assessment' },
                    { id: 'audit_report', name: 'Audit Report', icon: '🔍', description: 'Detailed audit findings' },
                    { id: 'incident_report', name: 'Incident Report', icon: '🚨', description: 'Security incident analysis' },
                    { id: 'risk_assessment', name: 'Risk Assessment', icon: '⚠️', description: 'Security risk evaluation' },
                    { id: 'executive_summary', name: 'Executive Summary', icon: '📈', description: 'High-level security overview' }
                  ].map((report) => (
                    <div key={report.id} className="flex items-center space-x-3 p-3 bg-cyber-dark rounded-lg">
                      <div className="text-xl">{report.icon}</div>
                      <div className="flex-1">
                        <div className="text-white font-medium">{report.name}</div>
                        <div className="text-gray-400 text-sm">{report.description}</div>
                      </div>
                      <button
                        onClick={() => {
                          setReportType(report.id);
                          setShowReportModal(true);
                        }}
                        className="bg-blue-600 hover:bg-blue-700 text-white px-3 py-1 rounded text-sm transition-colors"
                      >
                        Generate
                      </button>
                    </div>
                  ))}
                </div>
              </div>
              
              <div>
                <h3 className="text-lg font-semibold text-white mb-4">Report History</h3>
                <div className="space-y-3">
                  {[
                    { id: 'report_001', type: 'Security Report', title: 'Monthly Security Report - January 2024', date: '2024-01-31', status: 'completed' },
                    { id: 'report_002', type: 'Compliance Report', title: 'SOC 2 Compliance Assessment', date: '2024-01-15', status: 'completed' },
                    { id: 'report_003', type: 'Audit Report', title: 'Annual Security Audit', date: '2024-01-01', status: 'completed' }
                  ].map((report) => (
                    <div key={report.id} className="flex items-center justify-between p-3 bg-cyber-dark rounded-lg">
                      <div>
                        <div className="text-white font-medium">{report.title}</div>
                        <div className="text-gray-400 text-sm">{report.type} • {formatDate(report.date)}</div>
                      </div>
                      <div className="flex items-center space-x-2">
                        <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(report.status)}`}>
                          {report.status}
                        </span>
                        <button className="text-blue-400 hover:text-blue-300 text-sm">
                          Download
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Audit Tab */}
      {activeTab === 'audit' && (
        <div className="space-y-6">
          <div className="bg-cyber-darker border border-blue-700/30 rounded-lg p-6">
            <h2 className="text-xl font-bold text-white mb-6">🔍 Audit Management</h2>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <h3 className="text-lg font-semibold text-white mb-4">Recent Audit Findings</h3>
                <div className="space-y-3">
                  {dashboard?.recent_audit_findings.map((finding) => (
                    <div key={finding.id} className="p-4 bg-cyber-dark rounded-lg">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-white font-medium">{finding.category}</span>
                        <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(finding.status)}`}>
                          {finding.status}
                        </span>
                      </div>
                      <div className="flex items-center justify-between text-sm">
                        <span className={`${getSeverityColor(finding.severity)}`}>
                          Severity: {finding.severity}
                        </span>
                        <span className="text-gray-400">
                          {formatDate(finding.created_at)}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
              
              <div>
                <h3 className="text-lg font-semibold text-white mb-4">Audit Logs</h3>
                <div className="space-y-3">
                  {[
                    { action: 'User Login', user: 'admin@company.com', timestamp: '2024-01-31T10:30:00Z', ip: '192.168.1.100' },
                    { action: 'Report Generated', user: 'admin@company.com', timestamp: '2024-01-31T09:15:00Z', ip: '192.168.1.100' },
                    { action: 'Compliance Assessment', user: 'admin@company.com', timestamp: '2024-01-30T16:45:00Z', ip: '192.168.1.100' }
                  ].map((log, index) => (
                    <div key={index} className="p-3 bg-cyber-dark rounded-lg">
                      <div className="text-white font-medium">{log.action}</div>
                      <div className="text-gray-400 text-sm">
                        {log.user} • {formatDate(log.timestamp)} • {log.ip}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Metrics Tab */}
      {activeTab === 'metrics' && metrics && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-cyber-darker border border-blue-700/30 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-white mb-4">📊 Overall Metrics</h3>
              <div className="space-y-4">
                <div className="text-center">
                  <div className={`text-4xl font-bold ${getComplianceScoreColor(metrics.overall_compliance_score)}`}>
                    {metrics.overall_compliance_score}%
                  </div>
                  <div className="text-gray-400">Overall Compliance Score</div>
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <span className="text-gray-400">Last Month</span>
                    <span className="text-white">{metrics.trends.last_month}%</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Current Month</span>
                    <span className="text-white">{metrics.trends.current_month}%</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Trend</span>
                    <span className={`${metrics.trends.trend === 'improving' ? 'text-green-400' : 'text-red-400'}`}>
                      {metrics.trends.trend}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            <div className="bg-cyber-darker border border-blue-700/30 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-white mb-4">🛡️ Framework Scores</h3>
              <div className="space-y-3">
                {Object.entries(metrics.framework_scores).map(([framework, score]) => (
                  <div key={framework} className="flex items-center justify-between">
                    <span className="text-gray-400 capitalize">{framework}</span>
                    <div className="flex items-center space-x-2">
                      <div className="w-16 bg-gray-700 rounded-full h-2">
                        <div 
                          className={`h-2 rounded-full ${getComplianceScoreColor(score).replace('text-', 'bg-')}`}
                          style={{ width: `${score}%` }}
                        ></div>
                      </div>
                      <span className={`text-sm font-medium ${getComplianceScoreColor(score)}`}>
                        {score}%
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="bg-cyber-darker border border-blue-700/30 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-white mb-4">📋 Requirement Status</h3>
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Compliant</span>
                  <span className="text-green-400 font-bold">{metrics.requirement_status.compliant}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Partially Compliant</span>
                  <span className="text-yellow-400 font-bold">{metrics.requirement_status.partially_compliant}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Non-Compliant</span>
                  <span className="text-red-400 font-bold">{metrics.requirement_status.non_compliant}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Not Assessed</span>
                  <span className="text-gray-400 font-bold">{metrics.requirement_status.not_assessed}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Report Generation Modal */}
      {showReportModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-cyber-darker border border-blue-700/30 rounded-lg p-6 max-w-md w-full mx-4">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-xl font-bold text-white">📋 Generate Report</h3>
              <button
                onClick={() => setShowReportModal(false)}
                className="text-gray-400 hover:text-white"
              >
                ✕
              </button>
            </div>
            
            <div className="space-y-4">
              <div>
                <label className="block text-gray-400 mb-2">Report Type</label>
                <select
                  value={reportType}
                  onChange={(e) => setReportType(e.target.value)}
                  className="w-full bg-cyber-dark border border-blue-700/30 rounded-lg px-3 py-2 text-white"
                >
                  <option value="security_report">Security Report</option>
                  <option value="compliance_report">Compliance Report</option>
                  <option value="audit_report">Audit Report</option>
                  <option value="incident_report">Incident Report</option>
                  <option value="risk_assessment">Risk Assessment</option>
                  <option value="executive_summary">Executive Summary</option>
                </select>
              </div>
              
              <div>
                <label className="block text-gray-400 mb-2">Output Format</label>
                <select
                  value={reportFormat}
                  onChange={(e) => setReportFormat(e.target.value)}
                  className="w-full bg-cyber-dark border border-blue-700/30 rounded-lg px-3 py-2 text-white"
                >
                  <option value="json">JSON</option>
                  <option value="pdf">PDF</option>
                  <option value="csv">CSV</option>
                  <option value="html">HTML</option>
                </select>
              </div>
              
              {selectedFramework && (
                <div>
                  <label className="block text-gray-400 mb-2">Framework</label>
                  <div className="text-white bg-cyber-dark border border-blue-700/30 rounded-lg px-3 py-2">
                    {complianceFrameworks[selectedFramework]?.name}
                  </div>
                </div>
              )}
            </div>
            
            <div className="flex space-x-3 mt-6">
              <button
                onClick={() => setShowReportModal(false)}
                className="flex-1 bg-gray-600 hover:bg-gray-700 text-white py-2 rounded-lg transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={generateReport}
                className="flex-1 bg-blue-600 hover:bg-blue-700 text-white py-2 rounded-lg transition-colors"
              >
                Generate Report
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ComplianceReporting; 