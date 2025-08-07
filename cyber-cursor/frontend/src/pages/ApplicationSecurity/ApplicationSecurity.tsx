import React, { useState, useEffect } from 'react';
import EnhancedCard from '../../components/UI/EnhancedCard';
import EnhancedButton from '../../components/UI/EnhancedButton';
import EnhancedBadge from '../../components/UI/EnhancedBadge';
import EnhancedTabs from '../../components/UI/EnhancedTabs';
import {
  Shield, Bug, Eye, Activity, AlertTriangle, CheckCircle, XCircle,
  Download, Play, Clock, FileText, Globe, Server, Zap, BarChart3
} from 'lucide-react';
import toast from 'react-hot-toast';

interface SecuritySummary {
  sast_critical: number;
  sast_high: number;
  sast_medium: number;
  sast_low: number;
  dast_critical: number;
  dast_high: number;
  dast_medium: number;
  dast_low: number;
  rasp_blocked: number;
  rasp_incidents: number;
}

interface SASTResult {
  id: number;
  file_name: string;
  severity: string;
  description: string;
  recommendation: string;
  scan_date: string;
  line_number: number;
  rule_id: string;
}

interface DASTResult {
  id: number;
  url: string;
  severity: string;
  vulnerability_type: string;
  recommendation: string;
  scan_date: string;
  status: string;
  cwe_id: string;
}

interface RASPLog {
  id: number;
  incident_type: string;
  status: string;
  description: string;
  blocked: boolean;
  timestamp: string;
  source_ip: string;
  attack_vector: string;
}

const ApplicationSecurity: React.FC = () => {
  const [activeTab, setActiveTab] = useState('overview');
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);

  // Mock data - defined as constants to avoid any state issues
  const summary: SecuritySummary = {
    sast_critical: 3,
    sast_high: 8,
    sast_medium: 12,
    sast_low: 5,
    dast_critical: 2,
    dast_high: 6,
    dast_medium: 9,
    dast_low: 3,
    rasp_blocked: 15,
    rasp_incidents: 8
  };

  const sastResults: SASTResult[] = [
    {
      id: 1,
      file_name: 'app/api/v1/endpoints/auth.py',
      severity: 'critical',
      description: 'SQL injection vulnerability detected in user authentication',
      recommendation: 'Use parameterized queries or ORM to prevent SQL injection',
      scan_date: '2024-01-15T10:30:00Z',
      line_number: 45,
      rule_id: 'SQL_INJECTION_001'
    },
    {
      id: 2,
      file_name: 'frontend/src/components/Login.tsx',
      severity: 'high',
      description: 'Cross-site scripting vulnerability in login form',
      recommendation: 'Sanitize user input and implement proper output encoding',
      scan_date: '2024-01-15T10:30:00Z',
      line_number: 23,
      rule_id: 'XSS_001'
    }
  ];

  const dastResults: DASTResult[] = [
    {
      id: 1,
      url: 'https://app.example.com/login',
      severity: 'critical',
      vulnerability_type: 'Authentication Bypass',
      recommendation: 'Implement proper authentication checks and session management',
      scan_date: '2024-01-15T10:30:00Z',
      status: 'open',
      cwe_id: 'CWE-287'
    },
    {
      id: 2,
      url: 'https://app.example.com/profile',
      severity: 'high',
      vulnerability_type: 'CSRF Vulnerability',
      recommendation: 'Implement CSRF tokens and validate request origin',
      scan_date: '2024-01-15T10:30:00Z',
      status: 'open',
      cwe_id: 'CWE-352'
    }
  ];

  const raspLogs: RASPLog[] = [
    {
      id: 1,
      incident_type: 'SQL_INJECTION_ATTEMPT',
      status: 'blocked',
      description: 'SQL injection attempt detected and blocked',
      blocked: true,
      timestamp: '2024-01-15T10:30:00Z',
      source_ip: '192.168.1.100',
      attack_vector: 'POST /api/v1/users'
    },
    {
      id: 2,
      incident_type: 'XSS_ATTEMPT',
      status: 'blocked',
      description: 'XSS attempt detected and blocked',
      blocked: true,
      timestamp: '2024-01-15T10:25:00Z',
      source_ip: '192.168.1.101',
      attack_vector: 'POST /api/v1/comments'
    }
  ];

  const triggerScan = async (scanType: 'sast' | 'dast') => {
    try {
      setScanning(true);
      toast.success(`${scanType.toUpperCase()} scan triggered successfully`);
      // Simulate scan completion
      setTimeout(() => {
        setScanning(false);
        toast.success(`${scanType.toUpperCase()} scan completed`);
      }, 2000);
    } catch (error) {
      console.error(`Error triggering ${scanType} scan:`, error);
      toast.error(`Failed to trigger ${scanType.toUpperCase()} scan`);
      setScanning(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'danger';
      case 'high': return 'danger';
      case 'medium': return 'warning';
      case 'low': return 'primary';
      default: return 'default';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'blocked': return 'success';
      case 'monitoring': return 'warning';
      case 'open': return 'danger';
      default: return 'default';
    }
  };

  const tabs = [
    {
      id: 'overview',
      label: 'Overview',
      content: (
        <div className="space-y-6">
          {/* Security Summary Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {/* SAST Summary */}
            <EnhancedCard>
              <div className="p-6">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center space-x-2">
                    <Bug className="h-5 w-5 text-blue-500" />
                    <h3 className="text-lg font-semibold text-white">SAST Analysis</h3>
                  </div>
                  <EnhancedButton
                    onClick={() => triggerScan('sast')}
                    disabled={scanning}
                    size="sm"
                    variant="primary"
                  >
                    {scanning ? <Clock className="h-4 w-4" /> : <Play className="h-4 w-4" />}
                  </EnhancedButton>
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <span className="text-gray-400">Critical:</span>
                    <EnhancedBadge variant="danger">{summary.sast_critical}</EnhancedBadge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">High:</span>
                    <EnhancedBadge variant="danger">{summary.sast_high}</EnhancedBadge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Medium:</span>
                    <EnhancedBadge variant="warning">{summary.sast_medium}</EnhancedBadge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Low:</span>
                    <EnhancedBadge variant="primary">{summary.sast_low}</EnhancedBadge>
                  </div>
                </div>
              </div>
            </EnhancedCard>

            {/* DAST Summary */}
            <EnhancedCard>
              <div className="p-6">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center space-x-2">
                    <Globe className="h-5 w-5 text-green-500" />
                    <h3 className="text-lg font-semibold text-white">DAST Analysis</h3>
                  </div>
                  <EnhancedButton
                    onClick={() => triggerScan('dast')}
                    disabled={scanning}
                    size="sm"
                    variant="primary"
                  >
                    {scanning ? <Clock className="h-4 w-4" /> : <Play className="h-4 w-4" />}
                  </EnhancedButton>
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <span className="text-gray-400">Critical:</span>
                    <EnhancedBadge variant="danger">{summary.dast_critical}</EnhancedBadge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">High:</span>
                    <EnhancedBadge variant="danger">{summary.dast_high}</EnhancedBadge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Medium:</span>
                    <EnhancedBadge variant="warning">{summary.dast_medium}</EnhancedBadge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Low:</span>
                    <EnhancedBadge variant="primary">{summary.dast_low}</EnhancedBadge>
                  </div>
                </div>
              </div>
            </EnhancedCard>

            {/* RASP Summary */}
            <EnhancedCard>
              <div className="p-6">
                <div className="flex items-center space-x-2 mb-4">
                  <Shield className="h-5 w-5 text-purple-500" />
                  <h3 className="text-lg font-semibold text-white">RASP Protection</h3>
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <span className="text-gray-400">Threats Blocked:</span>
                    <EnhancedBadge variant="success">{summary.rasp_blocked}</EnhancedBadge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Total Incidents:</span>
                    <EnhancedBadge variant="primary">{summary.rasp_incidents}</EnhancedBadge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Status:</span>
                    <EnhancedBadge variant="success">Active</EnhancedBadge>
                  </div>
                </div>
              </div>
            </EnhancedCard>

            {/* Quick Actions */}
            <EnhancedCard>
              <div className="p-6">
                <div className="flex items-center space-x-2 mb-4">
                  <Zap className="h-5 w-5 text-yellow-500" />
                  <h3 className="text-lg font-semibold text-white">Quick Actions</h3>
                </div>
                <div className="space-y-3">
                  <EnhancedButton
                    onClick={() => triggerScan('sast')}
                    disabled={scanning}
                    variant="primary"
                    size="sm"
                    className="w-full"
                  >
                    Run SAST Scan
                  </EnhancedButton>
                  <EnhancedButton
                    onClick={() => triggerScan('dast')}
                    disabled={scanning}
                    variant="primary"
                    size="sm"
                    className="w-full"
                  >
                    Run DAST Scan
                  </EnhancedButton>
                  <EnhancedButton
                    variant="outline"
                    size="sm"
                    className="w-full"
                  >
                    <Download className="h-4 w-4 mr-2" />
                    Export Report
                  </EnhancedButton>
                </div>
              </div>
            </EnhancedCard>
          </div>
        </div>
      )
    },
    {
      id: 'sast',
      label: 'SAST Results',
      content: (
        <div className="space-y-6">
          <div className="flex justify-between items-center">
            <h2 className="text-2xl font-bold text-white">Static Application Security Testing</h2>
            <EnhancedButton
              onClick={() => triggerScan('sast')}
              disabled={scanning}
              variant="primary"
            >
              {scanning ? 'Scanning...' : 'New Scan'}
            </EnhancedButton>
          </div>
          
          <div className="space-y-4">
            {sastResults.map((result) => (
              <EnhancedCard key={result.id}>
                <div className="p-6">
                  <div className="flex justify-between items-start mb-4">
                    <div>
                      <h3 className="text-lg font-semibold text-white mb-2">{result.file_name}</h3>
                      <p className="text-gray-400 text-sm">Line {result.line_number} • Rule: {result.rule_id}</p>
                    </div>
                    <EnhancedBadge variant={getSeverityColor(result.severity)}>
                      {result.severity.toUpperCase()}
                    </EnhancedBadge>
                  </div>
                  <p className="text-gray-300 mb-3">{result.description}</p>
                  <div className="bg-gray-800 p-4 rounded-lg">
                    <h4 className="text-sm font-semibold text-white mb-2">Recommendation:</h4>
                    <p className="text-gray-300 text-sm">{result.recommendation}</p>
                  </div>
                  <div className="flex justify-between items-center mt-4">
                    <span className="text-gray-500 text-sm">
                      Scanned: {new Date(result.scan_date).toLocaleDateString()}
                    </span>
                    <EnhancedButton variant="outline" size="sm">
                      View Details
                    </EnhancedButton>
                  </div>
                </div>
              </EnhancedCard>
            ))}
          </div>
        </div>
      )
    },
    {
      id: 'dast',
      label: 'DAST Results',
      content: (
        <div className="space-y-6">
          <div className="flex justify-between items-center">
            <h2 className="text-2xl font-bold text-white">Dynamic Application Security Testing</h2>
            <EnhancedButton
              onClick={() => triggerScan('dast')}
              disabled={scanning}
              variant="primary"
            >
              {scanning ? 'Scanning...' : 'New Scan'}
            </EnhancedButton>
          </div>
          
          <div className="space-y-4">
            {dastResults.map((result) => (
              <EnhancedCard key={result.id}>
                <div className="p-6">
                  <div className="flex justify-between items-start mb-4">
                    <div>
                      <h3 className="text-lg font-semibold text-white mb-2">{result.url}</h3>
                      <p className="text-gray-400 text-sm">CWE: {result.cwe_id}</p>
                    </div>
                    <div className="flex space-x-2">
                      <EnhancedBadge variant={getSeverityColor(result.severity)}>
                        {result.severity.toUpperCase()}
                      </EnhancedBadge>
                      <EnhancedBadge variant={getStatusColor(result.status)}>
                        {result.status.toUpperCase()}
                      </EnhancedBadge>
                    </div>
                  </div>
                  <p className="text-gray-300 mb-3">{result.vulnerability_type}</p>
                  <div className="bg-gray-800 p-4 rounded-lg">
                    <h4 className="text-sm font-semibold text-white mb-2">Recommendation:</h4>
                    <p className="text-gray-300 text-sm">{result.recommendation}</p>
                  </div>
                  <div className="flex justify-between items-center mt-4">
                    <span className="text-gray-500 text-sm">
                      Scanned: {new Date(result.scan_date).toLocaleDateString()}
                    </span>
                    <EnhancedButton variant="outline" size="sm">
                      View Details
                    </EnhancedButton>
                  </div>
                </div>
              </EnhancedCard>
            ))}
          </div>
        </div>
      )
    },
    {
      id: 'rasp',
      label: 'RASP Monitoring',
      content: (
        <div className="space-y-6">
          <div className="flex justify-between items-center">
            <h2 className="text-2xl font-bold text-white">Runtime Application Self-Protection</h2>
            <EnhancedBadge variant="success">Active Protection</EnhancedBadge>
          </div>
          
          <div className="space-y-4">
            {raspLogs.map((log) => (
              <EnhancedCard key={log.id}>
                <div className="p-6">
                  <div className="flex justify-between items-start mb-4">
                    <div>
                      <h3 className="text-lg font-semibold text-white mb-2">{log.incident_type}</h3>
                      <p className="text-gray-400 text-sm">Source: {log.source_ip} • Vector: {log.attack_vector}</p>
                    </div>
                    <div className="flex space-x-2">
                      <EnhancedBadge variant={getStatusColor(log.status)}>
                        {log.status.toUpperCase()}
                      </EnhancedBadge>
                      {log.blocked ? (
                        <EnhancedBadge variant="success">
                          <CheckCircle className="h-3 w-3 mr-1" />
                          BLOCKED
                        </EnhancedBadge>
                      ) : (
                        <EnhancedBadge variant="warning">
                          <AlertTriangle className="h-3 w-3 mr-1" />
                          MONITORING
                        </EnhancedBadge>
                      )}
                    </div>
                  </div>
                  <p className="text-gray-300 mb-3">{log.description}</p>
                  <div className="flex justify-between items-center mt-4">
                    <span className="text-gray-500 text-sm">
                      {new Date(log.timestamp).toLocaleString()}
                    </span>
                    <EnhancedButton variant="outline" size="sm">
                      View Details
                    </EnhancedButton>
                  </div>
                </div>
              </EnhancedCard>
            ))}
          </div>
        </div>
      )
    }
  ];

  return (
    <div className="container mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Application Security</h1>
          <p className="text-gray-400">Comprehensive security analysis and monitoring</p>
        </div>
        <div className="flex space-x-3">
          <EnhancedButton variant="outline">
            <Download className="h-4 w-4 mr-2" />
            Export Report
          </EnhancedButton>
          <EnhancedButton variant="primary">
            <BarChart3 className="h-4 w-4 mr-2" />
            Security Dashboard
          </EnhancedButton>
        </div>
      </div>

      {/* Tabs */}
      <EnhancedTabs
        tabs={tabs}
        activeTab={activeTab}
        onTabChange={setActiveTab}
        variant="default"
        size="md"
      />
    </div>
  );
};

export default ApplicationSecurity; 