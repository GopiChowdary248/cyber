import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
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
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState('overview');
  const [loading, setLoading] = useState(true);
  const [summary, setSummary] = useState<SecuritySummary | null>(null);
  const [sastResults, setSastResults] = useState<SASTResult[]>([]);
  const [dastResults, setDastResults] = useState<DASTResult[]>([]);
  const [raspLogs, setRaspLogs] = useState<RASPLog[]>([]);
  const [scanning, setScanning] = useState(false);

  const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

  useEffect(() => {
    fetchSecurityData();
  }, []);

  const fetchSecurityData = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('access_token');
      
      const [summaryRes, sastRes, dastRes, raspRes] = await Promise.all([
        fetch(`${API_URL}/api/v1/security/summary`, {
          headers: { 'Authorization': `Bearer ${token}` }
        }),
        fetch(`${API_URL}/api/v1/security/sast/results`, {
          headers: { 'Authorization': `Bearer ${token}` }
        }),
        fetch(`${API_URL}/api/v1/security/dast/results`, {
          headers: { 'Authorization': `Bearer ${token}` }
        }),
        fetch(`${API_URL}/api/v1/security/rasp/logs`, {
          headers: { 'Authorization': `Bearer ${token}` }
        })
      ]);

      if (summaryRes.ok) setSummary(await summaryRes.json());
      if (sastRes.ok) setSastResults(await sastRes.json());
      if (dastRes.ok) setDastResults(await dastRes.json());
      if (raspRes.ok) setRaspLogs(await raspRes.json());
    } catch (error) {
      console.error('Error fetching security data:', error);
      toast.error('Failed to load security data');
    } finally {
      setLoading(false);
    }
  };

  const triggerScan = async (scanType: 'sast' | 'dast') => {
    try {
      setScanning(true);
      const token = localStorage.getItem('access_token');
      const response = await fetch(`${API_URL}/api/v1/security/${scanType}/scan`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (response.ok) {
        const result = await response.json();
        toast.success(`${scanType.toUpperCase()} scan triggered successfully`);
        // Refresh data after a delay to simulate scan completion
        setTimeout(fetchSecurityData, 2000);
      } else {
        toast.error(`Failed to trigger ${scanType.toUpperCase()} scan`);
      }
    } catch (error) {
      console.error(`Error triggering ${scanType} scan:`, error);
      toast.error(`Failed to trigger ${scanType.toUpperCase()} scan`);
    } finally {
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

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-500"></div>
      </div>
    );
  }

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
                    <EnhancedBadge variant="danger">{summary?.sast_critical || 0}</EnhancedBadge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">High:</span>
                    <EnhancedBadge variant="danger">{summary?.sast_high || 0}</EnhancedBadge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Medium:</span>
                    <EnhancedBadge variant="warning">{summary?.sast_medium || 0}</EnhancedBadge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Low:</span>
                    <EnhancedBadge variant="primary">{summary?.sast_low || 0}</EnhancedBadge>
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
                    <EnhancedBadge variant="danger">{summary?.dast_critical || 0}</EnhancedBadge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">High:</span>
                    <EnhancedBadge variant="danger">{summary?.dast_high || 0}</EnhancedBadge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Medium:</span>
                    <EnhancedBadge variant="warning">{summary?.dast_medium || 0}</EnhancedBadge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Low:</span>
                    <EnhancedBadge variant="primary">{summary?.dast_low || 0}</EnhancedBadge>
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
                    <EnhancedBadge variant="success">{summary?.rasp_blocked || 0}</EnhancedBadge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Total Incidents:</span>
                    <EnhancedBadge variant="primary">{summary?.rasp_incidents || 0}</EnhancedBadge>
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