import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Cloud, 
  AlertTriangle, 
  CheckCircle, 
  XCircle, 
  Activity,
  Users,
  Database,
  Server,
  Globe,
  Lock,
  Eye,
  BarChart3,
  TrendingUp,
  AlertCircle,
  Settings,
  RefreshCw,
  Download,
  Filter,
  Search
} from 'lucide-react';

interface CloudSecurityData {
  unified_risk_score: number;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  cspm_score: number;
  casb_score: number;
  cloud_native_score: number;
  recent_findings: Array<{
    id: string;
    title: string;
    severity: string;
    type: string;
    resource: string;
    detected_at: string;
  }>;
  compliance_status: {
    cis: number;
    nist: number;
    pci_dss: number;
    iso27001: number;
  };
  cloud_accounts: Array<{
    id: string;
    name: string;
    provider: string;
    status: string;
    security_score: number;
  }>;
}

const EnhancedCloudSecurityDashboard: React.FC = () => {
  const [data, setData] = useState<CloudSecurityData | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedProvider, setSelectedProvider] = useState<string>('all');
  const [selectedModule, setSelectedModule] = useState<string>('overview');
  const [refreshInterval, setRefreshInterval] = useState<number>(30000); // 30 seconds

  useEffect(() => {
    fetchCloudSecurityData();
    const interval = setInterval(fetchCloudSecurityData, refreshInterval);
    return () => clearInterval(interval);
  }, [refreshInterval]);

  const fetchCloudSecurityData = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/v1/cloud-security/dashboard/overview');
      const result = await response.json();
      setData(result);
    } catch (error) {
      console.error('Error fetching cloud security data:', error);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'text-red-600 bg-red-50 border-red-200';
      case 'high': return 'text-orange-600 bg-orange-50 border-orange-200';
      case 'medium': return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      case 'low': return 'text-blue-600 bg-blue-50 border-blue-200';
      default: return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return <XCircle className="w-4 h-4" />;
      case 'high': return <AlertTriangle className="w-4 h-4" />;
      case 'medium': return <AlertCircle className="w-4 h-4" />;
      case 'low': return <CheckCircle className="w-4 h-4" />;
      default: return <Activity className="w-4 h-4" />;
    }
  };

  const getRiskLevel = (score: number) => {
    if (score >= 90) return { level: 'Excellent', color: 'text-green-600 bg-green-50' };
    if (score >= 80) return { level: 'Good', color: 'text-blue-600 bg-blue-50' };
    if (score >= 70) return { level: 'Fair', color: 'text-yellow-600 bg-yellow-50' };
    if (score >= 60) return { level: 'Poor', color: 'text-orange-600 bg-orange-50' };
    return { level: 'Critical', color: 'text-red-600 bg-red-50' };
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-center">
          <AlertTriangle className="w-16 h-16 text-red-500 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-gray-900 mb-2">Unable to load data</h2>
          <p className="text-gray-600">Please check your connection and try again.</p>
        </div>
      </div>
    );
  }

  const riskLevel = getRiskLevel(data.unified_risk_score);

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white shadow-sm border-b border-gray-200">
        <div className="px-6 py-4">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-gray-900">Cloud Security Dashboard</h1>
              <p className="text-sm text-gray-600 mt-1">
                Comprehensive security monitoring across all cloud providers
              </p>
            </div>
            <div className="flex items-center space-x-4">
              <button
                onClick={fetchCloudSecurityData}
                className="flex items-center px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                <RefreshCw className="w-4 h-4 mr-2" />
                Refresh
              </button>
              <button className="flex items-center px-4 py-2 text-sm font-medium text-white bg-blue-600 border border-transparent rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                <Download className="w-4 h-4 mr-2" />
                Export Report
              </button>
            </div>
          </div>
        </div>
      </div>

      <div className="px-6 py-8">
        {/* Main Security Score Card */}
        <div className="mb-8">
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-gray-900">Overall Security Posture</h2>
              <span className={`px-3 py-1 rounded-full text-sm font-medium ${riskLevel.color}`}>
                {riskLevel.level}
              </span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
              <div className="text-center">
                <div className="text-3xl font-bold text-gray-900 mb-2">{data.unified_risk_score}</div>
                <div className="text-sm text-gray-600">Security Score</div>
              </div>
              <div className="text-center">
                <div className="text-3xl font-bold text-red-600 mb-2">{data.critical_count}</div>
                <div className="text-sm text-gray-600">Critical Issues</div>
              </div>
              <div className="text-center">
                <div className="text-3xl font-bold text-orange-600 mb-2">{data.high_count}</div>
                <div className="text-sm text-gray-600">High Risk</div>
              </div>
              <div className="text-center">
                <div className="text-3xl font-bold text-blue-600 mb-2">{data.total_findings}</div>
                <div className="text-sm text-gray-600">Total Findings</div>
              </div>
            </div>
          </div>
        </div>

        {/* Module Scores */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          {/* CSPM Score */}
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <div className="flex items-center mb-4">
              <div className="p-2 bg-blue-100 rounded-lg">
                <Shield className="w-6 h-6 text-blue-600" />
              </div>
              <div className="ml-3">
                <h3 className="text-lg font-semibold text-gray-900">CSPM</h3>
                <p className="text-sm text-gray-600">Cloud Security Posture Management</p>
              </div>
            </div>
            <div className="text-3xl font-bold text-blue-600 mb-2">{data.cspm_score}</div>
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div 
                className="bg-blue-600 h-2 rounded-full" 
                style={{ width: `${data.cspm_score}%` }}
              ></div>
            </div>
          </div>

          {/* CASB Score */}
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <div className="flex items-center mb-4">
              <div className="p-2 bg-green-100 rounded-lg">
                <Cloud className="w-6 h-6 text-green-600" />
              </div>
              <div className="ml-3">
                <h3 className="text-lg font-semibold text-gray-900">CASB</h3>
                <p className="text-sm text-gray-600">Cloud Access Security Broker</p>
              </div>
            </div>
            <div className="text-3xl font-bold text-green-600 mb-2">{data.casb_score}</div>
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div 
                className="bg-green-600 h-2 rounded-full" 
                style={{ width: `${data.casb_score}%` }}
              ></div>
            </div>
          </div>

          {/* Cloud-Native Score */}
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <div className="flex items-center mb-4">
              <div className="p-2 bg-purple-100 rounded-lg">
                <Server className="w-6 h-6 text-purple-600" />
              </div>
              <div className="ml-3">
                <h3 className="text-lg font-semibold text-gray-900">Cloud-Native</h3>
                <p className="text-sm text-gray-600">Native Security Features</p>
              </div>
            </div>
            <div className="text-3xl font-bold text-purple-600 mb-2">{data.cloud_native_score}</div>
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div 
                className="bg-purple-600 h-2 rounded-full" 
                style={{ width: `${data.cloud_native_score}%` }}
              ></div>
            </div>
          </div>
        </div>

        {/* Compliance Status */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6 mb-8">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Compliance Status</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center p-4 bg-gray-50 rounded-lg">
              <div className="text-2xl font-bold text-blue-600 mb-1">{data.compliance_status.cis}%</div>
              <div className="text-sm text-gray-600">CIS Benchmarks</div>
            </div>
            <div className="text-center p-4 bg-gray-50 rounded-lg">
              <div className="text-2xl font-bold text-green-600 mb-1">{data.compliance_status.nist}%</div>
              <div className="text-sm text-gray-600">NIST Framework</div>
            </div>
            <div className="text-center p-4 bg-gray-50 rounded-lg">
              <div className="text-2xl font-bold text-purple-600 mb-1">{data.compliance_status.pci_dss}%</div>
              <div className="text-sm text-gray-600">PCI DSS</div>
            </div>
            <div className="text-center p-4 bg-gray-50 rounded-lg">
              <div className="text-2xl font-bold text-orange-600 mb-1">{data.compliance_status.iso27001}%</div>
              <div className="text-sm text-gray-600">ISO 27001</div>
            </div>
          </div>
        </div>

        {/* Recent Findings */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6 mb-8">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900">Recent Security Findings</h3>
            <button className="text-sm text-blue-600 hover:text-blue-700">View All</button>
          </div>
          <div className="space-y-4">
            {data.recent_findings.map((finding) => (
              <div key={finding.id} className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                <div className="flex items-center space-x-4">
                  <div className={`p-2 rounded-lg ${getSeverityColor(finding.severity)}`}>
                    {getSeverityIcon(finding.severity)}
                  </div>
                  <div>
                    <h4 className="font-medium text-gray-900">{finding.title}</h4>
                    <p className="text-sm text-gray-600">{finding.resource}</p>
                  </div>
                </div>
                <div className="text-right">
                  <div className={`px-2 py-1 rounded-full text-xs font-medium ${getSeverityColor(finding.severity)}`}>
                    {finding.severity}
                  </div>
                  <div className="text-xs text-gray-500 mt-1">
                    {new Date(finding.detected_at).toLocaleDateString()}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Cloud Accounts */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Cloud Accounts</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {data.cloud_accounts.map((account) => (
              <div key={account.id} className="p-4 border border-gray-200 rounded-lg">
                <div className="flex items-center justify-between mb-2">
                  <h4 className="font-medium text-gray-900">{account.name}</h4>
                  <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                    account.status === 'active' ? 'text-green-600 bg-green-50' : 'text-red-600 bg-red-50'
                  }`}>
                    {account.status}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-600 capitalize">{account.provider}</span>
                  <span className="text-sm font-medium text-gray-900">{account.security_score}</span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-1 mt-2">
                  <div 
                    className="bg-blue-600 h-1 rounded-full" 
                    style={{ width: `${account.security_score}%` }}
                  ></div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default EnhancedCloudSecurityDashboard; 