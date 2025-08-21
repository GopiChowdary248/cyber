import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  ChartBarIcon,
  ExclamationTriangleIcon,
  DocumentMagnifyingGlassIcon,
  CloudIcon,
  WrenchScrewdriverIcon,
  ClipboardDocumentIcon,
  CogIcon,
  DocumentTextIcon,
  ShieldCheckIcon,
  BellIcon,
  ArrowPathIcon,
  ServerIcon,
  TagIcon,
  LockClosedIcon,
  ClockIcon,
  CheckCircleIcon,
  XCircleIcon,
  ExclamationCircleIcon
} from '@heroicons/react/24/outline';
import { Shield, Zap, Activity, Globe, Database, Server } from 'lucide-react';

interface CSPMData {
  overview: {
    totalAccounts: number;
    compliantResources: number;
    violations: number;
    securityScore: number;
  };
  compliance: {
    aws: {
      score: number;
      violations: number;
      status: 'compliant' | 'non-compliant' | 'warning';
    };
    azure: {
      score: number;
      violations: number;
      status: 'compliant' | 'non-compliant' | 'warning';
    };
    gcp: {
      score: number;
      violations: number;
      status: 'compliant' | 'non-compliant' | 'warning';
    };
  };
  resources: {
    compute: number;
    storage: number;
    network: number;
    database: number;
    security: number;
  };
  recentScans: Array<{
    id: string;
    cloudProvider: string;
    accountName: string;
    status: 'completed' | 'running' | 'failed' | 'queued';
    violationsFound: number;
    duration: string;
    timestamp: string;
  }>;
  topViolations: Array<{
    id: string;
    title: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    cloudProvider: string;
    resourceType: string;
    description: string;
    remediation: string;
  }>;
}

const CSPM: React.FC = () => {
  const [data, setData] = useState<CSPMData | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('dashboard');

  useEffect(() => {
    const fetchData = async () => {
      try {
        const mockData: CSPMData = {
          overview: {
            totalAccounts: 12,
            compliantResources: 2847,
            violations: 156,
            securityScore: 87
          },
          compliance: {
            aws: {
              score: 92,
              violations: 45,
              status: 'compliant'
            },
            azure: {
              score: 78,
              violations: 67,
              status: 'warning'
            },
            gcp: {
              score: 95,
              violations: 23,
              status: 'compliant'
            }
          },
          resources: {
            compute: 456,
            storage: 234,
            network: 189,
            database: 123,
            security: 67
          },
          recentScans: [
            {
              id: 'scan-001',
              cloudProvider: 'AWS',
              accountName: 'Production Account',
              status: 'completed',
              violationsFound: 12,
              duration: '2m 30s',
              timestamp: '1 hour ago'
            },
            {
              id: 'scan-002',
              cloudProvider: 'Azure',
              accountName: 'Development Account',
              status: 'running',
              violationsFound: 0,
              duration: '1m 15s',
              timestamp: '5 minutes ago'
            },
            {
              id: 'scan-003',
              cloudProvider: 'GCP',
              accountName: 'Staging Account',
              status: 'completed',
              violationsFound: 5,
              duration: '1m 45s',
              timestamp: '30 minutes ago'
            }
          ],
          topViolations: [
            {
              id: 'violation-001',
              title: 'Public S3 Bucket Access',
              severity: 'critical',
              cloudProvider: 'AWS',
              resourceType: 'S3 Bucket',
              description: 'S3 bucket is publicly accessible without proper access controls',
              remediation: 'Configure bucket policies and enable public access blocking'
            },
            {
              id: 'violation-002',
              title: 'Unencrypted EBS Volumes',
              severity: 'high',
              cloudProvider: 'AWS',
              resourceType: 'EBS Volume',
              description: 'EBS volumes are not encrypted at rest',
              remediation: 'Enable encryption for all EBS volumes'
            },
            {
              id: 'violation-003',
              title: 'Open Security Groups',
              severity: 'high',
              cloudProvider: 'AWS',
              resourceType: 'Security Group',
              description: 'Security group allows unrestricted access from 0.0.0.0/0',
              remediation: 'Restrict security group rules to specific IP ranges'
            }
          ]
        };

        setData(mockData);
      } catch (error) {
        console.error('Error fetching CSPM data:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'compliant':
        return 'text-green-500 bg-green-100';
      case 'warning':
        return 'text-yellow-500 bg-yellow-100';
      case 'non-compliant':
        return 'text-red-500 bg-red-100';
      default:
        return 'text-gray-500 bg-gray-100';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'text-red-600 bg-red-100 border-red-200';
      case 'high':
        return 'text-orange-600 bg-orange-100 border-orange-200';
      case 'medium':
        return 'text-yellow-600 bg-yellow-100 border-yellow-200';
      case 'low':
        return 'text-blue-600 bg-blue-100 border-blue-200';
      default:
        return 'text-gray-600 bg-gray-100 border-gray-200';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
        <div className="text-center">
          <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-blue-500 mx-auto mb-4"></div>
          <p className="text-white text-lg">Loading CSPM dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white">
      {/* Header */}
      <div className="bg-slate-800/50 backdrop-blur-sm border-b border-slate-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="h-10 w-10 bg-blue-600 rounded-lg flex items-center justify-center">
                <CloudIcon className="h-6 w-6 text-white" />
              </div>
              <div>
                <h1 className="text-2xl font-bold">Cloud Security Posture Management</h1>
                <p className="text-slate-400 text-sm">Monitor and manage cloud security compliance</p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <button className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg transition-colors flex items-center space-x-2">
                <ArrowPathIcon className="h-4 w-4" />
                <span>Run Scan</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
        <div className="flex space-x-1 bg-slate-800/50 rounded-lg p-1">
          {[
            { id: 'dashboard', label: 'Dashboard', icon: ChartBarIcon },
            { id: 'compliance', label: 'Compliance', icon: ShieldCheckIcon },
            { id: 'violations', label: 'Violations', icon: ExclamationTriangleIcon },
            { id: 'resources', label: 'Resources', icon: ServerIcon },
            { id: 'scans', label: 'Scans', icon: DocumentMagnifyingGlassIcon }
          ].map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center space-x-2 px-4 py-2 rounded-md transition-all ${
                  activeTab === tab.id
                    ? 'bg-blue-600 text-white shadow-lg'
                    : 'text-slate-400 hover:text-white hover:bg-slate-700/50'
                }`}
              >
                <Icon className="h-4 w-4" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'dashboard' && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="space-y-6"
          >
            {/* Key Metrics Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-slate-400 text-sm">Total Accounts</p>
                    <p className="text-3xl font-bold text-white">{data?.overview.totalAccounts || 0}</p>
                  </div>
                  <div className="h-12 w-12 bg-blue-500/20 rounded-lg flex items-center justify-center">
                    <CloudIcon className="h-6 w-6 text-blue-500" />
                  </div>
                </div>
                <div className="mt-4 flex items-center text-sm">
                  <span className="text-slate-400">Multi-cloud environment</span>
                </div>
              </div>

              <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-slate-400 text-sm">Security Score</p>
                    <p className="text-3xl font-bold text-white">{data?.overview.securityScore || 0}%</p>
                  </div>
                  <div className="h-12 w-12 bg-green-500/20 rounded-lg flex items-center justify-center">
                    <Shield className="h-6 w-6 text-green-500" />
                  </div>
                </div>
                <div className="mt-4 flex items-center text-sm">
                  <span className="text-slate-400">Overall compliance</span>
                </div>
              </div>

              <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-slate-400 text-sm">Compliant Resources</p>
                    <p className="text-3xl font-bold text-white">{data?.overview.compliantResources || 0}</p>
                  </div>
                  <div className="h-12 w-12 bg-green-500/20 rounded-lg flex items-center justify-center">
                    <CheckCircleIcon className="h-6 w-6 text-green-500" />
                  </div>
                </div>
                <div className="mt-4 flex items-center text-sm">
                  <span className="text-slate-400">Secure resources</span>
                </div>
              </div>

              <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-slate-400 text-sm">Violations</p>
                    <p className="text-3xl font-bold text-white">{data?.overview.violations || 0}</p>
                  </div>
                  <div className="h-12 w-12 bg-red-500/20 rounded-lg flex items-center justify-center">
                    <ExclamationTriangleIcon className="h-6 w-6 text-red-500" />
                  </div>
                </div>
                <div className="mt-4 flex items-center text-sm">
                  <span className="text-slate-400">Need attention</span>
                </div>
              </div>
            </div>

            {/* Cloud Provider Compliance */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
                <h3 className="text-lg font-semibold mb-4 flex items-center space-x-2">
                  <Globe className="h-5 w-5 text-blue-500" />
                  <span>Cloud Provider Compliance</span>
                </h3>
                <div className="space-y-4">
                  {data && Object.entries(data.compliance).map(([provider, info]) => (
                    <div key={provider} className="flex items-center justify-between p-3 bg-slate-700/50 rounded-lg">
                      <div className="flex items-center space-x-3">
                        <span className="text-lg font-semibold uppercase">{provider}</span>
                        <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(info.status)}`}>
                          {info.status}
                        </span>
                      </div>
                      <div className="text-right">
                        <div className="text-2xl font-bold">{info.score}%</div>
                        <div className="text-sm text-slate-400">{info.violations} violations</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
                <h3 className="text-lg font-semibold mb-4 flex items-center space-x-2">
                  <Server className="h-5 w-5 text-green-500" />
                  <span>Resource Distribution</span>
                </h3>
                <div className="space-y-3">
                  {data && Object.entries(data.resources).map(([type, count]) => (
                    <div key={type} className="flex items-center justify-between">
                      <span className="text-slate-400 capitalize">{type}</span>
                      <span className="font-semibold">{count}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Recent Scans */}
            <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
              <h3 className="text-lg font-semibold mb-4 flex items-center space-x-2">
                <DocumentMagnifyingGlassIcon className="h-5 w-5 text-purple-500" />
                <span>Recent Scans</span>
              </h3>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="text-left text-slate-400 border-b border-slate-700">
                      <th className="pb-2">Provider</th>
                      <th className="pb-2">Account</th>
                      <th className="pb-2">Status</th>
                      <th className="pb-2">Violations</th>
                      <th className="pb-2">Duration</th>
                      <th className="pb-2">Time</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data?.recentScans.map((scan) => (
                      <tr key={scan.id} className="border-b border-slate-700/50">
                        <td className="py-3">
                          <span className="font-medium">{scan.cloudProvider}</span>
                        </td>
                        <td className="py-3 text-slate-300">{scan.accountName}</td>
                        <td className="py-3">
                          <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                            scan.status === 'completed' ? 'bg-green-100 text-green-800' :
                            scan.status === 'running' ? 'bg-blue-100 text-blue-800' :
                            scan.status === 'failed' ? 'bg-red-100 text-red-800' :
                            'bg-yellow-100 text-yellow-800'
                          }`}>
                            {scan.status}
                          </span>
                        </td>
                        <td className="py-3 text-slate-300">{scan.violationsFound}</td>
                        <td className="py-3 text-slate-300">{scan.duration}</td>
                        <td className="py-3 text-slate-300">{scan.timestamp}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </motion.div>
        )}

        {activeTab === 'compliance' && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="space-y-6"
          >
            <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
              <h3 className="text-lg font-semibold mb-4">Compliance Frameworks</h3>
              <p className="text-slate-400">Compliance framework management content will be implemented here.</p>
            </div>
          </motion.div>
        )}

        {activeTab === 'violations' && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="space-y-6"
          >
            <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
              <h3 className="text-lg font-semibold mb-4">Top Violations</h3>
              <div className="space-y-4">
                {data?.topViolations.map((violation) => (
                  <div key={violation.id} className="p-4 bg-slate-700/50 rounded-lg border-l-4 border-red-500">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center space-x-2 mb-2">
                          <h4 className="font-semibold">{violation.title}</h4>
                          <span className={`px-2 py-1 rounded-full text-xs font-medium ${getSeverityColor(violation.severity)}`}>
                            {violation.severity}
                          </span>
                        </div>
                        <p className="text-slate-300 text-sm mb-2">{violation.description}</p>
                        <div className="flex items-center space-x-4 text-xs text-slate-400">
                          <span>{violation.cloudProvider}</span>
                          <span>{violation.resourceType}</span>
                        </div>
                      </div>
                      <button className="bg-blue-600 hover:bg-blue-700 px-3 py-1 rounded text-xs transition-colors">
                        Remediate
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </motion.div>
        )}

        {activeTab === 'resources' && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="space-y-6"
          >
            <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
              <h3 className="text-lg font-semibold mb-4">Resource Management</h3>
              <p className="text-slate-400">Resource management content will be implemented here.</p>
            </div>
          </motion.div>
        )}

        {activeTab === 'scans' && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="space-y-6"
          >
            <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
              <h3 className="text-lg font-semibold mb-4">Scan Management</h3>
              <p className="text-slate-400">Scan management content will be implemented here.</p>
            </div>
          </motion.div>
        )}
      </div>
    </div>
  );
};

export default CSPM;
