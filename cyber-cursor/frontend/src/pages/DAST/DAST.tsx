import React, { useState, useEffect } from 'react';
import {
  ShieldExclamationIcon,
  GlobeAltIcon,
  BugAntIcon,
  DocumentMagnifyingGlassIcon,
  PlayIcon,
  ClockIcon,
  CheckCircleIcon,
  XCircleIcon,
  ExclamationTriangleIcon,
  InformationCircleIcon,
  CogIcon,
  ChartBarIcon,
  EyeIcon,
  CodeBracketIcon,
  ServerIcon,
  KeyIcon,
  UserGroupIcon,
  DocumentTextIcon,
  ArrowPathIcon,
  PlusIcon
} from '@heroicons/react/24/outline';

interface DASTData {
  overview: {
    totalProjects: number;
    totalScans: number;
    activeScans: number;
    totalVulnerabilities: number;
    securityScore: number;
  };
  vulnerabilities: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  scanTypes: {
    full: number;
    passive: number;
    active: number;
    custom: number;
  };
  recentScans: Array<{
    id: string;
    projectName: string;
    status: string;
    vulnerabilities: number;
    duration: string;
    timestamp: string;
  }>;
}

const DAST: React.FC = () => {
  const [data, setData] = useState<DASTData | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    // Simulate API call
    setTimeout(() => {
      setData({
        overview: {
          totalProjects: 5,
          totalScans: 23,
          activeScans: 2,
          totalVulnerabilities: 47,
          securityScore: 78.5
        },
        vulnerabilities: {
          critical: 8,
          high: 15,
          medium: 18,
          low: 6,
          total: 47
        },
        scanTypes: {
          full: 45,
          passive: 32,
          active: 28,
          custom: 15
        },
        recentScans: [
          {
            id: 'scan-001',
            projectName: 'E-commerce Web App',
            status: 'completed',
            vulnerabilities: 3,
            duration: '3m 45s',
            timestamp: '2025-08-02T18:00:00Z'
          },
          {
            id: 'scan-002',
            projectName: 'Admin Portal',
            status: 'running',
            vulnerabilities: 0,
            duration: '1m 23s',
            timestamp: '2025-08-02T17:45:00Z'
          },
          {
            id: 'scan-003',
            projectName: 'API Gateway',
            status: 'completed',
            vulnerabilities: 1,
            duration: '2m 12s',
            timestamp: '2025-08-02T17:30:00Z'
          }
        ]
      });
      setLoading(false);
    }, 1000);
  }, []);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-50';
      case 'high': return 'text-orange-600 bg-orange-50';
      case 'medium': return 'text-yellow-600 bg-yellow-50';
      case 'low': return 'text-blue-600 bg-blue-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'text-green-600 bg-green-50';
      case 'running': return 'text-blue-600 bg-blue-50';
      case 'failed': return 'text-red-600 bg-red-50';
      case 'queued': return 'text-gray-600 bg-gray-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <CheckCircleIcon className="w-4 h-4" />;
      case 'running': return <ArrowPathIcon className="w-4 h-4 animate-spin" />;
      case 'failed': return <XCircleIcon className="w-4 h-4" />;
      case 'queued': return <ClockIcon className="w-4 h-4" />;
      default: return <InformationCircleIcon className="w-4 h-4" />;
    }
  };

  const tabs = [
    { id: 'overview', name: 'Overview', icon: <ChartBarIcon className="w-4 h-4" /> },
    { id: 'projects', name: 'Projects', icon: <GlobeAltIcon className="w-4 h-4" /> },
    { id: 'scans', name: 'Scans', icon: <BugAntIcon className="w-4 h-4" /> },
    { id: 'vulnerabilities', name: 'Vulnerabilities', icon: <ExclamationTriangleIcon className="w-4 h-4" /> },
    { id: 'payloads', name: 'Payloads', icon: <CodeBracketIcon className="w-4 h-4" /> },
    { id: 'reports', name: 'Reports', icon: <DocumentTextIcon className="w-4 h-4" /> },
    { id: 'settings', name: 'Settings', icon: <CogIcon className="w-4 h-4" /> }
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <ArrowPathIcon className="w-8 h-8 animate-spin text-blue-600" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Dynamic Application Security Testing (DAST)</h1>
          <p className="text-gray-600">Scan web applications for vulnerabilities in real-time</p>
        </div>
        <button className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700">
          <PlusIcon className="w-4 h-4 mr-2" />
          New Scan
        </button>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center py-2 px-1 border-b-2 font-medium text-sm ${
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              {tab.icon}
              <span className="ml-2">{tab.name}</span>
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      <div className="mt-6">
        {activeTab === 'overview' && data && (
          <div className="space-y-6">
            {/* Overview Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <div className="bg-white overflow-hidden shadow rounded-lg">
                <div className="p-5">
                  <div className="flex items-center">
                    <div className="flex-shrink-0">
                      <GlobeAltIcon className="h-6 w-6 text-gray-400" />
                    </div>
                    <div className="ml-5 w-0 flex-1">
                      <dl>
                        <dt className="text-sm font-medium text-gray-500 truncate">Total Projects</dt>
                        <dd className="text-lg font-medium text-gray-900">{data.overview.totalProjects}</dd>
                      </dl>
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-white overflow-hidden shadow rounded-lg">
                <div className="p-5">
                  <div className="flex items-center">
                    <div className="flex-shrink-0">
                      <BugAntIcon className="h-6 w-6 text-gray-400" />
                    </div>
                    <div className="ml-5 w-0 flex-1">
                      <dl>
                        <dt className="text-sm font-medium text-gray-500 truncate">Total Scans</dt>
                        <dd className="text-lg font-medium text-gray-900">{data.overview.totalScans}</dd>
                      </dl>
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-white overflow-hidden shadow rounded-lg">
                <div className="p-5">
                  <div className="flex items-center">
                    <div className="flex-shrink-0">
                      <PlayIcon className="h-6 w-6 text-gray-400" />
                    </div>
                    <div className="ml-5 w-0 flex-1">
                      <dl>
                        <dt className="text-sm font-medium text-gray-500 truncate">Active Scans</dt>
                        <dd className="text-lg font-medium text-gray-900">{data.overview.activeScans}</dd>
                      </dl>
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-white overflow-hidden shadow rounded-lg">
                <div className="p-5">
                  <div className="flex items-center">
                    <div className="flex-shrink-0">
                      <ShieldExclamationIcon className="h-6 w-6 text-gray-400" />
                    </div>
                    <div className="ml-5 w-0 flex-1">
                      <dl>
                        <dt className="text-sm font-medium text-gray-500 truncate">Security Score</dt>
                        <dd className="text-lg font-medium text-gray-900">{data.overview.securityScore}/100</dd>
                      </dl>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Vulnerability Distribution */}
            <div className="bg-white shadow rounded-lg">
              <div className="px-4 py-5 sm:p-6">
                <h3 className="text-lg leading-6 font-medium text-gray-900 mb-4">Vulnerability Distribution</h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="text-center">
                    <div className="text-2xl font-bold text-red-600">{data.vulnerabilities.critical}</div>
                    <div className="text-sm text-gray-500">Critical</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-orange-600">{data.vulnerabilities.high}</div>
                    <div className="text-sm text-gray-500">High</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-yellow-600">{data.vulnerabilities.medium}</div>
                    <div className="text-sm text-gray-500">Medium</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-blue-600">{data.vulnerabilities.low}</div>
                    <div className="text-sm text-gray-500">Low</div>
                  </div>
                </div>
              </div>
            </div>

            {/* Recent Scans */}
            <div className="bg-white shadow rounded-lg">
              <div className="px-4 py-5 sm:p-6">
                <h3 className="text-lg leading-6 font-medium text-gray-900 mb-4">Recent Scans</h3>
                <div className="space-y-4">
                  {data.recentScans.map((scan) => (
                    <div key={scan.id} className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
                      <div className="flex items-center space-x-4">
                        <div className={`p-2 rounded-full ${getStatusColor(scan.status)}`}>
                          {getStatusIcon(scan.status)}
                        </div>
                        <div>
                          <div className="font-medium text-gray-900">{scan.projectName}</div>
                          <div className="text-sm text-gray-500">Duration: {scan.duration}</div>
                        </div>
                      </div>
                      <div className="text-right">
                        <div className="text-sm font-medium text-gray-900">{scan.vulnerabilities} vulnerabilities</div>
                        <div className="text-sm text-gray-500">{new Date(scan.timestamp).toLocaleString()}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'projects' && (
          <div className="bg-white shadow rounded-lg">
            <div className="px-4 py-5 sm:p-6">
              <h3 className="text-lg leading-6 font-medium text-gray-900 mb-4">DAST Projects</h3>
              <div className="space-y-4">
                <div className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
                  <div className="flex items-center space-x-4">
                    <GlobeAltIcon className="h-8 w-8 text-blue-600" />
                    <div>
                      <div className="font-medium text-gray-900">E-commerce Web App</div>
                      <div className="text-sm text-gray-500">https://demo-ecommerce.example.com</div>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-sm font-medium text-gray-900">Security Score: 75.5</div>
                    <div className="text-sm text-gray-500">Last scan: 2 hours ago</div>
                  </div>
                </div>
                <div className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
                  <div className="flex items-center space-x-4">
                    <KeyIcon className="h-8 w-8 text-green-600" />
                    <div>
                      <div className="font-medium text-gray-900">Admin Portal</div>
                      <div className="text-sm text-gray-500">https://admin.example.com</div>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-sm font-medium text-gray-900">Security Score: 68.2</div>
                    <div className="text-sm text-gray-500">Last scan: 4 hours ago</div>
                  </div>
                </div>
                <div className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
                  <div className="flex items-center space-x-4">
                    <ServerIcon className="h-8 w-8 text-purple-600" />
                    <div>
                      <div className="font-medium text-gray-900">API Gateway</div>
                      <div className="text-sm text-gray-500">https://api.example.com</div>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-sm font-medium text-gray-900">Security Score: 82.1</div>
                    <div className="text-sm text-gray-500">Last scan: 6 hours ago</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'scans' && (
          <div className="bg-white shadow rounded-lg">
            <div className="px-4 py-5 sm:p-6">
              <h3 className="text-lg leading-6 font-medium text-gray-900 mb-4">Scan History</h3>
              <div className="space-y-4">
                {data?.recentScans.map((scan) => (
                  <div key={scan.id} className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
                    <div className="flex items-center space-x-4">
                      <div className={`p-2 rounded-full ${getStatusColor(scan.status)}`}>
                        {getStatusIcon(scan.status)}
                      </div>
                      <div>
                        <div className="font-medium text-gray-900">{scan.projectName}</div>
                        <div className="text-sm text-gray-500">Scan ID: {scan.id}</div>
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="text-sm font-medium text-gray-900">{scan.vulnerabilities} vulnerabilities found</div>
                      <div className="text-sm text-gray-500">Duration: {scan.duration}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'vulnerabilities' && (
          <div className="bg-white shadow rounded-lg">
            <div className="px-4 py-5 sm:p-6">
              <h3 className="text-lg leading-6 font-medium text-gray-900 mb-4">Detected Vulnerabilities</h3>
              <div className="space-y-4">
                <div className="flex items-center justify-between p-4 border border-red-200 rounded-lg bg-red-50">
                  <div className="flex items-center space-x-4">
                    <ExclamationTriangleIcon className="h-6 w-6 text-red-600" />
                    <div>
                      <div className="font-medium text-gray-900">SQL Injection in Search Parameter</div>
                      <div className="text-sm text-gray-500">CWE-89 | A03:2021-Injection</div>
                    </div>
                  </div>
                  <div className="text-right">
                    <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                      Critical
                    </span>
                  </div>
                </div>
                <div className="flex items-center justify-between p-4 border border-orange-200 rounded-lg bg-orange-50">
                  <div className="flex items-center space-x-4">
                    <ExclamationTriangleIcon className="h-6 w-6 text-orange-600" />
                    <div>
                      <div className="font-medium text-gray-900">Cross-Site Scripting in Contact Form</div>
                      <div className="text-sm text-gray-500">CWE-79 | A03:2021-Injection</div>
                    </div>
                  </div>
                  <div className="text-right">
                    <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-orange-100 text-orange-800">
                      High
                    </span>
                  </div>
                </div>
                <div className="flex items-center justify-between p-4 border border-yellow-200 rounded-lg bg-yellow-50">
                  <div className="flex items-center space-x-4">
                    <ExclamationTriangleIcon className="h-6 w-6 text-yellow-600" />
                    <div>
                      <div className="font-medium text-gray-900">Missing Security Headers</div>
                      <div className="text-sm text-gray-500">CWE-693 | A05:2021-Security Misconfiguration</div>
                    </div>
                  </div>
                  <div className="text-right">
                    <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                      Medium
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'payloads' && (
          <div className="bg-white shadow rounded-lg">
            <div className="px-4 py-5 sm:p-6">
              <h3 className="text-lg leading-6 font-medium text-gray-900 mb-4">OWASP Top 10 Payloads</h3>
              <div className="space-y-4">
                <div className="p-4 border border-gray-200 rounded-lg">
                  <div className="flex items-center justify-between mb-2">
                    <div className="font-medium text-gray-900">SQL Injection Payloads</div>
                    <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                      Critical
                    </span>
                  </div>
                  <div className="text-sm text-gray-600 space-y-1">
                    <div>• <code className="bg-gray-100 px-1 rounded">' OR 1=1 --</code></div>
                    <div>• <code className="bg-gray-100 px-1 rounded">' UNION SELECT NULL,NULL,NULL--</code></div>
                    <div>• <code className="bg-gray-100 px-1 rounded">'; WAITFOR DELAY '00:00:05'--</code></div>
                  </div>
                </div>
                <div className="p-4 border border-gray-200 rounded-lg">
                  <div className="flex items-center justify-between mb-2">
                    <div className="font-medium text-gray-900">XSS Payloads</div>
                    <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-orange-100 text-orange-800">
                      High
                    </span>
                  </div>
                  <div className="text-sm text-gray-600 space-y-1">
                    <div>• <code className="bg-gray-100 px-1 rounded">&lt;script&gt;alert('XSS')&lt;/script&gt;</code></div>
                    <div>• <code className="bg-gray-100 px-1 rounded">" onmouseover="alert('XSS')"</code></div>
                    <div>• <code className="bg-gray-100 px-1 rounded">javascript:alert("XSS")</code></div>
                  </div>
                </div>
                <div className="p-4 border border-gray-200 rounded-lg">
                  <div className="flex items-center justify-between mb-2">
                    <div className="font-medium text-gray-900">Command Injection Payloads</div>
                    <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                      Critical
                    </span>
                  </div>
                  <div className="text-sm text-gray-600 space-y-1">
                    <div>• <code className="bg-gray-100 px-1 rounded">; sleep 5 #</code></div>
                    <div>• <code className="bg-gray-100 px-1 rounded">| sleep 5</code></div>
                    <div>• <code className="bg-gray-100 px-1 rounded">`sleep 5`</code></div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'reports' && (
          <div className="bg-white shadow rounded-lg">
            <div className="px-4 py-5 sm:p-6">
              <h3 className="text-lg leading-6 font-medium text-gray-900 mb-4">Generated Reports</h3>
              <div className="space-y-4">
                <div className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
                  <div className="flex items-center space-x-4">
                    <DocumentTextIcon className="h-8 w-8 text-blue-600" />
                    <div>
                      <div className="font-medium text-gray-900">E-commerce Web App - Full Scan Report</div>
                      <div className="text-sm text-gray-500">Generated: 2 hours ago</div>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-sm font-medium text-gray-900">PDF | JSON | HTML</div>
                    <div className="text-sm text-gray-500">3 vulnerabilities found</div>
                  </div>
                </div>
                <div className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
                  <div className="flex items-center space-x-4">
                    <DocumentTextIcon className="h-8 w-8 text-green-600" />
                    <div>
                      <div className="font-medium text-gray-900">Admin Portal - Security Assessment</div>
                      <div className="text-sm text-gray-500">Generated: 4 hours ago</div>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-sm font-medium text-gray-900">PDF | JSON</div>
                    <div className="text-sm text-gray-500">2 vulnerabilities found</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'settings' && (
          <div className="bg-white shadow rounded-lg">
            <div className="px-4 py-5 sm:p-6">
              <h3 className="text-lg leading-6 font-medium text-gray-900 mb-4">DAST Configuration</h3>
              <div className="space-y-6">
                <div>
                  <h4 className="text-md font-medium text-gray-900 mb-2">Scan Settings</h4>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-600">Default scan type</span>
                      <span className="text-sm font-medium text-gray-900">Full Scan</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-600">Max scan duration</span>
                      <span className="text-sm font-medium text-gray-900">30 minutes</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-600">Concurrent scans</span>
                      <span className="text-sm font-medium text-gray-900">5</span>
                    </div>
                  </div>
                </div>
                <div>
                  <h4 className="text-md font-medium text-gray-900 mb-2">Payload Settings</h4>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-600">Enable custom payloads</span>
                      <span className="text-sm font-medium text-green-600">Enabled</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-600">Payload library size</span>
                      <span className="text-sm font-medium text-gray-900">25 payloads</span>
                    </div>
                  </div>
                </div>
                <div>
                  <h4 className="text-md font-medium text-gray-900 mb-2">Reporting</h4>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-600">Auto-generate reports</span>
                      <span className="text-sm font-medium text-green-600">Enabled</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-600">Report retention</span>
                      <span className="text-sm font-medium text-gray-900">90 days</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default DAST; 