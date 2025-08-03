import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  DocumentTextIcon, 
  ShieldCheckIcon, 
  BellIcon, 
  ChartBarIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  CogIcon,
  CodeBracketIcon,
  BugAntIcon,
  WrenchScrewdriverIcon,
  DocumentMagnifyingGlassIcon,
  ArrowPathIcon,
  ClipboardDocumentIcon
} from '@heroicons/react/24/outline';

interface SASTData {
  overview: {
    totalScans: number;
    activeScans: number;
    vulnerabilitiesFound: number;
    securityScore: number;
  };
  vulnerabilities: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  languages: {
    python: number;
    javascript: number;
    java: number;
    csharp: number;
    php: number;
  };
  recentScans: Array<{
    id: string;
    projectName: string;
    status: 'completed' | 'running' | 'failed' | 'queued';
    vulnerabilities: number;
    duration: string;
    timestamp: string;
  }>;
}

const SAST: React.FC = () => {
  const [data, setData] = useState<SASTData | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    const fetchData = async () => {
      try {
        const mockData: SASTData = {
          overview: {
            totalScans: 1247,
            activeScans: 3,
            vulnerabilitiesFound: 89,
            securityScore: 87
          },
          vulnerabilities: {
            critical: 5,
            high: 23,
            medium: 41,
            low: 20,
            total: 89
          },
          languages: {
            python: 34,
            javascript: 28,
            java: 15,
            csharp: 8,
            php: 4
          },
          recentScans: [
            {
              id: 'scan-001',
              projectName: 'E-commerce Platform',
              status: 'completed',
              vulnerabilities: 3,
              duration: '2m 34s',
              timestamp: '2 hours ago'
            },
            {
              id: 'scan-002',
              projectName: 'API Gateway',
              status: 'running',
              vulnerabilities: 0,
              duration: '1m 12s',
              timestamp: '5 minutes ago'
            },
            {
              id: 'scan-003',
              projectName: 'User Management',
              status: 'completed',
              vulnerabilities: 7,
              duration: '1m 45s',
              timestamp: '1 hour ago'
            }
          ]
        };
        
        setData(mockData);
      } catch (error) {
        console.error('Error fetching SAST data:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'text-green-600 bg-green-100';
      case 'running':
        return 'text-blue-600 bg-blue-100';
      case 'failed':
        return 'text-red-600 bg-red-100';
      case 'queued':
        return 'text-yellow-600 bg-yellow-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircleIcon className="w-5 h-5" />;
      case 'running':
        return <ArrowPathIcon className="w-5 h-5 animate-spin" />;
      case 'failed':
        return <XCircleIcon className="w-5 h-5" />;
      case 'queued':
        return <BellIcon className="w-5 h-5" />;
      default:
        return <ChartBarIcon className="w-5 h-5" />;
    }
  };

  const tabs = [
    { id: 'overview', label: 'Overview', icon: <ChartBarIcon className="w-4 h-4" /> },
    { id: 'vulnerabilities', label: 'Vulnerabilities', icon: <ExclamationTriangleIcon className="w-4 h-4" /> },
    { id: 'scans', label: 'Scan History', icon: <DocumentMagnifyingGlassIcon className="w-4 h-4" /> },
    { id: 'rules', label: 'Detection Rules', icon: <BugAntIcon className="w-4 h-4" /> },
    { id: 'auto-fix', label: 'Auto-Fix', icon: <WrenchScrewdriverIcon className="w-4 h-4" /> },
    { id: 'reports', label: 'Reports', icon: <ClipboardDocumentIcon className="w-4 h-4" /> },
    { id: 'settings', label: 'Settings', icon: <CogIcon className="w-4 h-4" /> }
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center">
          <ExclamationTriangleIcon className="w-12 h-12 text-red-500 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-gray-900">Error Loading Data</h3>
          <p className="text-gray-600">Unable to load SAST data</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">SAST - Static Application Security Testing</h1>
          <p className="text-gray-600">Detect vulnerabilities in source code using static analysis</p>
        </div>
        <div className="flex items-center space-x-2">
          <CodeBracketIcon className="w-8 h-8 text-blue-600" />
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8 overflow-x-auto">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center space-x-2 py-2 px-1 border-b-2 font-medium text-sm whitespace-nowrap ${
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              {tab.icon}
              <span>{tab.label}</span>
            </button>
          ))}
        </nav>
      </div>

      {/* Content */}
      <motion.div
        key={activeTab}
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="space-y-6"
      >
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Overview Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Total Scans</p>
                    <p className="text-2xl font-bold text-gray-900">{data.overview.totalScans.toLocaleString()}</p>
                  </div>
                  <DocumentMagnifyingGlassIcon className="w-8 h-8 text-blue-600" />
                </div>
              </div>
              
              <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Active Scans</p>
                    <p className="text-2xl font-bold text-blue-600">{data.overview.activeScans}</p>
                  </div>
                  <ArrowPathIcon className="w-8 h-8 text-blue-600 animate-spin" />
                </div>
              </div>
              
              <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Vulnerabilities Found</p>
                    <p className="text-2xl font-bold text-red-600">{data.overview.vulnerabilitiesFound}</p>
                  </div>
                  <ExclamationTriangleIcon className="w-8 h-8 text-red-600" />
                </div>
              </div>
              
              <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Security Score</p>
                    <p className="text-2xl font-bold text-gray-900">{data.overview.securityScore}%</p>
                  </div>
                  <ChartBarIcon className="w-8 h-8 text-green-600" />
                </div>
              </div>
            </div>

            {/* Vulnerability Distribution */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
                <h3 className="text-lg font-semibold text-gray-900 mb-4">Vulnerability Severity</h3>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                      <span className="text-sm">Critical</span>
                    </div>
                    <span className="text-sm font-medium">{data.vulnerabilities.critical}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <div className="w-3 h-3 bg-orange-500 rounded-full"></div>
                      <span className="text-sm">High</span>
                    </div>
                    <span className="text-sm font-medium">{data.vulnerabilities.high}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
                      <span className="text-sm">Medium</span>
                    </div>
                    <span className="text-sm font-medium">{data.vulnerabilities.medium}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <div className="w-3 h-3 bg-blue-500 rounded-full"></div>
                      <span className="text-sm">Low</span>
                    </div>
                    <span className="text-sm font-medium">{data.vulnerabilities.low}</span>
                  </div>
                </div>
              </div>

              <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
                <h3 className="text-lg font-semibold text-gray-900 mb-4">Language Distribution</h3>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Python</span>
                    <span className="text-sm font-medium">{data.languages.python}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">JavaScript</span>
                    <span className="text-sm font-medium">{data.languages.javascript}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Java</span>
                    <span className="text-sm font-medium">{data.languages.java}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">C#</span>
                    <span className="text-sm font-medium">{data.languages.csharp}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">PHP</span>
                    <span className="text-sm font-medium">{data.languages.php}</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Recent Scans */}
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Scans</h3>
              <div className="space-y-3">
                {data.recentScans.map((scan) => (
                  <div key={scan.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                    <div className="flex items-center space-x-3">
                      <div className={`flex items-center space-x-2 px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(scan.status)}`}>
                        {getStatusIcon(scan.status)}
                        <span className="capitalize">{scan.status}</span>
                      </div>
                      <div>
                        <p className="font-medium text-gray-900">{scan.projectName}</p>
                        <p className="text-sm text-gray-600">{scan.timestamp}</p>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className="text-sm font-medium">{scan.vulnerabilities} vulnerabilities</p>
                      <p className="text-sm text-gray-600">{scan.duration}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'vulnerabilities' && (
          <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Vulnerability Analysis</h3>
            <p className="text-gray-600">Detailed vulnerability breakdown and analysis will be displayed here.</p>
          </div>
        )}

        {activeTab === 'scans' && (
          <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Scan History</h3>
            <p className="text-gray-600">Complete scan history and management will be displayed here.</p>
          </div>
        )}

        {activeTab === 'rules' && (
          <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Detection Rules</h3>
            <p className="text-gray-600">OWASP Top 10 and custom detection rules will be displayed here.</p>
          </div>
        )}

        {activeTab === 'auto-fix' && (
          <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Auto-Fix Recommendations</h3>
            <p className="text-gray-600">Automated fix suggestions and code patches will be displayed here.</p>
          </div>
        )}

        {activeTab === 'reports' && (
          <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Reports</h3>
            <p className="text-gray-600">PDF, JSON, and HTML report generation will be displayed here.</p>
          </div>
        )}

        {activeTab === 'settings' && (
          <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">SAST Settings</h3>
            <p className="text-gray-600">Configuration options and scan settings will be displayed here.</p>
          </div>
        )}
      </motion.div>
    </div>
  );
};

export default SAST; 