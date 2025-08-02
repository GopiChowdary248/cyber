import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  DocumentTextIcon, 
  ShieldCheckIcon, 
  BellIcon, 
  UserCircleIcon, 
  ComputerDesktopIcon,
  ChartBarIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  CogIcon,
  LockClosedIcon,
  ServerIcon,
  ExclamationCircleIcon,
  ClockIcon,
  DocumentDuplicateIcon
} from '@heroicons/react/24/outline';

interface DataSecurityData {
  overview: {
    totalFiles: number;
    encryptedFiles: number;
    dlpViolations: number;
    securityScore: number;
  };
  encryption: {
    totalEncrypted: number;
    encryptionAlgorithms: number;
    keyRotation: number;
    status: 'healthy' | 'warning' | 'critical';
  };
  dlp: {
    totalPolicies: number;
    activePolicies: number;
    violationsToday: number;
    status: 'healthy' | 'warning' | 'critical';
  };
  databaseSecurity: {
    totalDatabases: number;
    monitoredQueries: number;
    suspiciousActivities: number;
    status: 'healthy' | 'warning' | 'critical';
  };
  compliance: {
    totalReports: number;
    complianceScore: number;
    auditLogs: number;
    status: 'healthy' | 'warning' | 'critical';
  };
  monitoring: {
    totalEvents: number;
    criticalEvents: number;
    realTimeAlerts: number;
    status: 'healthy' | 'warning' | 'critical';
  };
}

const DataSecurity: React.FC = () => {
  const [data, setData] = useState<DataSecurityData | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    // Simulate API call
    const fetchData = async () => {
      try {
        // Mock data - in real app, this would be an API call
        const mockData: DataSecurityData = {
          overview: {
            totalFiles: 15420,
            encryptedFiles: 14850,
            dlpViolations: 23,
            securityScore: 97
          },
          encryption: {
            totalEncrypted: 14850,
            encryptionAlgorithms: 3,
            keyRotation: 45,
            status: 'healthy'
          },
          dlp: {
            totalPolicies: 89,
            activePolicies: 85,
            violationsToday: 5,
            status: 'warning'
          },
          databaseSecurity: {
            totalDatabases: 12,
            monitoredQueries: 45670,
            suspiciousActivities: 8,
            status: 'healthy'
          },
          compliance: {
            totalReports: 156,
            complianceScore: 94,
            auditLogs: 23450,
            status: 'healthy'
          },
          monitoring: {
            totalEvents: 67890,
            criticalEvents: 12,
            realTimeAlerts: 45,
            status: 'warning'
          }
        };
        
        setData(mockData);
      } catch (error) {
        console.error('Error fetching data security data:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy':
        return 'text-green-500 bg-green-100';
      case 'warning':
        return 'text-yellow-500 bg-yellow-100';
      case 'critical':
        return 'text-red-500 bg-red-100';
      default:
        return 'text-gray-500 bg-gray-100';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy':
        return <CheckCircleIcon className="w-5 h-5" />;
      case 'warning':
        return <ExclamationTriangleIcon className="w-5 h-5" />;
      case 'critical':
        return <XCircleIcon className="w-5 h-5" />;
      default:
        return <ChartBarIcon className="w-5 h-5" />;
    }
  };

  const tabs = [
    { id: 'overview', label: 'Overview', icon: <ChartBarIcon className="w-4 h-4" /> },
    { id: 'encryption', label: 'Encryption', icon: <LockClosedIcon className="w-4 h-4" /> },
    { id: 'dlp', label: 'DLP', icon: <ShieldCheckIcon className="w-4 h-4" /> },
    { id: 'database-security', label: 'Database Security', icon: <ServerIcon className="w-4 h-4" /> },
    { id: 'compliance', label: 'Compliance', icon: <DocumentTextIcon className="w-4 h-4" /> },
    { id: 'monitoring', label: 'Monitoring', icon: <BellIcon className="w-4 h-4" /> }
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
          <p className="text-gray-600">Unable to load data security data</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Data Security</h1>
          <p className="text-gray-600">Protect sensitive data with encryption, DLP, and database monitoring</p>
        </div>
        <div className="flex items-center space-x-2">
          <DocumentTextIcon className="w-8 h-8 text-blue-600" />
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center space-x-2 py-2 px-1 border-b-2 font-medium text-sm ${
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
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Total Files</p>
                  <p className="text-2xl font-bold text-gray-900">{data.overview.totalFiles.toLocaleString()}</p>
                </div>
                <DocumentTextIcon className="w-8 h-8 text-blue-600" />
              </div>
            </div>
            
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Encrypted Files</p>
                  <p className="text-2xl font-bold text-gray-900">{data.overview.encryptedFiles.toLocaleString()}</p>
                </div>
                <LockClosedIcon className="w-8 h-8 text-green-600" />
              </div>
            </div>
            
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">DLP Violations</p>
                  <p className="text-2xl font-bold text-gray-900">{data.overview.dlpViolations}</p>
                </div>
                <ShieldCheckIcon className="w-8 h-8 text-red-600" />
              </div>
            </div>
            
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Security Score</p>
                  <p className="text-2xl font-bold text-gray-900">{data.overview.securityScore}%</p>
                </div>
                <ChartBarIcon className="w-8 h-8 text-purple-600" />
              </div>
            </div>
          </div>
        )}

        {activeTab === 'encryption' && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gray-900">Encryption Status</h3>
                <div className={`flex items-center space-x-2 px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(data.encryption.status)}`}>
                  {getStatusIcon(data.encryption.status)}
                  <span className="capitalize">{data.encryption.status}</span>
                </div>
              </div>
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-gray-600">Total Encrypted</p>
                  <p className="text-xl font-semibold text-gray-900">{data.encryption.totalEncrypted.toLocaleString()}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Encryption Algorithms</p>
                  <p className="text-xl font-semibold text-gray-900">{data.encryption.encryptionAlgorithms}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Key Rotation (days)</p>
                  <p className="text-xl font-semibold text-gray-900">{data.encryption.keyRotation}</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'dlp' && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gray-900">DLP Status</h3>
                <div className={`flex items-center space-x-2 px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(data.dlp.status)}`}>
                  {getStatusIcon(data.dlp.status)}
                  <span className="capitalize">{data.dlp.status}</span>
                </div>
              </div>
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-gray-600">Total Policies</p>
                  <p className="text-xl font-semibold text-gray-900">{data.dlp.totalPolicies}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Active Policies</p>
                  <p className="text-xl font-semibold text-gray-900">{data.dlp.activePolicies}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Violations Today</p>
                  <p className="text-xl font-semibold text-red-600">{data.dlp.violationsToday}</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'database-security' && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gray-900">Database Security Status</h3>
                <div className={`flex items-center space-x-2 px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(data.databaseSecurity.status)}`}>
                  {getStatusIcon(data.databaseSecurity.status)}
                  <span className="capitalize">{data.databaseSecurity.status}</span>
                </div>
              </div>
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-gray-600">Total Databases</p>
                  <p className="text-xl font-semibold text-gray-900">{data.databaseSecurity.totalDatabases}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Monitored Queries</p>
                  <p className="text-xl font-semibold text-gray-900">{data.databaseSecurity.monitoredQueries.toLocaleString()}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Suspicious Activities</p>
                  <p className="text-xl font-semibold text-red-600">{data.databaseSecurity.suspiciousActivities}</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'compliance' && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gray-900">Compliance Status</h3>
                <div className={`flex items-center space-x-2 px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(data.compliance.status)}`}>
                  {getStatusIcon(data.compliance.status)}
                  <span className="capitalize">{data.compliance.status}</span>
                </div>
              </div>
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-gray-600">Total Reports</p>
                  <p className="text-xl font-semibold text-gray-900">{data.compliance.totalReports}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Compliance Score</p>
                  <p className="text-xl font-semibold text-gray-900">{data.compliance.complianceScore}%</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Audit Logs</p>
                  <p className="text-xl font-semibold text-gray-900">{data.compliance.auditLogs.toLocaleString()}</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'monitoring' && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gray-900">Monitoring Status</h3>
                <div className={`flex items-center space-x-2 px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(data.monitoring.status)}`}>
                  {getStatusIcon(data.monitoring.status)}
                  <span className="capitalize">{data.monitoring.status}</span>
                </div>
              </div>
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-gray-600">Total Events</p>
                  <p className="text-xl font-semibold text-gray-900">{data.monitoring.totalEvents.toLocaleString()}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Critical Events</p>
                  <p className="text-xl font-semibold text-red-600">{data.monitoring.criticalEvents}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Real-time Alerts</p>
                  <p className="text-xl font-semibold text-blue-600">{data.monitoring.realTimeAlerts}</p>
                </div>
              </div>
            </div>
          </div>
        )}
      </motion.div>
    </div>
  );
};

export default DataSecurity; 