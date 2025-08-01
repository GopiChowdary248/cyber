import React from 'react';
import { 
  ShieldCheckIcon, 
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  CloudIcon,
  ServerIcon,
  LockClosedIcon,
  UserGroupIcon,
  EyeIcon
} from '@heroicons/react/24/outline';

interface CloudSecurityMetrics {
  totalResources: number;
  misconfigurations: number;
  criticalFindings: number;
  complianceScore: number;
  lastScan: string;
  providers: {
    aws: { status: string; resources: number; issues: number };
    azure: { status: string; resources: number; issues: number };
    gcp: { status: string; resources: number; issues: number };
  };
}

interface CloudSecurityDashboardProps {
  metrics: CloudSecurityMetrics;
  onScanRequest: () => void;
  isLoading?: boolean;
}

const CloudSecurityDashboard: React.FC<CloudSecurityDashboardProps> = ({
  metrics,
  onScanRequest,
  isLoading = false
}) => {
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy': return 'text-green-500 bg-green-100';
      case 'warning': return 'text-yellow-500 bg-yellow-100';
      case 'critical': return 'text-red-500 bg-red-100';
      default: return 'text-gray-500 bg-gray-100';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy': return <CheckCircleIcon className="w-5 h-5 text-green-500" />;
      case 'warning': return <ExclamationTriangleIcon className="w-5 h-5 text-yellow-500" />;
      case 'critical': return <XCircleIcon className="w-5 h-5 text-red-500" />;
      default: return <ExclamationTriangleIcon className="w-5 h-5 text-gray-500" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-white">Cloud Security Overview</h2>
          <p className="text-gray-400">Multi-cloud security monitoring and compliance status</p>
        </div>
        <button
          onClick={onScanRequest}
          disabled={isLoading}
          className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors"
        >
          <ShieldCheckIcon className="w-5 h-5 mr-2" />
          {isLoading ? 'Scanning...' : 'Run Security Scan'}
        </button>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="card-cyber p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Total Resources</p>
              <p className="text-2xl font-bold text-white">{metrics.totalResources}</p>
            </div>
            <CloudIcon className="w-8 h-8 text-blue-500" />
          </div>
        </div>

        <div className="card-cyber p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Misconfigurations</p>
              <p className="text-2xl font-bold text-white">{metrics.misconfigurations}</p>
            </div>
            <ExclamationTriangleIcon className="w-8 h-8 text-yellow-500" />
          </div>
        </div>

        <div className="card-cyber p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Critical Findings</p>
              <p className="text-2xl font-bold text-white">{metrics.criticalFindings}</p>
            </div>
            <XCircleIcon className="w-8 h-8 text-red-500" />
          </div>
        </div>

        <div className="card-cyber p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Compliance Score</p>
              <p className="text-2xl font-bold text-white">{metrics.complianceScore}%</p>
            </div>
            <ShieldCheckIcon className="w-8 h-8 text-green-500" />
          </div>
        </div>
      </div>

      {/* Cloud Provider Status */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {Object.entries(metrics.providers).map(([provider, data]) => (
          <div key={provider} className="card-cyber p-6">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center">
                <span className="text-2xl mr-3">
                  {provider === 'aws' ? '☁️' : provider === 'azure' ? '☁️' : '☁️'}
                </span>
                <h3 className="text-xl font-semibold text-white capitalize">{provider}</h3>
              </div>
              {getStatusIcon(data.status)}
            </div>
            <div className="space-y-3">
              <div className="flex justify-between">
                <span className="text-gray-400">Resources</span>
                <span className="text-white font-medium">{data.resources}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Issues</span>
                <span className="text-white font-medium">{data.issues}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Status</span>
                <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(data.status)}`}>
                  {data.status}
                </span>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Security Categories */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="card-cyber p-6">
          <div className="flex items-center mb-4">
            <ShieldCheckIcon className="w-6 h-6 text-blue-500 mr-3" />
            <h3 className="text-lg font-semibold text-white">CSPM</h3>
          </div>
          <p className="text-gray-400 text-sm mb-3">Cloud Security Posture Management</p>
          <div className="flex items-center justify-between">
            <span className="text-green-400 text-sm">Active</span>
            <CheckCircleIcon className="w-5 h-5 text-green-400" />
          </div>
        </div>

        <div className="card-cyber p-6">
          <div className="flex items-center mb-4">
            <ServerIcon className="w-6 h-6 text-green-500 mr-3" />
            <h3 className="text-lg font-semibold text-white">CWP</h3>
          </div>
          <p className="text-gray-400 text-sm mb-3">Cloud Workload Protection</p>
          <div className="flex items-center justify-between">
            <span className="text-green-400 text-sm">Protected</span>
            <CheckCircleIcon className="w-5 h-5 text-green-400" />
          </div>
        </div>

        <div className="card-cyber p-6">
          <div className="flex items-center mb-4">
            <LockClosedIcon className="w-6 h-6 text-purple-500 mr-3" />
            <h3 className="text-lg font-semibold text-white">CASB</h3>
          </div>
          <p className="text-gray-400 text-sm mb-3">Cloud Access Security Broker</p>
          <div className="flex items-center justify-between">
            <span className="text-green-400 text-sm">Secured</span>
            <CheckCircleIcon className="w-5 h-5 text-green-400" />
          </div>
        </div>

        <div className="card-cyber p-6">
          <div className="flex items-center mb-4">
            <UserGroupIcon className="w-6 h-6 text-orange-500 mr-3" />
            <h3 className="text-lg font-semibold text-white">CIEM</h3>
          </div>
          <p className="text-gray-400 text-sm mb-3">Cloud Infrastructure Entitlement Management</p>
          <div className="flex items-center justify-between">
            <span className="text-yellow-400 text-sm">Monitoring</span>
            <ExclamationTriangleIcon className="w-5 h-5 text-yellow-400" />
          </div>
        </div>
      </div>

      {/* Last Scan Info */}
      <div className="text-center text-gray-400 text-sm">
        Last security scan: {new Date(metrics.lastScan).toLocaleString()}
      </div>
    </div>
  );
};

export default CloudSecurityDashboard; 