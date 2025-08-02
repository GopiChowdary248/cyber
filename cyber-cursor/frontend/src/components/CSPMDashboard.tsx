import React, { useState, useEffect } from 'react';
import { 
  ShieldCheckIcon, 
  ExclamationTriangleIcon, 
  CheckCircleIcon,
  ClockIcon,
  ChartBarIcon,
  CogIcon,
  ArrowPathIcon
} from '@heroicons/react/24/outline';

interface CSPMProvider {
  name: string;
  status: string;
  last_scan: string;
  vulnerabilities_found: number;
  compliance_score: number;
  misconfigurations: number;
  recommendations: number;
}

interface CSPMDashboardProps {
  providerName: string;
}

const CSPMDashboard: React.FC<CSPMDashboardProps> = ({ providerName }) => {
  const [provider, setProvider] = useState<CSPMProvider | null>(null);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);

  useEffect(() => {
    fetchProviderData();
  }, [providerName]);

  const fetchProviderData = async () => {
    try {
      setLoading(true);
      const response = await fetch(`/api/v1/cloud-security/cspm/${encodeURIComponent(providerName)}`);
      if (response.ok) {
        const data = await response.json();
        setProvider(data);
      } else {
        console.error('Failed to fetch CSPM provider data');
      }
    } catch (error) {
      console.error('Error fetching CSPM provider data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleScan = async () => {
    try {
      setScanning(true);
      const response = await fetch(`/api/v1/cloud-security/cspm/${encodeURIComponent(providerName)}/scan`, {
        method: 'POST',
      });
      if (response.ok) {
        // Refresh data after scan
        setTimeout(() => {
          fetchProviderData();
          setScanning(false);
        }, 2000);
      }
    } catch (error) {
      console.error('Error triggering scan:', error);
      setScanning(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'active':
        return 'text-green-500';
      case 'inactive':
        return 'text-red-500';
      case 'warning':
        return 'text-yellow-500';
      default:
        return 'text-gray-500';
    }
  };

  const getComplianceColor = (score: number) => {
    if (score >= 90) return 'text-green-500';
    if (score >= 70) return 'text-yellow-500';
    return 'text-red-500';
  };

  if (loading) {
    return (
      <div className="p-6">
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
        </div>
      </div>
    );
  }

  if (!provider) {
    return (
      <div className="p-6">
        <div className="bg-red-900/20 border border-red-700/50 rounded-lg p-6">
          <p className="text-red-400">Failed to load provider data for {providerName}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white mb-2">{provider.name}</h1>
          <p className="text-gray-400">Cloud Security Posture Management</p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="flex items-center">
            <div className={`w-3 h-3 rounded-full mr-2 ${getStatusColor(provider.status).replace('text-', 'bg-')}`}></div>
            <span className={`text-sm font-medium ${getStatusColor(provider.status)}`}>
              {provider.status.toUpperCase()}
            </span>
          </div>
          <button
            onClick={handleScan}
            disabled={scanning}
            className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <ArrowPathIcon className={`h-4 w-4 mr-2 ${scanning ? 'animate-spin' : ''}`} />
            {scanning ? 'Scanning...' : 'Start Scan'}
          </button>
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Vulnerabilities</p>
              <p className="text-2xl font-bold text-red-500">{provider.vulnerabilities_found}</p>
            </div>
            <ExclamationTriangleIcon className="h-8 w-8 text-red-500" />
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Compliance Score</p>
              <p className={`text-2xl font-bold ${getComplianceColor(provider.compliance_score)}`}>
                {provider.compliance_score}%
              </p>
            </div>
            <ChartBarIcon className="h-8 w-8 text-blue-500" />
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Misconfigurations</p>
              <p className="text-2xl font-bold text-yellow-500">{provider.misconfigurations}</p>
            </div>
            <CogIcon className="h-8 w-8 text-yellow-500" />
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Recommendations</p>
              <p className="text-2xl font-bold text-green-500">{provider.recommendations}</p>
            </div>
            <CheckCircleIcon className="h-8 w-8 text-green-500" />
          </div>
        </div>
      </div>

      {/* Details Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Last Scan Information */}
        <div className="bg-gray-800 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
            <ClockIcon className="h-5 w-5 mr-2 text-blue-400" />
            Last Scan Information
          </h3>
          <div className="space-y-3">
            <div className="flex justify-between items-center">
              <span className="text-gray-400">Last Scan:</span>
              <span className="text-white">{new Date(provider.last_scan).toLocaleString()}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-gray-400">Status:</span>
              <span className={`font-medium ${getStatusColor(provider.status)}`}>
                {provider.status.toUpperCase()}
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-gray-400">Provider:</span>
              <span className="text-white">{provider.name}</span>
            </div>
          </div>
        </div>

        {/* Compliance Breakdown */}
        <div className="bg-gray-800 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
            <ShieldCheckIcon className="h-5 w-5 mr-2 text-green-400" />
            Compliance Breakdown
          </h3>
          <div className="space-y-4">
            <div>
              <div className="flex justify-between items-center mb-2">
                <span className="text-gray-400">Overall Score</span>
                <span className={`font-medium ${getComplianceColor(provider.compliance_score)}`}>
                  {provider.compliance_score}%
                </span>
              </div>
              <div className="w-full bg-gray-700 rounded-full h-2">
                <div 
                  className={`h-2 rounded-full ${
                    provider.compliance_score >= 90 ? 'bg-green-500' :
                    provider.compliance_score >= 70 ? 'bg-yellow-500' : 'bg-red-500'
                  }`}
                  style={{ width: `${provider.compliance_score}%` }}
                ></div>
              </div>
            </div>
            
            <div className="grid grid-cols-2 gap-4">
              <div className="text-center">
                <p className="text-2xl font-bold text-red-500">{provider.vulnerabilities_found}</p>
                <p className="text-sm text-gray-400">Vulnerabilities</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-yellow-500">{provider.misconfigurations}</p>
                <p className="text-sm text-gray-400">Misconfigurations</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Actions Section */}
      <div className="mt-8 bg-gray-800 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Quick Actions</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <button
            onClick={handleScan}
            disabled={scanning}
            className="flex items-center justify-center p-4 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <ArrowPathIcon className={`h-5 w-5 mr-2 ${scanning ? 'animate-spin' : ''}`} />
            {scanning ? 'Scanning...' : 'Run Security Scan'}
          </button>
          
          <button className="flex items-center justify-center p-4 bg-gray-700 text-white rounded-lg hover:bg-gray-600">
            <ChartBarIcon className="h-5 w-5 mr-2" />
            View Reports
          </button>
          
          <button className="flex items-center justify-center p-4 bg-gray-700 text-white rounded-lg hover:bg-gray-600">
            <CogIcon className="h-5 w-5 mr-2" />
            Configure Settings
          </button>
        </div>
      </div>
    </div>
  );
};

export default CSPMDashboard; 