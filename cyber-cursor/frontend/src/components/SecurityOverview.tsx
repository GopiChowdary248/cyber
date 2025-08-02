import React, { useState, useEffect } from 'react';
import { 
  ShieldCheckIcon, 
  ExclamationTriangleIcon, 
  CheckCircleIcon,
  ChartBarIcon,
  CloudIcon,
  EyeIcon,
  ServerIcon,
  ClockIcon
} from '@heroicons/react/24/outline';

interface SecurityOverviewData {
  cspm: {
    total_providers: number;
    total_vulnerabilities: number;
    average_compliance_score: number;
  };
  casb: {
    total_providers: number;
    total_monitored_apps: number;
    total_violations: number;
  };
  cloud_native: {
    total_providers: number;
    total_protected_resources: number;
    total_active_threats: number;
  };
  findings: {
    total: number;
    by_severity: {
      high: number;
      medium: number;
      low: number;
    };
  };
}

const SecurityOverview: React.FC = () => {
  const [overviewData, setOverviewData] = useState<SecurityOverviewData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchOverviewData();
  }, []);

  const fetchOverviewData = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/v1/cloud-security/overview');
      if (response.ok) {
        const data = await response.json();
        setOverviewData(data);
      } else {
        console.error('Failed to fetch overview data');
      }
    } catch (error) {
      console.error('Error fetching overview data:', error);
    } finally {
      setLoading(false);
    }
  };

  const getComplianceColor = (score: number) => {
    if (score >= 90) return 'text-green-500';
    if (score >= 70) return 'text-yellow-500';
    return 'text-red-500';
  };

  const getThreatColor = (count: number) => {
    if (count === 0) return 'text-green-500';
    if (count <= 5) return 'text-yellow-500';
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

  if (!overviewData) {
    return (
      <div className="p-6">
        <div className="bg-red-900/20 border border-red-700/50 rounded-lg p-6">
          <p className="text-red-400">Failed to load security overview data</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white mb-2">Cloud Security Overview</h1>
        <p className="text-gray-400">Comprehensive view of your cloud security posture across all providers</p>
      </div>

      {/* Overall Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Total Providers</p>
              <p className="text-2xl font-bold text-blue-500">
                {overviewData.cspm.total_providers + overviewData.casb.total_providers + overviewData.cloud_native.total_providers}
              </p>
            </div>
            <CloudIcon className="h-8 w-8 text-blue-500" />
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Total Vulnerabilities</p>
              <p className="text-2xl font-bold text-red-500">{overviewData.cspm.total_vulnerabilities}</p>
            </div>
            <ExclamationTriangleIcon className="h-8 w-8 text-red-500" />
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Active Threats</p>
              <p className={`text-2xl font-bold ${getThreatColor(overviewData.cloud_native.total_active_threats)}`}>
                {overviewData.cloud_native.total_active_threats}
              </p>
            </div>
            <ShieldCheckIcon className="h-8 w-8 text-orange-500" />
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Security Findings</p>
              <p className="text-2xl font-bold text-yellow-500">{overviewData.findings.total}</p>
            </div>
            <ChartBarIcon className="h-8 w-8 text-yellow-500" />
          </div>
        </div>
      </div>

      {/* CSPM Overview */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        <div className="bg-gray-800 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
            <ShieldCheckIcon className="h-5 w-5 mr-2 text-blue-400" />
            CSPM Status
          </h3>
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <span className="text-gray-400">Providers:</span>
              <span className="text-white font-semibold">{overviewData.cspm.total_providers}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-gray-400">Vulnerabilities:</span>
              <span className="text-red-500 font-semibold">{overviewData.cspm.total_vulnerabilities}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-gray-400">Compliance Score:</span>
              <span className={`font-semibold ${getComplianceColor(overviewData.cspm.average_compliance_score)}`}>
                {overviewData.cspm.average_compliance_score}%
              </span>
            </div>
            <div className="w-full bg-gray-700 rounded-full h-2">
              <div 
                className={`h-2 rounded-full ${
                  overviewData.cspm.average_compliance_score >= 90 ? 'bg-green-500' :
                  overviewData.cspm.average_compliance_score >= 70 ? 'bg-yellow-500' : 'bg-red-500'
                }`}
                style={{ width: `${overviewData.cspm.average_compliance_score}%` }}
              ></div>
            </div>
          </div>
        </div>

        {/* CASB Overview */}
        <div className="bg-gray-800 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
            <EyeIcon className="h-5 w-5 mr-2 text-green-400" />
            CASB Status
          </h3>
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <span className="text-gray-400">Providers:</span>
              <span className="text-white font-semibold">{overviewData.casb.total_providers}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-gray-400">Monitored Apps:</span>
              <span className="text-blue-500 font-semibold">{overviewData.casb.total_monitored_apps}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-gray-400">Violations:</span>
              <span className="text-red-500 font-semibold">{overviewData.casb.total_violations}</span>
            </div>
            <div className="w-full bg-gray-700 rounded-full h-2">
              <div 
                className="h-2 rounded-full bg-red-500"
                style={{ 
                  width: `${Math.min(100, (overviewData.casb.total_violations / overviewData.casb.total_monitored_apps) * 100)}%` 
                }}
              ></div>
            </div>
          </div>
        </div>

        {/* Cloud-Native Overview */}
        <div className="bg-gray-800 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
            <ServerIcon className="h-5 w-5 mr-2 text-purple-400" />
            Cloud-Native Status
          </h3>
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <span className="text-gray-400">Providers:</span>
              <span className="text-white font-semibold">{overviewData.cloud_native.total_providers}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-gray-400">Protected Resources:</span>
              <span className="text-green-500 font-semibold">{overviewData.cloud_native.total_protected_resources}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-gray-400">Active Threats:</span>
              <span className={`font-semibold ${getThreatColor(overviewData.cloud_native.total_active_threats)}`}>
                {overviewData.cloud_native.total_active_threats}
              </span>
            </div>
            <div className="w-full bg-gray-700 rounded-full h-2">
              <div 
                className="h-2 rounded-full bg-green-500"
                style={{ 
                  width: `${overviewData.cloud_native.total_active_threats === 0 ? 100 : 
                    ((overviewData.cloud_native.total_protected_resources - overviewData.cloud_native.total_active_threats) / overviewData.cloud_native.total_protected_resources) * 100}%` 
                }}
              ></div>
            </div>
          </div>
        </div>
      </div>

      {/* Security Findings Breakdown */}
      <div className="bg-gray-800 rounded-lg p-6 mb-8">
        <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
          <ChartBarIcon className="h-5 w-5 mr-2 text-yellow-400" />
          Security Findings Breakdown
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <div className="text-center">
            <p className="text-3xl font-bold text-red-500">{overviewData.findings.by_severity.high}</p>
            <p className="text-sm text-gray-400">High Severity</p>
          </div>
          <div className="text-center">
            <p className="text-3xl font-bold text-yellow-500">{overviewData.findings.by_severity.medium}</p>
            <p className="text-sm text-gray-400">Medium Severity</p>
          </div>
          <div className="text-center">
            <p className="text-3xl font-bold text-green-500">{overviewData.findings.by_severity.low}</p>
            <p className="text-sm text-gray-400">Low Severity</p>
          </div>
          <div className="text-center">
            <p className="text-3xl font-bold text-blue-500">{overviewData.findings.total}</p>
            <p className="text-sm text-gray-400">Total Findings</p>
          </div>
        </div>
      </div>

      {/* Recent Activity */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
          <ClockIcon className="h-5 w-5 mr-2 text-blue-400" />
          Recent Security Activity
        </h3>
        <div className="space-y-4">
          <div className="flex items-center justify-between p-4 bg-gray-700 rounded-lg">
            <div className="flex items-center">
              <ExclamationTriangleIcon className="h-5 w-5 text-red-500 mr-3" />
              <div>
                <p className="text-white font-medium">New vulnerability detected in Prisma Cloud</p>
                <p className="text-sm text-gray-400">2 hours ago</p>
              </div>
            </div>
            <span className="text-red-500 text-sm font-medium">High</span>
          </div>
          
          <div className="flex items-center justify-between p-4 bg-gray-700 rounded-lg">
            <div className="flex items-center">
              <CheckCircleIcon className="h-5 w-5 text-green-500 mr-3" />
              <div>
                <p className="text-white font-medium">Security scan completed for AWS Shield</p>
                <p className="text-sm text-gray-400">4 hours ago</p>
              </div>
            </div>
            <span className="text-green-500 text-sm font-medium">Clear</span>
          </div>
          
          <div className="flex items-center justify-between p-4 bg-gray-700 rounded-lg">
            <div className="flex items-center">
              <EyeIcon className="h-5 w-5 text-yellow-500 mr-3" />
              <div>
                <p className="text-white font-medium">DLP violation detected in Netskope</p>
                <p className="text-sm text-gray-400">6 hours ago</p>
              </div>
            </div>
            <span className="text-yellow-500 text-sm font-medium">Medium</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SecurityOverview; 