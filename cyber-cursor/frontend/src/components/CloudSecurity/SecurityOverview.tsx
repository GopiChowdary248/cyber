import React, { useState, useEffect } from 'react';
import { 
  ShieldCheckIcon, 
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  CloudIcon,
  ChartBarIcon,
  ClockIcon,
  ArrowTrendingUpIcon
} from '@heroicons/react/24/outline';
import { cloudSecurityService } from '../../services/cloudSecurityService';

interface SecurityOverviewProps {}

interface CloudSecurityMetrics {
  total_resources: number;
  compliant_resources: number;
  non_compliant_resources: number;
  high_risk_issues: number;
  medium_risk_issues: number;
  low_risk_issues: number;
  security_score: number;
  last_scan: string;
}

const SecurityOverview: React.FC<SecurityOverviewProps> = () => {
  const [metrics, setMetrics] = useState<CloudSecurityMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchMetrics();
  }, []);

  const fetchMetrics = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await cloudSecurityService.getCloudSecurityMetrics();
      setMetrics(data);
    } catch (error) {
      console.error('Error fetching security metrics:', error);
      setError('Failed to load security metrics. Please try again later.');
    } finally {
      setLoading(false);
    }
  };

  const getSecurityScoreColor = (score: number) => {
    if (score >= 90) return 'text-green-600';
    if (score >= 70) return 'text-yellow-600';
    return 'text-red-600';
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="text-center py-12">
        <ExclamationTriangleIcon className="w-12 h-12 text-yellow-500 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-gray-900 mb-2">Unable to Load Metrics</h3>
        <p className="text-gray-600">{error}</p>
        <button 
          onClick={fetchMetrics}
          className="mt-4 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
        >
          Retry
        </button>
      </div>
    );
  }

  if (!metrics) {
    return (
      <div className="text-center py-12">
        <ExclamationTriangleIcon className="w-12 h-12 text-yellow-500 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-gray-900 mb-2">Unable to Load Metrics</h3>
        <p className="text-gray-600">Security metrics could not be loaded at this time.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Cloud Security Overview</h2>
          <p className="text-gray-600">Comprehensive view of your cloud security posture</p>
        </div>
        <div className="flex items-center space-x-2 text-sm text-gray-500">
          <ClockIcon className="w-4 h-4" />
          <span>Last updated: {new Date(metrics.last_scan).toLocaleString()}</span>
        </div>
      </div>

      {/* Security Score */}
      <div className="bg-gradient-to-r from-blue-600 to-purple-600 rounded-lg shadow-lg p-6 text-white">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold mb-2">Overall Security Score</h3>
            <p className="text-blue-100">Based on compliance, vulnerabilities, and threats</p>
          </div>
          <div className="text-right">
            <div className={`text-4xl font-bold ${getSecurityScoreColor(metrics.security_score)}`}>
              {metrics.security_score}
            </div>
            <div className="text-blue-100 text-sm">out of 100</div>
          </div>
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-600 text-sm">Total Resources</p>
              <p className="text-2xl font-bold text-gray-900">{metrics.total_resources}</p>
            </div>
            <CloudIcon className="w-8 h-8 text-blue-500" />
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-600 text-sm">Compliant Resources</p>
              <p className="text-2xl font-bold text-green-600">{metrics.compliant_resources}</p>
            </div>
            <CheckCircleIcon className="w-8 h-8 text-green-500" />
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-600 text-sm">High Risk Issues</p>
              <p className="text-2xl font-bold text-red-600">{metrics.high_risk_issues}</p>
            </div>
            <XCircleIcon className="w-8 h-8 text-red-500" />
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-600 text-sm">Medium Risk Issues</p>
              <p className="text-2xl font-bold text-orange-600">{metrics.medium_risk_issues}</p>
            </div>
            <ExclamationTriangleIcon className="w-8 h-8 text-orange-500" />
          </div>
        </div>
      </div>

      {/* Detailed Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Resource Compliance */}
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Resource Compliance</h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Compliant Resources</span>
              <div className="flex items-center">
                <span className="text-sm font-medium text-green-600 mr-2">{metrics.compliant_resources}</span>
                <div className="w-16 bg-gray-200 rounded-full h-2">
                  <div 
                    className="bg-green-500 h-2 rounded-full" 
                    style={{ width: `${(metrics.compliant_resources / metrics.total_resources) * 100}%` }}
                  ></div>
                </div>
              </div>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Non-Compliant Resources</span>
              <div className="flex items-center">
                <span className="text-sm font-medium text-red-600 mr-2">{metrics.non_compliant_resources}</span>
                <div className="w-16 bg-gray-200 rounded-full h-2">
                  <div 
                    className="bg-red-500 h-2 rounded-full" 
                    style={{ width: `${(metrics.non_compliant_resources / metrics.total_resources) * 100}%` }}
                  ></div>
                </div>
              </div>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Compliance Rate</span>
              <span className="text-sm font-medium text-gray-900">
                {Math.round((metrics.compliant_resources / metrics.total_resources) * 100)}%
              </span>
            </div>
          </div>
        </div>

        {/* Risk Distribution */}
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Risk Distribution</h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center">
                <div className="w-3 h-3 bg-red-500 rounded-full mr-3"></div>
                <span className="text-sm font-medium">High Risk</span>
              </div>
              <span className="text-sm text-gray-600">{metrics.high_risk_issues}</span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center">
                <div className="w-3 h-3 bg-orange-500 rounded-full mr-3"></div>
                <span className="text-sm font-medium">Medium Risk</span>
              </div>
              <span className="text-sm text-gray-600">{metrics.medium_risk_issues}</span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center">
                <div className="w-3 h-3 bg-blue-500 rounded-full mr-3"></div>
                <span className="text-sm font-medium">Low Risk</span>
              </div>
              <span className="text-sm text-gray-600">{metrics.low_risk_issues}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Total Issues</span>
              <span className="text-sm font-medium text-gray-900">
                {metrics.high_risk_issues + metrics.medium_risk_issues + metrics.low_risk_issues}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Quick Actions</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <button className="flex items-center justify-center p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors">
            <ShieldCheckIcon className="w-5 h-5 text-blue-500 mr-2" />
            <span className="text-sm font-medium">Run Security Scan</span>
          </button>
          <button className="flex items-center justify-center p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors">
            <ChartBarIcon className="w-5 h-5 text-green-500 mr-2" />
            <span className="text-sm font-medium">View Reports</span>
          </button>
          <button className="flex items-center justify-center p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors">
            <ArrowTrendingUpIcon className="w-5 h-5 text-purple-500 mr-2" />
            <span className="text-sm font-medium">Trend Analysis</span>
          </button>
        </div>
      </div>
    </div>
  );
};

export default SecurityOverview; 