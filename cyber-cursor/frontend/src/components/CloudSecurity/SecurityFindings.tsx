import React, { useState, useEffect } from 'react';
import { 
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  ClockIcon,
  FunnelIcon
} from '@heroicons/react/24/outline';
import { cloudSecurityService } from '../../services/cloudSecurityService';

interface SecurityFindingsProps {}

interface SecurityFinding {
  id: string;
  title: string;
  description: string;
  severity: string;
  provider: string;
  resource_id: string;
  resource_type: string;
  region: string;
  status: string;
  created_at: string;
  updated_at: string;
  remediation_steps: string;
}

const SecurityFindings: React.FC<SecurityFindingsProps> = () => {
  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<string>('');
  const [filterProvider, setFilterProvider] = useState<string>('');
  const [filterStatus, setFilterStatus] = useState<string>('');

  useEffect(() => {
    fetchFindings();
  }, []);

  const fetchFindings = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await cloudSecurityService.getSecurityFindings();
      setFindings(data);
    } catch (error) {
      console.error('Error fetching security findings:', error);
      setError('Failed to load security findings. Please try again later.');
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'text-red-600 bg-red-100';
      case 'high':
        return 'text-orange-600 bg-orange-100';
      case 'medium':
        return 'text-yellow-600 bg-yellow-100';
      case 'low':
        return 'text-blue-600 bg-blue-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'open':
        return 'text-red-600 bg-red-100';
      case 'in_progress':
        return 'text-yellow-600 bg-yellow-100';
      case 'resolved':
        return 'text-green-600 bg-green-100';
      case 'false_positive':
        return 'text-gray-600 bg-gray-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const filteredFindings = findings.filter(finding => {
    if (filterSeverity && finding.severity !== filterSeverity) return false;
    if (filterProvider && finding.provider !== filterProvider) return false;
    if (filterStatus && finding.status !== filterStatus) return false;
    return true;
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Security Findings</h2>
          <p className="text-gray-600">Security issues detected across all cloud providers</p>
        </div>
        <div className="text-sm text-gray-500">
          Total: {findings.length} findings
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-lg shadow p-4">
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <FunnelIcon className="w-4 h-4 text-gray-400" />
            <span className="text-sm font-medium text-gray-700">Filters:</span>
          </div>
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="border border-gray-300 rounded-md px-3 py-1 text-sm"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select
            value={filterProvider}
            onChange={(e) => setFilterProvider(e.target.value)}
            className="border border-gray-300 rounded-md px-3 py-1 text-sm"
          >
            <option value="">All Providers</option>
            <option value="Prisma Cloud">Prisma Cloud</option>
            <option value="Dome9">Dome9</option>
            <option value="Wiz">Wiz</option>
          </select>
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="border border-gray-300 rounded-md px-3 py-1 text-sm"
          >
            <option value="">All Statuses</option>
            <option value="open">Open</option>
            <option value="in_progress">In Progress</option>
            <option value="resolved">Resolved</option>
            <option value="false_positive">False Positive</option>
          </select>
        </div>
      </div>

      {/* Findings List */}
      <div className="space-y-4">
        {filteredFindings.map((finding) => (
          <div key={finding.id} className="bg-white rounded-lg shadow p-6">
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center space-x-3 mb-2">
                  <h3 className="text-lg font-semibold text-gray-900">{finding.title}</h3>
                  <span className={`px-2 py-1 rounded-full text-xs font-medium ${getSeverityColor(finding.severity)}`}>
                    {finding.severity}
                  </span>
                  <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(finding.status)}`}>
                    {finding.status}
                  </span>
                </div>
                <p className="text-gray-600 mb-3">{finding.description}</p>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                  <div>
                    <span className="text-gray-500">Provider:</span>
                    <span className="ml-2 font-medium">{finding.provider}</span>
                  </div>
                  <div>
                    <span className="text-gray-500">Resource:</span>
                    <span className="ml-2 font-medium">{finding.resource_type}</span>
                  </div>
                  <div>
                    <span className="text-gray-500">Region:</span>
                    <span className="ml-2 font-medium">{finding.region}</span>
                  </div>
                </div>
                <div className="mt-3">
                  <span className="text-gray-500 text-sm">Remediation:</span>
                  <p className="text-sm text-gray-700 mt-1 whitespace-pre-line">{finding.remediation_steps}</p>
                </div>
              </div>
              <div className="flex items-center space-x-2 text-xs text-gray-500">
                <ClockIcon className="w-4 h-4" />
                <span>{new Date(finding.created_at).toLocaleDateString()}</span>
              </div>
            </div>
          </div>
        ))}
      </div>

      {filteredFindings.length === 0 && (
        <div className="text-center py-12">
          <CheckCircleIcon className="w-12 h-12 text-green-500 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">No Findings</h3>
          <p className="text-gray-600">No security findings match the current filters.</p>
        </div>
      )}
    </div>
  );
};

export default SecurityFindings; 