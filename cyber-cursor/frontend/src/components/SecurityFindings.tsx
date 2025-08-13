import React, { useState, useEffect, useCallback } from 'react';
import {
  ExclamationTriangleIcon,
  MagnifyingGlassIcon,
  DocumentTextIcon,
  ShieldCheckIcon
} from '@heroicons/react/24/outline';

interface SecurityFinding {
  id: string;
  severity: string;
  title: string;
  description: string;
  provider: string;
  category: string;
  created_at: string;
  status: string;
}

const SecurityFindings: React.FC = () => {
  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({
    severity: '',
    provider: '',
    category: '',
    status: ''
  });

  // Mock data for security findings
  const mockFindings: SecurityFinding[] = [
    {
      id: '1',
      severity: 'high',
      title: 'Unencrypted S3 Bucket Access',
      description: 'S3 bucket is publicly accessible without encryption',
      provider: 'AWS',
      category: 'Data Protection',
      created_at: '2024-01-15T10:30:00Z',
      status: 'open'
    },
    {
      id: '2',
      severity: 'medium',
      title: 'Weak IAM Policy',
      description: 'IAM user has excessive permissions',
      provider: 'AWS',
      category: 'Access Control',
      created_at: '2024-01-14T15:45:00Z',
      status: 'in_progress'
    },
    {
      id: '3',
      severity: 'low',
      title: 'Outdated SSL Certificate',
      description: 'SSL certificate expires in 30 days',
      provider: 'Azure',
      category: 'Network Security',
      created_at: '2024-01-13T09:20:00Z',
      status: 'resolved'
    }
  ];

  const fetchFindings = useCallback(async () => {
    try {
      setLoading(true);
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000));
      setFindings(mockFindings);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching findings:', error);
      setLoading(false);
    }
  }, [mockFindings]);

  useEffect(() => {
    fetchFindings();
  }, [fetchFindings]);

  const handleFilterChange = (key: string, value: string) => {
    setFilters(prev => ({ ...prev, [key]: value }));
  };

  const applyFilters = () => {
    fetchFindings();
  };

  const clearFilters = () => {
    setFilters({
      severity: '',
      provider: '',
      category: '',
      status: ''
    });
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'high':
        return 'text-red-500 bg-red-900/20';
      case 'medium':
        return 'text-yellow-500 bg-yellow-900/20';
      case 'low':
        return 'text-green-500 bg-green-900/20';
      default:
        return 'text-gray-500 bg-gray-900/20';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'open':
        return 'text-red-500';
      case 'in_progress':
        return 'text-yellow-500';
      case 'resolved':
        return 'text-green-500';
      default:
        return 'text-gray-500';
    }
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

  return (
    <div className="p-6">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white mb-2">Security Findings</h1>
        <p className="text-gray-400">Monitor and manage security findings across all cloud security providers</p>
      </div>

      {/* Filters */}
      <div className="bg-gray-800 rounded-lg p-6 mb-6">
        <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
          {/* FunnelIcon removed */}
          Filters
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Severity</label>
            <select
              value={filters.severity}
              onChange={(e) => handleFilterChange('severity', e.target.value)}
              className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">All Severities</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Provider</label>
            <select
              value={filters.provider}
              onChange={(e) => handleFilterChange('provider', e.target.value)}
              className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">All Providers</option>
              <option value="Prisma Cloud">Prisma Cloud</option>
              <option value="Dome9">Dome9</option>
              <option value="Wiz">Wiz</option>
              <option value="Netskope">Netskope</option>
              <option value="McAfee MVISION">McAfee MVISION</option>
              <option value="Microsoft Defender for Cloud Apps">Microsoft Defender for Cloud Apps</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Category</label>
            <select
              value={filters.category}
              onChange={(e) => handleFilterChange('category', e.target.value)}
              className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">All Categories</option>
              <option value="CSPM">CSPM</option>
              <option value="CASB">CASB</option>
              <option value="Cloud-Native">Cloud-Native</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Status</label>
            <select
              value={filters.status}
              onChange={(e) => handleFilterChange('status', e.target.value)}
              className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">All Statuses</option>
              <option value="open">Open</option>
              <option value="in_progress">In Progress</option>
              <option value="resolved">Resolved</option>
            </select>
          </div>
        </div>

        <div className="flex space-x-4">
          <button
            onClick={applyFilters}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 flex items-center"
          >
            <MagnifyingGlassIcon className="h-4 w-4 mr-2" />
            Apply Filters
          </button>
          <button
            onClick={clearFilters}
            className="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700"
          >
            Clear Filters
          </button>
        </div>
      </div>

      {/* Findings List */}
      <div className="bg-gray-800 rounded-lg p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-semibold text-white flex items-center">
            <ExclamationTriangleIcon className="h-5 w-5 mr-2 text-red-400" />
            Security Findings ({findings.length})
          </h3>
        </div>

        {findings.length === 0 ? (
          <div className="text-center py-12">
            <ShieldCheckIcon className="h-12 w-12 text-green-500 mx-auto mb-4" />
            <p className="text-gray-400">No security findings found with the current filters.</p>
          </div>
        ) : (
          <div className="space-y-4">
            {findings.map((finding) => (
              <div key={finding.id} className="bg-gray-700 rounded-lg p-6">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center mb-2">
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${getSeverityColor(finding.severity)}`}>
                        {finding.severity.toUpperCase()}
                      </span>
                      <span className={`ml-3 px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(finding.status)}`}>
                        {finding.status.replace('_', ' ').toUpperCase()}
                      </span>
                    </div>

                    <h4 className="text-lg font-semibold text-white mb-2">{finding.title}</h4>
                    <p className="text-gray-300 mb-4">{finding.description}</p>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                      <div>
                        <span className="text-gray-400">Provider:</span>
                        <span className="text-white ml-2">{finding.provider}</span>
                      </div>
                      <div>
                        <span className="text-gray-400">Category:</span>
                        <span className="text-white ml-2">{finding.category}</span>
                      </div>
                      <div>
                        <span className="text-gray-400">Created:</span>
                        <span className="text-white ml-2">
                          {new Date(finding.created_at).toLocaleDateString()}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="ml-4 flex flex-col space-y-2">
                    <button className="px-3 py-1 bg-blue-600 text-white rounded text-sm hover:bg-blue-700">
                      View Details
                    </button>
                    <button className="px-3 py-1 bg-gray-600 text-white rounded text-sm hover:bg-gray-700">
                      Update Status
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Statistics */}
      <div className="mt-8 grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-gray-800 rounded-lg p-6 text-center">
          <p className="text-3xl font-bold text-red-500">
            {findings.filter(f => f.severity === 'high').length}
          </p>
          <p className="text-sm text-gray-400">High Severity</p>
        </div>

        <div className="bg-gray-800 rounded-lg p-6 text-center">
          <p className="text-3xl font-bold text-yellow-500">
            {findings.filter(f => f.severity === 'medium').length}
          </p>
          <p className="text-sm text-gray-400">Medium Severity</p>
        </div>

        <div className="bg-gray-800 rounded-lg p-6 text-center">
          <p className="text-3xl font-bold text-green-500">
            {findings.filter(f => f.severity === 'low').length}
          </p>
          <p className="text-sm text-gray-400">Low Severity</p>
        </div>

        <div className="bg-gray-800 rounded-lg p-6 text-center">
          <p className="text-3xl font-bold text-blue-500">
            {findings.filter(f => f.status === 'open').length}
          </p>
          <p className="text-sm text-gray-400">Open Issues</p>
        </div>
      </div>
    </div>
  );
};

export default SecurityFindings; 