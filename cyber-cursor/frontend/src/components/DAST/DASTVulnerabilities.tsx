import React, { useState, useEffect } from 'react';
import { 
  Search, 
  Filter, 
  Eye, 
  Download,
  AlertTriangle,
  AlertCircle,
  Info,
  CheckCircle,
  RefreshCw,
  ExternalLink
} from 'lucide-react';

interface DASTVulnerability {
  id: string;
  project_id: string;
  project_name: string;
  scan_id: string;
  severity: 'high' | 'medium' | 'low' | 'info';
  category: string;
  title: string;
  description: string;
  url: string;
  parameter?: string;
  payload?: string;
  cwe_id?: string;
  cvss_score?: number;
  status: string;
  discovered_at: string;
  remediation?: string;
}

const API_BASE_URL = '/api/v1/dast';

const DASTVulnerabilities: React.FC = () => {
  const [vulnerabilities, setVulnerabilities] = useState<DASTVulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [selectedVuln, setSelectedVuln] = useState<DASTVulnerability | null>(null);

  const fetchVulnerabilities = async () => {
    try {
      const token = localStorage.getItem('token') || '';
      const headers = {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      };

      const response = await fetch(`${API_BASE_URL}/vulnerabilities`, { headers });
      if (response.ok) {
        const data = await response.json();
        setVulnerabilities(data.vulnerabilities || []);
      }
    } catch (error) {
      console.error('Error fetching vulnerabilities:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchVulnerabilities();
  }, []);

  const onRefresh = () => {
    setRefreshing(true);
    fetchVulnerabilities().finally(() => setRefreshing(false));
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'high':
        return 'text-red-600 bg-red-100';
      case 'medium':
        return 'text-yellow-600 bg-yellow-100';
      case 'low':
        return 'text-blue-600 bg-blue-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'high':
        return <AlertTriangle className="w-4 h-4" />;
      case 'medium':
        return <AlertCircle className="w-4 h-4" />;
      case 'low':
        return <Info className="w-4 h-4" />;
      default:
        return <Info className="w-4 h-4" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'open':
        return 'text-red-600 bg-red-100';
      case 'fixed':
        return 'text-green-600 bg-green-100';
      case 'in_progress':
        return 'text-yellow-600 bg-yellow-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'open':
        return <AlertTriangle className="w-4 h-4" />;
      case 'fixed':
        return <CheckCircle className="w-4 h-4" />;
      case 'in_progress':
        return <Info className="w-4 h-4" />;
      default:
        return <Info className="w-4 h-4" />;
    }
  };

  const filteredVulnerabilities = vulnerabilities.filter(vuln => {
    const matchesSearch = vuln.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         vuln.category.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         vuln.url.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesSeverity = severityFilter === 'all' || vuln.severity === severityFilter;
    const matchesStatus = statusFilter === 'all' || vuln.status === statusFilter;
    return matchesSearch && matchesSeverity && matchesStatus;
  });

  const vulnerabilityStats = {
    total: vulnerabilities.length,
    high: vulnerabilities.filter(v => v.severity === 'high').length,
    medium: vulnerabilities.filter(v => v.severity === 'medium').length,
    low: vulnerabilities.filter(v => v.severity === 'low').length,
    open: vulnerabilities.filter(v => v.status === 'open').length,
    fixed: vulnerabilities.filter(v => v.status === 'fixed').length,
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-gray-900 mb-2">
                DAST Vulnerabilities
              </h1>
              <p className="text-gray-600">
                Review and manage security vulnerabilities discovered by DAST scans
              </p>
            </div>
            <div className="flex space-x-3">
              <button
                onClick={onRefresh}
                disabled={refreshing}
                className="inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
              >
                <RefreshCw className={`w-4 h-4 mr-2 ${refreshing ? 'animate-spin' : ''}`} />
                Refresh
              </button>
              <button
                onClick={() => window.location.href = '/dast/vulnerabilities/export'}
                className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                <Download className="w-4 h-4 mr-2" />
                Export
              </button>
            </div>
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-2 md:grid-cols-6 gap-4 mb-8">
          <div className="bg-white rounded-lg shadow p-4">
            <div className="text-2xl font-bold text-gray-900">{vulnerabilityStats.total}</div>
            <div className="text-sm text-gray-600">Total</div>
          </div>
          <div className="bg-white rounded-lg shadow p-4">
            <div className="text-2xl font-bold text-red-600">{vulnerabilityStats.high}</div>
            <div className="text-sm text-gray-600">High</div>
          </div>
          <div className="bg-white rounded-lg shadow p-4">
            <div className="text-2xl font-bold text-yellow-600">{vulnerabilityStats.medium}</div>
            <div className="text-sm text-gray-600">Medium</div>
          </div>
          <div className="bg-white rounded-lg shadow p-4">
            <div className="text-2xl font-bold text-blue-600">{vulnerabilityStats.low}</div>
            <div className="text-sm text-gray-600">Low</div>
          </div>
          <div className="bg-white rounded-lg shadow p-4">
            <div className="text-2xl font-bold text-red-600">{vulnerabilityStats.open}</div>
            <div className="text-sm text-gray-600">Open</div>
          </div>
          <div className="bg-white rounded-lg shadow p-4">
            <div className="text-2xl font-bold text-green-600">{vulnerabilityStats.fixed}</div>
            <div className="text-sm text-gray-600">Fixed</div>
          </div>
        </div>

        {/* Filters */}
        <div className="mb-6 flex flex-col sm:flex-row gap-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
            <input
              type="text"
              placeholder="Search vulnerabilities..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          >
            <option value="all">All Severities</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          >
            <option value="all">All Status</option>
            <option value="open">Open</option>
            <option value="in_progress">In Progress</option>
            <option value="fixed">Fixed</option>
          </select>
        </div>

        {/* Vulnerabilities List */}
        {filteredVulnerabilities.length === 0 ? (
          <div className="text-center py-12">
            <AlertTriangle className="w-16 h-16 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">No vulnerabilities found</h3>
            <p className="text-gray-500">
              {searchTerm || severityFilter !== 'all' || statusFilter !== 'all' ? 'Try adjusting your filters.' : 'No vulnerabilities have been discovered yet.'}
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {filteredVulnerabilities.map((vuln) => (
              <div key={vuln.id} className="bg-white rounded-lg shadow-md hover:shadow-lg transition-shadow duration-200">
                <div className="p-6">
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex-1">
                      <div className="flex items-center space-x-3 mb-2">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(vuln.severity)}`}>
                          {getSeverityIcon(vuln.severity)}
                          <span className="ml-1 capitalize">{vuln.severity}</span>
                        </span>
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(vuln.status)}`}>
                          {getStatusIcon(vuln.status)}
                          <span className="ml-1 capitalize">{vuln.status.replace('_', ' ')}</span>
                        </span>
                        {vuln.cvss_score && (
                          <span className="text-xs text-gray-500">CVSS: {vuln.cvss_score}</span>
                        )}
                      </div>
                      <h3 className="text-lg font-semibold text-gray-900 mb-2">{vuln.title}</h3>
                      <p className="text-sm text-gray-600 mb-3">{vuln.description}</p>
                    </div>
                    <div className="flex space-x-2">
                      <button
                        onClick={() => setSelectedVuln(vuln)}
                        className="inline-flex items-center px-3 py-1.5 border border-gray-300 text-xs font-medium rounded text-gray-700 bg-white hover:bg-gray-50"
                      >
                        <Eye className="w-3 h-3 mr-1" />
                        Details
                      </button>
                      <button
                        onClick={() => window.location.href = `/dast/vulnerabilities/${vuln.id}/remediate`}
                        className="inline-flex items-center px-3 py-1.5 border border-transparent text-xs font-medium rounded text-white bg-blue-600 hover:bg-blue-700"
                      >
                        Remediate
                      </button>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="font-medium text-gray-700">Project:</span>
                      <span className="ml-2 text-gray-600">{vuln.project_name}</span>
                    </div>
                    <div>
                      <span className="font-medium text-gray-700">Category:</span>
                      <span className="ml-2 text-gray-600">{vuln.category}</span>
                    </div>
                    <div className="md:col-span-2">
                      <span className="font-medium text-gray-700">URL:</span>
                      <span className="ml-2 text-gray-600 font-mono text-xs break-all">{vuln.url}</span>
                    </div>
                    {vuln.parameter && (
                      <div>
                        <span className="font-medium text-gray-700">Parameter:</span>
                        <span className="ml-2 text-gray-600 font-mono text-xs">{vuln.parameter}</span>
                      </div>
                    )}
                    {vuln.cwe_id && (
                      <div>
                        <span className="font-medium text-gray-700">CWE ID:</span>
                        <span className="ml-2 text-gray-600">{vuln.cwe_id}</span>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Vulnerability Details Modal */}
        {selectedVuln && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-lg p-6 w-full max-w-4xl max-h-[90vh] overflow-y-auto">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-xl font-semibold">Vulnerability Details</h2>
                <button
                  onClick={() => setSelectedVuln(null)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  ×
                </button>
              </div>

              <div className="space-y-6">
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-2">{selectedVuln.title}</h3>
                  <div className="flex items-center space-x-3 mb-4">
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(selectedVuln.severity)}`}>
                      {getSeverityIcon(selectedVuln.severity)}
                      <span className="ml-1 capitalize">{selectedVuln.severity}</span>
                    </span>
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(selectedVuln.status)}`}>
                      {getStatusIcon(selectedVuln.status)}
                      <span className="ml-1 capitalize">{selectedVuln.status.replace('_', ' ')}</span>
                    </span>
                  </div>
                  <p className="text-gray-700">{selectedVuln.description}</p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <h4 className="font-semibold text-gray-900 mb-3">Technical Details</h4>
                    <dl className="space-y-2">
                      <div>
                        <dt className="text-sm font-medium text-gray-700">Project</dt>
                        <dd className="text-sm text-gray-900">{selectedVuln.project_name}</dd>
                      </div>
                      <div>
                        <dt className="text-sm font-medium text-gray-700">Category</dt>
                        <dd className="text-sm text-gray-900">{selectedVuln.category}</dd>
                      </div>
                      <div>
                        <dt className="text-sm font-medium text-gray-700">URL</dt>
                        <dd className="text-sm text-gray-900 font-mono break-all">{selectedVuln.url}</dd>
                      </div>
                      {selectedVuln.parameter && (
                        <div>
                          <dt className="text-sm font-medium text-gray-700">Parameter</dt>
                          <dd className="text-sm text-gray-900 font-mono">{selectedVuln.parameter}</dd>
                        </div>
                      )}
                      {selectedVuln.cwe_id && (
                        <div>
                          <dt className="text-sm font-medium text-gray-700">CWE ID</dt>
                          <dd className="text-sm text-gray-900">{selectedVuln.cwe_id}</dd>
                        </div>
                      )}
                      {selectedVuln.cvss_score && (
                        <div>
                          <dt className="text-sm font-medium text-gray-700">CVSS Score</dt>
                          <dd className="text-sm text-gray-900">{selectedVuln.cvss_score}</dd>
                        </div>
                      )}
                    </dl>
                  </div>

                  <div>
                    <h4 className="font-semibold text-gray-900 mb-3">Additional Information</h4>
                    {selectedVuln.payload && (
                      <div className="mb-4">
                        <dt className="text-sm font-medium text-gray-700 mb-1">Payload</dt>
                        <dd className="text-sm text-gray-900 font-mono bg-gray-100 p-2 rounded break-all">{selectedVuln.payload}</dd>
                      </div>
                    )}
                    {selectedVuln.remediation && (
                      <div>
                        <dt className="text-sm font-medium text-gray-700 mb-1">Remediation</dt>
                        <dd className="text-sm text-gray-900">{selectedVuln.remediation}</dd>
                      </div>
                    )}
                  </div>
                </div>

                <div className="flex justify-end space-x-3 pt-4 border-t">
                  <button
                    onClick={() => setSelectedVuln(null)}
                    className="px-4 py-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50"
                  >
                    Close
                  </button>
                  <button
                    onClick={() => window.location.href = `/dast/vulnerabilities/${selectedVuln.id}/remediate`}
                    className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
                  >
                    Remediate
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default DASTVulnerabilities; 