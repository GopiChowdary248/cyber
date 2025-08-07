import React, { useState, useEffect } from 'react';
import { 
  Search, 
  Filter, 
  SortAsc, 
  SortDesc, 
  Eye, 
  Edit, 
  CheckCircle, 
  XCircle, 
  AlertTriangle,
  Clock,
  FileText,
  Code,
  Shield,
  Bug,
  Zap,
  ChevronDown,
  ChevronUp,
  Download,
  RefreshCw,
  Plus,
  Trash2
} from 'lucide-react';

interface SASTIssue {
  id: string;
  project_id: string;
  scan_id: string;
  rule_id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  type: 'VULNERABILITY' | 'BUG' | 'CODE_SMELL' | 'SECURITY_HOTSPOT';
  status: 'OPEN' | 'CONFIRMED' | 'RESOLVED' | 'CLOSED' | 'REOPENED' | 'FIXED' | 'FALSE_POSITIVE' | 'WONT_FIX';
  component: string;
  line: number;
  message: string;
  description: string;
  cwe_id?: string;
  owasp_category?: string;
  cvss_score?: number;
  effort: number;
  debt: number;
  created_at: string;
  updated_at: string;
  resolved_at?: string;
  assignee?: string;
  tags: string[];
  comments: IssueComment[];
}

interface IssueComment {
  id: string;
  issue_id: string;
  user_id: string;
  user_name: string;
  content: string;
  created_at: string;
}

interface SASTIssuesProps {
  projectId?: string;
  scanId?: string;
}

const SASTIssues: React.FC<SASTIssuesProps> = ({ projectId, scanId }) => {
  const [issues, setIssues] = useState<SASTIssue[]>([]);
  const [filteredIssues, setFilteredIssues] = useState<SASTIssue[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedIssues, setSelectedIssues] = useState<string[]>([]);
  const [showFilters, setShowFilters] = useState(false);
  const [selectedIssue, setSelectedIssue] = useState<SASTIssue | null>(null);
  const [showIssueModal, setShowIssueModal] = useState(false);
  const [showBulkActions, setShowBulkActions] = useState(false);

  // Filters
  const [filters, setFilters] = useState({
    severity: [] as string[],
    type: [] as string[],
    status: [] as string[],
    assignee: '',
    search: '',
    cwe_id: '',
    owasp_category: '',
    dateRange: {
      start: '',
      end: ''
    }
  });

  // Sorting
  const [sortConfig, setSortConfig] = useState({
    field: 'severity' as keyof SASTIssue,
    direction: 'desc' as 'asc' | 'desc'
  });

  // Pagination
  const [pagination, setPagination] = useState({
    currentPage: 1,
    itemsPerPage: 25,
    totalItems: 0
  });

  const severityColors = {
    CRITICAL: 'text-red-600 bg-red-100 border-red-200',
    HIGH: 'text-orange-600 bg-orange-100 border-orange-200',
    MEDIUM: 'text-yellow-600 bg-yellow-100 border-yellow-200',
    LOW: 'text-blue-600 bg-blue-100 border-blue-200',
    INFO: 'text-gray-600 bg-gray-100 border-gray-200'
  };

  const typeIcons = {
    VULNERABILITY: <Shield className="w-4 h-4" />,
    BUG: <Bug className="w-4 h-4" />,
    CODE_SMELL: <Code className="w-4 h-4" />,
    SECURITY_HOTSPOT: <AlertTriangle className="w-4 h-4" />
  };

  const statusColors = {
    OPEN: 'text-blue-600 bg-blue-100',
    CONFIRMED: 'text-orange-600 bg-orange-100',
    RESOLVED: 'text-green-600 bg-green-100',
    CLOSED: 'text-gray-600 bg-gray-100',
    REOPENED: 'text-red-600 bg-red-100',
    FIXED: 'text-green-600 bg-green-100',
    FALSE_POSITIVE: 'text-purple-600 bg-purple-100',
    WONT_FIX: 'text-gray-600 bg-gray-100'
  };

  useEffect(() => {
    fetchIssues();
  }, [projectId, scanId]);

  useEffect(() => {
    applyFiltersAndSorting();
  }, [issues, filters, sortConfig]);

  const fetchIssues = async () => {
    try {
      setLoading(true);
      const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000/api/v1';
      
      let url = `${API_URL}/api/v1/sast/vulnerabilities`;
      const params = new URLSearchParams();
      
      if (projectId) params.append('project_id', projectId);
      if (scanId) params.append('scan_id', scanId);
      
      if (params.toString()) {
        url += `?${params.toString()}`;
      }

      const response = await fetch(url, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token') || ''}`,
          'Content-Type': 'application/json',
        },
      });

      if (response.ok) {
        const data = await response.json();
        setIssues(data.issues || []);
        setPagination(prev => ({ ...prev, totalItems: data.total || 0 }));
      } else {
        console.error('Failed to fetch issues');
      }
    } catch (error) {
      console.error('Error fetching issues:', error);
    } finally {
      setLoading(false);
    }
  };

  const applyFiltersAndSorting = () => {
    let filtered = [...issues];

    // Apply filters
    if (filters.severity.length > 0) {
      filtered = filtered.filter(issue => filters.severity.includes(issue.severity));
    }

    if (filters.type.length > 0) {
      filtered = filtered.filter(issue => filters.type.includes(issue.type));
    }

    if (filters.status.length > 0) {
      filtered = filtered.filter(issue => filters.status.includes(issue.status));
    }

    if (filters.assignee) {
      filtered = filtered.filter(issue => 
        issue.assignee?.toLowerCase().includes(filters.assignee.toLowerCase())
      );
    }

    if (filters.search) {
      filtered = filtered.filter(issue =>
        issue.message.toLowerCase().includes(filters.search.toLowerCase()) ||
        issue.description.toLowerCase().includes(filters.search.toLowerCase()) ||
        issue.component.toLowerCase().includes(filters.search.toLowerCase())
      );
    }

    if (filters.cwe_id) {
      filtered = filtered.filter(issue => issue.cwe_id?.includes(filters.cwe_id));
    }

    if (filters.owasp_category) {
      filtered = filtered.filter(issue => issue.owasp_category?.includes(filters.owasp_category));
    }

    // Apply sorting
    filtered.sort((a, b) => {
      const aValue = a[sortConfig.field];
      const bValue = b[sortConfig.field];

      if (typeof aValue === 'string' && typeof bValue === 'string') {
        const comparison = aValue.localeCompare(bValue);
        return sortConfig.direction === 'asc' ? comparison : -comparison;
      }

      if (typeof aValue === 'number' && typeof bValue === 'number') {
        return sortConfig.direction === 'asc' ? aValue - bValue : bValue - aValue;
      }

      return 0;
    });

    setFilteredIssues(filtered);
  };

  const handleSort = (field: keyof SASTIssue) => {
    setSortConfig(prev => ({
      field,
      direction: prev.field === field && prev.direction === 'asc' ? 'desc' : 'asc'
    }));
  };

  const handleBulkAction = async (action: string) => {
    if (selectedIssues.length === 0) return;

    try {
      const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000/api/v1';
      
      const response = await fetch(`${API_URL}/api/v1/sast/issues/bulk-action`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token') || ''}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          issue_ids: selectedIssues,
          action: action
        }),
      });

      if (response.ok) {
        setSelectedIssues([]);
        fetchIssues();
      }
    } catch (error) {
      console.error('Error performing bulk action:', error);
    }
  };

  const updateIssueStatus = async (issueId: string, status: string) => {
    try {
      const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000/api/v1';
      
      const response = await fetch(`${API_URL}/api/v1/sast/issues/${issueId}`, {
        method: 'PATCH',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token') || ''}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ status }),
      });

      if (response.ok) {
        fetchIssues();
      }
    } catch (error) {
      console.error('Error updating issue status:', error);
    }
  };

  const exportIssues = async (format: 'csv' | 'json' | 'pdf') => {
    try {
      const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000/api/v1';
      
              let url = `${API_URL}/api/v1/sast/issues/export?format=${format}`;
      const params = new URLSearchParams();
      
      if (projectId) params.append('project_id', projectId);
      if (scanId) params.append('scan_id', scanId);
      
      if (params.toString()) {
        url += `&${params.toString()}`;
      }

      const response = await fetch(url, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token') || ''}`,
        },
      });

      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `sast-issues-${new Date().toISOString().split('T')[0]}.${format}`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      }
    } catch (error) {
      console.error('Error exporting issues:', error);
    }
  };

  const getSeverityScore = (severity: string) => {
    const scores = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
    return scores[severity as keyof typeof scores] || 0;
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center p-8">
        <RefreshCw className="w-8 h-8 animate-spin text-blue-600" />
        <span className="ml-2 text-gray-600">Loading issues...</span>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg shadow-lg">
      {/* Header */}
      <div className="p-6 border-b border-gray-200">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-semibold text-gray-900">SAST Issues</h2>
            <p className="text-sm text-gray-500">
              {filteredIssues.length} issues found
              {selectedIssues.length > 0 && ` • ${selectedIssues.length} selected`}
            </p>
          </div>
          
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setShowFilters(!showFilters)}
              className="flex items-center space-x-2 px-3 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-md hover:bg-gray-200"
            >
              <Filter className="w-4 h-4" />
              <span>Filters</span>
            </button>
            
            <div className="relative">
              <button
                onClick={() => setShowBulkActions(!showBulkActions)}
                disabled={selectedIssues.length === 0}
                className="flex items-center space-x-2 px-3 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700 disabled:opacity-50"
              >
                <Plus className="w-4 h-4" />
                <span>Bulk Actions</span>
                <ChevronDown className="w-4 h-4" />
              </button>
              
              {showBulkActions && (
                <div className="absolute right-0 mt-2 w-48 bg-white rounded-md shadow-lg border border-gray-200 z-10">
                  <div className="py-1">
                    <button
                      onClick={() => handleBulkAction('confirm')}
                      className="block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                    >
                      Confirm Selected
                    </button>
                    <button
                      onClick={() => handleBulkAction('resolve')}
                      className="block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                    >
                      Resolve Selected
                    </button>
                    <button
                      onClick={() => handleBulkAction('false_positive')}
                      className="block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                    >
                      Mark as False Positive
                    </button>
                    <button
                      onClick={() => handleBulkAction('wont_fix')}
                      className="block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                    >
                      Won't Fix
                    </button>
                  </div>
                </div>
              )}
            </div>
            
            <div className="relative">
              <button className="flex items-center space-x-2 px-3 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-md hover:bg-gray-200">
                <Download className="w-4 h-4" />
                <span>Export</span>
                <ChevronDown className="w-4 h-4" />
              </button>
              <div className="absolute right-0 mt-2 w-32 bg-white rounded-md shadow-lg border border-gray-200 z-10">
                <div className="py-1">
                  <button
                    onClick={() => exportIssues('csv')}
                    className="block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                  >
                    CSV
                  </button>
                  <button
                    onClick={() => exportIssues('json')}
                    className="block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                  >
                    JSON
                  </button>
                  <button
                    onClick={() => exportIssues('pdf')}
                    className="block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                  >
                    PDF
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Search Bar */}
        <div className="mt-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
            <input
              type="text"
              placeholder="Search issues by message, description, or component..."
              value={filters.search}
              onChange={(e) => setFilters(prev => ({ ...prev, search: e.target.value }))}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
        </div>
      </div>

      {/* Filters Panel */}
      {showFilters && (
        <div className="p-4 bg-gray-50 border-b border-gray-200">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Severity</label>
              <div className="space-y-2">
                {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(severity => (
                  <label key={severity} className="flex items-center">
                    <input
                      type="checkbox"
                      checked={filters.severity.includes(severity)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setFilters(prev => ({
                            ...prev,
                            severity: [...prev.severity, severity]
                          }));
                        } else {
                          setFilters(prev => ({
                            ...prev,
                            severity: prev.severity.filter(s => s !== severity)
                          }));
                        }
                      }}
                      className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                    />
                    <span className="ml-2 text-sm text-gray-700">{severity}</span>
                  </label>
                ))}
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Type</label>
              <div className="space-y-2">
                {['VULNERABILITY', 'BUG', 'CODE_SMELL', 'SECURITY_HOTSPOT'].map(type => (
                  <label key={type} className="flex items-center">
                    <input
                      type="checkbox"
                      checked={filters.type.includes(type)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setFilters(prev => ({
                            ...prev,
                            type: [...prev.type, type]
                          }));
                        } else {
                          setFilters(prev => ({
                            ...prev,
                            type: prev.type.filter(t => t !== type)
                          }));
                        }
                      }}
                      className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                    />
                    <span className="ml-2 text-sm text-gray-700">{type}</span>
                  </label>
                ))}
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Status</label>
              <div className="space-y-2">
                {['OPEN', 'CONFIRMED', 'RESOLVED', 'CLOSED', 'REOPENED', 'FIXED', 'FALSE_POSITIVE', 'WONT_FIX'].map(status => (
                  <label key={status} className="flex items-center">
                    <input
                      type="checkbox"
                      checked={filters.status.includes(status)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setFilters(prev => ({
                            ...prev,
                            status: [...prev.status, status]
                          }));
                        } else {
                          setFilters(prev => ({
                            ...prev,
                            status: prev.status.filter(s => s !== status)
                          }));
                        }
                      }}
                      className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                    />
                    <span className="ml-2 text-sm text-gray-700">{status}</span>
                  </label>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Issues Table */}
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left">
                <input
                  type="checkbox"
                  checked={selectedIssues.length === filteredIssues.length && filteredIssues.length > 0}
                  onChange={(e) => {
                    if (e.target.checked) {
                      setSelectedIssues(filteredIssues.map(issue => issue.id));
                    } else {
                      setSelectedIssues([]);
                    }
                  }}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                <button
                  onClick={() => handleSort('severity')}
                  className="flex items-center space-x-1 hover:text-gray-700"
                >
                  <span>Severity</span>
                  {sortConfig.field === 'severity' && (
                    sortConfig.direction === 'asc' ? <SortAsc className="w-3 h-3" /> : <SortDesc className="w-3 h-3" />
                  )}
                </button>
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                <button
                  onClick={() => handleSort('type')}
                  className="flex items-center space-x-1 hover:text-gray-700"
                >
                  <span>Type</span>
                  {sortConfig.field === 'type' && (
                    sortConfig.direction === 'asc' ? <SortAsc className="w-3 h-3" /> : <SortDesc className="w-3 h-3" />
                  )}
                </button>
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                <button
                  onClick={() => handleSort('message')}
                  className="flex items-center space-x-1 hover:text-gray-700"
                >
                  <span>Message</span>
                  {sortConfig.field === 'message' && (
                    sortConfig.direction === 'asc' ? <SortAsc className="w-3 h-3" /> : <SortDesc className="w-3 h-3" />
                  )}
                </button>
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                <button
                  onClick={() => handleSort('component')}
                  className="flex items-center space-x-1 hover:text-gray-700"
                >
                  <span>Component</span>
                  {sortConfig.field === 'component' && (
                    sortConfig.direction === 'asc' ? <SortAsc className="w-3 h-3" /> : <SortDesc className="w-3 h-3" />
                  )}
                </button>
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                <button
                  onClick={() => handleSort('status')}
                  className="flex items-center space-x-1 hover:text-gray-700"
                >
                  <span>Status</span>
                  {sortConfig.field === 'status' && (
                    sortConfig.direction === 'asc' ? <SortAsc className="w-3 h-3" /> : <SortDesc className="w-3 h-3" />
                  )}
                </button>
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                <button
                  onClick={() => handleSort('created_at')}
                  className="flex items-center space-x-1 hover:text-gray-700"
                >
                  <span>Created</span>
                  {sortConfig.field === 'created_at' && (
                    sortConfig.direction === 'asc' ? <SortAsc className="w-3 h-3" /> : <SortDesc className="w-3 h-3" />
                  )}
                </button>
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {filteredIssues.map((issue) => (
              <tr key={issue.id} className="hover:bg-gray-50">
                <td className="px-6 py-4 whitespace-nowrap">
                  <input
                    type="checkbox"
                    checked={selectedIssues.includes(issue.id)}
                    onChange={(e) => {
                      if (e.target.checked) {
                        setSelectedIssues(prev => [...prev, issue.id]);
                      } else {
                        setSelectedIssues(prev => prev.filter(id => id !== issue.id));
                      }
                    }}
                    className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                  />
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${severityColors[issue.severity]}`}>
                    {issue.severity}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="flex items-center space-x-2">
                    {typeIcons[issue.type]}
                    <span className="text-sm text-gray-900">{issue.type}</span>
                  </div>
                </td>
                <td className="px-6 py-4">
                  <div className="text-sm text-gray-900 max-w-md truncate" title={issue.message}>
                    {issue.message}
                  </div>
                  {issue.cwe_id && (
                    <div className="text-xs text-gray-500">CWE-{issue.cwe_id}</div>
                  )}
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="text-sm text-gray-900">
                    <FileText className="w-4 h-4 inline mr-1" />
                    {issue.component.split('/').pop()}
                  </div>
                  <div className="text-xs text-gray-500">Line {issue.line}</div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${statusColors[issue.status]}`}>
                    {issue.status}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                  {new Date(issue.created_at).toLocaleDateString()}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => {
                        setSelectedIssue(issue);
                        setShowIssueModal(true);
                      }}
                      className="text-blue-600 hover:text-blue-900"
                      title="View Details"
                    >
                      <Eye className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => updateIssueStatus(issue.id, 'CONFIRMED')}
                      className="text-orange-600 hover:text-orange-900"
                      title="Confirm"
                    >
                      <CheckCircle className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => updateIssueStatus(issue.id, 'RESOLVED')}
                      className="text-green-600 hover:text-green-900"
                      title="Resolve"
                    >
                      <CheckCircle className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => updateIssueStatus(issue.id, 'FALSE_POSITIVE')}
                      className="text-purple-600 hover:text-purple-900"
                      title="False Positive"
                    >
                      <XCircle className="w-4 h-4" />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Empty State */}
      {filteredIssues.length === 0 && !loading && (
        <div className="text-center py-12">
          <Shield className="w-12 h-12 mx-auto text-gray-400 mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">No issues found</h3>
          <p className="text-gray-500">
            {filters.search || filters.severity.length > 0 || filters.type.length > 0 || filters.status.length > 0
              ? 'Try adjusting your filters to see more results.'
              : 'No security issues have been detected in this project yet.'}
          </p>
        </div>
      )}

      {/* Issue Details Modal */}
      {showIssueModal && selectedIssue && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-4xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-semibold">Issue Details</h2>
              <button
                onClick={() => setShowIssueModal(false)}
                className="text-gray-400 hover:text-gray-600"
              >
                ×
              </button>
            </div>
            
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Severity</label>
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${severityColors[selectedIssue.severity]}`}>
                    {selectedIssue.severity}
                  </span>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Type</label>
                  <div className="flex items-center space-x-2">
                    {typeIcons[selectedIssue.type]}
                    <span>{selectedIssue.type}</span>
                  </div>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Status</label>
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${statusColors[selectedIssue.status]}`}>
                    {selectedIssue.status}
                  </span>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Line</label>
                  <span>{selectedIssue.line}</span>
                </div>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700">Message</label>
                <p className="text-sm text-gray-900">{selectedIssue.message}</p>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700">Description</label>
                <p className="text-sm text-gray-900">{selectedIssue.description}</p>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700">Component</label>
                <p className="text-sm text-gray-900 font-mono">{selectedIssue.component}</p>
              </div>
              
              {selectedIssue.cwe_id && (
                <div>
                  <label className="block text-sm font-medium text-gray-700">CWE ID</label>
                  <p className="text-sm text-gray-900">CWE-{selectedIssue.cwe_id}</p>
                </div>
              )}
              
              {selectedIssue.owasp_category && (
                <div>
                  <label className="block text-sm font-medium text-gray-700">OWASP Category</label>
                  <p className="text-sm text-gray-900">{selectedIssue.owasp_category}</p>
                </div>
              )}
              
              {selectedIssue.cvss_score && (
                <div>
                  <label className="block text-sm font-medium text-gray-700">CVSS Score</label>
                  <p className="text-sm text-gray-900">{selectedIssue.cvss_score}</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SASTIssues; 