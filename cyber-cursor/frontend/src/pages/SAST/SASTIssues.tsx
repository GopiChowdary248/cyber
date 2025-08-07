import React, { useState, useEffect } from 'react';
import { 
  Search, 
  Filter, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  XCircle,
  Eye,
  Download,
  RefreshCw,
  Settings,
  ChevronDown,
  ChevronUp,
  FileText,
  Code,
  Shield,
  Bug,
  Zap,
  Users,
  Calendar,
  BarChart3,
  MoreHorizontal,
  CheckSquare,
  Square,
  Trash2,
  Edit,
  Flag,
  Lock,
  Unlock
} from 'lucide-react';

interface SASTIssue {
  id: string;
  project_id: string;
  project_name: string;
  file_path: string;
  line_number: number;
  rule_id: string;
  rule_name: string;
  rule_category: string;
  severity: 'BLOCKER' | 'CRITICAL' | 'MAJOR' | 'MINOR' | 'INFO';
  type: 'BUG' | 'VULNERABILITY' | 'CODE_SMELL' | 'SECURITY_HOTSPOT';
  status: 'OPEN' | 'CONFIRMED' | 'RESOLVED' | 'CLOSED' | 'REOPENED';
  resolution: 'UNRESOLVED' | 'FIXED' | 'FALSE_POSITIVE' | 'WON_FIX' | 'REMOVED';
  assignee?: string;
  author: string;
  created_at: string;
  updated_at: string;
  effort: number; // minutes to fix
  debt: number; // technical debt in minutes
  message: string;
  description: string;
  cwe_id?: string;
  cvss_score?: number;
  owasp_category?: string;
  tags: string[];
  hotspot?: boolean;
}

interface SASTProject {
  id: string;
  name: string;
  key: string;
  language: string;
  last_analysis: string;
  quality_gate: 'PASSED' | 'FAILED' | 'WARN';
  vulnerability_count: number;
  bug_count: number;
  code_smell_count: number;
  security_hotspot_count: number;
  maintainability_rating: 'A' | 'B' | 'C' | 'D' | 'E';
  security_rating: 'A' | 'B' | 'C' | 'D' | 'E';
  reliability_rating: 'A' | 'B' | 'C' | 'D' | 'E';
}

const API_BASE_URL = '/api/v1/sast';

const SASTIssues: React.FC = () => {
  const [issues, setIssues] = useState<SASTIssue[]>([]);
  const [projects, setProjects] = useState<SASTProject[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [selectedIssues, setSelectedIssues] = useState<Set<string>>(new Set());
  const [showFilters, setShowFilters] = useState(false);
  const [selectedIssue, setSelectedIssue] = useState<SASTIssue | null>(null);

  // Filter states
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedProject, setSelectedProject] = useState<string>('all');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedType, setSelectedType] = useState<string>('all');
  const [selectedStatus, setSelectedStatus] = useState<string>('all');
  const [selectedResolution, setSelectedResolution] = useState<string>('all');
  const [selectedAssignee, setSelectedAssignee] = useState<string>('all');
  const [sortBy, setSortBy] = useState<string>('severity');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');

  // Pagination
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [totalIssues, setTotalIssues] = useState(0);

  const fetchIssues = async () => {
    try {
      const token = localStorage.getItem('access_token') || '';
      const headers = {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      };

      const params = new URLSearchParams({
        page: currentPage.toString(),
        size: pageSize.toString(),
        sort_by: sortBy,
        sort_order: sortOrder,
        ...(searchTerm && { search: searchTerm }),
        ...(selectedProject !== 'all' && { project_id: selectedProject }),
        ...(selectedSeverity !== 'all' && { severity: selectedSeverity }),
        ...(selectedType !== 'all' && { type: selectedType }),
        ...(selectedStatus !== 'all' && { status: selectedStatus }),
        ...(selectedResolution !== 'all' && { resolution: selectedResolution }),
        ...(selectedAssignee !== 'all' && { assignee: selectedAssignee }),
      });

      const response = await fetch(`${API_BASE_URL}/issues?${params}`, { headers });
      if (response.ok) {
        const data = await response.json();
        setIssues(data.issues || []);
        setTotalIssues(data.total || 0);
      }
    } catch (error) {
      console.error('Error fetching issues:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchProjects = async () => {
    try {
      const token = localStorage.getItem('access_token') || '';
      const headers = {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      };

      const response = await fetch(`${API_BASE_URL}/projects`, { headers });
      if (response.ok) {
        const data = await response.json();
        setProjects(data.projects || []);
      }
    } catch (error) {
      console.error('Error fetching projects:', error);
    }
  };

  useEffect(() => {
    fetchProjects();
  }, []);

  useEffect(() => {
    fetchIssues();
  }, [currentPage, pageSize, sortBy, sortOrder, searchTerm, selectedProject, selectedSeverity, selectedType, selectedStatus, selectedResolution, selectedAssignee]);

  const onRefresh = () => {
    setRefreshing(true);
    fetchIssues().finally(() => setRefreshing(false));
  };

  const handleBulkAction = async (action: string) => {
    if (selectedIssues.size === 0) return;

    try {
      const token = localStorage.getItem('access_token') || '';
      const headers = {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      };

      const response = await fetch(`${API_BASE_URL}/issues/bulk-action`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          issue_ids: Array.from(selectedIssues),
          action: action,
        }),
      });

      if (response.ok) {
        setSelectedIssues(new Set());
        fetchIssues();
      }
    } catch (error) {
      console.error('Error performing bulk action:', error);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'BLOCKER':
        return 'text-red-600 bg-red-100';
      case 'CRITICAL':
        return 'text-orange-600 bg-orange-100';
      case 'MAJOR':
        return 'text-yellow-600 bg-yellow-100';
      case 'MINOR':
        return 'text-blue-600 bg-blue-100';
      case 'INFO':
        return 'text-gray-600 bg-gray-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'VULNERABILITY':
        return <Shield className="w-4 h-4" />;
      case 'BUG':
        return <Bug className="w-4 h-4" />;
      case 'CODE_SMELL':
        return <Code className="w-4 h-4" />;
      case 'SECURITY_HOTSPOT':
        return <Zap className="w-4 h-4" />;
      default:
        return <AlertTriangle className="w-4 h-4" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'OPEN':
        return 'text-red-600 bg-red-100';
      case 'CONFIRMED':
        return 'text-orange-600 bg-orange-100';
      case 'RESOLVED':
        return 'text-green-600 bg-green-100';
      case 'CLOSED':
        return 'text-gray-600 bg-gray-100';
      case 'REOPENED':
        return 'text-purple-600 bg-purple-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const toggleIssueSelection = (issueId: string) => {
    const newSelected = new Set(selectedIssues);
    if (newSelected.has(issueId)) {
      newSelected.delete(issueId);
    } else {
      newSelected.add(issueId);
    }
    setSelectedIssues(newSelected);
  };

  const toggleAllIssues = () => {
    if (selectedIssues.size === issues.length) {
      setSelectedIssues(new Set());
    } else {
      setSelectedIssues(new Set(issues.map(issue => issue.id)));
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto p-6">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-gray-900 mb-2">
                SAST Issues
              </h1>
              <p className="text-gray-600">
                Static Application Security Testing - Code Analysis & Vulnerability Management
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
                onClick={() => setShowFilters(!showFilters)}
                className="inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                <Filter className="w-4 h-4 mr-2" />
                Filters
                {showFilters ? <ChevronUp className="w-4 h-4 ml-2" /> : <ChevronDown className="w-4 h-4 ml-2" />}
              </button>
              <button
                onClick={() => window.location.href = '/sast/new-scan'}
                className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                <Code className="w-4 h-4 mr-2" />
                New Scan
              </button>
            </div>
          </div>
        </div>

        {/* Search Bar */}
        <div className="mb-6">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
            <input
              type="text"
              placeholder="Search issues by message, file path, or rule name..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
        </div>

        {/* Filters Panel */}
        {showFilters && (
          <div className="bg-white rounded-lg shadow p-6 mb-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Filters</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Project</label>
                <select
                  value={selectedProject}
                  onChange={(e) => setSelectedProject(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="all">All Projects</option>
                  {projects.map((project) => (
                    <option key={project.id} value={project.id}>{project.name}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Severity</label>
                <select
                  value={selectedSeverity}
                  onChange={(e) => setSelectedSeverity(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="all">All Severities</option>
                  <option value="BLOCKER">Blocker</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="MAJOR">Major</option>
                  <option value="MINOR">Minor</option>
                  <option value="INFO">Info</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Type</label>
                <select
                  value={selectedType}
                  onChange={(e) => setSelectedType(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="all">All Types</option>
                  <option value="VULNERABILITY">Vulnerability</option>
                  <option value="BUG">Bug</option>
                  <option value="CODE_SMELL">Code Smell</option>
                  <option value="SECURITY_HOTSPOT">Security Hotspot</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Status</label>
                <select
                  value={selectedStatus}
                  onChange={(e) => setSelectedStatus(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="all">All Statuses</option>
                  <option value="OPEN">Open</option>
                  <option value="CONFIRMED">Confirmed</option>
                  <option value="RESOLVED">Resolved</option>
                  <option value="CLOSED">Closed</option>
                  <option value="REOPENED">Reopened</option>
                </select>
              </div>
            </div>
          </div>
        )}

        {/* Bulk Actions */}
        {selectedIssues.size > 0 && (
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-4">
                <span className="text-sm font-medium text-blue-900">
                  {selectedIssues.size} issue(s) selected
                </span>
                <button
                  onClick={toggleAllIssues}
                  className="text-sm text-blue-600 hover:text-blue-800"
                >
                  {selectedIssues.size === issues.length ? 'Deselect All' : 'Select All'}
                </button>
              </div>
              <div className="flex space-x-2">
                <button
                  onClick={() => handleBulkAction('assign')}
                  className="inline-flex items-center px-3 py-1.5 border border-transparent text-xs font-medium rounded text-blue-700 bg-blue-100 hover:bg-blue-200"
                >
                  <Users className="w-3 h-3 mr-1" />
                  Assign
                </button>
                <button
                  onClick={() => handleBulkAction('resolve')}
                  className="inline-flex items-center px-3 py-1.5 border border-transparent text-xs font-medium rounded text-green-700 bg-green-100 hover:bg-green-200"
                >
                  <CheckCircle className="w-3 h-3 mr-1" />
                  Resolve
                </button>
                <button
                  onClick={() => handleBulkAction('reopen')}
                  className="inline-flex items-center px-3 py-1.5 border border-transparent text-xs font-medium rounded text-orange-700 bg-orange-100 hover:bg-orange-200"
                >
                  <RefreshCw className="w-3 h-3 mr-1" />
                  Reopen
                </button>
                <button
                  onClick={() => handleBulkAction('false_positive')}
                  className="inline-flex items-center px-3 py-1.5 border border-transparent text-xs font-medium rounded text-gray-700 bg-gray-100 hover:bg-gray-200"
                >
                  <Flag className="w-3 h-3 mr-1" />
                  False Positive
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Issues Table */}
        <div className="bg-white rounded-lg shadow overflow-hidden">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    <input
                      type="checkbox"
                      checked={selectedIssues.size === issues.length && issues.length > 0}
                      onChange={toggleAllIssues}
                      className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                    />
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Issue</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Project</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">File</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Assignee</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Created</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {issues.map((issue) => (
                  <tr key={issue.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <input
                        type="checkbox"
                        checked={selectedIssues.has(issue.id)}
                        onChange={() => toggleIssueSelection(issue.id)}
                        className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                      />
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <div className="flex-shrink-0 h-8 w-8">
                          {getTypeIcon(issue.type)}
                        </div>
                        <div className="ml-4">
                          <div className="text-sm font-medium text-gray-900">{issue.rule_name}</div>
                          <div className="text-sm text-gray-500">{issue.message}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{issue.project_name}</td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm text-gray-900">{issue.file_path}</div>
                      <div className="text-sm text-gray-500">Line {issue.line_number}</div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(issue.severity)}`}>
                        {issue.severity}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(issue.status)}`}>
                        {issue.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{issue.assignee || '-'}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{issue.created_at}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                      <div className="flex space-x-2">
                        <button
                          onClick={() => setSelectedIssue(issue)}
                          className="text-blue-600 hover:text-blue-900"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => window.location.href = `/sast/issues/${issue.id}/edit`}
                          className="text-gray-600 hover:text-gray-900"
                        >
                          <Edit className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Pagination */}
        <div className="mt-6 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <span className="text-sm text-gray-700">
              Showing {((currentPage - 1) * pageSize) + 1} to {Math.min(currentPage * pageSize, totalIssues)} of {totalIssues} results
            </span>
          </div>
          <div className="flex items-center space-x-2">
            <select
              value={pageSize}
              onChange={(e) => setPageSize(Number(e.target.value))}
              className="px-3 py-1 border border-gray-300 rounded-md text-sm"
            >
              <option value={25}>25 per page</option>
              <option value={50}>50 per page</option>
              <option value={100}>100 per page</option>
            </select>
            <button
              onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
              disabled={currentPage === 1}
              className="px-3 py-1 border border-gray-300 rounded-md text-sm disabled:opacity-50"
            >
              Previous
            </button>
            <span className="text-sm text-gray-700">
              Page {currentPage} of {Math.ceil(totalIssues / pageSize)}
            </span>
            <button
              onClick={() => setCurrentPage(Math.min(Math.ceil(totalIssues / pageSize), currentPage + 1))}
              disabled={currentPage >= Math.ceil(totalIssues / pageSize)}
              className="px-3 py-1 border border-gray-300 rounded-md text-sm disabled:opacity-50"
            >
              Next
            </button>
          </div>
        </div>

        {/* Issue Details Modal */}
        {selectedIssue && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-lg p-6 w-full max-w-4xl max-h-[90vh] overflow-y-auto">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-xl font-semibold">Issue Details</h2>
                <button
                  onClick={() => setSelectedIssue(null)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  ×
                </button>
              </div>

              <div className="space-y-6">
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-2">{selectedIssue.rule_name}</h3>
                  <p className="text-gray-700">{selectedIssue.message}</p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <h4 className="font-semibold text-gray-900 mb-3">Issue Information</h4>
                    <dl className="space-y-2">
                      <div>
                        <dt className="text-sm font-medium text-gray-700">Type</dt>
                        <dd className="text-sm text-gray-900">{selectedIssue.type}</dd>
                      </div>
                      <div>
                        <dt className="text-sm font-medium text-gray-700">Severity</dt>
                        <dd className="text-sm text-gray-900">{selectedIssue.severity}</dd>
                      </div>
                      <div>
                        <dt className="text-sm font-medium text-gray-700">Status</dt>
                        <dd className="text-sm text-gray-900">{selectedIssue.status}</dd>
                      </div>
                      <div>
                        <dt className="text-sm font-medium text-gray-700">Resolution</dt>
                        <dd className="text-sm text-gray-900">{selectedIssue.resolution}</dd>
                      </div>
                      <div>
                        <dt className="text-sm font-medium text-gray-700">Effort</dt>
                        <dd className="text-sm text-gray-900">{selectedIssue.effort} minutes</dd>
                      </div>
                      <div>
                        <dt className="text-sm font-medium text-gray-700">Technical Debt</dt>
                        <dd className="text-sm text-gray-900">{selectedIssue.debt} minutes</dd>
                      </div>
                    </dl>
                  </div>

                  <div>
                    <h4 className="font-semibold text-gray-900 mb-3">Location</h4>
                    <dl className="space-y-2">
                      <div>
                        <dt className="text-sm font-medium text-gray-700">Project</dt>
                        <dd className="text-sm text-gray-900">{selectedIssue.project_name}</dd>
                      </div>
                      <div>
                        <dt className="text-sm font-medium text-gray-700">File</dt>
                        <dd className="text-sm text-gray-900 font-mono">{selectedIssue.file_path}</dd>
                      </div>
                      <div>
                        <dt className="text-sm font-medium text-gray-700">Line</dt>
                        <dd className="text-sm text-gray-900">{selectedIssue.line_number}</dd>
                      </div>
                      <div>
                        <dt className="text-sm font-medium text-gray-700">Author</dt>
                        <dd className="text-sm text-gray-900">{selectedIssue.author}</dd>
                      </div>
                      <div>
                        <dt className="text-sm font-medium text-gray-700">Assignee</dt>
                        <dd className="text-sm text-gray-900">{selectedIssue.assignee || 'Unassigned'}</dd>
                      </div>
                    </dl>
                  </div>
                </div>

                {selectedIssue.description && (
                  <div>
                    <h4 className="font-semibold text-gray-900 mb-3">Description</h4>
                    <p className="text-gray-700">{selectedIssue.description}</p>
                  </div>
                )}

                <div className="flex justify-end space-x-3 pt-4 border-t">
                  <button
                    onClick={() => setSelectedIssue(null)}
                    className="px-4 py-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50"
                  >
                    Close
                  </button>
                  <button
                    onClick={() => window.location.href = `/sast/issues/${selectedIssue.id}/edit`}
                    className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
                  >
                    Edit Issue
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

export default SASTIssues; 