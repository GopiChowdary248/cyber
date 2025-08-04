import React, { useState, useEffect } from 'react';
import {
  Code,
  AlertTriangle,
  CheckCircle,
  Clock,
  XCircle,
  Plus,
  Eye,
  Download,
  RefreshCw,
  FileText
} from 'lucide-react';

interface SASTProject {
  id: string;
  name: string;
  repository_url: string;
  language: string;
  status: string;
  last_scan?: string;
  total_vulnerabilities: number;
  high_severity: number;
  medium_severity: number;
  low_severity: number;
  security_score: number;
}

interface SASTScan {
  id: string;
  project_id: string;
  status: string;
  started_at: string;
  completed_at?: string;
  total_vulnerabilities: number;
  scan_type: string;
  progress?: number;
}

interface SASTSummary {
  total_projects: number;
  active_scans: number;
  total_vulnerabilities: number;
  high_severity: number;
  medium_severity: number;
  low_severity: number;
  security_score: number;
}

const API_BASE_URL = '/api/v1/sast';

const SASTDashboard: React.FC = () => {
  const [summary, setSummary] = useState<SASTSummary | null>(null);
  const [projects, setProjects] = useState<SASTProject[]>([]);
  const [scans, setScans] = useState<SASTScan[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchSASTData = async () => {
    try {
      const token = localStorage.getItem('token') || '';
      const headers = {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      };

      const [summaryRes, projectsRes, scansRes] = await Promise.all([
        fetch(`${API_BASE_URL}/overview`, { headers }),
        fetch(`${API_BASE_URL}/projects`, { headers }),
        fetch(`${API_BASE_URL}/scans`, { headers }),
      ]);

      if (summaryRes.ok) {
        const summaryData = await summaryRes.json();
        setSummary(summaryData);
      }

      if (projectsRes.ok) {
        const projectsData = await projectsRes.json();
        setProjects(projectsData.projects || []);
      }

      if (scansRes.ok) {
        const scansData = await scansRes.json();
        setScans(scansData.scans || []);
      }
    } catch (error) {
      console.error('Error fetching SAST data:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSASTData();
  }, []);

  const onRefresh = () => {
    setRefreshing(true);
    fetchSASTData().finally(() => setRefreshing(false));
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'text-green-600 bg-green-100';
      case 'inactive':
        return 'text-gray-600 bg-gray-100';
      case 'error':
        return 'text-red-600 bg-red-100';
      default:
        return 'text-yellow-600 bg-yellow-100';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active':
        return <CheckCircle className="w-4 h-4" />;
      case 'inactive':
        return <Clock className="w-4 h-4" />;
      case 'error':
        return <XCircle className="w-4 h-4" />;
      default:
        return <Clock className="w-4 h-4" />;
    }
  };

  const getSecurityScoreColor = (score: number) => {
    if (score >= 80) return 'text-green-600';
    if (score >= 60) return 'text-yellow-600';
    return 'text-red-600';
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
                SAST Dashboard
              </h1>
              <p className="text-gray-600">
                Static Application Security Testing and code analysis
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
                onClick={() => window.location.href = '/sast/projects/new'}
                className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                <Plus className="w-4 h-4 mr-2" />
                New Project
              </button>
            </div>
          </div>
        </div>

        {/* Summary Stats */}
        {summary && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <div className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center">
                <div className="p-2 bg-blue-100 rounded-lg">
                  <Code className="w-6 h-6 text-blue-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Total Projects</p>
                  <p className="text-2xl font-semibold text-gray-900">{summary.total_projects}</p>
                </div>
              </div>
            </div>

            <div className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center">
                <div className="p-2 bg-green-100 rounded-lg">
                  <CheckCircle className="w-6 h-6 text-green-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Active Scans</p>
                  <p className="text-2xl font-semibold text-gray-900">{summary.active_scans}</p>
                </div>
              </div>
            </div>

            <div className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center">
                <div className="p-2 bg-red-100 rounded-lg">
                  <AlertTriangle className="w-6 h-6 text-red-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Total Vulnerabilities</p>
                  <p className="text-2xl font-semibold text-gray-900">{summary.total_vulnerabilities}</p>
                </div>
              </div>
            </div>

            <div className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center">
                <div className="p-2 bg-purple-100 rounded-lg">
                  <FileText className="w-6 h-6 text-purple-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Security Score</p>
                  <p className={`text-2xl font-semibold ${getSecurityScoreColor(summary.security_score)}`}>
                    {summary.security_score}%
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Vulnerability Breakdown */}
        {summary && (
          <div className="bg-white rounded-lg shadow p-6 mb-8">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">Vulnerability Severity Breakdown</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="text-center">
                <div className="text-3xl font-bold text-red-600 mb-2">{summary.high_severity}</div>
                <div className="text-sm text-gray-600">High Severity</div>
              </div>
              <div className="text-center">
                <div className="text-3xl font-bold text-yellow-600 mb-2">{summary.medium_severity}</div>
                <div className="text-sm text-gray-600">Medium Severity</div>
              </div>
              <div className="text-center">
                <div className="text-3xl font-bold text-blue-600 mb-2">{summary.low_severity}</div>
                <div className="text-sm text-gray-600">Low Severity</div>
              </div>
            </div>
          </div>
        )}

        {/* Recent Projects */}
        <div className="bg-white rounded-lg shadow mb-8">
          <div className="px-6 py-4 border-b border-gray-200">
            <h2 className="text-lg font-semibold text-gray-900">Recent Projects</h2>
          </div>
          <div className="p-6">
            {projects.length === 0 ? (
              <div className="text-center py-8">
                <Code className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                <p className="text-gray-500">No SAST projects found. Create your first project to get started.</p>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {projects.slice(0, 6).map((project) => (
                  <div key={project.id} className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow">
                    <div className="flex items-center justify-between mb-3">
                      <h3 className="font-semibold text-gray-900 truncate">{project.name}</h3>
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(project.status)}`}>
                        {getStatusIcon(project.status)}
                        <span className="ml-1 capitalize">{project.status}</span>
                      </span>
                    </div>
                    <p className="text-sm text-gray-600 mb-3">{project.language}</p>
                    <div className="text-xs text-gray-500 mb-3 font-mono">{project.repository_url}</div>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-gray-600">Security Score:</span>
                        <span className={`font-semibold ${getSecurityScoreColor(project.security_score)}`}>
                          {project.security_score}%
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-600">Vulnerabilities:</span>
                        <span className="font-medium">{project.total_vulnerabilities}</span>
                      </div>
                      <div className="flex space-x-4 text-xs">
                        <span className="text-red-600 font-medium">{project.high_severity} High</span>
                        <span className="text-yellow-600 font-medium">{project.medium_severity} Medium</span>
                        <span className="text-blue-600 font-medium">{project.low_severity} Low</span>
                      </div>
                    </div>
                    <div className="flex space-x-2 mt-4">
                      <button
                        onClick={() => window.location.href = `/sast/projects/${project.id}`}
                        className="text-blue-600 hover:text-blue-900 text-sm"
                      >
                        View Details
                      </button>
                      <button
                        onClick={() => window.location.href = `/sast/projects/${project.id}/scan`}
                        className="text-green-600 hover:text-green-900 text-sm"
                      >
                        Run Scan
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Recent Scans */}
        <div className="bg-white rounded-lg shadow mb-8">
          <div className="px-6 py-4 border-b border-gray-200">
            <h2 className="text-lg font-semibold text-gray-900">Recent Scans</h2>
          </div>
          <div className="p-6">
            {scans.length === 0 ? (
              <div className="text-center py-8">
                <Clock className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                <p className="text-gray-500">No scans found. Run your first SAST scan to begin analysis.</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Scan ID</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Started</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Vulnerabilities</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {scans.slice(0, 5).map((scan) => (
                      <tr key={scan.id} className="hover:bg-gray-50">
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{scan.id}</td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(scan.status)}`}>
                            {getStatusIcon(scan.status)}
                            <span className="ml-1 capitalize">{scan.status}</span>
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{scan.started_at}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{scan.total_vulnerabilities}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                          <button
                            onClick={() => window.location.href = `/sast/scans/${scan.id}`}
                            className="text-blue-600 hover:text-blue-900 mr-3"
                          >
                            <Eye className="w-4 h-4" />
                          </button>
                          {scan.status === 'completed' && (
                            <button
                              onClick={() => window.location.href = `/sast/scans/${scan.id}/report`}
                              className="text-green-600 hover:text-green-900"
                            >
                              <Download className="w-4 h-4" />
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default SASTDashboard; 