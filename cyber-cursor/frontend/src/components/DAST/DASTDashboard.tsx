import React, { useState, useEffect } from 'react';
import {
  Search, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  XCircle,
  Plus,
  Eye,
  Download,
  RefreshCw
} from 'lucide-react';

interface DASTProject {
  id: string;
  name: string;
  target_url: string;
  description: string;
  status: string;
  last_scan?: string;
  total_vulnerabilities: number;
  high_severity: number;
  medium_severity: number;
  low_severity: number;
  security_score: number;
}

interface DASTScan {
  id: string;
  project_id: string;
  status: string;
  started_at: string;
  completed_at?: string;
  total_vulnerabilities: number;
  scan_type: string;
  progress?: number;
}

interface DASTVulnerability {
  id: string;
  project_id: string;
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
}

interface DASTSummary {
  total_projects: number;
  active_scans: number;
  total_vulnerabilities: number;
  high_severity: number;
  medium_severity: number;
  low_severity: number;
  security_score: number;
}

const API_BASE_URL = '/api/v1/dast';

const DASTDashboard: React.FC = () => {
  const [summary, setSummary] = useState<DASTSummary | null>(null);
  const [projects, setProjects] = useState<DASTProject[]>([]);
  const [scans, setScans] = useState<DASTScan[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<DASTVulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchDASTData = async () => {
    try {
      const token = localStorage.getItem('token') || '';
      const headers = {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      };

      const [summaryRes, projectsRes, scansRes, vulnsRes] = await Promise.all([
        fetch(`${API_BASE_URL}/overview`, { headers }),
        fetch(`${API_BASE_URL}/projects`, { headers }),
        fetch(`${API_BASE_URL}/scans`, { headers }),
        fetch(`${API_BASE_URL}/vulnerabilities`, { headers }),
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

      if (vulnsRes.ok) {
        const vulnsData = await vulnsRes.json();
        setVulnerabilities(vulnsData.vulnerabilities || []);
      }
    } catch (error) {
      console.error('Error fetching DAST data:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDASTData();
  }, []);

  const onRefresh = () => {
    setRefreshing(true);
    fetchDASTData().finally(() => setRefreshing(false));
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

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'text-green-600 bg-green-100';
      case 'running':
        return 'text-blue-600 bg-blue-100';
      case 'failed':
        return 'text-red-600 bg-red-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const getSecurityScoreColor = (score: number) => {
    if (score >= 80) return 'text-green-600';
    if (score >= 60) return 'text-yellow-600';
    return 'text-red-600';
  };

  const handleNewScan = () => {
    // Navigate to new scan page
    window.location.href = '/dast/new-scan';
  };

  const handleNewProject = () => {
    // Navigate to new project page
    window.location.href = '/dast/new-project';
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
                DAST Security Dashboard
              </h1>
              <p className="text-gray-600">
                Dynamic Application Security Testing and vulnerability management
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
                onClick={handleNewProject}
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
                  <Search className="w-6 h-6 text-blue-600" />
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
                  <Eye className="w-6 h-6 text-purple-600" />
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

        {/* Vulnerability Severity Breakdown */}
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
                <Search className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                <p className="text-gray-500">No projects found. Create your first DAST project to get started.</p>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {projects.slice(0, 6).map((project) => (
                  <div key={project.id} className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow">
                    <div className="flex items-center justify-between mb-3">
                      <h3 className="font-semibold text-gray-900 truncate">{project.name}</h3>
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(project.status)}`}>
                        {project.status}
                      </span>
                    </div>
                    <p className="text-sm text-gray-600 mb-3 line-clamp-2">{project.description}</p>
                    <div className="text-xs text-gray-500 mb-3">{project.target_url}</div>
                    <div className="flex items-center justify-between text-sm">
                      <span className={`font-semibold ${getSecurityScoreColor(project.security_score)}`}>
                        Score: {project.security_score}%
                      </span>
                      <span className="text-gray-600">
                        {project.total_vulnerabilities} vulns
                      </span>
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
                <p className="text-gray-500">No scans found. Start a new scan to begin testing.</p>
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
                    {scan.status}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{scan.started_at}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{scan.total_vulnerabilities}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                          <button className="text-blue-600 hover:text-blue-900 mr-3">View</button>
                          <button className="text-green-600 hover:text-green-900">Report</button>
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

export default DASTDashboard; 