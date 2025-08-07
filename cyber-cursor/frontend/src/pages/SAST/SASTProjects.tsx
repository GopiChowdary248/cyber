import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  PlusIcon,
  MagnifyingGlassIcon,
  EyeIcon,
  DocumentDuplicateIcon,
  TrashIcon,
  PlayIcon,
  ClockIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  ArrowPathIcon,
  ChevronLeftIcon,
  ChevronRightIcon
} from '@heroicons/react/24/outline';
import { useAuth } from '../../contexts/AuthContext';
import { useNavigate } from 'react-router-dom';

interface SASTProject {
  id: number;
  name: string;
  key: string;
  language: string;
  repositoryUrl?: string;
  branch: string;
  lastScan?: {
    id: number;
    status: 'COMPLETED' | 'RUNNING' | 'FAILED' | 'PENDING';
    timestamp: string;
    duration?: string;
  };
  issues: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  qualityGate: 'PASSED' | 'FAILED' | 'WARNING' | 'NONE';
  createdBy: string;
  createdAt: string;
}

interface CreateProjectData {
  name: string;
  key: string;
  language: string;
  repository_url?: string;
  branch?: string;
}

interface DuplicateProjectData {
  name: string;
  key: string;
}

const SASTProjects: React.FC = () => {
  const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
  const navigate = useNavigate();
  const [projects, setProjects] = useState<SASTProject[]>([]);
  const [loading, setLoading] = useState(true);
  const [viewMode, setViewMode] = useState<'list' | 'cards'>('cards');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedLanguage, setSelectedLanguage] = useState<string>('all');
  const [selectedStatus, setSelectedStatus] = useState<string>('all');
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage] = useState(12);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showDuplicateModal, setShowDuplicateModal] = useState(false);
  const [selectedProject, setSelectedProject] = useState<SASTProject | null>(null);
  const [createFormData, setCreateFormData] = useState<CreateProjectData>({
    name: '',
    key: '',
    language: '',
    repository_url: '',
    branch: 'main'
  });
  const [duplicateFormData, setDuplicateFormData] = useState<DuplicateProjectData>({
    name: '',
    key: ''
  });
  const [totalProjects, setTotalProjects] = useState(0);
  const [totalPages, setTotalPages] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const fetchProjects = async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams({
        skip: ((currentPage - 1) * itemsPerPage).toString(),
        limit: itemsPerPage.toString()
      });

      if (searchTerm) params.append('search', searchTerm);
      if (selectedLanguage !== 'all') params.append('language', selectedLanguage);
      if (selectedStatus !== 'all') params.append('status_filter', selectedStatus);

      const response = await fetch(`${API_URL}/api/v1/sast/projects?${params}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      
      // Transform API response to match our interface
      const transformedProjects: SASTProject[] = data.projects.map((project: any) => ({
        id: project.id,
        name: project.name,
        key: project.key,
        language: project.language,
        repositoryUrl: project.repository_url,
        branch: project.branch,
        lastScan: project.last_scan ? {
          id: project.last_scan.id,
          status: project.last_scan.status,
          timestamp: project.last_scan.started_at,
          duration: project.last_scan.duration
        } : undefined,
        issues: project.issues || { critical: 0, high: 0, medium: 0, low: 0 },
        qualityGate: project.quality_gate || 'NONE',
        createdBy: project.created_by,
        createdAt: project.created_at
      }));

      setProjects(transformedProjects);
      setTotalProjects(data.total);
      setTotalPages(data.pages);
      setError(null);
    } catch (error) {
      console.error('Error fetching SAST projects:', error);
      setError('Failed to fetch projects');
      // Fallback to mock data for demo
      const mockProjects: SASTProject[] = [
        {
          id: 1,
          name: 'Web Application Security',
          key: 'web-app-sec',
          language: 'JavaScript',
          repositoryUrl: 'https://github.com/example/web-app',
          branch: 'main',
          lastScan: {
            id: 101,
            status: 'COMPLETED',
            timestamp: '2024-01-15T10:30:00Z',
            duration: '2m 34s'
          },
          issues: { critical: 2, high: 5, medium: 12, low: 8 },
          qualityGate: 'PASSED',
          createdBy: 'admin@example.com',
          createdAt: '2024-01-10T09:00:00Z'
        },
        {
          id: 2,
          name: 'API Security Testing',
          key: 'api-sec',
          language: 'Python',
          repositoryUrl: 'https://github.com/example/api',
          branch: 'develop',
          lastScan: {
            id: 102,
            status: 'COMPLETED',
            timestamp: '2024-01-14T15:45:00Z',
            duration: '1m 52s'
          },
          issues: { critical: 0, high: 3, medium: 7, low: 4 },
          qualityGate: 'PASSED',
          createdBy: 'admin@example.com',
          createdAt: '2024-01-08T14:30:00Z'
        },
        {
          id: 3,
          name: 'Mobile App Security',
          key: 'mobile-sec',
          language: 'React Native',
          repositoryUrl: 'https://github.com/example/mobile',
          branch: 'main',
          lastScan: {
            id: 103,
            status: 'RUNNING',
            timestamp: '2024-01-15T11:00:00Z'
          },
          issues: { critical: 1, high: 2, medium: 5, low: 3 },
          qualityGate: 'WARNING',
          createdBy: 'admin@example.com',
          createdAt: '2024-01-12T16:20:00Z'
        }
      ];
      setProjects(mockProjects);
      setTotalProjects(3);
      setTotalPages(1);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchProjects();
  }, [currentPage, searchTerm, selectedLanguage, selectedStatus]);

  const handleCreateProject = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const response = await fetch(`${API_URL}/api/v1/sast/projects`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(createFormData)
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to create project');
      }

      const newProject = await response.json();
      setProjects(prev => [newProject, ...prev]);
      setShowCreateModal(false);
      setCreateFormData({ name: '', key: '', language: '', repository_url: '', branch: 'main' });
      setError(null);
    } catch (error) {
      console.error('Error creating project:', error);
      setError(error instanceof Error ? error.message : 'Failed to create project');
    }
  };

  const handleDuplicateProject = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedProject) return;

    try {
      const response = await fetch(`${API_URL}/api/v1/sast/projects/${selectedProject.id}/duplicate`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(duplicateFormData)
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to duplicate project');
      }

      const duplicatedProject = await response.json();
      setProjects(prev => [duplicatedProject, ...prev]);
      setShowDuplicateModal(false);
      setSelectedProject(null);
      setDuplicateFormData({ name: '', key: '' });
      setError(null);
    } catch (error) {
      console.error('Error duplicating project:', error);
      setError(error instanceof Error ? error.message : 'Failed to duplicate project');
    }
  };

  const handleDeleteProject = async (projectId: number) => {
    if (!window.confirm('Are you sure you want to delete this project? This action cannot be undone.')) {
      return;
    }

    try {
      const response = await fetch(`${API_URL}/api/v1/sast/projects/${projectId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to delete project');
      }

      setProjects(prev => prev.filter(p => p.id !== projectId));
      setError(null);
    } catch (error) {
      console.error('Error deleting project:', error);
      setError(error instanceof Error ? error.message : 'Failed to delete project');
    }
  };

  const handleStartScan = async (projectId: number) => {
    try {
      const response = await fetch(`${API_URL}/api/v1/sast/scans`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          project_id: projectId,
          scan_type: 'full',
          branch: 'main'
        })
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to start scan');
      }

      // Refresh projects to show updated scan status
      fetchProjects();
      setError(null);
    } catch (error) {
      console.error('Error starting scan:', error);
      setError(error instanceof Error ? error.message : 'Failed to start scan');
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'COMPLETED':
        return 'text-green-600 bg-green-100';
      case 'RUNNING':
        return 'text-blue-600 bg-blue-100';
      case 'FAILED':
        return 'text-red-600 bg-red-100';
      case 'PENDING':
        return 'text-yellow-600 bg-yellow-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'COMPLETED':
        return <CheckCircleIcon className="w-4 h-4" />;
      case 'RUNNING':
        return <ArrowPathIcon className="w-4 h-4 animate-spin" />;
      case 'FAILED':
        return <XCircleIcon className="w-4 h-4" />;
      case 'PENDING':
        return <ClockIcon className="w-4 h-4" />;
      default:
        return <ClockIcon className="w-4 h-4" />;
    }
  };

  const getQualityGateColor = (status: string) => {
    switch (status) {
      case 'PASSED':
        return 'text-green-600 bg-green-100';
      case 'FAILED':
        return 'text-red-600 bg-red-100';
      case 'WARNING':
        return 'text-yellow-600 bg-yellow-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'text-red-600';
      case 'high':
        return 'text-orange-600';
      case 'medium':
        return 'text-yellow-600';
      case 'low':
        return 'text-blue-600';
      default:
        return 'text-gray-600';
    }
  };

  const languages = ['all', ...Array.from(new Set(projects.map(p => p.language)))];

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">SAST Projects</h1>
          <p className="text-gray-600">Manage and monitor your static application security testing projects</p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
        >
          <PlusIcon className="w-4 h-4 mr-2" />
          Create Project
        </button>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-md p-4">
          <div className="flex">
            <ExclamationTriangleIcon className="w-5 h-5 text-red-400" />
            <div className="ml-3">
              <h3 className="text-sm font-medium text-red-800">Error</h3>
              <p className="text-sm text-red-700 mt-1">{error}</p>
            </div>
          </div>
        </div>
      )}

      {/* Filters and Search */}
      <div className="bg-white p-4 rounded-lg shadow-sm border border-gray-200">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="flex-1">
            <div className="relative">
              <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search projects..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
              />
            </div>
          </div>
          <div className="flex gap-2">
            <select
              value={selectedLanguage}
              onChange={(e) => setSelectedLanguage(e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            >
              {languages.map(lang => (
                <option key={lang} value={lang}>
                  {lang === 'all' ? 'All Languages' : lang}
                </option>
              ))}
            </select>
            <select
              value={selectedStatus}
              onChange={(e) => setSelectedStatus(e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="all">All Status</option>
              <option value="active">Active</option>
              <option value="completed">Completed</option>
              <option value="failed">Failed</option>
            </select>
            <div className="flex border border-gray-300 rounded-md">
              <button
                onClick={() => setViewMode('cards')}
                className={`px-3 py-2 text-sm font-medium ${
                  viewMode === 'cards' 
                    ? 'bg-blue-600 text-white' 
                    : 'bg-white text-gray-700 hover:bg-gray-50'
                }`}
              >
                Cards
              </button>
              <button
                onClick={() => setViewMode('list')}
                className={`px-3 py-2 text-sm font-medium ${
                  viewMode === 'list' 
                    ? 'bg-blue-600 text-white' 
                    : 'bg-white text-gray-700 hover:bg-gray-50'
                }`}
              >
                List
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Projects Display */}
      {viewMode === 'cards' ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {projects.map((project) => (
            <motion.div
              key={project.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="bg-white p-6 rounded-lg shadow-sm border border-gray-200 hover:shadow-md transition-shadow"
            >
              <div className="flex items-start justify-between mb-4">
                <div className="flex-1">
                  <h3 className="text-lg font-semibold text-gray-900 mb-1">{project.name}</h3>
                  <p className="text-sm text-gray-600 mb-2">{project.key}</p>
                  <div className="flex items-center space-x-2">
                    <span className="text-xs bg-gray-100 text-gray-700 px-2 py-1 rounded">{project.language}</span>
                    <span className={`text-xs px-2 py-1 rounded ${getQualityGateColor(project.qualityGate)}`}>
                      {project.qualityGate}
                    </span>
                  </div>
                </div>
              </div>

              {/* Last Scan Info */}
              {project.lastScan && (
                <div className="mb-4 p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-gray-700">Last Scan</span>
                    <div className={`flex items-center space-x-1 px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(project.lastScan.status)}`}>
                      {getStatusIcon(project.lastScan.status)}
                      <span>{project.lastScan.status}</span>
                    </div>
                  </div>
                  <div className="text-xs text-gray-600">
                    {new Date(project.lastScan.timestamp).toLocaleDateString()}
                    {project.lastScan.duration && ` • ${project.lastScan.duration}`}
                  </div>
                </div>
              )}

              {/* Issues Summary */}
              <div className="mb-4">
                <h4 className="text-sm font-medium text-gray-700 mb-2">Issues</h4>
                <div className="grid grid-cols-4 gap-2 text-xs">
                  <div className="text-center">
                    <div className={`font-bold ${getSeverityColor('critical')}`}>{project.issues.critical}</div>
                    <div className="text-gray-500">Critical</div>
                  </div>
                  <div className="text-center">
                    <div className={`font-bold ${getSeverityColor('high')}`}>{project.issues.high}</div>
                    <div className="text-gray-500">High</div>
                  </div>
                  <div className="text-center">
                    <div className={`font-bold ${getSeverityColor('medium')}`}>{project.issues.medium}</div>
                    <div className="text-gray-500">Medium</div>
                  </div>
                  <div className="text-center">
                    <div className={`font-bold ${getSeverityColor('low')}`}>{project.issues.low}</div>
                    <div className="text-gray-500">Low</div>
                  </div>
                </div>
              </div>

              {/* Actions */}
              <div className="flex items-center justify-between pt-4 border-t border-gray-200">
                <div className="flex space-x-2">
                                     <button
                     onClick={() => navigate(`/sast/projects/${project.id}`)}
                     className="inline-flex items-center px-3 py-1.5 border border-gray-300 shadow-sm text-xs font-medium rounded text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                   >
                     <EyeIcon className="w-3 h-3 mr-1" />
                     View
                   </button>
                  <button
                    onClick={() => handleStartScan(project.id)}
                    className="inline-flex items-center px-3 py-1.5 border border-transparent text-xs font-medium rounded text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                  >
                    <PlayIcon className="w-3 h-3 mr-1" />
                    Scan
                  </button>
                </div>
                <div className="flex space-x-1">
                  <button
                    onClick={() => {
                      setSelectedProject(project);
                      setDuplicateFormData({
                        name: `${project.name} - Copy`,
                        key: `${project.key}-copy`
                      });
                      setShowDuplicateModal(true);
                    }}
                    className="p-1 text-gray-400 hover:text-gray-600"
                    title="Duplicate Project"
                  >
                    <DocumentDuplicateIcon className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => handleDeleteProject(project.id)}
                    className="p-1 text-gray-400 hover:text-red-600"
                    title="Delete Project"
                  >
                    <TrashIcon className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      ) : (
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Project</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Language</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Last Scan</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Issues</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Quality Gate</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {projects.map((project) => (
                <tr key={project.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div>
                      <div className="text-sm font-medium text-gray-900">{project.name}</div>
                      <div className="text-sm text-gray-500">{project.key}</div>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className="text-sm text-gray-900">{project.language}</span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    {project.lastScan ? (
                      <div>
                        <div className={`inline-flex items-center space-x-1 px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(project.lastScan.status)}`}>
                          {getStatusIcon(project.lastScan.status)}
                          <span>{project.lastScan.status}</span>
                        </div>
                        <div className="text-xs text-gray-500 mt-1">
                          {new Date(project.lastScan.timestamp).toLocaleDateString()}
                        </div>
                      </div>
                    ) : (
                      <span className="text-sm text-gray-500">No scans</span>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex space-x-2 text-xs">
                      <span className={`${getSeverityColor('critical')}`}>{project.issues.critical} Critical</span>
                      <span className={`${getSeverityColor('high')}`}>{project.issues.high} High</span>
                      <span className={`${getSeverityColor('medium')}`}>{project.issues.medium} Medium</span>
                      <span className={`${getSeverityColor('low')}`}>{project.issues.low} Low</span>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full ${getQualityGateColor(project.qualityGate)}`}>
                      {project.qualityGate}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                                         <div className="flex space-x-2">
                       <button 
                         onClick={() => navigate(`/sast/projects/${project.id}`)}
                         className="text-blue-600 hover:text-blue-900"
                       >
                         View
                       </button>
                      <button 
                        onClick={() => handleStartScan(project.id)}
                        className="text-green-600 hover:text-green-900"
                      >
                        Scan
                      </button>
                      <button className="text-gray-600 hover:text-gray-900">Duplicate</button>
                      <button 
                        onClick={() => handleDeleteProject(project.id)}
                        className="text-red-600 hover:text-red-900"
                      >
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <div className="text-sm text-gray-700">
            Showing {((currentPage - 1) * itemsPerPage) + 1} to {Math.min(currentPage * itemsPerPage, totalProjects)} of {totalProjects} projects
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
              disabled={currentPage === 1}
              className="inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm leading-4 font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <ChevronLeftIcon className="w-4 h-4" />
              Previous
            </button>
            <span className="text-sm text-gray-700">
              Page {currentPage} of {totalPages}
            </span>
            <button
              onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))}
              disabled={currentPage === totalPages}
              className="inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm leading-4 font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Next
              <ChevronRightIcon className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* Create Project Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Create New SAST Project</h3>
              <form onSubmit={handleCreateProject} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Project Name</label>
                  <input
                    type="text"
                    required
                    value={createFormData.name}
                    onChange={(e) => setCreateFormData({...createFormData, name: e.target.value})}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                    placeholder="Enter project name"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Project Key</label>
                  <input
                    type="text"
                    required
                    value={createFormData.key}
                    onChange={(e) => setCreateFormData({...createFormData, key: e.target.value})}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                    placeholder="project-key"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Repository URL</label>
                  <input
                    type="url"
                    value={createFormData.repository_url}
                    onChange={(e) => setCreateFormData({...createFormData, repository_url: e.target.value})}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                    placeholder="https://github.com/example/repo"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Programming Language</label>
                  <select 
                    required
                    value={createFormData.language}
                    onChange={(e) => setCreateFormData({...createFormData, language: e.target.value})}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  >
                    <option value="">Select language</option>
                    <option value="javascript">JavaScript</option>
                    <option value="python">Python</option>
                    <option value="java">Java</option>
                    <option value="csharp">C#</option>
                    <option value="php">PHP</option>
                    <option value="react-native">React Native</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Branch</label>
                  <input
                    type="text"
                    value={createFormData.branch}
                    onChange={(e) => setCreateFormData({...createFormData, branch: e.target.value})}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                    placeholder="main"
                  />
                </div>
                <div className="flex justify-end space-x-3 pt-4">
                  <button
                    type="button"
                    onClick={() => setShowCreateModal(false)}
                    className="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700"
                  >
                    Create Project
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* Duplicate Project Modal */}
      {showDuplicateModal && selectedProject && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Duplicate Project</h3>
              <p className="text-sm text-gray-600 mb-4">
                Create a copy of "{selectedProject.name}" with its settings and configuration.
              </p>
              <form onSubmit={handleDuplicateProject} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">New Project Name</label>
                  <input
                    type="text"
                    required
                    value={duplicateFormData.name}
                    onChange={(e) => setDuplicateFormData({...duplicateFormData, name: e.target.value})}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">New Project Key</label>
                  <input
                    type="text"
                    required
                    value={duplicateFormData.key}
                    onChange={(e) => setDuplicateFormData({...duplicateFormData, key: e.target.value})}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>
                <div className="flex justify-end space-x-3 pt-4">
                  <button
                    type="button"
                    onClick={() => setShowDuplicateModal(false)}
                    className="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700"
                  >
                    Duplicate Project
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SASTProjects; 