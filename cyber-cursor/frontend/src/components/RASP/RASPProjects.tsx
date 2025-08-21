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
  ChevronRightIcon,
  ShieldCheckIcon,
  ChartBarIcon,
  ServerIcon
} from '@heroicons/react/24/outline';
import { useAuth } from '../../contexts/AuthContext';
import { useNavigate } from 'react-router-dom';

interface RASPProject {
  id: number;
  name: string;
  key: string;
  environment: string;
  repositoryUrl?: string;
  branch: string;
  lastScan?: {
    id: number;
    status: 'COMPLETED' | 'RUNNING' | 'FAILED' | 'PENDING';
    timestamp: string;
    duration?: string;
  };
  attacks: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  securityStatus: 'SECURE' | 'VULNERABLE' | 'CRITICAL' | 'UNKNOWN';
  createdBy: string;
  createdAt: string;
  status: 'active' | 'monitoring' | 'stopped' | 'error';
}

interface CreateProjectData {
  name: string;
  key: string;
  environment: string;
  repository_url?: string;
  branch?: string;
}

interface DuplicateProjectData {
  name: string;
  key: string;
}

const RASPProjects: React.FC = () => {
  const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
  const navigate = useNavigate();
  const [projects, setProjects] = useState<RASPProject[]>([]);
  const [loading, setLoading] = useState(true);
  const [viewMode, setViewMode] = useState<'list' | 'cards'>('cards');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedEnvironment, setSelectedEnvironment] = useState<string>('all');
  const [selectedStatus, setSelectedStatus] = useState<string>('all');
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage] = useState(12);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showDuplicateModal, setShowDuplicateModal] = useState(false);
  const [selectedProject, setSelectedProject] = useState<RASPProject | null>(null);
  const [createFormData, setCreateFormData] = useState<CreateProjectData>({
    name: '',
    key: '',
    environment: '',
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

  const environments = [
    { value: 'production', label: 'Production' },
    { value: 'staging', label: 'Staging' },
    { value: 'development', label: 'Development' },
    { value: 'testing', label: 'Testing' }
  ];

  const fetchProjects = async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams({
        skip: ((currentPage - 1) * itemsPerPage).toString(),
        limit: itemsPerPage.toString()
      });

      if (searchTerm) params.append('search', searchTerm);
      if (selectedEnvironment !== 'all') params.append('environment', selectedEnvironment);
      if (selectedStatus !== 'all') params.append('status_filter', selectedStatus);

      const response = await fetch(`${API_URL}/api/v1/rasp/projects?${params}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token') || ''}`,
          'Content-Type': 'application/json',
        },
      });

      if (response.ok) {
        const data = await response.json();
        setProjects(data.projects || []);
        setTotalProjects(data.total || 0);
        setTotalPages(Math.ceil((data.total || 0) / itemsPerPage));
      } else {
        setError('Failed to fetch projects');
      }
    } catch (error) {
      console.error('Error fetching projects:', error);
      setError('Network error occurred');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchProjects();
  }, [currentPage, searchTerm, selectedEnvironment, selectedStatus]);

  const handleCreateProject = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const response = await fetch(`${API_URL}/api/v1/rasp/projects`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token') || ''}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(createFormData),
      });

      if (response.ok) {
        setShowCreateModal(false);
        setCreateFormData({ name: '', key: '', environment: '', repository_url: '', branch: 'main' });
        fetchProjects();
        setError(null);
      } else {
        const errorData = await response.json();
        setError(errorData.detail || 'Failed to create project');
      }
    } catch (error) {
      console.error('Error creating project:', error);
      setError('Network error occurred');
    }
  };

  const handleDuplicateProject = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedProject) return;

    try {
      const response = await fetch(`${API_URL}/api/v1/rasp/projects/${selectedProject.id}/duplicate`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token') || ''}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(duplicateFormData),
      });

      if (response.ok) {
        setShowDuplicateModal(false);
        setDuplicateFormData({ name: '', key: '' });
        fetchProjects();
        setError(null);
      } else {
        const errorData = await response.json();
        setError(errorData.detail || 'Failed to duplicate project');
      }
    } catch (error) {
      console.error('Error duplicating project:', error);
      setError('Network error occurred');
    }
  };

  const handleDeleteProject = async (projectId: number) => {
    if (!window.confirm('Are you sure you want to delete this project?')) return;

    try {
      const response = await fetch(`${API_URL}/api/v1/rasp/projects/${projectId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token') || ''}`,
        },
      });

      if (response.ok) {
        fetchProjects();
        setError(null);
      } else {
        setError('Failed to delete project');
      }
    } catch (error) {
      console.error('Error deleting project:', error);
      setError('Network error occurred');
    }
  };

  const handleStartScan = async (projectId: number) => {
    try {
      const response = await fetch(`${API_URL}/api/v1/rasp/projects/${projectId}/scans`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token') || ''}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          scan_type: 'full',
          priority: 'normal'
        }),
      });

      if (response.ok) {
        fetchProjects();
        setError(null);
      } else {
        setError('Failed to start scan');
      }
    } catch (error) {
      console.error('Error starting scan:', error);
      setError('Network error occurred');
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'text-green-600 bg-green-100';
      case 'monitoring':
        return 'text-blue-600 bg-blue-100';
      case 'stopped':
        return 'text-yellow-600 bg-yellow-100';
      case 'error':
        return 'text-red-600 bg-red-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active':
        return <CheckCircleIcon className="w-4 h-4" />;
      case 'monitoring':
        return <ChartBarIcon className="w-4 h-4" />;
      case 'stopped':
        return <ClockIcon className="w-4 h-4" />;
      case 'error':
        return <XCircleIcon className="w-4 h-4" />;
      default:
        return <ClockIcon className="w-4 h-4" />;
    }
  };

  const getSecurityStatusColor = (status: string) => {
    switch (status) {
      case 'SECURE':
        return 'text-green-600 bg-green-100';
      case 'VULNERABLE':
        return 'text-yellow-600 bg-yellow-100';
      case 'CRITICAL':
        return 'text-red-600 bg-red-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const getEnvironmentIcon = (environment: string) => {
    switch (environment) {
      case 'production':
        return <ServerIcon className="w-4 h-4 text-red-500" />;
      case 'staging':
        return <ServerIcon className="w-4 h-4 text-yellow-500" />;
      case 'development':
        return <ServerIcon className="w-4 h-4 text-blue-500" />;
      case 'testing':
        return <ServerIcon className="w-4 h-4 text-green-500" />;
      default:
        return <ServerIcon className="w-4 h-4 text-gray-500" />;
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold text-gray-900">RASP Projects</h2>
          <p className="text-sm text-gray-600">Manage your Runtime Application Self-Protection projects</p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
        >
          <PlusIcon className="w-4 h-4 mr-2" />
          New Project
        </button>
      </div>

      {/* Filters */}
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
          <select
            value={selectedEnvironment}
            onChange={(e) => setSelectedEnvironment(e.target.value)}
            className="px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
          >
            <option value="all">All Environments</option>
            {environments.map((env) => (
              <option key={env.value} value={env.value}>{env.label}</option>
            ))}
          </select>
          <select
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value)}
            className="px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
          >
            <option value="all">All Statuses</option>
            <option value="active">Active</option>
            <option value="monitoring">Monitoring</option>
            <option value="stopped">Stopped</option>
            <option value="error">Error</option>
          </select>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setViewMode('cards')}
              className={`p-2 rounded ${viewMode === 'cards' ? 'bg-blue-100 text-blue-600' : 'text-gray-400 hover:text-gray-600'}`}
            >
              <div className="grid grid-cols-2 gap-1 w-4 h-4">
                <div className="bg-current rounded-sm"></div>
                <div className="bg-current rounded-sm"></div>
                <div className="bg-current rounded-sm"></div>
                <div className="bg-current rounded-sm"></div>
              </div>
            </button>
            <button
              onClick={() => setViewMode('list')}
              className={`p-2 rounded ${viewMode === 'list' ? 'bg-blue-100 text-blue-600' : 'text-gray-400 hover:text-gray-600'}`}
            >
              <div className="space-y-1 w-4 h-4">
                <div className="bg-current rounded-sm h-0.5"></div>
                <div className="bg-current rounded-sm h-0.5"></div>
                <div className="bg-current rounded-sm h-0.5"></div>
              </div>
            </button>
          </div>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-md p-4">
          <div className="flex">
            <ExclamationTriangleIcon className="w-5 h-5 text-red-400" />
            <div className="ml-3">
              <h3 className="text-sm font-medium text-red-800">Error</h3>
              <div className="mt-2 text-sm text-red-700">{error}</div>
            </div>
          </div>
        </div>
      )}

      {/* Projects Grid/List */}
      {viewMode === 'cards' ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {projects.map((project) => (
            <motion.div
              key={project.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="bg-white rounded-lg shadow-sm border border-gray-200 hover:shadow-md transition-shadow"
            >
              <div className="p-6">
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center space-x-2">
                                         <ShieldCheckIcon className="w-6 h-6 text-blue-600" />
                    <div>
                      <h3 className="text-lg font-medium text-gray-900">{project.name}</h3>
                      <p className="text-sm text-gray-500">{project.key}</p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(project.status)}`}>
                      {getStatusIcon(project.status)}
                      <span className="ml-1">{project.status}</span>
                    </span>
                  </div>
                </div>

                <div className="space-y-3 mb-4">
                  <div className="flex items-center space-x-2">
                    {getEnvironmentIcon(project.environment)}
                    <span className="text-sm text-gray-600">{project.environment}</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSecurityStatusColor(project.securityStatus)}`}>
                      {project.securityStatus}
                    </span>
                  </div>
                  {project.lastScan && (
                    <div className="text-sm text-gray-600">
                      Last scan: {new Date(project.lastScan.timestamp).toLocaleDateString()}
                    </div>
                  )}
                </div>

                <div className="border-t border-gray-200 pt-4">
                  <div className="flex items-center justify-between text-sm text-gray-600 mb-2">
                    <span>Attacks detected:</span>
                    <span className="font-medium">
                      {project.attacks.critical + project.attacks.high + project.attacks.medium + project.attacks.low}
                    </span>
                  </div>
                  <div className="flex space-x-1">
                    {project.attacks.critical > 0 && (
                      <div className="flex-1 bg-red-500 h-2 rounded"></div>
                    )}
                    {project.attacks.high > 0 && (
                      <div className="flex-1 bg-orange-500 h-2 rounded"></div>
                    )}
                    {project.attacks.medium > 0 && (
                      <div className="flex-1 bg-yellow-500 h-2 rounded"></div>
                    )}
                    {project.attacks.low > 0 && (
                      <div className="flex-1 bg-blue-500 h-2 rounded"></div>
                    )}
                  </div>
                </div>

                <div className="mt-4 flex items-center justify-between">
                  <button
                    onClick={() => handleStartScan(project.id)}
                    className="inline-flex items-center px-3 py-2 border border-transparent text-sm font-medium rounded-md text-blue-700 bg-blue-100 hover:bg-blue-200"
                  >
                    <PlayIcon className="w-4 h-4 mr-1" />
                    Start Scan
                  </button>
                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => navigate(`/rasp/projects/${project.id}`)}
                      className="text-gray-400 hover:text-gray-600"
                    >
                      <EyeIcon className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => {
                        setSelectedProject(project);
                        setDuplicateFormData({ name: `${project.name} Copy`, key: `${project.key}_copy` });
                        setShowDuplicateModal(true);
                      }}
                      className="text-gray-400 hover:text-gray-600"
                    >
                      <DocumentDuplicateIcon className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => handleDeleteProject(project.id)}
                      className="text-gray-400 hover:text-red-600"
                    >
                      <TrashIcon className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      ) : (
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Project</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Environment</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Security</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Last Scan</th>
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
                      <div className="flex items-center space-x-2">
                        {getEnvironmentIcon(project.environment)}
                        <span className="text-sm text-gray-900">{project.environment}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(project.status)}`}>
                        {getStatusIcon(project.status)}
                        <span className="ml-1">{project.status}</span>
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSecurityStatusColor(project.securityStatus)}`}>
                        {project.securityStatus}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {project.lastScan ? new Date(project.lastScan.timestamp).toLocaleDateString() : 'Never'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                      <div className="flex items-center space-x-2">
                        <button
                          onClick={() => handleStartScan(project.id)}
                          className="text-blue-600 hover:text-blue-900"
                        >
                          <PlayIcon className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => navigate(`/rasp/projects/${project.id}`)}
                          className="text-gray-600 hover:text-gray-900"
                        >
                          <EyeIcon className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => {
                            setSelectedProject(project);
                            setDuplicateFormData({ name: `${project.name} Copy`, key: `${project.key}_copy` });
                            setShowDuplicateModal(true);
                          }}
                          className="text-gray-600 hover:text-gray-900"
                        >
                          <DocumentDuplicateIcon className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => handleDeleteProject(project.id)}
                          className="text-gray-600 hover:text-red-600"
                        >
                          <TrashIcon className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <div className="text-sm text-gray-700">
            Showing {((currentPage - 1) * itemsPerPage) + 1} to {Math.min(currentPage * itemsPerPage, totalProjects)} of {totalProjects} results
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setCurrentPage(currentPage - 1)}
              disabled={currentPage === 1}
              className="px-3 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <ChevronLeftIcon className="w-4 h-4" />
            </button>
            <span className="px-3 py-2 text-sm text-gray-700">
              Page {currentPage} of {totalPages}
            </span>
            <button
              onClick={() => setCurrentPage(currentPage + 1)}
              disabled={currentPage === totalPages}
              className="px-3 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
            >
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
              <h3 className="text-lg font-medium text-gray-900 mb-4">Create New RASP Project</h3>
              <form onSubmit={handleCreateProject} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Project Name</label>
                  <input
                    type="text"
                    required
                    value={createFormData.name}
                    onChange={(e) => setCreateFormData({ ...createFormData, name: e.target.value })}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Project Key</label>
                  <input
                    type="text"
                    required
                    value={createFormData.key}
                    onChange={(e) => setCreateFormData({ ...createFormData, key: e.target.value })}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Environment</label>
                  <select
                    required
                    value={createFormData.environment}
                    onChange={(e) => setCreateFormData({ ...createFormData, environment: e.target.value })}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  >
                    <option value="">Select Environment</option>
                    {environments.map((env) => (
                      <option key={env.value} value={env.value}>{env.label}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Repository URL (Optional)</label>
                  <input
                    type="url"
                    value={createFormData.repository_url}
                    onChange={(e) => setCreateFormData({ ...createFormData, repository_url: e.target.value })}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Branch</label>
                  <input
                    type="text"
                    value={createFormData.branch}
                    onChange={(e) => setCreateFormData({ ...createFormData, branch: e.target.value })}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>
                <div className="flex items-center justify-end space-x-3 pt-4">
                  <button
                    type="button"
                    onClick={() => setShowCreateModal(false)}
                    className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 border border-gray-300 rounded-md hover:bg-gray-200"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 text-sm font-medium text-white bg-blue-600 border border-transparent rounded-md hover:bg-blue-700"
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
              <h3 className="text-lg font-medium text-gray-900 mb-4">Duplicate Project: {selectedProject.name}</h3>
              <form onSubmit={handleDuplicateProject} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">New Project Name</label>
                  <input
                    type="text"
                    required
                    value={duplicateFormData.name}
                    onChange={(e) => setDuplicateFormData({ ...duplicateFormData, name: e.target.value })}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">New Project Key</label>
                  <input
                    type="text"
                    required
                    value={duplicateFormData.key}
                    onChange={(e) => setDuplicateFormData({ ...duplicateFormData, key: e.target.value })}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>
                <div className="flex items-center justify-end space-x-3 pt-4">
                  <button
                    type="button"
                    onClick={() => setShowDuplicateModal(false)}
                    className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 border border-gray-300 rounded-md hover:bg-gray-200"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 text-sm font-medium text-white bg-blue-600 border border-transparent rounded-md hover:bg-blue-700"
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

export default RASPProjects;
