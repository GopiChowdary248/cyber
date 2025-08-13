import React, { useState, useEffect, useCallback } from 'react';
import { motion } from 'framer-motion';
import {
  ShieldCheckIcon,
  GlobeAltIcon,
  CogIcon,
  PlusIcon,
  EyeIcon,
  PencilIcon,
  TrashIcon,
  ExclamationTriangleIcon,
  KeyIcon,
  ServerIcon,
  CheckCircleIcon,
  ArrowPathIcon,
  XCircleIcon,
  ClockIcon,
  MagnifyingGlassIcon,
  PlayIcon,
  DocumentDuplicateIcon,
  ChevronLeftIcon,
  ChevronRightIcon
} from '@heroicons/react/24/outline';

interface DASTProject {
  id: number;
  name: string;
  url: string;
  description?: string;
  scanType: 'full' | 'passive' | 'active' | 'custom';
  authentication?: {
    type: 'none' | 'basic' | 'form' | 'token';
    username?: string;
    password?: string;
  };
  lastScan?: {
    id: number;
    status: 'COMPLETED' | 'RUNNING' | 'FAILED' | 'PENDING';
    timestamp: string;
    duration?: string;
  };
  vulnerabilities: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  securityScore: number;
  createdBy: string;
  createdAt: string;
}

interface CreateProjectData {
  name: string;
  url: string;
  description?: string;
  scanType: 'full' | 'passive' | 'active' | 'custom';
  authentication?: {
    type: 'none' | 'basic' | 'form' | 'token';
    username?: string;
    password?: string;
  };
}

interface DuplicateProjectData {
  name: string;
  url: string;
}

const DASTProjects: React.FC = () => {
  const [projects, setProjects] = useState<DASTProject[]>([]);
  const [loading, setLoading] = useState(true);
  const [viewMode, setViewMode] = useState<'list' | 'cards'>('cards');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedScanType, setSelectedScanType] = useState<string>('all');
  const [selectedStatus, setSelectedStatus] = useState<string>('all');
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage] = useState(12);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showDuplicateModal, setShowDuplicateModal] = useState(false);
  const [selectedProject, setSelectedProject] = useState<DASTProject | null>(null);
  const [createFormData, setCreateFormData] = useState<CreateProjectData>({
    name: '',
    url: '',
    description: '',
    scanType: 'full',
    authentication: {
      type: 'none'
    }
  });
  const [duplicateFormData, setDuplicateFormData] = useState<DuplicateProjectData>({
    name: '',
    url: ''
  });
  const [totalProjects, setTotalProjects] = useState(0);
  const [totalPages, setTotalPages] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const mockProjects: DASTProject[] = [
    {
      id: 1,
      name: 'E-commerce Web App',
      url: 'https://demo-ecommerce.example.com',
      description: 'Main e-commerce application for online shopping',
      scanType: 'full',
      lastScan: {
        id: 101,
        status: 'COMPLETED',
        timestamp: '2025-08-10T10:30:00Z',
        duration: '3m 45s'
      },
      vulnerabilities: {
        critical: 2,
        high: 4,
        medium: 4,
        low: 2
      },
      securityScore: 75.5,
      createdBy: 'admin@example.com',
      createdAt: '2025-07-15T09:00:00Z'
    },
    {
      id: 2,
      name: 'Admin Portal',
      url: 'https://admin.example.com',
      description: 'Administrative interface for system management',
      scanType: 'active',
      authentication: {
        type: 'form',
        username: 'admin',
        password: '********'
      },
      lastScan: {
        id: 102,
        status: 'RUNNING',
        timestamp: '2025-08-10T09:15:00Z',
        duration: '1m 23s'
      },
      vulnerabilities: {
        critical: 1,
        high: 3,
        medium: 3,
        low: 1
      },
      securityScore: 68.2,
      createdBy: 'admin@example.com',
      createdAt: '2025-07-20T14:30:00Z'
    },
    {
      id: 3,
      name: 'API Gateway',
      url: 'https://api.example.com',
      description: 'REST API gateway for microservices',
      scanType: 'passive',
      lastScan: {
        id: 103,
        status: 'COMPLETED',
        timestamp: '2025-08-10T08:45:00Z',
        duration: '2m 12s'
      },
      vulnerabilities: {
        critical: 0,
        high: 1,
        medium: 2,
        low: 2
      },
      securityScore: 82.1,
      createdBy: 'dev@example.com',
      createdAt: '2025-07-25T11:15:00Z'
    }
  ];

  const fetchProjects = useCallback(async () => {
    try {
      setLoading(true);
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000));
      setProjects(mockProjects);
    } catch (error) {
      console.error('Error fetching projects:', error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchProjects();
  }, [fetchProjects]);

  const handleCreateProject = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      // Mock API call
      const newProject: DASTProject = {
        id: Date.now(),
        ...createFormData,
        vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0 },
        securityScore: 100,
        createdBy: 'current-user@example.com',
        createdAt: new Date().toISOString()
      };

      setProjects(prev => [newProject, ...prev]);
      setShowCreateModal(false);
      setCreateFormData({
        name: '',
        url: '',
        description: '',
        scanType: 'full',
        authentication: { type: 'none' }
      });
    } catch (err) {
      setError('Failed to create project');
    }
  };

  const handleDuplicateProject = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      if (!selectedProject) return;

      const duplicatedProject: DASTProject = {
        ...selectedProject,
        id: Date.now(),
        name: duplicateFormData.name,
        url: duplicateFormData.url,
        createdAt: new Date().toISOString(),
        lastScan: undefined,
        vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0 },
        securityScore: 100
      };

      setProjects(prev => [duplicatedProject, ...prev]);
      setShowDuplicateModal(false);
      setDuplicateFormData({ name: '', url: '' });
      setSelectedProject(null);
    } catch (err) {
      setError('Failed to duplicate project');
    }
  };

  const handleDeleteProject = async (projectId: number) => {
    if (window.confirm('Are you sure you want to delete this project?')) {
      try {
        setProjects(prev => prev.filter(project => project.id !== projectId));
      } catch (err) {
        setError('Failed to delete project');
      }
    }
  };

  const handleStartScan = async (projectId: number) => {
    try {
      // Mock scan start
      setProjects(prev => prev.map(project => {
        if (project.id === projectId) {
          return {
            ...project,
            lastScan: {
              id: Date.now(),
              status: 'RUNNING',
              timestamp: new Date().toISOString(),
              duration: '0s'
            }
          };
        }
        return project;
      }));
    } catch (err) {
      setError('Failed to start scan');
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'COMPLETED': return 'text-green-600 bg-green-50';
      case 'RUNNING': return 'text-blue-600 bg-blue-50';
      case 'FAILED': return 'text-red-600 bg-red-50';
      case 'PENDING': return 'text-gray-600 bg-gray-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'COMPLETED': return <CheckCircleIcon className="w-4 h-4" />;
      case 'RUNNING': return <ArrowPathIcon className="w-4 h-4 animate-spin" />;
      case 'FAILED': return <XCircleIcon className="w-4 h-4" />;
      case 'PENDING': return <ClockIcon className="w-4 h-4" />;
      default: return <ClockIcon className="w-4 h-4" />;
    }
  };

  const getScanTypeColor = (scanType: string) => {
    switch (scanType) {
      case 'full': return 'text-purple-600 bg-purple-50';
      case 'passive': return 'text-blue-600 bg-blue-50';
      case 'active': return 'text-orange-600 bg-orange-50';
      case 'custom': return 'text-gray-600 bg-gray-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-50';
      case 'high': return 'text-orange-600 bg-orange-50';
      case 'medium': return 'text-yellow-600 bg-yellow-50';
      case 'low': return 'text-blue-600 bg-blue-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <ArrowPathIcon className="w-8 h-8 animate-spin text-blue-600" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header with Create Button */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold text-gray-900">DAST Projects</h2>
          <p className="text-gray-600">Manage your dynamic application security testing projects</p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
        >
          <PlusIcon className="w-4 h-4 mr-2" />
          New Project
        </button>
      </div>

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
              value={selectedScanType}
              onChange={(e) => setSelectedScanType(e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="all">All Scan Types</option>
              <option value="full">Full Scan</option>
              <option value="passive">Passive Scan</option>
              <option value="active">Active Scan</option>
              <option value="custom">Custom Scan</option>
            </select>
            <select
              value={selectedStatus}
              onChange={(e) => setSelectedStatus(e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="all">All Statuses</option>
              <option value="completed">Completed</option>
              <option value="running">Running</option>
              <option value="failed">Failed</option>
              <option value="pending">Pending</option>
              <option value="none">No Scans</option>
            </select>
            <div className="flex border border-gray-300 rounded-md">
              <button
                onClick={() => setViewMode('cards')}
                className={`px-3 py-2 text-sm font-medium ${
                  viewMode === 'cards'
                    ? 'bg-blue-600 text-white'
                    : 'bg-white text-gray-700 hover:bg-gray-50'
                } border-r border-gray-300`}
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

      {/* Projects Grid/List */}
      {projects.length === 0 ? (
        <div className="text-center py-12">
          <GlobeAltIcon className="w-12 h-12 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">No projects found</h3>
          <p className="text-gray-600 mb-4">
            {searchTerm || selectedScanType !== 'all' || selectedStatus !== 'all'
              ? 'Try adjusting your search criteria'
              : 'Get started by creating your first DAST project'}
          </p>
          {!searchTerm && selectedScanType === 'all' && selectedStatus === 'all' && (
            <button
              onClick={() => setShowCreateModal(true)}
              className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700"
            >
              <PlusIcon className="w-4 h-4 mr-2" />
              Create Project
            </button>
          )}
        </div>
      ) : (
        <>
          {viewMode === 'cards' ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {projects.map((project) => (
                <div key={project.id} className="bg-white rounded-lg shadow-sm border border-gray-200 hover:shadow-md transition-shadow">
                  <div className="p-6">
                    <div className="flex items-start justify-between mb-4">
                      <div className="flex-1">
                        <h3 className="text-lg font-semibold text-gray-900 truncate">{project.name}</h3>
                        <p className="text-sm text-gray-500 truncate">{project.url}</p>
                      </div>
                      <div className="ml-2 flex-shrink-0">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getScanTypeColor(project.scanType)}`}>
                          {project.scanType}
                        </span>
                      </div>
                    </div>

                    {project.description && (
                      <p className="text-sm text-gray-600 mb-4 line-clamp-2">{project.description}</p>
                    )}

                    <div className="space-y-3 mb-4">
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-gray-600">Security Score</span>
                        <span className={`text-sm font-semibold ${
                          project.securityScore >= 80 ? 'text-green-600' :
                          project.securityScore >= 60 ? 'text-yellow-600' : 'text-red-600'
                        }`}>
                          {project.securityScore}/100
                        </span>
                      </div>
                      
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-gray-600">Vulnerabilities</span>
                        <div className="flex space-x-1">
                          {project.vulnerabilities.critical > 0 && (
                            <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-red-100 text-red-800">
                              {project.vulnerabilities.critical} Critical
                            </span>
                          )}
                          {project.vulnerabilities.high > 0 && (
                            <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-orange-100 text-orange-800">
                              {project.vulnerabilities.high} High
                            </span>
                          )}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center justify-between text-sm text-gray-500 mb-4">
                      <span>Created {new Date(project.createdAt).toLocaleDateString()}</span>
                      <span>by {project.createdBy}</span>
                    </div>

                    <div className="flex items-center justify-between">
                      <div className="flex space-x-2">
                        <button
                          onClick={() => handleStartScan(project.id)}
                          disabled={project.lastScan?.status === 'RUNNING'}
                          className="inline-flex items-center px-3 py-1.5 border border-transparent text-xs font-medium rounded text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50"
                        >
                          <PlayIcon className="w-3 h-3 mr-1" />
                          {project.lastScan?.status === 'RUNNING' ? 'Scanning...' : 'Start Scan'}
                        </button>
                        <button
                          onClick={() => {
                            setSelectedProject(project);
                            setDuplicateFormData({ name: `${project.name} Copy`, url: project.url });
                            setShowDuplicateModal(true);
                          }}
                          className="inline-flex items-center px-3 py-1.5 border border-gray-300 text-xs font-medium rounded text-gray-700 bg-white hover:bg-gray-50"
                        >
                          <DocumentDuplicateIcon className="w-3 h-3 mr-1" />
                          Duplicate
                        </button>
                      </div>
                      <div className="flex space-x-1">
                        <button className="text-gray-400 hover:text-gray-600">
                          <EyeIcon className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => handleDeleteProject(project.id)}
                          className="text-red-400 hover:text-red-600"
                        >
                          <TrashIcon className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="bg-white shadow-sm border border-gray-200 rounded-lg overflow-hidden">
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Project</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">URL</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Scan Type</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Security Score</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Vulnerabilities</th>
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
                            <div className="text-sm text-gray-500">by {project.createdBy}</div>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="text-sm text-gray-900 truncate max-w-xs">{project.url}</div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getScanTypeColor(project.scanType)}`}>
                            {project.scanType}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`text-sm font-semibold ${
                            project.securityScore >= 80 ? 'text-green-600' :
                            project.securityScore >= 60 ? 'text-yellow-600' : 'text-red-600'
                          }`}>
                            {project.securityScore}/100
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex space-x-1">
                            {project.vulnerabilities.critical > 0 && (
                              <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-red-100 text-red-800">
                                {project.vulnerabilities.critical}
                              </span>
                            )}
                            {project.vulnerabilities.high > 0 && (
                              <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-orange-100 text-orange-800">
                                {project.vulnerabilities.high}
                              </span>
                            )}
                            {project.vulnerabilities.medium > 0 && (
                              <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                                {project.vulnerabilities.medium}
                              </span>
                            )}
                            {project.vulnerabilities.low > 0 && (
                              <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                                {project.vulnerabilities.low}
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          {project.lastScan ? (
                            <div className="flex items-center">
                              <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(project.lastScan.status)}`}>
                                {getStatusIcon(project.lastScan.status)}
                                <span className="ml-1">{project.lastScan.status}</span>
                              </span>
                            </div>
                          ) : (
                            <span className="text-sm text-gray-500">No scans</span>
                          )}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                          <div className="flex space-x-2">
                            <button
                              onClick={() => handleStartScan(project.id)}
                              disabled={project.lastScan?.status === 'RUNNING'}
                              className="text-blue-600 hover:text-blue-900 disabled:opacity-50"
                            >
                              {project.lastScan?.status === 'RUNNING' ? 'Scanning...' : 'Scan'}
                            </button>
                            <button
                              onClick={() => {
                                setSelectedProject(project);
                                setDuplicateFormData({ name: `${project.name} Copy`, url: project.url });
                                setShowDuplicateModal(true);
                              }}
                              className="text-gray-600 hover:text-gray-900"
                            >
                              Duplicate
                            </button>
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
                  onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
                  disabled={currentPage === 1}
                  className="px-3 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50"
                >
                  <ChevronLeftIcon className="w-4 h-4" />
                </button>
                <span className="px-3 py-2 text-sm text-gray-700">
                  Page {currentPage} of {totalPages}
                </span>
                <button
                  onClick={() => setCurrentPage(prev => Math.min(prev + 1, totalPages))}
                  disabled={currentPage === totalPages}
                  className="px-3 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50"
                >
                  <ChevronRightIcon className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}
        </>
      )}

      {/* Create Project Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Create New DAST Project</h3>
              <form onSubmit={handleCreateProject} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Project Name</label>
                  <input
                    type="text"
                    required
                    value={createFormData.name}
                    onChange={(e) => setCreateFormData(prev => ({ ...prev, name: e.target.value }))}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Target URL</label>
                  <input
                    type="url"
                    required
                    value={createFormData.url}
                    onChange={(e) => setCreateFormData(prev => ({ ...prev, url: e.target.value }))}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Description (Optional)</label>
                  <textarea
                    value={createFormData.description}
                    onChange={(e) => setCreateFormData(prev => ({ ...prev, description: e.target.value }))}
                    rows={3}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Scan Type</label>
                  <select
                    value={createFormData.scanType}
                    onChange={(e) => setCreateFormData(prev => ({ ...prev, scanType: e.target.value as any }))}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  >
                    <option value="full">Full Scan</option>
                    <option value="passive">Passive Scan</option>
                    <option value="active">Active Scan</option>
                    <option value="custom">Custom Scan</option>
                  </select>
                </div>
                <div className="flex justify-end space-x-3 pt-4">
                  <button
                    type="button"
                    onClick={() => setShowCreateModal(false)}
                    className="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 bg-white hover:bg-gray-50"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 border border-transparent rounded-md text-sm font-medium text-white bg-blue-600 hover:bg-blue-700"
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
      {showDuplicateModal && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Duplicate Project</h3>
              <form onSubmit={handleDuplicateProject} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Project Name</label>
                  <input
                    type="text"
                    required
                    value={duplicateFormData.name}
                    onChange={(e) => setDuplicateFormData(prev => ({ ...prev, name: e.target.value }))}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Target URL</label>
                  <input
                    type="url"
                    required
                    value={duplicateFormData.url}
                    onChange={(e) => setDuplicateFormData(prev => ({ ...prev, url: e.target.value }))}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>
                <div className="flex justify-end space-x-3 pt-4">
                  <button
                    type="button"
                    onClick={() => setShowDuplicateModal(false)}
                    className="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 bg-white hover:bg-gray-50"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 border border-transparent rounded-md text-sm font-medium text-white bg-blue-600 hover:bg-blue-700"
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

export default DASTProjects;
