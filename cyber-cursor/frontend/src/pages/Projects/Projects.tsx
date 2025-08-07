import React, { useState, useEffect } from 'react';
import EnhancedCard from '../../components/UI/EnhancedCard';
import EnhancedButton from '../../components/UI/EnhancedButton';
import EnhancedBadge from '../../components/UI/EnhancedBadge';
import EnhancedTabs from '../../components/UI/EnhancedTabs';
import {
  Folder, GitBranch, Upload, Search, Plus, Settings, Users, 
  Shield, Bug, Eye, Activity, Clock, FileText, Globe, Server,
  Download, Play, BarChart3, Filter, RefreshCw, Trash2, Edit
} from 'lucide-react';
import toast from 'react-hot-toast';

interface Project {
  id: number;
  name: string;
  key: string;
  description: string;
  project_type: 'sast' | 'dast' | 'rasp' | 'cloud' | 'general';
  status: 'active' | 'inactive' | 'archived' | 'deleted';
  repository_type?: 'git' | 'svn' | 'zip' | 'local';
  repository_url?: string;
  language?: string;
  framework?: string;
  tags?: string[];
  created_at: string;
  updated_at: string;
  last_scan?: string;
  last_sync?: string;
  created_by: number;
  owner_id: number;
  team_id?: number;
}

interface ProjectScan {
  id: number;
  project_id: number;
  scan_type: string;
  scan_name: string;
  status: string;
  progress: number;
  total_issues: number;
  critical_issues: number;
  high_issues: number;
  medium_issues: number;
  low_issues: number;
  started_at: string;
  completed_at?: string;
}

interface ProjectIssue {
  id: number;
  project_id: number;
  issue_type: string;
  severity: string;
  status: string;
  title: string;
  description?: string;
  file_path?: string;
  line_number?: number;
  created_at: string;
}

const Projects: React.FC = () => {
  const [activeTab, setActiveTab] = useState('overview');
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState<string>('all');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [selectedProject, setSelectedProject] = useState<Project | null>(null);

  const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

  // Mock data for demonstration
  const mockProjects: Project[] = [
    {
      id: 1,
      name: "Web Application Security",
      key: "web-app-security",
      description: "Comprehensive security analysis for web application",
      project_type: "sast",
      status: "active",
      repository_type: "git",
      repository_url: "https://github.com/example/web-app",
      language: "JavaScript",
      framework: "React",
      tags: ["web", "security", "react"],
      created_at: "2024-01-15T10:00:00Z",
      updated_at: "2024-01-15T10:00:00Z",
      last_scan: "2024-01-15T09:30:00Z",
      created_by: 1,
      owner_id: 1
    },
    {
      id: 2,
      name: "API Security Testing",
      key: "api-security-test",
      description: "Dynamic security testing for REST API",
      project_type: "dast",
      status: "active",
      repository_type: "git",
      repository_url: "https://github.com/example/api-service",
      language: "Python",
      framework: "FastAPI",
      tags: ["api", "security", "python"],
      created_at: "2024-01-14T15:00:00Z",
      updated_at: "2024-01-14T15:00:00Z",
      last_scan: "2024-01-14T14:30:00Z",
      created_by: 1,
      owner_id: 1
    },
    {
      id: 3,
      name: "Mobile App Protection",
      key: "mobile-app-protection",
      description: "Runtime application self-protection for mobile app",
      project_type: "rasp",
      status: "active",
      repository_type: "git",
      repository_url: "https://github.com/example/mobile-app",
      language: "Swift",
      framework: "iOS",
      tags: ["mobile", "rasp", "ios"],
      created_at: "2024-01-13T12:00:00Z",
      updated_at: "2024-01-13T12:00:00Z",
      last_scan: "2024-01-13T11:30:00Z",
      created_by: 1,
      owner_id: 1
    }
  ];

  const mockScans: ProjectScan[] = [
    {
      id: 1,
      project_id: 1,
      scan_type: "sast",
      scan_name: "Full Security Scan",
      status: "completed",
      progress: 100,
      total_issues: 15,
      critical_issues: 2,
      high_issues: 5,
      medium_issues: 6,
      low_issues: 2,
      started_at: "2024-01-15T09:00:00Z",
      completed_at: "2024-01-15T09:30:00Z"
    },
    {
      id: 2,
      project_id: 2,
      scan_type: "dast",
      scan_name: "API Vulnerability Scan",
      status: "completed",
      progress: 100,
      total_issues: 8,
      critical_issues: 1,
      high_issues: 3,
      medium_issues: 3,
      low_issues: 1,
      started_at: "2024-01-14T14:00:00Z",
      completed_at: "2024-01-14T14:30:00Z"
    }
  ];

  const mockIssues: ProjectIssue[] = [
    {
      id: 1,
      project_id: 1,
      issue_type: "vulnerability",
      severity: "critical",
      status: "open",
      title: "SQL Injection Vulnerability",
      description: "Potential SQL injection in user authentication",
      file_path: "src/auth/login.js",
      line_number: 45,
      created_at: "2024-01-15T09:30:00Z"
    },
    {
      id: 2,
      project_id: 1,
      issue_type: "vulnerability",
      severity: "high",
      status: "open",
      title: "Cross-Site Scripting (XSS)",
      description: "XSS vulnerability in user input handling",
      file_path: "src/components/UserInput.js",
      line_number: 23,
      created_at: "2024-01-15T09:30:00Z"
    }
  ];

  useEffect(() => {
    // Load mock data for demonstration
    setProjects(mockProjects);
    setLoading(false);
  }, []);

  const getProjectTypeIcon = (type: string) => {
    switch (type) {
      case 'sast': return <Bug className="h-4 w-4" />;
      case 'dast': return <Globe className="h-4 w-4" />;
      case 'rasp': return <Shield className="h-4 w-4" />;
      case 'cloud': return <Server className="h-4 w-4" />;
      default: return <Folder className="h-4 w-4" />;
    }
  };

  const getProjectTypeColor = (type: string) => {
    switch (type) {
      case 'sast': return 'info';
      case 'dast': return 'success';
      case 'rasp': return 'primary';
      case 'cloud': return 'warning';
      default: return 'default';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'success';
      case 'inactive': return 'warning';
      case 'archived': return 'default';
      case 'deleted': return 'danger';
      default: return 'default';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'danger';
      case 'high': return 'danger';
      case 'medium': return 'warning';
      case 'low': return 'primary';
      default: return 'default';
    }
  };

  const filteredProjects = projects.filter(project => {
    const matchesSearch = project.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         project.key.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         project.description?.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesType = filterType === 'all' || project.project_type === filterType;
    return matchesSearch && matchesType;
  });

  const handleCreateProject = () => {
    setShowCreateModal(true);
  };

  const handleUploadCode = (projectId: number) => {
    toast.success(`Upload code for project ${projectId}`);
  };

  const handleRunScan = (projectId: number) => {
    toast.success(`Starting scan for project ${projectId}`);
  };

  const handleViewProject = (project: Project) => {
    setSelectedProject(project);
    setActiveTab('details');
  };

  const tabs = [
    {
      id: 'overview',
      label: 'Overview',
      content: (
        <div className="space-y-6">
          {/* Search and Filter Bar */}
          <div className="flex flex-col md:flex-row gap-4">
            <div className="flex-1">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
                <input
                  type="text"
                  placeholder="Search projects..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 border border-gray-600 rounded-lg bg-gray-800 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-red-500"
                />
              </div>
            </div>
            <div className="flex gap-2">
              <select
                value={filterType}
                onChange={(e) => setFilterType(e.target.value)}
                className="px-4 py-2 border border-gray-600 rounded-lg bg-gray-800 text-white focus:outline-none focus:ring-2 focus:ring-red-500"
              >
                <option value="all">All Types</option>
                <option value="sast">SAST</option>
                <option value="dast">DAST</option>
                <option value="rasp">RASP</option>
                <option value="cloud">Cloud</option>
                <option value="general">General</option>
              </select>
              <EnhancedButton
                onClick={handleCreateProject}
                variant="primary"
                size="sm"
              >
                <Plus className="h-4 w-4 mr-2" />
                New Project
              </EnhancedButton>
            </div>
          </div>

          {/* Projects Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {filteredProjects.map((project) => (
              <EnhancedCard key={project.id} className="hover:shadow-lg transition-shadow">
                <div className="p-6">
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex items-center space-x-2">
                      {getProjectTypeIcon(project.project_type)}
                      <div>
                        <h3 className="text-lg font-semibold text-white">{project.name}</h3>
                        <p className="text-sm text-gray-400">{project.key}</p>
                      </div>
                    </div>
                    <EnhancedBadge variant={
                      project.project_type === 'sast' ? 'info' : 
                      project.project_type === 'dast' ? 'success' : 
                      project.project_type === 'rasp' ? 'primary' : 
                      project.project_type === 'cloud' ? 'warning' : 'default'
                    }>
                      {project.project_type.toUpperCase()}
                    </EnhancedBadge>
                  </div>
                  
                  <p className="text-gray-300 text-sm mb-4 line-clamp-2">
                    {project.description}
                  </p>
                  
                  <div className="space-y-2 mb-4">
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-400">Language:</span>
                      <span className="text-white">{project.language || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-400">Framework:</span>
                      <span className="text-white">{project.framework || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-400">Status:</span>
                      <EnhancedBadge variant={getStatusColor(project.status)} size="sm">
                        {project.status}
                      </EnhancedBadge>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-400">Last Scan:</span>
                      <span className="text-white">
                        {project.last_scan ? new Date(project.last_scan).toLocaleDateString() : 'Never'}
                      </span>
                    </div>
                  </div>
                  
                  {project.tags && project.tags.length > 0 && (
                    <div className="flex flex-wrap gap-1 mb-4">
                      {project.tags.slice(0, 3).map((tag, index) => (
                        <span
                          key={index}
                          className="px-2 py-1 bg-gray-700 text-gray-300 text-xs rounded"
                        >
                          {tag}
                        </span>
                      ))}
                      {project.tags.length > 3 && (
                        <span className="px-2 py-1 bg-gray-700 text-gray-300 text-xs rounded">
                          +{project.tags.length - 3}
                        </span>
                      )}
                    </div>
                  )}
                  
                  <div className="flex space-x-2">
                    <EnhancedButton
                      onClick={() => handleViewProject(project)}
                      variant="outline"
                      size="sm"
                      className="flex-1"
                    >
                      <Eye className="h-4 w-4 mr-1" />
                      View
                    </EnhancedButton>
                    <EnhancedButton
                      onClick={() => handleUploadCode(project.id)}
                      variant="outline"
                      size="sm"
                    >
                      <Upload className="h-4 w-4" />
                    </EnhancedButton>
                    <EnhancedButton
                      onClick={() => handleRunScan(project.id)}
                      variant="primary"
                      size="sm"
                    >
                      <Play className="h-4 w-4" />
                    </EnhancedButton>
                  </div>
                </div>
              </EnhancedCard>
            ))}
          </div>

          {filteredProjects.length === 0 && (
            <div className="text-center py-12">
              <Folder className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-300 mb-2">No projects found</h3>
              <p className="text-gray-400 mb-4">
                {searchTerm || filterType !== 'all' 
                  ? 'Try adjusting your search or filter criteria'
                  : 'Get started by creating your first project'
                }
              </p>
              {!searchTerm && filterType === 'all' && (
                <EnhancedButton
                  onClick={handleCreateProject}
                  variant="primary"
                >
                  <Plus className="h-4 w-4 mr-2" />
                  Create Project
                </EnhancedButton>
              )}
            </div>
          )}
        </div>
      )
    },
    {
      id: 'details',
      label: 'Project Details',
      content: selectedProject ? (
        <div className="space-y-6">
          {/* Project Header */}
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-2xl font-bold text-white">{selectedProject.name}</h2>
              <p className="text-gray-400">{selectedProject.description}</p>
            </div>
            <div className="flex space-x-2">
              <EnhancedButton variant="outline">
                <Edit className="h-4 w-4 mr-2" />
                Edit
              </EnhancedButton>
              <EnhancedButton variant="outline">
                <Settings className="h-4 w-4 mr-2" />
                Settings
              </EnhancedButton>
            </div>
          </div>

          {/* Project Info Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <EnhancedCard>
              <div className="p-6">
                <div className="flex items-center space-x-2 mb-4">
                  <GitBranch className="h-5 w-5 text-blue-500" />
                  <h3 className="text-lg font-semibold text-white">Repository</h3>
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <span className="text-gray-400">Type:</span>
                    <span className="text-white">{selectedProject.repository_type || 'N/A'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">URL:</span>
                    <span className="text-white truncate">{selectedProject.repository_url || 'N/A'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Language:</span>
                    <span className="text-white">{selectedProject.language || 'N/A'}</span>
                  </div>
                </div>
              </div>
            </EnhancedCard>

            <EnhancedCard>
              <div className="p-6">
                <div className="flex items-center space-x-2 mb-4">
                  <Activity className="h-5 w-5 text-green-500" />
                  <h3 className="text-lg font-semibold text-white">Activity</h3>
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <span className="text-gray-400">Last Scan:</span>
                    <span className="text-white">
                      {selectedProject.last_scan ? new Date(selectedProject.last_scan).toLocaleDateString() : 'Never'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Last Sync:</span>
                    <span className="text-white">
                      {selectedProject.last_sync ? new Date(selectedProject.last_sync).toLocaleDateString() : 'Never'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Created:</span>
                    <span className="text-white">{new Date(selectedProject.created_at).toLocaleDateString()}</span>
                  </div>
                </div>
              </div>
            </EnhancedCard>

            <EnhancedCard>
              <div className="p-6">
                <div className="flex items-center space-x-2 mb-4">
                  <Shield className="h-5 w-5 text-purple-500" />
                  <h3 className="text-lg font-semibold text-white">Security</h3>
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <span className="text-gray-400">Type:</span>
                    <EnhancedBadge variant={getProjectTypeColor(selectedProject.project_type)}>
                      {selectedProject.project_type.toUpperCase()}
                    </EnhancedBadge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Status:</span>
                    <EnhancedBadge variant={getStatusColor(selectedProject.status)}>
                      {selectedProject.status}
                    </EnhancedBadge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Issues:</span>
                    <span className="text-white">15</span>
                  </div>
                </div>
              </div>
            </EnhancedCard>
          </div>

          {/* Recent Scans */}
          <EnhancedCard>
            <div className="p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-white">Recent Scans</h3>
                <EnhancedButton variant="primary" size="sm">
                  <Play className="h-4 w-4 mr-2" />
                  New Scan
                </EnhancedButton>
              </div>
              <div className="space-y-4">
                {mockScans.filter(scan => scan.project_id === selectedProject.id).map((scan) => (
                  <div key={scan.id} className="flex items-center justify-between p-4 bg-gray-800 rounded-lg">
                    <div className="flex items-center space-x-4">
                      <div className="flex items-center space-x-2">
                        {getProjectTypeIcon(scan.scan_type)}
                        <span className="text-white font-medium">{scan.scan_name}</span>
                      </div>
                      <EnhancedBadge variant={scan.status === 'completed' ? 'success' : 'warning'}>
                        {scan.status}
                      </EnhancedBadge>
                    </div>
                    <div className="flex items-center space-x-4">
                      <div className="text-right">
                        <div className="text-sm text-gray-400">Issues Found</div>
                        <div className="text-white font-medium">{scan.total_issues}</div>
                      </div>
                      <div className="text-right">
                        <div className="text-sm text-gray-400">Duration</div>
                        <div className="text-white font-medium">
                          {scan.completed_at && scan.started_at 
                            ? `${Math.round((new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()) / 1000 / 60)}m`
                            : 'N/A'
                          }
                        </div>
                      </div>
                      <div className="text-right">
                        <div className="text-sm text-gray-400">Date</div>
                        <div className="text-white font-medium">
                          {new Date(scan.started_at).toLocaleDateString()}
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </EnhancedCard>

          {/* Recent Issues */}
          <EnhancedCard>
            <div className="p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-white">Recent Issues</h3>
                <EnhancedButton variant="outline" size="sm">
                  <Download className="h-4 w-4 mr-2" />
                  Export
                </EnhancedButton>
              </div>
              <div className="space-y-4">
                {mockIssues.filter(issue => issue.project_id === selectedProject.id).map((issue) => (
                  <div key={issue.id} className="flex items-center justify-between p-4 bg-gray-800 rounded-lg">
                    <div className="flex items-center space-x-4">
                      <EnhancedBadge variant={getSeverityColor(issue.severity)}>
                        {issue.severity.toUpperCase()}
                      </EnhancedBadge>
                      <div>
                        <div className="text-white font-medium">{issue.title}</div>
                        <div className="text-sm text-gray-400">
                          {issue.file_path && issue.line_number 
                            ? `${issue.file_path}:${issue.line_number}`
                            : 'No location specified'
                          }
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <EnhancedBadge variant={issue.status === 'open' ? 'danger' : 'success'}>
                        {issue.status}
                      </EnhancedBadge>
                      <span className="text-sm text-gray-400">
                        {new Date(issue.created_at).toLocaleDateString()}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </EnhancedCard>
        </div>
      ) : (
        <div className="text-center py-12">
          <Folder className="h-12 w-12 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-300 mb-2">No project selected</h3>
          <p className="text-gray-400">Select a project from the overview to view its details</p>
        </div>
      )
    }
  ];

  return (
    <div className="container mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Projects & Code Management</h1>
          <p className="text-gray-400">Create and manage security projects, upload source code, and track scan history</p>
        </div>
        <div className="flex space-x-3">
          <EnhancedButton variant="outline">
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </EnhancedButton>
          <EnhancedButton variant="primary" onClick={handleCreateProject}>
            <Plus className="h-4 w-4 mr-2" />
            New Project
          </EnhancedButton>
        </div>
      </div>

      {/* Tabs */}
      <EnhancedTabs
        tabs={tabs}
        activeTab={activeTab}
        onTabChange={setActiveTab}
        variant="default"
        size="md"
      />
    </div>
  );
};

export default Projects; 