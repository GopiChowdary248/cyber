import React, { useState, useEffect } from 'react';
import { 
  Code, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  TrendingUp, 
  Shield,
  FileText,
  BarChart3,
  Settings,
  RefreshCw,
  Play,
  Pause,
  Square,
  Download,
  Upload,
  Eye,
  EyeOff,
  Filter,
  Search,
  Plus,
  Trash2,
  Edit,
  Copy,
  ExternalLink,
  Activity,
  Zap,
  Target,
  Bug,
  Lock,
  Unlock,
  AlertCircle,
  Info,
  HelpCircle,
  MoreVertical
} from 'lucide-react';
import { sastService } from '../../services/sastService';
import { integrationService } from '../../services/integrationService';

interface SASTProject {
  id: string;
  name: string;
  description: string;
  language: string;
  framework: string;
  status: 'active' | 'scanning' | 'completed' | 'failed' | 'paused';
  last_scan: string;
  vulnerabilities_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  health_score: number;
  scan_duration?: number;
  code_coverage?: number;
  branch?: string;
  repository_url?: string;
}

interface SASTScan {
  id: string;
  project_id: string;
  project_name: string;
  status: 'running' | 'completed' | 'failed' | 'paused' | 'queued';
  start_time: string;
  end_time?: string;
  duration?: number;
  vulnerabilities_found: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  progress: number;
  scan_type: 'full' | 'incremental' | 'quick';
  engine_version: string;
  rules_applied: number;
}

interface SASTVulnerability {
  id: string;
  project_id: string;
  scan_id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  cwe_id?: string;
  cve_id?: string;
  file_path: string;
  line_number: number;
  function_name?: string;
  code_snippet: string;
  remediation: string;
  status: 'open' | 'in_progress' | 'resolved' | 'false_positive';
  created_at: string;
  updated_at: string;
  assigned_to?: string;
  tags: string[];
  cvss_score?: number;
  exploitability?: string;
  impact: string;
}

interface SASTMetrics {
  total_projects: number;
  active_scans: number;
  total_vulnerabilities: number;
  critical_vulnerabilities: number;
  high_vulnerabilities: number;
  medium_vulnerabilities: number;
  low_vulnerabilities: number;
  average_scan_duration: number;
  code_coverage_average: number;
  health_score_average: number;
  vulnerabilities_trend: {
    date: string;
    critical: number;
    high: number;
    medium: number;
    low: number;
  }[];
}

const SASTDashboard: React.FC = () => {
  const [projects, setProjects] = useState<SASTProject[]>([]);
  const [scans, setScans] = useState<SASTScan[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<SASTVulnerability[]>([]);
  const [metrics, setMetrics] = useState<SASTMetrics | null>(null);
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefhing] = useState(false);
  const [selectedProject, setSelectedProject] = useState<string | null>(null);
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [viewMode, setViewMode] = useState<'overview' | 'projects' | 'scans' | 'vulnerabilities'>('overview');
  const [lastUpdate, setLastUpdate] = useState<string>('');

  useEffect(() => {
    loadSASTData();
    const interval = setInterval(loadSASTData, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, []);

  const loadSASTData = async () => {
    try {
      setLoading(true);
      const [projectsData, statisticsData, vulnerabilitiesData, dashboardData] = await Promise.all([
        sastService.getProjects(),
        sastService.getStatistics(),
        sastService.getVulnerabilities(),
        sastService.getDashboard()
      ]);

      // Convert service response types to local interface types
      const convertedProjects: SASTProject[] = (Array.isArray(projectsData) ? projectsData : []).map((project: any) => ({
        id: project.id || '',
        name: project.name || '',
        description: project.description || '',
        language: project.language || 'Unknown',
        framework: 'Unknown', // Default value since it's not in the service response
        status: 'active' as const, // Default status
        last_scan: project.last_analysis || '',
        vulnerabilities_count: project.vulnerability_count || 0,
        critical_count: 0, // These would need to be calculated from vulnerabilities
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        health_score: 0, // This would need to be calculated
        scan_duration: 0,
        code_coverage: project.coverage || 0,
        branch: project.branch || 'main',
        repository_url: project.repository_url || ''
      }));

      const convertedScans: SASTScan[] = ((statisticsData as any).recent_scans || []).map((scan: any) => ({
        id: scan.id || 'unknown',
        project_id: scan.project_id || 'unknown',
        project_name: 'Unknown Project', // Would need to be looked up
        status: 'completed' as const, // Default status
        start_time: scan.started_at || '',
        end_time: scan.completed_at,
        duration: scan.duration,
        vulnerabilities_found: scan.vulnerabilities_found || 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        progress: scan.progress || 100,
        scan_type: 'full' as const,
        engine_version: '1.0',
        rules_applied: 0
      }));

      const convertedVulnerabilities: SASTVulnerability[] = ((vulnerabilitiesData as any).vulnerabilities || []).map((vuln: any) => ({
        id: vuln.id,
        project_id: vuln.project_id,
        scan_id: vuln.scan_id || 'unknown',
        severity: vuln.severity.toLowerCase() as any,
        title: vuln.message,
        description: vuln.description || '',
        cwe_id: vuln.cwe_id,
        cve_id: undefined,
        file_path: vuln.file_path,
        line_number: vuln.line_number,
        function_name: undefined,
        code_snippet: '',
        remediation: '',
        status: vuln.status.toLowerCase() as any,
        created_at: vuln.created_at || new Date().toISOString(),
        updated_at: vuln.updated_at || new Date().toISOString(),
        assigned_to: vuln.assignee,
        tags: [],
        cvss_score: vuln.cvss_score,
        exploitability: undefined,
        impact: 'Unknown'
      }));

      setProjects(convertedProjects);
      setScans(convertedScans);
      setVulnerabilities(convertedVulnerabilities);
      setMetrics({
        total_projects: (dashboardData as any).total_projects || 0,
        active_scans: (dashboardData as any).active_scans || 0,
        total_vulnerabilities: (dashboardData as any).vulnerabilities || 0,
        critical_vulnerabilities: (dashboardData as any).critical_issues || 0,
        high_vulnerabilities: (dashboardData as any).high_issues || 0,
        medium_vulnerabilities: (dashboardData as any).medium_issues || 0,
        low_vulnerabilities: (dashboardData as any).low_issues || 0,
        average_scan_duration: (dashboardData as any).average_scan_duration || 0,
        code_coverage_average: (dashboardData as any).coverage_percentage || 0,
        health_score_average: Number((dashboardData as any).security_rating) || 0,
        vulnerabilities_trend: []
      });
      setLastUpdate(new Date().toLocaleTimeString());
    } catch (error) {
      console.error('Error loading SAST data:', error);
    } finally {
      setLoading(false);
    }
  };

  const onRefresh = async () => {
    setRefhing(true);
    await loadSASTData();
    setRefhing(false);
  };

  const startScan = async (projectId: string) => {
    try {
      await sastService.startScan(projectId);
      await loadSASTData(); // Refresh data
    } catch (error) {
      console.error('Error starting scan:', error);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
      case 'completed':
      case 'running':
        return 'text-green-600 bg-green-100 border-green-200';
      case 'scanning':
        return 'text-blue-600 bg-blue-100 border-blue-200';
      case 'paused':
      case 'queued':
        return 'text-yellow-600 bg-yellow-100 border-yellow-200';
      case 'failed':
        return 'text-red-600 bg-red-100 border-red-200';
      default:
        return 'text-gray-600 bg-gray-100 border-gray-200';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'text-red-600 bg-red-100 border-red-200';
      case 'high':
        return 'text-orange-600 bg-orange-100 border-orange-200';
      case 'medium':
        return 'text-yellow-600 bg-yellow-100 border-yellow-200';
      case 'low':
        return 'text-blue-600 bg-blue-100 border-blue-200';
      case 'info':
        return 'text-gray-600 bg-gray-100 border-gray-200';
      default:
        return 'text-gray-600 bg-gray-100 border-gray-200';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active':
      case 'completed':
        return <CheckCircle className="w-4 h-4" />;
      case 'scanning':
      case 'running':
        return <Activity className="w-4 h-4" />;
      case 'paused':
        return <Pause className="w-4 h-4" />;
      case 'failed':
        return <AlertTriangle className="w-4 h-4" />;
      case 'queued':
        return <Clock className="w-4 h-4" />;
      default:
        return <Clock className="w-4 h-4" />;
    }
  };

  const filteredProjects = projects.filter(project => {
    if (selectedProject && project.id !== selectedProject) return false;
    if (searchTerm && !project.name.toLowerCase().includes(searchTerm.toLowerCase())) return false;
    return true;
  });

  const filteredVulnerabilities = vulnerabilities.filter(vuln => {
    if (selectedProject && vuln.project_id !== selectedProject) return false;
    if (selectedSeverity !== 'all' && vuln.severity !== selectedSeverity) return false;
    if (searchTerm && !vuln.title.toLowerCase().includes(searchTerm.toLowerCase())) return false;
    return true;
  });

  const activeScans = scans.filter(scan => scan.status === 'running');
  const completedScans = scans.filter(scan => scan.status === 'completed');
  const failedScans = scans.filter(scan => scan.status === 'failed');
  const pausedScans = scans.filter(scan => scan.status === 'paused');
  const queuedScans = scans.filter(scan => scan.status === 'queued');

  return (
    <div className="min-h-screen bg-gray-50 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <div className="p-3 bg-blue-100 rounded-lg">
                <Code className="w-8 h-8 text-blue-600" />
              </div>
              <div>
                <h1 className="text-3xl font-bold text-gray-900">SAST Dashboard</h1>
                <p className="text-gray-600 mt-1">Static Application Security Testing & Code Analysis</p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <div className="text-right">
                <p className="text-sm text-gray-500">Last Updated</p>
                <p className="text-sm font-medium">{lastUpdate || 'Never'}</p>
              </div>
              <button
                onClick={onRefresh}
                disabled={refreshing}
                className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
              >
                <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
                <span>Refresh</span>
              </button>
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="mb-6">
          <nav className="flex space-x-8 border-b border-gray-200">
            {[
              { id: 'overview', label: 'Overview', icon: BarChart3 },
              { id: 'projects', label: 'Projects', icon: FileText },
              { id: 'scans', label: 'Scans', icon: Activity },
              { id: 'vulnerabilities', label: 'Vulnerabilities', icon: Bug }
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setViewMode(tab.id as any)}
                className={`flex items-center space-x-2 py-2 px-1 border-b-2 font-medium text-sm ${
                  viewMode === tab.id
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <tab.icon className="w-4 h-4" />
                <span>{tab.label}</span>
              </button>
            ))}
          </nav>
        </div>

        {/* Overview Dashboard */}
        {viewMode === 'overview' && (
          <div className="space-y-6">
            {/* Metrics Cards */}
            {metrics && (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <div className="bg-white p-6 rounded-lg shadow-sm border">
                  <div className="flex items-center">
                    <div className="p-2 bg-blue-100 rounded-lg">
                      <FileText className="w-6 h-6 text-blue-600" />
                    </div>
                    <div className="ml-4">
                      <p className="text-sm font-medium text-gray-600">Total Projects</p>
                      <p className="text-2xl font-bold text-gray-900">{metrics.total_projects}</p>
                    </div>
                  </div>
                </div>
                
                <div className="bg-white p-6 rounded-lg shadow-sm border">
                  <div className="flex items-center">
                    <div className="p-2 bg-green-100 rounded-lg">
                      <Activity className="w-6 h-6 text-green-600" />
                    </div>
                    <div className="ml-4">
                      <p className="text-sm font-medium text-gray-600">Active Scans</p>
                      <p className="text-2xl font-bold text-gray-900">{metrics.active_scans}</p>
                    </div>
                  </div>
                </div>
                
                <div className="bg-white p-6 rounded-lg shadow-sm border">
                  <div className="flex items-center">
                    <div className="p-2 bg-red-100 rounded-lg">
                      <AlertTriangle className="w-6 h-6 text-red-600" />
                    </div>
                    <div className="ml-4">
                      <p className="text-sm font-medium text-gray-600">Total Vulnerabilities</p>
                      <p className="text-2xl font-bold text-gray-900">{metrics.total_vulnerabilities}</p>
                    </div>
                  </div>
                </div>
                
                <div className="bg-white p-6 rounded-lg shadow-sm border">
                  <div className="flex items-center">
                    <div className="p-2 bg-yellow-100 rounded-lg">
                      <TrendingUp className="w-6 h-6 text-yellow-600" />
                    </div>
                    <div className="ml-4">
                      <p className="text-sm font-medium text-gray-600">Health Score</p>
                      <p className="text-2xl font-bold text-gray-900">{metrics.health_score_average}%</p>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Vulnerability Distribution */}
            {metrics && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="bg-white p-6 rounded-lg shadow-sm border">
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">Vulnerability Distribution</h3>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                        <span className="text-sm font-medium">Critical</span>
                      </div>
                      <span className="text-lg font-bold text-red-600">{metrics.critical_vulnerabilities}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <div className="w-3 h-3 bg-orange-500 rounded-full"></div>
                        <span className="text-sm font-medium">High</span>
                      </div>
                      <span className="text-lg font-bold text-orange-600">{metrics.high_vulnerabilities}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
                        <span className="text-sm font-medium">Medium</span>
                      </div>
                      <span className="text-lg font-bold text-yellow-600">{metrics.medium_vulnerabilities}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <div className="w-3 h-3 bg-blue-500 rounded-full"></div>
                        <span className="text-sm font-medium">Low</span>
                      </div>
                      <span className="text-lg font-bold text-blue-600">{metrics.low_vulnerabilities}</span>
                    </div>
                  </div>
                </div>
                
                <div className="bg-white p-6 rounded-lg shadow-sm border">
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">Performance Metrics</h3>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium text-gray-600">Avg Scan Duration</span>
                      <span className="text-lg font-bold text-gray-900">{metrics.average_scan_duration}s</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium text-gray-600">Code Coverage</span>
                      <span className="text-lg font-bold text-gray-900">{metrics.code_coverage_average}%</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium text-gray-600">Health Score</span>
                      <span className="text-lg font-bold text-gray-900">{metrics.health_score_average}%</span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Recent Activity */}
            <div className="bg-white rounded-lg shadow-sm border">
              <div className="p-6 border-b border-gray-200">
                <h3 className="text-lg font-semibold text-gray-900">Recent Activity</h3>
              </div>
              <div className="p-6">
                <div className="space-y-4">
                  {scans.slice(0, 5).map((scan) => (
                    <div key={scan.id} className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                      <div className="flex items-center space-x-4">
                        <div className={`p-2 rounded-lg ${getStatusColor(scan.status)}`}>
                          {getStatusIcon(scan.status)}
                        </div>
                        <div>
                          <p className="font-medium text-gray-900">{scan.project_name}</p>
                          <p className="text-sm text-gray-500">
                            {scan.scan_type} scan - {scan.status}
                          </p>
                        </div>
                      </div>
                      <div className="text-right">
                        <p className="text-sm text-gray-500">{scan.start_time}</p>
                        <p className="text-sm font-medium text-gray-900">
                          {scan.vulnerabilities_found} vulnerabilities
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Projects View */}
        {viewMode === 'projects' && (
          <div className="space-y-6">
            {/* Filters and Search */}
            <div className="bg-white p-6 rounded-lg shadow-sm border">
              <div className="flex flex-col sm:flex-row gap-4">
                <div className="flex-1">
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
                    <input
                      type="text"
                      placeholder="Search projects..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                  </div>
                </div>
                <div className="flex space-x-2">
                  <select
                    value={selectedProject || ''}
                    onChange={(e) => setSelectedProject(e.target.value || null)}
                    className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  >
                    <option value="">All Projects</option>
                    {projects.map(project => (
                      <option key={project.id} value={project.id}>{project.name}</option>
                    ))}
                  </select>
                  <button className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
                    <Plus className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>

            {/* Projects Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {filteredProjects.map((project) => (
                <div key={project.id} className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
                  <div className="flex items-start justify-between mb-4">
                    <div className="p-3 bg-blue-100 rounded-lg">
                      <Code className="w-6 h-6 text-blue-600" />
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getStatusColor(project.status)}`}>
                        {project.status}
                      </span>
                    </div>
                  </div>
                  
                  <h3 className="text-lg font-semibold text-gray-900 mb-2">{project.name}</h3>
                  <p className="text-sm text-gray-600 mb-4">{project.description}</p>
                  
                  <div className="space-y-2 mb-4">
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-gray-500">Language:</span>
                      <span className="font-medium text-gray-900">{project.language}</span>
                    </div>
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-gray-500">Framework:</span>
                      <span className="font-medium text-gray-900">{project.framework}</span>
                    </div>
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-gray-500">Health Score:</span>
                      <span className="font-medium text-gray-900">{project.health_score}%</span>
                    </div>
                  </div>
                  
                  <div className="grid grid-cols-2 gap-2 mb-4">
                    <div className="text-center p-2 bg-red-50 rounded">
                      <p className="text-sm font-bold text-red-600">{project.critical_count}</p>
                      <p className="text-xs text-red-500">Critical</p>
                    </div>
                    <div className="text-center p-2 bg-orange-50 rounded">
                      <p className="text-sm font-bold text-orange-600">{project.high_count}</p>
                      <p className="text-xs text-orange-500">High</p>
                    </div>
                  </div>
                  
                  <div className="flex space-x-2">
                    <button
                      onClick={() => startScan(project.id)}
                      disabled={project.status === 'scanning'}
                      className="flex-1 px-3 py-2 bg-blue-600 text-white text-sm rounded hover:bg-blue-700 disabled:opacity-50"
                    >
                      <Play className="w-4 h-4 mr-1" />
                      Scan
                    </button>
                    <button className="px-3 py-2 border border-gray-300 text-gray-700 text-sm rounded hover:bg-gray-50">
                      <Settings className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Scans View */}
        {viewMode === 'scans' && (
          <div className="space-y-6">
            {/* Scan Statistics */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-white p-6 rounded-lg shadow-sm border">
                <div className="flex items-center">
                  <div className="p-2 bg-blue-100 rounded-lg">
                    <Activity className="w-6 h-6 text-blue-600" />
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-600">Active Scans</p>
                    <p className="text-2xl font-bold text-blue-600">{activeScans.length}</p>
                  </div>
                </div>
              </div>
              
              <div className="bg-white p-6 rounded-lg shadow-sm border">
                <div className="flex items-center">
                  <div className="p-2 bg-green-100 rounded-lg">
                    <CheckCircle className="w-6 h-6 text-green-600" />
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-600">Completed</p>
                    <p className="text-2xl font-bold text-green-600">{completedScans.length}</p>
                  </div>
                </div>
              </div>
              
              <div className="bg-white p-6 rounded-lg shadow-sm border">
                <div className="flex items-center">
                  <div className="p-2 bg-red-100 rounded-lg">
                    <AlertTriangle className="w-6 h-6 text-red-600" />
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-600">Failed</p>
                    <p className="text-2xl font-bold text-red-600">{failedScans.length}</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Scans Table */}
            <div className="bg-white rounded-lg shadow-sm border">
              <div className="p-6 border-b border-gray-200">
                <h3 className="text-lg font-semibold text-gray-900">All Scans</h3>
              </div>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Project
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Status
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Type
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Vulnerabilities
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Duration
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Actions
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {scans.map((scan) => (
                      <tr key={scan.id} className="hover:bg-gray-50">
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div>
                            <div className="text-sm font-medium text-gray-900">{scan.project_name}</div>
                            <div className="text-sm text-gray-500">{scan.start_time}</div>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(scan.status)}`}>
                            {getStatusIcon(scan.status)}
                            <span className="ml-1 capitalize">{scan.status}</span>
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 capitalize">
                          {scan.scan_type}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="text-sm text-gray-900">{scan.vulnerabilities_found}</div>
                          <div className="text-sm text-gray-500">
                            {scan.critical_count}C {scan.high_count}H {scan.medium_count}M {scan.low_count}L
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          {scan.duration ? `${scan.duration}s` : '-'}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                          <div className="flex space-x-2">
                            {scan.status === 'running' && (
                              <>
                                <button
                                  onClick={() => {/* No pause/stop logic here as per new_code */}}
                                  className="text-yellow-600 hover:text-yellow-900"
                                >
                                  <Pause className="w-4 h-4" />
                                </button>
                                <button
                                  onClick={() => {/* No pause/stop logic here as per new_code */}}
                                  className="text-red-600 hover:text-red-900"
                                >
                                  <Square className="w-4 h-4" />
                                </button>
                              </>
                            )}
                            {scan.status === 'paused' && (
                              <button
                                onClick={() => startScan(scan.project_id)}
                                className="text-green-600 hover:text-green-900"
                              >
                                <Play className="w-4 h-4" />
                              </button>
                            )}
                            <button className="text-blue-600 hover:text-blue-900">
                              <Eye className="w-4 h-4" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* Vulnerabilities View */}
        {viewMode === 'vulnerabilities' && (
          <div className="space-y-6">
            {/* Filters */}
            <div className="bg-white p-6 rounded-lg shadow-sm border">
              <div className="flex flex-col sm:flex-row gap-4">
                <div className="flex-1">
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
                    <input
                      type="text"
                      placeholder="Search vulnerabilities..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                  </div>
                </div>
                <div className="flex space-x-2">
                  <select
                    value={selectedProject || ''}
                    onChange={(e) => setSelectedProject(e.target.value || null)}
                    className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  >
                    <option value="">All Projects</option>
                    {projects.map(project => (
                      <option key={project.id} value={project.id}>{project.name}</option>
                    ))}
                  </select>
                  <select
                    value={selectedSeverity}
                    onChange={(e) => setSelectedSeverity(e.target.value)}
                    className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  >
                    <option value="all">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="info">Info</option>
                  </select>
                </div>
              </div>
            </div>

            {/* Vulnerabilities List */}
            <div className="space-y-4">
              {filteredVulnerabilities.map((vuln) => (
                <div key={vuln.id} className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex items-center space-x-3">
                      <span className={`px-3 py-1 text-sm font-medium rounded-full border ${getSeverityColor(vuln.severity)}`}>
                        {vuln.severity.toUpperCase()}
                      </span>
                      {vuln.cve_id && (
                        <span className="px-2 py-1 text-xs bg-gray-100 text-gray-600 rounded">
                          {vuln.cve_id}
                        </span>
                      )}
                      {vuln.cwe_id && (
                        <span className="px-2 py-1 text-xs bg-gray-100 text-gray-600 rounded">
                          CWE-{vuln.cwe_id}
                        </span>
                      )}
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getStatusColor(vuln.status)}`}>
                        {vuln.status.replace('_', ' ')}
                      </span>
                      <button className="text-gray-400 hover:text-gray-600">
                        <MoreVertical className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                  
                  <h3 className="text-lg font-semibold text-gray-900 mb-2">{vuln.title}</h3>
                  <p className="text-gray-600 mb-4">{vuln.description}</p>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                    <div>
                      <p className="text-sm font-medium text-gray-900 mb-1">Location</p>
                      <p className="text-sm text-gray-600">{vuln.file_path}:{vuln.line_number}</p>
                      {vuln.function_name && (
                        <p className="text-sm text-gray-500">Function: {vuln.function_name}</p>
                      )}
                    </div>
                    <div>
                      <p className="text-sm font-medium text-gray-900 mb-1">Impact</p>
                      <p className="text-sm text-gray-600">{vuln.impact}</p>
                      {vuln.cvss_score && (
                        <p className="text-sm text-gray-500">CVSS: {vuln.cvss_score}</p>
                      )}
                    </div>
                  </div>
                  
                  <div className="bg-gray-50 p-4 rounded-lg mb-4">
                    <p className="text-sm font-medium text-gray-900 mb-2">Code Snippet</p>
                    <pre className="text-sm text-gray-700 bg-white p-3 rounded border overflow-x-auto">
                      <code>{vuln.code_snippet}</code>
                    </pre>
                  </div>
                  
                  <div className="bg-blue-50 p-4 rounded-lg mb-4">
                    <p className="text-sm font-medium text-gray-900 mb-2">Remediation</p>
                    <p className="text-sm text-gray-700">{vuln.remediation}</p>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-4 text-sm text-gray-500">
                      <span>Created: {vuln.created_at}</span>
                      <span>Updated: {vuln.updated_at}</span>
                    </div>
                    <div className="flex space-x-2">
                      <button className="px-3 py-2 border border-gray-300 text-gray-700 text-sm rounded hover:bg-gray-50">
                        <Edit className="w-4 h-4 mr-1" />
                        Edit
                      </button>
                      <button className="px-3 py-2 bg-blue-600 text-white text-sm rounded hover:bg-blue-700">
                        <Shield className="w-4 h-4 mr-1" />
                        Resolve
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Loading State */}
        {loading && (
          <div className="flex items-center justify-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            <span className="ml-2 text-gray-600">Loading SAST data...</span>
          </div>
        )}
      </div>
    </div>
  );
};

export default SASTDashboard; 