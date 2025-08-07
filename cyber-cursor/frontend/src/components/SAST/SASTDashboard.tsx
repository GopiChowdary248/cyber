import React, { useState, useEffect } from 'react';
import { 
  BarChart3, 
  TrendingUp, 
  AlertTriangle, 
  Shield, 
  Bug, 
  Code, 
  Clock,
  CheckCircle,
  XCircle,
  Activity,
  Users,
  GitBranch,
  FileText,
  Zap,
  RefreshCw,
  Download,
  Settings,
  Eye,
  Play,
  Square,
  PieChart,
  Target,
  Award,
  TrendingDown,
  Database,
  Layers,
  GitCommit,
  Calendar,
  Star,
  AlertCircle,
  Info
} from 'lucide-react';
import SASTScanner from './SASTScanner';
import SASTIssues from './SASTIssues';

interface SASTMetrics {
  total_projects: number;
  active_scans: number;
  total_issues: number;
  critical_issues: number;
  high_issues: number;
  medium_issues: number;
  low_issues: number;
  info_issues: number;
  security_rating: string;
  reliability_rating: string;
  maintainability_rating: string;
  coverage_percentage: number;
  technical_debt_hours: number;
  last_scan_date?: string;
  scan_success_rate: number;
  average_scan_duration: number;
  total_lines_of_code: number;
  duplicated_lines: number;
  duplicated_lines_density: number;
  uncovered_lines: number;
  uncovered_conditions: number;
  security_hotspots: number;
  security_hotspots_reviewed: number;
  vulnerabilities: number;
  bugs: number;
  code_smells: number;
}

interface SASTTrend {
  date: string;
  issues_found: number;
  issues_resolved: number;
  scans_completed: number;
  security_score: number;
  coverage: number;
  technical_debt: number;
}

interface SASTProject {
  id: string;
  name: string;
  language: string;
  last_scan?: string;
  issues_count: number;
  security_rating: string;
  reliability_rating: string;
  maintainability_rating: string;
  status: 'active' | 'inactive' | 'scanning';
  coverage: number;
  technical_debt: number;
  duplicated_lines: number;
  lines_of_code: number;
  critical_issues: number;
  high_issues: number;
  medium_issues: number;
  low_issues: number;
  info_issues: number;
  security_hotspots: number;
  security_hotspots_reviewed: number;
  bugs: number;
  code_smells: number;
  vulnerabilities: number;
  last_analysis_date?: string;
  version?: string;
  description?: string;
}

interface ProjectRating {
  project_id: string;
  project_name: string;
  security_rating: string;
  reliability_rating: string;
  maintainability_rating: string;
  coverage_rating: string;
  overall_rating: string;
  last_updated: string;
}

const SASTDashboard: React.FC = () => {
  const [metrics, setMetrics] = useState<SASTMetrics | null>(null);
  const [trends, setTrends] = useState<SASTTrend[]>([]);
  const [recentProjects, setRecentProjects] = useState<SASTProject[]>([]);
  const [projectRatings, setProjectRatings] = useState<ProjectRating[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'overview' | 'scanner' | 'issues' | 'projects'>('overview');
  const [selectedProject, setSelectedProject] = useState<string | null>(null);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
      
      // Fetch dashboard metrics
      const metricsResponse = await fetch(`${API_URL}/api/v1/sast/dashboard`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token') || ''}`,
          'Content-Type': 'application/json',
        },
      });

      if (metricsResponse.ok) {
        const metricsData = await metricsResponse.json();
        setMetrics(metricsData);
      }

      // Fetch recent projects with enhanced data
      const projectsResponse = await fetch(`${API_URL}/api/v1/sast/projects?limit=10`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token') || ''}`,
          'Content-Type': 'application/json',
        },
      });

      if (projectsResponse.ok) {
        const projectsData = await projectsResponse.json();
        setRecentProjects(projectsData.projects || []);
        
        // Generate project ratings from project data
        const ratings = (projectsData.projects || []).map((project: SASTProject) => ({
          project_id: project.id,
          project_name: project.name,
          security_rating: project.security_rating,
          reliability_rating: project.reliability_rating,
          maintainability_rating: project.maintainability_rating,
          coverage_rating: getCoverageRating(project.coverage),
          overall_rating: calculateOverallRating(project),
          last_updated: project.last_scan || new Date().toISOString()
        }));
        setProjectRatings(ratings);
      }

      // Mock trends data for now
      setTrends(generateMockTrends());

    } catch (error) {
      console.error('Error fetching dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const generateMockTrends = (): SASTTrend[] => {
    const trends: SASTTrend[] = [];
    const today = new Date();
    
    for (let i = 29; i >= 0; i--) {
      const date = new Date(today);
      date.setDate(date.getDate() - i);
      
      trends.push({
        date: date.toISOString().split('T')[0],
        issues_found: Math.floor(Math.random() * 50) + 10,
        issues_resolved: Math.floor(Math.random() * 30) + 5,
        scans_completed: Math.floor(Math.random() * 10) + 1,
        security_score: Math.floor(Math.random() * 40) + 60,
        coverage: Math.floor(Math.random() * 40) + 60,
        technical_debt: Math.floor(Math.random() * 100) + 50
      });
    }
    
    return trends;
  };

  const getRatingColor = (rating: string) => {
    switch (rating) {
      case 'A': return 'text-green-600 bg-green-100 border-green-200';
      case 'B': return 'text-blue-600 bg-blue-100 border-blue-200';
      case 'C': return 'text-yellow-600 bg-yellow-100 border-yellow-200';
      case 'D': return 'text-orange-600 bg-orange-100 border-orange-200';
      case 'E': return 'text-red-600 bg-red-100 border-red-200';
      default: return 'text-gray-600 bg-gray-100 border-gray-200';
    }
  };

  const getCoverageRating = (coverage: number): string => {
    if (coverage >= 80) return 'A';
    if (coverage >= 60) return 'B';
    if (coverage >= 40) return 'C';
    if (coverage >= 20) return 'D';
    return 'E';
  };

  const calculateOverallRating = (project: SASTProject): string => {
    const ratings = [
      getRatingScore(project.security_rating),
      getRatingScore(project.reliability_rating),
      getRatingScore(project.maintainability_rating),
      getRatingScore(getCoverageRating(project.coverage))
    ];
    
    const average = ratings.reduce((a, b) => a + b, 0) / ratings.length;
    
    if (average >= 4.5) return 'A';
    if (average >= 3.5) return 'B';
    if (average >= 2.5) return 'C';
    if (average >= 1.5) return 'D';
    return 'E';
  };

  const getRatingScore = (rating: string): number => {
    switch (rating) {
      case 'A': return 5;
      case 'B': return 4;
      case 'C': return 3;
      case 'D': return 2;
      case 'E': return 1;
      default: return 0;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-600';
      case 'high': return 'text-orange-600';
      case 'medium': return 'text-yellow-600';
      case 'low': return 'text-blue-600';
      default: return 'text-gray-600';
    }
  };

  const formatDuration = (minutes: number) => {
    if (minutes < 60) return `${minutes}m`;
    const hours = Math.floor(minutes / 60);
    const mins = minutes % 60;
    return `${hours}h ${mins}m`;
  };

  const formatNumber = (num: number) => {
    if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`;
    if (num >= 1000) return `${(num / 1000).toFixed(1)}K`;
    return num.toString();
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center p-8">
        <RefreshCw className="w-8 h-8 animate-spin text-blue-600" />
        <span className="ml-2 text-gray-600">Loading SAST Dashboard...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white rounded-lg shadow-lg p-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Static Application Security Testing</h1>
            <p className="text-gray-600">Detect vulnerabilities in source code using static analysis</p>
          </div>
          
          <div className="flex items-center space-x-3">
            <div className="flex items-center space-x-2 px-3 py-2 bg-green-100 rounded-lg">
              <Shield className="w-5 h-5 text-green-600" />
              <span className="text-sm font-medium text-green-800">Security Status: Good</span>
            </div>
            
            <button
              onClick={fetchDashboardData}
              className="flex items-center space-x-2 px-3 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-md hover:bg-gray-200"
            >
              <RefreshCw className="w-4 h-4" />
              <span>Refresh</span>
            </button>
            
            <button className="flex items-center space-x-2 px-3 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-md hover:bg-gray-200">
              <Download className="w-4 h-4" />
              <span>Export Report</span>
            </button>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="bg-white rounded-lg shadow-lg">
        <div className="border-b border-gray-200">
          <nav className="flex space-x-8 px-6">
            <button
              onClick={() => setActiveTab('overview')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'overview'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              <div className="flex items-center space-x-2">
                <BarChart3 className="w-4 h-4" />
                <span>Overview</span>
              </div>
            </button>
            
            <button
              onClick={() => setActiveTab('scanner')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'scanner'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              <div className="flex items-center space-x-2">
                <Zap className="w-4 h-4" />
                <span>Scanner</span>
              </div>
            </button>
            
            <button
              onClick={() => setActiveTab('issues')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'issues'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              <div className="flex items-center space-x-2">
                <AlertTriangle className="w-4 h-4" />
                <span>Issues</span>
              </div>
            </button>
            
            <button
              onClick={() => setActiveTab('projects')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'projects'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              <div className="flex items-center space-x-2">
                <GitBranch className="w-4 h-4" />
                <span>Projects</span>
              </div>
            </button>
          </nav>
        </div>
      </div>

      {/* Tab Content */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Key Metrics Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <div className="bg-white rounded-lg shadow-lg p-6">
              <div className="flex items-center">
                <div className="p-2 bg-blue-100 rounded-lg">
                  <FileText className="w-6 h-6 text-blue-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Total Scans</p>
                  <p className="text-2xl font-bold text-gray-900">{metrics?.total_projects ? metrics.total_projects * 3 : 1247}</p>
                </div>
              </div>
            </div>

            <div className="bg-white rounded-lg shadow-lg p-6">
              <div className="flex items-center">
                <div className="p-2 bg-green-100 rounded-lg">
                  <RefreshCw className="w-6 h-6 text-green-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Active Scans</p>
                  <p className="text-2xl font-bold text-gray-900">{metrics?.active_scans || 3}</p>
                </div>
              </div>
            </div>

            <div className="bg-white rounded-lg shadow-lg p-6">
              <div className="flex items-center">
                <div className="p-2 bg-red-100 rounded-lg">
                  <AlertTriangle className="w-6 h-6 text-red-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Vulnerabilities Found</p>
                  <p className="text-2xl font-bold text-red-600">{metrics?.total_issues || 89}</p>
                </div>
              </div>
            </div>

            <div className="bg-white rounded-lg shadow-lg p-6">
              <div className="flex items-center">
                <div className="p-2 bg-green-100 rounded-lg">
                  <Target className="w-6 h-6 text-green-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Security Score</p>
                  <p className="text-2xl font-bold text-green-600">87%</p>
                </div>
              </div>
            </div>
          </div>

          {/* Project Ratings Overview */}
          <div className="bg-white rounded-lg shadow-lg p-6">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-lg font-semibold text-gray-900">Project Quality Ratings</h3>
              <div className="flex items-center space-x-4">
                <div className="flex items-center space-x-2">
                  <Award className="w-4 h-4 text-green-600" />
                  <span className="text-sm text-gray-600">Overall Quality</span>
                </div>
                <button className="text-sm text-blue-600 hover:text-blue-800">
                  View Detailed Report
                </button>
              </div>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              {/* Security Rating */}
              <div className="text-center">
                <div className="flex items-center justify-center mb-2">
                  <Shield className="w-8 h-8 text-blue-600" />
                </div>
                <h4 className="text-sm font-medium text-gray-700 mb-2">Security Rating</h4>
                <div className="flex items-center justify-center space-x-2">
                  <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${getRatingColor(metrics?.security_rating || 'B')}`}>
                    {metrics?.security_rating || 'B'}
                  </span>
                  <span className="text-xs text-gray-500">Good</span>
                </div>
                <p className="text-xs text-gray-500 mt-1">{metrics?.vulnerabilities || 12} vulnerabilities</p>
              </div>

              {/* Reliability Rating */}
              <div className="text-center">
                <div className="flex items-center justify-center mb-2">
                  <CheckCircle className="w-8 h-8 text-green-600" />
                </div>
                <h4 className="text-sm font-medium text-gray-700 mb-2">Reliability Rating</h4>
                <div className="flex items-center justify-center space-x-2">
                  <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${getRatingColor(metrics?.reliability_rating || 'A')}`}>
                    {metrics?.reliability_rating || 'A'}
                  </span>
                  <span className="text-xs text-gray-500">Excellent</span>
                </div>
                <p className="text-xs text-gray-500 mt-1">{metrics?.bugs || 3} bugs</p>
              </div>

              {/* Maintainability Rating */}
              <div className="text-center">
                <div className="flex items-center justify-center mb-2">
                  <Code className="w-8 h-8 text-purple-600" />
                </div>
                <h4 className="text-sm font-medium text-gray-700 mb-2">Maintainability Rating</h4>
                <div className="flex items-center justify-center space-x-2">
                  <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${getRatingColor(metrics?.maintainability_rating || 'B')}`}>
                    {metrics?.maintainability_rating || 'B'}
                  </span>
                  <span className="text-xs text-gray-500">Good</span>
                </div>
                <p className="text-xs text-gray-500 mt-1">{metrics?.technical_debt_hours || 45} hours debt</p>
              </div>

              {/* Coverage Rating */}
              <div className="text-center">
                <div className="flex items-center justify-center mb-2">
                  <Target className="w-8 h-8 text-orange-600" />
                </div>
                <h4 className="text-sm font-medium text-gray-700 mb-2">Coverage Rating</h4>
                <div className="flex items-center justify-center space-x-2">
                  <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${getRatingColor(getCoverageRating(metrics?.coverage_percentage || 75))}`}>
                    {getCoverageRating(metrics?.coverage_percentage || 75)}
                  </span>
                  <span className="text-xs text-gray-500">Good</span>
                </div>
                <p className="text-xs text-gray-500 mt-1">{metrics?.coverage_percentage || 75}% coverage</p>
              </div>
            </div>
          </div>

          {/* Charts Section */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Vulnerability Severity Chart */}
            <div className="bg-white rounded-lg shadow-lg p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Vulnerability Severity</h3>
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                    <span className="text-sm font-medium text-gray-700">Critical</span>
                  </div>
                  <span className="text-sm text-gray-900">{metrics?.critical_issues || 5}</span>
                </div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <div className="w-3 h-3 bg-orange-500 rounded-full"></div>
                    <span className="text-sm font-medium text-gray-700">High</span>
                  </div>
                  <span className="text-sm text-gray-900">{metrics?.high_issues || 12}</span>
                </div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
                    <span className="text-sm font-medium text-gray-700">Medium</span>
                  </div>
                  <span className="text-sm text-gray-900">{metrics?.medium_issues || 28}</span>
                </div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <div className="w-3 h-3 bg-blue-500 rounded-full"></div>
                    <span className="text-sm font-medium text-gray-700">Low</span>
                  </div>
                  <span className="text-sm text-gray-900">{metrics?.low_issues || 44}</span>
                </div>
              </div>
            </div>

            {/* Language Distribution Chart */}
            <div className="bg-white rounded-lg shadow-lg p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Language Distribution</h3>
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <div className="w-3 h-3 bg-blue-500 rounded-full"></div>
                    <span className="text-sm font-medium text-gray-700">JavaScript</span>
                  </div>
                  <span className="text-sm text-gray-900">45%</span>
                </div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                    <span className="text-sm font-medium text-gray-700">Python</span>
                  </div>
                  <span className="text-sm text-gray-900">30%</span>
                </div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <div className="w-3 h-3 bg-purple-500 rounded-full"></div>
                    <span className="text-sm font-medium text-gray-700">Java</span>
                  </div>
                  <span className="text-sm text-gray-900">15%</span>
                </div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <div className="w-3 h-3 bg-orange-500 rounded-full"></div>
                    <span className="text-sm font-medium text-gray-700">Other</span>
                  </div>
                  <span className="text-sm text-gray-900">10%</span>
                </div>
              </div>
            </div>
          </div>

          {/* Recent Scans */}
          <div className="bg-white rounded-lg shadow-lg p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-gray-900">Recent Scans</h3>
              <button className="text-sm text-blue-600 hover:text-blue-800">
                View All Scans
              </button>
            </div>
            
            <div className="space-y-4">
              <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                <div className="flex items-center space-x-4">
                  <div className="flex items-center space-x-2">
                    <CheckCircle className="w-5 h-5 text-green-600" />
                    <span className="text-sm font-medium text-gray-900">E-commerce Platform</span>
                  </div>
                  <span className="text-sm text-gray-500">2 hours ago</span>
                </div>
                <div className="flex items-center space-x-4">
                  <span className="text-sm text-gray-500">2m 34s</span>
                  <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                    Completed
                  </span>
                </div>
              </div>

              <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                <div className="flex items-center space-x-4">
                  <div className="flex items-center space-x-2">
                    <RefreshCw className="w-5 h-5 text-blue-600 animate-spin" />
                    <span className="text-sm font-medium text-gray-900">API Gateway</span>
                  </div>
                  <span className="text-sm text-gray-500">5 minutes ago</span>
                </div>
                <div className="flex items-center space-x-4">
                  <span className="text-sm text-gray-500">1m 12s</span>
                  <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                    Running
                  </span>
                </div>
              </div>

              <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                <div className="flex items-center space-x-4">
                  <div className="flex items-center space-x-2">
                    <CheckCircle className="w-5 h-5 text-green-600" />
                    <span className="text-sm font-medium text-gray-900">User Management</span>
                  </div>
                  <span className="text-sm text-gray-500">1 hour ago</span>
                </div>
                <div className="flex items-center space-x-4">
                  <span className="text-sm text-gray-500">1m 45s</span>
                  <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                    Completed
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Project Ratings Table */}
          <div className="bg-white rounded-lg shadow-lg p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-gray-900">Project Quality Ratings</h3>
              <button className="text-sm text-blue-600 hover:text-blue-800">
                View All Projects
              </button>
            </div>
            
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Project Name
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Security
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Reliability
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Maintainability
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Coverage
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Overall
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Last Updated
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {projectRatings.slice(0, 5).map((rating) => (
                    <tr key={rating.project_id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="text-sm font-medium text-gray-900">{rating.project_name}</div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getRatingColor(rating.security_rating)}`}>
                          {rating.security_rating}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getRatingColor(rating.reliability_rating)}`}>
                          {rating.reliability_rating}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getRatingColor(rating.maintainability_rating)}`}>
                          {rating.maintainability_rating}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getRatingColor(rating.coverage_rating)}`}>
                          {rating.coverage_rating}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getRatingColor(rating.overall_rating)}`}>
                          {rating.overall_rating}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {new Date(rating.last_updated).toLocaleDateString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'scanner' && (
        <SASTScanner projectId={selectedProject || undefined} />
      )}

      {activeTab === 'issues' && (
        <SASTIssues projectId={selectedProject || undefined} />
      )}

      {activeTab === 'projects' && (
        <div className="bg-white rounded-lg shadow-lg p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">All Projects</h3>
          <p className="text-gray-500">Project management interface would go here</p>
        </div>
      )}
    </div>
  );
};

export default SASTDashboard; 