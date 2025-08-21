import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  XCircle,
  Activity,
  TrendingUp,
  Target,
  Zap,
  Eye,
  EyeOff,
  RefreshCw,
  Play,
  Pause,
  Square,
  Download,
  Filter,
  Search,
  BarChart3,
  Server,
  Globe,
  Lock,
  Unlock,
  AlertCircle,
  Info,
  HelpCircle,
  MoreVertical
} from 'lucide-react';

interface RASPProject {
  id: string;
  name: string;
  description: string;
  environment: string;
  status: 'active' | 'monitoring' | 'stopped' | 'error';
  last_scan: string;
  attacks_blocked: number;
  vulnerabilities_detected: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  security_score: number;
  runtime_coverage?: number;
  agent_version?: string;
  branch?: string;
  repository_url?: string;
}

interface RASPScan {
  id: string;
  project_id: string;
  project_name: string;
  status: 'running' | 'completed' | 'failed' | 'paused' | 'queued';
  start_time: string;
  end_time?: string;
  duration?: number;
  attacks_detected: number;
  attacks_blocked: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  progress: number;
  scan_type: 'full' | 'incremental' | 'quick';
  engine_version: string;
  rules_applied: number;
}

interface RASPAttack {
  id: string;
  project_id: string;
  scan_id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  attack_type: string;
  description: string;
  payload: string;
  endpoint: string;
  timestamp: string;
  blocked: boolean;
  status: 'detected' | 'blocked' | 'investigating' | 'resolved';
  created_at: string;
  updated_at: string;
  assigned_to?: string;
  tags: string[];
  cvss_score?: number;
  exploitability?: string;
}

interface RASPMetrics {
  total_projects: number;
  active_monitoring: number;
  total_attacks: number;
  blocked_attacks: number;
  critical_attacks: number;
  high_attacks: number;
  medium_attacks: number;
  low_attacks: number;
  average_response_time: number;
  runtime_coverage_average: number;
  security_score_average: number;
  attacks_trend: {
    date: string;
    critical: number;
    high: number;
    medium: number;
    low: number;
  }[];
}

const RASPOverview: React.FC = () => {
  const [metrics, setMetrics] = useState<RASPMetrics | null>(null);
  const [projects, setProjects] = useState<RASPProject[]>([]);
  const [scans, setScans] = useState<RASPScan[]>([]);
  const [attacks, setAttacks] = useState<RASPAttack[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [selectedProject, setSelectedProject] = useState<string | null>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);

  const loadRASPData = async () => {
    try {
      setLoading(true);
      const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
      
      // Fetch metrics
      const metricsResponse = await fetch(`${API_URL}/api/v1/rasp/dashboard/overview`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token') || ''}`,
          'Content-Type': 'application/json',
        },
      });

      if (metricsResponse.ok) {
        const metricsData = await metricsResponse.json();
        setMetrics(metricsData);
      }

      // Fetch projects
      const projectsResponse = await fetch(`${API_URL}/api/v1/rasp/projects`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token') || ''}`,
          'Content-Type': 'application/json',
        },
      });

      if (projectsResponse.ok) {
        const projectsData = await projectsResponse.json();
        setProjects(projectsData.projects || []);
      }

      // Fetch recent scans
      const scansResponse = await fetch(`${API_URL}/api/v1/rasp/scans/recent`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token') || ''}`,
          'Content-Type': 'application/json',
        },
      });

      if (scansResponse.ok) {
        const scansData = await scansResponse.json();
        setScans(scansData.scans || []);
      }

      // Fetch recent attacks
      const attacksResponse = await fetch(`${API_URL}/api/v1/rasp/attacks/recent`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token') || ''}`,
          'Content-Type': 'application/json',
        },
      });

      if (attacksResponse.ok) {
        const attacksData = await attacksResponse.json();
        setAttacks(attacksData.attacks || []);
      }
    } catch (error) {
      console.error('Error loading RASP data:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadRASPData();
  }, []);

  const onRefresh = async () => {
    setRefreshing(true);
    await loadRASPData();
    setRefreshing(false);
  };

  const startScan = async (projectId: string) => {
    try {
      const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
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
        await loadRASPData();
      }
    } catch (error) {
      console.error('Error starting scan:', error);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
      case 'completed':
        return 'text-green-600 bg-green-100';
      case 'monitoring':
      case 'running':
        return 'text-blue-600 bg-blue-100';
      case 'stopped':
      case 'paused':
        return 'text-yellow-600 bg-yellow-100';
      case 'error':
      case 'failed':
        return 'text-red-600 bg-red-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'text-red-600 bg-red-100';
      case 'high':
        return 'text-orange-600 bg-orange-100';
      case 'medium':
        return 'text-yellow-600 bg-yellow-100';
      case 'low':
        return 'text-blue-600 bg-blue-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active':
      case 'completed':
        return <CheckCircle className="w-4 h-4" />;
      case 'monitoring':
      case 'running':
        return <Activity className="w-4 h-4" />;
      case 'stopped':
      case 'paused':
        return <Pause className="w-4 h-4" />;
      case 'error':
      case 'failed':
        return <XCircle className="w-4 h-4" />;
      default:
        return <Clock className="w-4 h-4" />;
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
      {/* Metrics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
          className="bg-white p-6 rounded-lg shadow-sm border border-gray-200"
        >
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Total Projects</p>
              <p className="text-2xl font-bold text-gray-900">{metrics?.total_projects || 0}</p>
            </div>
            <div className="p-2 bg-blue-100 rounded-lg">
              <Server className="w-6 h-6 text-blue-600" />
            </div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.1 }}
          className="bg-white p-6 rounded-lg shadow-sm border border-gray-200"
        >
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Active Monitoring</p>
              <p className="text-2xl font-bold text-gray-900">{metrics?.active_monitoring || 0}</p>
            </div>
            <div className="p-2 bg-green-100 rounded-lg">
              <Activity className="w-6 h-6 text-green-600" />
            </div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.2 }}
          className="bg-white p-6 rounded-lg shadow-sm border border-gray-200"
        >
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Attacks Blocked</p>
              <p className="text-2xl font-bold text-gray-900">{metrics?.blocked_attacks || 0}</p>
            </div>
            <div className="p-2 bg-red-100 rounded-lg">
              <Shield className="w-6 h-6 text-red-600" />
            </div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.3 }}
          className="bg-white p-6 rounded-lg shadow-sm border border-gray-200"
        >
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Security Score</p>
              <p className="text-2xl font-bold text-gray-900">{metrics?.security_score_average || 0}%</p>
            </div>
            <div className="p-2 bg-purple-100 rounded-lg">
              <Target className="w-6 h-6 text-purple-600" />
            </div>
          </div>
        </motion.div>
      </div>

      {/* Projects Overview */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3, delay: 0.4 }}
        className="bg-white rounded-lg shadow-sm border border-gray-200"
      >
        <div className="p-6 border-b border-gray-200">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold text-gray-900">Projects Overview</h3>
            <button
              onClick={onRefresh}
              disabled={refreshing}
              className="flex items-center space-x-2 px-3 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-md hover:bg-gray-200 disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
              <span>Refresh</span>
            </button>
          </div>
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
                  Security Score
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Attacks Blocked
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Last Scan
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {projects.map((project) => (
                <tr key={project.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div>
                      <div className="text-sm font-medium text-gray-900">{project.name}</div>
                      <div className="text-sm text-gray-500">{project.environment}</div>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(project.status)}`}>
                      {getStatusIcon(project.status)}
                      <span className="ml-1">{project.status}</span>
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center">
                      <div className="w-16 bg-gray-200 rounded-full h-2 mr-2">
                        <div
                          className="bg-blue-600 h-2 rounded-full"
                          style={{ width: `${project.security_score}%` }}
                        ></div>
                      </div>
                      <span className="text-sm text-gray-900">{project.security_score}%</span>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {project.attacks_blocked}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {new Date(project.last_scan).toLocaleDateString()}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    <button
                      onClick={() => startScan(project.id)}
                      className="text-blue-600 hover:text-blue-900 mr-3"
                    >
                      <Play className="w-4 h-4" />
                    </button>
                    <button className="text-gray-600 hover:text-gray-900">
                      <Eye className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </motion.div>

      {/* Recent Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Scans */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.5 }}
          className="bg-white rounded-lg shadow-sm border border-gray-200"
        >
          <div className="p-6 border-b border-gray-200">
            <h3 className="text-lg font-semibold text-gray-900">Recent Scans</h3>
          </div>
          <div className="p-6">
            <div className="space-y-4">
              {scans.slice(0, 5).map((scan) => (
                <div key={scan.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center space-x-3">
                    <div className={`p-2 rounded-full ${getStatusColor(scan.status)}`}>
                      {getStatusIcon(scan.status)}
                    </div>
                    <div>
                      <p className="text-sm font-medium text-gray-900">{scan.project_name}</p>
                      <p className="text-xs text-gray-500">{scan.scan_type} scan</p>
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="text-sm text-gray-900">{scan.attacks_detected} attacks</p>
                    <p className="text-xs text-gray-500">{scan.duration}s</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </motion.div>

        {/* Recent Attacks */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.6 }}
          className="bg-white rounded-lg shadow-sm border border-gray-200"
        >
          <div className="p-6 border-b border-gray-200">
            <h3 className="text-lg font-semibold text-gray-900">Recent Attacks</h3>
          </div>
          <div className="p-6">
            <div className="space-y-4">
              {attacks.slice(0, 5).map((attack) => (
                <div key={attack.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center space-x-3">
                    <div className={`p-2 rounded-full ${getSeverityColor(attack.severity)}`}>
                      <AlertTriangle className="w-4 h-4" />
                    </div>
                    <div>
                      <p className="text-sm font-medium text-gray-900">{attack.attack_type}</p>
                      <p className="text-xs text-gray-500">{attack.endpoint}</p>
                    </div>
                  </div>
                  <div className="text-right">
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                      attack.blocked ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                    }`}>
                      {attack.blocked ? 'Blocked' : 'Detected'}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
};

export default RASPOverview;
