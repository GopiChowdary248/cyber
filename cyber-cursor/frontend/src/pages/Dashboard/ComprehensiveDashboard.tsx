import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Shield, 
  Activity, 
  Users, 
  AlertTriangle, 
  BarChart3, 
  Settings,
  Zap,
  Eye,
  Lock,
  Database,
  Network,
  FileText,
  Globe,
  Cpu,
  Server,
  Cloud,
  Bug,
  ShieldCheck,
  ExclamationTriangle,
  CheckCircle,
  XCircle
} from 'lucide-react';
import { Link } from 'react-router-dom';
import apiService from '../../services/apiService';

interface DashboardMetrics {
  incidents: {
    total: number;
    open: number;
    resolved: number;
  };
  security: {
    score: number;
    threats: number;
    vulnerabilities: number;
  };
  compliance: {
    score: number;
    frameworks: number;
    audits: number;
  };
  users: {
    total: number;
    active: number;
    online: number;
  };
}

interface SystemStatus {
  overall: string;
  components: {
    database: string;
    cache: string;
    file_storage: string;
    network: string;
  };
}

interface SecurityModuleStatus {
  rasp: {
    status: 'active' | 'warning' | 'error';
    applications: number;
    attacks_blocked: number;
    last_scan: string;
  };
  cspm: {
    status: 'active' | 'warning' | 'error';
    accounts: number;
    violations: number;
    last_scan: string;
  };
  sast: {
    status: 'active' | 'warning' | 'error';
    projects: number;
    vulnerabilities: number;
    last_scan: string;
  };
  dast: {
    status: 'active' | 'warning' | 'error';
    projects: number;
    scans: number;
    last_scan: string;
  };
}

const ComprehensiveDashboard: React.FC = () => {
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const [securityModules, setSecurityModules] = useState<SecurityModuleStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      
      // Load multiple data sources in parallel
      const [
        incidentsResponse,
        systemResponse,
        adminResponse,
        userResponse
      ] = await Promise.all([
        apiService.getIncidents(),
        apiService.getSystemStatus(),
        apiService.getAdminOverview(),
        apiService.getUsersManagement()
      ]);

      // Extract and format data
      const incidentsData = incidentsResponse.data;
      const systemData = systemResponse.data;
      const adminData = adminResponse.data;
      const userData = userResponse.data;

      setMetrics({
        incidents: {
          total: incidentsData.total_incidents || 0,
          open: incidentsData.by_status?.open || 0,
          resolved: incidentsData.by_status?.resolved || 0,
        },
        security: {
          score: 87, // Default value, could come from security metrics
          threats: incidentsData.by_severity?.high || 0,
          vulnerabilities: 12, // Could come from vulnerability scan
        },
        compliance: {
          score: 92, // Default value, could come from compliance metrics
          frameworks: 3, // Default value
          audits: 2, // Default value
        },
        users: {
          total: userData.total_users || 0,
          active: userData.active_users || 0,
          online: userData.active_users || 0,
        },
      });

      setSystemStatus({
        overall: systemData.system_status || 'unknown',
        components: {
          database: systemData.components?.database?.status || 'unknown',
          cache: systemData.components?.cache?.status || 'unknown',
          file_storage: systemData.components?.file_storage?.status || 'unknown',
          network: systemData.components?.network?.status || 'unknown',
        },
      });

      // Mock security module status data
      setSecurityModules({
        rasp: {
          status: 'active',
          applications: 24,
          attacks_blocked: 156,
          last_scan: '2 hours ago'
        },
        cspm: {
          status: 'warning',
          accounts: 12,
          violations: 45,
          last_scan: '1 hour ago'
        },
        sast: {
          status: 'active',
          projects: 18,
          vulnerabilities: 67,
          last_scan: '4 hours ago'
        },
        dast: {
          status: 'active',
          projects: 15,
          scans: 89,
          last_scan: '30 minutes ago'
        }
      });

    } catch (err) {
      console.error('Error loading dashboard data:', err);
      setError('Failed to load dashboard data. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'healthy':
      case 'active':
        return 'text-green-500';
      case 'degraded':
      case 'warning':
        return 'text-yellow-500';
      case 'down':
      case 'error':
        return 'text-red-500';
      default:
        return 'text-gray-500';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status.toLowerCase()) {
      case 'healthy':
      case 'active':
        return '🟢';
      case 'degraded':
      case 'warning':
        return '🟡';
      case 'down':
      case 'error':
        return '🔴';
      default:
        return '⚪';
    }
  };

  const getModuleStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'text-green-500 bg-green-100 border-green-200';
      case 'warning':
        return 'text-yellow-500 bg-yellow-100 border-yellow-200';
      case 'error':
        return 'text-red-500 bg-red-100 border-red-200';
      default:
        return 'text-gray-500 bg-gray-100 border-gray-200';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
        <div className="text-center">
          <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-blue-500 mx-auto mb-4"></div>
          <p className="text-white text-lg">Loading comprehensive dashboard...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
        <div className="text-center">
          <div className="text-red-500 text-6xl mb-4">⚠️</div>
          <p className="text-white text-lg mb-4">{error}</p>
          <button
            onClick={loadDashboardData}
            className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded-lg transition-colors"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white">
      {/* Header */}
      <div className="bg-slate-800/50 backdrop-blur-sm border-b border-slate-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="h-10 w-10 bg-blue-600 rounded-lg flex items-center justify-center">
                <Shield className="h-6 w-6 text-white" />
              </div>
              <div>
                <h1 className="text-2xl font-bold">CyberShield Dashboard</h1>
                <p className="text-slate-400 text-sm">Comprehensive Security Platform</p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <div className="text-right">
                <p className="text-sm text-slate-400">System Status</p>
                <p className={`font-semibold ${getStatusColor(systemStatus?.overall || 'unknown')}`}>
                  {getStatusIcon(systemStatus?.overall || 'unknown')} {systemStatus?.overall || 'Unknown'}
                </p>
              </div>
              <button
                onClick={loadDashboardData}
                className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg transition-colors flex items-center space-x-2"
              >
                <Activity className="h-4 w-4" />
                <span>Refresh</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
        <div className="flex space-x-1 bg-slate-800/50 rounded-lg p-1">
          {[
            { id: 'overview', label: 'Overview', icon: BarChart3 },
            { id: 'security', label: 'Security', icon: Shield },
            { id: 'incidents', label: 'Incidents', icon: AlertTriangle },
            { id: 'compliance', label: 'Compliance', icon: FileText },
            { id: 'users', label: 'Users', icon: Users },
            { id: 'system', label: 'System', icon: Server },
          ].map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center space-x-2 px-4 py-2 rounded-md transition-all ${
                  activeTab === tab.id
                    ? 'bg-blue-600 text-white shadow-lg'
                    : 'text-slate-400 hover:text-white hover:bg-slate-700/50'
                }`}
              >
                <Icon className="h-4 w-4" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'overview' && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="space-y-6"
          >
            {/* Key Metrics Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-slate-400 text-sm">Total Incidents</p>
                    <p className="text-3xl font-bold text-white">{metrics?.incidents.total || 0}</p>
                  </div>
                  <div className="h-12 w-12 bg-red-500/20 rounded-lg flex items-center justify-center">
                    <AlertTriangle className="h-6 w-6 text-red-500" />
                  </div>
                </div>
                <div className="mt-4 flex items-center text-sm">
                  <span className="text-slate-400">Open: {metrics?.incidents.open || 0}</span>
                  <span className="mx-2 text-slate-600">•</span>
                  <span className="text-green-400">Resolved: {metrics?.incidents.resolved || 0}</span>
                </div>
              </div>

              <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-slate-400 text-sm">Security Score</p>
                    <p className="text-3xl font-bold text-white">{metrics?.security.score || 0}%</p>
                  </div>
                  <div className="h-12 w-12 bg-blue-500/20 rounded-lg flex items-center justify-center">
                    <Shield className="h-6 w-6 text-blue-500" />
                  </div>
                </div>
                <div className="mt-4 flex items-center text-sm">
                  <span className="text-slate-400">Threats: {metrics?.security.threats || 0}</span>
                  <span className="mx-2 text-slate-600">•</span>
                  <span className="text-yellow-400">Vulnerabilities: {metrics?.security.vulnerabilities || 0}</span>
                </div>
              </div>

              <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-slate-400 text-sm">Compliance Score</p>
                    <p className="text-3xl font-bold text-white">{metrics?.compliance.score || 0}%</p>
                  </div>
                  <div className="h-12 w-12 bg-green-500/20 rounded-lg flex items-center justify-center">
                    <FileText className="h-6 w-6 text-green-500" />
                  </div>
                </div>
                <div className="mt-4 flex items-center text-sm">
                  <span className="text-slate-400">Frameworks: {metrics?.compliance.frameworks || 0}</span>
                  <span className="mx-2 text-slate-600">•</span>
                  <span className="text-blue-400">Audits: {metrics?.compliance.audits || 0}</span>
                </div>
              </div>

              <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-slate-400 text-sm">Active Users</p>
                    <p className="text-3xl font-bold text-white">{metrics?.users.active || 0}</p>
                  </div>
                  <div className="h-12 w-12 bg-purple-500/20 rounded-lg flex items-center justify-center">
                    <Users className="h-6 w-6 text-purple-500" />
                  </div>
                </div>
                <div className="mt-4 flex items-center text-sm">
                  <span className="text-slate-400">Total: {metrics?.users.total || 0}</span>
                  <span className="mx-2 text-slate-600">•</span>
                  <span className="text-green-400">Online: {metrics?.users.online || 0}</span>
                </div>
              </div>
            </div>

            {/* Security Modules Overview - Prominently Featured */}
            <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
              <h3 className="text-lg font-semibold mb-6 flex items-center space-x-2">
                <Shield className="h-5 w-5 text-blue-500" />
                <span>Security Modules Status</span>
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {/* RASP Module */}
                <Link to="/rasp" className="block">
                  <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600 hover:border-blue-500 transition-all hover:bg-slate-700/70">
                    <div className="flex items-center justify-between mb-3">
                                           <div className="h-10 w-10 bg-blue-600 rounded-lg flex items-center justify-center">
                       <Bug className="h-5 w-5 text-white" />
                     </div>
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${getModuleStatusColor(securityModules?.rasp.status || 'unknown')}`}>
                        {securityModules?.rasp.status || 'unknown'}
                      </span>
                    </div>
                    <h4 className="font-semibold text-white mb-2">RASP</h4>
                    <p className="text-slate-400 text-sm mb-3">Runtime Application Self-Protection</p>
                    <div className="space-y-1 text-xs text-slate-300">
                      <div>Applications: {securityModules?.rasp.applications || 0}</div>
                      <div>Attacks Blocked: {securityModules?.rasp.attacks_blocked || 0}</div>
                      <div>Last Scan: {securityModules?.rasp.last_scan || 'Unknown'}</div>
                    </div>
                  </div>
                </Link>

                {/* CSPM Module */}
                <Link to="/cloud-security/cspm" className="block">
                  <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600 hover:border-blue-500 transition-all hover:bg-slate-700/70">
                    <div className="flex items-center justify-between mb-3">
                                           <div className="h-10 w-10 bg-green-600 rounded-lg flex items-center justify-center">
                       <Cloud className="h-5 w-5 text-white" />
                     </div>
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${getModuleStatusColor(securityModules?.cspm.status || 'unknown')}`}>
                        {securityModules?.cspm.status || 'unknown'}
                      </span>
                    </div>
                    <h4 className="font-semibold text-white mb-2">CSPM</h4>
                    <p className="text-slate-400 text-sm mb-3">Cloud Security Posture Management</p>
                    <div className="space-y-1 text-xs text-slate-300">
                      <div>Accounts: {securityModules?.cspm.accounts || 0}</div>
                      <div>Violations: {securityModules?.cspm.violations || 0}</div>
                      <div>Last Scan: {securityModules?.cspm.last_scan || 'Unknown'}</div>
                    </div>
                  </div>
                </Link>

                {/* SAST Module */}
                <Link to="/sast" className="block">
                  <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600 hover:border-blue-500 transition-all hover:bg-slate-700/70">
                    <div className="flex items-center justify-between mb-3">
                                           <div className="h-10 w-10 bg-purple-600 rounded-lg flex items-center justify-center">
                       <FileText className="h-5 w-5 text-white" />
                     </div>
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${getModuleStatusColor(securityModules?.sast.status || 'unknown')}`}>
                        {securityModules?.sast.status || 'unknown'}
                      </span>
                    </div>
                    <h4 className="font-semibold text-white mb-2">SAST</h4>
                    <p className="text-slate-400 text-sm mb-3">Static Application Security Testing</p>
                    <div className="space-y-1 text-xs text-slate-300">
                      <div>Projects: {securityModules?.sast.projects || 0}</div>
                      <div>Vulnerabilities: {securityModules?.sast.vulnerabilities || 0}</div>
                      <div>Last Scan: {securityModules?.sast.last_scan || 'Unknown'}</div>
                    </div>
                  </div>
                </Link>

                {/* DAST Module */}
                <Link to="/dast" className="block">
                  <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600 hover:border-blue-500 transition-all hover:bg-slate-700/70">
                    <div className="flex items-center justify-between mb-3">
                                           <div className="h-10 w-10 bg-orange-600 rounded-lg flex items-center justify-center">
                       <Shield className="h-5 w-5 text-white" />
                     </div>
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${getModuleStatusColor(securityModules?.dast.status || 'unknown')}`}>
                        {securityModules?.dast.status || 'unknown'}
                      </span>
                    </div>
                    <h4 className="font-semibold text-white mb-2">DAST</h4>
                    <p className="text-slate-400 text-sm mb-3">Dynamic Application Security Testing</p>
                    <div className="space-y-1 text-xs text-slate-300">
                      <div>Projects: {securityModules?.dast.projects || 0}</div>
                      <div>Scans: {securityModules?.dast.scans || 0}</div>
                      <div>Last Scan: {securityModules?.dast.last_scan || 'Unknown'}</div>
                    </div>
                  </div>
                </Link>
              </div>
            </div>

            {/* System Components Status */}
            <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
              <h3 className="text-lg font-semibold mb-4 flex items-center space-x-2">
                <Server className="h-5 w-5 text-blue-500" />
                <span>System Components Status</span>
              </h3>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {systemStatus && Object.entries(systemStatus.components).map(([component, status]) => (
                  <div key={component} className="text-center">
                    <div className="text-2xl mb-2">{getStatusIcon(status)}</div>
                    <p className="text-sm text-slate-400 capitalize">{component.replace('_', ' ')}</p>
                    <p className={`font-semibold ${getStatusColor(status)}`}>
                      {status}
                    </p>
                  </div>
                ))}
              </div>
            </div>

            {/* Quick Actions */}
            <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
              <h3 className="text-lg font-semibold mb-4 flex items-center space-x-2">
                <Zap className="h-5 w-5 text-yellow-500" />
                <span>Quick Actions</span>
              </h3>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                                 <Link to="/rasp" className="bg-blue-600 hover:bg-blue-700 p-4 rounded-lg transition-colors text-center">
                   <Bug className="h-6 w-6 mx-auto mb-2" />
                   <span className="text-sm">RASP Dashboard</span>
                 </Link>
                                 <Link to="/cloud-security/cspm" className="bg-green-600 hover:bg-green-700 p-4 rounded-lg transition-colors text-center">
                   <Cloud className="h-6 w-6 mx-auto mb-2" />
                   <span className="text-sm">CSPM Dashboard</span>
                 </Link>
                <Link to="/incidents" className="bg-red-600 hover:bg-red-700 p-4 rounded-lg transition-colors text-center">
                  <Eye className="h-6 w-6 mx-auto mb-2" />
                  <span className="text-sm">View Incidents</span>
                </Link>
                <Link to="/settings" className="bg-orange-600 hover:bg-orange-700 p-4 rounded-lg transition-colors text-center">
                  <Settings className="h-6 w-6 mx-auto mb-2" />
                  <span className="text-sm">System Config</span>
                </Link>
              </div>
            </div>
          </motion.div>
        )}

        {activeTab === 'security' && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="space-y-6"
          >
            <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
              <h3 className="text-lg font-semibold mb-4">Security Overview</h3>
              <p className="text-slate-400">Security dashboard content will be implemented here.</p>
            </div>
          </motion.div>
        )}

        {activeTab === 'incidents' && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="space-y-6"
          >
            <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
              <h3 className="text-lg font-semibold mb-4">Incident Management</h3>
              <p className="text-slate-400">Incident management content will be implemented here.</p>
            </div>
          </motion.div>
        )}

        {activeTab === 'compliance' && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="space-y-6"
          >
            <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
              <h3 className="text-lg font-semibold mb-4">Compliance Management</h3>
              <p className="text-slate-400">Compliance management content will be implemented here.</p>
            </div>
          </motion.div>
        )}

        {activeTab === 'users' && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="space-y-6"
          >
            <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
              <h3 className="text-lg font-semibold mb-4">User Management</h3>
              <p className="text-slate-400">User management content will be implemented here.</p>
            </div>
          </motion.div>
        )}

        {activeTab === 'system' && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="space-y-6"
          >
            <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
              <h3 className="text-lg font-semibold mb-4">System Administration</h3>
              <p className="text-slate-400">System administration content will be implemented here.</p>
            </div>
          </motion.div>
        )}
      </div>
    </div>
  );
};

export default ComprehensiveDashboard;
