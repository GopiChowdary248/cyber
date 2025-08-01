import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { 
  Shield, 
  Search, 
  Code, 
  Globe, 
  AlertTriangle, 
  CheckCircle, 
  XCircle, 
  Activity, 
  BarChart3,
  Play,
  Settings,
  FileText,
  Lock,
  Zap,
  Clock,
  Users,
  Database,
  Package
} from 'lucide-react';

interface Application {
  id: string;
  name: string;
  description: string;
  repository_url: string;
  deployment_url: string;
  technology_stack: string[];
  security_score: number;
  last_scan: string | null;
  total_vulnerabilities: number;
  critical_vulnerabilities: number;
  high_vulnerabilities: number;
  created_at: string;
  updated_at: string;
}

interface SASTScan {
  id: string;
  project_name: string;
  repository_url: string;
  status: string;
  started_at: string;
  completed_at?: string;
  files_scanned: number;
  vulnerabilities_found: number;
  scan_duration: number;
  engine_version: string;
}

interface DASTScan {
  id: string;
  target_url: string;
  status: string;
  started_at: string;
  completed_at?: string;
  pages_scanned: number;
  vulnerabilities_found: number;
  scan_duration: number;
  engine_version: string;
}

interface SCAScan {
  id: string;
  project_name: string;
  manifest_files: string[];
  status: string;
  started_at: string;
  completed_at?: string;
  dependencies_scanned: number;
  vulnerabilities_found: number;
  scan_duration: number;
  engine_version: string;
}

interface WAFRule {
  id: string;
  name: string;
  description: string;
  action: string;
  conditions: any;
  priority: number;
  enabled: boolean;
  created_at: string;
  hit_count: number;
}

interface Vulnerability {
  id: string;
  scan_id: string;
  scan_type: string;
  title: string;
  description: string;
  severity: string;
  cve_id?: string;
  cvss_score?: number;
  file_path?: string;
  line_number?: number;
  component_name?: string;
  component_version?: string;
  remediation: string;
  discovered_at: string;
  status: string;
  false_positive: boolean;
}

interface ApplicationSecuritySummary {
  total_applications: number;
  total_vulnerabilities: number;
  critical_vulnerabilities: number;
  high_vulnerabilities: number;
  active_waf_rules: number;
  avg_security_score: number;
}

const ApplicationSecurity: React.FC = () => {
  const { user } = useAuth();
  const [summary, setSummary] = useState<ApplicationSecuritySummary | null>(null);
  const [applications, setApplications] = useState<Application[]>([]);
  const [sastScans, setSastScans] = useState<SASTScan[]>([]);
  const [dastScans, setDastScans] = useState<DASTScan[]>([]);
  const [scaScans, setScaScans] = useState<SCAScan[]>([]);
  const [wafRules, setWafRules] = useState<WAFRule[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [activeTab, setActiveTab] = useState('overview');
  const [loading, setLoading] = useState(true);
  const [selectedApp, setSelectedApp] = useState<string | null>(null);

  useEffect(() => {
    fetchApplicationData();
  }, []);

  const fetchApplicationData = async () => {
    try {
      setLoading(true);
      
      // Fetch summary
      const summaryResponse = await fetch('/api/v1/application-security/summary', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      const summaryData = await summaryResponse.json();
      setSummary(summaryData);

      // Fetch applications
      const appsResponse = await fetch('/api/v1/application-security/applications', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      const appsData = await appsResponse.json();
      setApplications(appsData);

      // Fetch SAST scans
      const sastResponse = await fetch('/api/v1/application-security/sast/scans', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      const sastData = await sastResponse.json();
      setSastScans(sastData.slice(0, 5)); // Show last 5 scans

      // Fetch DAST scans
      const dastResponse = await fetch('/api/v1/application-security/dast/scans', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      const dastData = await dastResponse.json();
      setDastScans(dastData.slice(0, 5)); // Show last 5 scans

      // Fetch SCA scans
      const scaResponse = await fetch('/api/v1/application-security/sca/scans', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      const scaData = await scaResponse.json();
      setScaScans(scaData.slice(0, 5)); // Show last 5 scans

      // Fetch WAF rules
      const wafResponse = await fetch('/api/v1/application-security/waf/rules', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      const wafData = await wafResponse.json();
      setWafRules(wafData);

      // Fetch vulnerabilities
      const vulnResponse = await fetch('/api/v1/application-security/vulnerabilities', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      const vulnData = await vulnResponse.json();
      setVulnerabilities(vulnData.slice(0, 10)); // Show last 10 vulnerabilities

    } catch (error) {
      console.error('Error fetching application data:', error);
    } finally {
      setLoading(false);
    }
  };

  const startSASTScan = async (appId: string) => {
    try {
      const response = await fetch('/api/v1/application-security/sast/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({
          app_id: appId,
          scan_config: {}
        })
      });
      
      if (response.ok) {
        // Refresh data after starting scan
        setTimeout(fetchApplicationData, 2000);
      }
    } catch (error) {
      console.error('Error starting SAST scan:', error);
    }
  };

  const startDASTScan = async (targetUrl: string) => {
    try {
      const response = await fetch('/api/v1/application-security/dast/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({
          target_url: targetUrl,
          scan_config: {}
        })
      });
      
      if (response.ok) {
        // Refresh data after starting scan
        setTimeout(fetchApplicationData, 2000);
      }
    } catch (error) {
      console.error('Error starting DAST scan:', error);
    }
  };

  const startSCAScan = async (appId: string) => {
    try {
      const response = await fetch('/api/v1/application-security/sca/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({
          app_id: appId,
          manifest_files: ['package.json', 'requirements.txt', 'pom.xml']
        })
      });
      
      if (response.ok) {
        // Refresh data after starting scan
        setTimeout(fetchApplicationData, 2000);
      }
    } catch (error) {
      console.error('Error starting SCA scan:', error);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-100';
      case 'high': return 'text-red-500 bg-red-50';
      case 'medium': return 'text-yellow-600 bg-yellow-100';
      case 'low': return 'text-blue-600 bg-blue-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getScanStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'text-green-500';
      case 'scanning': return 'text-blue-500';
      case 'pending': return 'text-yellow-500';
      case 'failed': return 'text-red-500';
      default: return 'text-gray-500';
    }
  };

  const getWAFActionColor = (action: string) => {
    switch (action) {
      case 'block': return 'text-red-600 bg-red-100';
      case 'allow': return 'text-green-600 bg-green-100';
      case 'challenge': return 'text-yellow-600 bg-yellow-100';
      case 'log': return 'text-blue-600 bg-blue-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-cyber-dark text-white p-6">
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-500"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-cyber-dark text-white p-6">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2 flex items-center">
          <Shield className="mr-3 text-red-500" size={32} />
          Application Security
        </h1>
        <p className="text-gray-400">Comprehensive application security testing and protection</p>
      </div>

      {/* Summary Cards */}
      {summary && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <div className="bg-cyber-dark border border-red-700/20 rounded-lg p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Applications</p>
                <p className="text-2xl font-bold text-white">{summary.total_applications}</p>
              </div>
              <Code className="text-red-500" size={24} />
            </div>
            <div className="mt-2">
              <span className="text-gray-400 text-sm">Avg Score: {summary.avg_security_score}%</span>
            </div>
          </div>

          <div className="bg-cyber-dark border border-red-700/20 rounded-lg p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Vulnerabilities</p>
                <p className="text-2xl font-bold text-white">{summary.total_vulnerabilities}</p>
              </div>
              <AlertTriangle className="text-yellow-500" size={24} />
            </div>
            <div className="mt-2">
              <span className="text-red-500 text-sm">{summary.critical_vulnerabilities} critical</span>
            </div>
          </div>

          <div className="bg-cyber-dark border border-red-700/20 rounded-lg p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">WAF Rules</p>
                <p className="text-2xl font-bold text-white">{summary.active_waf_rules}</p>
              </div>
              <Lock className="text-blue-500" size={24} />
            </div>
            <div className="mt-2">
              <span className="text-gray-400 text-sm">Active protection</span>
            </div>
          </div>

          <div className="bg-cyber-dark border border-red-700/20 rounded-lg p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Security Score</p>
                <p className="text-2xl font-bold text-white">{summary.avg_security_score}%</p>
              </div>
              <CheckCircle className="text-green-500" size={24} />
            </div>
            <div className="mt-2">
              <span className="text-gray-400 text-sm">Overall health</span>
            </div>
          </div>
        </div>
      )}

      {/* Navigation Tabs */}
      <div className="mb-6">
        <nav className="flex space-x-1 bg-cyber-dark border border-red-700/20 rounded-lg p-1">
          {[
            { id: 'overview', label: 'Overview', icon: BarChart3 },
            { id: 'applications', label: 'Applications', icon: Code },
            { id: 'sast', label: 'SAST', icon: Search },
            { id: 'dast', label: 'DAST', icon: Globe },
            { id: 'sca', label: 'SCA', icon: Package },
            { id: 'waf', label: 'WAF', icon: Lock },
            { id: 'vulnerabilities', label: 'Vulnerabilities', icon: AlertTriangle }
          ].map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                  activeTab === tab.id
                    ? 'bg-red-600 text-white'
                    : 'text-gray-400 hover:text-white hover:bg-red-600/20'
                }`}
              >
                <Icon className="mr-2" size={16} />
                {tab.label}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Tab Content */}
      <div className="bg-cyber-dark border border-red-700/20 rounded-lg p-6">
        {activeTab === 'overview' && (
          <div className="space-y-6">
            <h2 className="text-xl font-bold text-white mb-4">Application Security Overview</h2>
            
            {/* Recent Activity */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div>
                <h3 className="text-lg font-semibold text-white mb-3">Recent SAST Scans</h3>
                <div className="space-y-3">
                  {sastScans.slice(0, 3).map((scan) => (
                    <div key={scan.id} className="bg-cyber-dark border border-gray-700 rounded-lg p-3">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-white font-medium">{scan.project_name}</p>
                          <p className="text-gray-400 text-sm">
                            {scan.files_scanned.toLocaleString()} files scanned
                          </p>
                        </div>
                        <div className="text-right">
                          <p className={`text-sm font-medium ${getScanStatusColor(scan.status)}`}>
                            {scan.status}
                          </p>
                          <p className="text-gray-400 text-xs">
                            {scan.vulnerabilities_found} vulnerabilities found
                          </p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <h3 className="text-lg font-semibold text-white mb-3">Recent DAST Scans</h3>
                <div className="space-y-3">
                  {dastScans.slice(0, 3).map((scan) => (
                    <div key={scan.id} className="bg-cyber-dark border border-gray-700 rounded-lg p-3">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-white font-medium">{scan.target_url}</p>
                          <p className="text-gray-400 text-sm">
                            {scan.pages_scanned} pages scanned
                          </p>
                        </div>
                        <div className="text-right">
                          <p className={`text-sm font-medium ${getScanStatusColor(scan.status)}`}>
                            {scan.status}
                          </p>
                          <p className="text-gray-400 text-xs">
                            {scan.vulnerabilities_found} vulnerabilities found
                          </p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Recent Vulnerabilities */}
            <div>
              <h3 className="text-lg font-semibold text-white mb-3">Recent Vulnerabilities</h3>
              <div className="space-y-3">
                {vulnerabilities.slice(0, 5).map((vuln) => (
                  <div key={vuln.id} className="bg-cyber-dark border border-gray-700 rounded-lg p-3">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-white font-medium">{vuln.title}</p>
                        <p className="text-gray-400 text-sm">{vuln.description.substring(0, 100)}...</p>
                      </div>
                      <div className="text-right">
                        <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(vuln.severity)}`}>
                          {vuln.severity}
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'applications' && (
          <div>
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-bold text-white">Managed Applications</h2>
              <button className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg flex items-center">
                <Code className="mr-2" size={16} />
                Add Application
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-700">
                    <th className="text-left py-3 px-4">Application</th>
                    <th className="text-left py-3 px-4">Repository</th>
                    <th className="text-left py-3 px-4">Technology Stack</th>
                    <th className="text-left py-3 px-4">Security Score</th>
                    <th className="text-left py-3 px-4">Vulnerabilities</th>
                    <th className="text-left py-3 px-4">Last Scan</th>
                    <th className="text-left py-3 px-4">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {applications.map((app) => (
                    <tr key={app.id} className="border-b border-gray-800">
                      <td className="py-3 px-4">
                        <div>
                          <p className="text-white font-medium">{app.name}</p>
                          <p className="text-gray-400 text-xs">{app.description}</p>
                        </div>
                      </td>
                      <td className="py-3 px-4 text-gray-300 text-xs">{app.repository_url}</td>
                      <td className="py-3 px-4">
                        <div className="flex flex-wrap gap-1">
                          {app.technology_stack.slice(0, 3).map((tech, index) => (
                            <span key={index} className="px-2 py-1 bg-gray-700 rounded text-xs">
                              {tech}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex items-center">
                          <div className="w-16 bg-gray-700 rounded-full h-2 mr-2">
                            <div 
                              className="bg-green-500 h-2 rounded-full" 
                              style={{ width: `${app.security_score}%` }}
                            ></div>
                          </div>
                          <span className="text-gray-300">{app.security_score}%</span>
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <div className="text-center">
                          <p className="text-white">{app.total_vulnerabilities}</p>
                          <p className="text-red-500 text-xs">{app.critical_vulnerabilities} critical</p>
                        </div>
                      </td>
                      <td className="py-3 px-4 text-gray-300 text-xs">
                        {app.last_scan ? new Date(app.last_scan).toLocaleDateString() : 'Never'}
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex space-x-2">
                          <button
                            onClick={() => startSASTScan(app.id)}
                            className="text-blue-400 hover:text-blue-300"
                            title="Start SAST Scan"
                          >
                            <Search size={16} />
                          </button>
                          <button
                            onClick={() => startSCAScan(app.id)}
                            className="text-green-400 hover:text-green-300"
                            title="Start SCA Scan"
                          >
                            <Package size={16} />
                          </button>
                          <button className="text-gray-400 hover:text-gray-300" title="Settings">
                            <Settings size={16} />
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

        {activeTab === 'sast' && (
          <div>
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-bold text-white">SAST Scans</h2>
              <div className="flex space-x-2">
                <button className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg flex items-center">
                  <Play className="mr-2" size={16} />
                  New SAST Scan
                </button>
              </div>
            </div>

            <div className="space-y-4">
              {sastScans.map((scan) => (
                <div key={scan.id} className="bg-cyber-dark border border-gray-700 rounded-lg p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="flex items-center space-x-3">
                        <h3 className="text-white font-medium">{scan.project_name}</h3>
                        <span className={`px-2 py-1 rounded text-xs font-medium ${getScanStatusColor(scan.status)}`}>
                          {scan.status}
                        </span>
                      </div>
                      <p className="text-gray-400 text-sm mt-1">
                        Repository: {scan.repository_url}
                      </p>
                    </div>
                    <div className="text-right">
                      <p className="text-white font-medium">{scan.files_scanned.toLocaleString()} files</p>
                      <p className="text-red-500 text-sm">{scan.vulnerabilities_found} vulnerabilities found</p>
                    </div>
                  </div>
                  <div className="mt-3 pt-3 border-t border-gray-700">
                    <div className="flex justify-between text-sm text-gray-400">
                      <span>Engine: {scan.engine_version}</span>
                      <span>Duration: {scan.scan_duration}s</span>
                      <span>Started: {new Date(scan.started_at).toLocaleString()}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'dast' && (
          <div>
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-bold text-white">DAST Scans</h2>
              <div className="flex space-x-2">
                <button className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg flex items-center">
                  <Play className="mr-2" size={16} />
                  New DAST Scan
                </button>
              </div>
            </div>

            <div className="space-y-4">
              {dastScans.map((scan) => (
                <div key={scan.id} className="bg-cyber-dark border border-gray-700 rounded-lg p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="flex items-center space-x-3">
                        <h3 className="text-white font-medium">{scan.target_url}</h3>
                        <span className={`px-2 py-1 rounded text-xs font-medium ${getScanStatusColor(scan.status)}`}>
                          {scan.status}
                        </span>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className="text-white font-medium">{scan.pages_scanned} pages</p>
                      <p className="text-red-500 text-sm">{scan.vulnerabilities_found} vulnerabilities found</p>
                    </div>
                  </div>
                  <div className="mt-3 pt-3 border-t border-gray-700">
                    <div className="flex justify-between text-sm text-gray-400">
                      <span>Engine: {scan.engine_version}</span>
                      <span>Duration: {scan.scan_duration}s</span>
                      <span>Started: {new Date(scan.started_at).toLocaleString()}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'sca' && (
          <div>
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-bold text-white">SCA Scans</h2>
              <div className="flex space-x-2">
                <button className="bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg flex items-center">
                  <Play className="mr-2" size={16} />
                  New SCA Scan
                </button>
              </div>
            </div>

            <div className="space-y-4">
              {scaScans.map((scan) => (
                <div key={scan.id} className="bg-cyber-dark border border-gray-700 rounded-lg p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="flex items-center space-x-3">
                        <h3 className="text-white font-medium">{scan.project_name}</h3>
                        <span className={`px-2 py-1 rounded text-xs font-medium ${getScanStatusColor(scan.status)}`}>
                          {scan.status}
                        </span>
                      </div>
                      <p className="text-gray-400 text-sm mt-1">
                        Manifest files: {scan.manifest_files.join(', ')}
                      </p>
                    </div>
                    <div className="text-right">
                      <p className="text-white font-medium">{scan.dependencies_scanned} dependencies</p>
                      <p className="text-red-500 text-sm">{scan.vulnerabilities_found} vulnerabilities found</p>
                    </div>
                  </div>
                  <div className="mt-3 pt-3 border-t border-gray-700">
                    <div className="flex justify-between text-sm text-gray-400">
                      <span>Engine: {scan.engine_version}</span>
                      <span>Duration: {scan.scan_duration}s</span>
                      <span>Started: {new Date(scan.started_at).toLocaleString()}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'waf' && (
          <div>
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-bold text-white">WAF Rules</h2>
              <button className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg flex items-center">
                <Lock className="mr-2" size={16} />
                Add WAF Rule
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-700">
                    <th className="text-left py-3 px-4">Rule Name</th>
                    <th className="text-left py-3 px-4">Description</th>
                    <th className="text-left py-3 px-4">Action</th>
                    <th className="text-left py-3 px-4">Priority</th>
                    <th className="text-left py-3 px-4">Status</th>
                    <th className="text-left py-3 px-4">Hit Count</th>
                    <th className="text-left py-3 px-4">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {wafRules.map((rule) => (
                    <tr key={rule.id} className="border-b border-gray-800">
                      <td className="py-3 px-4">
                        <p className="text-white font-medium">{rule.name}</p>
                      </td>
                      <td className="py-3 px-4 text-gray-300 text-xs">{rule.description}</td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-1 rounded text-xs font-medium ${getWAFActionColor(rule.action)}`}>
                          {rule.action}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-gray-300">{rule.priority}</td>
                      <td className="py-3 px-4">
                        <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
                          rule.enabled ? 'bg-green-600/20 text-green-400' : 'bg-gray-600/20 text-gray-400'
                        }`}>
                          {rule.enabled ? 'Active' : 'Inactive'}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-gray-300">{rule.hit_count}</td>
                      <td className="py-3 px-4">
                        <div className="flex space-x-2">
                          <button className="text-blue-400 hover:text-blue-300" title="Edit">
                            <Settings size={16} />
                          </button>
                          <button className="text-red-400 hover:text-red-300" title="Delete">
                            <XCircle size={16} />
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

        {activeTab === 'vulnerabilities' && (
          <div>
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-bold text-white">Vulnerabilities</h2>
              <div className="flex space-x-2">
                <select className="bg-cyber-dark border border-gray-700 rounded-lg px-3 py-2 text-white">
                  <option>All Severities</option>
                  <option>Critical</option>
                  <option>High</option>
                  <option>Medium</option>
                  <option>Low</option>
                </select>
                <select className="bg-cyber-dark border border-gray-700 rounded-lg px-3 py-2 text-white">
                  <option>All Types</option>
                  <option>SAST</option>
                  <option>DAST</option>
                  <option>SCA</option>
                </select>
              </div>
            </div>

            <div className="space-y-4">
              {vulnerabilities.map((vuln) => (
                <div key={vuln.id} className="bg-cyber-dark border border-gray-700 rounded-lg p-4">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center space-x-3 mb-2">
                        <h3 className="text-white font-medium">{vuln.title}</h3>
                        <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(vuln.severity)}`}>
                          {vuln.severity}
                        </span>
                        <span className="px-2 py-1 rounded text-xs font-medium bg-gray-600 text-gray-200">
                          {vuln.scan_type}
                        </span>
                      </div>
                      <p className="text-gray-400 text-sm mb-3">{vuln.description}</p>
                      
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                        {vuln.file_path && (
                          <div>
                            <p className="text-gray-500">File</p>
                            <p className="text-white">{vuln.file_path}</p>
                          </div>
                        )}
                        {vuln.component_name && (
                          <div>
                            <p className="text-gray-500">Component</p>
                            <p className="text-white">{vuln.component_name} {vuln.component_version}</p>
                          </div>
                        )}
                        <div>
                          <p className="text-gray-500">Discovered</p>
                          <p className="text-white">{new Date(vuln.discovered_at).toLocaleDateString()}</p>
                        </div>
                      </div>

                      <div className="mt-3">
                        <p className="text-gray-500 text-sm mb-1">Remediation:</p>
                        <p className="text-gray-300 text-sm">{vuln.remediation}</p>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ApplicationSecurity; 