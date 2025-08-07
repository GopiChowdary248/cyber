import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  BugAntIcon, 
  ExclamationTriangleIcon, 
  CheckCircleIcon, 
  ClockIcon,
  DocumentTextIcon,
  ChartBarIcon,
  FunnelIcon,
  EyeIcon,
  CodeBracketIcon,
  ShieldCheckIcon,
  ArrowDownTrayIcon,
  MagnifyingGlassIcon
} from '@heroicons/react/24/outline';
import EnhancedCard from '../../components/UI/EnhancedCard';
import EnhancedButton from '../../components/UI/EnhancedButton';
import EnhancedBadge from '../../components/UI/EnhancedBadge';
import EnhancedTabs from '../../components/UI/EnhancedTabs';
import { toast } from 'react-hot-toast';

interface Vulnerability {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  status: 'open' | 'resolved' | 'in_progress';
  file_path: string;
  line_number: number;
  line_content: string;
  vulnerability_type: string;
  remediation: string;
  created_at: string;
  cwe_id?: string;
  cvss_score?: number;
  owasp_category?: string;
}

interface ScanResult {
  id: string;
  scan_name: string;
  scan_type: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  progress: number;
  total_issues: number;
  critical_issues: number;
  high_issues: number;
  medium_issues: number;
  low_issues: number;
  created_at: string;
  completed_at?: string;
  scan_duration?: number;
  files_scanned?: number;
  lines_scanned?: number;
}

const SASTScanResults: React.FC = () => {
  const [activeTab, setActiveTab] = useState('overview');
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [filteredVulnerabilities, setFilteredVulnerabilities] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(false);
  const [filters, setFilters] = useState({
    severity: 'all',
    category: 'all',
    status: 'all',
    search: ''
  });

  // Mock data for demonstration
  const mockScans: ScanResult[] = [
    {
      id: '1',
      scan_name: 'Full Security Scan',
      scan_type: 'sast',
      status: 'completed',
      progress: 100,
      total_issues: 24,
      critical_issues: 2,
      high_issues: 8,
      medium_issues: 10,
      low_issues: 4,
      created_at: '2024-01-15T10:30:00Z',
      completed_at: '2024-01-15T10:45:00Z',
      scan_duration: 900,
      files_scanned: 156,
      lines_scanned: 12450
    },
    {
      id: '2',
      scan_name: 'Quick Security Check',
      scan_type: 'sast',
      status: 'completed',
      progress: 100,
      total_issues: 12,
      critical_issues: 0,
      high_issues: 3,
      medium_issues: 6,
      low_issues: 3,
      created_at: '2024-01-14T15:20:00Z',
      completed_at: '2024-01-14T15:25:00Z',
      scan_duration: 300,
      files_scanned: 89,
      lines_scanned: 7200
    }
  ];

  const mockVulnerabilities: Vulnerability[] = [
    {
      id: '1',
      title: 'SQL Injection Vulnerability',
      description: 'User input is directly concatenated into SQL query without proper sanitization',
      severity: 'critical',
      category: 'injection',
      status: 'open',
      file_path: 'src/controllers/user_controller.py',
      line_number: 45,
      line_content: 'query = f"SELECT * FROM users WHERE id = {user_id}"',
      vulnerability_type: 'sql_injection',
      remediation: 'Use parameterized queries or ORM to prevent SQL injection',
      created_at: '2024-01-15T10:45:00Z',
      cwe_id: 'CWE-89',
      cvss_score: 9.8,
      owasp_category: 'A03:2021'
    },
    {
      id: '2',
      title: 'Cross-Site Scripting (XSS)',
      description: 'User input is rendered directly in HTML without proper encoding',
      severity: 'high',
      category: 'xss',
      status: 'open',
      file_path: 'src/views/user_profile.html',
      line_number: 23,
      line_content: '<div id="user-info">${user.name}</div>',
      vulnerability_type: 'xss',
      remediation: 'Use proper input validation and output encoding',
      created_at: '2024-01-15T10:45:00Z',
      cwe_id: 'CWE-79',
      cvss_score: 7.2,
      owasp_category: 'A03:2021'
    },
    {
      id: '3',
      title: 'Hardcoded Credentials',
      description: 'Database password is hardcoded in source code',
      severity: 'high',
      category: 'credentials',
      status: 'in_progress',
      file_path: 'src/config/database.py',
      line_number: 12,
      line_content: 'password = "super_secret_password_123"',
      vulnerability_type: 'hardcoded_credentials',
      remediation: 'Use environment variables for sensitive configuration',
      created_at: '2024-01-15T10:45:00Z',
      cwe_id: 'CWE-259',
      cvss_score: 7.5,
      owasp_category: 'A02:2021'
    },
    {
      id: '4',
      title: 'Command Injection',
      description: 'User input is passed to system command without validation',
      severity: 'critical',
      category: 'injection',
      status: 'open',
      file_path: 'src/utils/system_utils.py',
      line_number: 67,
      line_content: 'os.system(f"ping {hostname}")',
      vulnerability_type: 'command_injection',
      remediation: 'Use subprocess.run with proper argument validation',
      created_at: '2024-01-15T10:45:00Z',
      cwe_id: 'CWE-78',
      cvss_score: 9.1,
      owasp_category: 'A03:2021'
    },
    {
      id: '5',
      title: 'Weak Cryptographic Algorithm',
      description: 'MD5 hash function is used for password hashing',
      severity: 'medium',
      category: 'cryptography',
      status: 'resolved',
      file_path: 'src/auth/password_utils.py',
      line_number: 34,
      line_content: 'hashed = hashlib.md5(password.encode()).hexdigest()',
      vulnerability_type: 'weak_crypto',
      remediation: 'Use bcrypt, Argon2, or PBKDF2 for password hashing',
      created_at: '2024-01-15T10:45:00Z',
      cwe_id: 'CWE-327',
      cvss_score: 5.3,
      owasp_category: 'A02:2021'
    }
  ];

  useEffect(() => {
    setVulnerabilities(mockVulnerabilities);
    setSelectedScan(mockScans[0]);
  }, []);

  useEffect(() => {
    // Apply filters
    let filtered = vulnerabilities;

    if (filters.severity !== 'all') {
      filtered = filtered.filter(v => v.severity === filters.severity);
    }

    if (filters.category !== 'all') {
      filtered = filtered.filter(v => v.category === filters.category);
    }

    if (filters.status !== 'all') {
      filtered = filtered.filter(v => v.status === filters.status);
    }

    if (filters.search) {
      filtered = filtered.filter(v => 
        v.title.toLowerCase().includes(filters.search.toLowerCase()) ||
        v.description.toLowerCase().includes(filters.search.toLowerCase()) ||
        v.file_path.toLowerCase().includes(filters.search.toLowerCase())
      );
    }

    setFilteredVulnerabilities(filtered);
  }, [vulnerabilities, filters]);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'red';
      case 'high': return 'orange';
      case 'medium': return 'yellow';
      case 'low': return 'green';
      default: return 'gray';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'open': return 'red';
      case 'in_progress': return 'yellow';
      case 'resolved': return 'green';
      default: return 'gray';
    }
  };

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'injection': return <CodeBracketIcon className="w-4 h-4" />;
      case 'xss': return <BugAntIcon className="w-4 h-4" />;
      case 'credentials': return <ShieldCheckIcon className="w-4 h-4" />;
      case 'cryptography': return <ShieldCheckIcon className="w-4 h-4" />;
      default: return <ExclamationTriangleIcon className="w-4 h-4" />;
    }
  };

  const exportReport = (format: 'json' | 'csv' | 'html') => {
    toast.success(`Exporting report in ${format.toUpperCase()} format...`);
    // In real implementation, this would call the API
  };

  const tabs = [
    {
      id: 'overview',
      label: 'Overview',
      icon: <ChartBarIcon className="w-5 h-5" />,
      content: (
        <div className="space-y-6">
          {/* Scan Summary */}
          <EnhancedCard>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold">Scan Summary</h3>
              <div className="flex space-x-2">
                <EnhancedButton
                  variant="outline"
                  size="sm"
                  onClick={() => exportReport('json')}
                >
                  <ArrowDownTrayIcon className="w-4 h-4 mr-2" />
                  Export JSON
                </EnhancedButton>
                <EnhancedButton
                  variant="outline"
                  size="sm"
                  onClick={() => exportReport('csv')}
                >
                  <ArrowDownTrayIcon className="w-4 h-4 mr-2" />
                  Export CSV
                </EnhancedButton>
              </div>
            </div>
            
            {selectedScan && (
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="text-center p-4 bg-red-50 rounded-lg">
                  <div className="text-2xl font-bold text-red-600">{selectedScan.critical_issues}</div>
                  <div className="text-sm text-gray-600">Critical</div>
                </div>
                <div className="text-center p-4 bg-orange-50 rounded-lg">
                  <div className="text-2xl font-bold text-orange-600">{selectedScan.high_issues}</div>
                  <div className="text-sm text-gray-600">High</div>
                </div>
                <div className="text-center p-4 bg-yellow-50 rounded-lg">
                  <div className="text-2xl font-bold text-yellow-600">{selectedScan.medium_issues}</div>
                  <div className="text-sm text-gray-600">Medium</div>
                </div>
                <div className="text-center p-4 bg-green-50 rounded-lg">
                  <div className="text-2xl font-bold text-green-600">{selectedScan.low_issues}</div>
                  <div className="text-sm text-gray-600">Low</div>
                </div>
              </div>
            )}
          </EnhancedCard>

          {/* Scan Details */}
          <EnhancedCard>
            <h3 className="text-lg font-semibold mb-4">Scan Details</h3>
            {selectedScan && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <div className="text-sm text-gray-600">Scan Name</div>
                  <div className="font-medium">{selectedScan.scan_name}</div>
                </div>
                <div>
                  <div className="text-sm text-gray-600">Status</div>
                  <EnhancedBadge variant={selectedScan.status === 'completed' ? 'success' : 'warning'}>
                    {selectedScan.status}
                  </EnhancedBadge>
                </div>
                <div>
                  <div className="text-sm text-gray-600">Files Scanned</div>
                  <div className="font-medium">{selectedScan.files_scanned}</div>
                </div>
                <div>
                  <div className="text-sm text-gray-600">Lines Scanned</div>
                  <div className="font-medium">{selectedScan.lines_scanned?.toLocaleString()}</div>
                </div>
                <div>
                  <div className="text-sm text-gray-600">Duration</div>
                  <div className="font-medium">{selectedScan.scan_duration ? `${selectedScan.scan_duration}s` : 'N/A'}</div>
                </div>
                <div>
                  <div className="text-sm text-gray-600">Completed</div>
                  <div className="font-medium">
                    {selectedScan.completed_at ? new Date(selectedScan.completed_at).toLocaleString() : 'N/A'}
                  </div>
                </div>
              </div>
            )}
          </EnhancedCard>
        </div>
      )
    },
    {
      id: 'vulnerabilities',
      label: 'Vulnerabilities',
      icon: <BugAntIcon className="w-5 h-5" />,
      content: (
        <div className="space-y-6">
          {/* Filters */}
          <EnhancedCard>
            <div className="flex flex-col md:flex-row gap-4">
              <div className="flex-1">
                <div className="relative">
                  <MagnifyingGlassIcon className="w-5 h-5 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                  <input
                    type="text"
                    placeholder="Search vulnerabilities..."
                    className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    value={filters.search}
                    onChange={(e) => setFilters({ ...filters, search: e.target.value })}
                  />
                </div>
              </div>
              <div className="flex gap-2">
                <select
                  className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                  value={filters.severity}
                  onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
                >
                  <option value="all">All Severities</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
                <select
                  className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                  value={filters.category}
                  onChange={(e) => setFilters({ ...filters, category: e.target.value })}
                >
                  <option value="all">All Categories</option>
                  <option value="injection">Injection</option>
                  <option value="xss">XSS</option>
                  <option value="credentials">Credentials</option>
                  <option value="cryptography">Cryptography</option>
                </select>
                <select
                  className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                  value={filters.status}
                  onChange={(e) => setFilters({ ...filters, status: e.target.value })}
                >
                  <option value="all">All Status</option>
                  <option value="open">Open</option>
                  <option value="in_progress">In Progress</option>
                  <option value="resolved">Resolved</option>
                </select>
              </div>
            </div>
          </EnhancedCard>

          {/* Vulnerabilities List */}
          <div className="space-y-4">
            {filteredVulnerabilities.map((vuln) => (
              <EnhancedCard key={vuln.id} className="hover:shadow-md transition-shadow">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <div className="flex items-center gap-2">
                        {getCategoryIcon(vuln.category)}
                        <h4 className="font-semibold text-lg">{vuln.title}</h4>
                      </div>
                      <EnhancedBadge variant={vuln.severity === 'critical' ? 'danger' : vuln.severity === 'high' ? 'warning' : vuln.severity === 'medium' ? 'warning' : 'success'}>
                        {vuln.severity}
                      </EnhancedBadge>
                      <EnhancedBadge variant={vuln.status === 'open' ? 'danger' : vuln.status === 'in_progress' ? 'warning' : 'success'}>
                        {vuln.status.replace('_', ' ')}
                      </EnhancedBadge>
                    </div>
                    
                    <p className="text-gray-600 mb-3">{vuln.description}</p>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                      <div>
                        <span className="font-medium">File:</span> {vuln.file_path}:{vuln.line_number}
                      </div>
                      <div>
                        <span className="font-medium">Type:</span> {vuln.vulnerability_type}
                      </div>
                      {vuln.cwe_id && (
                        <div>
                          <span className="font-medium">CWE:</span> {vuln.cwe_id}
                        </div>
                      )}
                      {vuln.cvss_score && (
                        <div>
                          <span className="font-medium">CVSS:</span> {vuln.cvss_score}
                        </div>
                      )}
                    </div>
                    
                    <div className="mt-3 p-3 bg-gray-50 rounded-lg">
                      <div className="font-medium text-sm mb-1">Code Line:</div>
                      <code className="text-sm bg-white p-2 rounded border">{vuln.line_content}</code>
                    </div>
                    
                    <div className="mt-3">
                      <div className="font-medium text-sm mb-1">Remediation:</div>
                      <p className="text-sm text-gray-700">{vuln.remediation}</p>
                    </div>
                  </div>
                  
                  <div className="flex flex-col gap-2 ml-4">
                    <EnhancedButton variant="outline" size="sm">
                      <EyeIcon className="w-4 h-4 mr-2" />
                      View Details
                    </EnhancedButton>
                    <EnhancedButton variant="outline" size="sm">
                      <DocumentTextIcon className="w-4 h-4 mr-2" />
                      Mark Resolved
                    </EnhancedButton>
                  </div>
                </div>
              </EnhancedCard>
            ))}
          </div>
        </div>
      )
    },
    {
      id: 'trends',
      label: 'Trends',
      icon: <ChartBarIcon className="w-5 h-5" />,
      content: (
        <div className="space-y-6">
          <EnhancedCard>
            <h3 className="text-lg font-semibold mb-4">Vulnerability Trends</h3>
            <div className="text-center text-gray-500 py-8">
              <ChartBarIcon className="w-12 h-12 mx-auto mb-4 text-gray-300" />
              <p>Trend analysis and charts will be displayed here</p>
              <p className="text-sm">Showing vulnerability trends over time</p>
            </div>
          </EnhancedCard>
        </div>
      )
    }
  ];

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">SAST Scan Results</h1>
          <p className="text-gray-600">Comprehensive vulnerability analysis and reporting</p>
        </div>
        <div className="flex space-x-2">
          <EnhancedButton variant="outline">
            <DocumentTextIcon className="w-4 h-4 mr-2" />
            Generate Report
          </EnhancedButton>
          <EnhancedButton>
            <ArrowDownTrayIcon className="w-4 h-4 mr-2" />
            Export All
          </EnhancedButton>
        </div>
      </div>

      <EnhancedTabs tabs={tabs} activeTab={activeTab} onTabChange={setActiveTab} />
    </div>
  );
};

export default SASTScanResults; 