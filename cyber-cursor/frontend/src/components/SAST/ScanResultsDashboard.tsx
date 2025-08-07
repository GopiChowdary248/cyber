import React, { useState, useEffect } from 'react';
import EnhancedCard from '../UI/EnhancedCard';
import EnhancedButton from '../UI/EnhancedButton';
import EnhancedBadge from '../UI/EnhancedBadge';
import EnhancedTabs from '../UI/EnhancedTabs';
import { 
  BugAntIcon, 
  ExclamationTriangleIcon, 
  InformationCircleIcon,
  CheckCircleIcon,
  ClockIcon,
  DocumentTextIcon,
  ChartBarIcon,
  EyeIcon,
  ArrowDownTrayIcon,
  FunnelIcon,
  MagnifyingGlassIcon
} from '@heroicons/react/24/outline';

interface Vulnerability {
  id: string;
  pattern_id: string;
  name: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  cwe_id: string;
  category: string;
  cvss_score: number;
  owasp_category: string;
  remediation: string;
  file_path: string;
  line_number: number;
  start_line: number;
  end_line: number;
  code_snippet: string;
  context: string;
  language: string;
  status: 'open' | 'in_progress' | 'resolved' | 'false_positive';
  created_at: string;
}

interface ScanResult {
  id: string;
  scan_name: string;
  scan_type: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  progress: number;
  total_vulnerabilities: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  files_scanned: number;
  lines_scanned: number;
  scan_duration: number;
  started_at: string;
  completed_at?: string;
  vulnerabilities: Vulnerability[];
  categorized_vulns: {
    by_severity: Record<string, number>;
    by_category: Record<string, number>;
    by_language: Record<string, number>;
    by_cwe: Record<string, number>;
    by_owasp: Record<string, number>;
  };
}

interface ScanResultsDashboardProps {
  scanId?: string;
  projectId?: string;
}

const ScanResultsDashboard: React.FC<ScanResultsDashboardProps> = ({ scanId, projectId }) => {
  const [activeTab, setActiveTab] = useState('overview');
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [filterCategory, setFilterCategory] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [sortBy, setSortBy] = useState<string>('severity');

  // Mock data for demonstration
  const mockScanResult: ScanResult = {
    id: "scan-001",
    scan_name: "SAST Security Scan",
    scan_type: "sast",
    status: "completed",
    progress: 100,
    total_vulnerabilities: 15,
    critical: 3,
    high: 5,
    medium: 4,
    low: 3,
    files_scanned: 45,
    lines_scanned: 1250,
    scan_duration: 45,
    started_at: "2024-01-15T10:00:00Z",
    completed_at: "2024-01-15T10:45:00Z",
    vulnerabilities: [
      {
        id: "vuln-001",
        pattern_id: "SQL_INJECTION_1",
        name: "SQL Injection via string concatenation",
        description: "SQL query constructed using string concatenation with user input",
        severity: "critical",
        cwe_id: "CWE-89",
        category: "sql_injection",
        cvss_score: 9.8,
        owasp_category: "A03:2021-Injection",
        remediation: "Use parameterized queries or ORM to prevent SQL injection",
        file_path: "src/database/connection.py",
        line_number: 45,
        start_line: 45,
        end_line: 45,
        code_snippet: "execute('SELECT * FROM users WHERE id = ' + user_input)",
        context: "def get_user(user_input):\n    # Vulnerable code\n    execute('SELECT * FROM users WHERE id = ' + user_input)\n    return result",
        language: "python",
        status: "open",
        created_at: "2024-01-15T10:45:00Z"
      },
      {
        id: "vuln-002",
        pattern_id: "XSS_1",
        name: "Reflected XSS via innerHTML",
        description: "User input directly assigned to innerHTML",
        severity: "high",
        cwe_id: "CWE-79",
        category: "xss",
        cvss_score: 6.1,
        owasp_category: "A03:2021-Injection",
        remediation: "Use textContent or sanitize input before assignment",
        file_path: "src/components/UserProfile.jsx",
        line_number: 23,
        start_line: 23,
        end_line: 23,
        code_snippet: "element.innerHTML = userData.name",
        context: "function updateProfile(userData) {\n    const element = document.getElementById('profile');\n    element.innerHTML = userData.name;\n}",
        language: "javascript",
        status: "open",
        created_at: "2024-01-15T10:45:00Z"
      },
      {
        id: "vuln-003",
        pattern_id: "HARDCODED_SECRET_1",
        name: "Hardcoded API Key",
        description: "API key hardcoded in source code",
        severity: "medium",
        cwe_id: "CWE-798",
        category: "hardcoded_secrets",
        cvss_score: 5.3,
        owasp_category: "A07:2021-Identification and Authentication Failures",
        remediation: "Use environment variables or secure secret management",
        file_path: "config/api_config.py",
        line_number: 12,
        start_line: 12,
        end_line: 12,
        code_snippet: "api_key = 'sk-1234567890abcdef1234567890abcdef'",
        context: "# API Configuration\napi_key = 'sk-1234567890abcdef1234567890abcdef'\nbase_url = 'https://api.example.com'",
        language: "python",
        status: "open",
        created_at: "2024-01-15T10:45:00Z"
      }
    ],
    categorized_vulns: {
      by_severity: { critical: 3, high: 5, medium: 4, low: 3 },
      by_category: { 
        sql_injection: 3, 
        xss: 4, 
        command_injection: 2, 
        hardcoded_secrets: 3, 
        path_traversal: 2, 
        weak_cryptography: 1 
      },
      by_language: { python: 8, javascript: 5, java: 2 },
      by_cwe: { "CWE-89": 3, "CWE-79": 4, "CWE-78": 2, "CWE-798": 3, "CWE-22": 2, "CWE-327": 1 },
      by_owasp: { 
        "A03:2021-Injection": 9, 
        "A07:2021-Identification and Authentication Failures": 3, 
        "A01:2021-Broken Access Control": 2, 
        "A02:2021-Cryptographic Failures": 1 
      }
    }
  };

  useEffect(() => {
    // Load scan results
    setScanResult(mockScanResult);
    setLoading(false);
  }, [scanId]);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'red';
      case 'high': return 'orange';
      case 'medium': return 'yellow';
      case 'low': return 'green';
      default: return 'gray';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical': return <ExclamationTriangleIcon className="w-5 h-5" />;
      case 'high': return <BugAntIcon className="w-5 h-5" />;
      case 'medium': return <InformationCircleIcon className="w-5 h-5" />;
      case 'low': return <CheckCircleIcon className="w-5 h-5" />;
      default: return <InformationCircleIcon className="w-5 h-5" />;
    }
  };

  const filteredVulnerabilities = scanResult?.vulnerabilities.filter(vuln => {
    const matchesSeverity = filterSeverity === 'all' || vuln.severity === filterSeverity;
    const matchesCategory = filterCategory === 'all' || vuln.category === filterCategory;
    const matchesSearch = searchTerm === '' || 
      vuln.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      vuln.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      vuln.file_path.toLowerCase().includes(searchTerm.toLowerCase());
    
    return matchesSeverity && matchesCategory && matchesSearch;
  }) || [];

  const sortedVulnerabilities = [...filteredVulnerabilities].sort((a, b) => {
    switch (sortBy) {
      case 'severity':
        const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
        return severityOrder[b.severity] - severityOrder[a.severity];
      case 'cvss_score':
        return b.cvss_score - a.cvss_score;
      case 'file_path':
        return a.file_path.localeCompare(b.file_path);
      case 'line_number':
        return a.line_number - b.line_number;
      default:
        return 0;
    }
  });

  const exportReport = (format: 'pdf' | 'json' | 'csv') => {
    // Implementation for report export
    console.log(`Exporting report in ${format} format`);
  };

  const tabs = [
    {
      id: 'overview',
      label: 'Overview',
      content: (
        <div className="space-y-6">
          {/* Scan Summary */}
          <EnhancedCard>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold">Scan Summary</h3>
              <EnhancedBadge variant={scanResult?.status === 'completed' ? 'success' : 'warning'}>
                {scanResult?.status || 'unknown'}
              </EnhancedBadge>
            </div>
            
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
              <div className="text-center">
                <div className="text-2xl font-bold text-red-600">{scanResult?.critical || 0}</div>
                <div className="text-sm text-gray-600">Critical</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-orange-600">{scanResult?.high || 0}</div>
                <div className="text-sm text-gray-600">High</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-yellow-600">{scanResult?.medium || 0}</div>
                <div className="text-sm text-gray-600">Medium</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-green-600">{scanResult?.low || 0}</div>
                <div className="text-sm text-gray-600">Low</div>
              </div>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
              <div>
                <span className="font-medium">Files Scanned:</span> {scanResult?.files_scanned || 0}
              </div>
              <div>
                <span className="font-medium">Lines Scanned:</span> {scanResult?.lines_scanned || 0}
              </div>
              <div>
                <span className="font-medium">Scan Duration:</span> {scanResult?.scan_duration || 0}s
              </div>
            </div>
          </EnhancedCard>

          {/* Vulnerability Categories */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <EnhancedCard>
              <h3 className="text-lg font-semibold mb-4">By Category</h3>
              <div className="space-y-2">
                {Object.entries(scanResult?.categorized_vulns.by_category || {}).map(([category, count]) => (
                  <div key={category} className="flex justify-between items-center">
                    <span className="capitalize">{category.replace('_', ' ')}</span>
                    <EnhancedBadge variant="info">{count.toString()}</EnhancedBadge>
                  </div>
                ))}
              </div>
            </EnhancedCard>

            <EnhancedCard>
              <h3 className="text-lg font-semibold mb-4">By Language</h3>
              <div className="space-y-2">
                {Object.entries(scanResult?.categorized_vulns.by_language || {}).map(([language, count]) => (
                  <div key={language} className="flex justify-between items-center">
                    <span className="capitalize">{language}</span>
                    <EnhancedBadge variant="primary">{count.toString()}</EnhancedBadge>
                  </div>
                ))}
              </div>
            </EnhancedCard>
          </div>
        </div>
      )
    },
    {
      id: 'vulnerabilities',
      label: 'Vulnerabilities',
      content: (
        <div className="space-y-6">
          {/* Filters and Search */}
          <EnhancedCard>
            <div className="flex flex-col md:flex-row gap-4 mb-4">
              <div className="flex-1">
                <div className="relative">
                  <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                  <input
                    type="text"
                    placeholder="Search vulnerabilities..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>
              </div>
              <select
                value={filterSeverity}
                onChange={(e) => setFilterSeverity(e.target.value)}
                className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
              <select
                value={filterCategory}
                onChange={(e) => setFilterCategory(e.target.value)}
                className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="all">All Categories</option>
                <option value="sql_injection">SQL Injection</option>
                <option value="xss">XSS</option>
                <option value="command_injection">Command Injection</option>
                <option value="hardcoded_secrets">Hardcoded Secrets</option>
                <option value="path_traversal">Path Traversal</option>
                <option value="weak_cryptography">Weak Cryptography</option>
              </select>
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value)}
                className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="severity">Sort by Severity</option>
                <option value="cvss_score">Sort by CVSS Score</option>
                <option value="file_path">Sort by File</option>
                <option value="line_number">Sort by Line</option>
              </select>
            </div>
            <div className="text-sm text-gray-600">
              Showing {sortedVulnerabilities.length} of {scanResult?.total_vulnerabilities || 0} vulnerabilities
            </div>
          </EnhancedCard>

          {/* Vulnerability List */}
          <div className="space-y-4">
            {sortedVulnerabilities.map((vuln) => (
              <EnhancedCard key={vuln.id} className="hover:shadow-lg transition-shadow">
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-3">
                    {getSeverityIcon(vuln.severity)}
                    <div>
                      <h4 className="font-semibold text-lg">{vuln.name}</h4>
                      <div className="flex items-center gap-2 text-sm text-gray-600">
                        <span>{vuln.file_path}:{vuln.line_number}</span>
                        <span>•</span>
                        <span className="capitalize">{vuln.language}</span>
                        <span>•</span>
                        <span>{vuln.cwe_id}</span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <EnhancedBadge 
                      variant={vuln.severity === 'critical' ? 'danger' : vuln.severity === 'high' ? 'warning' : vuln.severity === 'medium' ? 'warning' : 'success'}
                    >
                      {vuln.severity}
                    </EnhancedBadge>
                    <span className="text-sm font-medium">CVSS: {vuln.cvss_score}</span>
                  </div>
                </div>
                
                <p className="text-gray-700 mb-3">{vuln.description}</p>
                
                <div className="bg-gray-50 p-3 rounded-lg mb-3">
                  <div className="text-sm font-medium text-gray-700 mb-1">Vulnerable Code:</div>
                  <pre className="text-sm bg-white p-2 rounded border overflow-x-auto">
                    <code>{vuln.code_snippet}</code>
                  </pre>
                </div>
                
                <div className="flex items-center justify-between">
                  <div className="text-sm text-gray-600">
                    <span className="font-medium">Remediation:</span> {vuln.remediation}
                  </div>
                  <div className="flex gap-2">
                    <EnhancedButton
                      size="sm"
                      variant="outline"
                      onClick={() => console.log('View details:', vuln.id)}
                    >
                      <EyeIcon className="w-4 h-4 mr-1" />
                      Details
                    </EnhancedButton>
                    <EnhancedButton
                      size="sm"
                      variant="outline"
                      onClick={() => console.log('Mark as resolved:', vuln.id)}
                    >
                      <CheckCircleIcon className="w-4 h-4 mr-1" />
                      Resolve
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
      id: 'reports',
      label: 'Reports',
      content: (
        <div className="space-y-6">
          <EnhancedCard>
            <h3 className="text-lg font-semibold mb-4">Export Reports</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <EnhancedButton
                onClick={() => exportReport('pdf')}
                className="flex items-center justify-center"
              >
                <DocumentTextIcon className="w-5 h-5 mr-2" />
                Export PDF
              </EnhancedButton>
              <EnhancedButton
                onClick={() => exportReport('json')}
                className="flex items-center justify-center"
              >
                <DocumentTextIcon className="w-5 h-5 mr-2" />
                Export JSON
              </EnhancedButton>
              <EnhancedButton
                onClick={() => exportReport('csv')}
                className="flex items-center justify-center"
              >
                <ArrowDownTrayIcon className="w-5 h-5 mr-2" />
                Export CSV
              </EnhancedButton>
            </div>
          </EnhancedCard>

          <EnhancedCard>
            <h3 className="text-lg font-semibold mb-4">OWASP Top 10 Analysis</h3>
            <div className="space-y-3">
              {Object.entries(scanResult?.categorized_vulns.by_owasp || {}).map(([owasp, count]) => (
                <div key={owasp} className="flex justify-between items-center p-3 bg-gray-50 rounded-lg">
                  <span className="font-medium">{owasp}</span>
                  <EnhancedBadge variant="danger">{count.toString()}</EnhancedBadge>
                </div>
              ))}
            </div>
          </EnhancedCard>
        </div>
      )
    }
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <ClockIcon className="w-12 h-12 mx-auto text-gray-400 mb-4" />
          <p className="text-gray-600">Loading scan results...</p>
        </div>
      </div>
    );
  }

  if (!scanResult) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <DocumentTextIcon className="w-12 h-12 mx-auto text-gray-400 mb-4" />
          <p className="text-gray-600">No scan results found</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">{scanResult.scan_name}</h2>
          <p className="text-gray-600">Comprehensive vulnerability analysis results</p>
        </div>
        <div className="flex items-center gap-2">
          <EnhancedBadge 
            variant={scanResult.status === 'completed' ? 'success' : 'warning'}
          >
            {scanResult.status}
          </EnhancedBadge>
          <span className="text-sm text-gray-600">
            {new Date(scanResult.started_at).toLocaleDateString()}
          </span>
        </div>
      </div>

      <EnhancedTabs tabs={tabs} activeTab={activeTab} onTabChange={setActiveTab} />
    </div>
  );
};

export default ScanResultsDashboard; 