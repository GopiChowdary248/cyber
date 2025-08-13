import React, { useState, useEffect } from 'react';
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Settings,
  Filter,
  Search,
  Eye,
  Edit,
  Save,
  X,
  Plus,
  Trash2,
  Code,
  Bug,
  Lock,
  Unlock,
  RefreshCw
} from 'lucide-react';

interface QualityRule {
  id: string;
  rule_id: string;
  name: string;
  description: string;
  category: string;
  subcategory: string;
  severity: string;
  type: string;
  cwe_id?: string;
  owasp_category?: string;
  tags: string[];
  enabled: boolean;
  effort: string;
  languages: string[];
  created_at?: string;
}

interface QualityRulesProps {
  projectId?: string;
}

const QualityRules: React.FC<QualityRulesProps> = ({ projectId }) => {
  const [rules, setRules] = useState<QualityRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [filteredRules, setFilteredRules] = useState<QualityRule[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [selectedLanguage, setSelectedLanguage] = useState<string>('all');
  const [showRuleDetails, setShowRuleDetails] = useState<string | null>(null);
  const [editingRule, setEditingRule] = useState<QualityRule | null>(null);
  const [error, setError] = useState<string | null>(null);

  const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

  useEffect(() => {
    fetchRules();
  }, [projectId]);

  useEffect(() => {
    filterRules();
  }, [rules, searchTerm, selectedSeverity, selectedCategory, selectedLanguage]);

  const fetchRules = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('access_token');
      
      if (!token) {
        setError('Authentication token not found');
        return;
      }

      const response = await fetch(`${API_BASE_URL}/api/v1/sast/rules`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      setRules(data.rules || []);
      setError(null);
    } catch (error) {
      console.error('Error fetching quality rules:', error);
      setError('Failed to fetch quality rules');
      // Fallback to mock data for demo
      setRules(getMockRules());
    } finally {
      setLoading(false);
    }
  };

  const getMockRules = (): QualityRule[] => [
    {
      id: '1',
      rule_id: 'S1488',
      name: 'Local variables should not be declared and then immediately returned or thrown',
      description: 'Declaring a variable only to immediately return or throw it is a bad practice.',
      category: 'Code Smell',
      subcategory: 'Unnecessary',
      severity: 'minor',
      type: 'CODE_SMELL',
      cwe_id: 'CWE-398',
      owasp_category: 'A9',
      tags: ['unnecessary', 'clumsy'],
      enabled: true,
      effort: '5min',
      languages: ['java', 'python', 'javascript']
    },
    {
      id: '2',
      rule_id: 'S1172',
      name: 'Unused function parameters should be removed',
      description: 'Unused parameters are misleading and should be removed.',
      category: 'Code Smell',
      subcategory: 'Unused',
      severity: 'major',
      type: 'CODE_SMELL',
      cwe_id: 'CWE-398',
      owasp_category: 'A9',
      tags: ['unused', 'dead-code'],
      enabled: true,
      effort: '5min',
      languages: ['java', 'python', 'javascript']
    },
    {
      id: '3',
      rule_id: 'S1135',
      name: 'Track uses of "FIXME" tags',
      description: 'Track uses of FIXME tags to promote the removal of technical debt.',
      category: 'Code Smell',
      subcategory: 'Technical Debt',
      severity: 'info',
      type: 'CODE_SMELL',
      cwe_id: 'CWE-398',
      owasp_category: 'A9',
      tags: ['technical-debt', 'todo'],
      enabled: false,
      effort: '10min',
      languages: ['java', 'python', 'javascript']
    },
    {
      id: '4',
      rule_id: 'S107',
      name: 'Functions should not have too many parameters',
      description: 'Functions with too many parameters are hard to understand and maintain.',
      category: 'Code Smell',
      subcategory: 'Complexity',
      severity: 'major',
      type: 'CODE_SMELL',
      cwe_id: 'CWE-398',
      owasp_category: 'A9',
      tags: ['complexity', 'maintainability'],
      enabled: true,
      effort: '30min',
      languages: ['java', 'python', 'javascript']
    },
    {
      id: '5',
      rule_id: 'S1066',
      name: 'Collapsible "if" statements should be merged',
      description: 'Merging collapsible if statements increases the code readability.',
      category: 'Code Smell',
      subcategory: 'Readability',
      severity: 'minor',
      type: 'CODE_SMELL',
      cwe_id: 'CWE-398',
      owasp_category: 'A9',
      tags: ['readability', 'refactoring'],
      enabled: true,
      effort: '5min',
      languages: ['java', 'python', 'javascript']
    }
  ];

  const filterRules = () => {
    let filtered = [...rules];

    if (searchTerm) {
      filtered = filtered.filter(rule =>
        rule.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        rule.rule_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        rule.description.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    if (selectedSeverity !== 'all') {
      filtered = filtered.filter(rule => rule.severity === selectedSeverity);
    }

    if (selectedCategory !== 'all') {
      filtered = filtered.filter(rule => rule.category === selectedCategory);
    }

    if (selectedLanguage !== 'all') {
      filtered = filtered.filter(rule => rule.languages.includes(selectedLanguage));
    }

    setFilteredRules(filtered);
  };

  const toggleRuleStatus = async (ruleId: string) => {
    try {
      const token = localStorage.getItem('access_token');
      if (!token) {
        setError('Authentication token not found');
        return;
      }

      // Update local state immediately for better UX
      setRules(prev => prev.map(rule =>
        rule.id === ruleId ? { ...rule, enabled: !rule.enabled } : rule
      ));

      // In a real implementation, you would call the backend to update the rule status
      // For now, we'll just update the local state
      console.log(`Rule ${ruleId} ${rules.find(r => r.id === ruleId)?.enabled ? 'disabled' : 'enabled'}`);
    } catch (error) {
      console.error('Error updating rule status:', error);
      setError('Failed to update rule status');
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'blocker':
        return 'text-red-800 bg-red-100';
      case 'critical':
        return 'text-red-700 bg-red-100';
      case 'major':
        return 'text-orange-700 bg-orange-100';
      case 'minor':
        return 'text-yellow-700 bg-yellow-100';
      case 'info':
        return 'text-blue-700 bg-blue-100';
      default:
        return 'text-gray-700 bg-gray-100';
    }
  };

  const getCategoryColor = (category: string) => {
    switch (category.toLowerCase()) {
      case 'bug':
        return 'text-red-700 bg-red-100';
      case 'vulnerability':
        return 'text-purple-700 bg-purple-100';
      case 'code smell':
        return 'text-yellow-700 bg-yellow-100';
      case 'security hotspot':
        return 'text-orange-700 bg-orange-100';
      default:
        return 'text-gray-700 bg-gray-100';
    }
  };

  const getEffortColor = (effort: string) => {
    if (effort.includes('5min')) return 'text-green-700 bg-green-100';
    if (effort.includes('10min')) return 'text-yellow-700 bg-yellow-100';
    if (effort.includes('30min')) return 'text-orange-700 bg-orange-100';
    if (effort.includes('1h')) return 'text-red-700 bg-red-100';
    return 'text-gray-700 bg-gray-100';
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
          <h2 className="text-2xl font-bold text-gray-900">Quality Rules</h2>
          <p className="text-gray-600">Manage and configure SAST detection rules</p>
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={fetchRules}
            className="inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm leading-4 font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
          >
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </button>
        </div>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-md p-4">
          <div className="flex">
            <AlertTriangle className="w-5 h-5 text-red-400" />
            <div className="ml-3">
              <h3 className="text-sm font-medium text-red-800">Error</h3>
              <p className="text-sm text-red-700 mt-1">{error}</p>
            </div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="bg-white p-4 rounded-lg shadow-sm border border-gray-200">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="flex-1">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search rules..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
              />
            </div>
          </div>
          <div className="flex gap-2">
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="all">All Severities</option>
              <option value="blocker">Blocker</option>
              <option value="critical">Critical</option>
              <option value="major">Major</option>
              <option value="minor">Minor</option>
              <option value="info">Info</option>
            </select>
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="all">All Categories</option>
              <option value="Bug">Bug</option>
              <option value="Vulnerability">Vulnerability</option>
              <option value="Code Smell">Code Smell</option>
              <option value="Security Hotspot">Security Hotspot</option>
            </select>
            <select
              value={selectedLanguage}
              onChange={(e) => setSelectedLanguage(e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="all">All Languages</option>
              <option value="java">Java</option>
              <option value="python">Python</option>
              <option value="javascript">JavaScript</option>
              <option value="typescript">TypeScript</option>
              <option value="csharp">C#</option>
              <option value="php">PHP</option>
            </select>
          </div>
        </div>
      </div>

      {/* Rules List */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-200">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-medium text-gray-900">
              Rules ({filteredRules.length})
            </h3>
            <div className="text-sm text-gray-500">
              {rules.filter(r => r.enabled).length} enabled, {rules.filter(r => !r.enabled).length} disabled
            </div>
          </div>
        </div>
        
        <div className="divide-y divide-gray-200">
          {filteredRules.map((rule) => (
            <div key={rule.id} className="p-6 hover:bg-gray-50">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3 mb-2">
                    <h4 className="text-lg font-medium text-gray-900">{rule.name}</h4>
                    <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                      {rule.rule_id}
                    </span>
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(rule.severity)}`}>
                      {rule.severity}
                    </span>
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getCategoryColor(rule.category)}`}>
                      {rule.category}
                    </span>
                  </div>
                  
                  <p className="text-gray-600 mb-3">{rule.description}</p>
                  
                  <div className="flex items-center space-x-4 text-sm text-gray-500">
                    <div className="flex items-center space-x-1">
                      <Code className="w-4 h-4" />
                      <span>{rule.languages.join(', ')}</span>
                    </div>
                    <div className="flex items-center space-x-1">
                      <Bug className="w-4 h-4" />
                      <span>{rule.cwe_id || 'N/A'}</span>
                    </div>
                    <div className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${getEffortColor(rule.effort)}`}>
                      {rule.effort}
                    </div>
                  </div>
                  
                  {rule.tags.length > 0 && (
                    <div className="flex items-center space-x-2 mt-3">
                      {rule.tags.map((tag, index) => (
                        <span
                          key={index}
                          className="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-gray-100 text-gray-800"
                        >
                          {tag}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
                
                <div className="flex items-center space-x-2 ml-4">
                  <button
                    onClick={() => toggleRuleStatus(rule.id)}
                    className={`inline-flex items-center px-3 py-2 border text-sm font-medium rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 ${
                      rule.enabled
                        ? 'border-green-300 text-green-700 bg-green-50 hover:bg-green-100'
                        : 'border-gray-300 text-gray-700 bg-gray-50 hover:bg-gray-100'
                    }`}
                  >
                    {rule.enabled ? (
                      <>
                        <Unlock className="w-4 h-4 mr-2" />
                        Enabled
                      </>
                    ) : (
                      <>
                        <Lock className="w-4 h-4 mr-2" />
                        Disabled
                      </>
                    )}
                  </button>
                  
                  <button
                    onClick={() => setShowRuleDetails(showRuleDetails === rule.id ? null : rule.id)}
                    className="inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm leading-4 font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                  >
                    <Eye className="w-4 h-4 mr-2" />
                    Details
                  </button>
                </div>
              </div>
              
              {/* Rule Details */}
              {showRuleDetails === rule.id && (
                <div className="mt-4 p-4 bg-gray-50 rounded-lg">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                    <div>
                      <h5 className="font-medium text-gray-900 mb-2">Rule Information</h5>
                      <div className="space-y-1">
                        <div><span className="font-medium">Type:</span> {rule.type}</div>
                        <div><span className="font-medium">Subcategory:</span> {rule.subcategory}</div>
                        {rule.owasp_category && (
                          <div><span className="font-medium">OWASP Category:</span> {rule.owasp_category}</div>
                        )}
                        {rule.created_at && (
                          <div><span className="font-medium">Created:</span> {new Date(rule.created_at).toLocaleDateString()}</div>
                        )}
                      </div>
                    </div>
                    <div>
                      <h5 className="font-medium text-gray-900 mb-2">Impact & Effort</h5>
                      <div className="space-y-1">
                        <div><span className="font-medium">Severity:</span> {rule.severity}</div>
                        <div><span className="font-medium">Effort:</span> {rule.effort}</div>
                        <div><span className="font-medium">Languages:</span> {rule.languages.join(', ')}</div>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
        
        {filteredRules.length === 0 && (
          <div className="p-8 text-center">
            <Shield className="mx-auto h-12 w-12 text-gray-400" />
            <h3 className="mt-2 text-sm font-medium text-gray-900">No rules found</h3>
            <p className="mt-1 text-sm text-gray-500">
              Try adjusting your search or filter criteria.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

export default QualityRules;
