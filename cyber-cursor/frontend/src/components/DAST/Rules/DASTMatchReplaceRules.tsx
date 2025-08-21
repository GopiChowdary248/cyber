import React, { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Plus, 
  Edit, 
  Trash2, 
  Save, 
  X, 
  Filter,
  Settings,
  Code,
  Globe,
  FileText,
  Shield,
  Play,
  Eye,
  EyeOff,
  TestTube,
  AlertTriangle,
  CheckCircle
} from 'lucide-react';
import { 
  getMatchReplaceRules, 
  createMatchReplaceRule, 
  updateMatchReplaceRule, 
  deleteMatchReplaceRule 
} from '../../../services/dastProjectToolsService';

interface MatchReplaceRule {
  id: string;
  name: string;
  description?: string;
  match_pattern: string;
  replace_pattern: string;
  match_type: 'regex' | 'string' | 'wildcard';
  apply_to: 'request' | 'response' | 'both';
  enabled: boolean;
  priority: number;
  created_at: string;
}

interface DASTMatchReplaceRulesProps {
  projectId: string;
}

const DASTMatchReplaceRules: React.FC<DASTMatchReplaceRulesProps> = ({ projectId }) => {
  const [rules, setRules] = useState<MatchReplaceRule[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [editingRule, setEditingRule] = useState<MatchReplaceRule | null>(null);
  const [isCreating, setIsCreating] = useState(false);
  const [filter, setFilter] = useState({
    enabled: 'all',
    matchType: 'all',
    replaceType: 'all'
  });
  const [searchText, setSearchText] = useState('');
  const [showAdvancedOptions, setShowAdvancedOptions] = useState(false);
  const [testMode, setTestMode] = useState(false);
  const [testData, setTestData] = useState({
    url: 'https://example.com/test',
    headers: 'Content-Type: application/json\nAuthorization: Bearer token',
    body: '{"test": "data"}',
    response: '{"result": "success"}'
  });
  const [testResults, setTestResults] = useState<any[]>([]);

  const loadRules = useCallback(async () => {
    try {
      const data = await getMatchReplaceRules(projectId);
      setRules(data);
    } catch (error) {
      console.error('Failed to load rules:', error);
    } finally {
      setIsLoading(false);
    }
  }, [projectId]);

  useEffect(() => {
    loadRules();
  }, [loadRules]);

  const handleCreateRule = useCallback(async (ruleData: Omit<MatchReplaceRule, 'id' | 'created_at'>) => {
    try {
      await createMatchReplaceRule(projectId, ruleData);
      await loadRules();
      setIsCreating(false);
    } catch (error) {
      console.error('Failed to create rule:', error);
    }
  }, [projectId, loadRules]);

  const handleUpdateRule = useCallback(async (ruleId: string, updates: Partial<MatchReplaceRule>) => {
    try {
      await updateMatchReplaceRule(projectId, ruleId, updates);
      await loadRules();
      setEditingRule(null);
    } catch (error) {
      console.error('Failed to update rule:', error);
    }
  }, [projectId, loadRules]);

  const handleDeleteRule = useCallback(async (ruleId: string) => {
    if (!confirm('Are you sure you want to delete this rule?')) return;
    
    try {
      await deleteMatchReplaceRule(projectId, ruleId);
      await loadRules();
    } catch (error) {
      console.error('Failed to delete rule:', error);
    }
  }, [projectId, loadRules]);

  const handleToggleRule = useCallback(async (ruleId: string, enabled: boolean) => {
    try {
      await handleUpdateRule(ruleId, { enabled });
    } catch (error) {
      console.error('Failed to toggle rule:', error);
    }
  }, [handleUpdateRule]);

  const handleReorderRules = useCallback(async (ruleId: string, newOrder: number) => {
    try {
      await handleUpdateRule(ruleId, { priority: newOrder });
    } catch (error) {
      console.error('Failed to reorder rule:', error);
    }
  }, [handleUpdateRule]);

  const testRule = useCallback((rule: MatchReplaceRule) => {
    const results = [];
    
    // Test based on apply_to field
    if (rule.apply_to === 'request' || rule.apply_to === 'both') {
      // Test URL matching
      if (rule.match_type === 'regex') {
        try {
          const regex = new RegExp(rule.match_pattern);
          const matches = regex.test(testData.url);
          results.push({
            type: 'URL',
            input: testData.url,
            pattern: rule.match_pattern,
            matches,
            result: matches ? testData.url.replace(regex, rule.replace_pattern) : 'No match'
          });
        } catch (error) {
          results.push({
            type: 'URL',
            input: testData.url,
            pattern: rule.match_pattern,
            matches: false,
            result: 'Invalid regex pattern'
          });
        }
      }
      
      // Test header matching
      const headers = testData.headers.split('\n');
      if (rule.match_type === 'regex') {
        try {
          const regex = new RegExp(rule.match_pattern);
          headers.forEach(header => {
            const matches = regex.test(header);
            if (matches) {
              results.push({
                type: 'Header',
                input: header,
                pattern: rule.match_pattern,
                matches: true,
                result: header.replace(regex, rule.replace_pattern)
              });
            }
          });
        } catch (error) {
          results.push({
            type: 'Header',
            input: 'Headers',
            pattern: rule.match_pattern,
            matches: false,
            result: 'Invalid regex pattern'
          });
        }
      }
      
      // Test body matching
      if (rule.match_type === 'regex') {
        try {
          const regex = new RegExp(rule.match_pattern);
          const matches = regex.test(testData.body);
          results.push({
            type: 'Body',
            input: testData.body,
            pattern: rule.match_pattern,
            matches,
            result: matches ? testData.body.replace(regex, rule.replace_pattern) : 'No match'
          });
        } catch (error) {
          results.push({
            type: 'Body',
            input: testData.body,
            pattern: rule.match_pattern,
            matches: false,
            result: 'Invalid regex pattern'
          });
        }
      }
    }
    
    // Test response matching
    if (rule.apply_to === 'response' || rule.apply_to === 'both') {
      if (rule.match_type === 'regex') {
        try {
          const regex = new RegExp(rule.match_pattern);
          const matches = regex.test(testData.response);
          results.push({
            type: 'Response',
            input: testData.response,
            pattern: rule.match_pattern,
            matches,
            result: matches ? testData.response.replace(regex, rule.replace_pattern) : 'No match'
          });
        } catch (error) {
          results.push({
            type: 'Response',
            input: testData.response,
            pattern: rule.match_pattern,
            matches: false,
            result: 'Invalid regex pattern'
          });
        }
      }
    }
    
    setTestResults(results);
  }, [testData]);

  const filteredRules = rules.filter(rule => {
    const matchesSearch = rule.name.toLowerCase().includes(searchText.toLowerCase()) ||
                         (rule.description && rule.description.toLowerCase().includes(searchText.toLowerCase()));
    const matchesEnabled = filter.enabled === 'all' || 
                          (filter.enabled === 'enabled' && rule.enabled) ||
                          (filter.enabled === 'disabled' && !rule.enabled);
    const matchesMatchType = filter.matchType === 'all' || rule.match_type === filter.matchType;
    const matchesReplaceType = filter.replaceType === 'all' || rule.replace_type === filter.replaceType;
    
    return matchesSearch && matchesEnabled && matchesMatchType && matchesReplaceType;
  });

  const getMatchTypeIcon = (type: string) => {
    switch (type) {
      case 'url': return <Globe className="w-4 h-4" />;
      case 'header': return <FileText className="w-4 h-4" />;
      case 'body': return <Code className="w-4 h-4" />;
      case 'response': return <Shield className="w-4 h-4" />;
      default: return <Code className="w-4 h-4" />;
    }
  };

  const getReplaceTypeIcon = (type: string) => {
    switch (type) {
      case 'url': return <Globe className="w-4 h-4" />;
      case 'header': return <FileText className="w-4 h-4" />;
      case 'body': return <Code className="w-4 h-4" />;
      default: return <Code className="w-4 h-4" />;
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Match & Replace Rules</h2>
          <p className="text-gray-600">Configure rules to modify requests and responses in real-time</p>
        </div>
        <button
          onClick={() => setIsCreating(true)}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
        >
          <Plus className="w-4 h-4" />
          New Rule
        </button>
      </div>

      {/* Filters and Search */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Search</label>
            <input
              type="text"
              placeholder="Search rules..."
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Status</label>
            <select
              value={filter.enabled}
              onChange={(e) => setFilter(prev => ({ ...prev, enabled: e.target.value as any }))}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="all">All</option>
              <option value="enabled">Enabled</option>
              <option value="disabled">Disabled</option>
            </select>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Match Type</label>
            <select
              value={filter.matchType}
              onChange={(e) => setFilter(prev => ({ ...prev, matchType: e.target.value as any }))}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="all">All</option>
              <option value="url">URL</option>
              <option value="header">Header</option>
              <option value="body">Body</option>
              <option value="response">Response</option>
            </select>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Replace Type</label>
            <select
              value={filter.replaceType}
              onChange={(e) => setFilter(prev => ({ ...prev, replaceType: e.target.value as any }))}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="all">All</option>
              <option value="url">URL</option>
              <option value="header">Header</option>
              <option value="body">Body</option>
            </select>
          </div>
        </div>
      </div>

      {/* Test Mode Toggle */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">Test Mode</h3>
            <p className="text-sm text-gray-600">Test your rules against sample data</p>
          </div>
          <button
            onClick={() => setTestMode(!testMode)}
            className={`flex items-center gap-2 px-4 py-2 rounded-md ${
              testMode 
                ? 'bg-green-600 text-white hover:bg-green-700' 
                : 'bg-gray-600 text-white hover:bg-gray-700'
            }`}
          >
            {testMode ? <CheckCircle className="w-4 h-4" /> : <TestTube className="w-4 h-4" />}
            {testMode ? 'Test Mode Active' : 'Enable Test Mode'}
          </button>
        </div>
      </div>

      {/* Test Data Input */}
      {testMode && (
        <motion.div 
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: 'auto' }}
          className="bg-white rounded-lg shadow-sm border border-gray-200 p-4"
        >
          <h4 className="text-md font-semibold text-gray-900 mb-3">Test Data</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">URL</label>
              <input
                type="text"
                value={testData.url}
                onChange={(e) => setTestData(prev => ({ ...prev, url: e.target.value }))}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Headers</label>
              <textarea
                value={testData.headers}
                onChange={(e) => setTestData(prev => ({ ...prev, headers: e.target.value }))}
                rows={2}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Request Body</label>
              <textarea
                value={testData.body}
                onChange={(e) => setTestData(prev => ({ ...prev, body: e.target.value }))}
                rows={2}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Response</label>
              <textarea
                value={testData.response}
                onChange={(e) => setTestData(prev => ({ ...prev, response: e.target.value }))}
                rows={2}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
          </div>
        </motion.div>
      )}

      {/* Rules List */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200">
        <div className="p-4 border-b border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900">
            Rules ({filteredRules.length})
          </h3>
        </div>
        
        <div className="divide-y divide-gray-200">
          {filteredRules.map((rule) => (
            <div key={rule.id} className="p-4 hover:bg-gray-50">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <div className="flex items-center gap-2">
                      {getMatchTypeIcon(rule.match_type)}
                      <span className="text-sm text-gray-500">→</span>
                      {getReplaceTypeIcon(rule.replace_type)}
                    </div>
                    <h4 className="font-medium text-gray-900">{rule.name}</h4>
                    <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                      rule.enabled ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'
                    }`}>
                      {rule.enabled ? 'Active' : 'Inactive'}
                    </span>
                    <span className="text-xs text-gray-500">Order: {rule.order_index}</span>
                  </div>
                  
                  {rule.description && (
                    <p className="text-sm text-gray-600 mb-2">{rule.description}</p>
                  )}
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="font-medium text-gray-700">Match Pattern:</span>
                      <code className="ml-2 px-2 py-1 bg-gray-100 text-gray-800 rounded text-xs">
                        {rule.match_pattern}
                      </code>
                      {rule.match_case_sensitive && (
                        <span className="ml-2 text-xs text-gray-500">(case-sensitive)</span>
                      )}
                    </div>
                    <div>
                      <span className="font-medium text-gray-700">Replace Value:</span>
                      <code className="ml-2 px-2 py-1 bg-gray-100 text-gray-800 rounded text-xs">
                        {rule.replace_value || rule.replace_pattern}
                      </code>
                    </div>
                  </div>
                </div>
                
                <div className="flex items-center gap-2 ml-4">
                  {testMode && (
                    <button
                      onClick={() => testRule(rule)}
                      className="p-2 text-blue-600 hover:bg-blue-50 rounded-md"
                      title="Test Rule"
                    >
                      <Play className="w-4 h-4" />
                    </button>
                  )}
                  
                  <button
                    onClick={() => setEditingRule(rule)}
                    className="p-2 text-gray-600 hover:bg-gray-50 rounded-md"
                    title="Edit Rule"
                  >
                    <Edit className="w-4 h-4" />
                  </button>
                  
                  <button
                    onClick={() => handleToggleRule(rule.id, !rule.enabled)}
                    className={`p-2 rounded-md ${
                      rule.enabled 
                        ? 'text-yellow-600 hover:bg-yellow-50' 
                        : 'text-green-600 hover:bg-green-50'
                    }`}
                    title={rule.enabled ? 'Disable Rule' : 'Enable Rule'}
                  >
                    {rule.enabled ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                  
                  <button
                    onClick={() => handleDeleteRule(rule.id)}
                    className="p-2 text-red-600 hover:bg-red-50 rounded-md"
                    title="Delete Rule"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
        
        {filteredRules.length === 0 && (
          <div className="p-8 text-center text-gray-500">
            <Code className="w-12 h-12 mx-auto mb-4 text-gray-300" />
            <p>No rules found matching your criteria</p>
            <p className="text-sm">Create your first rule to get started</p>
          </div>
        )}
      </div>

      {/* Test Results */}
      {testMode && testResults.length > 0 && (
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-white rounded-lg shadow-sm border border-gray-200 p-4"
        >
          <h4 className="text-md font-semibold text-gray-900 mb-3">Test Results</h4>
          <div className="space-y-3">
            {testResults.map((result, index) => (
              <div key={index} className="border border-gray-200 rounded-lg p-3">
                <div className="flex items-center gap-2 mb-2">
                  <span className={`px-2 py-1 rounded text-xs font-medium ${
                    result.matches ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'
                  }`}>
                    {result.type}
                  </span>
                  {result.matches ? (
                    <CheckCircle className="w-4 h-4 text-green-600" />
                  ) : (
                    <AlertTriangle className="w-4 h-4 text-gray-400" />
                  )}
                </div>
                <div className="text-sm space-y-1">
                  <div><span className="font-medium">Input:</span> <code className="bg-gray-100 px-1 rounded">{result.input}</code></div>
                  <div><span className="font-medium">Pattern:</span> <code className="bg-gray-100 px-1 rounded">{result.pattern}</code></div>
                  {result.matches && (
                    <div><span className="font-medium">Result:</span> <code className="bg-green-100 px-1 rounded">{result.result}</code></div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </motion.div>
      )}

      {/* Create/Edit Rule Modal */}
      <AnimatePresence>
        {(isCreating || editingRule) && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50"
          >
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="bg-white rounded-lg shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto"
            >
              <div className="p-6">
                <h3 className="text-lg font-semibold text-gray-900 mb-4">
                  {isCreating ? 'Create New Rule' : 'Edit Rule'}
                </h3>
                
                <form onSubmit={(e) => {
                  e.preventDefault();
                  const formData = new FormData(e.currentTarget);
                  const ruleData = {
                    name: formData.get('name') as string,
                    description: formData.get('description') as string,
                    enabled: formData.get('enabled') === 'true',
                    order_index: parseInt(formData.get('order_index') as string),
                    match_type: formData.get('match_type') as any,
                    match_pattern: formData.get('match_pattern') as string,
                    match_case_sensitive: formData.get('match_case_sensitive') === 'true',
                    replace_type: formData.get('replace_type') as any,
                    replace_pattern: formData.get('replace_pattern') as string,
                    replace_value: formData.get('replace_value') as string
                  };
                  
                  if (isCreating) {
                    handleCreateRule(ruleData);
                  } else if (editingRule) {
                    handleUpdateRule(editingRule.id, ruleData);
                  }
                }}>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Rule Name</label>
                      <input
                        name="name"
                        type="text"
                        defaultValue={editingRule?.name || ''}
                        required
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      />
                    </div>
                    
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Order Index</label>
                      <input
                        name="order_index"
                        type="number"
                        defaultValue={editingRule?.order_index || 0}
                        min="0"
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      />
                    </div>
                  </div>
                  
                  <div className="mb-4">
                    <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
                    <textarea
                      name="description"
                      rows={2}
                      defaultValue={editingRule?.description || ''}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                  </div>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Match Type</label>
                      <select
                        name="match_type"
                        defaultValue={editingRule?.match_type || 'url'}
                        required
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      >
                        <option value="url">URL</option>
                        <option value="header">Header</option>
                        <option value="body">Body</option>
                        <option value="response">Response</option>
                      </select>
                    </div>
                    
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Replace Type</label>
                      <select
                        name="replace_type"
                        defaultValue={editingRule?.replace_type || 'url'}
                        required
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      >
                        <option value="url">URL</option>
                        <option value="header">Header</option>
                        <option value="body">Body</option>
                      </select>
                    </div>
                  </div>
                  
                  <div className="mb-4">
                    <label className="block text-sm font-medium text-gray-700 mb-1">Match Pattern (Regex)</label>
                    <input
                      name="match_pattern"
                      type="text"
                      defaultValue={editingRule?.match_pattern || ''}
                      required
                      placeholder=".*\.example\.com"
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                  </div>
                  
                  <div className="mb-4">
                    <label className="block text-sm font-medium text-gray-700 mb-1">Replace Value</label>
                    <input
                      name="replace_value"
                      type="text"
                      defaultValue={editingRule?.replace_value || ''}
                      placeholder="https://new.example.com"
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                  </div>
                  
                  <div className="mb-6 space-y-3">
                    <label className="flex items-center">
                      <input
                        name="enabled"
                        type="checkbox"
                        defaultChecked={editingRule?.enabled ?? true}
                        value="true"
                        className="rounded border-gray-300 text-blue-600 focus:ring-blue-500 mr-2"
                      />
                      <span className="text-sm text-gray-700">Enable rule</span>
                    </label>
                    
                    <label className="flex items-center">
                      <input
                        name="match_case_sensitive"
                        type="checkbox"
                        defaultChecked={editingRule?.match_case_sensitive ?? false}
                        value="true"
                        className="rounded border-gray-300 text-blue-600 focus:ring-blue-500 mr-2"
                      />
                      <span className="text-sm text-gray-700">Case sensitive matching</span>
                    </label>
                  </div>
                  
                  <div className="flex justify-end gap-3">
                    <button
                      type="button"
                      onClick={() => {
                        setIsCreating(false);
                        setEditingRule(null);
                      }}
                      className="px-4 py-2 text-gray-700 bg-gray-100 rounded-md hover:bg-gray-200"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
                    >
                      {isCreating ? 'Create Rule' : 'Update Rule'}
                    </button>
                  </div>
                </form>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default DASTMatchReplaceRules;
