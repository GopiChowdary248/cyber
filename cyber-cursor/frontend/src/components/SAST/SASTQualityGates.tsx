import React, { useState, useEffect } from 'react';
import {
  Target,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Settings,
  Edit,
  Eye,
  Download,
  RefreshCw,
  Plus,
  Trash2,
  Save,
  X,
  BarChart3,
  TrendingUp,
  TrendingDown,
  Clock,
  Calendar,
  User,
  GitBranch,
  Code,
  Shield,
  Bug,
  Zap,
  Copy
} from 'lucide-react';

interface QualityGate {
  id: string;
  project_id: string;
  status: string;
  max_blocker_issues: number;
  max_critical_issues: number;
  max_major_issues: number;
  max_minor_issues: number;
  max_info_issues: number;
  min_coverage: number;
  min_branch_coverage: number;
  max_debt_ratio: number;
  max_technical_debt: number;
  max_duplicated_lines: number;
  max_duplicated_blocks: number;
  min_maintainability_rating: string;
  min_security_rating: string;
  min_reliability_rating: string;
  last_evaluation?: string;
  evaluation_results?: any;
  created_at?: string;
  updated_at?: string;
}

interface Project {
  id: string;
  name: string;
  key: string;
  language: string;
  quality_gate: string;
  maintainability_rating: string;
  security_rating: string;
  reliability_rating: string;
  vulnerability_count: number;
  coverage: number;
  technical_debt: number;
  debt_ratio: number;
}

interface EvaluationResult {
  condition: string;
  actual: number;
  threshold: number;
  passed: boolean;
  operator: string;
}

const API_BASE_URL = '/api/v1/sast';

const SASTQualityGates: React.FC = () => {
  const [qualityGates, setQualityGates] = useState<QualityGate[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [selectedGate, setSelectedGate] = useState<QualityGate | null>(null);
  const [showConfigModal, setShowConfigModal] = useState(false);
  const [showEvaluationModal, setShowEvaluationModal] = useState(false);
  
  // Configuration form
  const [configForm, setConfigForm] = useState({
    max_blocker_issues: 0,
    max_critical_issues: 5,
    max_major_issues: 20,
    max_minor_issues: 100,
    max_info_issues: 500,
    min_coverage: 80.0,
    min_branch_coverage: 80.0,
    max_debt_ratio: 5.0,
    max_technical_debt: 1440,
    max_duplicated_lines: 1000,
    max_duplicated_blocks: 100,
    min_maintainability_rating: 'C',
    min_security_rating: 'C',
    min_reliability_rating: 'C'
  });

  const fetchData = async () => {
    try {
      const token = localStorage.getItem('access_token') || '';
      const headers = {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      };

      const [gatesRes, projectsRes] = await Promise.all([
        fetch(`${API_BASE_URL}/quality-gates`, { headers }),
        fetch(`${API_BASE_URL}/projects`, { headers }),
      ]);

      if (gatesRes.ok) {
        const gatesData = await gatesRes.json();
        setQualityGates(gatesData.quality_gates || []);
      }

      if (projectsRes.ok) {
        const projectsData = await projectsRes.json();
        setProjects(projectsData.projects || []);
      }
    } catch (error) {
      console.error('Error fetching quality gates:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const onRefresh = () => {
    setRefreshing(true);
    fetchData().finally(() => setRefreshing(false));
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'passed':
        return 'text-green-600 bg-green-100';
      case 'failed':
        return 'text-red-600 bg-red-100';
      case 'warn':
        return 'text-yellow-600 bg-yellow-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status.toLowerCase()) {
      case 'passed':
        return <CheckCircle className="w-4 h-4" />;
      case 'failed':
        return <XCircle className="w-4 h-4" />;
      case 'warn':
        return <AlertTriangle className="w-4 h-4" />;
      default:
        return <Clock className="w-4 h-4" />;
    }
  };

  const getRatingColor = (rating: string) => {
    switch (rating) {
      case 'A':
        return 'text-green-600 bg-green-100';
      case 'B':
        return 'text-blue-600 bg-blue-100';
      case 'C':
        return 'text-yellow-600 bg-yellow-100';
      case 'D':
        return 'text-orange-600 bg-orange-100';
      case 'E':
        return 'text-red-600 bg-red-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const getProjectName = (projectId: string) => {
    const project = projects.find(p => p.id === projectId);
    return project ? project.name : `Project ${projectId}`;
  };

  const handleConfigureGate = (gate: QualityGate) => {
    setSelectedGate(gate);
    setConfigForm({
      max_blocker_issues: gate.max_blocker_issues,
      max_critical_issues: gate.max_critical_issues,
      max_major_issues: gate.max_major_issues,
      max_minor_issues: gate.max_minor_issues,
      max_info_issues: gate.max_info_issues,
      min_coverage: gate.min_coverage,
      min_branch_coverage: gate.min_branch_coverage,
      max_debt_ratio: gate.max_debt_ratio,
      max_technical_debt: gate.max_technical_debt,
      max_duplicated_lines: gate.max_duplicated_lines,
      max_duplicated_blocks: gate.max_duplicated_blocks,
      min_maintainability_rating: gate.min_maintainability_rating,
      min_security_rating: gate.min_security_rating,
      min_reliability_rating: gate.min_reliability_rating
    });
    setShowConfigModal(true);
  };

  const handleSaveConfiguration = async () => {
    if (!selectedGate) return;

    try {
      const token = localStorage.getItem('access_token') || '';
      const response = await fetch(`${API_BASE_URL}/quality-gates/${selectedGate.id}`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(configForm),
      });

      if (response.ok) {
        // Update the gate in the list
        setQualityGates(prev => prev.map(g => 
          g.id === selectedGate.id 
            ? { ...g, ...configForm, updated_at: new Date().toISOString() }
            : g
        ));
        setShowConfigModal(false);
        setSelectedGate(null);
      }
    } catch (error) {
      console.error('Error updating quality gate:', error);
    }
  };

  const handleEvaluateGate = async (gate: QualityGate) => {
    try {
      const token = localStorage.getItem('access_token') || '';
      const response = await fetch(`${API_BASE_URL}/quality-gates/${gate.id}/evaluate`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (response.ok) {
        const result = await response.json();
        // Update the gate with new evaluation results
        setQualityGates(prev => prev.map(g => 
          g.id === gate.id 
            ? { ...g, status: result.status, last_evaluation: new Date().toISOString(), evaluation_results: result.evaluation_results }
            : g
        ));
      }
    } catch (error) {
      console.error('Error evaluating quality gate:', error);
    }
  };

  const renderEvaluationResults = (results: any) => {
    if (!results) return null;

    const conditions = [
      { key: 'blocker_issues', label: 'Blocker Issues', icon: Bug },
      { key: 'critical_issues', label: 'Critical Issues', icon: AlertTriangle },
      { key: 'coverage', label: 'Code Coverage', icon: BarChart3 },
      { key: 'debt_ratio', label: 'Technical Debt', icon: Clock },
      { key: 'duplicated_lines', label: 'Duplicated Lines', icon: Copy },
      { key: 'maintainability_rating', label: 'Maintainability', icon: Code },
      { key: 'security_rating', label: 'Security Rating', icon: Shield },
      { key: 'reliability_rating', label: 'Reliability Rating', icon: CheckCircle }
    ];

    return (
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {conditions.map(({ key, label, icon: Icon }) => {
          const result = results[key];
          if (!result) return null;

          return (
            <div key={key} className="flex items-center space-x-3 p-3 bg-gray-50 rounded-lg">
              <div className={`p-2 rounded-full ${result.passed ? 'bg-green-100' : 'bg-red-100'}`}>
                <Icon className={`w-4 h-4 ${result.passed ? 'text-green-600' : 'text-red-600'}`} />
              </div>
              <div className="flex-1">
                <p className="text-sm font-medium text-gray-900">{label}</p>
                <p className="text-xs text-gray-500">
                  {result.actual} {result.operator} {result.threshold}
                </p>
              </div>
              <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                result.passed ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
              }`}>
                {result.passed ? 'PASS' : 'FAIL'}
              </span>
            </div>
          );
        })}
      </div>
    );
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Quality Gates</h1>
          <p className="text-gray-600">Configure and monitor quality gates for your projects</p>
        </div>
        <div className="flex space-x-3">
          <button
            onClick={onRefresh}
            disabled={refreshing}
            className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
          <button className="flex items-center space-x-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700">
            <Plus className="w-4 h-4" />
            <span>New Gate</span>
          </button>
        </div>
      </div>

      {/* Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white p-4 rounded-lg shadow-sm border">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-green-100 rounded-full">
              <CheckCircle className="w-5 h-5 text-green-600" />
            </div>
            <div>
              <p className="text-sm font-medium text-gray-600">Passed</p>
              <p className="text-xl font-bold text-green-600">
                {qualityGates.filter(g => g.status.toLowerCase() === 'passed').length}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white p-4 rounded-lg shadow-sm border">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-red-100 rounded-full">
              <XCircle className="w-5 h-5 text-red-600" />
            </div>
            <div>
              <p className="text-sm font-medium text-gray-600">Failed</p>
              <p className="text-xl font-bold text-red-600">
                {qualityGates.filter(g => g.status.toLowerCase() === 'failed').length}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white p-4 rounded-lg shadow-sm border">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-yellow-100 rounded-full">
              <AlertTriangle className="w-5 h-5 text-yellow-600" />
            </div>
            <div>
              <p className="text-sm font-medium text-gray-600">Warning</p>
              <p className="text-xl font-bold text-yellow-600">
                {qualityGates.filter(g => g.status.toLowerCase() === 'warn').length}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white p-4 rounded-lg shadow-sm border">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-blue-100 rounded-full">
              <Target className="w-5 h-5 text-blue-600" />
            </div>
            <div>
              <p className="text-sm font-medium text-gray-600">Total Gates</p>
              <p className="text-xl font-bold text-blue-600">{qualityGates.length}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Quality Gates List */}
      <div className="bg-white rounded-lg shadow-sm border">
        <div className="p-6 border-b border-gray-200">
          <h2 className="text-lg font-medium text-gray-900">
            Quality Gates ({qualityGates.length})
          </h2>
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
                  Critical Issues
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Coverage
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Technical Debt
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Ratings
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Last Evaluation
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {qualityGates.map((gate) => (
                <tr key={gate.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm font-medium text-gray-900">
                      {getProjectName(gate.project_id)}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(gate.status)}`}>
                      {getStatusIcon(gate.status)}
                      <span className="ml-1">{gate.status}</span>
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm text-gray-900">
                      ≤ {gate.max_critical_issues} issues
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm text-gray-900">
                      ≥ {gate.min_coverage}%
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm text-gray-900">
                      ≤ {gate.max_debt_ratio}%
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex space-x-1">
                      <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getRatingColor(gate.min_maintainability_rating)}`}>
                        M:{gate.min_maintainability_rating}
                      </span>
                      <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getRatingColor(gate.min_security_rating)}`}>
                        S:{gate.min_security_rating}
                      </span>
                      <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getRatingColor(gate.min_reliability_rating)}`}>
                        R:{gate.min_reliability_rating}
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {gate.last_evaluation ? new Date(gate.last_evaluation).toLocaleDateString() : 'Never'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    <div className="flex space-x-2">
                      <button
                        onClick={() => handleConfigureGate(gate)}
                        className="text-blue-600 hover:text-blue-900"
                        title="Configure"
                      >
                        <Settings className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => handleEvaluateGate(gate)}
                        className="text-green-600 hover:text-green-900"
                        title="Evaluate"
                      >
                        <Target className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => {
                          setSelectedGate(gate);
                          setShowEvaluationModal(true);
                        }}
                        className="text-purple-600 hover:text-purple-900"
                        title="View Results"
                      >
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

      {/* Configuration Modal */}
      {showConfigModal && selectedGate && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-10 mx-auto p-5 border w-full max-w-4xl shadow-lg rounded-md bg-white">
            <div className="flex justify-between items-center mb-6">
              <h3 className="text-lg font-medium text-gray-900">
                Configure Quality Gate - {getProjectName(selectedGate.project_id)}
              </h3>
              <button
                onClick={() => setShowConfigModal(false)}
                className="text-gray-400 hover:text-gray-600"
              >
                <X className="w-6 h-6" />
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {/* Issue Limits */}
              <div className="space-y-4">
                <h4 className="text-sm font-medium text-gray-900">Issue Limits</h4>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Blocker Issues
                  </label>
                  <input
                    type="number"
                    value={configForm.max_blocker_issues}
                    onChange={(e) => setConfigForm(prev => ({ ...prev, max_blocker_issues: parseInt(e.target.value) || 0 }))}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Critical Issues
                  </label>
                  <input
                    type="number"
                    value={configForm.max_critical_issues}
                    onChange={(e) => setConfigForm(prev => ({ ...prev, max_critical_issues: parseInt(e.target.value) || 0 }))}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Major Issues
                  </label>
                  <input
                    type="number"
                    value={configForm.max_major_issues}
                    onChange={(e) => setConfigForm(prev => ({ ...prev, max_major_issues: parseInt(e.target.value) || 0 }))}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>
              </div>

              {/* Coverage */}
              <div className="space-y-4">
                <h4 className="text-sm font-medium text-gray-900">Coverage</h4>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Minimum Coverage (%)
                  </label>
                  <input
                    type="number"
                    step="0.1"
                    value={configForm.min_coverage}
                    onChange={(e) => setConfigForm(prev => ({ ...prev, min_coverage: parseFloat(e.target.value) || 0 }))}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Minimum Branch Coverage (%)
                  </label>
                  <input
                    type="number"
                    step="0.1"
                    value={configForm.min_branch_coverage}
                    onChange={(e) => setConfigForm(prev => ({ ...prev, min_branch_coverage: parseFloat(e.target.value) || 0 }))}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>
              </div>

              {/* Technical Debt */}
              <div className="space-y-4">
                <h4 className="text-sm font-medium text-gray-900">Technical Debt</h4>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Max Debt Ratio (%)
                  </label>
                  <input
                    type="number"
                    step="0.1"
                    value={configForm.max_debt_ratio}
                    onChange={(e) => setConfigForm(prev => ({ ...prev, max_debt_ratio: parseFloat(e.target.value) || 0 }))}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Max Technical Debt (minutes)
                  </label>
                  <input
                    type="number"
                    value={configForm.max_technical_debt}
                    onChange={(e) => setConfigForm(prev => ({ ...prev, max_technical_debt: parseInt(e.target.value) || 0 }))}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>
              </div>

              {/* Ratings */}
              <div className="space-y-4">
                <h4 className="text-sm font-medium text-gray-900">Minimum Ratings</h4>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Maintainability
                  </label>
                  <select
                    value={configForm.min_maintainability_rating}
                    onChange={(e) => setConfigForm(prev => ({ ...prev, min_maintainability_rating: e.target.value }))}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  >
                    <option value="A">A</option>
                    <option value="B">B</option>
                    <option value="C">C</option>
                    <option value="D">D</option>
                    <option value="E">E</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Security
                  </label>
                  <select
                    value={configForm.min_security_rating}
                    onChange={(e) => setConfigForm(prev => ({ ...prev, min_security_rating: e.target.value }))}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  >
                    <option value="A">A</option>
                    <option value="B">B</option>
                    <option value="C">C</option>
                    <option value="D">D</option>
                    <option value="E">E</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Reliability
                  </label>
                  <select
                    value={configForm.min_reliability_rating}
                    onChange={(e) => setConfigForm(prev => ({ ...prev, min_reliability_rating: e.target.value }))}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  >
                    <option value="A">A</option>
                    <option value="B">B</option>
                    <option value="C">C</option>
                    <option value="D">D</option>
                    <option value="E">E</option>
                  </select>
                </div>
              </div>
            </div>

            <div className="flex justify-end space-x-3 mt-6 pt-6 border-t border-gray-200">
              <button
                onClick={() => setShowConfigModal(false)}
                className="px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={handleSaveConfiguration}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
              >
                Save Configuration
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Evaluation Results Modal */}
      {showEvaluationModal && selectedGate && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-10 mx-auto p-5 border w-full max-w-4xl shadow-lg rounded-md bg-white">
            <div className="flex justify-between items-center mb-6">
              <h3 className="text-lg font-medium text-gray-900">
                Quality Gate Results - {getProjectName(selectedGate.project_id)}
              </h3>
              <button
                onClick={() => setShowEvaluationModal(false)}
                className="text-gray-400 hover:text-gray-600"
              >
                <X className="w-6 h-6" />
              </button>
            </div>

            <div className="mb-6">
              <div className="flex items-center space-x-4">
                <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(selectedGate.status)}`}>
                  {getStatusIcon(selectedGate.status)}
                  <span className="ml-1">{selectedGate.status}</span>
                </span>
                <span className="text-sm text-gray-500">
                  Last evaluated: {selectedGate.last_evaluation ? new Date(selectedGate.last_evaluation).toLocaleString() : 'Never'}
                </span>
              </div>
            </div>

            {selectedGate.evaluation_results && (
              <div>
                <h4 className="text-sm font-medium text-gray-900 mb-4">Evaluation Results</h4>
                {renderEvaluationResults(selectedGate.evaluation_results)}
              </div>
            )}

            <div className="flex justify-end mt-6 pt-6 border-t border-gray-200">
              <button
                onClick={() => setShowEvaluationModal(false)}
                className="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SASTQualityGates; 