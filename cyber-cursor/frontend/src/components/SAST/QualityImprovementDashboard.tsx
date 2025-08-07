import React, { useState, useEffect } from 'react';
import { 
  Target, 
  TrendingUp, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  Calendar,
  BarChart3,
  Shield,
  Code,
  TestTube,
  Wrench,
  Flag,
  ArrowUp,
  ArrowDown,
  Minus,
  Star,
  Zap,
  Users,
  Settings,
  Download
} from 'lucide-react';

interface QualityGoal {
  id: string;
  title: string;
  description: string;
  category: 'immediate' | 'short-term' | 'long-term';
  priority: 'high' | 'medium' | 'low';
  status: 'not-started' | 'in-progress' | 'completed' | 'blocked';
  progress: number; // 0-100
  targetDate: string;
  currentValue: string;
  targetValue: string;
  metric: string;
  impact: 'security' | 'reliability' | 'maintainability' | 'coverage' | 'overall';
}

interface QualityMetrics {
  securityRating: string;
  reliabilityRating: string;
  maintainabilityRating: string;
  coverageRating: string;
  overallRating: string;
  criticalVulnerabilities: number;
  technicalDebtHours: number;
  testCoverage: number;
  codeSmells: number;
  bugs: number;
}

const QualityImprovementDashboard: React.FC = () => {
  const [goals, setGoals] = useState<QualityGoal[]>([]);
  const [metrics, setMetrics] = useState<QualityMetrics | null>(null);
  const [selectedGoal, setSelectedGoal] = useState<QualityGoal | null>(null);
  const [showGoalModal, setShowGoalModal] = useState(false);

  useEffect(() => {
    fetchQualityGoals();
    fetchQualityMetrics();
  }, []);

  const initializeQualityGoals = () => {
    const initialGoals: QualityGoal[] = [
      // Immediate Actions
      {
        id: '1',
        title: 'Address Critical Vulnerabilities',
        description: 'Fix all critical security vulnerabilities identified in SAST scans',
        category: 'immediate',
        priority: 'high',
        status: 'in-progress',
        progress: 65,
        targetDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
        currentValue: '5 critical',
        targetValue: '0 critical',
        metric: 'Critical Vulnerabilities',
        impact: 'security'
      },
      {
        id: '2',
        title: 'Increase Test Coverage',
        description: 'Improve test coverage for projects with low coverage ratings',
        category: 'immediate',
        priority: 'high',
        status: 'in-progress',
        progress: 40,
        targetDate: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString(),
        currentValue: '75%',
        targetValue: '85%',
        metric: 'Test Coverage',
        impact: 'coverage'
      },
      {
        id: '3',
        title: 'Reduce Technical Debt',
        description: 'Refactor code to reduce technical debt in high-debt projects',
        category: 'immediate',
        priority: 'medium',
        status: 'not-started',
        progress: 0,
        targetDate: new Date(Date.now() + 21 * 24 * 60 * 60 * 1000).toISOString(),
        currentValue: '45 hours',
        targetValue: '36 hours',
        metric: 'Technical Debt',
        impact: 'maintainability'
      },

      // Short-term Goals (1-2 weeks)
      {
        id: '4',
        title: 'Improve Security Rating to A',
        description: 'Achieve A rating for security by addressing all high-priority vulnerabilities',
        category: 'short-term',
        priority: 'high',
        status: 'in-progress',
        progress: 75,
        targetDate: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString(),
        currentValue: 'B',
        targetValue: 'A',
        metric: 'Security Rating',
        impact: 'security'
      },
      {
        id: '5',
        title: 'Increase Coverage Rating to A',
        description: 'Achieve A rating for test coverage by improving test suite',
        category: 'short-term',
        priority: 'medium',
        status: 'in-progress',
        progress: 60,
        targetDate: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString(),
        currentValue: 'B',
        targetValue: 'A',
        metric: 'Coverage Rating',
        impact: 'coverage'
      },
      {
        id: '6',
        title: 'Reduce Technical Debt by 20%',
        description: 'Reduce technical debt from 45 hours to 36 hours',
        category: 'short-term',
        priority: 'medium',
        status: 'not-started',
        progress: 0,
        targetDate: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString(),
        currentValue: '45 hours',
        targetValue: '36 hours',
        metric: 'Technical Debt',
        impact: 'maintainability'
      },

      // Long-term Goals (1-2 months)
      {
        id: '7',
        title: 'Achieve A Ratings Across All Metrics',
        description: 'Maintain A ratings for security, reliability, maintainability, and coverage',
        category: 'long-term',
        priority: 'high',
        status: 'not-started',
        progress: 0,
        targetDate: new Date(Date.now() + 60 * 24 * 60 * 60 * 1000).toISOString(),
        currentValue: 'B (avg)',
        targetValue: 'A (all)',
        metric: 'Overall Quality',
        impact: 'overall'
      },
      {
        id: '8',
        title: 'Implement Automated Quality Gates',
        description: 'Set up automated quality gates in CI/CD pipeline',
        category: 'long-term',
        priority: 'medium',
        status: 'not-started',
        progress: 0,
        targetDate: new Date(Date.now() + 45 * 24 * 60 * 60 * 1000).toISOString(),
        currentValue: 'Manual',
        targetValue: 'Automated',
        metric: 'Quality Gates',
        impact: 'overall'
      },
      {
        id: '9',
        title: 'Establish Quality Monitoring Dashboards',
        description: 'Create comprehensive quality monitoring and reporting system',
        category: 'long-term',
        priority: 'medium',
        status: 'not-started',
        progress: 0,
        targetDate: new Date(Date.now() + 60 * 24 * 60 * 60 * 1000).toISOString(),
        currentValue: 'Basic',
        targetValue: 'Comprehensive',
        metric: 'Monitoring',
        impact: 'overall'
      }
    ];
    setGoals(initialGoals);
  };

  const fetchQualityMetrics = async () => {
    try {
      const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000/api/v1';
      const response = await fetch(`${API_URL}/api/v1/sast/dashboard`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token') || ''}`,
          'Content-Type': 'application/json',
        },
      });

      if (response.ok) {
        const data = await response.json();
        setMetrics({
          securityRating: data.security_rating || 'B',
          reliabilityRating: data.reliability_rating || 'A',
          maintainabilityRating: data.maintainability_rating || 'B',
          coverageRating: data.coverage_percentage >= 80 ? 'A' : data.coverage_percentage >= 60 ? 'B' : 'C',
          overallRating: 'B',
          criticalVulnerabilities: data.critical_issues || 5,
          technicalDebtHours: data.technical_debt_hours || 45,
          testCoverage: data.coverage_percentage || 75,
          codeSmells: data.code_smells || 28,
          bugs: data.bugs || 3
        });
      }
    } catch (error) {
      console.error('Error fetching quality metrics:', error);
    }
  };

  const fetchQualityGoals = async () => {
    try {
      const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000/api/v1';
      const response = await fetch(`${API_URL}/quality-goals/goals`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token') || ''}`,
          'Content-Type': 'application/json',
        },
      });

      if (response.ok) {
        const data = await response.json();
        setGoals(data.goals || []);
      }
    } catch (error) {
      console.error('Error fetching quality goals:', error);
      // Fallback to mock data if API fails
      initializeQualityGoals();
    }
  };

  const getCategoryColor = (category: string) => {
    switch (category) {
      case 'immediate': return 'text-red-600 bg-red-100 border-red-200';
      case 'short-term': return 'text-orange-600 bg-orange-100 border-orange-200';
      case 'long-term': return 'text-blue-600 bg-blue-100 border-blue-200';
      default: return 'text-gray-600 bg-gray-100 border-gray-200';
    }
  };

  const getPriorityIcon = (priority: string) => {
    switch (priority) {
      case 'high': return <AlertTriangle className="w-4 h-4 text-red-600" />;
      case 'medium': return <Clock className="w-4 h-4 text-orange-600" />;
      case 'low': return <Minus className="w-4 h-4 text-gray-600" />;
      default: return <Minus className="w-4 h-4 text-gray-600" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'text-green-600 bg-green-100';
      case 'in-progress': return 'text-blue-600 bg-blue-100';
      case 'blocked': return 'text-red-600 bg-red-100';
      case 'not-started': return 'text-gray-600 bg-gray-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getImpactIcon = (impact: string) => {
    switch (impact) {
      case 'security': return <Shield className="w-4 h-4 text-blue-600" />;
      case 'reliability': return <CheckCircle className="w-4 h-4 text-green-600" />;
      case 'maintainability': return <Code className="w-4 h-4 text-purple-600" />;
      case 'coverage': return <TestTube className="w-4 h-4 text-orange-600" />;
      case 'overall': return <Star className="w-4 h-4 text-yellow-600" />;
      default: return <Target className="w-4 h-4 text-gray-600" />;
    }
  };

  const updateGoalProgress = async (goalId: string, progress: number) => {
    try {
      const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000/api/v1';
      const response = await fetch(`${API_URL}/quality-goals/goals/${goalId}/progress?progress=${progress}`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token') || ''}`,
          'Content-Type': 'application/json',
        },
      });

      if (response.ok) {
        const updatedGoal = await response.json();
        setGoals(prev => prev.map(goal => 
          goal.id === goalId ? updatedGoal : goal
        ));
      }
    } catch (error) {
      console.error('Error updating goal progress:', error);
      // Fallback to local update if API fails
      setGoals(prev => prev.map(goal => 
        goal.id === goalId 
          ? { ...goal, progress: Math.min(100, Math.max(0, progress)) }
          : goal
      ));
    }
  };

  const getGoalsByCategory = (category: string) => {
    return goals.filter(goal => goal.category === category);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white rounded-lg shadow-lg p-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Quality Improvement Dashboard</h1>
            <p className="text-gray-600">Track and manage quality improvement goals</p>
          </div>
          
          <div className="flex items-center space-x-3">
            <button
              onClick={fetchQualityMetrics}
              className="flex items-center space-x-2 px-3 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-md hover:bg-gray-200"
            >
              <Zap className="w-4 h-4" />
              <span>Refresh</span>
            </button>
            
            <button className="flex items-center space-x-2 px-3 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-md hover:bg-gray-200">
              <Download className="w-4 h-4" />
              <span>Export Report</span>
            </button>
          </div>
        </div>
      </div>

      {/* Current Quality Metrics */}
      {metrics && (
        <div className="bg-white rounded-lg shadow-lg p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Current Quality Metrics</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
            <div className="text-center p-4 bg-blue-50 rounded-lg">
              <Shield className="w-8 h-8 text-blue-600 mx-auto mb-2" />
              <p className="text-sm font-medium text-gray-600">Security</p>
              <p className="text-xl font-bold text-blue-600">{metrics.securityRating}</p>
            </div>
            <div className="text-center p-4 bg-green-50 rounded-lg">
              <CheckCircle className="w-8 h-8 text-green-600 mx-auto mb-2" />
              <p className="text-sm font-medium text-gray-600">Reliability</p>
              <p className="text-xl font-bold text-green-600">{metrics.reliabilityRating}</p>
            </div>
            <div className="text-center p-4 bg-purple-50 rounded-lg">
              <Code className="w-8 h-8 text-purple-600 mx-auto mb-2" />
              <p className="text-sm font-medium text-gray-600">Maintainability</p>
              <p className="text-xl font-bold text-purple-600">{metrics.maintainabilityRating}</p>
            </div>
            <div className="text-center p-4 bg-orange-50 rounded-lg">
              <TestTube className="w-8 h-8 text-orange-600 mx-auto mb-2" />
              <p className="text-sm font-medium text-gray-600">Coverage</p>
              <p className="text-xl font-bold text-orange-600">{metrics.coverageRating}</p>
            </div>
            <div className="text-center p-4 bg-yellow-50 rounded-lg">
              <Star className="w-8 h-8 text-yellow-600 mx-auto mb-2" />
              <p className="text-sm font-medium text-gray-600">Overall</p>
              <p className="text-xl font-bold text-yellow-600">{metrics.overallRating}</p>
            </div>
          </div>
        </div>
      )}

      {/* Quality Goals by Category */}
      <div className="space-y-6">
        {/* Immediate Actions */}
        <div className="bg-white rounded-lg shadow-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-gray-900">Immediate Actions (This Week)</h2>
            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium text-red-600 bg-red-100 border border-red-200">
              High Priority
            </span>
          </div>
          
          <div className="space-y-4">
            {getGoalsByCategory('immediate').map((goal) => (
              <div key={goal.id} className="border border-gray-200 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-3">
                    {getPriorityIcon(goal.priority)}
                    <h3 className="font-medium text-gray-900">{goal.title}</h3>
                    {getImpactIcon(goal.impact)}
                  </div>
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(goal.status)}`}>
                    {goal.status.replace('-', ' ')}
                  </span>
                </div>
                
                <p className="text-sm text-gray-600 mb-3">{goal.description}</p>
                
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center space-x-4">
                    <span className="text-sm text-gray-600">Current: {goal.currentValue}</span>
                    <ArrowUp className="w-4 h-4 text-gray-400" />
                    <span className="text-sm text-gray-600">Target: {goal.targetValue}</span>
                  </div>
                  <span className="text-sm text-gray-500">
                    Due: {new Date(goal.targetDate).toLocaleDateString()}
                  </span>
                </div>
                
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div 
                    className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                    style={{ width: `${goal.progress}%` }}
                  ></div>
                </div>
                
                <div className="flex items-center justify-between mt-2">
                  <span className="text-sm text-gray-600">{goal.progress}% Complete</span>
                  <div className="flex space-x-2">
                    <button
                      onClick={() => updateGoalProgress(goal.id, goal.progress - 10)}
                      className="px-2 py-1 text-xs bg-gray-100 text-gray-600 rounded hover:bg-gray-200"
                    >
                      -10%
                    </button>
                    <button
                      onClick={() => updateGoalProgress(goal.id, goal.progress + 10)}
                      className="px-2 py-1 text-xs bg-blue-100 text-blue-600 rounded hover:bg-blue-200"
                    >
                      +10%
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Short-term Goals */}
        <div className="bg-white rounded-lg shadow-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-gray-900">Short-term Goals (1-2 Weeks)</h2>
            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium text-orange-600 bg-orange-100 border border-orange-200">
              Medium Priority
            </span>
          </div>
          
          <div className="space-y-4">
            {getGoalsByCategory('short-term').map((goal) => (
              <div key={goal.id} className="border border-gray-200 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-3">
                    {getPriorityIcon(goal.priority)}
                    <h3 className="font-medium text-gray-900">{goal.title}</h3>
                    {getImpactIcon(goal.impact)}
                  </div>
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(goal.status)}`}>
                    {goal.status.replace('-', ' ')}
                  </span>
                </div>
                
                <p className="text-sm text-gray-600 mb-3">{goal.description}</p>
                
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center space-x-4">
                    <span className="text-sm text-gray-600">Current: {goal.currentValue}</span>
                    <ArrowUp className="w-4 h-4 text-gray-400" />
                    <span className="text-sm text-gray-600">Target: {goal.targetValue}</span>
                  </div>
                  <span className="text-sm text-gray-500">
                    Due: {new Date(goal.targetDate).toLocaleDateString()}
                  </span>
                </div>
                
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div 
                    className="bg-orange-600 h-2 rounded-full transition-all duration-300"
                    style={{ width: `${goal.progress}%` }}
                  ></div>
                </div>
                
                <div className="flex items-center justify-between mt-2">
                  <span className="text-sm text-gray-600">{goal.progress}% Complete</span>
                  <div className="flex space-x-2">
                    <button
                      onClick={() => updateGoalProgress(goal.id, goal.progress - 10)}
                      className="px-2 py-1 text-xs bg-gray-100 text-gray-600 rounded hover:bg-gray-200"
                    >
                      -10%
                    </button>
                    <button
                      onClick={() => updateGoalProgress(goal.id, goal.progress + 10)}
                      className="px-2 py-1 text-xs bg-orange-100 text-orange-600 rounded hover:bg-orange-200"
                    >
                      +10%
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Long-term Goals */}
        <div className="bg-white rounded-lg shadow-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-gray-900">Long-term Goals (1-2 Months)</h2>
            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium text-blue-600 bg-blue-100 border border-blue-200">
              Strategic
            </span>
          </div>
          
          <div className="space-y-4">
            {getGoalsByCategory('long-term').map((goal) => (
              <div key={goal.id} className="border border-gray-200 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-3">
                    {getPriorityIcon(goal.priority)}
                    <h3 className="font-medium text-gray-900">{goal.title}</h3>
                    {getImpactIcon(goal.impact)}
                  </div>
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(goal.status)}`}>
                    {goal.status.replace('-', ' ')}
                  </span>
                </div>
                
                <p className="text-sm text-gray-600 mb-3">{goal.description}</p>
                
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center space-x-4">
                    <span className="text-sm text-gray-600">Current: {goal.currentValue}</span>
                    <ArrowUp className="w-4 h-4 text-gray-400" />
                    <span className="text-sm text-gray-600">Target: {goal.targetValue}</span>
                  </div>
                  <span className="text-sm text-gray-500">
                    Due: {new Date(goal.targetDate).toLocaleDateString()}
                  </span>
                </div>
                
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div 
                    className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                    style={{ width: `${goal.progress}%` }}
                  ></div>
                </div>
                
                <div className="flex items-center justify-between mt-2">
                  <span className="text-sm text-gray-600">{goal.progress}% Complete</span>
                  <div className="flex space-x-2">
                    <button
                      onClick={() => updateGoalProgress(goal.id, goal.progress - 10)}
                      className="px-2 py-1 text-xs bg-gray-100 text-gray-600 rounded hover:bg-gray-200"
                    >
                      -10%
                    </button>
                    <button
                      onClick={() => updateGoalProgress(goal.id, goal.progress + 10)}
                      className="px-2 py-1 text-xs bg-blue-100 text-blue-600 rounded hover:bg-blue-200"
                    >
                      +10%
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default QualityImprovementDashboard; 