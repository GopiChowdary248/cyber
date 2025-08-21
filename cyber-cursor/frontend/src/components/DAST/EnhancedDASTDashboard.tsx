import React, { useState, useEffect } from 'react';
import {
  Brain,
  Shield,
  AlertTriangle,
  CheckCircle,
  TrendingUp,
  BarChart3,
  Zap,
  Target,
  Activity,
  RefreshCw,
  Download,
  Settings,
  Eye,
  BrainCircuit,
  Network,
  Database
} from 'lucide-react';

interface AIAnalysisResult {
  analysis_id: string;
  vulnerability_id: string;
  analysis_status: string;
  confidence_score: number;
  false_positive_probability: number;
  detection_method: string;
  analysis_duration: number;
  started_at: string;
  completed_at?: string;
  findings: {
    request_patterns: string[];
    response_anomalies: string[];
    behavioral_indicators: string[];
  };
  recommendations: string[];
}

interface EnhancedDASTMetrics {
  total_vulnerabilities: number;
  ai_analyzed_vulnerabilities: number;
  high_confidence_findings: number;
  low_confidence_findings: number;
  false_positive_rate: number;
  average_confidence_score: number;
  ai_analysis_coverage: number;
  ai_performance_metrics: {
    accuracy: number;
    precision: number;
    recall: number;
    f1_score: number;
  };
}

const EnhancedDASTDashboard: React.FC = () => {
  const [metrics, setMetrics] = useState<EnhancedDASTMetrics | null>(null);
  const [recentAnalysis, setRecentAnalysis] = useState<AIAnalysisResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedAnalysis, setSelectedAnalysis] = useState<AIAnalysisResult | null>(null);

  useEffect(() => {
    fetchEnhancedDASTData();
  }, []);

  const fetchEnhancedDASTData = async () => {
    try {
      setLoading(true);
      
      // Simulate API call to enhanced DAST service
      const mockMetrics: EnhancedDASTMetrics = {
        total_vulnerabilities: 45,
        ai_analyzed_vulnerabilities: 32,
        high_confidence_findings: 28,
        low_confidence_findings: 4,
        false_positive_rate: 0.08,
        average_confidence_score: 0.87,
        ai_analysis_coverage: 0.71,
        ai_performance_metrics: {
          accuracy: 0.92,
          precision: 0.89,
          recall: 0.94,
          f1_score: 0.91
        }
      };

      const mockAnalysis: AIAnalysisResult[] = [
        {
          analysis_id: "ai_001",
          vulnerability_id: "vuln_001",
          analysis_status: "completed",
          confidence_score: 0.95,
          false_positive_probability: 0.05,
          detection_method: "machine_learning",
          analysis_duration: 2.5,
          started_at: new Date().toISOString(),
          completed_at: new Date().toISOString(),
          findings: {
            request_patterns: ["SQL injection pattern detected"],
            response_anomalies: ["Database error response"],
            behavioral_indicators: ["Unusual parameter manipulation"]
          },
          recommendations: [
            "Implement input validation and sanitization",
            "Use parameterized queries",
            "Add WAF protection"
          ]
        },
        {
          analysis_id: "ai_002",
          vulnerability_id: "vuln_002",
          analysis_status: "completed",
          confidence_score: 0.87,
          false_positive_probability: 0.13,
          detection_method: "behavioral_analysis",
          analysis_duration: 3.2,
          started_at: new Date().toISOString(),
          completed_at: new Date().toISOString(),
          findings: {
            request_patterns: ["Script injection pattern detected"],
            response_anomalies: ["Script execution in response"],
            behavioral_indicators: ["DOM manipulation detected"]
          },
          recommendations: [
            "Implement output encoding",
            "Use Content Security Policy headers",
            "Validate and sanitize inputs"
          ]
        }
      ];

      setMetrics(mockMetrics);
      setRecentAnalysis(mockAnalysis);
    } catch (error) {
      console.error('Failed to fetch enhanced DAST data:', error);
    } finally {
      setLoading(false);
    }
  };

  const getConfidenceColor = (score: number) => {
    if (score >= 0.9) return 'text-green-600 bg-green-100';
    if (score >= 0.7) return 'text-blue-600 bg-blue-100';
    if (score >= 0.5) return 'text-yellow-600 bg-yellow-100';
    return 'text-red-600 bg-red-100';
  };

  const getConfidenceLabel = (score: number) => {
    if (score >= 0.9) return 'Very High';
    if (score >= 0.7) return 'High';
    if (score >= 0.5) return 'Medium';
    return 'Low';
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (!metrics) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-center">
          <AlertTriangle className="w-16 h-16 text-red-500 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-gray-900 mb-2">Unable to load data</h2>
          <p className="text-gray-600">Please check your connection and try again.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white shadow-sm border-b border-gray-200">
        <div className="px-6 py-4">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-gray-900">Enhanced DAST Dashboard</h1>
              <p className="text-sm text-gray-600 mt-1">
                AI-powered Dynamic Application Security Testing with advanced intelligence
              </p>
            </div>
            <div className="flex items-center space-x-4">
              <button
                onClick={fetchEnhancedDASTData}
                className="flex items-center px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                <RefreshCw className="w-4 h-4 mr-2" />
                Refresh
              </button>
              <button className="flex items-center px-4 py-2 text-sm font-medium text-white bg-blue-600 border border-transparent rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                <Download className="w-4 h-4 mr-2" />
                Export Report
              </button>
            </div>
          </div>
        </div>
      </div>

      <div className="px-6 py-8">
        {/* AI Intelligence Overview */}
        <div className="mb-8">
          <div className="bg-gradient-to-r from-blue-600 to-purple-600 rounded-lg shadow-lg p-6 text-white">
            <div className="flex items-center mb-4">
              <Brain className="w-8 h-8 mr-3" />
              <h2 className="text-xl font-semibold">AI Intelligence Overview</h2>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
              <div className="text-center">
                <div className="text-3xl font-bold mb-2">{metrics.ai_analyzed_vulnerabilities}</div>
                <div className="text-blue-100">AI Analyzed</div>
              </div>
              <div className="text-center">
                <div className="text-3xl font-bold mb-2">{metrics.high_confidence_findings}</div>
                <div className="text-blue-100">High Confidence</div>
              </div>
              <div className="text-center">
                <div className="text-3xl font-bold mb-2">{(metrics.average_confidence_score * 100).toFixed(1)}%</div>
                <div className="text-blue-100">Avg Confidence</div>
              </div>
              <div className="text-center">
                <div className="text-3xl font-bold mb-2">{(metrics.ai_analysis_coverage * 100).toFixed(1)}%</div>
                <div className="text-blue-100">Coverage</div>
              </div>
            </div>
          </div>
        </div>

        {/* AI Performance Metrics */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <div className="flex items-center mb-4">
              <BarChart3 className="w-6 h-6 text-blue-600 mr-2" />
              <h3 className="text-lg font-semibold text-gray-900">AI Performance Metrics</h3>
            </div>
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">Accuracy</span>
                <span className="text-sm font-medium text-gray-900">{(metrics.ai_performance_metrics.accuracy * 100).toFixed(1)}%</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">Precision</span>
                <span className="text-sm font-medium text-gray-900">{(metrics.ai_performance_metrics.precision * 100).toFixed(1)}%</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">Recall</span>
                <span className="text-sm font-medium text-gray-900">{(metrics.ai_performance_metrics.recall * 100).toFixed(1)}%</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">F1 Score</span>
                <span className="text-sm font-medium text-gray-900">{(metrics.ai_performance_metrics.f1_score * 100).toFixed(1)}%</span>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <div className="flex items-center mb-4">
              <Shield className="w-6 h-6 text-green-600 mr-2" />
              <h3 className="text-lg font-semibold text-gray-900">Security Metrics</h3>
            </div>
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">Total Vulnerabilities</span>
                <span className="text-sm font-medium text-gray-900">{metrics.total_vulnerabilities}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">False Positive Rate</span>
                <span className="text-sm font-medium text-gray-900">{(metrics.false_positive_rate * 100).toFixed(1)}%</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">High Confidence</span>
                <span className="text-sm font-medium text-gray-900">{metrics.high_confidence_findings}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">Low Confidence</span>
                <span className="text-sm font-medium text-gray-900">{metrics.low_confidence_findings}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Recent AI Analysis */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center">
              <BrainCircuit className="w-6 h-6 text-purple-600 mr-2" />
              <h3 className="text-lg font-semibold text-gray-900">Recent AI Analysis</h3>
            </div>
            <button className="text-sm text-blue-600 hover:text-blue-800">View All</button>
          </div>
          
          <div className="space-y-4">
            {recentAnalysis.map((analysis) => (
              <div
                key={analysis.analysis_id}
                className="border border-gray-200 rounded-lg p-4 hover:bg-gray-50 cursor-pointer"
                onClick={() => setSelectedAnalysis(analysis)}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-4">
                    <div className={`p-2 rounded-full ${getConfidenceColor(analysis.confidence_score)}`}>
                      <Brain className="w-4 h-4" />
                    </div>
                    <div>
                      <h4 className="font-medium text-gray-900">
                        Analysis {analysis.analysis_id}
                      </h4>
                      <p className="text-sm text-gray-600">
                        {analysis.detection_method.replace('_', ' ').toUpperCase()}
                      </p>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getConfidenceColor(analysis.confidence_score)}`}>
                      {getConfidenceLabel(analysis.confidence_score)} Confidence
                    </div>
                    <p className="text-sm text-gray-600 mt-1">
                      {(analysis.confidence_score * 100).toFixed(1)}%
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* AI Analysis Details Modal */}
        {selectedAnalysis && (
          <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
            <div className="relative top-20 mx-auto p-5 border w-11/12 md:w-3/4 lg:w-1/2 shadow-lg rounded-md bg-white">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gray-900">AI Analysis Details</h3>
                <button
                  onClick={() => setSelectedAnalysis(null)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  <span className="sr-only">Close</span>
                  <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
              
              <div className="space-y-4">
                <div>
                  <h4 className="font-medium text-gray-900 mb-2">Analysis Results</h4>
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="text-gray-600">Confidence Score:</span>
                      <span className="ml-2 font-medium">{(selectedAnalysis.confidence_score * 100).toFixed(1)}%</span>
                    </div>
                    <div>
                      <span className="text-gray-600">False Positive:</span>
                      <span className="ml-2 font-medium">{(selectedAnalysis.false_positive_probability * 100).toFixed(1)}%</span>
                    </div>
                    <div>
                      <span className="text-gray-600">Detection Method:</span>
                      <span className="ml-2 font-medium">{selectedAnalysis.detection_method}</span>
                    </div>
                    <div>
                      <span className="text-gray-600">Duration:</span>
                      <span className="ml-2 font-medium">{selectedAnalysis.analysis_duration}s</span>
                    </div>
                  </div>
                </div>

                <div>
                  <h4 className="font-medium text-gray-900 mb-2">AI Findings</h4>
                  <div className="space-y-2">
                    <div>
                      <span className="text-sm font-medium text-gray-700">Request Patterns:</span>
                      <ul className="text-sm text-gray-600 ml-4 list-disc">
                        {selectedAnalysis.findings.request_patterns.map((pattern, index) => (
                          <li key={index}>{pattern}</li>
                        ))}
                      </ul>
                    </div>
                    <div>
                      <span className="text-sm font-medium text-gray-700">Response Anomalies:</span>
                      <ul className="text-sm text-gray-600 ml-4 list-disc">
                        {selectedAnalysis.findings.response_anomalies.map((anomaly, index) => (
                          <li key={index}>{anomaly}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>

                <div>
                  <h4 className="font-medium text-gray-900 mb-2">Recommendations</h4>
                  <ul className="text-sm text-gray-600 space-y-1">
                    {selectedAnalysis.recommendations.map((rec, index) => (
                      <li key={index} className="flex items-start">
                        <CheckCircle className="w-4 h-4 text-green-500 mr-2 mt-0.5 flex-shrink-0" />
                        {rec}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default EnhancedDASTDashboard;
