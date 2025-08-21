import React, { useState, useEffect } from 'react';
import {
  Shield,
  Brain,
  AlertTriangle,
  TrendingUp,
  BarChart3,
  Target,
  Activity,
  RefreshCw,
  Download,
  Eye,
  BrainCircuit,
  Network,
  Database,
  Globe,
  Zap,
  CheckCircle
} from 'lucide-react';

interface AIThreatAnalysis {
  analysis_id: string;
  threat_indicator_id: string;
  analysis_status: string;
  confidence_score: number;
  false_positive_probability: number;
  detection_methods: string[];
  behavioral_indicators: {
    network_behavior: string[];
    user_behavior: string[];
    system_behavior: string[];
  };
  pattern_matches: string[];
  analysis_notes: string;
}

interface ThreatCorrelation {
  correlation_id: string;
  threat_indicator_id: string;
  correlation_type: string;
  correlation_score: number;
  correlated_domain: string;
  correlation_evidence: string;
  risk_impact: string;
}

interface PredictiveThreat {
  prediction_id: string;
  threat_type: string;
  predicted_severity: string;
  prediction_confidence: number;
  prediction_horizon: number;
  contributing_factors: string[];
  mitigation_recommendations: string[];
}

interface UnifiedSecurityMetrics {
  total_threats: number;
  ai_analyzed_threats: number;
  high_severity_threats: number;
  correlated_findings: number;
  cross_domain_correlation: {
    cloud_security: number;
    dast: number;
    network_security: number;
  };
  overall_risk_score: number;
  ai_performance: {
    threat_classification: number;
    correlation: number;
    prediction: number;
  };
}

const EnhancedThreatIntelligenceDashboard: React.FC = () => {
  const [metrics, setMetrics] = useState<UnifiedSecurityMetrics | null>(null);
  const [recentAnalysis, setRecentAnalysis] = useState<AIThreatAnalysis[]>([]);
  const [correlations, setCorrelations] = useState<ThreatCorrelation[]>([]);
  const [predictions, setPredictions] = useState<PredictiveThreat[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedAnalysis, setSelectedAnalysis] = useState<AIThreatAnalysis | null>(null);

  useEffect(() => {
    fetchEnhancedThreatIntelligenceData();
  }, []);

  const fetchEnhancedThreatIntelligenceData = async () => {
    try {
      setLoading(true);
      
      // Simulate API call to enhanced threat intelligence service
      const mockMetrics: UnifiedSecurityMetrics = {
        total_threats: 156,
        ai_analyzed_threats: 89,
        high_severity_threats: 23,
        correlated_findings: 67,
        cross_domain_correlation: {
          cloud_security: 0.78,
          dast: 0.72,
          network_security: 0.85
        },
        overall_risk_score: 7.2,
        ai_performance: {
          threat_classification: 0.94,
          correlation: 0.89,
          prediction: 0.82
        }
      };

      const mockAnalysis: AIThreatAnalysis[] = [
        {
          analysis_id: "ai_threat_001",
          threat_indicator_id: "threat_001",
          analysis_status: "completed",
          confidence_score: 0.92,
          false_positive_probability: 0.08,
          detection_methods: ["pattern_recognition", "behavioral_analysis"],
          behavioral_indicators: {
            network_behavior: ["Unusual outbound connections", "Command and control communication"],
            user_behavior: ["Suspicious credential submissions"],
            system_behavior: ["Registry modifications", "File system changes"]
          },
          pattern_matches: ["Known malware signature patterns", "Suspicious file behavior patterns"],
          analysis_notes: "AI analysis completed for malware threat with high severity. Pattern recognition and behavioral analysis indicate high confidence in malware classification. Recommend immediate containment and analysis."
        },
        {
          analysis_id: "ai_threat_002",
          threat_indicator_id: "threat_002",
          analysis_status: "completed",
          confidence_score: 0.87,
          false_positive_probability: 0.13,
          detection_methods: ["behavioral_analysis", "machine_learning"],
          behavioral_indicators: {
            network_behavior: ["Phishing site connections"],
            user_behavior: ["Credential submission to suspicious sites", "Unusual email interactions"],
            system_behavior: []
          },
          pattern_matches: ["Phishing campaign patterns", "Social engineering indicators"],
          analysis_notes: "AI analysis completed for phishing threat with medium severity. Behavioral analysis suggests sophisticated phishing campaign. User education and technical controls recommended."
        }
      ];

      const mockCorrelations: ThreatCorrelation[] = [
        {
          correlation_id: "corr_001",
          threat_indicator_id: "threat_001",
          correlation_type: "cloud_security",
          correlation_score: 0.85,
          correlated_domain: "Container Security",
          correlation_evidence: "Malware threat correlates with container security findings",
          risk_impact: "high"
        },
        {
          correlation_id: "corr_002",
          threat_indicator_id: "threat_002",
          correlation_type: "dast_vulnerability",
          correlation_score: 0.78,
          correlated_domain: "Web Application Security",
          correlation_evidence: "Phishing threat correlates with XSS vulnerabilities",
          risk_impact: "medium"
        }
      ];

      const mockPredictions: PredictiveThreat[] = [
        {
          prediction_id: "pred_001",
          threat_type: "Advanced Persistent Threat",
          predicted_severity: "critical",
          prediction_confidence: 0.89,
          prediction_horizon: 30,
          contributing_factors: ["Advanced evasion techniques", "Long-term persistence mechanisms"],
          mitigation_recommendations: [
            "Implement advanced threat hunting capabilities",
            "Deploy AI-powered security monitoring",
            "Establish incident response playbooks"
          ]
        }
      ];

      setMetrics(mockMetrics);
      setRecentAnalysis(mockAnalysis);
      setCorrelations(mockCorrelations);
      setPredictions(mockPredictions);
    } catch (error) {
      console.error('Failed to fetch enhanced threat intelligence data:', error);
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

  const getRiskImpactColor = (impact: string) => {
    switch (impact.toLowerCase()) {
      case 'critical': return 'text-red-600 bg-red-100';
      case 'high': return 'text-orange-600 bg-orange-100';
      case 'medium': return 'text-yellow-600 bg-yellow-100';
      case 'low': return 'text-green-600 bg-green-100';
      default: return 'text-gray-600 bg-gray-100';
    }
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
              <h1 className="text-2xl font-bold text-gray-900">Enhanced Threat Intelligence Dashboard</h1>
              <p className="text-sm text-gray-600 mt-1">
                AI-powered threat intelligence with cross-domain security correlation
              </p>
            </div>
            <div className="flex items-center space-x-4">
              <button
                onClick={fetchEnhancedThreatIntelligenceData}
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
          <div className="bg-gradient-to-r from-red-600 to-orange-600 rounded-lg shadow-lg p-6 text-white">
            <div className="flex items-center mb-4">
              <Brain className="w-8 h-8 mr-3" />
              <h2 className="text-xl font-semibold">AI Threat Intelligence Overview</h2>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
              <div className="text-center">
                <div className="text-3xl font-bold mb-2">{metrics.ai_analyzed_threats}</div>
                <div className="text-red-100">AI Analyzed</div>
              </div>
              <div className="text-center">
                <div className="text-3xl font-bold mb-2">{metrics.high_severity_threats}</div>
                <div className="text-red-100">High Severity</div>
              </div>
              <div className="text-center">
                <div className="text-3xl font-bold mb-2">{metrics.correlated_findings}</div>
                <div className="text-red-100">Correlated</div>
              </div>
              <div className="text-center">
                <div className="text-3xl font-bold mb-2">{metrics.overall_risk_score.toFixed(1)}</div>
                <div className="text-red-100">Risk Score</div>
              </div>
            </div>
          </div>
        </div>

        {/* Cross-Domain Correlation */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <div className="flex items-center mb-4">
              <Network className="w-6 h-6 text-blue-600 mr-2" />
              <h3 className="text-lg font-semibold text-gray-900">Cross-Domain Correlation</h3>
            </div>
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">Cloud Security</span>
                <span className="text-sm font-medium text-gray-900">{(metrics.cross_domain_correlation.cloud_security * 100).toFixed(1)}%</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">DAST Analysis</span>
                <span className="text-sm font-medium text-gray-900">{(metrics.cross_domain_correlation.dast * 100).toFixed(1)}%</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">Network Security</span>
                <span className="text-sm font-medium text-gray-900">{(metrics.cross_domain_correlation.network_security * 100).toFixed(1)}%</span>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <div className="flex items-center mb-4">
              <BarChart3 className="w-6 h-6 text-green-600 mr-2" />
              <h3 className="text-lg font-semibold text-gray-900">AI Performance Metrics</h3>
            </div>
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">Threat Classification</span>
                <span className="text-sm font-medium text-gray-900">{(metrics.ai_performance.threat_classification * 100).toFixed(1)}%</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">Correlation</span>
                <span className="text-sm font-medium text-gray-900">{(metrics.ai_performance.correlation * 100).toFixed(1)}%</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">Prediction</span>
                <span className="text-sm font-medium text-gray-900">{(metrics.ai_performance.prediction * 100).toFixed(1)}%</span>
              </div>
            </div>
          </div>
        </div>

        {/* Recent AI Analysis */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6 mb-8">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center">
              <BrainCircuit className="w-6 h-6 text-purple-600 mr-2" />
              <h3 className="text-lg font-semibold text-gray-900">Recent AI Threat Analysis</h3>
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
                        {analysis.detection_methods.join(", ").toUpperCase()}
                      </p>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getConfidenceColor(analysis.confidence_score)}`}>
                      {(analysis.confidence_score * 100).toFixed(1)}% Confidence
                    </div>
                    <p className="text-sm text-gray-600 mt-1">
                      FP: {(analysis.false_positive_probability * 100).toFixed(1)}%
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Threat Correlations */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6 mb-8">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center">
              <Target className="w-6 h-6 text-orange-600 mr-2" />
              <h3 className="text-lg font-semibold text-gray-900">Cross-Domain Threat Correlations</h3>
            </div>
            <button className="text-sm text-blue-600 hover:text-blue-800">View All</button>
          </div>
          
          <div className="space-y-4">
            {correlations.map((correlation) => (
              <div key={correlation.correlation_id} className="border border-gray-200 rounded-lg p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-4">
                    <div className={`p-2 rounded-full ${getRiskImpactColor(correlation.risk_impact)}`}>
                      <Network className="w-4 h-4" />
                    </div>
                    <div>
                      <h4 className="font-medium text-gray-900">
                        {correlation.correlated_domain} Correlation
                      </h4>
                      <p className="text-sm text-gray-600">
                        {correlation.correlation_evidence}
                      </p>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getRiskImpactColor(correlation.risk_impact)}`}>
                      {correlation.risk_impact.toUpperCase()} Risk
                    </div>
                    <p className="text-sm text-gray-600 mt-1">
                      {(correlation.correlation_score * 100).toFixed(1)}% Correlation
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Threat Predictions */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center">
              <TrendingUp className="w-6 h-6 text-green-600 mr-2" />
              <h3 className="text-lg font-semibold text-gray-900">AI Threat Predictions</h3>
            </div>
            <button className="text-sm text-blue-600 hover:text-blue-800">View All</button>
          </div>
          
          <div className="space-y-4">
            {predictions.map((prediction) => (
              <div key={prediction.prediction_id} className="border border-gray-200 rounded-lg p-4">
                <div className="flex items-center justify-between mb-3">
                  <div>
                    <h4 className="font-medium text-gray-900">{prediction.threat_type}</h4>
                    <p className="text-sm text-gray-600">
                      Predicted in {prediction.prediction_horizon} days
                    </p>
                  </div>
                  <div className="text-right">
                    <div className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getRiskImpactColor(prediction.predicted_severity)}`}>
                      {prediction.predicted_severity.toUpperCase()}
                    </div>
                    <p className="text-sm text-gray-600 mt-1">
                      {(prediction.prediction_confidence * 100).toFixed(1)}% Confidence
                    </p>
                  </div>
                </div>
                
                <div className="space-y-2">
                  <div>
                    <span className="text-sm font-medium text-gray-700">Contributing Factors:</span>
                    <ul className="text-sm text-gray-600 ml-4 list-disc">
                      {prediction.contributing_factors.map((factor, index) => (
                        <li key={index}>{factor}</li>
                      ))}
                    </ul>
                  </div>
                  
                  <div>
                    <span className="text-sm font-medium text-gray-700">Mitigation Recommendations:</span>
                    <ul className="text-sm text-gray-600 ml-4 list-disc">
                      {prediction.mitigation_recommendations.map((rec, index) => (
                        <li key={index}>{rec}</li>
                      ))}
                    </ul>
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
                <h3 className="text-lg font-semibold text-gray-900">AI Threat Analysis Details</h3>
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
                      <span className="text-gray-600">Detection Methods:</span>
                      <span className="ml-2 font-medium">{selectedAnalysis.detection_methods.join(", ")}</span>
                    </div>
                  </div>
                </div>

                <div>
                  <h4 className="font-medium text-gray-900 mb-2">Behavioral Indicators</h4>
                  <div className="space-y-2">
                    <div>
                      <span className="text-sm font-medium text-gray-700">Network Behavior:</span>
                      <ul className="text-sm text-gray-600 ml-4 list-disc">
                        {selectedAnalysis.behavioral_indicators.network_behavior.map((behavior, index) => (
                          <li key={index}>{behavior}</li>
                        ))}
                      </ul>
                    </div>
                    <div>
                      <span className="text-sm font-medium text-gray-700">System Behavior:</span>
                      <ul className="text-sm text-gray-600 ml-4 list-disc">
                        {selectedAnalysis.behavioral_indicators.system_behavior.map((behavior, index) => (
                          <li key={index}>{behavior}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>

                <div>
                  <h4 className="font-medium text-gray-900 mb-2">Pattern Matches</h4>
                  <ul className="text-sm text-gray-600 space-y-1">
                    {selectedAnalysis.pattern_matches.map((pattern, index) => (
                      <li key={index} className="flex items-start">
                        <CheckCircle className="w-4 h-4 text-green-500 mr-2 mt-0.5 flex-shrink-0" />
                        {pattern}
                      </li>
                    ))}
                  </ul>
                </div>

                <div>
                  <h4 className="font-medium text-gray-900 mb-2">Analysis Notes</h4>
                  <p className="text-sm text-gray-600">{selectedAnalysis.analysis_notes}</p>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default EnhancedThreatIntelligenceDashboard;
