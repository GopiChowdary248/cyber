import { apiClient } from '../utils/apiClient';

export interface ThreatAnalysisRequest {
  data: any;
}

export interface ThreatIndicator {
  id: string;
  name: string;
  description: string;
  confidence: number;
  threat_level: 'low' | 'medium' | 'high' | 'critical';
  source: string;
  timestamp: string;
  metadata: any;
}

export interface ThreatAnalysisResponse {
  success: boolean;
  indicators: ThreatIndicator[];
  total_indicators: number;
  analysis_timestamp: string;
}

export interface AnomalyDetectionRequest {
  data: any;
}

export interface Anomaly {
  id: string;
  type: 'user_behavior' | 'network_traffic' | 'system_activity' | 'data_access';
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  user_id?: number;
  timestamp: string;
  features: any;
  metadata: any;
}

export interface AnomalyDetectionResponse {
  success: boolean;
  anomalies: Anomaly[];
  total_anomalies: number;
  detection_timestamp: string;
}

export interface ThreatPredictionResponse {
  threat_type: string;
  probability: number;
  timeframe: string;
  confidence: number;
  recommended_actions: string[];
}

export interface IncidentClassificationRequest {
  title: string;
  description: string;
  source_data?: any;
}

export interface IncidentClassificationResponse {
  incident_type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  tags: string[];
  recommended_playbook?: string;
}

export interface SecurityInsightsResponse {
  insights: string[];
  trends: any[];
  recommendations: string[];
  risk_score: number;
  generated_at: string;
}

export interface ModelTrainingRequest {
  model_type: string;
  training_data: any;
  parameters: any;
}

export interface ThreatLandscape {
  current_threats: any[];
  emerging_threats: any[];
  threat_level: string;
  last_updated: string;
}

export interface SecurityMetrics {
  total_alerts: number;
  false_positives: number;
  true_positives: number;
  detection_rate: number;
  response_time: number;
  risk_score: number;
}

export interface SecurityTrends {
  timeframe: string;
  trends: any[];
  predictions: any[];
  anomalies: any[];
}

class AIMLService {
  // Analyze threats
  async analyzeThreats(request: ThreatAnalysisRequest): Promise<ThreatAnalysisResponse> {
    const response = await apiClient.post('/ai-ml/analyze-threats', request);
    return response.data;
  }

  // Detect anomalies
  async detectAnomalies(request: AnomalyDetectionRequest): Promise<AnomalyDetectionResponse> {
    const response = await apiClient.post('/ai-ml/detect-anomalies', request);
    return response.data;
  }

  // Predict threats
  async predictThreats(historicalData: any[]): Promise<ThreatPredictionResponse[]> {
    const response = await apiClient.post('/ai-ml/predict-threats', historicalData);
    return response.data;
  }

  // Classify incident
  async classifyIncident(request: IncidentClassificationRequest): Promise<IncidentClassificationResponse> {
    const response = await apiClient.post('/ai-ml/classify-incident', request);
    return response.data;
  }

  // Generate security insights
  async generateSecurityInsights(data: any): Promise<SecurityInsightsResponse> {
    const response = await apiClient.post('/ai-ml/generate-insights', data);
    return response.data;
  }

  // Train models
  async trainModels(request: ModelTrainingRequest): Promise<any> {
    const response = await apiClient.post('/ai-ml/train-models', request);
    return response.data;
  }

  // Get model status
  async getModelStatus(): Promise<any> {
    const response = await apiClient.get('/ai-ml/models/status');
    return response.data;
  }

  // Save models
  async saveModels(): Promise<any> {
    const response = await apiClient.post('/ai-ml/models/save');
    return response.data;
  }

  // Get threat landscape
  async getThreatLandscape(): Promise<ThreatLandscape> {
    const response = await apiClient.get('/ai-ml/analytics/threat-landscape');
    return response.data;
  }

  // Get security metrics
  async getSecurityMetrics(): Promise<SecurityMetrics> {
    const response = await apiClient.get('/ai-ml/analytics/security-metrics');
    return response.data;
  }

  // Get security trends
  async getSecurityTrends(timeframe: string = '30d'): Promise<SecurityTrends> {
    const response = await apiClient.get(`/ai-ml/analytics/trends?timeframe=${timeframe}`);
    return response.data;
  }

  // Generate recommendations
  async generateRecommendations(data: any): Promise<any> {
    const response = await apiClient.post('/ai-ml/recommendations/generate', data);
    return response.data;
  }

  // Get AI/ML health
  async getHealth(): Promise<any> {
    const response = await apiClient.get('/ai-ml/health');
    return response.data;
  }
}

export const aiMlService = new AIMLService();
export default aiMlService;
