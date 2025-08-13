import { apiClient } from '../utils/apiClient';

export interface SecurityMetrics {
  total_incidents: number;
  open_incidents: number;
  resolved_incidents: number;
  mean_time_to_resolution: number;
  incidents_by_severity: Record<string, number>;
  incidents_by_category: Record<string, number>;
  top_threat_vectors: Array<{
    vector: string;
    count: number;
    percentage: number;
  }>;
  security_score: number;
  trend: 'improving' | 'stable' | 'declining';
}

export interface RiskAssessment {
  overall_risk_score: number;
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  risk_factors: Array<{
    factor: string;
    score: number;
    impact: string;
    likelihood: string;
  }>;
  asset_risk_distribution: Record<string, number>;
  vulnerability_risk_distribution: Record<string, number>;
  compliance_risk_distribution: Record<string, number>;
  recommendations: Array<{
    priority: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    effort: 'low' | 'medium' | 'high';
    impact: 'low' | 'medium' | 'high';
  }>;
  assessment_date: string;
  next_assessment: string;
}

export interface ComplianceMetrics {
  overall_compliance_score: number;
  compliance_by_standard: Record<string, {
    score: number;
    passed_checks: number;
    failed_checks: number;
    total_checks: number;
    critical_findings: number;
    high_findings: number;
    medium_findings: number;
    low_findings: number;
  }>;
  compliance_trends: Array<{
    date: string;
    score: number;
    changes: number;
  }>;
  top_compliance_issues: Array<{
    standard: string;
    issue: string;
    severity: string;
    affected_assets: number;
    remediation_effort: string;
  }>;
  upcoming_audits: Array<{
    standard: string;
    audit_date: string;
    preparation_status: string;
    estimated_score: number;
  }>;
}

export interface ThreatIntelligenceMetrics {
  total_indicators: number;
  indicators_by_type: Record<string, number>;
  indicators_by_severity: Record<string, number>;
  threat_actors: Array<{
    name: string;
    threat_level: string;
    attack_vectors: string[];
    target_industries: string[];
    recent_activity: string;
  }>;
  emerging_threats: Array<{
    threat: string;
    description: string;
    severity: string;
    affected_platforms: string[];
    detection_methods: string[];
    mitigation_strategies: string[];
  }>;
  ioc_effectiveness: Array<{
    indicator: string;
    detection_rate: number;
    false_positive_rate: number;
    last_updated: string;
  }>;
}

export interface PerformanceMetrics {
  system_uptime: number;
  response_time: {
    average: number;
    p95: number;
    p99: number;
  };
  throughput: {
    requests_per_second: number;
    data_processed_per_second: number;
  };
  resource_utilization: {
    cpu: number;
    memory: number;
    disk: number;
    network: number;
  };
  error_rates: {
    total_errors: number;
    error_rate_percentage: number;
    top_error_types: Array<{
      type: string;
      count: number;
      percentage: number;
    }>;
  };
  capacity_planning: {
    current_usage: number;
    projected_growth: number;
    recommended_capacity: number;
    upgrade_recommendations: string[];
  };
}

export interface UserBehaviorAnalytics {
  total_users: number;
  active_users: {
    daily: number;
    weekly: number;
    monthly: number;
  };
  user_activity_patterns: Array<{
    time_period: string;
    activity_level: number;
    peak_hours: string[];
    low_activity_hours: string[];
  }>;
  feature_usage: Array<{
    feature: string;
    usage_count: number;
    unique_users: number;
    satisfaction_score: number;
  }>;
  user_risk_profiles: Array<{
    risk_level: string;
    user_count: number;
    percentage: number;
    common_behaviors: string[];
  }>;
  training_needs: Array<{
    user_group: string;
    skill_gaps: string[];
    recommended_training: string[];
    priority: 'low' | 'medium' | 'high';
  }>;
}

export interface CostAnalysis {
  total_security_cost: number;
  cost_breakdown: {
    personnel: number;
    technology: number;
    services: number;
    compliance: number;
    incident_response: number;
  };
  cost_per_incident: number;
  cost_savings: {
    incident_prevention: number;
    automation_efficiency: number;
    process_optimization: number;
    total_savings: number;
  };
  roi_metrics: {
    security_investment: number;
    incident_cost_reduction: number;
    compliance_cost_reduction: number;
    total_roi: number;
    roi_percentage: number;
  };
  budget_allocation: Array<{
    category: string;
    allocated_amount: number;
    spent_amount: number;
    remaining_amount: number;
    utilization_percentage: number;
  }>;
}

export interface PredictiveAnalytics {
  incident_prediction: {
    probability: number;
    confidence: number;
    predicted_severity: string;
    predicted_category: string;
    risk_factors: string[];
    recommended_actions: string[];
  };
  threat_evolution: {
    current_threats: string[];
    emerging_threats: string[];
    threat_evolution_trend: string;
    predicted_impact: string;
    preparation_recommendations: string[];
  };
  capacity_forecasting: {
    current_capacity: number;
    projected_demand: number;
    capacity_gap: number;
    recommended_investments: string[];
    timeline: string;
  };
  risk_forecasting: {
    current_risk_score: number;
    projected_risk_score: number;
    risk_trend: string;
    contributing_factors: string[];
    mitigation_strategies: string[];
  };
}

export interface CustomReport {
  id: string;
  name: string;
  description: string;
  report_type: string;
  parameters: Record<string, any>;
  schedule?: string;
  recipients: string[];
  format: 'pdf' | 'csv' | 'json' | 'html';
  last_generated?: string;
  next_generation?: string;
  is_active: boolean;
}

class AnalyticsService {
  private baseUrl = '/api/v1/analytics';

  // Security Metrics
  async getSecurityMetrics(
    startDate?: string,
    endDate?: string,
    includeTrends: boolean = true
  ): Promise<SecurityMetrics> {
    const params = new URLSearchParams();
    if (startDate) params.append('start_date', startDate);
    if (endDate) params.append('end_date', endDate);
    params.append('include_trends', includeTrends.toString());
    
    const response = await apiClient.get(`${this.baseUrl}/security-metrics?${params.toString()}`);
    return response.data;
  }

  async getSecurityMetricsTrends(days: number = 30): Promise<{
    dates: string[];
    metrics: SecurityMetrics[];
  }> {
    const response = await apiClient.get(`${this.baseUrl}/security-metrics/trends?days=${days}`);
    return response.data;
  }

  // Risk Assessment
  async getRiskAssessment(
    assetId?: string,
    includeRecommendations: boolean = true
  ): Promise<RiskAssessment> {
    const params = new URLSearchParams();
    if (assetId) params.append('asset_id', assetId);
    params.append('include_recommendations', includeRecommendations.toString());
    
    const response = await apiClient.get(`${this.baseUrl}/risk-assessment?${params.toString()}`);
    return response.data;
  }

  async updateRiskAssessment(
    assessmentId: string,
    updates: Partial<RiskAssessment>
  ): Promise<{
    message: string;
    assessment_id: string;
    status: string;
  }> {
    const response = await apiClient.patch(`${this.baseUrl}/risk-assessment/${assessmentId}`, updates);
    return response.data;
  }

  // Compliance Metrics
  async getComplianceMetrics(
    standard?: string,
    includeTrends: boolean = true
  ): Promise<ComplianceMetrics> {
    const params = new URLSearchParams();
    if (standard) params.append('standard', standard);
    params.append('include_trends', includeTrends.toString());
    
    const response = await apiClient.get(`${this.baseUrl}/compliance-metrics?${params.toString()}`);
    return response.data;
  }

  async generateComplianceReport(
    standard: string,
    format: 'pdf' | 'csv' | 'json' = 'pdf'
  ): Promise<{
    message: string;
    report_id: string;
    download_url: string;
    generated_at: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/compliance-report`, {
      standard,
      format
    });
    return response.data;
  }

  // Threat Intelligence Metrics
  async getThreatIntelligenceMetrics(
    includeEmergingThreats: boolean = true,
    includeIOCOutcomes: boolean = true
  ): Promise<ThreatIntelligenceMetrics> {
    const params = new URLSearchParams();
    params.append('include_emerging_threats', includeEmergingThreats.toString());
    params.append('include_ioc_outcomes', includeIOCOutcomes.toString());
    
    const response = await apiClient.get(`${this.baseUrl}/threat-intelligence-metrics?${params.toString()}`);
    return response.data;
  }

  async updateThreatIntelligence(
    intelId: string,
    updates: Partial<ThreatIntelligenceMetrics>
  ): Promise<{
    message: string;
    intel_id: string;
    status: string;
  }> {
    const response = await apiClient.patch(`${this.baseUrl}/threat-intelligence/${intelId}`, updates);
    return response.data;
  }

  // Performance Metrics
  async getPerformanceMetrics(
    includeCapacityPlanning: boolean = true,
    includeErrorAnalysis: boolean = true
  ): Promise<PerformanceMetrics> {
    const params = new URLSearchParams();
    params.append('include_capacity_planning', includeCapacityPlanning.toString());
    params.append('include_error_analysis', includeErrorAnalysis.toString());
    
    const response = await apiClient.get(`${this.baseUrl}/performance-metrics?${params.toString()}`);
    return response.data;
  }

  async getPerformanceTrends(
    metric: string,
    startDate: string,
    endDate: string,
    interval: string = '1h'
  ): Promise<{
    metric: string;
    values: Array<{ timestamp: string; value: number }>;
    trend: 'up' | 'down' | 'stable';
    anomalies: Array<{ timestamp: string; value: number; severity: string }>;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/performance-trends`, {
      metric,
      start_date: startDate,
      end_date: endDate,
      interval
    });
    return response.data;
  }

  // User Behavior Analytics
  async getUserBehaviorAnalytics(
    includeRiskProfiles: boolean = true,
    includeTrainingNeeds: boolean = true
  ): Promise<UserBehaviorAnalytics> {
    const params = new URLSearchParams();
    params.append('include_risk_profiles', includeRiskProfiles.toString());
    params.append('include_training_needs', includeTrainingNeeds.toString());
    
    const response = await apiClient.get(`${this.baseUrl}/user-behavior-analytics?${params.toString()}`);
    return response.data;
  }

  async getUserActivityHeatmap(
    startDate: string,
    endDate: string
  ): Promise<{
    dates: string[];
    hours: string[];
    activity_matrix: number[][];
    peak_activity: { date: string; hour: string; activity_level: number };
  }> {
    const response = await apiClient.post(`${this.baseUrl}/user-activity-heatmap`, {
      start_date: startDate,
      end_date: endDate
    });
    return response.data;
  }

  // Cost Analysis
  async getCostAnalysis(
    startDate?: string,
    endDate?: string,
    includeROI: boolean = true
  ): Promise<CostAnalysis> {
    const params = new URLSearchParams();
    if (startDate) params.append('start_date', startDate);
    if (endDate) params.append('end_date', endDate);
    params.append('include_roi', includeROI.toString());
    
    const response = await apiClient.get(`${this.baseUrl}/cost-analysis?${params.toString()}`);
    return response.data;
  }

  async getCostOptimizationRecommendations(): Promise<{
    recommendations: Array<{
      category: string;
      description: string;
      potential_savings: number;
      effort: 'low' | 'medium' | 'high';
      priority: 'low' | 'medium' | 'high';
      timeline: string;
    }>;
    total_potential_savings: number;
  }> {
    const response = await apiClient.get(`${this.baseUrl}/cost-optimization-recommendations`);
    return response.data;
  }

  // Predictive Analytics
  async getPredictiveAnalytics(
    includeAllPredictions: boolean = true
  ): Promise<PredictiveAnalytics> {
    const params = new URLSearchParams();
    params.append('include_all_predictions', includeAllPredictions.toString());
    
    const response = await apiClient.get(`${this.baseUrl}/predictive-analytics?${params.toString()}`);
    return response.data;
  }

  async generateIncidentPrediction(
    assetId?: string,
    timeHorizon: string = '7d'
  ): Promise<{
    prediction_id: string;
    predictions: Array<{
      asset_id: string;
      incident_probability: number;
      predicted_severity: string;
      confidence: number;
      risk_factors: string[];
      recommended_actions: string[];
    }>;
    generated_at: string;
    validity_period: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/incident-prediction`, {
      asset_id: assetId,
      time_horizon: timeHorizon
    });
    return response.data;
  }

  // Custom Reports
  async getCustomReports(): Promise<CustomReport[]> {
    const response = await apiClient.get(`${this.baseUrl}/custom-reports`);
    return response.data;
  }

  async createCustomReport(reportData: Omit<CustomReport, 'id' | 'last_generated'>): Promise<{
    message: string;
    report_id: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/custom-reports`, reportData);
    return response.data;
  }

  async generateCustomReport(
    reportId: string,
    parameters?: Record<string, any>
  ): Promise<{
    message: string;
    report_id: string;
    download_url: string;
    generated_at: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/custom-reports/${reportId}/generate`, {
      parameters
    });
    return response.data;
  }

  // Data Export
  async exportAnalyticsData(
    dataType: string,
    format: 'csv' | 'json' | 'xlsx',
    filters?: Record<string, any>
  ): Promise<{
    message: string;
    export_id: string;
    download_url: string;
    expires_at: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/export`, {
      data_type: dataType,
      format,
      filters
    });
    return response.data;
  }

  // Dashboard Data
  async getAnalyticsDashboard(): Promise<{
    overview: {
      total_assets: number;
      security_score: number;
      compliance_score: number;
      risk_score: number;
      active_incidents: number;
    };
    recent_activity: Array<{
      timestamp: string;
      activity: string;
      severity: string;
      asset: string;
    }>;
    quick_metrics: Record<string, number>;
    alerts: Array<{
      id: string;
      title: string;
      severity: string;
      timestamp: string;
    }>;
  }> {
    const response = await apiClient.get(`${this.baseUrl}/dashboard`);
    return response.data;
  }
}

export const analyticsService = new AnalyticsService();
