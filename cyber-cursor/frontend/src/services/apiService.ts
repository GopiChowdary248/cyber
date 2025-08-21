import axios, { AxiosInstance, AxiosResponse } from 'axios';

// API Response types
export interface ApiResponse<T = any> {
  data: T;
  message?: string;
  status: string;
}

export interface PaginatedResponse<T> {
  data: T[];
  pagination: {
    total: number;
    limit: number;
    offset: number;
    has_more: boolean;
  };
}

// Base API service class
class ApiService {
  private api: AxiosInstance;

  constructor() {
    this.api = axios.create({
      baseURL: process.env.REACT_APP_API_URL || 'http://localhost:8000',
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Request interceptor
    this.api.interceptors.request.use(
      (config) => {
        const token = localStorage.getItem('authToken');
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => {
        return Promise.reject(error);
      }
    );

    // Response interceptor
    this.api.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response?.status === 401) {
          localStorage.removeItem('authToken');
          window.location.href = '/login';
        }
        return Promise.reject(error);
      }
    );
  }

  // Generic methods
  async get<T>(url: string, params?: any): Promise<AxiosResponse<T>> {
    return this.api.get(url, { params });
  }

  async post<T>(url: string, data?: any): Promise<AxiosResponse<T>> {
    return this.api.post(url, data);
  }

  async put<T>(url: string, data?: any): Promise<AxiosResponse<T>> {
    return this.api.put(url, data);
  }

  async delete<T>(url: string): Promise<AxiosResponse<T>> {
    return this.api.delete(url);
  }

  // Health and Status
  async getHealthStatus() {
    return this.get('/health');
  }

  async getApiStatus() {
    return this.get('/api/status');
  }

  // Authentication
  async login(credentials: { username: string; password: string }) {
    return this.post('/api/v1/auth/login', credentials);
  }

  async register(userData: { username: string; email: string; password: string }) {
    return this.post('/api/v1/auth/register', userData);
  }

  async refreshToken() {
    return this.post('/api/v1/auth/refresh');
  }

  // User Management
  async getUsers(params?: { department?: string; active_only?: boolean }) {
    return this.get('/api/v1/users/profiles', params);
  }

  async getUserProfile(userId: string) {
    return this.get(`/api/v1/users/${userId}/profile`);
  }

  async updateUserProfile(userId: string, profile: any) {
    return this.put(`/api/v1/users/${userId}/profile`, profile);
  }

  async getOnboardingUsers() {
    return this.get('/api/v1/users/onboarding');
  }

  async startUserOnboarding(userData: any) {
    return this.post('/api/v1/users/onboarding/start', userData);
  }

  // IAM Security
  async getUsersManagement() {
    return this.get('/api/v1/users/management');
  }

  async updateUserRole(update: any) {
    return this.post('/api/v1/users/roles/update', update);
  }

  async getUserRoles() {
    return this.get('/api/v1/users/roles');
  }

  async getUserAccess(userId?: string) {
    return this.get('/api/v1/users/access', { user_id: userId });
  }

  async grantUserAccess(access: any) {
    return this.post('/api/v1/users/access/grant', access);
  }

  async getAccessReviews() {
    return this.get('/api/v1/users/access/reviews');
  }

  async completeAccessReview(reviewId: string, data: any) {
    return this.post(`/api/v1/users/access/reviews/${reviewId}/complete`, data);
  }

  async getUserAnalytics() {
    return this.get('/api/v1/users/analytics');
  }

  // Incident Management
  async getIncidents(params?: { status?: string; severity?: string; category?: string }) {
    return this.get('/api/v1/incidents', params);
  }

  async createIncident(incident: any) {
    return this.post('/api/v1/incidents', incident);
  }

  async getIncidentDetails(incidentId: string) {
    return this.get(`/api/v1/incidents/${incidentId}`);
  }

  async updateIncident(incidentId: string, updates: any) {
    return this.put(`/api/v1/incidents/${incidentId}`, updates);
  }

  async addIncidentResponse(incidentId: string, response: any) {
    return this.post(`/api/v1/incidents/${incidentId}/respond`, response);
  }

  async escalateIncident(incidentId: string, data: any) {
    return this.post(`/api/v1/incidents/${incidentId}/escalate`, data);
  }

  async resolveIncident(incidentId: string, data: any) {
    return this.post(`/api/v1/incidents/${incidentId}/resolve`, data);
  }

  async getIncidentWorkflows() {
    return this.get('/api/v1/workflows');
  }

  async getIncidentMetrics() {
    return this.get('/api/v1/metrics/overview');
  }

  // AI/ML
  async getAIMLOverview() {
    return this.get('/api/v1/ai-ml');
  }

  async getAvailableModels() {
    return this.get('/api/v1/ai-ml/models');
  }

  async makePrediction(request: any) {
    return this.post('/api/v1/ai-ml/predict', request);
  }

  async detectAnomalies(request: any) {
    return this.post('/api/v1/ai-ml/anomaly-detection', request);
  }

  async trainModel(request: any) {
    return this.post('/api/v1/ai-ml/train', request);
  }

  async getTrainingStatus(trainingId: string) {
    return this.get(`/api/v1/ai-ml/training-status/${trainingId}`);
  }

  async uploadDataset(file: File) {
    const formData = new FormData();
    formData.append('file', file);
    return this.api.post('/api/v1/ai-ml/upload-dataset', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
  }

  async getPerformanceMetrics() {
    return this.get('/api/v1/ai-ml/performance-metrics');
  }

  async triggerAutomatedResponse(incidentData: any) {
    return this.post('/api/v1/ai-ml/automated-response', incidentData);
  }

  // DevSecOps
  async getDevSecOpsOverview() {
    return this.get('/api/v1/devsecops');
  }

  async getSecurityPipelines() {
    return this.get('/api/v1/devsecops/pipelines');
  }

  async scanPipelineSecurity(request: any) {
    return this.post('/api/v1/devsecops/pipelines/scan', request);
  }

  async getPipelineSecurityReport(pipelineId: string) {
    return this.get(`/api/v1/devsecops/pipelines/${pipelineId}/security-report`);
  }

  async scanContainerSecurity(request: any) {
    return this.post('/api/v1/devsecops/containers/scan', request);
  }

  async getContainerVulnerabilities() {
    return this.get('/api/v1/devsecops/containers/vulnerabilities');
  }

  async scanInfrastructureSecurity(request: any) {
    return this.post('/api/v1/devsecops/infrastructure/scan', request);
  }

  async validateSecurityGate(request: any) {
    return this.post('/api/v1/devsecops/security-gates/validate', request);
  }

  async getComplianceFrameworks() {
    return this.get('/api/v1/devsecops/compliance/frameworks');
  }

  async getComplianceStatus() {
    return this.get('/api/v1/devsecops/compliance/status');
  }

  async triggerSecurityAutomation(automationType: string, parameters: any) {
    return this.post('/api/v1/devsecops/automation/trigger', { automation_type: automationType, parameters });
  }

  async getDevSecOpsMetrics() {
    return this.get('/api/v1/devsecops/metrics/overview');
  }

  // Compliance
  async getComplianceOverview() {
    return this.get('/api/v1/compliance');
  }

  async getComplianceFrameworks() {
    return this.get('/api/v1/compliance/frameworks');
  }

  async getFrameworkDetails(frameworkId: string) {
    return this.get(`/api/v1/compliance/frameworks/${frameworkId}`);
  }

  async getComplianceAudits() {
    return this.get('/api/v1/compliance/audits');
  }

  async createComplianceAudit(request: any) {
    return this.post('/api/v1/compliance/audits', request);
  }

  async getAuditDetails(auditId: string) {
    return this.get(`/api/v1/compliance/audits/${auditId}`);
  }

  async getComplianceControls(framework?: string) {
    return this.get('/api/v1/compliance/controls', { framework });
  }

  async assessComplianceControl(controlId: string, assessment: any) {
    return this.post(`/api/v1/compliance/controls/assess`, { control_id: controlId, ...assessment });
  }

  async getCompliancePolicies() {
    return this.get('/api/v1/compliance/policies');
  }

  async getComplianceSummaryReport() {
    return this.get('/api/v1/compliance/reports/compliance-summary');
  }

  async getRiskAssessmentReport() {
    return this.get('/api/v1/compliance/reports/risk-assessment');
  }

  async runAutomatedComplianceCheck(framework: string, scope: string = 'full') {
    return this.post('/api/v1/compliance/automation/compliance-check', { framework, scope });
  }

  // Network Security
  async getNetworkSecurityOverview() {
    return this.get('/api/v1/network-security');
  }

  async getNetworkTrafficOverview() {
    return this.get('/api/v1/network-security/traffic/overview');
  }

  async analyzeNetworkTraffic(filter: any) {
    return this.post('/api/v1/network-security/traffic/analyze', filter);
  }

  async getRealTimeTraffic() {
    return this.get('/api/v1/network-security/traffic/real-time');
  }

  async getFirewallRules() {
    return this.get('/api/v1/network-security/firewall/rules');
  }

  async createFirewallRule(rule: any) {
    return this.post('/api/v1/network-security/firewall/rules', rule);
  }

  async updateFirewallRule(ruleId: string, rule: any) {
    return this.put(`/api/v1/network-security/firewall/rules/${ruleId}`, rule);
  }

  async deleteFirewallRule(ruleId: string) {
    return this.delete(`/api/v1/network-security/firewall/rules/${ruleId}`);
  }

  async getIdsRules() {
    return this.get('/api/v1/network-security/ids/rules');
  }

  async createIdsRule(rule: any) {
    return this.post('/api/v1/network-security/ids/rules', rule);
  }

  async getDetectedThreats() {
    return this.get('/api/v1/network-security/threats/detected');
  }

  async getNetworkMonitoringStatus() {
    return this.get('/api/v1/network-security/monitoring/status');
  }

  async blockIpAddress(ipAddress: string, reason: string, durationHours: number = 24) {
    return this.post('/api/v1/network-security/response/block-ip', { ip_address: ipAddress, reason, duration_hours: durationHours });
  }

  async getSecurityMetrics(timeRange: string = '24h') {
    return this.get('/api/v1/network-security/analytics/security-metrics', { time_range: timeRange });
  }

  // Data Security
  async getDataSecurityOverview() {
    return this.get('/api/v1/data-security');
  }

  async getDataClassificationOverview() {
    return this.get('/api/v1/data-security/classification/overview');
  }

  async classifyData(dataDescription: string, contentSample?: string) {
    return this.post('/api/v1/data-security/classification/classify', { data_description: dataDescription, content_sample: contentSample });
  }

  async getEncryptionStatus() {
    return this.get('/api/v1/data-security/encryption/status');
  }

  async encryptData(request: any) {
    return this.post('/api/v1/data-security/encryption/encrypt', request);
  }

  async getDlpRules() {
    return this.get('/api/v1/data-security/dlp/rules');
  }

  async createDlpRule(rule: any) {
    return this.post('/api/v1/data-security/dlp/rules', rule);
  }

  async getDlpIncidents() {
    return this.get('/api/v1/data-security/dlp/incidents');
  }

  async getPrivacyOverview() {
    return this.get('/api/v1/data-security/privacy/overview');
  }

  async getDataConsents(subjectId?: string) {
    return this.get('/api/v1/data-security/privacy/consents', { subject_id: subjectId });
  }

  async manageConsent(subjectId: string, purpose: string, dataTypes: string[], consentGiven: boolean) {
    return this.post('/api/v1/data-security/privacy/consent', { subject_id: subjectId, purpose, data_types: dataTypes, consent_given: consentGiven });
  }

  async getDataAccessAuditLogs() {
    return this.get('/api/v1/data-security/audit/data-access');
  }

  async getDataProtectionCompliance() {
    return this.get('/api/v1/data-security/compliance/data-protection');
  }

  // Admin
  async getAdminOverview() {
    return this.get('/api/v1/admin');
  }

  async getSystemStatus() {
    return this.get('/api/v1/admin/system/status');
  }

  async getSystemConfiguration() {
    return this.get('/api/v1/admin/system/config');
  }

  async updateSystemConfiguration(settingName: string, newValue: string) {
    return this.put('/api/v1/admin/system/config', { setting_name: settingName, new_value: newValue });
  }

  async getUserManagementOverview() {
    return this.get('/api/v1/admin/users/management');
  }

  async getMaintenanceSchedule() {
    return this.get('/api/v1/admin/system/maintenance');
  }

  async scheduleMaintenance(maintenance: any) {
    return this.post('/api/v1/admin/system/maintenance', maintenance);
  }

  async getBackupStatus() {
    return this.get('/api/v1/admin/system/backup');
  }

  async triggerManualBackup(backupType: string = 'full') {
    return this.post('/api/v1/admin/system/backup/trigger', { backup_type: backupType });
  }

  async getSecurityPolicies() {
    return this.get('/api/v1/admin/system/security/policies');
  }

  async getAdminAuditLogs() {
    return this.get('/api/v1/admin/system/audit/logs');
  }

  async getDetailedSystemHealth() {
    return this.get('/api/v1/admin/system/health/detailed');
  }

  // Audit Logs
  async getAuditLogsOverview() {
    return this.get('/api/v1/audit');
  }

  async getAuditLogs(params?: any) {
    return this.get('/api/v1/audit/logs', params);
  }

  async searchAuditLogs(query: string, limit: number = 100) {
    return this.get('/api/v1/audit/logs/search', { query, limit });
  }

  async getAuditLogStatistics(timeRange: string = '24h') {
    return this.get('/api/v1/audit/logs/statistics', { time_range: timeRange });
  }

  async getRealTimeAuditLogs() {
    return this.get('/api/v1/audit/logs/real-time');
  }

  async exportAuditLogs(exportRequest: any) {
    return this.post('/api/v1/audit/logs/export', exportRequest);
  }

  async getLogRetentionPolicy() {
    return this.get('/api/v1/audit/logs/retention');
  }

  async triggerLogCleanup() {
    return this.post('/api/v1/audit/logs/retention/cleanup');
  }

  async getComplianceReport() {
    return this.get('/api/v1/audit/logs/compliance');
  }

  async getRiskAssessmentReport() {
    return this.get('/api/v1/audit/logs/risk-assessment');
  }

  async runAutomatedComplianceCheck(framework: string, scope: string = 'full') {
    return this.post('/api/v1/audit/logs/automation/compliance-check', { framework, scope });
  }

  async getAuditLogAlerts() {
    return this.get('/api/v1/audit/logs/alerts');
  }

  // Reporting
  async getReportingOverview() {
    return this.get('/api/v1/reporting');
  }

  async getAvailableReports() {
    return this.get('/api/v1/reporting/reports/available');
  }

  async generateReport(request: any) {
    return this.post('/api/v1/reporting/reports/generate', request);
  }

  async getReportStatus(reportId: string) {
    return this.get(`/api/v1/reporting/reports/${reportId}`);
  }

  async getScheduledReports() {
    return this.get('/api/v1/reporting/reports/scheduled');
  }

  async scheduleReport(schedule: any) {
    return this.post('/api/v1/reporting/reports/schedule', schedule);
  }

  async updateScheduledReport(scheduleId: string, updates: any) {
    return this.put(`/api/v1/reporting/reports/schedule/${scheduleId}`, updates);
  }

  async deleteScheduledReport(scheduleId: string) {
    return this.delete(`/api/v1/reporting/reports/schedule/${scheduleId}`);
  }

  async getReportTemplates() {
    return this.get('/api/v1/reporting/templates');
  }

  async createReportTemplate(template: any) {
    return this.post('/api/v1/reporting/templates', template);
  }

  async getAnalyticsDashboard() {
    return this.get('/api/v1/reporting/analytics/dashboard');
  }

  async getAnalyticsTrends(metric: string, timeRange: string = '30d') {
    return this.get('/api/v1/reporting/analytics/trends', { metric, time_range: timeRange });
  }

  async getExportFormats() {
    return this.get('/api/v1/reporting/export/formats');
  }

  // Integrations
  async getIntegrationsOverview() {
    return this.get('/api/v1/integrations');
  }

  async getIntegrations() {
    return this.get('/api/v1/integrations/integrations');
  }

  async getIntegrationDetails(integrationId: string) {
    return this.get(`/api/v1/integrations/integrations/${integrationId}`);
  }

  async createIntegration(integration: any) {
    return this.post('/api/v1/integrations/integrations', integration);
  }

  async updateIntegration(integrationId: string, updates: any) {
    return this.put(`/api/v1/integrations/integrations/${integrationId}`, updates);
  }

  async deleteIntegration(integrationId: string) {
    return this.delete(`/api/v1/integrations/integrations/${integrationId}`);
  }

  async testIntegration(integrationId: string, test: any) {
    return this.post(`/api/v1/integrations/integrations/${integrationId}/test`, test);
  }

  async triggerIntegrationSync(integrationId: string, syncType: string = 'full') {
    return this.post(`/api/v1/integrations/integrations/${integrationId}/sync`, { sync_type: syncType });
  }

  async getIntegrationLogs(integrationId: string, limit: number = 100) {
    return this.get(`/api/v1/integrations/integrations/${integrationId}/logs`, { limit });
  }

  async getWebhooks() {
    return this.get('/api/v1/integrations/webhooks');
  }

  async createWebhook(name: string, url: string, events: string[]) {
    return this.post('/api/v1/integrations/webhooks', { name, url, events });
  }

  async getApiEndpoints() {
    return this.get('/api/v1/integrations/api/endpoints');
  }

  async getApiCredentials() {
    return this.get('/api/v1/integrations/api/credentials');
  }

  async createApiCredential(credential: any) {
    return this.post('/api/v1/integrations/api/credentials', credential);
  }

  async getIntegrationMonitoringStatus() {
    return this.get('/api/v1/integrations/monitoring/status');
  }

  // Threat Intelligence
  async getThreatIntelligenceOverview() {
    return this.get('/api/v1/threat-intelligence');
  }

  async getIocs() {
    return this.get('/api/v1/threat-intelligence/iocs');
  }

  async getThreatFeeds() {
    return this.get('/api/v1/threat-intelligence/feeds');
  }

  async getThreatAnalysis() {
    return this.get('/api/v1/threat-intelligence/analysis');
  }

  async getThreats() {
    return this.get('/api/v1/threat-intelligence/threats');
  }

  async getIndicators() {
    return this.get('/api/v1/threat-intelligence/indicators');
  }

  async createIoc() {
    return this.post('/api/v1/threat-intelligence/iocs');
  }

  async updateIoc(iocId: string) {
    return this.put(`/api/v1/threat-intelligence/iocs/${iocId}`);
  }

  async deleteIoc(iocId: string) {
    return this.delete(`/api/v1/threat-intelligence/iocs/${iocId}`);
  }
}

// Export singleton instance
export const apiService = new ApiService();
export default apiService;
