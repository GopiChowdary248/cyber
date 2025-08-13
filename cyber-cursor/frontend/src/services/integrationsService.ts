import { apiClient } from '../utils/apiClient';

export interface Integration {
  id: string;
  name: string;
  description: string;
  type: 'security_tool' | 'cloud_service' | 'communication' | 'monitoring' | 'ticketing' | 'custom';
  provider: string;
  version: string;
  status: 'active' | 'inactive' | 'error' | 'configuring' | 'testing';
  configuration: Record<string, any>;
  credentials: Record<string, any>;
  endpoints: string[];
  capabilities: string[];
  is_enabled: boolean;
  last_sync?: string;
  sync_status: 'success' | 'failed' | 'in_progress' | 'pending';
  error_count: number;
  last_error?: string;
  created_at: string;
  updated_at: string;
  created_by: string;
  tags: string[];
}

export interface IntegrationTemplate {
  id: string;
  name: string;
  description: string;
  type: string;
  provider: string;
  category: string;
  complexity: 'simple' | 'medium' | 'complex';
  estimated_setup_time: string;
  prerequisites: string[];
  required_fields: Array<{
    name: string;
    type: string;
    description: string;
    is_required: boolean;
    default_value?: any;
    validation_rules?: string[];
  }>;
  optional_fields: Array<{
    name: string;
    type: string;
    description: string;
    default_value?: any;
    validation_rules?: string[];
  }>;
  capabilities: string[];
  documentation_url?: string;
  is_official: boolean;
  rating: number;
  usage_count: number;
  created_at: string;
  updated_at: string;
}

export interface IntegrationTest {
  id: string;
  integration_id: string;
  test_type: 'connection' | 'authentication' | 'functionality' | 'performance' | 'full';
  status: 'running' | 'passed' | 'failed' | 'partial';
  started_at: string;
  completed_at?: string;
  duration_seconds?: number;
  results: {
    connection: boolean;
    authentication: boolean;
    permissions: boolean;
    data_access: boolean;
    api_rate_limits: boolean;
    error_handling: boolean;
  };
  error_messages: string[];
  warnings: string[];
  recommendations: string[];
  executed_by: string;
}

export interface DataMapping {
  id: string;
  integration_id: string;
  source_field: string;
  target_field: string;
  transformation_type: 'direct' | 'transform' | 'conditional' | 'aggregate';
  transformation_rules?: Record<string, any>;
  is_required: boolean;
  default_value?: any;
  validation_rules?: string[];
  created_at: string;
  updated_at: string;
}

export interface SyncJob {
  id: string;
  integration_id: string;
  sync_type: 'full' | 'incremental' | 'real_time';
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  started_at: string;
  completed_at?: string;
  duration_seconds?: number;
  records_processed: number;
  records_created: number;
  records_updated: number;
  records_deleted: number;
  errors_count: number;
  error_details?: any;
  progress: number;
  estimated_completion?: string;
  created_by: string;
}

export interface IntegrationLog {
  id: string;
  integration_id: string;
  timestamp: string;
  level: 'debug' | 'info' | 'warning' | 'error' | 'critical';
  message: string;
  details?: any;
  correlation_id?: string;
  user_id?: string;
  ip_address?: string;
}

export interface WebhookConfiguration {
  id: string;
  integration_id: string;
  name: string;
  url: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  headers: Record<string, string>;
  payload_template: string;
  trigger_conditions: Array<{
    event_type: string;
    conditions: Record<string, any>;
  }>;
  is_active: boolean;
  retry_count: number;
  retry_delay: number;
  timeout_seconds: number;
  created_at: string;
  updated_at: string;
}

export interface APIConfiguration {
  id: string;
  integration_id: string;
  base_url: string;
  authentication_type: 'none' | 'basic' | 'bearer' | 'api_key' | 'oauth2';
  credentials: Record<string, any>;
  headers: Record<string, string>;
  rate_limits: {
    requests_per_minute: number;
    requests_per_hour: number;
    burst_limit: number;
  };
  timeout_seconds: number;
  retry_config: {
    max_retries: number;
    retry_delay: number;
    backoff_multiplier: number;
  };
  endpoints: Array<{
    name: string;
    path: string;
    method: string;
    description: string;
    parameters: Record<string, any>;
  }>;
  created_at: string;
  updated_at: string;
}

export interface IntegrationMetrics {
  total_integrations: number;
  active_integrations: number;
  integrations_by_type: Record<string, number>;
  integrations_by_status: Record<string, number>;
  sync_success_rate: number;
  average_sync_duration: number;
  error_rate: number;
  most_active_integrations: Array<{
    integration_id: string;
    integration_name: string;
    sync_count: number;
    success_rate: number;
    last_sync: string;
  }>;
  sync_trends: Array<{
    date: string;
    sync_count: number;
    success_rate: number;
    average_duration: number;
  }>;
}

class IntegrationsService {
  private baseUrl = '/api/v1/integrations';

  // Integration Management
  async getIntegrations(
    type?: string,
    status?: string,
    provider?: string,
    isEnabled?: boolean
  ): Promise<Integration[]> {
    const params = new URLSearchParams();
    if (type) params.append('type', type);
    if (status) params.append('status', status);
    if (provider) params.append('provider', provider);
    if (isEnabled !== undefined) params.append('is_enabled', isEnabled.toString());
    
    const response = await apiClient.get(`${this.baseUrl}?${params.toString()}`);
    return response.data;
  }

  async getIntegration(integrationId: string): Promise<Integration> {
    const response = await apiClient.get(`${this.baseUrl}/${integrationId}`);
    return response.data;
  }

  async createIntegration(
    integrationData: Omit<Integration, 'id' | 'created_at' | 'updated_at' | 'last_sync' | 'sync_status' | 'error_count' | 'last_error'>
  ): Promise<{
    message: string;
    integration_id: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}`, integrationData);
    return response.data;
  }

  async updateIntegration(
    integrationId: string,
    updateData: Partial<Integration>
  ): Promise<{
    message: string;
    integration_id: string;
    status: string;
  }> {
    const response = await apiClient.patch(`${this.baseUrl}/${integrationId}`, updateData);
    return response.data;
  }

  async deleteIntegration(integrationId: string): Promise<{
    message: string;
    integration_id: string;
  }> {
    const response = await apiClient.delete(`${this.baseUrl}/${integrationId}`);
    return response.data;
  }

  async enableIntegration(integrationId: string): Promise<{
    message: string;
    integration_id: string;
    status: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/${integrationId}/enable`);
    return response.data;
  }

  async disableIntegration(integrationId: string): Promise<{
    message: string;
    integration_id: string;
    status: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/${integrationId}/disable`);
    return response.data;
  }

  // Integration Templates
  async getIntegrationTemplates(
    type?: string,
    category?: string,
    complexity?: string,
    isOfficial?: boolean
  ): Promise<IntegrationTemplate[]> {
    const params = new URLSearchParams();
    if (type) params.append('type', type);
    if (category) params.append('category', category);
    if (complexity) params.append('complexity', complexity);
    if (isOfficial !== undefined) params.append('is_official', isOfficial.toString());
    
    const response = await apiClient.get(`${this.baseUrl}/templates?${params.toString()}`);
    return response.data;
  }

  async createIntegrationFromTemplate(
    templateId: string,
    integrationName: string,
    integrationDescription?: string,
    configuration?: Record<string, any>
  ): Promise<{
    message: string;
    integration_id: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/templates/${templateId}/create`, {
      integration_name: integrationName,
      integration_description: integrationDescription,
      configuration
    });
    return response.data;
  }

  // Integration Testing
  async testIntegration(
    integrationId: string,
    testType: string = 'full'
  ): Promise<{
    message: string;
    test_id: string;
    status: string;
    estimated_duration: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/${integrationId}/test`, {
      test_type: testType
    });
    return response.data;
  }

  async getIntegrationTest(testId: string): Promise<IntegrationTest> {
    const response = await apiClient.get(`${this.baseUrl}/tests/${testId}`);
    return response.data;
  }

  async getIntegrationTests(
    integrationId?: string,
    status?: string,
    limit: number = 100
  ): Promise<IntegrationTest[]> {
    const params = new URLSearchParams();
    if (integrationId) params.append('integration_id', integrationId);
    if (status) params.append('status', status);
    params.append('limit', limit.toString());
    
    const response = await apiClient.get(`${this.baseUrl}/tests?${params.toString()}`);
    return response.data;
  }

  // Data Mapping
  async getDataMappings(integrationId: string): Promise<DataMapping[]> {
    const response = await apiClient.get(`${this.baseUrl}/${integrationId}/mappings`);
    return response.data;
  }

  async createDataMapping(
    integrationId: string,
    mappingData: Omit<DataMapping, 'id' | 'integration_id' | 'created_at' | 'updated_at'>
  ): Promise<{
    message: string;
    mapping_id: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/${integrationId}/mappings`, mappingData);
    return response.data;
  }

  async updateDataMapping(
    mappingId: string,
    updateData: Partial<DataMapping>
  ): Promise<{
    message: string;
    mapping_id: string;
    status: string;
  }> {
    const response = await apiClient.patch(`${this.baseUrl}/mappings/${mappingId}`, updateData);
    return response.data;
  }

  async deleteDataMapping(mappingId: string): Promise<{
    message: string;
    mapping_id: string;
  }> {
    const response = await apiClient.delete(`${this.baseUrl}/mappings/${mappingId}`);
    return response.data;
  }

  // Sync Management
  async startSync(
    integrationId: string,
    syncType: string = 'incremental'
  ): Promise<{
    message: string;
    sync_job_id: string;
    status: string;
    estimated_duration: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/${integrationId}/sync`, {
      sync_type: syncType
    });
    return response.data;
  }

  async getSyncJob(syncJobId: string): Promise<SyncJob> {
    const response = await apiClient.get(`${this.baseUrl}/sync-jobs/${syncJobId}`);
    return response.data;
  }

  async getSyncJobs(
    integrationId?: string,
    status?: string,
    startDate?: string,
    endDate?: string,
    limit: number = 100
  ): Promise<SyncJob[]> {
    const params = new URLSearchParams();
    if (integrationId) params.append('integration_id', integrationId);
    if (status) params.append('status', status);
    if (startDate) params.append('start_date', startDate);
    if (endDate) params.append('end_date', endDate);
    params.append('limit', limit.toString());
    
    const response = await apiClient.get(`${this.baseUrl}/sync-jobs?${params.toString()}`);
    return response.data;
  }

  async cancelSyncJob(syncJobId: string): Promise<{
    message: string;
    sync_job_id: string;
    status: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/sync-jobs/${syncJobId}/cancel`);
    return response.data;
  }

  // Webhook Configuration
  async getWebhookConfigurations(integrationId: string): Promise<WebhookConfiguration[]> {
    const response = await apiClient.get(`${this.baseUrl}/${integrationId}/webhooks`);
    return response.data;
  }

  async createWebhookConfiguration(
    integrationId: string,
    webhookData: Omit<WebhookConfiguration, 'id' | 'integration_id' | 'created_at' | 'updated_at'>
  ): Promise<{
    message: string;
    webhook_id: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/${integrationId}/webhooks`, webhookData);
    return response.data;
  }

  async updateWebhookConfiguration(
    webhookId: string,
    updateData: Partial<WebhookConfiguration>
  ): Promise<{
    message: string;
    webhook_id: string;
    status: string;
  }> {
    const response = await apiClient.patch(`${this.baseUrl}/webhooks/${webhookId}`, updateData);
    return response.data;
  }

  async deleteWebhookConfiguration(webhookId: string): Promise<{
    message: string;
    webhook_id: string;
  }> {
    const response = await apiClient.delete(`${this.baseUrl}/webhooks/${webhookId}`);
    return response.data;
  }

  // API Configuration
  async getAPIConfiguration(integrationId: string): Promise<APIConfiguration> {
    const response = await apiClient.get(`${this.baseUrl}/${integrationId}/api-config`);
    return response.data;
  }

  async updateAPIConfiguration(
    integrationId: string,
    updateData: Partial<APIConfiguration>
  ): Promise<{
    message: string;
    integration_id: string;
    status: string;
  }> {
    const response = await apiClient.patch(`${this.baseUrl}/${integrationId}/api-config`, updateData);
    return response.data;
  }

  // Integration Logs
  async getIntegrationLogs(
    integrationId?: string,
    level?: string,
    startDate?: string,
    endDate?: string,
    limit: number = 100
  ): Promise<IntegrationLog[]> {
    const params = new URLSearchParams();
    if (integrationId) params.append('integration_id', integrationId);
    if (level) params.append('level', level);
    if (startDate) params.append('start_date', startDate);
    if (endDate) params.append('end_date', endDate);
    params.append('limit', limit.toString());
    
    const response = await apiClient.get(`${this.baseUrl}/logs?${params.toString()}`);
    return response.data;
  }

  // Integration Metrics
  async getIntegrationMetrics(
    startDate?: string,
    endDate?: string,
    includeTrends: boolean = true
  ): Promise<IntegrationMetrics> {
    const params = new URLSearchParams();
    if (startDate) params.append('start_date', startDate);
    if (endDate) params.append('end_date', endDate);
    params.append('include_trends', includeTrends.toString());
    
    const response = await apiClient.get(`${this.baseUrl}/metrics?${params.toString()}`);
    return response.data;
  }

  // Integration Health Check
  async checkIntegrationHealth(integrationId: string): Promise<{
    integration_id: string;
    overall_health: 'healthy' | 'warning' | 'critical' | 'unknown';
    checks: Array<{
      check_name: string;
      status: 'pass' | 'fail' | 'warning';
      message: string;
      details?: any;
    }>;
    last_check: string;
    next_check: string;
  }> {
    const response = await apiClient.get(`${this.baseUrl}/${integrationId}/health`);
    return response.data;
  }

  // Integration Discovery
  async discoverIntegrations(
    networkRange?: string,
    credentials?: Record<string, any>
  ): Promise<{
    discovered_integrations: Array<{
      name: string;
      type: string;
      provider: string;
      version: string;
      capabilities: string[];
      confidence: number;
    }>;
    total_discovered: number;
    scan_duration: number;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/discover`, {
      network_range: networkRange,
      credentials
    });
    return response.data;
  }

  // Integration Validation
  async validateIntegrationConfiguration(
    integrationData: Partial<Integration>
  ): Promise<{
    is_valid: boolean;
    errors: string[];
    warnings: string[];
    suggestions: string[];
  }> {
    const response = await apiClient.post(`${this.baseUrl}/validate`, integrationData);
    return response.data;
  }

  // Integration Import/Export
  async exportIntegration(
    integrationId: string,
    format: 'json' | 'yaml' = 'json'
  ): Promise<{
    message: string;
    integration_data: any;
    format: string;
  }> {
    const response = await apiClient.get(`${this.baseUrl}/${integrationId}/export?format=${format}`);
    return response.data;
  }

  async importIntegration(
    integrationData: any,
    format: 'json' | 'yaml' = 'json',
    overwrite?: boolean
  ): Promise<{
    message: string;
    integration_id: string;
    status: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/import`, {
      integration_data: integrationData,
      format,
      overwrite
    });
    return response.data;
  }
}

export const integrationsService = new IntegrationsService();
