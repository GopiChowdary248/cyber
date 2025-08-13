import { apiClient } from '../utils/apiClient';

export interface Report {
  id: string;
  title: string;
  description: string;
  report_type: 'security' | 'compliance' | 'incident' | 'vulnerability' | 'threat' | 'audit' | 'performance' | 'custom';
  format: 'pdf' | 'html' | 'csv' | 'json' | 'xml';
  status: 'draft' | 'generating' | 'completed' | 'failed';
  generated_by: string;
  generated_at?: string;
  file_path?: string;
  file_size?: number;
  parameters: Record<string, any>;
  schedule?: ReportSchedule;
  recipients: string[];
  tags: string[];
  metadata: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface ReportSchedule {
  id: string;
  frequency: 'daily' | 'weekly' | 'monthly' | 'quarterly' | 'yearly' | 'custom';
  interval?: number;
  start_date: string;
  end_date?: string;
  time_zone: string;
  is_active: boolean;
  last_run?: string;
  next_run?: string;
}

export interface ReportTemplate {
  id: string;
  name: string;
  description: string;
  report_type: string;
  format: string;
  template_data: Record<string, any>;
  is_default: boolean;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface ReportParameter {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'date' | 'select' | 'multiselect';
  label: string;
  description: string;
  required: boolean;
  default_value?: any;
  options?: string[];
  validation_rules?: Record<string, any>;
}

export interface ReportExecution {
  id: string;
  report_id: string;
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
  started_at?: string;
  completed_at?: string;
  duration?: number;
  error_message?: string;
  output_file?: string;
  parameters_used: Record<string, any>;
  executed_by: string;
}

export interface ReportDistribution {
  id: string;
  report_id: string;
  distribution_type: 'email' | 'webhook' | 'file_share' | 'api';
  recipients: string[];
  schedule?: ReportSchedule;
  is_active: boolean;
  last_sent?: string;
  next_send?: string;
  created_at: string;
  updated_at: string;
}

class ReportsService {
  private baseUrl = '/api/v1/reports';

  // Report Management
  async getReports(
    reportType?: string,
    status?: string,
    format?: string,
    limit: number = 100
  ): Promise<Report[]> {
    const params = new URLSearchParams();
    if (reportType) params.append('report_type', reportType);
    if (status) params.append('status', status);
    if (format) params.append('format', format);
    if (limit) params.append('limit', limit.toString());

    const response = await apiClient.get(`${this.baseUrl}?${params}`);
    return response.data;
  }

  async getReport(reportId: string): Promise<Report> {
    const response = await apiClient.get(`${this.baseUrl}/${reportId}`);
    return response.data;
  }

  async createReport(reportData: Omit<Report, 'id' | 'created_at' | 'updated_at'>): Promise<{
    message: string;
    report_id: string;
  }> {
    const response = await apiClient.post(this.baseUrl, reportData);
    return response.data;
  }

  async updateReport(reportId: string, updateData: Partial<Report>): Promise<{
    message: string;
    report_id: string;
  }> {
    const response = await apiClient.put(`${this.baseUrl}/${reportId}`, updateData);
    return response.data;
  }

  async deleteReport(reportId: string): Promise<{
    message: string;
    report_id: string;
  }> {
    const response = await apiClient.delete(`${this.baseUrl}/${reportId}`);
    return response.data;
  }

  // Report Generation
  async generateReport(
    reportId: string,
    parameters?: Record<string, any>,
    format?: string
  ): Promise<{
    message: string;
    execution_id: string;
    status: string;
    estimated_duration?: number;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/${reportId}/generate`, {
      parameters,
      format
    });
    return response.data;
  }

  async generateReportByType(
    reportType: string,
    parameters: Record<string, any>,
    format: string = 'pdf',
    title?: string,
    description?: string
  ): Promise<{
    message: string;
    execution_id: string;
    report_id: string;
    status: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/generate-by-type`, {
      report_type: reportType,
      parameters,
      format,
      title,
      description
    });
    return response.data;
  }

  async getReportExecution(executionId: string): Promise<ReportExecution> {
    const response = await apiClient.get(`${this.baseUrl}/executions/${executionId}`);
    return response.data;
  }

  async cancelReportExecution(executionId: string): Promise<{
    message: string;
    execution_id: string;
    status: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/executions/${executionId}/cancel`);
    return response.data;
  }

  // Report Templates
  async getReportTemplates(reportType?: string): Promise<ReportTemplate[]> {
    const params = new URLSearchParams();
    if (reportType) params.append('report_type', reportType);

    const response = await apiClient.get(`${this.baseUrl}/templates?${params}`);
    return response.data;
  }

  async getReportTemplate(templateId: string): Promise<ReportTemplate> {
    const response = await apiClient.get(`${this.baseUrl}/templates/${templateId}`);
    return response.data;
  }

  async createReportTemplate(templateData: Omit<ReportTemplate, 'id' | 'created_at' | 'updated_at'>): Promise<{
    message: string;
    template_id: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/templates`, templateData);
    return response.data;
  }

  async updateReportTemplate(templateId: string, updateData: Partial<ReportTemplate>): Promise<{
    message: string;
    template_id: string;
  }> {
    const response = await apiClient.put(`${this.baseUrl}/templates/${templateId}`, updateData);
    return response.data;
  }

  async deleteReportTemplate(templateId: string): Promise<{
    message: string;
    template_id: string;
  }> {
    const response = await apiClient.delete(`${this.baseUrl}/templates/${templateId}`);
    return response.data;
  }

  // Report Scheduling
  async scheduleReport(
    reportId: string,
    scheduleData: Omit<ReportSchedule, 'id'>
  ): Promise<{
    message: string;
    schedule_id: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/${reportId}/schedule`, scheduleData);
    return response.data;
  }

  async updateReportSchedule(
    reportId: string,
    scheduleId: string,
    updateData: Partial<ReportSchedule>
  ): Promise<{
    message: string;
    schedule_id: string;
  }> {
    const response = await apiClient.put(`${this.baseUrl}/${reportId}/schedule/${scheduleId}`, updateData);
    return response.data;
  }

  async deleteReportSchedule(reportId: string, scheduleId: string): Promise<{
    message: string;
    schedule_id: string;
  }> {
    const response = await apiClient.delete(`${this.baseUrl}/${reportId}/schedule/${scheduleId}`);
    return response.data;
  }

  async getReportSchedules(reportId: string): Promise<ReportSchedule[]> {
    const response = await apiClient.get(`${this.baseUrl}/${reportId}/schedules`);
    return response.data;
  }

  // Report Distribution
  async getReportDistributions(reportId: string): Promise<ReportDistribution[]> {
    const response = await apiClient.get(`${this.baseUrl}/${reportId}/distributions`);
    return response.data;
  }

  async createReportDistribution(
    reportId: string,
    distributionData: Omit<ReportDistribution, 'id' | 'report_id' | 'created_at' | 'updated_at'>
  ): Promise<{
    message: string;
    distribution_id: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/${reportId}/distributions`, distributionData);
    return response.data;
  }

  async updateReportDistribution(
    reportId: string,
    distributionId: string,
    updateData: Partial<ReportDistribution>
  ): Promise<{
    message: string;
    distribution_id: string;
  }> {
    const response = await apiClient.put(`${this.baseUrl}/${reportId}/distributions/${distributionId}`, updateData);
    return response.data;
  }

  async deleteReportDistribution(reportId: string, distributionId: string): Promise<{
    message: string;
    distribution_id: string;
  }> {
    const response = await apiClient.delete(`${this.baseUrl}/${reportId}/distributions/${distributionId}`);
    return response.data;
  }

  // Report Parameters
  async getReportParameters(reportId: string): Promise<ReportParameter[]> {
    const response = await apiClient.get(`${this.baseUrl}/${reportId}/parameters`);
    return response.data;
  }

  async validateReportParameters(
    reportId: string,
    parameters: Record<string, any>
  ): Promise<{
    valid: boolean;
    errors: string[];
    warnings: string[];
  }> {
    const response = await apiClient.post(`${this.baseUrl}/${reportId}/validate-parameters`, {
      parameters
    });
    return response.data;
  }

  // Report Download and Access
  async downloadReport(reportId: string, format?: string): Promise<Blob> {
    const params = new URLSearchParams();
    if (format) params.append('format', format);

    const response = await apiClient.get(`${this.baseUrl}/${reportId}/download?${params}`, {
      responseType: 'blob'
    });
    return response.data;
  }

  async getReportPreview(reportId: string, parameters?: Record<string, any>): Promise<{
    preview_url: string;
    expires_at: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/${reportId}/preview`, {
      parameters
    });
    return response.data;
  }

  // Report Analytics
  async getReportUsageStats(
    startDate?: string,
    endDate?: string,
    reportType?: string
  ): Promise<{
    total_reports: number;
    total_executions: number;
    successful_executions: number;
    failed_executions: number;
    average_generation_time: number;
    popular_reports: Array<{
      report_id: string;
      title: string;
      execution_count: number;
    }>;
    format_distribution: Record<string, number>;
    user_activity: Array<{
      user_id: string;
      username: string;
      report_count: number;
    }>;
  }> {
    const params = new URLSearchParams();
    if (startDate) params.append('start_date', startDate);
    if (endDate) params.append('end_date', endDate);
    if (reportType) params.append('report_type', reportType);

    const response = await apiClient.get(`${this.baseUrl}/analytics/usage?${params}`);
    return response.data;
  }

  async getReportPerformanceMetrics(reportId: string): Promise<{
    report_id: string;
    total_executions: number;
    average_generation_time: number;
    success_rate: number;
    error_distribution: Record<string, number>;
    user_satisfaction_score?: number;
    last_30_days_trend: Array<{
      date: string;
      execution_count: number;
      success_count: number;
      average_time: number;
    }>;
  }> {
    const response = await apiClient.get(`${this.baseUrl}/${reportId}/performance`);
    return response.data;
  }

  // Bulk Operations
  async bulkGenerateReports(
    reportIds: string[],
    parameters?: Record<string, any>,
    format?: string
  ): Promise<{
    message: string;
    total_reports: number;
    queued_count: number;
    failed_count: number;
    failed_reports: string[];
  }> {
    const response = await apiClient.post(`${this.baseUrl}/bulk-generate`, {
      report_ids: reportIds,
      parameters,
      format
    });
    return response.data;
  }

  async bulkDeleteReports(reportIds: string[]): Promise<{
    message: string;
    deleted_count: number;
    failed_count: number;
    failed_reports: string[];
  }> {
    const response = await apiClient.post(`${this.baseUrl}/bulk-delete`, {
      report_ids: reportIds
    });
    return response.data;
  }

  // Report Export/Import
  async exportReportConfiguration(reportId: string): Promise<{
    message: string;
    config_file: string;
    download_url: string;
  }> {
    const response = await apiClient.get(`${this.baseUrl}/${reportId}/export-config`);
    return response.data;
  }

  async importReportConfiguration(
    configFile: File,
    overwrite?: boolean
  ): Promise<{
    message: string;
    imported_reports: number;
    imported_templates: number;
    errors: string[];
  }> {
    const formData = new FormData();
    formData.append('config_file', configFile);
    if (overwrite !== undefined) formData.append('overwrite', overwrite.toString());

    const response = await apiClient.post(`${this.baseUrl}/import-config`, formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  }
}

export const reportsService = new ReportsService();
export default reportsService;
