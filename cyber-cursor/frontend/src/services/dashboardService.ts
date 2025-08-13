import { apiClient } from '../utils/apiClient';

// Enums matching backend schemas
export enum DashboardType {
  OVERVIEW = "overview",
  SECURITY = "security",
  COMPLIANCE = "compliance",
  PERFORMANCE = "performance",
  CUSTOM = "custom"
}

export enum WidgetType {
  CHART = "chart",
  METRIC = "metric",
  TABLE = "table",
  STATUS = "status",
  ALERT = "alert",
  TIMELINE = "timeline"
}

export enum ChartType {
  LINE = "line",
  BAR = "bar",
  PIE = "pie",
  DONUT = "donut",
  AREA = "area",
  SCATTER = "scatter",
  GAUGE = "gauge"
}

// Base interfaces matching backend schemas
export interface DashboardBase {
  name: string;
  description?: string;
  dashboard_type: DashboardType;
  is_public: boolean;
  refresh_interval: number; // seconds
  layout_config?: Record<string, any>;
  theme?: string;
}

export interface DashboardCreate extends DashboardBase {
  widgets?: DashboardWidgetCreate[];
}

export interface DashboardUpdate {
  name?: string;
  description?: string;
  dashboard_type?: DashboardType;
  is_public?: boolean;
  refresh_interval?: number;
  layout_config?: Record<string, any>;
  theme?: string;
}

export interface DashboardWidgetBase {
  name: string;
  widget_type: WidgetType;
  chart_type?: ChartType;
  data_source: string;
  query?: string;
  refresh_interval?: number;
  position: {
    x: number;
    y: number;
    width: number;
    height: number;
  };
  config?: Record<string, any>;
}

export interface DashboardWidgetCreate extends DashboardWidgetBase {
  dashboard_id: string;
}

export interface DashboardWidgetUpdate {
  name?: string;
  widget_type?: WidgetType;
  chart_type?: ChartType;
  data_source?: string;
  query?: string;
  refresh_interval?: number;
  position?: {
    x: number;
    y: number;
    width: number;
    height: number;
  };
  config?: Record<string, any>;
}

export interface DashboardWidget extends DashboardWidgetBase {
  id: string;
  dashboard_id: string;
  created_at: string;
  updated_at: string;
  last_refresh?: string;
  data?: any;
  error?: string;
}

export interface Dashboard extends DashboardBase {
  id: string;
  created_by: number;
  created_at: string;
  updated_at: string;
  widgets: DashboardWidget[];
  permissions?: DashboardPermissions;
}

export interface DashboardPermissions {
  can_view: boolean;
  can_edit: boolean;
  can_delete: boolean;
  can_share: boolean;
  shared_with: string[];
}

export interface DashboardData {
  dashboard: Dashboard;
  data: Record<string, any>;
  last_updated: string;
  refresh_status: 'success' | 'error' | 'pending';
}

export interface DashboardOverview {
  total_dashboards: number;
  public_dashboards: number;
  private_dashboards: number;
  active_widgets: number;
  total_views: number;
  recent_activity: DashboardActivity[];
}

export interface DashboardActivity {
  id: string;
  dashboard_id: string;
  dashboard_name: string;
  action: 'created' | 'updated' | 'viewed' | 'shared' | 'deleted';
  user_id: number;
  user_name: string;
  timestamp: string;
  details?: Record<string, any>;
}

export interface DashboardMetrics {
  total_dashboards: number;
  dashboards_by_type: Record<DashboardType, number>;
  widgets_by_type: Record<WidgetType, number>;
  average_widgets_per_dashboard: number;
  most_viewed_dashboards: Array<{
    id: string;
    name: string;
    views: number;
  }>;
  recent_creations: Array<{
    id: string;
    name: string;
    created_at: string;
  }>;
}

export interface DashboardFilter {
  dashboard_type?: DashboardType;
  is_public?: boolean;
  created_by?: number;
  search?: string;
  tags?: string[];
}

export interface DashboardResponse {
  dashboards: Dashboard[];
  total: number;
  skip: number;
  limit: number;
}

export interface WidgetDataResponse {
  widget_id: string;
  data: any;
  last_updated: string;
  next_refresh?: string;
  error?: string;
}

export interface DashboardExportOptions {
  format: 'json' | 'pdf' | 'html';
  include_data: boolean;
  include_layout: boolean;
  include_permissions: boolean;
}

class DashboardService {
  private baseUrl = '/dashboard';

  // Dashboard Management
  async getDashboards(
    skip: number = 0,
    limit: number = 100,
    filter?: DashboardFilter
  ): Promise<DashboardResponse> {
    const params: any = { skip, limit };
    if (filter) {
      Object.assign(params, filter);
    }

    const response = await apiClient.get(this.baseUrl, { params });
    return response.data;
  }

  async getDashboard(dashboardId: string): Promise<Dashboard> {
    const response = await apiClient.get(`${this.baseUrl}/${dashboardId}`);
    return response.data;
  }

  async createDashboard(dashboardData: DashboardCreate): Promise<Dashboard> {
    const response = await apiClient.post(this.baseUrl, dashboardData);
    return response.data;
  }

  async updateDashboard(
    dashboardId: string,
    updateData: DashboardUpdate
  ): Promise<Dashboard> {
    const response = await apiClient.put(`${this.baseUrl}/${dashboardId}`, updateData);
    return response.data;
  }

  async deleteDashboard(dashboardId: string): Promise<{ message: string }> {
    const response = await apiClient.delete(`${this.baseUrl}/${dashboardId}`);
    return response.data;
  }

  async duplicateDashboard(
    dashboardId: string,
    newName: string
  ): Promise<Dashboard> {
    const response = await apiClient.post(`${this.baseUrl}/${dashboardId}/duplicate`, {
      name: newName
    });
    return response.data;
  }

  // Widget Management
  async getDashboardWidgets(dashboardId: string): Promise<DashboardWidget[]> {
    const response = await apiClient.get(`${this.baseUrl}/${dashboardId}/widgets`);
    return response.data;
  }

  async getDashboardWidget(
    dashboardId: string,
    widgetId: string
  ): Promise<DashboardWidget> {
    const response = await apiClient.get(`${this.baseUrl}/${dashboardId}/widgets/${widgetId}`);
    return response.data;
  }

  async createDashboardWidget(
    dashboardId: string,
    widgetData: DashboardWidgetCreate
  ): Promise<DashboardWidget> {
    const response = await apiClient.post(`${this.baseUrl}/${dashboardId}/widgets`, widgetData);
    return response.data;
  }

  async updateDashboardWidget(
    dashboardId: string,
    widgetId: string,
    updateData: DashboardWidgetUpdate
  ): Promise<DashboardWidget> {
    const response = await apiClient.put(
      `${this.baseUrl}/${dashboardId}/widgets/${widgetId}`,
      updateData
    );
    return response.data;
  }

  async deleteDashboardWidget(
    dashboardId: string,
    widgetId: string
  ): Promise<{ message: string }> {
    const response = await apiClient.delete(`${this.baseUrl}/${dashboardId}/widgets/${widgetId}`);
    return response.data;
  }

  async refreshWidget(
    dashboardId: string,
    widgetId: string
  ): Promise<WidgetDataResponse> {
    const response = await apiClient.post(`${this.baseUrl}/${dashboardId}/widgets/${widgetId}/refresh`);
    return response.data;
  }

  // Dashboard Data
  async getDashboardData(dashboardId: string): Promise<DashboardData> {
    const response = await apiClient.get(`${this.baseUrl}/${dashboardId}/data`);
    return response.data;
  }

  async getWidgetData(
    dashboardId: string,
    widgetId: string
  ): Promise<WidgetDataResponse> {
    const response = await apiClient.get(`${this.baseUrl}/${dashboardId}/widgets/${widgetId}/data`);
    return response.data;
  }

  // Overview and Metrics
  async getDashboardOverview(): Promise<DashboardOverview> {
    const response = await apiClient.get(`${this.baseUrl}/overview`);
    return response.data;
  }

  async getDashboardMetrics(): Promise<DashboardMetrics> {
    const response = await apiClient.get(`${this.baseUrl}/metrics`);
    return response.data;
  }

  // Dashboard Sharing and Permissions
  async shareDashboard(
    dashboardId: string,
    userEmails: string[],
    permissions: Partial<DashboardPermissions>
  ): Promise<{ message: string; shared_with: string[] }> {
    const response = await apiClient.post(`${this.baseUrl}/${dashboardId}/share`, {
      user_emails: userEmails,
      permissions
    });
    return response.data;
  }

  async updateDashboardPermissions(
    dashboardId: string,
    permissions: Partial<DashboardPermissions>
  ): Promise<DashboardPermissions> {
    const response = await apiClient.put(`${this.baseUrl}/${dashboardId}/permissions`, permissions);
    return response.data;
  }

  async getDashboardPermissions(dashboardId: string): Promise<DashboardPermissions> {
    const response = await apiClient.get(`${this.baseUrl}/${dashboardId}/permissions`);
    return response.data;
  }

  // Dashboard Templates
  async getDashboardTemplates(): Promise<Dashboard[]> {
    const response = await apiClient.get(`${this.baseUrl}/templates`);
    return response.data;
  }

  async createDashboardFromTemplate(
    templateId: string,
    name: string,
    description?: string
  ): Promise<Dashboard> {
    const response = await apiClient.post(`${this.baseUrl}/templates/${templateId}/create`, {
      name,
      description
    });
    return response.data;
  }

  // Export and Import
  async exportDashboard(
    dashboardId: string,
    options: DashboardExportOptions
  ): Promise<Blob> {
    const response = await apiClient.post(`${this.baseUrl}/${dashboardId}/export`, options, {
      responseType: 'blob'
    });
    return response.data;
  }

  async importDashboard(
    dashboardData: File,
    options?: {
      overwrite?: boolean;
      import_permissions?: boolean;
    }
  ): Promise<{ message: string; dashboard_id: string }> {
    const formData = new FormData();
    formData.append('dashboard_file', dashboardData);
    if (options) {
      Object.entries(options).forEach(([key, value]) => {
        formData.append(key, value.toString());
      });
    }

    const response = await apiClient.post(`${this.baseUrl}/import`, formData, {
      headers: {
        'Content-Type': 'multipart/form-data'
      }
    });
    return response.data;
  }

  // Real-time Updates
  async subscribeToDashboardUpdates(
    dashboardId: string,
    callback: (data: DashboardData) => void
  ): Promise<void> {
    // This could be implemented with WebSocket connection
    // For now, we'll use polling
    setInterval(async () => {
      try {
        const data = await this.getDashboardData(dashboardId);
        callback(data);
      } catch (error) {
        console.error('Failed to poll dashboard updates:', error);
      }
    }, 30000); // Poll every 30 seconds
  }

  // Dashboard Analytics
  async getDashboardAnalytics(
    dashboardId: string,
    timeRange: string = '24h'
  ): Promise<{
    views: number;
    unique_viewers: number;
    average_view_time: number;
    popular_widgets: Array<{
      widget_id: string;
      widget_name: string;
      views: number;
    }>;
    viewer_activity: Array<{
      timestamp: string;
      views: number;
    }>;
  }> {
    const response = await apiClient.get(`${this.baseUrl}/${dashboardId}/analytics`, {
      params: { time_range: timeRange }
    });
    return response.data;
  }

  // Bulk Operations
  async bulkUpdateDashboards(
    dashboardIds: string[],
    updates: DashboardUpdate
  ): Promise<{ message: string; updated_count: number }> {
    const response = await apiClient.put(`${this.baseUrl}/bulk-update`, {
      dashboard_ids: dashboardIds,
      updates
    });
    return response.data;
  }

  async bulkDeleteDashboards(
    dashboardIds: string[]
  ): Promise<{ message: string; deleted_count: number }> {
    const response = await apiClient.delete(`${this.baseUrl}/bulk-delete`, {
      data: { dashboard_ids: dashboardIds }
    });
    return response.data;
  }

  // Dashboard Health Check
  async getDashboardHealth(dashboardId: string): Promise<{
    status: 'healthy' | 'warning' | 'error';
    issues: Array<{
      type: 'widget_error' | 'data_source_error' | 'permission_error' | 'performance_issue';
      severity: 'low' | 'medium' | 'high' | 'critical';
      message: string;
      widget_id?: string;
    }>;
    last_check: string;
    next_check: string;
  }> {
    const response = await apiClient.get(`${this.baseUrl}/${dashboardId}/health`);
    return response.data;
  }

  // Helper Methods
  async getPublicDashboards(): Promise<Dashboard[]> {
    const response = await this.getDashboards(0, 100, { is_public: true });
    return response.dashboards;
  }

  async getUserDashboards(userId?: number): Promise<Dashboard[]> {
    const filter: DashboardFilter = {};
    if (userId) filter.created_by = userId;
    
    const response = await this.getDashboards(0, 100, filter);
    return response.dashboards;
  }

  async searchDashboards(query: string): Promise<Dashboard[]> {
    const response = await this.getDashboards(0, 100, { search: query });
    return response.dashboards;
  }

  async getDashboardByType(dashboardType: DashboardType): Promise<Dashboard[]> {
    const response = await this.getDashboards(0, 100, { dashboard_type: dashboardType });
    return response.dashboards;
  }

  // Widget Configuration Helpers
  async getAvailableDataSources(): Promise<Array<{
    id: string;
    name: string;
    type: string;
    description: string;
    supported_widgets: WidgetType[];
  }>> {
    const response = await apiClient.get(`${this.baseUrl}/data-sources`);
    return response.data;
  }

  async getWidgetConfigurationSchema(widgetType: WidgetType): Promise<{
    properties: Record<string, any>;
    required: string[];
    default_values: Record<string, any>;
  }> {
    const response = await apiClient.get(`${this.baseUrl}/widgets/${widgetType}/schema`);
    return response.data;
  }

  // Dashboard Performance
  async optimizeDashboard(dashboardId: string): Promise<{
    message: string;
    optimizations: Array<{
      type: string;
      description: string;
      impact: 'low' | 'medium' | 'high';
    }>;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/${dashboardId}/optimize`);
    return response.data;
  }
}

export const dashboardService = new DashboardService();
export default dashboardService;
