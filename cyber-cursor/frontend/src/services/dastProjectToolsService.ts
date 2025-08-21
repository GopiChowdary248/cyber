// DAST Project Tools Service
// Handles all API calls to the DAST backend endpoints

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'http://localhost:8000';

// ============================================================================
// INTERFACES & TYPES
// ============================================================================

export interface HttpHistoryEntry {
  id: string;
  method: string;
  url: string;
  host: string;
  port: number;
  protocol: string;
  status_code?: number;
  content_type?: string;
  request_size: number;
  response_size: number;
  duration: number;
  timestamp: string;
  tags: string[];
  highlighted: boolean;
  notes?: string;
}

export interface HttpHistoryResponse {
  entries: HttpHistoryEntry[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface PaginationParams {
  page: number;
  page_size: number;
}

export interface ScanProfile {
  id: string;
  name: string;
  description?: string;
  modules: string[];
  settings: Record<string, any>;
  is_default: boolean;
  created_at: string;
}

export interface ScanCreate {
  profile_id: string;
  name: string;
  target_urls: string[];
  scan_config?: Record<string, any>;
}

export interface ScanResponse {
  id: string;
  project_id: string;
  profile_id: string;
  name: string;
  target_urls: string[];
  status: 'pending' | 'running' | 'completed' | 'failed' | 'paused';
  progress: number;
  total_requests: number;
  completed_requests: number;
  issues_found: number;
  scan_config: Record<string, any>;
  started_at?: string;
  completed_at?: string;
  created_at: string;
}

export interface ScanIssue {
  id: string;
  scan_id: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  url: string;
  evidence?: string;
  confidence: number;
  cwe_id?: string;
  cvss_score?: number;
  status: 'open' | 'confirmed' | 'false_positive' | 'fixed';
  tags: string[];
  discovered_at: string;
}

export interface CrawlConfig {
  start_urls: string[];
  max_depth: number;
  max_pages: number;
  follow_redirects: boolean;
  verify_ssl: boolean;
  user_agent?: string;
  delay: number;
  include_patterns?: string[];
  exclude_patterns?: string[];
  custom_headers?: Record<string, string>;
}

export interface CrawlResult {
  id: string;
  url: string;
  method: string;
  status_code?: number;
  content_type?: string;
  title?: string;
  depth: number;
  parent_url?: string;
  in_scope: boolean;
  tags: string[];
  discovered_at: string;
}

export interface CrawlerStatus {
  status: 'idle' | 'running' | 'paused' | 'completed' | 'failed';
  progress: number;
  total_urls: number;
  discovered_urls: number;
  in_scope_urls: number;
  started_at?: string;
  estimated_completion?: string;
  current_url?: string;
  errors: string[];
}

export interface MatchReplaceRule {
  id: string;
  name: string;
  description?: string;
  match_pattern: string;
  replace_pattern: string;
  match_type: 'regex' | 'string' | 'wildcard';
  apply_to: 'request' | 'response' | 'both';
  enabled: boolean;
  priority: number;
  created_at: string;
}

export interface IntruderAttack {
  id: string;
  name: string;
  target_url: string;
  attack_type: 'sniper' | 'battering_ram' | 'pitchfork' | 'cluster_bomb';
  payload_sets: any[];
  positions: any[];
  status: 'pending' | 'running' | 'completed' | 'failed' | 'paused';
  progress: number;
  total_requests: number;
  completed_requests: number;
  successful_requests: number;
  failed_requests: number;
  started_at?: string;
  completed_at?: string;
}

export interface RepeaterRequest {
  id: string;
  name: string;
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
  params: Record<string, any>;
  created_at: string;
}

export interface ProxyConfig {
  host: string;
  port: number;
  ssl_cert?: string;
  ssl_key?: string;
  intercept_requests: boolean;
  intercept_responses: boolean;
  auto_save: boolean;
  max_history: number;
}

export interface ProxyStatus {
  status: 'stopped' | 'running' | 'error';
  host: string;
  port: number;
  ssl_enabled: boolean;
  intercept_requests: boolean;
  intercept_responses: boolean;
  total_requests: number;
  total_responses: number;
  started_at?: string;
  uptime?: number;
  error?: string;
}

export interface SiteMapNode {
  url: string;
  method: string;
  status_code?: number;
  content_type?: string;
  title?: string;
  depth: number;
  in_scope: boolean;
  children: SiteMapNode[];
  tags: string[];
  notes?: string;
}

export interface SiteMapResponse {
  nodes: SiteMapNode[];
  total_nodes: number;
  in_scope_nodes: number;
  out_of_scope_nodes: number;
  view_mode: string;
}

export interface ScopeConfig {
  include_patterns: string[];
  exclude_patterns: string[];
  allowed_ports: number[];
  allowed_protocols: string[];
  file_extensions: string[];
  max_depth: number;
  follow_subdomains: boolean;
  follow_external_links: boolean;
}

export interface ProjectStatus {
  project_id: string;
  total_scans: number;
  active_scans: number;
  completed_scans: number;
  total_issues: number;
  issues_by_severity: Record<string, number>;
  last_scan_date?: string;
  proxy_status: string;
  crawler_status: string;
}

// ============================================================================
// MAIN SERVICE CLASS
// ============================================================================

class DASTProjectToolsService {
  private async makeRequest<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${API_BASE_URL}${endpoint}`;
    
    const defaultOptions: RequestInit = {
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
      ...options,
    };

    try {
      const response = await fetch(url, defaultOptions);
      
      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`HTTP error! status: ${response.status}, message: ${errorText}`);
      }

      return await response.json();
    } catch (error) {
      console.error(`API request failed for ${endpoint}:`, error);
      throw error;
    }
  }

  // ============================================================================
  // PROJECT MANAGEMENT
  // ============================================================================

  async getProjectStatus(projectId: string): Promise<ProjectStatus> {
    return this.makeRequest<ProjectStatus>(`/api/v1/dast/projects/${projectId}/status`);
  }

  // ============================================================================
  // HTTP HISTORY & TRAFFIC ANALYSIS
  // ============================================================================

  async getHttpHistory(
    projectId: string,
    params: PaginationParams & {
      method?: string;
      status?: number;
      host?: string;
      url_regex?: string;
      start_time?: string;
      end_time?: string;
    }
  ): Promise<HttpHistoryResponse> {
    const queryParams = new URLSearchParams({
      page: params.page.toString(),
      page_size: params.page_size.toString(),
    });

    if (params.method) queryParams.append('method', params.method);
    if (params.status) queryParams.append('status', params.status.toString());
    if (params.host) queryParams.append('host', params.host);
    if (params.url_regex) queryParams.append('url_regex', params.url_regex);
    if (params.start_time) queryParams.append('start_time', params.start_time);
    if (params.end_time) queryParams.append('end_time', params.end_time);

    return this.makeRequest<HttpHistoryResponse>(
      `/api/v1/dast/projects/${projectId}/http-history?${queryParams}`
    );
  }

  async getHttpEntryDetail(projectId: string, entryId: string): Promise<HttpHistoryEntry> {
    return this.makeRequest<HttpHistoryEntry>(
      `/api/v1/dast/projects/${projectId}/http-history/${entryId}`
    );
  }

  async exportHttpHistory(
    projectId: string,
    format: 'json' | 'csv' | 'xml' = 'json',
    filters?: Record<string, any>
  ): Promise<any> {
    return this.makeRequest(`/api/v1/dast/projects/${projectId}/http-history/export`, {
      method: 'POST',
      body: JSON.stringify({ format, filters }),
    });
  }

  // ============================================================================
  // SCANNER & VULNERABILITY SCANNING
  // ============================================================================

  async getScanProfiles(projectId: string): Promise<ScanProfile[]> {
    return this.makeRequest<ScanProfile[]>(`/api/v1/dast/projects/${projectId}/scanner/profiles`);
  }

  async createScanProfile(projectId: string, profile: Omit<ScanProfile, 'id' | 'created_at'>): Promise<ScanProfile> {
    return this.makeRequest<ScanProfile>(`/api/v1/dast/projects/${projectId}/scanner/profiles`, {
      method: 'POST',
      body: JSON.stringify(profile),
    });
  }

  async updateScanProfile(projectId: string, profileId: string, profile: Partial<ScanProfile>): Promise<ScanProfile> {
    return this.makeRequest<ScanProfile>(`/api/v1/dast/projects/${projectId}/scanner/profiles/${profileId}`, {
      method: 'PUT',
      body: JSON.stringify(profile),
    });
  }

  async deleteScanProfile(projectId: string, profileId: string): Promise<any> {
    return this.makeRequest(`/api/v1/dast/projects/${projectId}/scanner/profiles/${profileId}`, {
      method: 'DELETE',
    });
  }

  async getActiveScans(projectId: string, status?: string): Promise<ScanResponse[]> {
    const endpoint = status 
      ? `/api/v1/dast/projects/${projectId}/scanner/scans?status=${status}`
      : `/api/v1/dast/projects/${projectId}/scanner/scans`;
    
    return this.makeRequest<ScanResponse[]>(endpoint);
  }

  async createScan(projectId: string, scan: ScanCreate): Promise<ScanResponse> {
    return this.makeRequest<ScanResponse>(`/api/v1/dast/projects/${projectId}/scanner/scans`, {
      method: 'POST',
      body: JSON.stringify(scan),
    });
  }

  async getScanDetails(projectId: string, scanId: string): Promise<ScanResponse> {
    return this.makeRequest<ScanResponse>(`/api/v1/dast/projects/${projectId}/scanner/scans/${scanId}`);
  }

  async startScan(projectId: string, scanId: string): Promise<any> {
    return this.makeRequest(`/api/v1/dast/projects/${projectId}/scanner/scans/${scanId}/start`, {
      method: 'POST',
    });
  }

  async stopScan(projectId: string, scanId: string): Promise<any> {
    return this.makeRequest(`/api/v1/dast/projects/${projectId}/scanner/scans/${scanId}/stop`, {
      method: 'POST',
    });
  }

  async deleteScan(projectId: string, scanId: string): Promise<any> {
    return this.makeRequest(`/api/v1/dast/projects/${projectId}/scanner/scans/${scanId}`, {
      method: 'DELETE',
    });
  }

  async getScanIssues(
    projectId: string,
    params: PaginationParams & {
      scan_id?: string;
      severity?: string;
      status?: string;
    }
  ): Promise<{ issues: ScanIssue[]; total: number; page: number; page_size: number }> {
    const queryParams = new URLSearchParams({
      page: params.page.toString(),
      page_size: params.page_size.toString(),
    });

    if (params.scan_id) queryParams.append('scan_id', params.scan_id);
    if (params.severity) queryParams.append('severity', params.severity);
    if (params.status) queryParams.append('status', params.status);

    return this.makeRequest(`/api/v1/dast/projects/${projectId}/scanner/issues?${queryParams}`);
  }

  async updateIssueStatus(projectId: string, issueId: string, statusUpdate: Record<string, string>): Promise<ScanIssue> {
    return this.makeRequest<ScanIssue>(`/api/v1/dast/projects/${projectId}/scanner/issues/${issueId}`, {
      method: 'PATCH',
      body: JSON.stringify(statusUpdate),
    });
  }

  // ============================================================================
  // CRAWLER & SITE MAPPING
  // ============================================================================

  async startCrawler(projectId: string, crawlConfig: CrawlConfig): Promise<any> {
    return this.makeRequest(`/api/v1/dast/projects/${projectId}/crawler/start`, {
      method: 'POST',
      body: JSON.stringify(crawlConfig),
    });
  }

  async stopCrawler(projectId: string): Promise<any> {
    return this.makeRequest(`/api/v1/dast/projects/${projectId}/crawler/stop`, {
      method: 'POST',
    });
  }

  async getCrawlerStatus(projectId: string): Promise<CrawlerStatus> {
    return this.makeRequest<CrawlerStatus>(`/api/v1/dast/projects/${projectId}/crawler/status`);
  }

  async getCrawlResults(
    projectId: string,
    params: PaginationParams
  ): Promise<{ results: CrawlResult[]; total: number; page: number; page_size: number }> {
    const queryParams = new URLSearchParams({
      page: params.page.toString(),
      page_size: params.page_size.toString(),
    });

    return this.makeRequest(`/api/v1/dast/projects/${projectId}/crawler/results?${queryParams}`);
  }

  // ============================================================================
  // TARGET & SCOPE MANAGEMENT
  // ============================================================================

  async getSiteMap(projectId: string, viewMode: string = 'tree'): Promise<SiteMapResponse> {
    return this.makeRequest<SiteMapResponse>(`/api/v1/dast/projects/${projectId}/target/sitemap?view_mode=${viewMode}`);
  }

  async updateScope(projectId: string, scopeConfig: ScopeConfig): Promise<any> {
    return this.makeRequest(`/api/v1/dast/projects/${projectId}/target/scope`, {
      method: 'PUT',
      body: JSON.stringify(scopeConfig),
    });
  }

  // ============================================================================
  // INTRUDER TOOL
  // ============================================================================

  async startIntruderAttack(projectId: string, attack: Omit<IntruderAttack, 'id' | 'status' | 'progress' | 'created_at'>): Promise<IntruderAttack> {
    return this.makeRequest<IntruderAttack>(`/api/v1/dast/projects/${projectId}/intruder/start`, {
      method: 'POST',
      body: JSON.stringify(attack),
    });
  }

  async stopIntruderAttack(projectId: string, attackId: string): Promise<any> {
    return this.makeRequest(`/api/v1/dast/projects/${projectId}/intruder/${attackId}/stop`, {
      method: 'POST',
    });
  }

  async getIntruderResults(projectId: string, attackId: string): Promise<any[]> {
    return this.makeRequest<any[]>(`/api/v1/dast/projects/${projectId}/intruder/${attackId}/results`);
  }

  // ============================================================================
  // REPEATER TOOL
  // ============================================================================

  async sendRepeaterRequest(projectId: string, request: Omit<RepeaterRequest, 'id' | 'created_at'>): Promise<any> {
    return this.makeRequest(`/api/v1/dast/projects/${projectId}/repeater/send`, {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async getRepeaterHistory(
    projectId: string,
    params: PaginationParams
  ): Promise<{ requests: RepeaterRequest[]; total: number; page: number; page_size: number }> {
    const queryParams = new URLSearchParams({
      page: params.page.toString(),
      page_size: params.page_size.toString(),
    });

    return this.makeRequest(`/api/v1/dast/projects/${projectId}/repeater/history?${queryParams}`);
  }

  // ============================================================================
  // MATCH & REPLACE RULES
  // ============================================================================

  async getMatchReplaceRules(projectId: string): Promise<MatchReplaceRule[]> {
    return this.makeRequest<MatchReplaceRule[]>(`/api/v1/dast/projects/${projectId}/rules`);
  }

  async createMatchReplaceRule(projectId: string, rule: Omit<MatchReplaceRule, 'id' | 'created_at'>): Promise<MatchReplaceRule> {
    return this.makeRequest<MatchReplaceRule>(`/api/v1/dast/projects/${projectId}/rules`, {
      method: 'POST',
      body: JSON.stringify(rule),
    });
  }

  async updateMatchReplaceRule(projectId: string, ruleId: string, rule: Partial<MatchReplaceRule>): Promise<MatchReplaceRule> {
    return this.makeRequest<MatchReplaceRule>(`/api/v1/dast/projects/${projectId}/rules/${ruleId}`, {
      method: 'PUT',
      body: JSON.stringify(rule),
    });
  }

  async deleteMatchReplaceRule(projectId: string, ruleId: string): Promise<any> {
    return this.makeRequest(`/api/v1/dast/projects/${projectId}/rules/${ruleId}`, {
      method: 'DELETE',
    });
  }

  // ============================================================================
  // PROXY ENGINE
  // ============================================================================

  async getProxyStatus(projectId: string): Promise<ProxyStatus> {
    return this.makeRequest<ProxyStatus>(`/api/v1/dast/projects/${projectId}/proxy/status`);
  }

  async startProxy(projectId: string, config: ProxyConfig): Promise<any> {
    return this.makeRequest(`/api/v1/dast/projects/${projectId}/proxy/start`, {
      method: 'POST',
      body: JSON.stringify(config),
    });
  }

  async stopProxy(projectId: string): Promise<any> {
    return this.makeRequest(`/api/v1/dast/projects/${projectId}/proxy/stop`, {
      method: 'POST',
    });
  }

  // ============================================================================
  // EXPORT & REPORTING
  // ============================================================================

  async exportScanResults(
    projectId: string,
    scanId: string,
    format: 'json' | 'csv' | 'xml' | 'pdf' = 'json'
  ): Promise<any> {
    return this.makeRequest(`/api/v1/dast/projects/${projectId}/export/scan-results`, {
      method: 'POST',
      body: JSON.stringify({ scan_id: scanId, format }),
    });
  }

  async exportProjectReport(
    projectId: string,
    format: 'pdf' | 'html' | 'docx' = 'pdf',
    includeIssues: boolean = true,
    includeTraffic: boolean = false
  ): Promise<any> {
    return this.makeRequest(`/api/v1/dast/projects/${projectId}/export/project-report`, {
      method: 'POST',
      body: JSON.stringify({ format, include_issues: includeIssues, include_traffic: includeTraffic }),
    });
  }

  async exportCrawlResults(
    projectId: string,
    format: 'json' | 'csv' | 'xml' = 'json'
  ): Promise<any> {
    return this.makeRequest(`/api/v1/dast/projects/${projectId}/crawler/results/export`, {
      method: 'POST',
      body: JSON.stringify({ format }),
    });
  }

  // ============================================================================
  // WEBSOCKET CONNECTION
  // ============================================================================

  createWebSocketConnection(projectId: string, token: string): WebSocket {
    const wsUrl = `${API_BASE_URL.replace('http', 'ws')}/api/v1/dast/projects/${projectId}/ws?token=${token}`;
    return new WebSocket(wsUrl);
  }

  // ============================================================================
  // LEGACY METHODS (for backward compatibility)
  // ============================================================================

  // Scanner (legacy)
  async startScannerLegacy(projectId: string, targetUrls: string[], config: any): Promise<any> {
    const scanData: ScanCreate = {
      profile_id: config.profile_id || 'default',
      name: `Scan ${new Date().toISOString()}`,
      target_urls: targetUrls,
      scan_config: config,
    };
    return this.createScan(projectId, scanData);
  }

  async stopScannerLegacy(projectId: string): Promise<any> {
    // Get active scans and stop them
    const activeScans = await this.getActiveScans(projectId);
    const stopPromises = activeScans
      .filter(scan => scan.status === 'running')
      .map(scan => this.stopScan(projectId, scan.id));
    
    return Promise.all(stopPromises);
  }

  async getScannerStatusLegacy(projectId: string, scanId?: string): Promise<any> {
    if (scanId) {
      return this.getScanDetails(projectId, scanId);
    }
    
    const activeScans = await this.getActiveScans(projectId);
    return activeScans.find(scan => scan.status === 'running') || null;
  }

  async getAllScannerIssuesLegacy(projectId: string): Promise<any> {
    return this.getScanIssues(projectId, { page: 1, page_size: 1000 });
  }

  // Crawler (legacy)
  async startCrawlerLegacy(projectId: string, config: any): Promise<any> {
    return this.startCrawler(projectId, config);
  }

  async stopCrawlerLegacy(projectId: string): Promise<any> {
    return this.stopCrawler(projectId);
  }

  async getCrawlerStatusLegacy(projectId: string): Promise<any> {
    return this.getCrawlerStatus(projectId);
  }

  async getCrawlResultsLegacy(projectId: string): Promise<any> {
    return this.getCrawlResults(projectId, { page: 1, page_size: 1000 });
  }

  // Rules (legacy)
  async getMatchReplaceRulesLegacy(projectId: string): Promise<any> {
    return this.getMatchReplaceRules(projectId);
  }

  async createMatchReplaceRuleLegacy(projectId: string, rule: any): Promise<any> {
    return this.createMatchReplaceRule(projectId, rule);
  }

  async updateMatchReplaceRuleLegacy(projectId: string, ruleId: string, rule: any): Promise<any> {
    return this.updateMatchReplaceRule(projectId, ruleId, rule);
  }

  async deleteMatchReplaceRuleLegacy(projectId: string, ruleId: string): Promise<any> {
    return this.deleteMatchReplaceRule(projectId, ruleId);
  }

  // Proxy (legacy)
  async getProxyStatusLegacy(projectId: string): Promise<any> {
    return this.getProxyStatus(projectId);
  }

  async startProxyLegacy(projectId: string, config: any): Promise<any> {
    return this.startProxy(projectId, config);
  }

  async stopProxyLegacy(projectId: string): Promise<any> {
    return this.stopProxy(projectId);
  }

  // Repeater (legacy)
  async sendRepeaterRequestLegacy(projectId: string, request: any): Promise<any> {
    return this.sendRepeaterRequest(projectId, request);
  }

  // Intruder (legacy)
  async startIntruderAttackLegacy(projectId: string, attack: any): Promise<any> {
    return this.startIntruderAttack(projectId, attack);
  }

  async stopIntruderAttackLegacy(projectId: string, attackId: string): Promise<any> {
    return this.stopIntruderAttack(projectId, attackId);
  }

  async getIntruderResultsLegacy(projectId: string, attackId: string): Promise<any> {
    return this.getIntruderResults(projectId, attackId);
  }

  // Target/Site Map (legacy)
  async getSiteMapLegacy(projectId: string): Promise<any> {
    return this.getSiteMap(projectId);
  }

  async updateScopeLegacy(projectId: string, scope: any): Promise<any> {
    return this.updateScope(projectId, scope);
  }

  // Scan Profiles (legacy)
  async getScanProfilesLegacy(projectId: string): Promise<any> {
    return this.getScanProfiles(projectId);
  }

  async createScanProfileLegacy(projectId: string, profile: any): Promise<any> {
    return this.createScanProfile(projectId, profile);
  }

  async updateScanProfileLegacy(projectId: string, profileId: string, profile: any): Promise<any> {
    return this.updateScanProfile(projectId, profileId, profile);
  }

  async deleteScanProfileLegacy(projectId: string, profileId: string): Promise<any> {
    return this.deleteScanProfile(projectId, profileId);
  }

  // Active Scans (legacy)
  async createActiveScanLegacy(projectId: string, scan: any): Promise<any> {
    return this.createScan(projectId, scan);
  }

  async getActiveScansLegacy(projectId: string): Promise<any> {
    return this.getActiveScans(projectId);
  }

  async getActiveScanLegacy(projectId: string, scanId: string): Promise<any> {
    return this.getScanDetails(projectId, scanId);
  }

  async startActiveScanLegacy(projectId: string, scanId: string): Promise<any> {
    return this.startScan(projectId, scanId);
  }

  async stopActiveScanLegacy(projectId: string, scanId: string): Promise<any> {
    return this.stopScan(projectId, scanId);
  }

  async deleteActiveScanLegacy(projectId: string, scanId: string): Promise<any> {
    return this.deleteScan(projectId, scanId);
  }

  // Scan Issues (legacy)
  async getScanIssuesLegacy(projectId: string, scanId?: string): Promise<any> {
    return this.getScanIssues(projectId, { page: 1, page_size: 1000, scan_id: scanId });
  }

  async updateIssueStatusLegacy(projectId: string, issueId: string, status: string): Promise<any> {
    return this.updateIssueStatus(projectId, issueId, { status });
  }

  // Export functionality (legacy)
  async exportScanResultsLegacy(projectId: string, scanId: string, format: 'json' | 'csv' | 'xml' = 'json'): Promise<any> {
    return this.exportScanResults(projectId, scanId, format);
  }

  async exportHttpHistoryLegacy(projectId: string, format: 'json' | 'csv' | 'xml' = 'json'): Promise<any> {
    return this.exportHttpHistory(projectId, format);
  }

  async exportCrawlResultsLegacy(projectId: string, format: 'json' | 'csv' | 'xml' = 'json'): Promise<any> {
    return this.exportCrawlResults(projectId, format);
  }
}

export const dastProjectToolsService = new DASTProjectToolsService();

// Export individual methods for convenience
export const {
  getProjectStatus,
  getHttpHistory,
  getHttpEntryDetail,
  exportHttpHistory,
  getScanProfiles,
  createScanProfile,
  getActiveScans,
  createScan,
  getScanDetails,
  startScan,
  stopScan,
  deleteScan,
  getScanIssues,
  updateIssueStatus,
  startCrawler,
  stopCrawler,
  getCrawlerStatus,
  getCrawlResults,
  getSiteMap,
  updateScope,
  startIntruderAttack,
  stopIntruderAttack,
  getIntruderResults,
  sendRepeaterRequest,
  getRepeaterHistory,
  getMatchReplaceRules,
  createMatchReplaceRule,
  updateMatchReplaceRule,
  deleteMatchReplaceRule,
  getProxyStatus,
  startProxy,
  stopProxy,
  exportScanResults,
  exportProjectReport,
  createWebSocketConnection,
} = dastProjectToolsService;


