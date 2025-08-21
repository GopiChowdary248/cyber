import { serviceRegistry, apiCallWithRetry } from './serviceRegistry';
import { API_ENDPOINTS } from './comprehensiveIntegrationService';

export interface SASTProject {
  id: number;
  name: string;
  description?: string;
  status: string;
  owner_id: number;
  created_at: string;
  updated_at: string;
}

export interface SASTScan {
  id: number;
  project_id: number;
  status: string;
  started_at: string;
  completed_at?: string;
  findings_count: number;
  severity_distribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

export interface SASTVulnerability {
  id: number;
  scan_id: number;
  project_id: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  cwe_id?: string;
  cve_id?: string;
  file_path?: string;
  line_number?: number;
  status: 'open' | 'fixed' | 'false_positive';
  created_at: string;
}

export interface SASTDashboard {
  total_projects: number;
  total_scans: number;
  critical_vulnerabilities: number;
  last_scan: string;
}

export interface SASTMetrics {
  security_rating: string;
  reliability_rating: string;
  maintainability_rating: string;
  coverage: number;
  duplications: number;
  technical_debt: string;
}

export interface SASTQualityGate {
  id: number;
  name: string;
  status: 'passed' | 'failed' | 'warning';
  conditions: Array<{
    metric: string;
    operator: string;
    value: string;
    status: string;
  }>;
}

class SASTService {
  /**
   * Get all SAST projects
   */
  async getProjects(): Promise<SASTProject[]> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.SAST.PROJECTS)
      );
      return response as SASTProject[];
    } catch (error) {
      console.error('Failed to fetch SAST projects:', error);
      throw error;
    }
  }

  /**
   * Create a new SAST project
   */
  async createProject(projectData: { name: string; description?: string }): Promise<SASTProject> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.post(API_ENDPOINTS.SAST.PROJECTS, projectData)
      );
      return response as SASTProject;
    } catch (error) {
      console.error('Failed to create SAST project:', error);
      throw error;
    }
  }

  /**
   * Get SAST project by ID
   */
  async getProject(projectId: string): Promise<SASTProject> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.SAST.PROJECT(projectId))
      );
      return response as SASTProject;
    } catch (error) {
      console.error('Failed to fetch SAST project:', error);
      throw error;
    }
  }

  /**
   * Update SAST project
   */
  async updateProject(projectId: string, projectData: Partial<SASTProject>): Promise<SASTProject> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.put(API_ENDPOINTS.SAST.PROJECT(projectId), projectData)
      );
      return response as SASTProject;
    } catch (error) {
      console.error('Failed to update SAST project:', error);
      throw error;
    }
  }

  /**
   * Delete SAST project
   */
  async deleteProject(projectId: string): Promise<void> {
    try {
      await apiCallWithRetry(() => 
        serviceRegistry.delete(API_ENDPOINTS.SAST.PROJECT(projectId))
      );
    } catch (error) {
      console.error('Failed to delete SAST project:', error);
      throw error;
    }
  }

  /**
   * Get SAST scans for a project
   */
  async getScans(projectId?: string): Promise<SASTScan[]> {
    try {
      const endpoint = projectId 
        ? API_ENDPOINTS.SAST.SCAN(projectId)
        : API_ENDPOINTS.SAST.SCANS;
      
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(endpoint)
      );
      return response as SASTScan[];
    } catch (error) {
      console.error('Failed to fetch SAST scans:', error);
      throw error;
    }
  }

  /**
   * Start a new SAST scan
   */
  async startScan(projectId: string, scanConfig: { branch?: string; quality_gate?: boolean }): Promise<SASTScan> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.post(API_ENDPOINTS.SAST.SCAN(projectId), scanConfig)
      );
      return response;
    } catch (error) {
      console.error('Failed to start SAST scan:', error);
      throw error;
    }
  }

  /**
   * Get SAST vulnerabilities
   */
  async getVulnerabilities(projectId?: string): Promise<SASTVulnerability[]> {
    try {
      const endpoint = projectId 
        ? `${API_ENDPOINTS.SAST.PROJECT(projectId)}/vulnerabilities`
        : API_ENDPOINTS.SAST.VULNERABILITIES;
      
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(endpoint)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST vulnerabilities:', error);
      throw error;
    }
  }

  // ============================================================================
  // NEW CODE ANALYSIS ENDPOINTS
  // ============================================================================

  /**
   * Get new code metrics for a project
   */
  async getNewCodeMetrics(projectId: string, mode: string, days?: number, since?: string): Promise<any> {
    try {
      const params = new URLSearchParams({ mode });
      if (days) params.append('days', days.toString());
      if (since) params.append('since', since);
      
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(`${API_ENDPOINTS.SAST.PROJECT(projectId)}/new-code-metrics?${params}`)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch new code metrics:', error);
      throw error;
    }
  }

  /**
   * Get new code settings for a project
   */
  async getNewCodeSettings(projectId: string): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(`${API_ENDPOINTS.SAST.PROJECT(projectId)}/new-code/settings`)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch new code settings:', error);
      throw error;
    }
  }

  /**
   * Update new code settings for a project
   */
  async updateNewCodeSettings(projectId: string, settings: any): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.put(`${API_ENDPOINTS.SAST.PROJECT(projectId)}/new-code/settings`, settings)
      );
      return response;
    } catch (error) {
      console.error('Failed to update new code settings:', error);
      throw error;
    }
  }

  // ============================================================================
  // BRANCH AND PR ANALYSIS ENDPOINTS
  // ============================================================================

  /**
   * Get project branches
   */
  async getProjectBranches(projectId: string): Promise<any[]> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(`${API_ENDPOINTS.SAST.PROJECT(projectId)}/branches`)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch project branches:', error);
      throw error;
    }
  }

  /**
   * Get project pull requests
   */
  async getProjectPRs(projectId: string, state: string = 'open'): Promise<any[]> {
    try {
      const params = new URLSearchParams({ state });
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(`${API_ENDPOINTS.SAST.PROJECT(projectId)}/prs?${params}`)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch project PRs:', error);
      throw error;
    }
  }

  // ============================================================================
  // CODE BROWSING ENDPOINTS
  // ============================================================================

  /**
   * Get repository tree structure
   */
  async getRepoTree(projectId: string, path: string = '', ref: string = ''): Promise<any[]> {
    try {
      const params = new URLSearchParams();
      if (path) params.append('path', path);
      if (ref) params.append('ref', ref);
      
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(`${API_ENDPOINTS.SAST.PROJECT(projectId)}/repo/tree?${params}`)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch repository tree:', error);
      throw error;
    }
  }

  /**
   * Get file content
   */
  async getFileContent(projectId: string, filePath: string, ref: string = ''): Promise<any> {
    try {
      const params = new URLSearchParams({ file_path: filePath });
      if (ref) params.append('ref', ref);
      
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(`${API_ENDPOINTS.SAST.PROJECT(projectId)}/repo/file?${params}`)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch file content:', error);
      throw error;
    }
  }

  // ============================================================================
  // QUALITY PROFILES ENDPOINTS
  // ============================================================================

  /**
   * Get all quality profiles
   */
  async getQualityProfiles(language?: string): Promise<any[]> {
    try {
      const params = language ? new URLSearchParams({ language }) : '';
      const endpoint = language ? `/rule-profiles?${params}` : '/rule-profiles';
      
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(`/api/v1/sast${endpoint}`)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch quality profiles:', error);
      throw error;
    }
  }

  /**
   * Create a new quality profile
   */
  async createQualityProfile(profileData: any): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.post(`/api/v1/sast/rule-profiles`, profileData)
      );
      return response;
    } catch (error) {
      console.error('Failed to create quality profile:', error);
      throw error;
    }
  }

  /**
   * Update quality profile
   */
  async updateQualityProfile(profileId: string, profileData: any): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.put(`${API_ENDPOINTS.SAST.BASE}/rule-profiles/${profileId}`, profileData)
      );
      return response;
    } catch (error) {
      console.error('Failed to update quality profile:', error);
      throw error;
    }
  }

  /**
   * Assign quality profile to project
   */
  async assignQualityProfile(projectId: string, profileId: string): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.post(`${API_ENDPOINTS.SAST.PROJECT(projectId)}/rule-profile/${profileId}`)
      );
      return response;
    } catch (error) {
      console.error('Failed to assign quality profile:', error);
      throw error;
    }
  }

  // ============================================================================
  // ISSUE MANAGEMENT ENDPOINTS
  // ============================================================================

  /**
   * Get issues by file
   */
  async getIssuesByFile(projectId: string, filePath: string): Promise<any[]> {
    try {
      const params = new URLSearchParams({ file_path: filePath });
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(`${API_ENDPOINTS.SAST.PROJECT(projectId)}/issues/by-file?${params}`)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch issues by file:', error);
      throw error;
    }
  }

  /**
   * Get issue comments
   */
  async getIssueComments(issueId: string): Promise<any[]> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(`${API_ENDPOINTS.SAST.BASE}/issues/${issueId}/comments`)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch issue comments:', error);
      throw error;
    }
  }

  /**
   * Add comment to issue
   */
  async addIssueComment(issueId: string, comment: string): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.post(`${API_ENDPOINTS.SAST.BASE}/issues/${issueId}/comments`, { message: comment })
      );
      return response;
    } catch (error) {
      console.error('Failed to add issue comment:', error);
      throw error;
    }
  }

  /**
   * Update issue
   */
  async updateIssue(issueId: string, updates: any): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.put(`${API_ENDPOINTS.SAST.BASE}/issues/${issueId}`, updates)
      );
      return response;
    } catch (error) {
      console.error('Failed to update issue:', error);
      throw error;
    }
  }

  /**
   * Bulk update issues
   */
  async bulkUpdateIssues(issueIds: number[], updates: any): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.put(`${API_ENDPOINTS.SAST.BASE}/issues/bulk-update`, { issue_ids: issueIds, updates })
      );
      return response;
    } catch (error) {
      console.error('Failed to bulk update issues:', error);
      throw error;
    }
  }

  /**
   * Get issue history
   */
  async getIssueHistory(issueId: string): Promise<any[]> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(`${API_ENDPOINTS.SAST.BASE}/issues/${issueId}/history`)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch issue history:', error);
      throw error;
    }
  }

  // ============================================================================
  // QUALITY GATES ENDPOINTS
  // ============================================================================

  /**
   * Get quality gates
   */
  async getQualityGates(): Promise<any[]> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(`${API_ENDPOINTS.SAST.BASE}/quality-gates`)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch quality gates:', error);
      throw error;
    }
  }

  /**
   * Get project quality gate
   */
  async getProjectQualityGate(projectId: string): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(`${API_ENDPOINTS.SAST.PROJECT(projectId)}/quality-gate`)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch project quality gate:', error);
      throw error;
    }
  }

  /**
   * Update project quality gate
   */
  async updateProjectQualityGate(projectId: string, gateData: any): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.put(`${API_ENDPOINTS.SAST.PROJECT(projectId)}/quality-gate`, gateData)
      );
      return response;
    } catch (error) {
      console.error('Failed to update project quality gate:', error);
      throw error;
    }
  }

  /**
   * Evaluate quality gate for new code
   */
  async evaluateQualityGateNewCode(projectId: string): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.post(`${API_ENDPOINTS.SAST.PROJECT(projectId)}/quality-gate/evaluate-new-code`)
      );
      return response;
    } catch (error) {
      console.error('Failed to evaluate quality gate for new code:', error);
      throw error;
    }
  }

  // ============================================================================
  // CODE COVERAGE ENDPOINTS
  // ============================================================================

  /**
   * Get code coverage
   */
  async getCodeCoverage(projectId?: string, scanId?: string, minCoverage?: number): Promise<any[]> {
    try {
      const params = new URLSearchParams();
      if (projectId) params.append('project_id', projectId);
      if (scanId) params.append('scan_id', scanId);
      if (minCoverage) params.append('min_coverage', minCoverage.toString());
      
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(`${API_ENDPOINTS.SAST.BASE}/code-coverage?${params}`)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch code coverage:', error);
      throw error;
    }
  }

  /**
   * Get detailed code coverage for a project
   */
  async getDetailedCodeCoverage(projectId: string, filePath?: string): Promise<any> {
    try {
      const params = filePath ? new URLSearchParams({ file_path: filePath }) : '';
      const endpoint = filePath ? `?${params}` : '';
      
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(`${API_ENDPOINTS.SAST.BASE}/code-coverage/${projectId}/detailed${endpoint}`)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch detailed code coverage:', error);
      throw error;
    }
  }

  /**
   * Import code coverage data
   */
  async importCodeCoverage(projectId: string, coverageData: any): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.post(`${API_ENDPOINTS.SAST.PROJECT(projectId)}/coverage/import`, coverageData)
      );
      return response;
    } catch (error) {
      console.error('Failed to import code coverage:', error);
      throw error;
    }
  }

  // ============================================================================
  // SECURITY HOTSPOTS ENDPOINTS
  // ============================================================================

  /**
   * Get security hotspots
   */
  async getSecurityHotspots(projectId?: string, filters?: any): Promise<any[]> {
    try {
      const endpoint = projectId 
        ? `${API_ENDPOINTS.SAST.PROJECT(projectId)}/security-hotspots`
        : `${API_ENDPOINTS.SAST.BASE}/security-hotspots`;
      
      const params = filters ? new URLSearchParams(filters) : '';
      const fullEndpoint = params ? `${endpoint}?${params}` : endpoint;
      
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(fullEndpoint)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch security hotspots:', error);
      throw error;
    }
  }

  /**
   * Review security hotspot
   */
  async reviewSecurityHotspot(hotspotId: string, reviewData: any): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.post(`${API_ENDPOINTS.SAST.BASE}/security-hotspots/${hotspotId}/review`, reviewData)
      );
      return response;
    } catch (error) {
      console.error('Failed to review security hotspot:', error);
      throw error;
    }
  }

  /**
   * Get security hotspot reviews
   */
  async getSecurityHotspotReviews(hotspotId: string): Promise<any[]> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(`${API_ENDPOINTS.SAST.BASE}/security-hotspots/${hotspotId}/reviews`)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch security hotspot reviews:', error);
      throw error;
    }
  }

  // ============================================================================
  // MONTH 1 FEATURES ENDPOINTS
  // ============================================================================

  /**
   * Start incremental analysis
   */
  async startIncrementalAnalysis(projectId: string, analysisConfig: any): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.post(`${API_ENDPOINTS.SAST.PROJECT(projectId)}/incremental-scan`, analysisConfig)
      );
      return response;
    } catch (error) {
      console.error('Failed to start incremental analysis:', error);
      throw error;
    }
  }

  /**
   * Get file changes for incremental analysis
   */
  async getFileChanges(projectId: string, scanId?: string): Promise<any[]> {
    try {
      const params = scanId ? new URLSearchParams({ scan_id: scanId }) : '';
      const endpoint = params ? `?${params}` : '';
      
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(`${API_ENDPOINTS.SAST.PROJECT(projectId)}/file-changes${endpoint}`)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch file changes:', error);
      throw error;
    }
  }

  /**
   * Get background jobs
   */
  async getBackgroundJobs(): Promise<any[]> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(`${API_ENDPOINTS.SAST.BASE}/background-jobs`)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch background jobs:', error);
      throw error;
    }
  }

  // ============================================================================
  // SAVED FILTERS ENDPOINTS
  // ============================================================================

  /**
   * Create saved filter
   */
  async createSavedFilter(filterData: any): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.post(`${API_ENDPOINTS.SAST.BASE}/saved-filters`, filterData)
      );
      return response;
    } catch (error) {
      console.error('Failed to create saved filter:', error);
      throw error;
    }
  }

  /**
   * Get saved filters
   */
  async getSavedFilters(filterType: string, projectId?: number): Promise<any> {
    try {
      const params = new URLSearchParams({ filter_type: filterType });
      if (projectId) params.append('project_id', projectId.toString());
      
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(`${API_ENDPOINTS.SAST.BASE}/saved-filters?${params}`)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch saved filters:', error);
      throw error;
    }
  }

  /**
   * Update saved filter
   */
  async updateSavedFilter(filterId: string, filterData: any): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.put(`${API_ENDPOINTS.SAST.BASE}/saved-filters/${filterId}`, filterData)
      );
      return response;
    } catch (error) {
      console.error('Failed to update saved filter:', error);
      throw error;
    }
  }

  /**
   * Delete saved filter
   */
  async deleteSavedFilter(filterId: string): Promise<void> {
    try {
      await apiCallWithRetry(() => 
        serviceRegistry.delete(`${API_ENDPOINTS.SAST.BASE}/saved-filters/${filterId}`)
      );
    } catch (error) {
      console.error('Failed to delete saved filter:', error);
      throw error;
    }
  }

  // ============================================================================
  // ADVANCED ANALYSIS ENDPOINTS
  // ============================================================================

  /**
   * Start advanced analysis
   */
  async startAdvancedAnalysis(projectId: string, analysisTypes: string[], languages: string[], options?: any): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.post(`${API_ENDPOINTS.SAST.BASE}/advanced-analysis/${projectId}`, {
          analysis_types: analysisTypes,
          languages,
          options
        })
      );
      return response;
    } catch (error) {
      console.error('Failed to start advanced analysis:', error);
      throw error;
    }
  }

  /**
   * Get advanced analysis results
   */
  async getAdvancedAnalysisResults(analysisId: string): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(`${API_ENDPOINTS.SAST.BASE}/advanced-analysis/${analysisId}`)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch advanced analysis results:', error);
      throw error;
    }
  }

  // ============================================================================
  // DASHBOARD AND OVERVIEW ENDPOINTS
  // ============================================================================

  /**
   * Get SAST dashboard stats
   */
  async getDashboardStats(): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(`${API_ENDPOINTS.SAST.BASE}/dashboard`)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch dashboard stats:', error);
      throw error;
    }
  }

  /**
   * Get SAST overview
   */
  async getOverview(): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(`${API_ENDPOINTS.SAST.BASE}/overview`)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST overview:', error);
      throw error;
    }
  }

  /**
   * Update vulnerability status
   */
  async updateVulnerability(vulnerabilityId: string, status: string): Promise<SASTVulnerability> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.put(API_ENDPOINTS.SAST.VULNERABILITIES, { id: vulnerabilityId, status })
      );
      return response;
    } catch (error) {
      console.error('Failed to update vulnerability:', error);
      throw error;
    }
  }

  /**
   * Get SAST dashboard overview
   */
  async getDashboard(): Promise<SASTDashboard> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.SAST.DASHBOARD)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST dashboard:', error);
      throw error;
    }
  }

  /**
   * Get SAST overview
   */
  async getOverview(): Promise<SASTDashboard> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.SAST.OVERVIEW)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST overview:', error);
      throw error;
    }
  }

  /**
   * Get SAST metrics for a project
   */
  async getMetrics(projectId: string): Promise<SASTMetrics> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.SAST.METRICS(projectId))
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST metrics:', error);
      throw error;
    }
  }

  /**
   * Get SAST quality gates
   */
  async getQualityGates(projectId?: string): Promise<SASTQualityGate[]> {
    try {
      const endpoint = projectId 
        ? `${API_ENDPOINTS.SAST.PROJECT(projectId)}/quality-gates`
        : API_ENDPOINTS.SAST.QUALITY_GATES;
      
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(endpoint)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST quality gates:', error);
      throw error;
    }
  }

  /**
   * Get SAST security hotspots
   */
  async getSecurityHotspots(projectId?: string): Promise<any[]> {
    try {
      const endpoint = projectId 
        ? `${API_ENDPOINTS.SAST.PROJECT(projectId)}/security-hotspots`
        : API_ENDPOINTS.SAST.SECURITY_HOTSPOTS;
      
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(endpoint)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST security hotspots:', error);
      throw error;
    }
  }

  /**
   * Get SAST code coverage
   */
  async getCodeCoverage(projectId: string): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.SAST.CODE_COVERAGE)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST code coverage:', error);
      throw error;
    }
  }

  async importCoverage(projectId: string | number, body: FormData | Blob, params?: { scan_id?: string|number; format?: 'lcov'|'cobertura'|'jacoco'; clear?: boolean }) {
    const url = `/api/v1/sast/projects/${projectId}/coverage/import`;
    const opts: any = { params };
    // If Blob, wrap as FormData
    let payload: any = body;
    if (!(body instanceof FormData)) {
      const fd = new FormData();
      fd.append('file', body as any, 'coverage');
      payload = fd;
    }
    return apiCallWithRetry(() => serviceRegistry.post(url, payload, opts));
  }

  /**
   * Get SAST duplications
   */
  async getDuplications(projectId: string): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.SAST.DUPLICATIONS)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST duplications:', error);
      throw error;
    }
  }

  /**
   * Get SAST statistics
   */
  async getStatistics(projectId?: string): Promise<any> {
    try {
      const endpoint = projectId 
        ? `${API_ENDPOINTS.SAST.PROJECT(projectId)}/statistics`
        : API_ENDPOINTS.SAST.STATISTICS;
      
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(endpoint)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST statistics:', error);
      throw error;
    }
  }

  // Baseline (New Code)
  async getBaseline(projectId: string): Promise<{ baseline_type: 'DATE'|'BRANCH'; value: string; }>{
    return apiCallWithRetry(() => serviceRegistry.get(`/api/v1/sast/projects/${projectId}/baseline`));
  }
  async setBaseline(projectId: string, baseline_type: 'DATE'|'BRANCH', value: string): Promise<any>{
    return apiCallWithRetry(() => serviceRegistry.post(`/api/v1/sast/projects/${projectId}/baseline`, { baseline_type, value }));
  }

  // New-code issues and PR analysis
  async getNewCodeIssues(projectId: string, params?: { branch?: string; severity?: string; issue_type?: string; skip?: number; limit?: number; }): Promise<any> {
    return apiCallWithRetry(() => serviceRegistry.get(`/api/v1/sast/projects/${projectId}/issues/new-code`, { params }));
  }
  async analyzePullRequest(payload: { project_id: number; base_ref: string; head_ref: string; pr_number?: number; repo_url?: string; scm?: string; }): Promise<any> {
    return apiCallWithRetry(() => serviceRegistry.post(`/api/v1/sast/pulls/analyze`, payload));
  }

  /**
   * Get SAST rules
   */
  async getRules(): Promise<any[]> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.SAST.RULES)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST rules:', error);
      throw error;
    }
  }

  // Rule profiles
  async listRuleProfiles(language?: string): Promise<any> {
    const params = language ? { language } : undefined;
    return apiCallWithRetry(() => serviceRegistry.get(`/api/v1/sast/rule-profiles`, { params }));
  }

  async createRuleProfile(payload: { name: string; language: string; description?: string }): Promise<any> {
    return apiCallWithRetry(() => serviceRegistry.post(`/api/v1/sast/rule-profiles`, payload));
  }

  async getProfileRules(profileId: number | string): Promise<any> {
    return apiCallWithRetry(() => serviceRegistry.get(`/api/v1/sast/rule-profiles/${profileId}/rules`));
  }

  async assignProjectRuleProfile(projectId: string | number, profileId: string | number): Promise<any> {
    return apiCallWithRetry(() => serviceRegistry.post(`/api/v1/sast/projects/${projectId}/rule-profile/${profileId}`));
  }

  async updateRule(ruleId: number | string, payload: { enabled?: boolean; severity?: 'BLOCKER'|'CRITICAL'|'MAJOR'|'MINOR'|'INFO' }): Promise<any> {
    return apiCallWithRetry(() => serviceRegistry.put(`/api/v1/sast/rules/${ruleId}`, payload));
  }

  /**
   * Get SAST languages
   */
  async getLanguages(): Promise<any[]> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.SAST.LANGUAGES)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST languages:', error);
      throw error;
    }
  }

  /**
   * Get SAST configuration for a project
   */
  async getConfiguration(projectId: string): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.SAST.CONFIGURATION(projectId))
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST configuration:', error);
      throw error;
    }
  }

  /**
   * Update SAST configuration for a project
   */
  async updateConfiguration(projectId: string, config: any): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.put(API_ENDPOINTS.SAST.CONFIGURATION(projectId), config)
      );
      return response;
    } catch (error) {
      console.error('Failed to update SAST configuration:', error);
      throw error;
    }
  }

  // Quality Gate
  async updateQualityGate(projectId: string | number, payload: Partial<{
    max_blocker_issues: number; max_critical_issues: number; max_major_issues: number; max_minor_issues: number; max_info_issues: number;
    min_coverage: number; min_branch_coverage: number; max_debt_ratio: number; max_technical_debt: number; max_duplicated_lines: number; max_duplicated_blocks: number;
  }>): Promise<any> {
    return apiCallWithRetry(() => serviceRegistry.put(`/api/v1/sast/projects/${projectId}/quality-gate`, payload));
  }

  // Issue workflow
  async updateIssue(issueId: string | number, payload: Partial<{ status: string; resolution: string; assignee_id: number }>): Promise<any> {
    return apiCallWithRetry(() => serviceRegistry.put(`/api/v1/sast/issues/${issueId}`, payload));
  }

  async bulkUpdateIssues(issueIds: (string | number)[], payload: Partial<{ status: string; resolution: string; assignee_id: number }>): Promise<any> {
    return apiCallWithRetry(() => serviceRegistry.put(`/api/v1/sast/issues/bulk-update`, { issue_ids: issueIds, updates: payload }));
  }

  // Saved Filters
  async createSavedFilter(filterData: { name: string; description?: string; filter_type: string; filter_criteria: any; project_id?: number }): Promise<any> {
    return apiCallWithRetry(() => serviceRegistry.post(`/api/v1/sast/saved-filters`, filterData));
  }

  async getSavedFilters(filterType?: string, projectId?: number): Promise<any> {
    const params: any = {};
    if (filterType) params.filter_type = filterType;
    if (projectId) params.project_id = projectId;
    return apiCallWithRetry(() => serviceRegistry.get(`/api/v1/sast/saved-filters`, { params }));
  }

  async updateSavedFilter(filterId: number, filterData: Partial<{ name: string; description: string; filter_criteria: any }>): Promise<any> {
    return apiCallWithRetry(() => serviceRegistry.put(`/api/v1/sast/saved-filters/${filterId}`, filterData));
  }

  async deleteSavedFilter(filterId: number): Promise<any> {
    return apiCallWithRetry(() => serviceRegistry.delete(`/api/v1/sast/saved-filters/${filterId}`));
  }

  /**
   * Get SAST trends for a project
   */
  async getTrends(projectId: string): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.SAST.TRENDS(projectId))
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST trends:', error);
      throw error;
    }
  }

  /**
   * Get SAST security reports for a project
   */
  async getSecurityReports(projectId: string): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.SAST.SECURITY_REPORTS(projectId))
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST security reports:', error);
      throw error;
    }
  }

  /**
   * Get SAST reliability metrics for a project
   */
  async getReliability(projectId: string): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.SAST.RELIABILITY(projectId))
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST reliability:', error);
      throw error;
    }
  }

  /**
   * Get SAST maintainability metrics for a project
   */
  async getMaintainability(projectId: string): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.SAST.MAINTAINABILITY(projectId))
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST maintainability:', error);
      throw error;
    }
  }

  /**
   * Get SAST activity for a project
   */
  async getActivity(projectId: string): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.SAST.ACTIVITY(projectId))
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST activity:', error);
      throw error;
    }
  }

  /**
   * Export SAST report
   */
  async exportReport(projectId: string, format: 'pdf' | 'html' | 'json' = 'pdf'): Promise<Blob> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(`${API_ENDPOINTS.SAST.PROJECT(projectId)}/export`, {
          params: { format },
          responseType: 'blob'
        })
      );
      return response;
    } catch (error) {
      console.error('Failed to export SAST report:', error);
      throw error;
    }
  }

  /**
   * Schedule SAST scan
   */
  async scheduleScan(projectId: string, schedule: { cron: string; enabled: boolean }): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.post(`${API_ENDPOINTS.SAST.PROJECT(projectId)}/schedule`, schedule)
      );
      return response;
    } catch (error) {
      console.error('Failed to schedule SAST scan:', error);
      throw error;
    }
  }

  /**
   * Start advanced analysis for a project
   */
  async startAdvancedAnalysis(
    projectId: string, 
    analysisTypes: string[], 
    languages: string[], 
    options?: any
  ): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.post(`${API_ENDPOINTS.SAST.PROJECT(projectId)}/advanced-analysis`, {
          analysis_types: analysisTypes,
          languages,
          options
        })
      );
      return response;
    } catch (error) {
      console.error('Failed to start advanced analysis:', error);
      throw error;
    }
  }
}

export const sastService = new SASTService();
export default SASTService;
