import { apiClient } from '../utils/apiClient';

export interface ComplianceFramework {
  id: string;
  name: string;
  version: string;
  description: string;
  requirements: ComplianceRequirement[];
  created_at: string;
  updated_at: string;
}

export interface ComplianceRequirement {
  id: string;
  code: string;
  title: string;
  description: string;
  category: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
  status: 'compliant' | 'non_compliant' | 'partial' | 'not_applicable';
  evidence?: string;
  last_assessed: string;
}

export interface ComplianceAssessment {
  id: string;
  framework_id: string;
  assessment_date: string;
  assessor_id: number;
  status: 'draft' | 'in_progress' | 'completed' | 'reviewed';
  overall_score: number;
  requirements: ComplianceRequirement[];
  findings: ComplianceFinding[];
  recommendations: string[];
  created_at: string;
  updated_at: string;
}

export interface ComplianceFinding {
  id: string;
  requirement_id: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  evidence: string;
  remediation: string;
  due_date: string;
  status: 'open' | 'in_progress' | 'resolved' | 'closed';
}

export interface ComplianceReport {
  id: string;
  assessment_id: string;
  report_type: 'executive' | 'detailed' | 'technical';
  content: any;
  generated_at: string;
  download_url?: string;
}

export interface ComplianceMetrics {
  total_frameworks: number;
  active_assessments: number;
  compliance_rate: number;
  critical_findings: number;
  overdue_remediations: number;
  next_assessment_due: string;
}

class ComplianceService {
  // Get compliance frameworks
  async getComplianceFrameworks(): Promise<ComplianceFramework[]> {
    const response = await apiClient.get('/compliance/frameworks');
    return response.data;
  }

  // Get compliance framework by ID
  async getComplianceFramework(frameworkId: string): Promise<ComplianceFramework> {
    const response = await apiClient.get(`/compliance/frameworks/${frameworkId}`);
    return response.data;
  }

  // Create compliance framework
  async createComplianceFramework(frameworkData: Partial<ComplianceFramework>): Promise<ComplianceFramework> {
    const response = await apiClient.post('/compliance/frameworks', frameworkData);
    return response.data;
  }

  // Update compliance framework
  async updateComplianceFramework(
    frameworkId: string,
    updateData: Partial<ComplianceFramework>
  ): Promise<ComplianceFramework> {
    const response = await apiClient.put(`/compliance/frameworks/${frameworkId}`, updateData);
    return response.data;
  }

  // Delete compliance framework
  async deleteComplianceFramework(frameworkId: string): Promise<{ message: string }> {
    const response = await apiClient.delete(`/compliance/frameworks/${frameworkId}`);
    return response.data;
  }

  // Get compliance assessments
  async getComplianceAssessments(
    frameworkId?: string,
    status?: string,
    skip: number = 0,
    limit: number = 100
  ): Promise<{ assessments: ComplianceAssessment[]; total: number }> {
    const params = new URLSearchParams();
    if (frameworkId) params.append('framework_id', frameworkId);
    if (status) params.append('status', status);
    if (skip) params.append('skip', skip.toString());
    if (limit) params.append('limit', limit.toString());

    const response = await apiClient.get(`/compliance/assessments?${params.toString()}`);
    return response.data;
  }

  // Get compliance assessment by ID
  async getComplianceAssessment(assessmentId: string): Promise<ComplianceAssessment> {
    const response = await apiClient.get(`/compliance/assessments/${assessmentId}`);
    return response.data;
  }

  // Create compliance assessment
  async createComplianceAssessment(assessmentData: Partial<ComplianceAssessment>): Promise<ComplianceAssessment> {
    const response = await apiClient.post('/compliance/assessments', assessmentData);
    return response.data;
  }

  // Update compliance assessment
  async updateComplianceAssessment(
    assessmentId: string,
    updateData: Partial<ComplianceAssessment>
  ): Promise<ComplianceAssessment> {
    const response = await apiClient.put(`/compliance/assessments/${assessmentId}`, updateData);
    return response.data;
  }

  // Delete compliance assessment
  async deleteComplianceAssessment(assessmentId: string): Promise<{ message: string }> {
    const response = await apiClient.delete(`/compliance/assessments/${assessmentId}`);
    return response.data;
  }

  // Update requirement status
  async updateRequirementStatus(
    assessmentId: string,
    requirementId: string,
    status: 'compliant' | 'non_compliant' | 'partial' | 'not_applicable',
    evidence?: string
  ): Promise<ComplianceRequirement> {
    const response = await apiClient.put(
      `/compliance/assessments/${assessmentId}/requirements/${requirementId}`,
      { status, evidence }
    );
    return response.data;
  }

  // Add compliance finding
  async addComplianceFinding(
    assessmentId: string,
    findingData: Partial<ComplianceFinding>
  ): Promise<ComplianceFinding> {
    const response = await apiClient.post(`/compliance/assessments/${assessmentId}/findings`, findingData);
    return response.data;
  }

  // Update compliance finding
  async updateComplianceFinding(
    assessmentId: string,
    findingId: string,
    updateData: Partial<ComplianceFinding>
  ): Promise<ComplianceFinding> {
    const response = await apiClient.put(
      `/compliance/assessments/${assessmentId}/findings/${findingId}`,
      updateData
    );
    return response.data;
  }

  // Generate compliance report
  async generateComplianceReport(
    assessmentId: string,
    reportType: 'executive' | 'detailed' | 'technical'
  ): Promise<ComplianceReport> {
    const response = await apiClient.post(`/compliance/assessments/${assessmentId}/reports`, {
      report_type: reportType
    });
    return response.data;
  }

  // Get compliance reports
  async getComplianceReports(assessmentId: string): Promise<ComplianceReport[]> {
    const response = await apiClient.get(`/compliance/assessments/${assessmentId}/reports`);
    return response.data;
  }

  // Get compliance metrics
  async getComplianceMetrics(): Promise<ComplianceMetrics> {
    const response = await apiClient.get('/compliance/metrics');
    return response.data;
  }

  // Export compliance data
  async exportComplianceData(
    frameworkId: string,
    format: 'csv' | 'excel' | 'pdf'
  ): Promise<{ download_url: string }> {
    const response = await apiClient.post(`/compliance/frameworks/${frameworkId}/export`, { format });
    return response.data;
  }
}

export const complianceService = new ComplianceService();
export default complianceService;
