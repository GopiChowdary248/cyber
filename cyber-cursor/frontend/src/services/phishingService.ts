import { apiClient } from '../utils/apiClient';

export interface PhishingScanRequest {
  url: string;
  content?: string;
  metadata?: any;
}

export interface PhishingScanResult {
  id: string;
  url: string;
  is_phishing: boolean;
  confidence_score: number;
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  indicators: string[];
  description: string;
  scan_timestamp: string;
  metadata?: any;
}

export interface PhishingReport {
  id: string;
  url: string;
  reporter_id: number;
  report_reason: string;
  evidence: string;
  status: 'pending' | 'investigating' | 'confirmed' | 'false_positive';
  created_at: string;
  updated_at: string;
}

export interface PhishingReportCreate {
  url: string;
  report_reason: string;
  evidence: string;
}

export interface PhishingStats {
  total_scans: number;
  phishing_detected: number;
  false_positives: number;
  detection_rate: number;
  avg_confidence: number;
  top_indicators: string[];
}

export interface PhishingTrends {
  timeframe: string;
  daily_scans: number[];
  daily_detections: number[];
  top_domains: string[];
  top_techniques: string[];
}

class PhishingService {
  // Scan URL for phishing
  async scanUrl(request: PhishingScanRequest): Promise<PhishingScanResult> {
    const response = await apiClient.post('/phishing/scan', request);
    return response.data;
  }

  // Get scan history
  async getScanHistory(
    skip: number = 0,
    limit: number = 100,
    url?: string,
    is_phishing?: boolean
  ): Promise<{ results: PhishingScanResult[]; total: number }> {
    const params = new URLSearchParams();
    if (skip) params.append('skip', skip.toString());
    if (limit) params.append('limit', limit.toString());
    if (url) params.append('url', url);
    if (is_phishing !== undefined) params.append('is_phishing', is_phishing.toString());

    const response = await apiClient.get(`/phishing/history?${params.toString()}`);
    return response.data;
  }

  // Get scan result by ID
  async getScanResult(scanId: string): Promise<PhishingScanResult> {
    const response = await apiClient.get(`/phishing/scan/${scanId}`);
    return response.data;
  }

  // Report phishing URL
  async reportPhishing(reportData: PhishingReportCreate): Promise<PhishingReport> {
    const response = await apiClient.post('/phishing/report', reportData);
    return response.data;
  }

  // Get phishing reports
  async getPhishingReports(
    skip: number = 0,
    limit: number = 100,
    status?: string
  ): Promise<{ reports: PhishingReport[]; total: number }> {
    const params = new URLSearchParams();
    if (skip) params.append('skip', skip.toString());
    if (limit) params.append('limit', limit.toString());
    if (status) params.append('status', status);

    const response = await apiClient.get(`/phishing/reports?${params.toString()}`);
    return response.data;
  }

  // Update report status
  async updateReportStatus(
    reportId: string,
    status: 'investigating' | 'confirmed' | 'false_positive'
  ): Promise<PhishingReport> {
    const response = await apiClient.put(`/phishing/reports/${reportId}/status`, { status });
    return response.data;
  }

  // Get phishing statistics
  async getPhishingStats(): Promise<PhishingStats> {
    const response = await apiClient.get('/phishing/stats');
    return response.data;
  }

  // Get phishing trends
  async getPhishingTrends(timeframe: string = '30d'): Promise<PhishingTrends> {
    const response = await apiClient.get(`/phishing/trends?timeframe=${timeframe}`);
    return response.data;
  }

  // Bulk scan URLs
  async bulkScanUrls(urls: string[]): Promise<PhishingScanResult[]> {
    const response = await apiClient.post('/phishing/bulk-scan', { urls });
    return response.data;
  }

  // Get phishing indicators
  async getPhishingIndicators(): Promise<string[]> {
    const response = await apiClient.get('/phishing/indicators');
    return response.data;
  }

  // Update phishing indicators
  async updatePhishingIndicators(indicators: string[]): Promise<{ message: string }> {
    const response = await apiClient.put('/phishing/indicators', { indicators });
    return response.data;
  }
}

export const phishingService = new PhishingService();
export default phishingService;
