import { apiClient } from '../utils/apiClient';

export interface ThreatIndicator {
  id: string;
  type: 'ip' | 'domain' | 'url' | 'hash' | 'email';
  value: string;
  threat_type: string;
  confidence: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  first_seen: string;
  last_seen: string;
  tags: string[];
  metadata: any;
}

export interface ThreatFeed {
  id: string;
  name: string;
  description: string;
  source: string;
  feed_type: 'stix' | 'misp' | 'csv' | 'json';
  url?: string;
  api_key?: string;
  last_update: string;
  status: 'active' | 'inactive' | 'error';
  indicators_count: number;
}

export interface ThreatReport {
  id: string;
  title: string;
  description: string;
  threat_type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  indicators: ThreatIndicator[];
  tactics: string[];
  techniques: string[];
  targets: string[];
  published_date: string;
  last_updated: string;
  source: string;
  tags: string[];
}

export interface ThreatCampaign {
  id: string;
  name: string;
  description: string;
  threat_actor: string;
  start_date: string;
  end_date?: string;
  status: 'active' | 'inactive' | 'completed';
  targets: string[];
  techniques: string[];
  indicators: ThreatIndicator[];
  impact: string;
  mitigation: string[];
}

export interface ThreatActor {
  id: string;
  name: string;
  aliases: string[];
  description: string;
  motivation: string[];
  capabilities: string[];
  targets: string[];
  techniques: string[];
  first_seen: string;
  last_seen: string;
  threat_level: 'low' | 'medium' | 'high' | 'critical';
  country?: string;
  group_type?: string;
}

export interface ThreatIntelligenceQuery {
  query: string;
  query_type: 'indicator' | 'threat_report' | 'campaign' | 'actor';
  filters?: {
    threat_type?: string;
    severity?: string;
    date_from?: string;
    date_to?: string;
    tags?: string[];
  };
}

export interface ThreatIntelligenceSearchResult {
  indicators: ThreatIndicator[];
  reports: ThreatReport[];
  campaigns: ThreatCampaign[];
  actors: ThreatActor[];
  total_results: number;
  search_time: number;
}

export interface ThreatIntelligenceMetrics {
  total_indicators: number;
  active_feeds: number;
  new_indicators_today: number;
  threat_reports_count: number;
  active_campaigns: number;
  top_threat_types: string[];
  last_update: string;
}

class ThreatIntelligenceService {
  // Search threat intelligence
  async searchThreatIntelligence(query: ThreatIntelligenceQuery): Promise<ThreatIntelligenceSearchResult> {
    const response = await apiClient.post('/threat-intelligence/search', query);
    return response.data;
  }

  // Get threat indicators
  async getThreatIndicators(
    skip: number = 0,
    limit: number = 100,
    type?: string,
    threat_type?: string,
    severity?: string
  ): Promise<{ indicators: ThreatIndicator[]; total: number }> {
    const params = new URLSearchParams();
    if (skip) params.append('skip', skip.toString());
    if (limit) params.append('limit', limit.toString());
    if (type) params.append('type', type);
    if (threat_type) params.append('threat_type', threat_type);
    if (severity) params.append('severity', severity);

    const response = await apiClient.get(`/threat-intelligence/indicators?${params.toString()}`);
    return response.data;
  }

  // Get threat indicator by ID
  async getThreatIndicator(indicatorId: string): Promise<ThreatIndicator> {
    const response = await apiClient.get(`/threat-intelligence/indicators/${indicatorId}`);
    return response.data;
  }

  // Add threat indicator
  async addThreatIndicator(indicatorData: Partial<ThreatIndicator>): Promise<ThreatIndicator> {
    const response = await apiClient.post('/threat-intelligence/indicators', indicatorData);
    return response.data;
  }

  // Update threat indicator
  async updateThreatIndicator(
    indicatorId: string,
    updateData: Partial<ThreatIndicator>
  ): Promise<ThreatIndicator> {
    const response = await apiClient.put(`/threat-intelligence/indicators/${indicatorId}`, updateData);
    return response.data;
  }

  // Delete threat indicator
  async deleteThreatIndicator(indicatorId: string): Promise<{ message: string }> {
    const response = await apiClient.delete(`/threat-intelligence/indicators/${indicatorId}`);
    return response.data;
  }

  // Get threat feeds
  async getThreatFeeds(): Promise<ThreatFeed[]> {
    const response = await apiClient.get('/threat-intelligence/feeds');
    return response.data;
  }

  // Get threat feed by ID
  async getThreatFeed(feedId: string): Promise<ThreatFeed> {
    const response = await apiClient.get(`/threat-intelligence/feeds/${feedId}`);
    return response.data;
  }

  // Add threat feed
  async addThreatFeed(feedData: Partial<ThreatFeed>): Promise<ThreatFeed> {
    const response = await apiClient.post('/threat-intelligence/feeds', feedData);
    return response.data;
  }

  // Update threat feed
  async updateThreatFeed(feedId: string, updateData: Partial<ThreatFeed>): Promise<ThreatFeed> {
    const response = await apiClient.put(`/threat-intelligence/feeds/${feedId}`, updateData);
    return response.data;
  }

  // Delete threat feed
  async deleteThreatFeed(feedId: string): Promise<{ message: string }> {
    const response = await apiClient.delete(`/threat-intelligence/feeds/${feedId}`);
    return response.data;
  }

  // Sync threat feed
  async syncThreatFeed(feedId: string): Promise<{ message: string; indicators_added: number }> {
    const response = await apiClient.post(`/threat-intelligence/feeds/${feedId}/sync`);
    return response.data;
  }

  // Get threat reports
  async getThreatReports(
    skip: number = 0,
    limit: number = 100,
    threat_type?: string,
    severity?: string
  ): Promise<{ reports: ThreatReport[]; total: number }> {
    const params = new URLSearchParams();
    if (skip) params.append('skip', skip.toString());
    if (limit) params.append('limit', limit.toString());
    if (threat_type) params.append('threat_type', threat_type);
    if (severity) params.append('severity', severity);

    const response = await apiClient.get(`/threat-intelligence/reports?${params.toString()}`);
    return response.data;
  }

  // Get threat report by ID
  async getThreatReport(reportId: string): Promise<ThreatReport> {
    const response = await apiClient.get(`/threat-intelligence/reports/${reportId}`);
    return response.data;
  }

  // Get threat campaigns
  async getThreatCampaigns(
    skip: number = 0,
    limit: number = 100,
    status?: string
  ): Promise<{ campaigns: ThreatCampaign[]; total: number }> {
    const params = new URLSearchParams();
    if (skip) params.append('skip', skip.toString());
    if (limit) params.append('limit', limit.toString());
    if (status) params.append('status', status);

    const response = await apiClient.get(`/threat-intelligence/campaigns?${params.toString()}`);
    return response.data;
  }

  // Get threat campaign by ID
  async getThreatCampaign(campaignId: string): Promise<ThreatCampaign> {
    const response = await apiClient.get(`/threat-intelligence/campaigns/${campaignId}`);
    return response.data;
  }

  // Get threat actors
  async getThreatActors(
    skip: number = 0,
    limit: number = 100,
    threat_level?: string
  ): Promise<{ actors: ThreatActor[]; total: number }> {
    const params = new URLSearchParams();
    if (skip) params.append('skip', skip.toString());
    if (limit) params.append('limit', limit.toString());
    if (threat_level) params.append('threat_level', threat_level);

    const response = await apiClient.get(`/threat-intelligence/actors?${params.toString()}`);
    return response.data;
  }

  // Get threat actor by ID
  async getThreatActor(actorId: string): Promise<ThreatActor> {
    const response = await apiClient.get(`/threat-intelligence/actors/${actorId}`);
    return response.data;
  }

  // Get threat intelligence metrics
  async getThreatIntelligenceMetrics(): Promise<ThreatIntelligenceMetrics> {
    const response = await apiClient.get('/threat-intelligence/metrics');
    return response.data;
  }

  // Export threat intelligence data
  async exportThreatIntelligence(
    dataType: 'indicators' | 'reports' | 'campaigns' | 'actors',
    format: 'csv' | 'stix' | 'json',
    filters?: any
  ): Promise<{ download_url: string }> {
    const response = await apiClient.post('/threat-intelligence/export', {
      data_type: dataType,
      format,
      filters
    });
    return response.data;
  }

  // Check indicator reputation
  async checkIndicatorReputation(
    indicatorType: string,
    indicatorValue: string
  ): Promise<{ reputation: string; confidence: number; details: any }> {
    const response = await apiClient.post('/threat-intelligence/reputation', {
      type: indicatorType,
      value: indicatorValue
    });
    return response.data;
  }
}

export const threatIntelligenceService = new ThreatIntelligenceService();
export default threatIntelligenceService;
