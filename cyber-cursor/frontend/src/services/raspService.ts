import { apiClient, apiCallWithRetry } from '../utils/apiClient';
import { API_ENDPOINTS } from './comprehensiveIntegrationService';

export interface RASPAgent {
  id: number;
  name: string;
  status: 'active' | 'inactive' | 'error';
  version: string;
  last_heartbeat: string;
  protected_applications: number;
  hostname?: string;
  ip_address?: string;
  os_info?: string;
  memory_usage?: number;
  cpu_usage?: number;
}

export interface RAPSAttack {
  id: number;
  timestamp: string;
  attack_type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  blocked: boolean;
  agent_id: number;
  source_ip?: string;
  target_url?: string;
  payload?: string;
  details?: any;
}

export interface RASPRule {
  id: number;
  name: string;
  description: string;
  rule_type: string;
  pattern: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  enabled: boolean;
  action: 'block' | 'log' | 'alert';
  created_at: string;
  updated_at: string;
}

export interface RAPSVulnerability {
  id: number;
  agent_id: number;
  vulnerability_type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  discovered_at: string;
  status: 'open' | 'fixed' | 'investigating';
  remediation?: string;
}

export interface RAPSVirtualPatch {
  id: number;
  name: string;
  description: string;
  target_vulnerability: string;
  patch_type: 'request_filter' | 'response_filter' | 'behavior_modification';
  enabled: boolean;
  created_at: string;
}

export interface RAPSAlert {
  id: number;
  agent_id: number;
  alert_type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  message: string;
  timestamp: string;
  acknowledged: boolean;
  acknowledged_by?: string;
  acknowledged_at?: string;
}

export interface RAPSDashboard {
  total_agents: number;
  active_agents: number;
  total_attacks_blocked: number;
  last_attack: string;
  protection_status: string;
  threat_level: string;
}

export interface RAPSAttackSummary {
  total_attacks: number;
  blocked_attacks: number;
  attacks_by_type: Record<string, number>;
  attacks_by_severity: Record<string, number>;
  recent_attacks: RAPSAttack[];
}

export interface RAPSAgentStatus {
  agent_id: number;
  status: string;
  last_heartbeat: string;
  uptime: number;
  performance_metrics: {
    memory_usage: number;
    cpu_usage: number;
    network_activity: number;
  };
}

class RASPService {
  /**
   * Get all RASP agents
   */
  async getAgents(): Promise<RASPAgent[]> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.get(API_ENDPOINTS.RASP.AGENTS)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to fetch RASP agents:', error);
      throw error;
    }
  }

  /**
   * Get RASP agent by ID
   */
  async getAgent(agentId: string): Promise<RASPAgent> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.get(API_ENDPOINTS.RASP.AGENT(agentId))
      );
      return response.data;
    } catch (error) {
      console.error('Failed to fetch RASP agent:', error);
      throw error;
    }
  }

  /**
   * Create a new RASP agent
   */
  async createAgent(agentData: {
    name: string;
    hostname?: string;
    ip_address?: string;
    os_info?: string;
  }): Promise<RASPAgent> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.post(API_ENDPOINTS.RASP.AGENTS, agentData)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to create RASP agent:', error);
      throw error;
    }
  }

  /**
   * Update RASP agent
   */
  async updateAgent(agentId: string, agentData: Partial<RASPAgent>): Promise<RASPAgent> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.put(API_ENDPOINTS.RASP.AGENT(agentId), agentData)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to update RASP agent:', error);
      throw error;
    }
  }

  /**
   * Delete RASP agent
   */
  async deleteAgent(agentId: string): Promise<void> {
    try {
      await apiCallWithRetry(() => 
        apiClient.delete(API_ENDPOINTS.RASP.AGENT(agentId))
      );
    } catch (error) {
      console.error('Failed to delete RASP agent:', error);
      throw error;
    }
  }

  /**
   * Get RASP attacks
   */
  async getAttacks(agentId?: string): Promise<RAPSAttack[]> {
    try {
      const endpoint = agentId 
        ? `${API_ENDPOINTS.RASP.AGENT(agentId)}/attacks`
        : API_ENDPOINTS.RASP.ATTACKS;
      
      const response = await apiCallWithRetry(() => 
        apiClient.get(endpoint)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to fetch RASP attacks:', error);
      throw error;
    }
  }

  /**
   * Get RASP attack by ID
   */
  async getAttack(attackId: string): Promise<RAPSAttack> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.get(API_ENDPOINTS.RASP.ATTACK(attackId))
      );
      return response.data;
    } catch (error) {
      console.error('Failed to fetch RASP attack:', error);
      throw error;
    }
  }

  /**
   * Get RASP rules
   */
  async getRules(): Promise<RASPRule[]> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.get(API_ENDPOINTS.RASP.RULES)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to fetch RASP rules:', error);
      throw error;
    }
  }

  /**
   * Create a new RASP rule
   */
  async createRule(ruleData: {
    name: string;
    description: string;
    rule_type: string;
    pattern: string;
    severity: string;
    action: string;
  }): Promise<RASPRule> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.post(API_ENDPOINTS.RASP.RULES, ruleData)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to create RASP rule:', error);
      throw error;
    }
  }

  /**
   * Update RASP rule
   */
  async updateRule(ruleId: string, ruleData: Partial<RASPRule>): Promise<RASPRule> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.put(API_ENDPOINTS.RASP.RULE(ruleId), ruleData)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to update RASP rule:', error);
      throw error;
    }
  }

  /**
   * Delete RASP rule
   */
  async deleteRule(ruleId: string): Promise<void> {
    try {
      await apiCallWithRetry(() => 
        apiClient.delete(API_ENDPOINTS.RASP.RULE(ruleId))
      );
    } catch (error) {
      console.error('Failed to delete RASP rule:', error);
      throw error;
    }
  }

  /**
   * Get RASP vulnerabilities
   */
  async getVulnerabilities(agentId?: string): Promise<RAPSVulnerability[]> {
    try {
      const endpoint = agentId 
        ? `${API_ENDPOINTS.RASP.AGENT(agentId)}/vulnerabilities`
        : API_ENDPOINTS.RASP.VULNERABILITIES;
      
      const response = await apiCallWithRetry(() => 
        apiClient.get(endpoint)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to fetch RASP vulnerabilities:', error);
      throw error;
    }
  }

  /**
   * Get RASP virtual patches
   */
  async getVirtualPatches(): Promise<RAPSVirtualPatch[]> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.get(API_ENDPOINTS.RASP.VIRTUAL_PATCHES)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to fetch RASP virtual patches:', error);
      throw error;
    }
  }

  /**
   * Create a new virtual patch
   */
  async createVirtualPatch(patchData: {
    name: string;
    description: string;
    target_vulnerability: string;
    patch_type: string;
  }): Promise<RAPSVirtualPatch> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.post(API_ENDPOINTS.RASP.VIRTUAL_PATCHES, patchData)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to create virtual patch:', error);
      throw error;
    }
  }

  /**
   * Get RASP alerts
   */
  async getAlerts(agentId?: string): Promise<RAPSAlert[]> {
    try {
      const endpoint = agentId 
        ? `${API_ENDPOINTS.RASP.AGENT(agentId)}/alerts`
        : API_ENDPOINTS.RASP.ALERTS;
      
      const response = await apiCallWithRetry(() => 
        apiClient.get(endpoint)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to fetch RASP alerts:', error);
      throw error;
    }
    }

  /**
   * Acknowledge RASP alert
   */
  async acknowledgeAlert(alertId: string, acknowledgedBy: string): Promise<RAPSAlert> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.put(API_ENDPOINTS.RASP.ALERT(alertId), { 
          acknowledged: true, 
          acknowledged_by: acknowledgedBy,
          acknowledged_at: new Date().toISOString()
        })
      );
      return response.data;
    } catch (error) {
      console.error('Failed to acknowledge RASP alert:', error);
      throw error;
    }
  }

  /**
   * Get RASP dashboard overview
   */
  async getDashboardOverview(): Promise<RAPSDashboard> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.get(API_ENDPOINTS.RASP.DASHBOARD_OVERVIEW)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to fetch RASP dashboard overview:', error);
      throw error;
    }
  }

  /**
   * Get RASP attack summary
   */
  async getAttackSummary(): Promise<RAPSAttackSummary> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.get(API_ENDPOINTS.RASP.ATTACK_SUMMARY)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to fetch RASP attack summary:', error);
      throw error;
    }
  }

  /**
   * Get RASP agent status
   */
  async getAgentStatus(agentId: string): Promise<RAPSAgentStatus> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.get(API_ENDPOINTS.RASP.AGENT_STATUS(agentId))
      );
      return response.data;
    } catch (error) {
      console.error('Failed to fetch RASP agent status:', error);
      throw error;
    }
  }

  /**
   * Send heartbeat for RASP agent
   */
  async sendHeartbeat(agentId: string, heartbeatData: {
    status: string;
    memory_usage: number;
    cpu_usage: number;
    network_activity: number;
  }): Promise<void> {
    try {
      await apiCallWithRetry(() => 
        apiClient.post(API_ENDPOINTS.RASP.HEARTBEAT(agentId), heartbeatData)
      );
    } catch (error) {
      console.error('Failed to send RASP heartbeat:', error);
      throw error;
    }
  }

  /**
   * Get RASP integrations
   */
  async getIntegrations(): Promise<any[]> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.get(API_ENDPOINTS.RASP.INTEGRATIONS)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to fetch RASP integrations:', error);
      throw error;
    }
  }

  /**
   * Test RASP webhook
   */
  async testWebhook(): Promise<boolean> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.post(`${API_ENDPOINTS.RASP.WEBHOOK}/test`)
      );
      return response.data.success;
    } catch (error) {
      console.error('Failed to test RASP webhook:', error);
      throw error;
    }
  }

  /**
   * Get RASP agent performance metrics
   */
  async getAgentPerformance(agentId: string, timeframe: string = '24h'): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.get(`${API_ENDPOINTS.RASP.AGENT(agentId)}/performance`, {
          params: { timeframe }
        })
      );
      return response.data;
    } catch (error) {
      console.error('Failed to fetch RASP agent performance:', error);
      throw error;
    }
  }

  /**
   * Enable/disable RASP agent
   */
  async toggleAgentStatus(agentId: string, enabled: boolean): Promise<RASPAgent> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.put(API_ENDPOINTS.RASP.AGENT(agentId), { status: enabled ? 'active' : 'inactive' })
      );
      return response.data;
    } catch (error) {
      console.error('Failed to toggle RASP agent status:', error);
      throw error;
    }
  }

  /**
   * Get RASP agent logs
   */
  async getAgentLogs(agentId: string, level: string = 'info', limit: number = 100): Promise<any[]> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.get(`${API_ENDPOINTS.RASP.AGENT(agentId)}/logs`, {
          params: { level, limit }
        })
      );
      return response.data;
    } catch (error) {
      console.error('Failed to fetch RASP agent logs:', error);
      throw error;
    }
  }

  /**
   * Export RASP data
   */
  async exportRASPData(agentId?: string, format: 'csv' | 'json' = 'json'): Promise<Blob> {
    try {
      const endpoint = agentId 
        ? `${API_ENDPOINTS.RASP.AGENT(agentId)}/export`
        : `${API_ENDPOINTS.RASP.AGENTS}/export`;
      
      const response = await apiCallWithRetry(() => 
        apiClient.get(endpoint, {
          params: { format },
          responseType: 'blob'
        })
      );
      return response.data;
    } catch (error) {
      console.error('Failed to export RASP data:', error);
      throw error;
    }
  }
}

export const raspService = new RASPService();
export default RASPService;
