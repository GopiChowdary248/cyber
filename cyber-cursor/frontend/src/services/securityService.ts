import { apiClient } from '../utils/apiClient';

// Enums matching backend schemas
export enum MFAMethod {
  TOTP = "totp",
  SMS = "sms",
  EMAIL = "email",
  BACKUP_CODES = "backup_codes"
}

export enum SecurityEventType {
  LOGIN = "login",
  LOGOUT = "logout",
  MFA_SETUP = "mfa_setup",
  MFA_VERIFY = "mfa_verify",
  PASSWORD_CHANGE = "password_change",
  ACCOUNT_LOCK = "account_lock",
  ACCOUNT_UNLOCK = "account_unlock",
  SUSPICIOUS_ACTIVITY = "suspicious_activity",
  SECURITY_VIOLATION = "security_violation"
}

export enum AccountStatus {
  ACTIVE = "active",
  LOCKED = "locked",
  SUSPENDED = "suspended",
  PENDING_VERIFICATION = "pending_verification"
}

export enum PasswordStrength {
  WEAK = "weak",
  MEDIUM = "medium",
  STRONG = "strong",
  VERY_STRONG = "very_strong"
}

// Interfaces matching backend schemas
export interface MFASetupRequest {
  method: MFAMethod;
}

export interface MFASetupResponse {
  success: boolean;
  data: {
    qr_code?: string;
    secret_key?: string;
    backup_codes?: string[];
    setup_instructions?: string;
  };
  message: string;
}

export interface MFAVerificationRequest {
  method: MFAMethod;
  code: string;
}

export interface MFAVerificationResponse {
  success: boolean;
  message: string;
}

export interface BackupCodesResponse {
  success: boolean;
  data: {
    backup_codes: string[];
  };
  message: string;
}

export interface SessionValidationRequest {
  session_token: string;
}

export interface SessionValidationResponse {
  valid: boolean;
  user_id?: number;
  expires_at?: string;
  last_activity?: string;
}

export interface SecurityEvent {
  id: string;
  user_id: number;
  event_type: SecurityEventType;
  timestamp: string;
  ip_address?: string;
  user_agent?: string;
  location?: string;
  details?: Record<string, any>;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

export interface SecurityEventsResponse {
  events: SecurityEvent[];
  total: number;
  time_range: string;
}

export interface SecurityReport {
  user_id: number;
  time_range: string;
  total_events: number;
  events_by_type: Record<SecurityEventType, number>;
  events_by_severity: Record<string, number>;
  suspicious_activities: number;
  failed_login_attempts: number;
  mfa_usage: number;
  risk_score: number;
  recommendations: string[];
}

export interface AccountSecurityStatus {
  user_id: number;
  status: AccountStatus;
  mfa_enabled: boolean;
  mfa_methods: MFAMethod[];
  last_password_change?: string;
  password_expires_in?: number;
  failed_login_attempts: number;
  account_locked_until?: string;
  suspicious_activities: number;
  risk_score: number;
  security_recommendations: string[];
}

export interface PasswordValidationRequest {
  password: string;
}

export interface PasswordValidationResponse {
  strength: PasswordStrength;
  score: number;
  feedback: string[];
  meets_requirements: boolean;
  requirements: {
    min_length: boolean;
    has_uppercase: boolean;
    has_lowercase: boolean;
    has_numbers: boolean;
    has_special_chars: boolean;
    not_common: boolean;
  };
}

export interface SecuritySummary {
  overall_risk_score: number;
  account_security: {
    status: AccountStatus;
    mfa_enabled: boolean;
    password_age_days: number;
    last_security_review?: string;
  };
  recent_activity: {
    total_events: number;
    suspicious_activities: number;
    failed_attempts: number;
    successful_logins: number;
  };
  threat_indicators: {
    suspicious_ips: number;
    unusual_locations: number;
    failed_mfa_attempts: number;
    account_lockouts: number;
  };
  recommendations: string[];
}

export interface SASTSecurityResults {
  total_vulnerabilities: number;
  critical_vulnerabilities: number;
  high_vulnerabilities: number;
  medium_vulnerabilities: number;
  low_vulnerabilities: number;
  security_rating: string;
  last_scan?: string;
  trend: 'improving' | 'stable' | 'worsening';
}

export interface DASTSecurityResults {
  total_vulnerabilities: number;
  critical_vulnerabilities: number;
  high_vulnerabilities: number;
  medium_vulnerabilities: number;
  low_vulnerabilities: number;
  risk_score: number;
  last_scan?: string;
  scan_coverage: number;
}

export interface RASPSecurityLogs {
  total_logs: number;
  security_violations: number;
  blocked_requests: number;
  suspicious_activities: number;
  last_incident?: string;
  risk_level: 'low' | 'medium' | 'high' | 'critical';
}

export interface AccountUnlockRequest {
  user_id: number;
}

export interface AccountUnlockResponse {
  success: boolean;
  message: string;
  unlocked_at?: string;
}

export interface SuspiciousActivity {
  id: string;
  type: string;
  description: string;
  timestamp: string;
  ip_address?: string;
  location?: string;
  risk_score: number;
  status: 'investigating' | 'confirmed' | 'false_positive' | 'resolved';
  details?: Record<string, any>;
}

export interface SuspiciousActivitiesResponse {
  activities: SuspiciousActivity[];
  total: number;
  high_risk_count: number;
}

class SecurityService {
  // MFA Management
  async setupMFA(method: MFAMethod): Promise<MFASetupResponse> {
    const response = await apiClient.post('/security/mfa/setup', { method });
    return response.data;
  }

  async verifyMFA(method: MFAMethod, code: string): Promise<MFAVerificationResponse> {
    const response = await apiClient.post('/security/mfa/verify', { method, code });
    return response.data;
  }

  async disableMFA(): Promise<{ success: boolean; message: string }> {
    const response = await apiClient.delete('/security/mfa/disable');
    return response.data;
  }

  async generateBackupCodes(): Promise<BackupCodesResponse> {
    const response = await apiClient.post('/security/mfa/backup-codes');
    return response.data;
  }

  // Session Management
  async validateSession(sessionToken: string): Promise<SessionValidationResponse> {
    const response = await apiClient.get('/security/session/validate', {
      params: { session_token: sessionToken }
    });
    return response.data;
  }

  async logout(sessionToken: string): Promise<{ success: boolean; message: string }> {
    const response = await apiClient.post('/security/logout', { session_token: sessionToken });
    return response.data;
  }

  // Audit and Events
  async getSecurityEvents(
    userId?: number,
    eventType?: SecurityEventType,
    timeRange: string = '24h',
    limit: number = 100
  ): Promise<SecurityEventsResponse> {
    const params: any = { time_range: timeRange, limit };
    if (userId) params.user_id = userId;
    if (eventType) params.event_type = eventType;

    const response = await apiClient.get('/security/audit/events', { params });
    return response.data;
  }

  async getSecurityReport(
    userId?: number,
    timeRange: string = '24h'
  ): Promise<SecurityReport> {
    const params: any = { time_range: timeRange };
    if (userId) params.user_id = userId;

    const response = await apiClient.get('/security/audit/report', { params });
    return response.data;
  }

  // Account Security
  async getAccountSecurityStatus(): Promise<AccountSecurityStatus> {
    const response = await apiClient.get('/security/account/status');
    return response.data;
  }

  async unlockAccount(userId: number): Promise<AccountUnlockResponse> {
    const response = await apiClient.post('/security/account/unlock', { user_id: userId });
    return response.data;
  }

  // Password Security
  async validatePasswordStrength(password: string): Promise<PasswordValidationResponse> {
    const response = await apiClient.post('/security/password/validate', { password });
    return response.data;
  }

  // Security Summary
  async getSecuritySummary(): Promise<SecuritySummary> {
    const response = await apiClient.get('/security/summary');
    return response.data;
  }

  // Security Results from Different Tools
  async getSASTSecurityResults(): Promise<SASTSecurityResults> {
    const response = await apiClient.get('/security/sast/results');
    return response.data;
  }

  async getDASTSecurityResults(): Promise<DASTSecurityResults> {
    const response = await apiClient.get('/security/dast/results');
    return response.data;
  }

  async getRASPSecurityLogs(): Promise<RASPSecurityLogs> {
    const response = await apiClient.get('/security/rasp/logs');
    return response.data;
  }

  // Threat Detection
  async getSuspiciousActivities(): Promise<SuspiciousActivitiesResponse> {
    const response = await apiClient.get('/security/threats/suspicious-activity');
    return response.data;
  }

  // Helper Methods
  async isAccountLocked(): Promise<boolean> {
    try {
      const status = await this.getAccountSecurityStatus();
      return status.status === AccountStatus.LOCKED;
    } catch (error) {
      console.error('Failed to check account status:', error);
      return false;
    }
  }

  async getRiskLevel(): Promise<'low' | 'medium' | 'high' | 'critical'> {
    try {
      const summary = await this.getSecuritySummary();
      if (summary.overall_risk_score >= 80) return 'critical';
      if (summary.overall_risk_score >= 60) return 'high';
      if (summary.overall_risk_score >= 30) return 'medium';
      return 'low';
    } catch (error) {
      console.error('Failed to get risk level:', error);
      return 'medium';
    }
  }

  async hasSuspiciousActivity(): Promise<boolean> {
    try {
      const activities = await this.getSuspiciousActivities();
      return activities.high_risk_count > 0;
    } catch (error) {
      console.error('Failed to check suspicious activities:', error);
      return false;
    }
  }

  async getSecurityRecommendations(): Promise<string[]> {
    try {
      const summary = await this.getSecuritySummary();
      return summary.recommendations;
    } catch (error) {
      console.error('Failed to get security recommendations:', error);
      return [];
    }
  }

  // Real-time Security Monitoring
  async subscribeToSecurityEvents(callback: (event: SecurityEvent) => void): Promise<void> {
    // This could be implemented with WebSocket connection
    // For now, we'll use polling
    setInterval(async () => {
      try {
        const events = await this.getSecurityEvents(undefined, undefined, '1h', 10);
        events.events.forEach(event => {
          if (event.severity === 'high' || event.severity === 'critical') {
            callback(event);
          }
        });
      } catch (error) {
        console.error('Failed to poll security events:', error);
      }
    }, 30000); // Poll every 30 seconds
  }

  // Security Health Check
  async performSecurityHealthCheck(): Promise<{
    overall_score: number;
    checks: Array<{
      name: string;
      status: 'pass' | 'fail' | 'warning';
      details: string;
      recommendation?: string;
    }>;
  }> {
    try {
      const [
        accountStatus,
        suspiciousActivities,
        securitySummary
      ] = await Promise.all([
        this.getAccountSecurityStatus(),
        this.getSuspiciousActivities(),
        this.getSecuritySummary()
      ]);

      const checks: Array<{
        name: string;
        status: 'pass' | 'fail' | 'warning';
        details: string;
        recommendation?: string;
      }> = [
        {
          name: 'Account Status',
          status: accountStatus.status === AccountStatus.ACTIVE ? 'pass' : 'fail',
          details: `Account is ${accountStatus.status}`,
          recommendation: accountStatus.status !== AccountStatus.ACTIVE ? 'Contact administrator' : undefined
        },
        {
          name: 'MFA Status',
          status: accountStatus.mfa_enabled ? 'pass' : 'warning',
          details: accountStatus.mfa_enabled ? 'MFA is enabled' : 'MFA is not enabled',
          recommendation: accountStatus.mfa_enabled ? undefined : 'Enable MFA for enhanced security'
        },
        {
          name: 'Suspicious Activities',
          status: suspiciousActivities.high_risk_count === 0 ? 'pass' : 'fail',
          details: `${suspiciousActivities.high_risk_count} high-risk activities detected`,
          recommendation: suspiciousActivities.high_risk_count > 0 ? 'Review and investigate activities' : undefined
        },
        {
          name: 'Risk Score',
          status: securitySummary.overall_risk_score < 50 ? 'pass' : 
                 securitySummary.overall_risk_score < 70 ? 'warning' : 'fail',
          details: `Risk score: ${securitySummary.overall_risk_score}`,
          recommendation: securitySummary.overall_risk_score >= 70 ? 'Immediate action required' : undefined
        }
      ];

      const overall_score = Math.max(0, 100 - securitySummary.overall_risk_score);

      return {
        overall_score,
        checks
      };
    } catch (error) {
      console.error('Failed to perform security health check:', error);
      throw new Error('Security health check failed');
    }
  }
}

export const securityService = new SecurityService();
export default securityService;
