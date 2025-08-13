import { apiClient } from '../utils/apiClient';

export interface MFASetupResponse {
  success: boolean;
  qr_code: string;
  backup_codes: string[];
  secret: string;
  setup_uri: string;
  message: string;
}

export interface MFAResponse {
  success: boolean;
  message: string;
}

export interface BackupCodesResponse {
  success: boolean;
  backup_codes: string[];
  message: string;
}

export interface MFAStatusResponse {
  enabled: boolean;
  setup_complete: boolean;
  last_used?: string;
  backup_codes_remaining: number;
}

export interface RecoveryTokenResponse {
  success: boolean;
  message: string;
  recovery_token?: string;
}

export interface RecoveryTokenValidationResponse {
  success: boolean;
  message: string;
  user_id?: number;
  email?: string;
}

class MFAService {
  // Setup MFA for the current user
  async setupMFA(): Promise<MFASetupResponse> {
    const response = await apiClient.post('/mfa/setup');
    return response.data;
  }

  // Verify MFA setup with first token
  async verifyMFASetup(token: string): Promise<MFAResponse> {
    const formData = new FormData();
    formData.append('token', token);
    
    const response = await apiClient.post('/mfa/verify-setup', formData, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });
    return response.data;
  }

  // Verify MFA token during login
  async verifyMFALogin(userId: number, token: string): Promise<MFAResponse> {
    const formData = new FormData();
    formData.append('user_id', userId.toString());
    formData.append('token', token);
    
    const response = await apiClient.post('/mfa/verify-login', formData, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });
    return response.data;
  }

  // Disable MFA
  async disableMFA(password: string): Promise<MFAResponse> {
    const formData = new FormData();
    formData.append('password', password);
    
    const response = await apiClient.post('/mfa/disable', formData, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });
    return response.data;
  }

  // Regenerate backup codes
  async regenerateBackupCodes(password: string): Promise<BackupCodesResponse> {
    const formData = new FormData();
    formData.append('password', password);
    
    const response = await apiClient.post('/mfa/regenerate-backup-codes', formData, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });
    return response.data;
  }

  // Get MFA status
  async getMFAStatus(): Promise<MFAStatusResponse> {
    const response = await apiClient.get('/mfa/status');
    return response.data;
  }

  // Generate recovery token
  async generateRecoveryToken(email: string): Promise<RecoveryTokenResponse> {
    const formData = new FormData();
    formData.append('email', email);
    
    const response = await apiClient.post('/mfa/recovery-token', formData, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });
    return response.data;
  }

  // Validate recovery token
  async validateRecoveryToken(recoveryToken: string): Promise<RecoveryTokenValidationResponse> {
    const formData = new FormData();
    formData.append('recovery_token', recoveryToken);
    
    const response = await apiClient.post('/mfa/validate-recovery-token', formData, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });
    return response.data;
  }

  // Get QR code for MFA setup
  async getQRCode(secret: string): Promise<Blob> {
    const response = await apiClient.get(`/mfa/qr-code/${secret}`, {
      responseType: 'blob',
    });
    return response.data;
  }

  // Verify backup code
  async verifyBackupCode(backupCode: string): Promise<MFAResponse> {
    const formData = new FormData();
    formData.append('backup_code', backupCode);
    
    const response = await apiClient.post('/mfa/verify-backup-code', formData, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });
    return response.data;
  }

  // Get MFA configuration options
  async getMFAConfiguration(): Promise<{
    supported_methods: string[];
    backup_code_count: number;
    qr_code_size: number;
    token_length: number;
    token_validity: number;
  }> {
    const response = await apiClient.get('/mfa/configuration');
    return response.data;
  }

  // Update MFA preferences
  async updateMFAPreferences(preferences: {
    backup_code_count?: number;
    require_backup_codes?: boolean;
    allow_remember_device?: boolean;
    remember_device_days?: number;
  }): Promise<MFAResponse> {
    const response = await apiClient.put('/mfa/preferences', preferences);
    return response.data;
  }

  // Get MFA activity log
  async getMFAActivityLog(
    skip: number = 0,
    limit: number = 50
  ): Promise<{
    activities: Array<{
      id: number;
      action: string;
      timestamp: string;
      ip_address?: string;
      user_agent?: string;
      success: boolean;
    }>;
    total: number;
  }> {
    const response = await apiClient.get('/mfa/activity-log', {
      params: { skip, limit },
    });
    return response.data;
  }

  // Export MFA backup codes
  async exportBackupCodes(format: 'txt' | 'pdf' = 'txt'): Promise<Blob> {
    const response = await apiClient.get('/mfa/export-backup-codes', {
      params: { format },
      responseType: 'blob',
    });
    return response.data;
  }

  // Import MFA backup codes
  async importBackupCodes(backupCodes: string[]): Promise<MFAResponse> {
    const response = await apiClient.post('/mfa/import-backup-codes', {
      backup_codes: backupCodes,
    });
    return response.data;
  }

  // Get MFA statistics
  async getMFAStatistics(): Promise<{
    total_users: number;
    mfa_enabled_users: number;
    mfa_setup_rate: number;
    average_setup_time: number;
    failed_attempts: number;
    successful_verifications: number;
    backup_code_usage: number;
  }> {
    const response = await apiClient.get('/mfa/statistics');
    return response.data;
  }

  // Reset MFA for user (admin only)
  async resetMFAForUser(userId: number): Promise<MFAResponse> {
    const response = await apiClient.post(`/mfa/reset/${userId}`);
    return response.data;
  }

  // Get MFA compliance report
  async getMFAComplianceReport(): Promise<{
    compliance_score: number;
    total_users: number;
    compliant_users: number;
    non_compliant_users: number;
    compliance_by_department: Record<string, number>;
    compliance_by_role: Record<string, number>;
    recommendations: string[];
  }> {
    const response = await apiClient.get('/mfa/compliance-report');
    return response.data;
  }
}

export const mfaService = new MFAService();
export default mfaService;
