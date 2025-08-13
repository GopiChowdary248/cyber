import { apiClient } from '../utils/apiClient';

export interface IAMUser {
  id: number;
  username: string;
  email: string;
  full_name: string;
  role: string;
  status: 'active' | 'inactive' | 'suspended';
  last_login?: string;
  created_at: string;
  updated_at: string;
  mfa_enabled: boolean;
  password_expires_at?: string;
}

export interface IAMUserCreate {
  username: string;
  email: string;
  full_name: string;
  password: string;
  role: string;
  department?: string;
  manager_id?: number;
}

export interface IAMRole {
  id: number;
  name: string;
  description: string;
  permissions: string[];
  created_at: string;
  updated_at: string;
}

export interface IAMPermission {
  id: number;
  name: string;
  description: string;
  resource: string;
  action: string;
  created_at: string;
}

export interface IAMGroup {
  id: number;
  name: string;
  description: string;
  members: IAMUser[];
  roles: IAMRole[];
  created_at: string;
  updated_at: string;
}

export interface IAMPolicy {
  id: number;
  name: string;
  description: string;
  type: 'access' | 'password' | 'session' | 'mfa';
  rules: any[];
  created_at: string;
  updated_at: string;
}

export interface IAMSession {
  id: string;
  user_id: number;
  ip_address: string;
  user_agent: string;
  created_at: string;
  expires_at: string;
  is_active: boolean;
}

export interface IAMAuditLog {
  id: number;
  user_id: number;
  action: string;
  resource: string;
  resource_id?: string;
  ip_address: string;
  user_agent: string;
  timestamp: string;
  details?: any;
}

export interface IAMDashboard {
  total_users: number;
  active_users: number;
  total_roles: number;
  total_groups: number;
  active_sessions: number;
  recent_logins: IAMUser[];
  recent_audit_events: IAMAuditLog[];
  mfa_adoption_rate: number;
}

class IAMService {
  // Users
  async getUsers(params?: {
    skip?: number;
    limit?: number;
    search?: string;
    role?: string;
    status?: string;
    department?: string;
  }): Promise<{ users: IAMUser[]; total: number }> {
    const response = await apiClient.get('/iam/users', { params });
    return response.data;
  }

  async getUser(userId: number): Promise<IAMUser> {
    const response = await apiClient.get(`/iam/users/${userId}`);
    return response.data;
  }

  async createUser(userData: IAMUserCreate): Promise<IAMUser> {
    const response = await apiClient.post('/iam/users', userData);
    return response.data;
  }

  async updateUser(userId: number, userData: Partial<IAMUserCreate>): Promise<IAMUser> {
    const response = await apiClient.put(`/iam/users/${userId}`, userData);
    return response.data;
  }

  async deleteUser(userId: number): Promise<void> {
    await apiClient.delete(`/iam/users/${userId}`);
  }

  async activateUser(userId: number): Promise<{ message: string }> {
    const response = await apiClient.post(`/iam/users/${userId}/activate`);
    return response.data;
  }

  async suspendUser(userId: number, reason?: string): Promise<{ message: string }> {
    const response = await apiClient.post(`/iam/users/${userId}/suspend`, { reason });
    return response.data;
  }

  async resetUserPassword(userId: number): Promise<{ message: string; temporary_password: string }> {
    const response = await apiClient.post(`/iam/users/${userId}/reset-password`);
    return response.data;
  }

  async changeUserPassword(userId: number, passwordData: {
    current_password: string;
    new_password: string;
  }): Promise<{ message: string }> {
    const response = await apiClient.post(`/iam/users/${userId}/change-password`, passwordData);
    return response.data;
  }

  // Roles
  async getRoles(params?: {
    skip?: number;
    limit?: number;
    search?: string;
  }): Promise<{ roles: IAMRole[]; total: number }> {
    const response = await apiClient.get('/iam/roles', { params });
    return response.data;
  }

  async getRole(roleId: number): Promise<IAMRole> {
    const response = await apiClient.get(`/iam/roles/${roleId}`);
    return response.data;
  }

  async createRole(roleData: {
    name: string;
    description: string;
    permissions: string[];
  }): Promise<IAMRole> {
    const response = await apiClient.post('/iam/roles', roleData);
    return response.data;
  }

  async updateRole(roleId: number, roleData: Partial<IAMRole>): Promise<IAMRole> {
    const response = await apiClient.put(`/iam/roles/${roleId}`, roleData);
    return response.data;
  }

  async deleteRole(roleId: number): Promise<void> {
    await apiClient.delete(`/iam/roles/${roleId}`);
  }

  async assignRoleToUser(userId: number, roleId: number): Promise<{ message: string }> {
    const response = await apiClient.post(`/iam/users/${userId}/roles`, { role_id: roleId });
    return response.data;
  }

  async removeRoleFromUser(userId: number, roleId: number): Promise<{ message: string }> {
    const response = await apiClient.delete(`/iam/users/${userId}/roles/${roleId}`);
    return response.data;
  }

  // Permissions
  async getPermissions(params?: {
    skip?: number;
    limit?: number;
    resource?: string;
    action?: string;
  }): Promise<{ permissions: IAMPermission[]; total: number }> {
    const response = await apiClient.get('/iam/permissions', { params });
    return response.data;
  }

  async getPermission(permissionId: number): Promise<IAMPermission> {
    const response = await apiClient.get(`/iam/permissions/${permissionId}`);
    return response.data;
  }

  // Groups
  async getGroups(params?: {
    skip?: number;
    limit?: number;
    search?: string;
  }): Promise<{ groups: IAMGroup[]; total: number }> {
    const response = await apiClient.get('/iam/groups', { params });
    return response.data;
  }

  async getGroup(groupId: number): Promise<IAMGroup> {
    const response = await apiClient.get(`/iam/groups/${groupId}`);
    return response.data;
  }

  async createGroup(groupData: {
    name: string;
    description: string;
    member_ids?: number[];
    role_ids?: number[];
  }): Promise<IAMGroup> {
    const response = await apiClient.post('/iam/groups', groupData);
    return response.data;
  }

  async updateGroup(groupId: number, groupData: Partial<IAMGroup>): Promise<IAMGroup> {
    const response = await apiClient.put(`/iam/groups/${groupId}`, groupData);
    return response.data;
  }

  async deleteGroup(groupId: number): Promise<void> {
    await apiClient.delete(`/iam/groups/${groupId}`);
  }

  async addUserToGroup(groupId: number, userId: number): Promise<{ message: string }> {
    const response = await apiClient.post(`/iam/groups/${groupId}/users`, { user_id: userId });
    return response.data;
  }

  async removeUserFromGroup(groupId: number, userId: number): Promise<{ message: string }> {
    const response = await apiClient.delete(`/iam/groups/${groupId}/users/${userId}`);
    return response.data;
  }

  // Policies
  async getPolicies(params?: {
    skip?: number;
    limit?: number;
    type?: string;
  }): Promise<{ policies: IAMPolicy[]; total: number }> {
    const response = await apiClient.get('/iam/policies', { params });
    return response.data;
  }

  async getPolicy(policyId: number): Promise<IAMPolicy> {
    const response = await apiClient.get(`/iam/policies/${policyId}`);
    return response.data;
  }

  async createPolicy(policyData: {
    name: string;
    description: string;
    type: string;
    rules: any[];
  }): Promise<IAMPolicy> {
    const response = await apiClient.post('/iam/policies', policyData);
    return response.data;
  }

  async updatePolicy(policyId: number, policyData: Partial<IAMPolicy>): Promise<IAMPolicy> {
    const response = await apiClient.put(`/iam/policies/${policyId}`, policyData);
    return response.data;
  }

  async deletePolicy(policyId: number): Promise<void> {
    await apiClient.delete(`/iam/policies/${policyId}`);
  }

  // Sessions
  async getActiveSessions(params?: {
    skip?: number;
    limit?: number;
    user_id?: number;
  }): Promise<{ sessions: IAMSession[]; total: number }> {
    const response = await apiClient.get('/iam/sessions', { params });
    return response.data;
  }

  async getSession(sessionId: string): Promise<IAMSession> {
    const response = await apiClient.get(`/iam/sessions/${sessionId}`);
    return response.data;
  }

  async terminateSession(sessionId: string): Promise<{ message: string }> {
    const response = await apiClient.post(`/iam/sessions/${sessionId}/terminate`);
    return response.data;
  }

  async terminateAllUserSessions(userId: number): Promise<{ message: string }> {
    const response = await apiClient.post(`/iam/users/${userId}/terminate-sessions`);
    return response.data;
  }

  // MFA
  async enableMFA(userId: number, mfaData: {
    mfa_type: 'totp' | 'sms' | 'email';
    phone_number?: string;
    email?: string;
  }): Promise<{ message: string; qr_code?: string; backup_codes: string[] }> {
    const response = await apiClient.post(`/iam/users/${userId}/mfa`, mfaData);
    return response.data;
  }

  async disableMFA(userId: number): Promise<{ message: string }> {
    const response = await apiClient.delete(`/iam/users/${userId}/mfa`);
    return response.data;
  }

  async verifyMFAToken(userId: number, token: string): Promise<{ message: string }> {
    const response = await apiClient.post(`/iam/users/${userId}/mfa/verify`, { token });
    return response.data;
  }

  // Audit Logs
  async getAuditLogs(params?: {
    skip?: number;
    limit?: number;
    user_id?: number;
    action?: string;
    resource?: string;
    date_from?: string;
    date_to?: string;
  }): Promise<{ logs: IAMAuditLog[]; total: number }> {
    const response = await apiClient.get('/iam/audit-logs', { params });
    return response.data;
  }

  async getAuditLog(logId: number): Promise<IAMAuditLog> {
    const response = await apiClient.get(`/iam/audit-logs/${logId}`);
    return response.data;
  }

  async exportAuditLogs(params?: {
    format: 'csv' | 'json' | 'pdf';
    date_from?: string;
    date_to?: string;
  }): Promise<{ download_url: string }> {
    const response = await apiClient.post('/iam/audit-logs/export', params);
    return response.data;
  }

  // Dashboard
  async getDashboard(): Promise<IAMDashboard> {
    const response = await apiClient.get('/iam/dashboard');
    return response.data;
  }

  // Access Reviews
  async createAccessReview(reviewData: {
    name: string;
    description: string;
    reviewers: number[];
    scope: {
      users?: number[];
      groups?: number[];
      roles?: number[];
    };
    due_date: string;
  }): Promise<{ review_id: number; message: string }> {
    const response = await apiClient.post('/iam/access-reviews', reviewData);
    return response.data;
  }

  async getAccessReviews(params?: {
    skip?: number;
    limit?: number;
    status?: string;
  }): Promise<{ reviews: any[]; total: number }> {
    const response = await apiClient.get('/iam/access-reviews', { params });
    return response.data;
  }

  async submitAccessReviewResponse(reviewId: number, responseData: {
    user_id: number;
    approved: boolean;
    comments?: string;
  }): Promise<{ message: string }> {
    const response = await apiClient.post(`/iam/access-reviews/${reviewId}/responses`, responseData);
    return response.data;
  }

  // Compliance
  async getComplianceReport(params?: {
    framework: string;
    date_from?: string;
    date_to?: string;
  }): Promise<any> {
    const response = await apiClient.get('/iam/compliance', { params });
    return response.data;
  }

  async runComplianceCheck(framework: string): Promise<{ check_id: string; message: string }> {
    const response = await apiClient.post('/iam/compliance/check', { framework });
    return response.data;
  }
}

export const iamService = new IAMService();
export default iamService;
