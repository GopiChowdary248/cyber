import { apiClient } from '../utils/apiClient';

export interface Role {
  id: number;
  name: string;
  description?: string;
  permissions: Permission[];
  created_at: string;
  updated_at: string;
}

export interface Permission {
  id: number;
  name: string;
  description?: string;
  resource: string;
  action: string;
  created_at: string;
}

export interface RoleCreate {
  name: string;
  description?: string;
  permission_ids: number[];
}

export interface RoleUpdate {
  name?: string;
  description?: string;
  permission_ids?: number[];
}

export interface PermissionCreate {
  name: string;
  description?: string;
  resource: string;
  action: string;
}

export interface PermissionUpdate {
  name?: string;
  description?: string;
  resource?: string;
  action?: string;
}

export interface Policy {
  id: number;
  name: string;
  description?: string;
  type: string;
  content: string;
  version: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface PolicyCreate {
  name: string;
  description?: string;
  type: string;
  content: string;
  version?: string;
  is_active?: boolean;
}

export interface PolicyUpdate {
  name?: string;
  description?: string;
  type?: string;
  content?: string;
  version?: string;
  is_active?: boolean;
}

export interface AccessControl {
  id: number;
  resource: string;
  resource_id?: number;
  role_id: number;
  permission_id: number;
  granted: boolean;
  conditions?: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface AccessControlCreate {
  resource: string;
  resource_id?: number;
  role_id: number;
  permission_id: number;
  granted: boolean;
  conditions?: Record<string, any>;
}

export interface AccessControlUpdate {
  granted?: boolean;
  conditions?: Record<string, any>;
}

export interface AuditLog {
  id: number;
  user_id: number;
  action: string;
  resource: string;
  resource_id?: number;
  details: Record<string, any>;
  ip_address?: string;
  user_agent?: string;
  timestamp: string;
}

export interface Session {
  id: string;
  user_id: number;
  ip_address?: string;
  user_agent?: string;
  created_at: string;
  last_activity: string;
  expires_at: string;
}

export interface IAMStats {
  total_roles: number;
  total_permissions: number;
  total_policies: number;
  active_policies: number;
  roles_by_permission_count: Record<string, number>;
  recent_audit_logs: AuditLog[];
  access_control_summary: Record<string, any>;
}

class IAMSecurityService {
  // Role management
  async getRoles(): Promise<Role[]> {
    const response = await apiClient.get('/iam/roles');
    return response.data;
  }

  async getRole(roleId: number): Promise<Role> {
    const response = await apiClient.get(`/iam/roles/${roleId}`);
    return response.data;
  }

  async createRole(roleData: RoleCreate): Promise<Role> {
    const response = await apiClient.post('/iam/roles', roleData);
    return response.data;
  }

  async updateRole(roleId: number, roleUpdate: RoleUpdate): Promise<Role> {
    const response = await apiClient.put(`/iam/roles/${roleId}`, roleUpdate);
    return response.data;
  }

  async deleteRole(roleId: number): Promise<{ message: string }> {
    const response = await apiClient.delete(`/iam/roles/${roleId}`);
    return response.data;
  }

  // Permission management
  async getPermissions(): Promise<Permission[]> {
    const response = await apiClient.get('/iam/permissions');
    return response.data;
  }

  async getPermission(permissionId: number): Promise<Permission> {
    const response = await apiClient.get(`/iam/permissions/${permissionId}`);
    return response.data;
  }

  async createPermission(permissionData: PermissionCreate): Promise<Permission> {
    const response = await apiClient.post('/iam/permissions', permissionData);
    return response.data;
  }

  async updatePermission(permissionId: number, permissionUpdate: PermissionUpdate): Promise<Permission> {
    const response = await apiClient.put(`/iam/permissions/${permissionId}`, permissionUpdate);
    return response.data;
  }

  async deletePermission(permissionId: number): Promise<{ message: string }> {
    const response = await apiClient.delete(`/iam/permissions/${permissionId}`);
    return response.data;
  }

  // Policy management
  async getPolicies(): Promise<Policy[]> {
    const response = await apiClient.get('/iam/policies');
    return response.data;
  }

  async getPolicy(policyId: number): Promise<Policy> {
    const response = await apiClient.get(`/iam/policies/${policyId}`);
    return response.data;
  }

  async createPolicy(policyData: PolicyCreate): Promise<Policy> {
    const response = await apiClient.post('/iam/policies', policyData);
    return response.data;
  }

  async updatePolicy(policyId: number, policyUpdate: PolicyUpdate): Promise<Policy> {
    const response = await apiClient.put(`/iam/policies/${policyId}`, policyUpdate);
    return response.data;
  }

  async deletePolicy(policyId: number): Promise<{ message: string }> {
    const response = await apiClient.delete(`/iam/policies/${policyId}`);
    return response.data;
  }

  async activatePolicy(policyId: number): Promise<{ message: string }> {
    const response = await apiClient.put(`/iam/policies/${policyId}/activate`);
    return response.data;
  }

  async deactivatePolicy(policyId: number): Promise<{ message: string }> {
    const response = await apiClient.put(`/iam/policies/${policyId}/deactivate`);
    return response.data;
  }

  // Access control management
  async getAccessControls(
    resource?: string,
    resourceId?: number,
    roleId?: number
  ): Promise<AccessControl[]> {
    const params = new URLSearchParams();
    if (resource) params.append('resource', resource);
    if (resourceId) params.append('resource_id', resourceId.toString());
    if (roleId) params.append('role_id', roleId.toString());

    const response = await apiClient.get(`/iam/access-controls?${params.toString()}`);
    return response.data;
  }

  async getAccessControl(accessControlId: number): Promise<AccessControl> {
    const response = await apiClient.get(`/iam/access-controls/${accessControlId}`);
    return response.data;
  }

  async createAccessControl(accessControlData: AccessControlCreate): Promise<AccessControl> {
    const response = await apiClient.post('/iam/access-controls', accessControlData);
    return response.data;
  }

  async updateAccessControl(accessControlId: number, accessControlUpdate: AccessControlUpdate): Promise<AccessControl> {
    const response = await apiClient.put(`/iam/access-controls/${accessControlId}`, accessControlUpdate);
    return response.data;
  }

  async deleteAccessControl(accessControlId: number): Promise<{ message: string }> {
    const response = await apiClient.delete(`/iam/access-controls/${accessControlId}`);
    return response.data;
  }

  // Audit logging
  async getAuditLogs(
    skip: number = 0,
    limit: number = 100,
    userId?: number,
    action?: string,
    resource?: string,
    dateFrom?: string,
    dateTo?: string
  ): Promise<{ audit_logs: AuditLog[]; total: number }> {
    const params = new URLSearchParams();
    params.append('skip', skip.toString());
    params.append('limit', limit.toString());
    
    if (userId) params.append('user_id', userId.toString());
    if (action) params.append('action', action);
    if (resource) params.append('resource', resource);
    if (dateFrom) params.append('date_from', dateFrom);
    if (dateTo) params.append('date_to', dateTo);

    const response = await apiClient.get(`/iam/audit-logs?${params.toString()}`);
    return response.data;
  }

  async getAuditLog(auditLogId: number): Promise<AuditLog> {
    const response = await apiClient.get(`/iam/audit-logs/${auditLogId}`);
    return response.data;
  }

  // Session management
  async getSessions(
    skip: number = 0,
    limit: number = 100,
    userId?: number,
    active?: boolean
  ): Promise<{ sessions: Session[]; total: number }> {
    const params = new URLSearchParams();
    params.append('skip', skip.toString());
    params.append('limit', limit.toString());
    
    if (userId) params.append('user_id', userId.toString());
    if (active !== undefined) params.append('active', active.toString());

    const response = await apiClient.get(`/iam/sessions?${params.toString()}`);
    return response.data;
  }

  async getSession(sessionId: string): Promise<Session> {
    const response = await apiClient.get(`/iam/sessions/${sessionId}`);
    return response.data;
  }

  async revokeSession(sessionId: string): Promise<{ message: string }> {
    const response = await apiClient.delete(`/iam/sessions/${sessionId}`);
    return response.data;
  }

  async revokeAllUserSessions(userId: number): Promise<{ message: string }> {
    const response = await apiClient.delete(`/iam/sessions/user/${userId}`);
    return response.data;
  }

  // User role management
  async getUserRoles(userId: number): Promise<Role[]> {
    const response = await apiClient.get(`/iam/users/${userId}/roles`);
    return response.data;
  }

  async assignRoleToUser(userId: number, roleId: number): Promise<{ message: string }> {
    const response = await apiClient.post(`/iam/users/${userId}/roles`, { role_id: roleId });
    return response.data;
  }

  async removeRoleFromUser(userId: number, roleId: number): Promise<{ message: string }> {
    const response = await apiClient.delete(`/iam/users/${userId}/roles/${roleId}`);
    return response.data;
  }

  async getUserPermissions(userId: number): Promise<Permission[]> {
    const response = await apiClient.get(`/iam/users/${userId}/permissions`);
    return response.data;
  }

  // Bulk operations
  async bulkAssignRoles(userIds: number[], roleIds: number[]): Promise<{ message: string; assigned_count: number }> {
    const response = await apiClient.post('/iam/bulk-assign-roles', {
      user_ids: userIds,
      role_ids: roleIds
    });
    return response.data;
  }

  async bulkRemoveRoles(userIds: number[], roleIds: number[]): Promise<{ message: string; removed_count: number }> {
    const response = await apiClient.delete('/iam/bulk-remove-roles', {
      data: { user_ids: userIds, role_ids: roleIds }
    });
    return response.data;
  }

  // Policy evaluation
  async evaluatePolicy(
    policyId: number,
    context: Record<string, any>
  ): Promise<{ allowed: boolean; reason?: string; conditions?: Record<string, any> }> {
    const response = await apiClient.post(`/iam/policies/${policyId}/evaluate`, { context });
    return response.data;
  }

  async evaluateAccess(
    resource: string,
    resourceId: number,
    userId: number,
    action: string
  ): Promise<{ allowed: boolean; reason?: string; policies_applied: string[] }> {
    const response = await apiClient.post('/iam/access/evaluate', {
      resource,
      resource_id: resourceId,
      user_id: userId,
      action
    });
    return response.data;
  }

  // Statistics and reporting
  async getIAMStats(): Promise<IAMStats> {
    const response = await apiClient.get('/iam/stats');
    return response.data;
  }

  async exportAuditLogs(
    format: 'csv' | 'json' | 'xlsx' = 'csv',
    dateFrom?: string,
    dateTo?: string
  ): Promise<Blob> {
    const params = new URLSearchParams();
    params.append('format', format);
    
    if (dateFrom) params.append('date_from', dateFrom);
    if (dateTo) params.append('date_to', dateTo);

    const response = await apiClient.get(`/iam/audit-logs/export?${params.toString()}`, {
      responseType: 'blob'
    });
    return response.data;
  }

  async generateAccessReport(
    userId?: number,
    roleId?: number,
    resource?: string
  ): Promise<{ report: Record<string, any>; generated_at: string }> {
    const params = new URLSearchParams();
    if (userId) params.append('user_id', userId.toString());
    if (roleId) params.append('role_id', roleId.toString());
    if (resource) params.append('resource', resource);

    const response = await apiClient.get(`/iam/reports/access?${params.toString()}`);
    return response.data;
  }

  // Policy templates
  async getPolicyTemplates(): Promise<{ templates: Record<string, any>[] }> {
    const response = await apiClient.get('/iam/policy-templates');
    return response.data;
  }

  async createPolicyFromTemplate(
    templateId: string,
    customizations: Record<string, any>
  ): Promise<Policy> {
    const response = await apiClient.post('/iam/policies/from-template', {
      template_id: templateId,
      customizations
    });
    return response.data;
  }

  // Compliance and validation
  async validatePolicy(policyId: number): Promise<{ valid: boolean; errors: string[]; warnings: string[] }> {
    const response = await apiClient.post(`/iam/policies/${policyId}/validate`);
    return response.data;
  }

  async checkCompliance(
    standard: string,
    scope?: string[]
  ): Promise<{ compliant: boolean; violations: Record<string, any>[]; score: number }> {
    const response = await apiClient.post('/iam/compliance/check', {
      standard,
      scope
    });
    return response.data;
  }
}

export const iamSecurityService = new IAMSecurityService();
export default iamSecurityService;
