import { apiClient } from '../utils/apiClient';

export interface User {
  id: number;
  email: string;
  username: string;
  full_name?: string;
  role: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface UserCreate {
  email: string;
  username: string;
  password: string;
  full_name?: string;
  role?: string;
  is_active?: boolean;
}

export interface UserUpdate {
  email?: string;
  username?: string;
  full_name?: string;
  role?: string;
  is_active?: boolean;
}

export interface UserResponse {
  id: number;
  email: string;
  username: string;
  full_name?: string;
  role: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface UserListResponse {
  users: UserResponse[];
  total: number;
  skip: number;
  limit: number;
}

export interface UserFilter {
  role?: string;
  is_active?: boolean;
  search?: string;
  date_from?: string;
  date_to?: string;
}

export interface UserStats {
  total_users: number;
  active_users: number;
  inactive_users: number;
  users_by_role: Record<string, number>;
  recent_registrations: UserResponse[];
  user_activity: Record<string, any>[];
}

class UserService {
  // Get current user info
  async getCurrentUser(): Promise<UserResponse> {
    const response = await apiClient.get('/users/me');
    return response.data;
  }

  // Update current user
  async updateCurrentUser(userUpdate: UserUpdate): Promise<UserResponse> {
    const response = await apiClient.put('/users/me', userUpdate);
    return response.data;
  }

  // Get all users (admin only)
  async getUsers(
    skip: number = 0,
    limit: number = 100,
    filter?: UserFilter
  ): Promise<UserListResponse> {
    const params = new URLSearchParams();
    params.append('skip', skip.toString());
    params.append('limit', limit.toString());
    
    if (filter?.role) params.append('role', filter.role);
    if (filter?.is_active !== undefined) params.append('is_active', filter.is_active.toString());
    if (filter?.search) params.append('search', filter.search);
    if (filter?.date_from) params.append('date_from', filter.date_from);
    if (filter?.date_to) params.append('date_to', filter.date_to);

    const response = await apiClient.get(`/users/?${params.toString()}`);
    return response.data;
  }

  // Get user by ID (admin only)
  async getUser(userId: number): Promise<UserResponse> {
    const response = await apiClient.get(`/users/${userId}`);
    return response.data;
  }

  // Create user (admin only)
  async createUser(userData: UserCreate): Promise<UserResponse> {
    const response = await apiClient.post('/users/', userData);
    return response.data;
  }

  // Update user (admin only)
  async updateUser(userId: number, userUpdate: UserUpdate): Promise<UserResponse> {
    const response = await apiClient.put(`/users/${userId}`, userUpdate);
    return response.data;
  }

  // Delete user (admin only)
  async deleteUser(userId: number): Promise<{ message: string }> {
    const response = await apiClient.delete(`/users/${userId}`);
    return response.data;
  }

  // Get user statistics (admin only)
  async getUserStats(): Promise<UserStats> {
    const response = await apiClient.get('/users/stats');
    return response.data;
  }

  // Bulk update users (admin only)
  async bulkUpdateUsers(
    userIds: number[],
    updates: UserUpdate
  ): Promise<{ message: string; updated_count: number }> {
    const response = await apiClient.put('/users/bulk-update', {
      user_ids: userIds,
      updates
    });
    return response.data;
  }

  // Bulk delete users (admin only)
  async bulkDeleteUsers(userIds: number[]): Promise<{ message: string; deleted_count: number }> {
    const response = await apiClient.delete('/users/bulk-delete', {
      data: { user_ids: userIds }
    });
    return response.data;
  }

  // Export users (admin only)
  async exportUsers(
    format: 'csv' | 'json' | 'xlsx' = 'csv',
    filter?: UserFilter
  ): Promise<Blob> {
    const params = new URLSearchParams();
    params.append('format', format);
    
    if (filter?.role) params.append('role', filter.role);
    if (filter?.is_active !== undefined) params.append('is_active', filter.is_active.toString());
    if (filter?.search) params.append('search', filter.search);

    const response = await apiClient.get(`/users/export?${params.toString()}`, {
      responseType: 'blob'
    });
    return response.data;
  }

  // Import users (admin only)
  async importUsers(file: File): Promise<{ message: string; imported_count: number; errors: string[] }> {
    const formData = new FormData();
    formData.append('file', file);

    const response = await apiClient.post('/users/import', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  }

  // Get user activity (admin only)
  async getUserActivity(
    userId: number,
    skip: number = 0,
    limit: number = 100
  ): Promise<{ activities: Record<string, any>[]; total: number }> {
    const response = await apiClient.get(`/users/${userId}/activity?skip=${skip}&limit=${limit}`);
    return response.data;
  }

  // Get user permissions (admin only)
  async getUserPermissions(userId: number): Promise<{ permissions: string[]; roles: string[] }> {
    const response = await apiClient.get(`/users/${userId}/permissions`);
    return response.data;
  }

  // Update user permissions (admin only)
  async updateUserPermissions(
    userId: number,
    permissions: string[],
    roles: string[]
  ): Promise<{ message: string }> {
    const response = await apiClient.put(`/users/${userId}/permissions`, {
      permissions,
      roles
    });
    return response.data;
  }

  // Get user sessions (admin only)
  async getUserSessions(userId: number): Promise<{ sessions: Record<string, any>[]; total: number }> {
    const response = await apiClient.get(`/users/${userId}/sessions`);
    return response.data;
  }

  // Revoke user session (admin only)
  async revokeUserSession(userId: number, sessionId: string): Promise<{ message: string }> {
    const response = await apiClient.delete(`/users/${userId}/sessions/${sessionId}`);
    return response.data;
  }

  // Revoke all user sessions (admin only)
  async revokeAllUserSessions(userId: number): Promise<{ message: string }> {
    const response = await apiClient.delete(`/users/${userId}/sessions`);
    return response.data;
  }

  // Get user audit log (admin only)
  async getUserAuditLog(
    userId: number,
    skip: number = 0,
    limit: number = 100
  ): Promise<{ audit_logs: Record<string, any>[]; total: number }> {
    const response = await apiClient.get(`/users/${userId}/audit-log?skip=${skip}&limit=${limit}`);
    return response.data;
  }

  // Search users (admin only)
  async searchUsers(
    query: string,
    skip: number = 0,
    limit: number = 100
  ): Promise<UserListResponse> {
    const response = await apiClient.get(`/users/search?q=${encodeURIComponent(query)}&skip=${skip}&limit=${limit}`);
    return response.data;
  }

  // Get users by role (admin only)
  async getUsersByRole(
    role: string,
    skip: number = 0,
    limit: number = 100
  ): Promise<UserListResponse> {
    const response = await apiClient.get(`/users/role/${role}?skip=${skip}&limit=${limit}`);
    return response.data;
  }

  // Get active users count (admin only)
  async getActiveUsersCount(): Promise<{ count: number }> {
    const response = await apiClient.get('/users/active/count');
    return response.data;
  }

  // Get users created in date range (admin only)
  async getUsersByDateRange(
    dateFrom: string,
    dateTo: string,
    skip: number = 0,
    limit: number = 100
  ): Promise<UserListResponse> {
    const response = await apiClient.get(`/users/date-range?date_from=${dateFrom}&date_to=${dateTo}&skip=${skip}&limit=${limit}`);
    return response.data;
  }
}

export const userService = new UserService();
export default userService;
