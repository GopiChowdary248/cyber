import { apiClient } from '../utils/apiClient';

export interface LoginRequest {
  username: string;
  password: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  user_id: number;
  email: string;
  role: string;
  mfa_required: boolean;
}

export interface UserCreate {
  email: string;
  username: string;
  password: string;
  full_name?: string;
  role?: string;
}

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

export interface PasswordChange {
  current_password: string;
  new_password: string;
}

export interface PasswordReset {
  email: string;
}

export interface PasswordResetConfirm {
  token: string;
  new_password: string;
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

class AuthService {
  // Login
  async login(credentials: LoginRequest): Promise<TokenResponse> {
    const response = await apiClient.post('/auth/login', credentials);
    return response.data;
  }

  // OAuth2 login
  async loginOAuth(username: string, password: string): Promise<TokenResponse> {
    const formData = new FormData();
    formData.append('username', username);
    formData.append('password', password);
    
    const response = await apiClient.post('/auth/login/oauth', formData, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });
    return response.data;
  }

  // Register
  async register(userData: UserCreate): Promise<User> {
    const response = await apiClient.post('/auth/register', userData);
    return response.data;
  }

  // Refresh token
  async refreshToken(): Promise<TokenResponse> {
    const response = await apiClient.post('/auth/refresh');
    return response.data;
  }

  // Change password
  async changePassword(passwordData: PasswordChange): Promise<{ message: string }> {
    const response = await apiClient.post('/auth/change-password', passwordData);
    return response.data;
  }

  // Forgot password
  async forgotPassword(email: string): Promise<{ message: string }> {
    const response = await apiClient.post('/auth/forgot-password', { email });
    return response.data;
  }

  // Reset password
  async resetPassword(resetData: PasswordResetConfirm): Promise<{ message: string }> {
    const response = await apiClient.post('/auth/reset-password', resetData);
    return response.data;
  }

  // Get current user info
  async getCurrentUser(): Promise<User> {
    const response = await apiClient.get('/auth/me');
    return response.data;
  }

  // Logout
  async logout(): Promise<{ message: string }> {
    const response = await apiClient.post('/auth/logout');
    return response.data;
  }

  // Logout all sessions
  async logoutAllSessions(): Promise<{ message: string }> {
    const response = await apiClient.post('/auth/logout-all');
    return response.data;
  }

  // Store auth token
  setAuthToken(token: string): void {
    localStorage.setItem('authToken', token);
  }

  // Get auth token
  getAuthToken(): string | null {
    return localStorage.getItem('authToken');
  }

  // Remove auth token
  removeAuthToken(): void {
    localStorage.removeItem('authToken');
  }

  // Check if user is authenticated
  isAuthenticated(): boolean {
    return !!this.getAuthToken();
  }

  // Get user role
  getUserRole(): string | null {
    const user = localStorage.getItem('user');
    if (user) {
      try {
        const userData = JSON.parse(user);
        return userData.role;
      } catch {
        return null;
      }
    }
    return null;
  }

  // Check if user is admin
  isAdmin(): boolean {
    const role = this.getUserRole();
    return role === 'admin';
  }

  // Check if user is analyst
  isAnalyst(): boolean {
    const role = this.getUserRole();
    return role === 'analyst' || role === 'admin';
  }

  // Store user data
  setUserData(user: User): void {
    localStorage.setItem('user', JSON.stringify(user));
  }

  // Get user data
  getUserData(): User | null {
    const user = localStorage.getItem('user');
    if (user) {
      try {
        return JSON.parse(user);
      } catch {
        return null;
      }
    }
    return null;
  }

  // Clear all auth data
  clearAuthData(): void {
    localStorage.removeItem('authToken');
    localStorage.removeItem('user');
  }
}

export const authService = new AuthService();
export default authService;
