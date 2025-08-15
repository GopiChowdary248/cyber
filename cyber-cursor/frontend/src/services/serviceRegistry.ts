import apiClient from './apiClient';
import { API_ENDPOINTS } from './comprehensiveIntegrationService';

// Retry function for API calls
export const apiCallWithRetry = async <T>(
  apiCall: () => Promise<T>,
  maxRetries: number = 3,
  delay: number = 1000
): Promise<T> => {
  let lastError: any;
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await apiCall();
    } catch (error) {
      lastError = error;
      
      if (attempt === maxRetries) {
        throw error;
      }
      
      // Wait before retrying
      await new Promise(resolve => setTimeout(resolve, delay * attempt));
    }
  }
  
  throw lastError;
};

// Unified service registry
export class ServiceRegistry {
  private static instance: ServiceRegistry;
  private apiClient: typeof apiClient;
  private endpoints: typeof API_ENDPOINTS;

  private constructor() {
    this.apiClient = apiClient;
    this.endpoints = API_ENDPOINTS;
  }

  public static getInstance(): ServiceRegistry {
    if (!ServiceRegistry.instance) {
      ServiceRegistry.instance = new ServiceRegistry();
    }
    return ServiceRegistry.instance;
  }

  // Generic API methods
  public async get<T>(url: string, config?: any): Promise<T> {
    try {
      const response = await this.apiClient.get(url, config);
      return response.data as T;
    } catch (error) {
      console.error(`GET request failed for ${url}:`, error);
      if ((error as any)?.response?.status === 404) {
        console.error(`Endpoint not found (404): ${url}`);
      }
      throw error;
    }
  }

  public async post<T>(url: string, data?: any, config?: any): Promise<T> {
    try {
      const response = await this.apiClient.post(url, data, config);
      return response.data as T;
    } catch (error) {
      console.error(`POST request failed for ${url}:`, error);
      throw error;
    }
  }

  public async put<T>(url: string, data?: any, config?: any): Promise<T> {
    try {
      const response = await this.apiClient.put(url, data, config);
      return response.data as T;
    } catch (error) {
      console.error(`PUT request failed for ${url}:`, error);
      throw error;
    }
  }

  public async delete<T>(url: string, config?: any): Promise<T> {
    try {
      const response = await this.apiClient.delete(url, config);
      return response.data as T;
    } catch (error) {
      console.error(`DELETE request failed for ${url}:`, error);
      throw error;
    }
  }

  public async patch<T>(url: string, data?: any, config?: any): Promise<T> {
    try {
      const response = await this.apiClient.patch(url, data, config);
      return response.data as T;
    } catch (error) {
      console.error(`PATCH request failed for ${url}:`, error);
      throw error;
    }
  }

  // Get endpoints
  public getEndpoints() {
    return this.endpoints;
  }

  // Get API client
  public getApiClient() {
    return this.apiClient;
  }

  // Check if user is authenticated
  public isAuthenticated(): boolean {
    const token = localStorage.getItem('access_token');
    return !!token;
  }

  // Get auth token
  public getAuthToken(): string | null {
    return localStorage.getItem('access_token');
  }

  // Clear auth data
  public clearAuth(): void {
    localStorage.removeItem('access_token');
    localStorage.removeItem('user');
  }
}

// Export singleton instance
export const serviceRegistry = ServiceRegistry.getInstance();

// Export individual methods for convenience
export const { get, post, put, delete: del, patch } = serviceRegistry;
export const { getEndpoints, isAuthenticated, getAuthToken, clearAuth } = serviceRegistry;
