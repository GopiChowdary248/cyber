import React, { createContext, useContext, useEffect, useState } from 'react';
import AsyncStorage from '@react-native-async-storage/async-storage';
import EncryptedStorage from 'react-native-encrypted-storage';
import { Alert } from 'react-native';
import { BiometricService } from '../services/BiometricService';
import { SecurityService } from '../services/SecurityService';
import { API_URL } from '../config/api';

interface User {
  id: number;
  email: string;
  username: string;
  role: 'admin' | 'user';
  first_name: string;
  last_name: string;
  is_active: boolean;
  mfa_enabled: boolean;
  last_login: string;
  created_at: string;
}

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<boolean>;
  register: (userData: RegisterData) => Promise<boolean>;
  logout: () => Promise<void>;
  setupMFA: () => Promise<boolean>;
  verifyMFA: (token: string) => Promise<boolean>;
  refreshToken: () => Promise<boolean>;
  biometricLogin: () => Promise<boolean>;
  updateProfile: (data: Partial<User>) => Promise<boolean>;
  changePassword: (currentPassword: string, newPassword: string) => Promise<boolean>;
}

interface RegisterData {
  email: string;
  password: string;
  username: string;
  first_name: string;
  last_name: string;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [refreshToken, setRefreshToken] = useState<string | null>(null);

  useEffect(() => {
    initializeAuth();
  }, []);

  const initializeAuth = async () => {
    try {
      // Check for stored tokens
      const storedAccessToken = await EncryptedStorage.getItem('access_token');
      const storedRefreshToken = await EncryptedStorage.getItem('refresh_token');
      const storedUser = await AsyncStorage.getItem('user');

      if (storedAccessToken && storedRefreshToken && storedUser) {
        setAccessToken(storedAccessToken);
        setRefreshToken(storedRefreshToken);
        setUser(JSON.parse(storedUser));
        setIsAuthenticated(true);

        // Verify token validity
        const isValid = await verifyToken(storedAccessToken);
        if (!isValid) {
          // Try to refresh token
          const refreshSuccess = await refreshTokenFromServer(storedRefreshToken);
          if (!refreshSuccess) {
            await clearAuthData();
          }
        }
      }
    } catch (error) {
      console.error('Auth initialization error:', error);
      await clearAuthData();
    } finally {
      setIsLoading(false);
    }
  };

  const verifyToken = async (token: string): Promise<boolean> => {
    try {
      const response = await fetch(`${API_URL}/api/v1/auth/verify`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });
      return response.ok;
    } catch (error) {
      console.error('Token verification error:', error);
      return false;
    }
  };

  const refreshTokenFromServer = async (refreshToken: string): Promise<boolean> => {
    try {
      const response = await fetch(`${API_URL}/api/v1/auth/refresh`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ refresh_token: refreshToken }),
      });

      if (response.ok) {
        const data = await response.json();
        await storeTokens(data.access_token, data.refresh_token);
        setAccessToken(data.access_token);
        setRefreshToken(data.refresh_token);
        return true;
      }
      return false;
    } catch (error) {
      console.error('Token refresh error:', error);
      return false;
    }
  };

  const storeTokens = async (accessToken: string, refreshToken: string) => {
    try {
      await EncryptedStorage.setItem('access_token', accessToken);
      await EncryptedStorage.setItem('refresh_token', refreshToken);
    } catch (error) {
      console.error('Error storing tokens:', error);
    }
  };

  const clearAuthData = async () => {
    try {
      await EncryptedStorage.removeItem('access_token');
      await EncryptedStorage.removeItem('refresh_token');
      await AsyncStorage.removeItem('user');
      setUser(null);
      setAccessToken(null);
      setRefreshToken(null);
      setIsAuthenticated(false);
    } catch (error) {
      console.error('Error clearing auth data:', error);
    }
  };

  const login = async (email: string, password: string): Promise<boolean> => {
    try {
      setIsLoading(true);

      // Check device security before login
      const securityStatus = await SecurityService.checkDeviceSecurity();
      if (!securityStatus.isSecure) {
        Alert.alert(
          'Security Warning',
          'Your device may not be secure. Please enable device security features.',
          [{ text: 'OK' }]
        );
      }

      const response = await fetch(`${API_URL}/api/v1/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
      });

      if (response.ok) {
        const data = await response.json();
        
        // Store tokens securely
        await storeTokens(data.access_token, data.refresh_token);
        
        // Store user data
        await AsyncStorage.setItem('user', JSON.stringify(data.user));
        
        setUser(data.user);
        setAccessToken(data.access_token);
        setRefreshToken(data.refresh_token);
        setIsAuthenticated(true);

        // Log successful login
        await SecurityService.logSecurityEvent('login_success', {
          email,
          timestamp: new Date().toISOString(),
          device_info: await SecurityService.getDeviceInfo(),
        });

        return true;
      } else {
        const errorData = await response.json();
        Alert.alert('Login Failed', errorData.detail || 'Invalid credentials');
        
        // Log failed login attempt
        await SecurityService.logSecurityEvent('login_failed', {
          email,
          timestamp: new Date().toISOString(),
          reason: errorData.detail,
        });

        return false;
      }
    } catch (error) {
      console.error('Login error:', error);
      Alert.alert('Login Error', 'Network error. Please try again.');
      return false;
    } finally {
      setIsLoading(false);
    }
  };

  const register = async (userData: RegisterData): Promise<boolean> => {
    try {
      setIsLoading(true);

      const response = await fetch(`${API_URL}/api/v1/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(userData),
      });

      if (response.ok) {
        const data = await response.json();
        Alert.alert('Registration Successful', 'Please check your email to verify your account.');
        return true;
      } else {
        const errorData = await response.json();
        Alert.alert('Registration Failed', errorData.detail || 'Registration failed');
        return false;
      }
    } catch (error) {
      console.error('Registration error:', error);
      Alert.alert('Registration Error', 'Network error. Please try again.');
      return false;
    } finally {
      setIsLoading(false);
    }
  };

  const logout = async (): Promise<void> => {
    try {
      // Log logout event
      await SecurityService.logSecurityEvent('logout', {
        user_id: user?.id,
        timestamp: new Date().toISOString(),
      });

      // Clear all auth data
      await clearAuthData();
    } catch (error) {
      console.error('Logout error:', error);
    }
  };

  const setupMFA = async (): Promise<boolean> => {
    try {
      if (!accessToken) return false;

      const response = await fetch(`${API_URL}/api/v1/mfa/setup`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
      });

      if (response.ok) {
        const data = await response.json();
        Alert.alert('MFA Setup', 'MFA has been enabled for your account.');
        
        // Update user data
        if (user) {
          const updatedUser = { ...user, mfa_enabled: true };
          setUser(updatedUser);
          await AsyncStorage.setItem('user', JSON.stringify(updatedUser));
        }

        return true;
      } else {
        const errorData = await response.json();
        Alert.alert('MFA Setup Failed', errorData.detail || 'Failed to setup MFA');
        return false;
      }
    } catch (error) {
      console.error('MFA setup error:', error);
      Alert.alert('MFA Setup Error', 'Network error. Please try again.');
      return false;
    }
  };

  const verifyMFA = async (token: string): Promise<boolean> => {
    try {
      if (!accessToken) return false;

      const response = await fetch(`${API_URL}/api/v1/mfa/verify`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ token }),
      });

      if (response.ok) {
        Alert.alert('MFA Verification', 'MFA verification successful.');
        return true;
      } else {
        const errorData = await response.json();
        Alert.alert('MFA Verification Failed', errorData.detail || 'Invalid MFA token');
        return false;
      }
    } catch (error) {
      console.error('MFA verification error:', error);
      Alert.alert('MFA Verification Error', 'Network error. Please try again.');
      return false;
    }
  };

  const refreshToken = async (): Promise<boolean> => {
    if (!refreshToken) return false;
    return await refreshTokenFromServer(refreshToken);
  };

  const biometricLogin = async (): Promise<boolean> => {
    try {
      // Check if biometric authentication is available
      const biometricStatus = await BiometricService.isBiometricAvailable();
      if (!biometricStatus.available) {
        Alert.alert('Biometric Unavailable', 'Biometric authentication is not available on this device.');
        return false;
      }

      // Authenticate with biometrics
      const biometricResult = await BiometricService.authenticate();
      if (!biometricResult.success) {
        Alert.alert('Biometric Authentication Failed', 'Please try again or use your password.');
        return false;
      }

      // Retrieve stored credentials
      const storedCredentials = await EncryptedStorage.getItem('biometric_credentials');
      if (!storedCredentials) {
        Alert.alert('No Stored Credentials', 'Please login with your password first to enable biometric login.');
        return false;
      }

      const credentials = JSON.parse(storedCredentials);
      
      // Attempt login with stored credentials
      const loginSuccess = await login(credentials.email, credentials.password);
      
      if (loginSuccess) {
        Alert.alert('Biometric Login', 'Login successful using biometric authentication.');
      }

      return loginSuccess;
    } catch (error) {
      console.error('Biometric login error:', error);
      Alert.alert('Biometric Login Error', 'An error occurred during biometric authentication.');
      return false;
    }
  };

  const updateProfile = async (data: Partial<User>): Promise<boolean> => {
    try {
      if (!accessToken) return false;

      const response = await fetch(`${API_URL}/api/v1/users/profile`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
      });

      if (response.ok) {
        const updatedUser = await response.json();
        setUser(updatedUser);
        await AsyncStorage.setItem('user', JSON.stringify(updatedUser));
        Alert.alert('Profile Updated', 'Your profile has been updated successfully.');
        return true;
      } else {
        const errorData = await response.json();
        Alert.alert('Update Failed', errorData.detail || 'Failed to update profile');
        return false;
      }
    } catch (error) {
      console.error('Profile update error:', error);
      Alert.alert('Update Error', 'Network error. Please try again.');
      return false;
    }
  };

  const changePassword = async (currentPassword: string, newPassword: string): Promise<boolean> => {
    try {
      if (!accessToken) return false;

      const response = await fetch(`${API_URL}/api/v1/auth/change-password`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          current_password: currentPassword,
          new_password: newPassword,
        }),
      });

      if (response.ok) {
        Alert.alert('Password Changed', 'Your password has been changed successfully.');
        
        // Log password change event
        await SecurityService.logSecurityEvent('password_changed', {
          user_id: user?.id,
          timestamp: new Date().toISOString(),
        });

        return true;
      } else {
        const errorData = await response.json();
        Alert.alert('Password Change Failed', errorData.detail || 'Failed to change password');
        return false;
      }
    } catch (error) {
      console.error('Password change error:', error);
      Alert.alert('Password Change Error', 'Network error. Please try again.');
      return false;
    }
  };

  const value: AuthContextType = {
    user,
    isAuthenticated,
    isLoading,
    login,
    register,
    logout,
    setupMFA,
    verifyMFA,
    refreshToken,
    biometricLogin,
    updateProfile,
    changePassword,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}; 