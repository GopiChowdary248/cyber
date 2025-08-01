import ReactNativeBiometrics, { BiometryTypes } from 'react-native-biometrics';
import { Platform, Alert } from 'react-native';
import EncryptedStorage from 'react-native-encrypted-storage';
import { securityService } from './SecurityService';

interface BiometricStatus {
  available: boolean;
  type: BiometryTypes | null;
  error: string | null;
}

interface BiometricResult {
  success: boolean;
  error?: string;
  data?: any;
}

class BiometricService {
  private static instance: BiometricService;
  private rnBiometrics: ReactNativeBiometrics;
  private isInitialized = false;

  constructor() {
    this.rnBiometrics = new ReactNativeBiometrics();
  }

  static getInstance(): BiometricService {
    if (!BiometricService.instance) {
      BiometricService.instance = new BiometricService();
    }
    return BiometricService.instance;
  }

  async initialize(): Promise<void> {
    if (this.isInitialized) return;

    try {
      // Check if biometric hardware is available
      const { available, biometryType } = await this.rnBiometrics.isSensorAvailable();
      
      if (available) {
        console.log('Biometric sensor available:', biometryType);
        
        // Log biometric availability
        await securityService.logSecurityEvent('biometric_available', {
          type: biometryType,
          platform: Platform.OS,
        }, 'low');
      } else {
        console.log('Biometric sensor not available');
      }

      this.isInitialized = true;
    } catch (error) {
      console.error('BiometricService initialization error:', error);
      throw error;
    }
  }

  async isBiometricAvailable(): Promise<BiometricStatus> {
    try {
      const { available, biometryType } = await this.rnBiometrics.isSensorAvailable();
      
      return {
        available,
        type: biometryType,
        error: null,
      };
    } catch (error) {
      console.error('Check biometric availability error:', error);
      return {
        available: false,
        type: null,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  async authenticate(promptMessage?: string): Promise<BiometricResult> {
    try {
      const message = promptMessage || 'Please authenticate to continue';
      
      const { success, error } = await this.rnBiometrics.simplePrompt({
        promptMessage: message,
        cancelButtonText: 'Cancel',
      });

      if (success) {
        // Log successful authentication
        await securityService.logSecurityEvent('biometric_auth_success', {
          timestamp: new Date().toISOString(),
        }, 'low');

        return { success: true };
      } else {
        // Log failed authentication
        await securityService.logSecurityEvent('biometric_auth_failed', {
          error: error || 'User cancelled',
          timestamp: new Date().toISOString(),
        }, 'medium');

        return {
          success: false,
          error: error || 'Authentication failed',
        };
      }
    } catch (error) {
      console.error('Biometric authentication error:', error);
      
      await securityService.logSecurityEvent('biometric_auth_error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      }, 'high');

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Authentication error',
      };
    }
  }

  async createKeys(): Promise<BiometricResult> {
    try {
      const { publicKey } = await this.rnBiometrics.createKeys();
      
      // Store public key securely
      await EncryptedStorage.setItem('biometric_public_key', publicKey);
      
      // Log key creation
      await securityService.logSecurityEvent('biometric_keys_created', {
        timestamp: new Date().toISOString(),
      }, 'low');

      return {
        success: true,
        data: { publicKey },
      };
    } catch (error) {
      console.error('Create biometric keys error:', error);
      
      await securityService.logSecurityEvent('biometric_keys_error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      }, 'high');

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to create keys',
      };
    }
  }

  async deleteKeys(): Promise<BiometricResult> {
    try {
      await this.rnBiometrics.deleteKeys();
      
      // Remove stored public key
      await EncryptedStorage.removeItem('biometric_public_key');
      
      // Log key deletion
      await securityService.logSecurityEvent('biometric_keys_deleted', {
        timestamp: new Date().toISOString(),
      }, 'low');

      return { success: true };
    } catch (error) {
      console.error('Delete biometric keys error:', error);
      
      await securityService.logSecurityEvent('biometric_keys_deletion_error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      }, 'medium');

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to delete keys',
      };
    }
  }

  async signData(data: string): Promise<BiometricResult> {
    try {
      const { success, signature, error } = await this.rnBiometrics.createSignature({
        promptMessage: 'Sign data with biometric',
        payload: data,
      });

      if (success && signature) {
        // Log successful signature
        await securityService.logSecurityEvent('biometric_signature_created', {
          timestamp: new Date().toISOString(),
        }, 'low');

        return {
          success: true,
          data: { signature },
        };
      } else {
        // Log failed signature
        await securityService.logSecurityEvent('biometric_signature_failed', {
          error: error || 'Signature failed',
          timestamp: new Date().toISOString(),
        }, 'medium');

        return {
          success: false,
          error: error || 'Signature failed',
        };
      }
    } catch (error) {
      console.error('Sign data error:', error);
      
      await securityService.logSecurityEvent('biometric_signature_error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      }, 'high');

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Signing error',
      };
    }
  }

  async verifySignature(data: string, signature: string): Promise<BiometricResult> {
    try {
      const { success, error } = await this.rnBiometrics.verifySignature({
        payload: data,
        signature: signature,
      });

      if (success) {
        // Log successful verification
        await securityService.logSecurityEvent('biometric_signature_verified', {
          timestamp: new Date().toISOString(),
        }, 'low');

        return { success: true };
      } else {
        // Log failed verification
        await securityService.logSecurityEvent('biometric_signature_verification_failed', {
          error: error || 'Verification failed',
          timestamp: new Date().toISOString(),
        }, 'medium');

        return {
          success: false,
          error: error || 'Verification failed',
        };
      }
    } catch (error) {
      console.error('Verify signature error:', error);
      
      await securityService.logSecurityEvent('biometric_signature_verification_error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      }, 'high');

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Verification error',
      };
    }
  }

  async storeCredentials(email: string, password: string): Promise<BiometricResult> {
    try {
      // First authenticate with biometrics
      const authResult = await this.authenticate('Authenticate to store credentials');
      
      if (!authResult.success) {
        return authResult;
      }

      // Encrypt credentials
      const credentials = {
        email,
        password,
        timestamp: new Date().toISOString(),
      };

      const encryptedCredentials = await securityService.encryptData(
        JSON.stringify(credentials),
        'biometric_credentials_key'
      );

      // Store encrypted credentials
      await EncryptedStorage.setItem('biometric_credentials', encryptedCredentials);
      
      // Log credential storage
      await securityService.logSecurityEvent('biometric_credentials_stored', {
        timestamp: new Date().toISOString(),
      }, 'low');

      return { success: true };
    } catch (error) {
      console.error('Store credentials error:', error);
      
      await securityService.logSecurityEvent('biometric_credentials_storage_error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      }, 'high');

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to store credentials',
      };
    }
  }

  async retrieveCredentials(): Promise<BiometricResult> {
    try {
      // First authenticate with biometrics
      const authResult = await this.authenticate('Authenticate to retrieve credentials');
      
      if (!authResult.success) {
        return authResult;
      }

      // Retrieve encrypted credentials
      const encryptedCredentials = await EncryptedStorage.getItem('biometric_credentials');
      
      if (!encryptedCredentials) {
        return {
          success: false,
          error: 'No stored credentials found',
        };
      }

      // Decrypt credentials
      const decryptedCredentials = await securityService.decryptData(
        encryptedCredentials,
        'biometric_credentials_key'
      );

      const credentials = JSON.parse(decryptedCredentials);
      
      // Log credential retrieval
      await securityService.logSecurityEvent('biometric_credentials_retrieved', {
        timestamp: new Date().toISOString(),
      }, 'low');

      return {
        success: true,
        data: credentials,
      };
    } catch (error) {
      console.error('Retrieve credentials error:', error);
      
      await securityService.logSecurityEvent('biometric_credentials_retrieval_error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      }, 'high');

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to retrieve credentials',
      };
    }
  }

  async removeCredentials(): Promise<BiometricResult> {
    try {
      // First authenticate with biometrics
      const authResult = await this.authenticate('Authenticate to remove credentials');
      
      if (!authResult.success) {
        return authResult;
      }

      // Remove stored credentials
      await EncryptedStorage.removeItem('biometric_credentials');
      
      // Log credential removal
      await securityService.logSecurityEvent('biometric_credentials_removed', {
        timestamp: new Date().toISOString(),
      }, 'low');

      return { success: true };
    } catch (error) {
      console.error('Remove credentials error:', error);
      
      await securityService.logSecurityEvent('biometric_credentials_removal_error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      }, 'medium');

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to remove credentials',
      };
    }
  }

  async hasStoredCredentials(): Promise<boolean> {
    try {
      const credentials = await EncryptedStorage.getItem('biometric_credentials');
      return credentials !== null;
    } catch (error) {
      console.error('Check stored credentials error:', error);
      return false;
    }
  }

  async getBiometricType(): Promise<BiometryTypes | null> {
    try {
      const { available, biometryType } = await this.rnBiometrics.isSensorAvailable();
      return available ? biometryType : null;
    } catch (error) {
      console.error('Get biometric type error:', error);
      return null;
    }
  }

  async isHardwareSupported(): Promise<boolean> {
    try {
      const { available } = await this.rnBiometrics.isSensorAvailable();
      return available;
    } catch (error) {
      console.error('Check hardware support error:', error);
      return false;
    }
  }

  async isEnrolled(): Promise<boolean> {
    try {
      const { available } = await this.rnBiometrics.isSensorAvailable();
      return available;
    } catch (error) {
      console.error('Check enrollment error:', error);
      return false;
    }
  }

  async showBiometricPrompt(
    title: string = 'Biometric Authentication',
    subtitle: string = 'Please authenticate to continue',
    cancelText: string = 'Cancel'
  ): Promise<BiometricResult> {
    try {
      const { success, error } = await this.rnBiometrics.simplePrompt({
        promptMessage: subtitle,
        cancelButtonText: cancelText,
      });

      if (success) {
        await securityService.logSecurityEvent('biometric_prompt_success', {
          title,
          timestamp: new Date().toISOString(),
        }, 'low');

        return { success: true };
      } else {
        await securityService.logSecurityEvent('biometric_prompt_failed', {
          title,
          error: error || 'User cancelled',
          timestamp: new Date().toISOString(),
        }, 'medium');

        return {
          success: false,
          error: error || 'Authentication cancelled',
        };
      }
    } catch (error) {
      console.error('Show biometric prompt error:', error);
      
      await securityService.logSecurityEvent('biometric_prompt_error', {
        title,
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      }, 'high');

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Prompt error',
      };
    }
  }

  async enableBiometricLogin(): Promise<BiometricResult> {
    try {
      // Check if biometric is available
      const biometricStatus = await this.isBiometricAvailable();
      
      if (!biometricStatus.available) {
        return {
          success: false,
          error: 'Biometric authentication is not available on this device',
        };
      }

      // Create biometric keys
      const keysResult = await this.createKeys();
      if (!keysResult.success) {
        return keysResult;
      }

      // Log biometric login enabled
      await securityService.logSecurityEvent('biometric_login_enabled', {
        type: biometricStatus.type,
        timestamp: new Date().toISOString(),
      }, 'low');

      return { success: true };
    } catch (error) {
      console.error('Enable biometric login error:', error);
      
      await securityService.logSecurityEvent('biometric_login_enable_error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      }, 'high');

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to enable biometric login',
      };
    }
  }

  async disableBiometricLogin(): Promise<BiometricResult> {
    try {
      // Delete biometric keys
      const keysResult = await this.deleteKeys();
      if (!keysResult.success) {
        return keysResult;
      }

      // Remove stored credentials
      await this.removeCredentials();

      // Log biometric login disabled
      await securityService.logSecurityEvent('biometric_login_disabled', {
        timestamp: new Date().toISOString(),
      }, 'low');

      return { success: true };
    } catch (error) {
      console.error('Disable biometric login error:', error);
      
      await securityService.logSecurityEvent('biometric_login_disable_error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      }, 'high');

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to disable biometric login',
      };
    }
  }
}

export const biometricService = BiometricService.getInstance(); 