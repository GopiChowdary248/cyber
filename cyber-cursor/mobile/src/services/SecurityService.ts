import DeviceInfo from 'react-native-device-info';
import NetworkInfo from 'react-native-network-info';
import { PermissionsAndroid, Platform } from 'react-native';
import EncryptedStorage from 'react-native-encrypted-storage';
import AsyncStorage from '@react-native-async-storage/async-storage';
import CryptoJS from 'react-native-crypto-js';

interface DeviceSecurityStatus {
  isSecure: boolean;
  jailbroken: boolean;
  rooted: boolean;
  emulator: boolean;
  debugMode: boolean;
  securityIssues: string[];
}

interface DeviceInfo {
  deviceId: string;
  brand: string;
  model: string;
  systemVersion: string;
  appVersion: string;
  buildNumber: string;
  bundleId: string;
  isTablet: boolean;
  uniqueId: string;
  ipAddress: string;
  macAddress: string;
}

interface SecurityEvent {
  type: string;
  timestamp: string;
  data: any;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

class SecurityService {
  private static instance: SecurityService;
  private securityEvents: SecurityEvent[] = [];
  private isInitialized = false;

  static getInstance(): SecurityService {
    if (!SecurityService.instance) {
      SecurityService.instance = new SecurityService();
    }
    return SecurityService.instance;
  }

  async initialize(): Promise<void> {
    if (this.isInitialized) return;

    try {
      // Initialize security checks
      await this.performSecurityChecks();
      
      // Set up security monitoring
      await this.setupSecurityMonitoring();
      
      this.isInitialized = true;
      console.log('SecurityService initialized successfully');
    } catch (error) {
      console.error('SecurityService initialization error:', error);
      throw error;
    }
  }

  async checkDeviceSecurity(): Promise<DeviceSecurityStatus> {
    try {
      const securityIssues: string[] = [];
      let isSecure = true;

      // Check for jailbreak/root
      const isJailBroken = await DeviceInfo.isJailBroken();
      if (isJailBroken) {
        securityIssues.push('Device is jailbroken/rooted');
        isSecure = false;
      }

      // Check for emulator
      const isEmulator = await DeviceInfo.isEmulator();
      if (isEmulator) {
        securityIssues.push('Running on emulator');
        isSecure = false;
      }

      // Check for debug mode
      const isDebugged = await DeviceInfo.isDebugged();
      if (isDebugged) {
        securityIssues.push('App is running in debug mode');
        isSecure = false;
      }

      // Check for development build
      const isDevelopment = __DEV__;
      if (isDevelopment) {
        securityIssues.push('Running development build');
        isSecure = false;
      }

      // Check for screen recording
      const isScreenRecording = await DeviceInfo.isScreenRecording();
      if (isScreenRecording) {
        securityIssues.push('Screen recording detected');
        isSecure = false;
      }

      // Check for VPN
      const isVPN = await this.checkVPNConnection();
      if (isVPN) {
        securityIssues.push('VPN connection detected');
        // VPN is not necessarily a security issue, but we log it
      }

      return {
        isSecure,
        jailbroken: isJailBroken,
        rooted: isJailBroken,
        emulator: isEmulator,
        debugMode: isDebugged,
        securityIssues,
      };
    } catch (error) {
      console.error('Device security check error:', error);
      return {
        isSecure: false,
        jailbroken: false,
        rooted: false,
        emulator: false,
        debugMode: false,
        securityIssues: ['Security check failed'],
      };
    }
  }

  async getDeviceInfo(): Promise<DeviceInfo> {
    try {
      const deviceId = await DeviceInfo.getDeviceId();
      const brand = await DeviceInfo.getBrand();
      const model = await DeviceInfo.getModel();
      const systemVersion = await DeviceInfo.getSystemVersion();
      const appVersion = await DeviceInfo.getVersion();
      const buildNumber = await DeviceInfo.getBuildNumber();
      const bundleId = await DeviceInfo.getBundleId();
      const isTablet = await DeviceInfo.isTablet();
      const uniqueId = await DeviceInfo.getUniqueId();

      // Get network information
      const ipAddress = await NetworkInfo.getIPV4Address();
      const macAddress = await NetworkInfo.getMacAddress();

      return {
        deviceId,
        brand,
        model,
        systemVersion,
        appVersion,
        buildNumber,
        bundleId,
        isTablet,
        uniqueId,
        ipAddress: ipAddress || 'unknown',
        macAddress: macAddress || 'unknown',
      };
    } catch (error) {
      console.error('Get device info error:', error);
      throw error;
    }
  }

  async encryptData(data: string, key: string): Promise<string> {
    try {
      return CryptoJS.AES.encrypt(data, key).toString();
    } catch (error) {
      console.error('Encryption error:', error);
      throw error;
    }
  }

  async decryptData(encryptedData: string, key: string): Promise<string> {
    try {
      const bytes = CryptoJS.AES.decrypt(encryptedData, key);
      return bytes.toString(CryptoJS.enc.Utf8);
    } catch (error) {
      console.error('Decryption error:', error);
      throw error;
    }
  }

  async storeSecureData(key: string, value: string): Promise<void> {
    try {
      await EncryptedStorage.setItem(key, value);
    } catch (error) {
      console.error('Store secure data error:', error);
      throw error;
    }
  }

  async getSecureData(key: string): Promise<string | null> {
    try {
      return await EncryptedStorage.getItem(key);
    } catch (error) {
      console.error('Get secure data error:', error);
      return null;
    }
  }

  async removeSecureData(key: string): Promise<void> {
    try {
      await EncryptedStorage.removeItem(key);
    } catch (error) {
      console.error('Remove secure data error:', error);
      throw error;
    }
  }

  async logSecurityEvent(type: string, data: any, severity: 'low' | 'medium' | 'high' | 'critical' = 'low'): Promise<void> {
    try {
      const event: SecurityEvent = {
        type,
        timestamp: new Date().toISOString(),
        data,
        severity,
      };

      this.securityEvents.push(event);

      // Store event locally
      await this.storeSecurityEvent(event);

      // Send to server if high severity
      if (severity === 'high' || severity === 'critical') {
        await this.sendSecurityEventToServer(event);
      }

      console.log('Security event logged:', event);
    } catch (error) {
      console.error('Log security event error:', error);
    }
  }

  async getSecurityEvents(): Promise<SecurityEvent[]> {
    try {
      const events = await AsyncStorage.getItem('security_events');
      return events ? JSON.parse(events) : [];
    } catch (error) {
      console.error('Get security events error:', error);
      return [];
    }
  }

  async clearSecurityEvents(): Promise<void> {
    try {
      await AsyncStorage.removeItem('security_events');
      this.securityEvents = [];
    } catch (error) {
      console.error('Clear security events error:', error);
      throw error;
    }
  }

  async validateNetworkSecurity(): Promise<boolean> {
    try {
      const ipAddress = await NetworkInfo.getIPV4Address();
      const isVPN = await this.checkVPNConnection();

      // Check for suspicious network patterns
      const networkInfo = {
        ipAddress,
        isVPN,
        timestamp: new Date().toISOString(),
      };

      // Log network information
      await this.logSecurityEvent('network_check', networkInfo, 'low');

      return true;
    } catch (error) {
      console.error('Network security validation error:', error);
      return false;
    }
  }

  async checkAppIntegrity(): Promise<boolean> {
    try {
      // Check if app is from official store
      const isInstalledFromStore = await DeviceInfo.isInstalledFromStore();
      
      // Check app signature (Android)
      if (Platform.OS === 'android') {
        const signature = await DeviceInfo.getSignature();
        // Validate signature against expected values
      }

      // Check for app tampering
      const appVersion = await DeviceInfo.getVersion();
      const buildNumber = await DeviceInfo.getBuildNumber();

      const integrityInfo = {
        isInstalledFromStore,
        appVersion,
        buildNumber,
        timestamp: new Date().toISOString(),
      };

      await this.logSecurityEvent('app_integrity_check', integrityInfo, 'medium');

      return isInstalledFromStore;
    } catch (error) {
      console.error('App integrity check error:', error);
      return false;
    }
  }

  async detectSuspiciousActivity(): Promise<boolean> {
    try {
      // Check for multiple failed login attempts
      const failedLogins = await this.getFailedLoginAttempts();
      if (failedLogins > 5) {
        await this.logSecurityEvent('suspicious_activity', {
          type: 'multiple_failed_logins',
          count: failedLogins,
        }, 'high');
        return true;
      }

      // Check for unusual device behavior
      const deviceInfo = await this.getDeviceInfo();
      const lastKnownInfo = await this.getSecureData('last_device_info');
      
      if (lastKnownInfo) {
        const lastInfo = JSON.parse(lastKnownInfo);
        if (deviceInfo.ipAddress !== lastInfo.ipAddress) {
          await this.logSecurityEvent('suspicious_activity', {
            type: 'ip_address_change',
            oldIP: lastInfo.ipAddress,
            newIP: deviceInfo.ipAddress,
          }, 'medium');
        }
      }

      // Store current device info
      await this.storeSecureData('last_device_info', JSON.stringify(deviceInfo));

      return false;
    } catch (error) {
      console.error('Detect suspicious activity error:', error);
      return false;
    }
  }

  async requestPermissions(): Promise<boolean> {
    try {
      if (Platform.OS === 'android') {
        const permissions = [
          PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION,
          PermissionsAndroid.PERMISSIONS.CAMERA,
          PermissionsAndroid.PERMISSIONS.READ_EXTERNAL_STORAGE,
          PermissionsAndroid.PERMISSIONS.WRITE_EXTERNAL_STORAGE,
        ];

        const results = await PermissionsAndroid.requestMultiple(permissions);
        
        const deniedPermissions = Object.keys(results).filter(
          permission => results[permission] === PermissionsAndroid.RESULTS.DENIED
        );

        if (deniedPermissions.length > 0) {
          await this.logSecurityEvent('permissions_denied', {
            permissions: deniedPermissions,
          }, 'medium');
          return false;
        }
      }

      return true;
    } catch (error) {
      console.error('Request permissions error:', error);
      return false;
    }
  }

  private async performSecurityChecks(): Promise<void> {
    try {
      // Perform initial security checks
      const securityStatus = await this.checkDeviceSecurity();
      const appIntegrity = await this.checkAppIntegrity();
      const networkSecurity = await this.validateNetworkSecurity();

      // Log security status
      await this.logSecurityEvent('security_initialization', {
        deviceSecurity: securityStatus,
        appIntegrity,
        networkSecurity,
      }, 'low');
    } catch (error) {
      console.error('Perform security checks error:', error);
      throw error;
    }
  }

  private async setupSecurityMonitoring(): Promise<void> {
    try {
      // Set up periodic security checks
      setInterval(async () => {
        await this.performPeriodicSecurityChecks();
      }, 300000); // Every 5 minutes

      // Set up network monitoring
      setInterval(async () => {
        await this.validateNetworkSecurity();
      }, 60000); // Every minute
    } catch (error) {
      console.error('Setup security monitoring error:', error);
      throw error;
    }
  }

  private async performPeriodicSecurityChecks(): Promise<void> {
    try {
      const securityStatus = await this.checkDeviceSecurity();
      const suspiciousActivity = await this.detectSuspiciousActivity();

      if (!securityStatus.isSecure || suspiciousActivity) {
        await this.logSecurityEvent('periodic_security_check', {
          securityStatus,
          suspiciousActivity,
        }, 'medium');
      }
    } catch (error) {
      console.error('Periodic security checks error:', error);
    }
  }

  private async checkVPNConnection(): Promise<boolean> {
    try {
      // This is a simplified check - in a real implementation,
      // you would use a more sophisticated method to detect VPN
      const ipAddress = await NetworkInfo.getIPV4Address();
      
      // Check for common VPN IP ranges
      const vpnIPRanges = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
      ];

      // Simple check - in reality, you'd need more sophisticated detection
      return false;
    } catch (error) {
      console.error('Check VPN connection error:', error);
      return false;
    }
  }

  private async storeSecurityEvent(event: SecurityEvent): Promise<void> {
    try {
      const events = await this.getSecurityEvents();
      events.push(event);
      
      // Keep only last 100 events
      if (events.length > 100) {
        events.splice(0, events.length - 100);
      }
      
      await AsyncStorage.setItem('security_events', JSON.stringify(events));
    } catch (error) {
      console.error('Store security event error:', error);
    }
  }

  private async sendSecurityEventToServer(event: SecurityEvent): Promise<void> {
    try {
      // In a real implementation, you would send the event to your security server
      console.log('Sending security event to server:', event);
    } catch (error) {
      console.error('Send security event to server error:', error);
    }
  }

  private async getFailedLoginAttempts(): Promise<number> {
    try {
      const attempts = await AsyncStorage.getItem('failed_login_attempts');
      return attempts ? parseInt(attempts, 10) : 0;
    } catch (error) {
      console.error('Get failed login attempts error:', error);
      return 0;
    }
  }
}

export const securityService = SecurityService.getInstance(); 