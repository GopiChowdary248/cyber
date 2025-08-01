import { Dimensions } from 'react-native';

const { width, height } = Dimensions.get('window');

// Colors
export const COLORS = {
  // Primary Colors
  primary: '#00D4FF',
  secondary: '#0099CC',
  accent: '#FF6B35',
  
  // Background Colors
  dark: '#0A0A0A',
  darker: '#1A1A1A',
  darkest: '#000000',
  
  // Text Colors
  white: '#FFFFFF',
  gray: '#8A8A8A',
  lightGray: '#B0B0B0',
  darkGray: '#404040',
  
  // Status Colors
  success: '#00C851',
  warning: '#FFB300',
  error: '#FF4444',
  info: '#33B5E5',
  
  // Security Colors
  secure: '#00C851',
  insecure: '#FF4444',
  warning: '#FFB300',
  critical: '#CC0000',
  
  // UI Colors
  border: '#2A2A2A',
  card: '#1E1E1E',
  overlay: 'rgba(0, 0, 0, 0.7)',
  shadow: 'rgba(0, 0, 0, 0.3)',
  
  // Gradient Colors
  gradientStart: '#00D4FF',
  gradientEnd: '#0099CC',
  gradientDark: '#1A1A1A',
  gradientDarker: '#0A0A0A',
  
  // Transparent Colors
  transparent: 'transparent',
  semiTransparent: 'rgba(255, 255, 255, 0.1)',
  darkTransparent: 'rgba(0, 0, 0, 0.5)',
};

// Typography
export const FONTS = {
  // Font Families
  regular: 'System',
  medium: 'System',
  bold: 'System',
  light: 'System',
  
  // Font Sizes
  h1: 32,
  h2: 28,
  h3: 24,
  h4: 20,
  h5: 18,
  h6: 16,
  body: 14,
  caption: 12,
  small: 10,
  
  // Line Heights
  lineHeight: {
    h1: 40,
    h2: 36,
    h3: 32,
    h4: 28,
    h5: 26,
    h6: 24,
    body: 20,
    caption: 16,
    small: 14,
  },
};

// Sizes
export const SIZES = {
  // Base sizes
  base: 8,
  small: 12,
  font: 14,
  medium: 16,
  large: 18,
  extraLarge: 24,
  
  // Spacing
  padding: 16,
  margin: 16,
  radius: 12,
  border: 1,
  
  // Screen dimensions
  width,
  height,
  
  // Component sizes
  buttonHeight: 50,
  inputHeight: 50,
  cardPadding: 16,
  iconSize: 24,
  avatarSize: 40,
  
  // Border radius
  borderRadius: {
    small: 4,
    medium: 8,
    large: 12,
    extraLarge: 16,
    round: 50,
  },
  
  // Shadows
  shadow: {
    small: {
      shadowColor: COLORS.shadow,
      shadowOffset: {
        width: 0,
        height: 2,
      },
      shadowOpacity: 0.25,
      shadowRadius: 3.84,
      elevation: 5,
    },
    medium: {
      shadowColor: COLORS.shadow,
      shadowOffset: {
        width: 0,
        height: 4,
      },
      shadowOpacity: 0.30,
      shadowRadius: 4.65,
      elevation: 8,
    },
    large: {
      shadowColor: COLORS.shadow,
      shadowOffset: {
        width: 0,
        height: 6,
      },
      shadowOpacity: 0.37,
      shadowRadius: 7.49,
      elevation: 12,
    },
  },
};

// Theme object for React Native Paper
export const theme = {
  dark: true,
  colors: {
    primary: COLORS.primary,
    accent: COLORS.accent,
    background: COLORS.dark,
    surface: COLORS.darker,
    error: COLORS.error,
    text: COLORS.white,
    onSurface: COLORS.white,
    disabled: COLORS.gray,
    placeholder: COLORS.gray,
    backdrop: COLORS.overlay,
    notification: COLORS.accent,
  },
  fonts: {
    regular: {
      fontFamily: FONTS.regular,
      fontWeight: 'normal',
    },
    medium: {
      fontFamily: FONTS.medium,
      fontWeight: '500',
    },
    bold: {
      fontFamily: FONTS.bold,
      fontWeight: 'bold',
    },
    light: {
      fontFamily: FONTS.light,
      fontWeight: '300',
    },
  },
  roundness: SIZES.radius,
};

// Common styles
export const COMMON_STYLES = {
  // Container styles
  container: {
    flex: 1,
    backgroundColor: COLORS.dark,
  },
  
  // Card styles
  card: {
    backgroundColor: COLORS.darker,
    borderRadius: SIZES.radius,
    padding: SIZES.padding,
    marginBottom: SIZES.margin,
    ...SIZES.shadow.medium,
  },
  
  // Button styles
  button: {
    primary: {
      backgroundColor: COLORS.primary,
      borderRadius: SIZES.radius,
      paddingVertical: SIZES.padding,
      paddingHorizontal: SIZES.padding * 2,
      alignItems: 'center',
      justifyContent: 'center',
      ...SIZES.shadow.small,
    },
    secondary: {
      backgroundColor: COLORS.transparent,
      borderWidth: 1,
      borderColor: COLORS.primary,
      borderRadius: SIZES.radius,
      paddingVertical: SIZES.padding,
      paddingHorizontal: SIZES.padding * 2,
      alignItems: 'center',
      justifyContent: 'center',
    },
    outline: {
      backgroundColor: COLORS.transparent,
      borderWidth: 1,
      borderColor: COLORS.border,
      borderRadius: SIZES.radius,
      paddingVertical: SIZES.padding,
      paddingHorizontal: SIZES.padding * 2,
      alignItems: 'center',
      justifyContent: 'center',
    },
  },
  
  // Input styles
  input: {
    backgroundColor: COLORS.dark,
    borderWidth: 1,
    borderColor: COLORS.border,
    borderRadius: SIZES.radius,
    paddingHorizontal: SIZES.padding,
    paddingVertical: SIZES.padding,
    color: COLORS.white,
    fontSize: FONTS.body,
    fontFamily: FONTS.regular,
  },
  
  // Text styles
  text: {
    h1: {
      fontSize: FONTS.h1,
      fontFamily: FONTS.bold,
      color: COLORS.white,
      lineHeight: FONTS.lineHeight.h1,
    },
    h2: {
      fontSize: FONTS.h2,
      fontFamily: FONTS.bold,
      color: COLORS.white,
      lineHeight: FONTS.lineHeight.h2,
    },
    h3: {
      fontSize: FONTS.h3,
      fontFamily: FONTS.bold,
      color: COLORS.white,
      lineHeight: FONTS.lineHeight.h3,
    },
    h4: {
      fontSize: FONTS.h4,
      fontFamily: FONTS.medium,
      color: COLORS.white,
      lineHeight: FONTS.lineHeight.h4,
    },
    h5: {
      fontSize: FONTS.h5,
      fontFamily: FONTS.medium,
      color: COLORS.white,
      lineHeight: FONTS.lineHeight.h5,
    },
    h6: {
      fontSize: FONTS.h6,
      fontFamily: FONTS.medium,
      color: COLORS.white,
      lineHeight: FONTS.lineHeight.h6,
    },
    body: {
      fontSize: FONTS.body,
      fontFamily: FONTS.regular,
      color: COLORS.white,
      lineHeight: FONTS.lineHeight.body,
    },
    caption: {
      fontSize: FONTS.caption,
      fontFamily: FONTS.regular,
      color: COLORS.gray,
      lineHeight: FONTS.lineHeight.caption,
    },
    small: {
      fontSize: FONTS.small,
      fontFamily: FONTS.regular,
      color: COLORS.gray,
      lineHeight: FONTS.lineHeight.small,
    },
  },
  
  // Status styles
  status: {
    success: {
      backgroundColor: COLORS.success + '20',
      borderColor: COLORS.success,
      color: COLORS.success,
    },
    warning: {
      backgroundColor: COLORS.warning + '20',
      borderColor: COLORS.warning,
      color: COLORS.warning,
    },
    error: {
      backgroundColor: COLORS.error + '20',
      borderColor: COLORS.error,
      color: COLORS.error,
    },
    info: {
      backgroundColor: COLORS.info + '20',
      borderColor: COLORS.info,
      color: COLORS.info,
    },
  },
  
  // Security status styles
  security: {
    secure: {
      backgroundColor: COLORS.secure + '20',
      borderColor: COLORS.secure,
      color: COLORS.secure,
    },
    insecure: {
      backgroundColor: COLORS.insecure + '20',
      borderColor: COLORS.insecure,
      color: COLORS.insecure,
    },
    warning: {
      backgroundColor: COLORS.warning + '20',
      borderColor: COLORS.warning,
      color: COLORS.warning,
    },
    critical: {
      backgroundColor: COLORS.critical + '20',
      borderColor: COLORS.critical,
      color: COLORS.critical,
    },
  },
};

// Animation configurations
export const ANIMATIONS = {
  // Duration
  duration: {
    fast: 200,
    normal: 300,
    slow: 500,
  },
  
  // Easing
  easing: {
    ease: 'ease',
    easeIn: 'ease-in',
    easeOut: 'ease-out',
    easeInOut: 'ease-in-out',
  },
  
  // Scale
  scale: {
    small: 0.95,
    normal: 1,
    large: 1.05,
  },
};

// Layout constants
export const LAYOUT = {
  // Screen breakpoints
  breakpoints: {
    small: 375,
    medium: 768,
    large: 1024,
  },
  
  // Grid system
  grid: {
    columns: 12,
    gutter: SIZES.padding,
  },
  
  // Spacing scale
  spacing: {
    xs: SIZES.base / 2,
    sm: SIZES.base,
    md: SIZES.padding,
    lg: SIZES.padding * 1.5,
    xl: SIZES.padding * 2,
    xxl: SIZES.padding * 3,
  },
};

// API configuration
export const API_CONFIG = {
  baseURL: 'http://localhost:8000',
  timeout: 10000,
  retries: 3,
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
  },
};

// Security configuration
export const SECURITY_CONFIG = {
  // Token configuration
  token: {
    accessTokenKey: 'access_token',
    refreshTokenKey: 'refresh_token',
    expiresIn: 3600, // 1 hour
  },
  
  // Biometric configuration
  biometric: {
    promptMessage: 'Authenticate to continue',
    cancelButtonText: 'Cancel',
  },
  
  // Encryption configuration
  encryption: {
    algorithm: 'AES-256-GCM',
    keySize: 256,
  },
};

// Notification configuration
export const NOTIFICATION_CONFIG = {
  // Push notification settings
  push: {
    channelId: 'cybershield_channel',
    channelName: 'CyberShield Notifications',
    channelDescription: 'Security and system notifications',
  },
  
  // Local notification settings
  local: {
    defaultSound: true,
    defaultVibration: true,
    defaultLight: true,
  },
};

export default {
  COLORS,
  FONTS,
  SIZES,
  theme,
  COMMON_STYLES,
  ANIMATIONS,
  LAYOUT,
  API_CONFIG,
  SECURITY_CONFIG,
  NOTIFICATION_CONFIG,
}; 