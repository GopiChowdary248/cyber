import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  Alert,
  KeyboardAvoidingView,
  Platform,
  ScrollView,
  ActivityIndicator,
  Dimensions,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';
import LinearGradient from 'react-native-linear-gradient';
import { useAuth } from '../../contexts/AuthContext';
import { biometricService } from '../../services/BiometricService';
import { securityService } from '../../services/SecurityService';
import { COLORS, SIZES, FONTS } from '../../constants/theme';

const { width, height } = Dimensions.get('window');

const LoginScreen: React.FC = () => {
  const { login, biometricLogin } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [isBiometricAvailable, setIsBiometricAvailable] = useState(false);
  const [hasStoredCredentials, setHasStoredCredentials] = useState(false);

  useEffect(() => {
    checkBiometricAvailability();
    checkStoredCredentials();
  }, []);

  const checkBiometricAvailability = async () => {
    try {
      const biometricStatus = await biometricService.isBiometricAvailable();
      setIsBiometricAvailable(biometricStatus.available);
    } catch (error) {
      console.error('Check biometric availability error:', error);
    }
  };

  const checkStoredCredentials = async () => {
    try {
      const hasCredentials = await biometricService.hasStoredCredentials();
      setHasStoredCredentials(hasCredentials);
    } catch (error) {
      console.error('Check stored credentials error:', error);
    }
  };

  const handleLogin = async () => {
    if (!email || !password) {
      Alert.alert('Error', 'Please enter both email and password');
      return;
    }

    setIsLoading(true);
    try {
      const success = await login(email, password);
      if (success) {
        // Store credentials for biometric login if biometric is available
        if (isBiometricAvailable) {
          await biometricService.storeCredentials(email, password);
        }
      }
    } catch (error) {
      console.error('Login error:', error);
      Alert.alert('Login Error', 'An error occurred during login');
    } finally {
      setIsLoading(false);
    }
  };

  const handleBiometricLogin = async () => {
    setIsLoading(true);
    try {
      const success = await biometricLogin();
      if (!success) {
        Alert.alert('Biometric Login Failed', 'Please try again or use your password');
      }
    } catch (error) {
      console.error('Biometric login error:', error);
      Alert.alert('Biometric Login Error', 'An error occurred during biometric authentication');
    } finally {
      setIsLoading(false);
    }
  };

  const handleForgotPassword = () => {
    Alert.alert(
      'Forgot Password',
      'Please contact your system administrator to reset your password.',
      [{ text: 'OK' }]
    );
  };

  const handleRegister = () => {
    // Navigate to register screen
    // navigation.navigate('Register');
  };

  return (
    <SafeAreaView style={styles.container}>
      <KeyboardAvoidingView
        behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
        style={styles.keyboardAvoidingView}
      >
        <ScrollView
          contentContainerStyle={styles.scrollContainer}
          showsVerticalScrollIndicator={false}
        >
          {/* Header */}
          <View style={styles.header}>
            <LinearGradient
              colors={[COLORS.primary, COLORS.secondary]}
              style={styles.logoContainer}
            >
              <Icon name="shield-lock" size={60} color={COLORS.white} />
            </LinearGradient>
            <Text style={styles.title}>CyberShield</Text>
            <Text style={styles.subtitle}>Secure Cybersecurity Platform</Text>
          </View>

          {/* Login Form */}
          <View style={styles.formContainer}>
            <Text style={styles.formTitle}>Welcome Back</Text>
            <Text style={styles.formSubtitle}>Sign in to your account</Text>

            {/* Email Input */}
            <View style={styles.inputContainer}>
              <Icon name="email-outline" size={20} color={COLORS.gray} style={styles.inputIcon} />
              <TextInput
                style={styles.input}
                placeholder="Email Address"
                placeholderTextColor={COLORS.gray}
                value={email}
                onChangeText={setEmail}
                keyboardType="email-address"
                autoCapitalize="none"
                autoCorrect={false}
              />
            </View>

            {/* Password Input */}
            <View style={styles.inputContainer}>
              <Icon name="lock-outline" size={20} color={COLORS.gray} style={styles.inputIcon} />
              <TextInput
                style={[styles.input, styles.passwordInput]}
                placeholder="Password"
                placeholderTextColor={COLORS.gray}
                value={password}
                onChangeText={setPassword}
                secureTextEntry={!showPassword}
                autoCapitalize="none"
                autoCorrect={false}
              />
              <TouchableOpacity
                onPress={() => setShowPassword(!showPassword)}
                style={styles.passwordToggle}
              >
                <Icon
                  name={showPassword ? 'eye-off' : 'eye'}
                  size={20}
                  color={COLORS.gray}
                />
              </TouchableOpacity>
            </View>

            {/* Forgot Password */}
            <TouchableOpacity onPress={handleForgotPassword} style={styles.forgotPassword}>
              <Text style={styles.forgotPasswordText}>Forgot Password?</Text>
            </TouchableOpacity>

            {/* Login Button */}
            <TouchableOpacity
              style={[styles.loginButton, isLoading && styles.loginButtonDisabled]}
              onPress={handleLogin}
              disabled={isLoading}
            >
              {isLoading ? (
                <ActivityIndicator color={COLORS.white} size="small" />
              ) : (
                <>
                  <Icon name="login" size={20} color={COLORS.white} style={styles.buttonIcon} />
                  <Text style={styles.loginButtonText}>Sign In</Text>
                </>
              )}
            </TouchableOpacity>

            {/* Biometric Login */}
            {isBiometricAvailable && hasStoredCredentials && (
              <TouchableOpacity
                style={styles.biometricButton}
                onPress={handleBiometricLogin}
                disabled={isLoading}
              >
                <Icon name="fingerprint" size={24} color={COLORS.primary} />
                <Text style={styles.biometricButtonText}>Sign in with Biometric</Text>
              </TouchableOpacity>
            )}

            {/* Divider */}
            <View style={styles.divider}>
              <View style={styles.dividerLine} />
              <Text style={styles.dividerText}>OR</Text>
              <View style={styles.dividerLine} />
            </View>

            {/* Register Link */}
            <View style={styles.registerContainer}>
              <Text style={styles.registerText}>Don't have an account? </Text>
              <TouchableOpacity onPress={handleRegister}>
                <Text style={styles.registerLink}>Sign Up</Text>
              </TouchableOpacity>
            </View>
          </View>

          {/* Security Info */}
          <View style={styles.securityInfo}>
            <Icon name="security" size={16} color={COLORS.gray} />
            <Text style={styles.securityText}>
              Your data is encrypted and secure
            </Text>
          </View>
        </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: COLORS.dark,
  },
  keyboardAvoidingView: {
    flex: 1,
  },
  scrollContainer: {
    flexGrow: 1,
    paddingHorizontal: SIZES.padding,
  },
  header: {
    alignItems: 'center',
    marginTop: height * 0.1,
    marginBottom: height * 0.05,
  },
  logoContainer: {
    width: 100,
    height: 100,
    borderRadius: 50,
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: SIZES.padding,
    shadowColor: COLORS.primary,
    shadowOffset: {
      width: 0,
      height: 4,
    },
    shadowOpacity: 0.3,
    shadowRadius: 8,
    elevation: 8,
  },
  title: {
    fontSize: 32,
    fontFamily: FONTS.bold,
    color: COLORS.white,
    marginBottom: SIZES.base,
  },
  subtitle: {
    fontSize: 16,
    fontFamily: FONTS.regular,
    color: COLORS.gray,
    textAlign: 'center',
  },
  formContainer: {
    backgroundColor: COLORS.darker,
    borderRadius: SIZES.radius,
    padding: SIZES.padding * 1.5,
    marginBottom: SIZES.padding,
    shadowColor: COLORS.black,
    shadowOffset: {
      width: 0,
      height: 2,
    },
    shadowOpacity: 0.25,
    shadowRadius: 8,
    elevation: 5,
  },
  formTitle: {
    fontSize: 24,
    fontFamily: FONTS.bold,
    color: COLORS.white,
    marginBottom: SIZES.base,
    textAlign: 'center',
  },
  formSubtitle: {
    fontSize: 14,
    fontFamily: FONTS.regular,
    color: COLORS.gray,
    textAlign: 'center',
    marginBottom: SIZES.padding,
  },
  inputContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: COLORS.dark,
    borderRadius: SIZES.radius,
    marginBottom: SIZES.padding,
    paddingHorizontal: SIZES.padding,
    borderWidth: 1,
    borderColor: COLORS.border,
  },
  inputIcon: {
    marginRight: SIZES.base,
  },
  input: {
    flex: 1,
    height: 50,
    color: COLORS.white,
    fontSize: 16,
    fontFamily: FONTS.regular,
  },
  passwordInput: {
    paddingRight: 50,
  },
  passwordToggle: {
    position: 'absolute',
    right: SIZES.padding,
    height: 50,
    justifyContent: 'center',
  },
  forgotPassword: {
    alignSelf: 'flex-end',
    marginBottom: SIZES.padding,
  },
  forgotPasswordText: {
    color: COLORS.primary,
    fontSize: 14,
    fontFamily: FONTS.medium,
  },
  loginButton: {
    backgroundColor: COLORS.primary,
    borderRadius: SIZES.radius,
    height: 50,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: SIZES.padding,
    shadowColor: COLORS.primary,
    shadowOffset: {
      width: 0,
      height: 2,
    },
    shadowOpacity: 0.3,
    shadowRadius: 4,
    elevation: 4,
  },
  loginButtonDisabled: {
    opacity: 0.6,
  },
  buttonIcon: {
    marginRight: SIZES.base,
  },
  loginButtonText: {
    color: COLORS.white,
    fontSize: 16,
    fontFamily: FONTS.bold,
  },
  biometricButton: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: COLORS.dark,
    borderRadius: SIZES.radius,
    height: 50,
    marginBottom: SIZES.padding,
    borderWidth: 1,
    borderColor: COLORS.primary,
  },
  biometricButtonText: {
    color: COLORS.primary,
    fontSize: 16,
    fontFamily: FONTS.medium,
    marginLeft: SIZES.base,
  },
  divider: {
    flexDirection: 'row',
    alignItems: 'center',
    marginVertical: SIZES.padding,
  },
  dividerLine: {
    flex: 1,
    height: 1,
    backgroundColor: COLORS.border,
  },
  dividerText: {
    color: COLORS.gray,
    fontSize: 14,
    fontFamily: FONTS.medium,
    marginHorizontal: SIZES.padding,
  },
  registerContainer: {
    flexDirection: 'row',
    justifyContent: 'center',
    alignItems: 'center',
  },
  registerText: {
    color: COLORS.gray,
    fontSize: 14,
    fontFamily: FONTS.regular,
  },
  registerLink: {
    color: COLORS.primary,
    fontSize: 14,
    fontFamily: FONTS.bold,
  },
  securityInfo: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    marginTop: SIZES.padding,
    marginBottom: SIZES.padding * 2,
  },
  securityText: {
    color: COLORS.gray,
    fontSize: 12,
    fontFamily: FONTS.regular,
    marginLeft: SIZES.base,
  },
});

export default LoginScreen; 