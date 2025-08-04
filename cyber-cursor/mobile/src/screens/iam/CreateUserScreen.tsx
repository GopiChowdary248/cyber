import React, { useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  Alert,
  KeyboardAvoidingView,
  Platform,
} from 'react-native';
import {
  Card,
  Title,
  TextInput,
  Button,
  HelperText,
  SegmentedButtons,
  Checkbox,
  Divider,
  List,
  IconButton,
} from 'react-native-paper';
import { LinearGradient } from 'react-native-linear-gradient';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';
import { APIService } from '../../services/APIService';

interface CreateUserScreenProps {
  navigation: any;
}

const CreateUserScreen: React.FC<CreateUserScreenProps> = ({ navigation }) => {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    full_name: '',
    department: '',
    phone: '',
    role: 'user',
    password: '',
    confirmPassword: '',
    mfa_enabled: false,
    sso_provider: '',
    sso_external_id: '',
  });

  const [errors, setErrors] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const roles = [
    { value: 'user', label: 'User', icon: 'account' },
    { value: 'analyst', label: 'Analyst', icon: 'account-search' },
    { value: 'admin', label: 'Admin', icon: 'account-cog' },
  ];

  const departments = [
    'IT',
    'Security',
    'HR',
    'Finance',
    'Marketing',
    'Sales',
    'Operations',
    'Engineering',
    'Support',
    'Other',
  ];

  const ssoProviders = [
    { value: '', label: 'None' },
    { value: 'azure_ad', label: 'Azure AD' },
    { value: 'okta', label: 'Okta' },
    { value: 'google', label: 'Google Workspace' },
    { value: 'ldap', label: 'LDAP' },
    { value: 'active_directory', label: 'Active Directory' },
  ];

  const validateForm = () => {
    const newErrors: Record<string, string> = {};

    // Username validation
    if (!formData.username.trim()) {
      newErrors.username = 'Username is required';
    } else if (formData.username.length < 3) {
      newErrors.username = 'Username must be at least 3 characters';
    } else if (!/^[a-zA-Z0-9_-]+$/.test(formData.username)) {
      newErrors.username = 'Username can only contain letters, numbers, underscores, and hyphens';
    }

    // Email validation
    if (!formData.email.trim()) {
      newErrors.email = 'Email is required';
    } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
      newErrors.email = 'Please enter a valid email address';
    }

    // Full name validation
    if (!formData.full_name.trim()) {
      newErrors.full_name = 'Full name is required';
    }

    // Password validation
    if (!formData.sso_provider) {
      if (!formData.password) {
        newErrors.password = 'Password is required';
      } else if (formData.password.length < 8) {
        newErrors.password = 'Password must be at least 8 characters';
      } else if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(formData.password)) {
        newErrors.password = 'Password must contain uppercase, lowercase, and number';
      }

      if (formData.password !== formData.confirmPassword) {
        newErrors.confirmPassword = 'Passwords do not match';
      }
    }

    // SSO validation
    if (formData.sso_provider && !formData.sso_external_id.trim()) {
      newErrors.sso_external_id = 'External ID is required for SSO users';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async () => {
    if (!validateForm()) {
      return;
    }

    setLoading(true);
    try {
      const userData = {
        username: formData.username.trim(),
        email: formData.email.trim(),
        full_name: formData.full_name.trim(),
        department: formData.department.trim(),
        phone: formData.phone.trim(),
        role: formData.role,
        password: formData.sso_provider ? undefined : formData.password,
        mfa_enabled: formData.mfa_enabled,
        sso_provider: formData.sso_provider || undefined,
        sso_external_id: formData.sso_external_id.trim() || undefined,
      };

      await APIService.createIAMUser(userData);
      Alert.alert(
        'Success',
        'User created successfully',
        [
          {
            text: 'OK',
            onPress: () => navigation.goBack(),
          },
        ]
      );
    } catch (error: any) {
      console.error('Failed to create user:', error);
      Alert.alert(
        'Error',
        error.response?.data?.detail || 'Failed to create user. Please try again.'
      );
    } finally {
      setLoading(false);
    }
  };

  const updateFormData = (field: string, value: any) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    // Clear error when user starts typing
    if (errors[field]) {
      setErrors(prev => ({ ...prev, [field]: '' }));
    }
  };

  return (
    <KeyboardAvoidingView
      style={styles.container}
      behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
    >
      {/* Header */}
      <LinearGradient colors={['#1e3c72', '#2a5298']} style={styles.header}>
        <View style={styles.headerContent}>
          <IconButton
            icon="arrow-left"
            iconColor="white"
            size={24}
            onPress={() => navigation.goBack()}
          />
          <Text style={styles.headerTitle}>Create New User</Text>
        </View>
      </LinearGradient>

      <ScrollView style={styles.content} showsVerticalScrollIndicator={false}>
        {/* Basic Information */}
        <Card style={styles.card}>
          <Card.Content>
            <Title style={styles.cardTitle}>
              <Icon name="account-plus" size={20} color="#2196F3" />
              {' '}Basic Information
            </Title>

            <TextInput
              label="Username *"
              value={formData.username}
              onChangeText={(text) => updateFormData('username', text)}
              error={!!errors.username}
              style={styles.input}
              autoCapitalize="none"
              autoCorrect={false}
            />
            <HelperText type="error" visible={!!errors.username}>
              {errors.username}
            </HelperText>

            <TextInput
              label="Email Address *"
              value={formData.email}
              onChangeText={(text) => updateFormData('email', text)}
              error={!!errors.email}
              style={styles.input}
              keyboardType="email-address"
              autoCapitalize="none"
              autoCorrect={false}
            />
            <HelperText type="error" visible={!!errors.email}>
              {errors.email}
            </HelperText>

            <TextInput
              label="Full Name *"
              value={formData.full_name}
              onChangeText={(text) => updateFormData('full_name', text)}
              error={!!errors.full_name}
              style={styles.input}
            />
            <HelperText type="error" visible={!!errors.full_name}>
              {errors.full_name}
            </HelperText>

            <TextInput
              label="Department"
              value={formData.department}
              onChangeText={(text) => updateFormData('department', text)}
              style={styles.input}
            />

            <TextInput
              label="Phone Number"
              value={formData.phone}
              onChangeText={(text) => updateFormData('phone', text)}
              style={styles.input}
              keyboardType="phone-pad"
            />
          </Card.Content>
        </Card>

        {/* Role Selection */}
        <Card style={styles.card}>
          <Card.Content>
            <Title style={styles.cardTitle}>
              <Icon name="shield-account" size={20} color="#FF9800" />
              {' '}Role & Permissions
            </Title>

            <Text style={styles.sectionLabel}>User Role *</Text>
            <SegmentedButtons
              value={formData.role}
              onValueChange={(value) => updateFormData('role', value)}
              buttons={roles.map(role => ({
                value: role.value,
                label: role.label,
                icon: role.icon,
              }))}
              style={styles.segmentedButtons}
            />

            <View style={styles.checkboxContainer}>
              <Checkbox
                status={formData.mfa_enabled ? 'checked' : 'unchecked'}
                onPress={() => updateFormData('mfa_enabled', !formData.mfa_enabled)}
              />
              <Text style={styles.checkboxLabel}>
                Enable Multi-Factor Authentication (MFA)
              </Text>
            </View>
          </Card.Content>
        </Card>

        {/* Authentication */}
        <Card style={styles.card}>
          <Card.Content>
            <Title style={styles.cardTitle}>
              <Icon name="lock" size={20} color="#4CAF50" />
              {' '}Authentication
            </Title>

            <Text style={styles.sectionLabel}>SSO Provider</Text>
            <SegmentedButtons
              value={formData.sso_provider}
              onValueChange={(value) => updateFormData('sso_provider', value)}
              buttons={ssoProviders.map(provider => ({
                value: provider.value,
                label: provider.label,
              }))}
              style={styles.segmentedButtons}
            />

            {formData.sso_provider && (
              <TextInput
                label="External ID"
                value={formData.sso_external_id}
                onChangeText={(text) => updateFormData('sso_external_id', text)}
                error={!!errors.sso_external_id}
                style={styles.input}
                placeholder="Enter the user's ID from the SSO provider"
              />
            )}

            {!formData.sso_provider && (
              <>
                <TextInput
                  label="Password *"
                  value={formData.password}
                  onChangeText={(text) => updateFormData('password', text)}
                  error={!!errors.password}
                  style={styles.input}
                  secureTextEntry={!showPassword}
                  right={
                    <TextInput.Icon
                      icon={showPassword ? 'eye-off' : 'eye'}
                      onPress={() => setShowPassword(!showPassword)}
                    />
                  }
                />
                <HelperText type="error" visible={!!errors.password}>
                  {errors.password}
                </HelperText>

                <TextInput
                  label="Confirm Password *"
                  value={formData.confirmPassword}
                  onChangeText={(text) => updateFormData('confirmPassword', text)}
                  error={!!errors.confirmPassword}
                  style={styles.input}
                  secureTextEntry={!showConfirmPassword}
                  right={
                    <TextInput.Icon
                      icon={showConfirmPassword ? 'eye-off' : 'eye'}
                      onPress={() => setShowConfirmPassword(!showConfirmPassword)}
                    />
                  }
                />
                <HelperText type="error" visible={!!errors.confirmPassword}>
                  {errors.confirmPassword}
                </HelperText>
              </>
            )}
          </Card.Content>
        </Card>

        {/* Password Requirements */}
        {!formData.sso_provider && (
          <Card style={styles.card}>
            <Card.Content>
              <Title style={styles.cardTitle}>
                <Icon name="information" size={20} color="#9C27B0" />
                {' '}Password Requirements
              </Title>
              <List.Item
                title="At least 8 characters"
                left={(props) => (
                  <List.Icon
                    {...props}
                    icon={formData.password.length >= 8 ? 'check-circle' : 'circle-outline'}
                    color={formData.password.length >= 8 ? '#4CAF50' : '#9E9E9E'}
                  />
                )}
              />
              <List.Item
                title="Contains uppercase letter"
                left={(props) => (
                  <List.Icon
                    {...props}
                    icon={/[A-Z]/.test(formData.password) ? 'check-circle' : 'circle-outline'}
                    color={/[A-Z]/.test(formData.password) ? '#4CAF50' : '#9E9E9E'}
                  />
                )}
              />
              <List.Item
                title="Contains lowercase letter"
                left={(props) => (
                  <List.Icon
                    {...props}
                    icon={/[a-z]/.test(formData.password) ? 'check-circle' : 'circle-outline'}
                    color={/[a-z]/.test(formData.password) ? '#4CAF50' : '#9E9E9E'}
                  />
                )}
              />
              <List.Item
                title="Contains number"
                left={(props) => (
                  <List.Icon
                    {...props}
                    icon={/\d/.test(formData.password) ? 'check-circle' : 'circle-outline'}
                    color={/\d/.test(formData.password) ? '#4CAF50' : '#9E9E9E'}
                  />
                )}
              />
            </Card.Content>
          </Card>
        )}

        {/* Action Buttons */}
        <View style={styles.buttonContainer}>
          <Button
            mode="outlined"
            onPress={() => navigation.goBack()}
            style={[styles.button, styles.cancelButton]}
            disabled={loading}
          >
            Cancel
          </Button>
          <Button
            mode="contained"
            onPress={handleSubmit}
            style={[styles.button, styles.submitButton]}
            loading={loading}
            disabled={loading}
          >
            Create User
          </Button>
        </View>
      </ScrollView>
    </KeyboardAvoidingView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f5f5f5',
  },
  header: {
    paddingTop: 50,
    paddingBottom: 20,
    paddingHorizontal: 20,
  },
  headerContent: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  headerTitle: {
    color: 'white',
    fontSize: 20,
    fontWeight: 'bold',
    marginLeft: 10,
  },
  content: {
    flex: 1,
    padding: 15,
  },
  card: {
    marginBottom: 15,
  },
  cardTitle: {
    fontSize: 16,
    marginBottom: 15,
  },
  sectionLabel: {
    fontSize: 14,
    fontWeight: 'bold',
    marginBottom: 10,
    color: '#666',
  },
  input: {
    marginBottom: 5,
  },
  segmentedButtons: {
    marginBottom: 15,
  },
  checkboxContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    marginTop: 10,
  },
  checkboxLabel: {
    marginLeft: 8,
    fontSize: 14,
  },
  buttonContainer: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginTop: 20,
    marginBottom: 30,
  },
  button: {
    flex: 1,
    marginHorizontal: 5,
  },
  cancelButton: {
    borderColor: '#666',
  },
  submitButton: {
    backgroundColor: '#2196F3',
  },
});

export default CreateUserScreen; 