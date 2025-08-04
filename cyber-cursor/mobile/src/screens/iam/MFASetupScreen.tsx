import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  Alert,
  KeyboardAvoidingView,
  Platform,
  Dimensions,
} from 'react-native';
import {
  Card,
  Title,
  TextInput,
  Button,
  HelperText,
  SegmentedButtons,
  Checkbox,
  List,
  IconButton,
  ActivityIndicator,
  Divider,
} from 'react-native-paper';
import { LinearGradient } from 'react-native-linear-gradient';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';
import { APIService } from '../../services/APIService';

const { width } = Dimensions.get('window');

interface MFASetupScreenProps {
  navigation: any;
  route: any;
}

const MFASetupScreen: React.FC<MFASetupScreenProps> = ({ navigation, route }) => {
  const [mfaType, setMfaType] = useState('totp');
  const [qrCode, setQrCode] = useState('');
  const [secretKey, setSecretKey] = useState('');
  const [verificationCode, setVerificationCode] = useState('');
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [step, setStep] = useState(1);
  const [loading, setLoading] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [showBackupCodes, setShowBackupCodes] = useState(false);

  const mfaTypes = [
    { value: 'totp', label: 'Authenticator App', icon: 'cellphone-key' },
    { value: 'sms', label: 'SMS', icon: 'message-text' },
    { value: 'email', label: 'Email', icon: 'email' },
    { value: 'push', label: 'Push Notification', icon: 'bell' },
  ];

  useEffect(() => {
    if (step === 1) {
      generateMFASecret();
    }
  }, [mfaType]);

  const generateMFASecret = async () => {
    try {
      setLoading(true);
      const response = await APIService.post('/iam/auth/mfa/setup', {
        mfa_type: mfaType,
      });
      
      setQrCode(response.data.qr_code);
      setSecretKey(response.data.secret_key);
      setBackupCodes(response.data.backup_codes || []);
    } catch (error) {
      console.error('Failed to generate MFA secret:', error);
      Alert.alert('Error', 'Failed to generate MFA setup');
    } finally {
      setLoading(false);
    }
  };

  const verifyMFACode = async () => {
    if (!verificationCode.trim()) {
      Alert.alert('Error', 'Please enter the verification code');
      return;
    }

    try {
      setVerifying(true);
      const response = await APIService.post('/iam/auth/mfa/verify', {
        token: verificationCode,
        user_id: route.params?.userId,
      });

      if (response.data.success) {
        Alert.alert(
          'Success',
          'MFA has been successfully enabled',
          [
            {
              text: 'OK',
              onPress: () => navigation.goBack(),
            },
          ]
        );
      } else {
        Alert.alert('Error', 'Invalid verification code');
      }
    } catch (error) {
      console.error('Failed to verify MFA code:', error);
      Alert.alert('Error', 'Failed to verify MFA code');
    } finally {
      setVerifying(false);
    }
  };

  const handleNext = () => {
    if (step === 1) {
      setStep(2);
    }
  };

  const handleBack = () => {
    if (step === 2) {
      setStep(1);
    }
  };

  const renderStep1 = () => (
    <ScrollView style={styles.content} showsVerticalScrollIndicator={false}>
      <Card style={styles.card}>
        <Card.Content>
          <Title style={styles.cardTitle}>
            <Icon name="two-factor-authentication" size={24} color="#2196F3" />
            {' '}Choose MFA Method
          </Title>
          
          <Text style={styles.description}>
            Select your preferred multi-factor authentication method to enhance your account security.
          </Text>

          <SegmentedButtons
            value={mfaType}
            onValueChange={setMfaType}
            buttons={mfaTypes.map(type => ({
              value: type.value,
              label: type.label,
              icon: type.icon,
            }))}
            style={styles.segmentedButtons}
          />
        </Card.Content>
      </Card>

      {mfaType === 'totp' && (
        <Card style={styles.card}>
          <Card.Content>
            <Title style={styles.cardTitle}>
              <Icon name="qrcode" size={24} color="#4CAF50" />
              {' '}Setup Authenticator App
            </Title>

            {loading ? (
              <View style={styles.loadingContainer}>
                <ActivityIndicator size="large" color="#2196F3" />
                <Text style={styles.loadingText}>Generating QR code...</Text>
              </View>
            ) : (
              <>
                <Text style={styles.setupInstructions}>
                  1. Install an authenticator app like Google Authenticator, Authy, or Microsoft Authenticator
                </Text>
                <Text style={styles.setupInstructions}>
                  2. Scan the QR code below with your authenticator app
                </Text>
                <Text style={styles.setupInstructions}>
                  3. Or manually enter the secret key: {secretKey}
                </Text>

                {qrCode && (
                  <View style={styles.qrContainer}>
                    <Text style={styles.qrPlaceholder}>[QR Code Image]</Text>
                    <Text style={styles.qrNote}>QR Code would be displayed here</Text>
                  </View>
                )}

                <View style={styles.backupCodesContainer}>
                  <Title style={styles.backupTitle}>Backup Codes</Title>
                  <Text style={styles.backupDescription}>
                    Save these backup codes in a secure location. You can use them to access your account if you lose your authenticator device.
                  </Text>
                  
                  <Button
                    mode="outlined"
                    onPress={() => setShowBackupCodes(!showBackupCodes)}
                    icon={showBackupCodes ? 'eye-off' : 'eye'}
                    style={styles.backupButton}
                  >
                    {showBackupCodes ? 'Hide' : 'Show'} Backup Codes
                  </Button>

                  {showBackupCodes && (
                    <View style={styles.backupCodesList}>
                      {backupCodes.map((code, index) => (
                        <Text key={index} style={styles.backupCode}>
                          {code}
                        </Text>
                      ))}
                    </View>
                  )}
                </View>
              </>
            )}
          </Card.Content>
        </Card>
      )}

      {mfaType === 'sms' && (
        <Card style={styles.card}>
          <Card.Content>
            <Title style={styles.cardTitle}>
              <Icon name="message-text" size={24} color="#FF9800" />
              {' '}SMS Verification
            </Title>

            <Text style={styles.setupInstructions}>
              You will receive a verification code via SMS to your registered phone number.
            </Text>

            <TextInput
              label="Phone Number"
              value={route.params?.phoneNumber || ''}
              disabled
              style={styles.input}
            />
          </Card.Content>
        </Card>
      )}

      {mfaType === 'email' && (
        <Card style={styles.card}>
          <Card.Content>
            <Title style={styles.cardTitle}>
              <Icon name="email" size={24} color="#9C27B0" />
              {' '}Email Verification
            </Title>

            <Text style={styles.setupInstructions}>
              You will receive a verification code via email to your registered email address.
            </Text>

            <TextInput
              label="Email Address"
              value={route.params?.email || ''}
              disabled
              style={styles.input}
            />
          </Card.Content>
        </Card>
      )}

      {mfaType === 'push' && (
        <Card style={styles.card}>
          <Card.Content>
            <Title style={styles.cardTitle}>
              <Icon name="bell" size={24} color="#F44336" />
              {' '}Push Notification
            </Title>

            <Text style={styles.setupInstructions}>
              You will receive push notifications on your registered mobile device for authentication.
            </Text>

            <Text style={styles.setupInstructions}>
              Make sure you have the mobile app installed and notifications enabled.
            </Text>
          </Card.Content>
        </Card>
      )}

      <View style={styles.buttonContainer}>
        <Button
          mode="outlined"
          onPress={() => navigation.goBack()}
          style={[styles.button, styles.cancelButton]}
        >
          Cancel
        </Button>
        <Button
          mode="contained"
          onPress={handleNext}
          style={[styles.button, styles.nextButton]}
          disabled={loading}
        >
          Next
        </Button>
      </View>
    </ScrollView>
  );

  const renderStep2 = () => (
    <ScrollView style={styles.content} showsVerticalScrollIndicator={false}>
      <Card style={styles.card}>
        <Card.Content>
          <Title style={styles.cardTitle}>
            <Icon name="check-circle" size={24} color="#4CAF50" />
            {' '}Verify Setup
          </Title>

          <Text style={styles.verificationDescription}>
            Enter the verification code from your {mfaType === 'totp' ? 'authenticator app' : mfaType === 'sms' ? 'SMS' : mfaType === 'email' ? 'email' : 'push notification'} to complete the setup.
          </Text>

          <TextInput
            label="Verification Code"
            value={verificationCode}
            onChangeText={setVerificationCode}
            keyboardType="numeric"
            maxLength={6}
            style={styles.input}
            placeholder="Enter 6-digit code"
          />

          <View style={styles.verificationTips}>
            <Text style={styles.tipTitle}>Tips:</Text>
            <List.Item
              title="Make sure the time on your device is accurate"
              left={(props) => <List.Icon {...props} icon="clock" />}
            />
            <List.Item
              title="Enter the code within 30 seconds"
              left={(props) => <List.Icon {...props} icon="timer" />}
            />
            <List.Item
              title="If the code doesn't work, try the next one"
              left={(props) => <List.Icon {...props} icon="refresh" />}
            />
          </View>
        </Card.Content>
      </Card>

      <View style={styles.buttonContainer}>
        <Button
          mode="outlined"
          onPress={handleBack}
          style={[styles.button, styles.backButton]}
        >
          Back
        </Button>
        <Button
          mode="contained"
          onPress={verifyMFACode}
          style={[styles.button, styles.verifyButton]}
          loading={verifying}
          disabled={verifying || !verificationCode.trim()}
        >
          Verify & Enable MFA
        </Button>
      </View>
    </ScrollView>
  );

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
          <Text style={styles.headerTitle}>
            {step === 1 ? 'Setup MFA' : 'Verify MFA'}
          </Text>
        </View>
      </LinearGradient>

      {/* Progress Indicator */}
      <View style={styles.progressContainer}>
        <View style={styles.progressBar}>
          <View style={[styles.progressFill, { width: `${(step / 2) * 100}%` }]} />
        </View>
        <Text style={styles.progressText}>Step {step} of 2</Text>
      </View>

      {step === 1 ? renderStep1() : renderStep2()}
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
  progressContainer: {
    backgroundColor: 'white',
    padding: 15,
    alignItems: 'center',
  },
  progressBar: {
    width: '100%',
    height: 4,
    backgroundColor: '#e0e0e0',
    borderRadius: 2,
    marginBottom: 8,
  },
  progressFill: {
    height: '100%',
    backgroundColor: '#2196F3',
    borderRadius: 2,
  },
  progressText: {
    fontSize: 12,
    color: '#666',
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
  description: {
    fontSize: 14,
    color: '#666',
    marginBottom: 20,
    lineHeight: 20,
  },
  segmentedButtons: {
    marginBottom: 15,
  },
  loadingContainer: {
    alignItems: 'center',
    paddingVertical: 30,
  },
  loadingText: {
    marginTop: 10,
    fontSize: 16,
    color: '#666',
  },
  setupInstructions: {
    fontSize: 14,
    color: '#666',
    marginBottom: 10,
    lineHeight: 20,
  },
  qrContainer: {
    alignItems: 'center',
    marginVertical: 20,
    padding: 20,
    backgroundColor: '#f9f9f9',
    borderRadius: 8,
  },
  qrPlaceholder: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#ccc',
    marginBottom: 10,
  },
  qrNote: {
    fontSize: 12,
    color: '#999',
    textAlign: 'center',
  },
  backupCodesContainer: {
    marginTop: 20,
  },
  backupTitle: {
    fontSize: 16,
    marginBottom: 10,
  },
  backupDescription: {
    fontSize: 14,
    color: '#666',
    marginBottom: 15,
    lineHeight: 20,
  },
  backupButton: {
    marginBottom: 15,
  },
  backupCodesList: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 10,
  },
  backupCode: {
    fontSize: 16,
    fontFamily: 'monospace',
    backgroundColor: '#f0f0f0',
    padding: 8,
    borderRadius: 4,
    minWidth: 80,
    textAlign: 'center',
  },
  input: {
    marginBottom: 15,
  },
  verificationDescription: {
    fontSize: 14,
    color: '#666',
    marginBottom: 20,
    lineHeight: 20,
  },
  verificationTips: {
    marginTop: 20,
  },
  tipTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    marginBottom: 10,
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
  nextButton: {
    backgroundColor: '#2196F3',
  },
  backButton: {
    borderColor: '#666',
  },
  verifyButton: {
    backgroundColor: '#4CAF50',
  },
});

export default MFASetupScreen; 