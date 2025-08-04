import React from 'react';
import { NavigationContainer } from '@react-navigation/native';
import { createStackNavigator } from '@react-navigation/stack';
import { Provider as PaperProvider } from 'react-native-paper';
import { StatusBar } from 'expo-status-bar';
import { AuthProvider } from './src/contexts/AuthContext';
import { theme } from './src/constants/theme';

// Import screens
import LoginScreen from './src/screens/auth/LoginScreen';
import DashboardScreen from './src/screens/DashboardScreen';
import CloudSecurityScreen from './src/screens/CloudSecurityScreen';
import ComplianceScreen from './src/screens/ComplianceScreen';
import NetworkSecurityScreen from './src/screens/security/NetworkSecurityScreen';
import DASTScreen from './src/screens/security/DASTScreen';
import SASTScreen from './src/screens/security/SASTScreen';
import RASPScreen from './src/screens/security/RASPScreen';
import EndpointSecurityScreen from './src/screens/security/EndpointSecurityScreen';
import IAMScreen from './src/screens/iam/IAMScreen';
import CreateUserScreen from './src/screens/iam/CreateUserScreen';
import MFASetupScreen from './src/screens/iam/MFASetupScreen';
import AuditLogsScreen from './src/screens/iam/AuditLogsScreen';
import PrivilegedAccessScreen from './src/screens/iam/PrivilegedAccessScreen';
import DataSecurityScreen from './src/screens/DataSecurityScreen';
import ThreatIntelligenceScreen from './src/screens/ThreatIntelligenceScreen';
import IncidentsScreen from './src/screens/IncidentsScreen';
import SettingsScreen from './src/screens/SettingsScreen';

const Stack = createStackNavigator();

export default function App() {
  return (
    <PaperProvider theme={theme}>
      <AuthProvider>
        <NavigationContainer>
          <StatusBar style="auto" />
          <Stack.Navigator
            initialRouteName="Login"
            screenOptions={{
              headerStyle: {
                backgroundColor: theme.colors.primary,
              },
              headerTintColor: '#fff',
              headerTitleStyle: {
                fontWeight: 'bold',
              },
            }}
          >
            {/* Auth Screens */}
            <Stack.Screen 
              name="Login" 
              component={LoginScreen} 
              options={{ headerShown: false }}
            />

            {/* Main Screens */}
            <Stack.Screen 
              name="Dashboard" 
              component={DashboardScreen}
              options={{ title: 'CyberShield Dashboard' }}
            />
            <Stack.Screen 
              name="CloudSecurity" 
              component={CloudSecurityScreen}
              options={{ title: 'Cloud Security' }}
            />
            <Stack.Screen 
              name="Compliance" 
              component={ComplianceScreen}
              options={{ title: 'Compliance' }}
            />

            {/* Security Screens */}
            <Stack.Screen 
              name="NetworkSecurity" 
              component={NetworkSecurityScreen}
              options={{ title: 'Network Security' }}
            />
            <Stack.Screen 
              name="DAST" 
              component={DASTScreen}
              options={{ title: 'Dynamic Application Security Testing' }}
            />
            <Stack.Screen 
              name="SAST" 
              component={SASTScreen}
              options={{ title: 'Static Application Security Testing' }}
            />
            <Stack.Screen 
              name="RASP" 
              component={RASPScreen}
              options={{ title: 'Runtime Application Self-Protection' }}
            />
            <Stack.Screen 
              name="EndpointSecurity" 
              component={EndpointSecurityScreen}
              options={{ title: 'Endpoint Security' }}
            />

            {/* IAM Screens */}
            <Stack.Screen 
              name="IAM" 
              component={IAMScreen}
              options={{ title: 'Identity & Access Management' }}
            />
            <Stack.Screen 
              name="CreateUser" 
              component={CreateUserScreen}
              options={{ title: 'Create User' }}
            />
            <Stack.Screen 
              name="MFASetup" 
              component={MFASetupScreen}
              options={{ title: 'MFA Setup' }}
            />
            <Stack.Screen 
              name="AuditLogs" 
              component={AuditLogsScreen}
              options={{ title: 'Audit Logs' }}
            />
            <Stack.Screen 
              name="PrivilegedAccess" 
              component={PrivilegedAccessScreen}
              options={{ title: 'Privileged Access' }}
            />

            {/* Other Screens */}
            <Stack.Screen 
              name="DataSecurity" 
              component={DataSecurityScreen}
              options={{ title: 'Data Security' }}
            />
            <Stack.Screen 
              name="ThreatIntelligence" 
              component={ThreatIntelligenceScreen}
              options={{ title: 'Threat Intelligence' }}
            />
            <Stack.Screen 
              name="Incidents" 
              component={IncidentsScreen}
              options={{ title: 'Security Incidents' }}
            />
            <Stack.Screen 
              name="Settings" 
              component={SettingsScreen}
              options={{ title: 'Settings' }}
            />
          </Stack.Navigator>
        </NavigationContainer>
      </AuthProvider>
    </PaperProvider>
  );
} 