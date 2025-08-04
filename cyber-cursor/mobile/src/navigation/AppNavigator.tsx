import React from 'react';
import { NavigationContainer } from '@react-navigation/native';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { createStackNavigator } from '@react-navigation/stack';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';

// Import screens
import DashboardScreen from '../screens/DashboardScreen';
import SASTScreen from '../screens/SASTScreen';
import DASTScreen from '../screens/DASTScreen';
import RASPScreen from '../screens/RASPScreen';
import CloudSecurityScreen from '../screens/CloudSecurityScreen';
import NetworkSecurityScreen from '../screens/NetworkSecurityScreen';
import ThreatIntelligenceScreen from '../screens/ThreatIntelligenceScreen';
import IncidentsScreen from '../screens/IncidentsScreen';
import ComplianceScreen from '../screens/ComplianceScreen';
import IAMScreen from '../screens/IAMScreen';
import DataSecurityScreen from '../screens/DataSecurityScreen';
import LoginScreen from '../screens/auth/LoginScreen';

// Import IAM screens
import UserManagementScreen from '../screens/iam/UserManagementScreen';
import CreateUserScreen from '../screens/iam/CreateUserScreen';
import PrivilegedAccessScreen from '../screens/iam/PrivilegedAccessScreen';
import AuditLogsScreen from '../screens/iam/AuditLogsScreen';
import MFASetupScreen from '../screens/iam/MFASetupScreen';

const Tab = createBottomTabNavigator();
const Stack = createStackNavigator();
const IAMStack = createStackNavigator();

// IAM Stack Navigator
const IAMStackNavigator = () => {
  return (
    <IAMStack.Navigator
      screenOptions={{
        headerShown: false,
      }}
    >
      <IAMStack.Screen name="IAMDashboard" component={IAMScreen} />
      <IAMStack.Screen name="UserManagement" component={UserManagementScreen} />
      <IAMStack.Screen name="CreateUser" component={CreateUserScreen} />
      <IAMStack.Screen name="PrivilegedAccess" component={PrivilegedAccessScreen} />
      <IAMStack.Screen name="AuditLogs" component={AuditLogsScreen} />
      <IAMStack.Screen name="MFASetup" component={MFASetupScreen} />
    </IAMStack.Navigator>
  );
};

const MainTabs = () => {
  return (
    <Tab.Navigator
      screenOptions={({ route }) => ({
        tabBarIcon: ({ focused, color, size }) => {
          let iconName: string;

          switch (route.name) {
            case 'Dashboard':
              iconName = 'view-dashboard';
              break;
            case 'SAST':
              iconName = 'code-braces';
              break;
            case 'DAST':
              iconName = 'web';
              break;
            case 'RASP':
              iconName = 'shield-alert';
              break;
            case 'Cloud':
              iconName = 'cloud-security';
              break;
            case 'Network':
              iconName = 'network';
              break;
            case 'IAM':
              iconName = 'shield-account';
              break;
            case 'Threats':
              iconName = 'brain';
              break;
            case 'Incidents':
              iconName = 'alert-circle';
              break;
            case 'Compliance':
              iconName = 'clipboard-check';
              break;
            default:
              iconName = 'circle';
          }

          return <Icon name={iconName} size={size} color={color} />;
        },
        tabBarActiveTintColor: '#2196F3',
        tabBarInactiveTintColor: 'gray',
        tabBarStyle: {
          backgroundColor: 'white',
          borderTopWidth: 1,
          borderTopColor: '#e0e0e0',
          paddingBottom: 5,
          paddingTop: 5,
          height: 60,
        },
        headerShown: false,
      })}
    >
      <Tab.Screen 
        name="Dashboard" 
        component={DashboardScreen}
        options={{
          tabBarLabel: 'Dashboard',
        }}
      />
      <Tab.Screen 
        name="SAST" 
        component={SASTScreen}
        options={{
          tabBarLabel: 'SAST',
        }}
      />
      <Tab.Screen 
        name="DAST" 
        component={DASTScreen}
        options={{
          tabBarLabel: 'DAST',
        }}
      />
      <Tab.Screen 
        name="RASP" 
        component={RASPScreen}
        options={{
          tabBarLabel: 'RASP',
        }}
      />
      <Tab.Screen 
        name="Cloud" 
        component={CloudSecurityScreen}
        options={{
          tabBarLabel: 'Cloud',
        }}
      />
      <Tab.Screen 
        name="Network" 
        component={NetworkSecurityScreen}
        options={{
          tabBarLabel: 'Network',
        }}
      />
      <Tab.Screen 
        name="IAM" 
        component={IAMStackNavigator}
        options={{
          tabBarLabel: 'IAM',
        }}
      />
      <Tab.Screen 
        name="Data Security" 
        component={DataSecurityScreen}
        options={{
          tabBarLabel: 'Data Security',
        }}
      />
      <Tab.Screen 
        name="Threats" 
        component={ThreatIntelligenceScreen}
        options={{
          tabBarLabel: 'Threats',
        }}
      />
      <Tab.Screen 
        name="Incidents" 
        component={IncidentsScreen}
        options={{
          tabBarLabel: 'Incidents',
        }}
      />
      <Tab.Screen 
        name="Compliance" 
        component={ComplianceScreen}
        options={{
          tabBarLabel: 'Compliance',
        }}
      />
    </Tab.Navigator>
  );
};

const AppNavigator = () => {
  return (
    <NavigationContainer>
      <Stack.Navigator
        initialRouteName="Login"
        screenOptions={{
          headerShown: false,
        }}
      >
        <Stack.Screen name="Login" component={LoginScreen} />
        <Stack.Screen name="Main" component={MainTabs} />
      </Stack.Navigator>
    </NavigationContainer>
  );
};

export default AppNavigator; 