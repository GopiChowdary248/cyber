import React, { useEffect, useState } from 'react';
import {
  SafeAreaView,
  StatusBar,
  StyleSheet,
  View,
  Text,
  Alert,
  Platform,
} from 'react-native';
import { NavigationContainer } from '@react-navigation/native';
import { createStackNavigator } from '@react-navigation/stack';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { createDrawerNavigator } from '@react-navigation/drawer';
import { Provider as PaperProvider } from 'react-native-paper';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import SplashScreen from 'react-native-splash-screen';
import { GestureHandlerRootView } from 'react-native-gesture-handler';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';

// Import screens
import LoginScreen from './src/screens/auth/LoginScreen';
import RegisterScreen from './src/screens/auth/RegisterScreen';
import MFASetupScreen from './src/screens/auth/MFASetupScreen';
import MFAVerificationScreen from './src/screens/auth/MFAVerificationScreen';

// Admin Portal Screens
import AdminDashboardScreen from './src/screens/admin/DashboardScreen';
import AdminIncidentsScreen from './src/screens/admin/IncidentsScreen';
import AdminUsersScreen from './src/screens/admin/UsersScreen';
import AdminAnalyticsScreen from './src/screens/admin/AnalyticsScreen';
import AdminIntegrationsScreen from './src/screens/admin/IntegrationsScreen';
import AdminComplianceScreen from './src/screens/admin/ComplianceScreen';
import AdminAIMLScreen from './src/screens/admin/AIMLScreen';

// User Portal Screens
import UserDashboardScreen from './src/screens/user/DashboardScreen';
import UserIncidentsScreen from './src/screens/user/IncidentsScreen';
import UserTrainingScreen from './src/screens/user/TrainingScreen';
import UserTipsScreen from './src/screens/user/TipsScreen';
import UserMFAScreen from './src/screens/user/MFAScreen';

// Common Screens
import ProfileScreen from './src/screens/common/ProfileScreen';
import SettingsScreen from './src/screens/common/SettingsScreen';
import NotificationsScreen from './src/screens/common/NotificationsScreen';
import SecurityScreen from './src/screens/common/SecurityScreen';

// Import context and services
import { AuthProvider, useAuth } from './src/contexts/AuthContext';
import { ThemeProvider } from './src/contexts/ThemeContext';
import { NotificationProvider } from './src/contexts/NotificationContext';
import { SecurityService } from './src/services/SecurityService';
import { BiometricService } from './src/services/BiometricService';
import { NetworkService } from './src/services/NetworkService';

// Import theme and constants
import { theme } from './src/theme/theme';
import { COLORS, SIZES, FONTS } from './src/constants/theme';

const Stack = createStackNavigator();
const Tab = createBottomTabNavigator();
const Drawer = createDrawerNavigator();

// Query client for data fetching
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 3,
      retryDelay: attemptIndex => Math.min(1000 * 2 ** attemptIndex, 30000),
      staleTime: 5 * 60 * 1000, // 5 minutes
    },
  },
});

// Admin Tab Navigator
const AdminTabNavigator = () => {
  return (
    <Tab.Navigator
      screenOptions={({ route }) => ({
        tabBarIcon: ({ focused, color, size }) => {
          let iconName: string;

          switch (route.name) {
            case 'Dashboard':
              iconName = focused ? 'view-dashboard' : 'view-dashboard-outline';
              break;
            case 'Incidents':
              iconName = focused ? 'alert-circle' : 'alert-circle-outline';
              break;
            case 'Users':
              iconName = focused ? 'account-group' : 'account-group-outline';
              break;
            case 'Analytics':
              iconName = focused ? 'chart-line' : 'chart-line-variant';
              break;
            case 'More':
              iconName = focused ? 'dots-horizontal' : 'dots-horizontal';
              break;
            default:
              iconName = 'circle';
          }

          return <Icon name={iconName} size={size} color={color} />;
        },
        tabBarActiveTintColor: COLORS.primary,
        tabBarInactiveTintColor: COLORS.gray,
        tabBarStyle: {
          backgroundColor: COLORS.dark,
          borderTopColor: COLORS.border,
          height: 60,
          paddingBottom: 8,
          paddingTop: 8,
        },
        tabBarLabelStyle: {
          fontSize: 12,
          fontFamily: FONTS.medium,
        },
        headerStyle: {
          backgroundColor: COLORS.dark,
          borderBottomColor: COLORS.border,
          borderBottomWidth: 1,
        },
        headerTintColor: COLORS.white,
        headerTitleStyle: {
          fontFamily: FONTS.bold,
          fontSize: 18,
        },
      })}
    >
      <Tab.Screen 
        name="Dashboard" 
        component={AdminDashboardScreen}
        options={{ title: 'Admin Dashboard' }}
      />
      <Tab.Screen 
        name="Incidents" 
        component={AdminIncidentsScreen}
        options={{ title: 'Incident Management' }}
      />
      <Tab.Screen 
        name="Users" 
        component={AdminUsersScreen}
        options={{ title: 'User Management' }}
      />
      <Tab.Screen 
        name="Analytics" 
        component={AdminAnalyticsScreen}
        options={{ title: 'Analytics' }}
      />
      <Tab.Screen 
        name="More" 
        component={AdminMoreNavigator}
        options={{ title: 'More' }}
      />
    </Tab.Navigator>
  );
};

// Admin More Navigator (Drawer)
const AdminMoreNavigator = () => {
  return (
    <Drawer.Navigator
      screenOptions={{
        headerStyle: {
          backgroundColor: COLORS.dark,
        },
        headerTintColor: COLORS.white,
        drawerStyle: {
          backgroundColor: COLORS.dark,
          width: 280,
        },
        drawerLabelStyle: {
          color: COLORS.white,
          fontFamily: FONTS.medium,
        },
        drawerActiveBackgroundColor: COLORS.primary + '20',
        drawerActiveTintColor: COLORS.primary,
      }}
    >
      <Drawer.Screen 
        name="Integrations" 
        component={AdminIntegrationsScreen}
        options={{
          title: 'Integrations',
          drawerIcon: ({ color, size }) => (
            <Icon name="connection" size={size} color={color} />
          ),
        }}
      />
      <Drawer.Screen 
        name="Compliance" 
        component={AdminComplianceScreen}
        options={{
          title: 'Compliance',
          drawerIcon: ({ color, size }) => (
            <Icon name="shield-check" size={size} color={color} />
          ),
        }}
      />
      <Drawer.Screen 
        name="AI/ML" 
        component={AdminAIMLScreen}
        options={{
          title: 'AI/ML Analytics',
          drawerIcon: ({ color, size }) => (
            <Icon name="brain" size={size} color={color} />
          ),
        }}
      />
      <Drawer.Screen 
        name="Profile" 
        component={ProfileScreen}
        options={{
          title: 'Profile',
          drawerIcon: ({ color, size }) => (
            <Icon name="account" size={size} color={color} />
          ),
        }}
      />
      <Drawer.Screen 
        name="Settings" 
        component={SettingsScreen}
        options={{
          title: 'Settings',
          drawerIcon: ({ color, size }) => (
            <Icon name="cog" size={size} color={color} />
          ),
        }}
      />
      <Drawer.Screen 
        name="Security" 
        component={SecurityScreen}
        options={{
          title: 'Security',
          drawerIcon: ({ color, size }) => (
            <Icon name="shield-lock" size={size} color={color} />
          ),
        }}
      />
      <Drawer.Screen 
        name="Notifications" 
        component={NotificationsScreen}
        options={{
          title: 'Notifications',
          drawerIcon: ({ color, size }) => (
            <Icon name="bell" size={size} color={color} />
          ),
        }}
      />
    </Drawer.Navigator>
  );
};

// User Tab Navigator
const UserTabNavigator = () => {
  return (
    <Tab.Navigator
      screenOptions={({ route }) => ({
        tabBarIcon: ({ focused, color, size }) => {
          let iconName: string;

          switch (route.name) {
            case 'Dashboard':
              iconName = focused ? 'view-dashboard' : 'view-dashboard-outline';
              break;
            case 'Incidents':
              iconName = focused ? 'alert-circle' : 'alert-circle-outline';
              break;
            case 'Training':
              iconName = focused ? 'school' : 'school-outline';
              break;
            case 'Tips':
              iconName = focused ? 'lightbulb' : 'lightbulb-outline';
              break;
            case 'More':
              iconName = focused ? 'dots-horizontal' : 'dots-horizontal';
              break;
            default:
              iconName = 'circle';
          }

          return <Icon name={iconName} size={size} color={color} />;
        },
        tabBarActiveTintColor: COLORS.primary,
        tabBarInactiveTintColor: COLORS.gray,
        tabBarStyle: {
          backgroundColor: COLORS.dark,
          borderTopColor: COLORS.border,
          height: 60,
          paddingBottom: 8,
          paddingTop: 8,
        },
        tabBarLabelStyle: {
          fontSize: 12,
          fontFamily: FONTS.medium,
        },
        headerStyle: {
          backgroundColor: COLORS.dark,
          borderBottomColor: COLORS.border,
          borderBottomWidth: 1,
        },
        headerTintColor: COLORS.white,
        headerTitleStyle: {
          fontFamily: FONTS.bold,
          fontSize: 18,
        },
      })}
    >
      <Tab.Screen 
        name="Dashboard" 
        component={UserDashboardScreen}
        options={{ title: 'Dashboard' }}
      />
      <Tab.Screen 
        name="Incidents" 
        component={UserIncidentsScreen}
        options={{ title: 'My Incidents' }}
      />
      <Tab.Screen 
        name="Training" 
        component={UserTrainingScreen}
        options={{ title: 'Security Training' }}
      />
      <Tab.Screen 
        name="Tips" 
        component={UserTipsScreen}
        options={{ title: 'Security Tips' }}
      />
      <Tab.Screen 
        name="More" 
        component={UserMoreNavigator}
        options={{ title: 'More' }}
      />
    </Tab.Navigator>
  );
};

// User More Navigator (Drawer)
const UserMoreNavigator = () => {
  return (
    <Drawer.Navigator
      screenOptions={{
        headerStyle: {
          backgroundColor: COLORS.dark,
        },
        headerTintColor: COLORS.white,
        drawerStyle: {
          backgroundColor: COLORS.dark,
          width: 280,
        },
        drawerLabelStyle: {
          color: COLORS.white,
          fontFamily: FONTS.medium,
        },
        drawerActiveBackgroundColor: COLORS.primary + '20',
        drawerActiveTintColor: COLORS.primary,
      }}
    >
      <Drawer.Screen 
        name="MFA" 
        component={UserMFAScreen}
        options={{
          title: 'Multi-Factor Auth',
          drawerIcon: ({ color, size }) => (
            <Icon name="two-factor-authentication" size={size} color={color} />
          ),
        }}
      />
      <Drawer.Screen 
        name="Profile" 
        component={ProfileScreen}
        options={{
          title: 'Profile',
          drawerIcon: ({ color, size }) => (
            <Icon name="account" size={size} color={color} />
          ),
        }}
      />
      <Drawer.Screen 
        name="Settings" 
        component={SettingsScreen}
        options={{
          title: 'Settings',
          drawerIcon: ({ color, size }) => (
            <Icon name="cog" size={size} color={color} />
          ),
        }}
      />
      <Drawer.Screen 
        name="Security" 
        component={SecurityScreen}
        options={{
          title: 'Security',
          drawerIcon: ({ color, size }) => (
            <Icon name="shield-lock" size={size} color={color} />
          ),
        }}
      />
      <Drawer.Screen 
        name="Notifications" 
        component={NotificationsScreen}
        options={{
          title: 'Notifications',
          drawerIcon: ({ color, size }) => (
            <Icon name="bell" size={size} color={color} />
          ),
        }}
      />
    </Drawer.Navigator>
  );
};

// Main App Navigator
const AppNavigator = () => {
  const { user, isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <View style={styles.loadingContainer}>
        <Text style={styles.loadingText}>Loading CyberShield...</Text>
      </View>
    );
  }

  return (
    <NavigationContainer>
      <Stack.Navigator
        screenOptions={{
          headerShown: false,
        }}
      >
        {!isAuthenticated ? (
          // Auth Stack
          <>
            <Stack.Screen name="Login" component={LoginScreen} />
            <Stack.Screen name="Register" component={RegisterScreen} />
            <Stack.Screen name="MFASetup" component={MFASetupScreen} />
            <Stack.Screen name="MFAVerification" component={MFAVerificationScreen} />
          </>
        ) : (
          // Main App Stack
          <>
            {user?.role === 'admin' ? (
              <Stack.Screen name="AdminTabs" component={AdminTabNavigator} />
            ) : (
              <Stack.Screen name="UserTabs" component={UserTabNavigator} />
            )}
          </>
        )}
      </Stack.Navigator>
    </NavigationContainer>
  );
};

// Main App Component
const App = () => {
  const [isInitialized, setIsInitialized] = useState(false);

  useEffect(() => {
    initializeApp();
  }, []);

  const initializeApp = async () => {
    try {
      // Initialize security services
      await SecurityService.initialize();
      await BiometricService.initialize();
      await NetworkService.initialize();

      // Check for security threats
      const securityStatus = await SecurityService.checkDeviceSecurity();
      if (!securityStatus.isSecure) {
        Alert.alert(
          'Security Warning',
          'Your device may not be secure. Please enable device security features.',
          [{ text: 'OK' }]
        );
      }

      // Hide splash screen
      SplashScreen.hide();
      setIsInitialized(true);
    } catch (error) {
      console.error('App initialization error:', error);
      SplashScreen.hide();
      setIsInitialized(true);
    }
  };

  if (!isInitialized) {
    return (
      <View style={styles.loadingContainer}>
        <Text style={styles.loadingText}>Initializing CyberShield...</Text>
      </View>
    );
  }

  return (
    <GestureHandlerRootView style={styles.container}>
      <StatusBar
        barStyle="light-content"
        backgroundColor={COLORS.dark}
        translucent={false}
      />
      <SafeAreaView style={styles.container}>
        <QueryClientProvider client={queryClient}>
          <PaperProvider theme={theme}>
            <ThemeProvider>
              <AuthProvider>
                <NotificationProvider>
                  <AppNavigator />
                </NotificationProvider>
              </AuthProvider>
            </ThemeProvider>
          </PaperProvider>
        </QueryClientProvider>
      </SafeAreaView>
    </GestureHandlerRootView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: COLORS.dark,
  },
  loadingContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: COLORS.dark,
  },
  loadingText: {
    color: COLORS.white,
    fontSize: 18,
    fontFamily: FONTS.medium,
  },
});

export default App; 