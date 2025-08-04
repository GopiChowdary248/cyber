import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  RefreshControl,
  Alert,
  Dimensions,
} from 'react-native';
import { Card, Title, Paragraph, Button, Chip, Avatar, List, Divider } from 'react-native-paper';
import { LinearGradient } from 'react-native-linear-gradient';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';
import { LineChart, BarChart, PieChart } from 'react-native-chart-kit';

import { APIService } from '../services/APIService';

const { width } = Dimensions.get('window');

interface IAMStats {
  total_users: number;
  active_users: number;
  privileged_accounts: number;
  active_sessions: int;
  pending_approvals: number;
  recent_audit_events: number;
  mfa_enabled_users: number;
  sso_enabled_users: number;
}

interface User {
  id: number;
  username: string;
  email: string;
  full_name: string;
  role: string;
  is_active: boolean;
  mfa_enabled: boolean;
  last_login: string;
}

interface PrivilegedAccount {
  id: number;
  system_name: string;
  system_type: string;
  username: string;
  account_type: string;
  is_active: boolean;
  last_rotation: string;
}

interface PrivilegedAccess {
  id: number;
  user_id: number;
  account_id: number;
  status: string;
  reason: string;
  requested_at: string;
  expires_at: string;
}

const IAMScreen: React.FC = ({ navigation }: any) => {
  const [stats, setStats] = useState<IAMStats | null>(null);
  const [users, setUsers] = useState<User[]>([]);
  const [privilegedAccounts, setPrivilegedAccounts] = useState<PrivilegedAccount[]>([]);
  const [pendingAccess, setPendingAccess] = useState<PrivilegedAccess[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    loadIAMData();
  }, []);

  const loadIAMData = async () => {
    try {
      setLoading(true);
      
      // Load dashboard stats
      const statsResponse = await APIService.get('/iam/dashboard/stats');
      setStats(statsResponse.data);
      
      // Load recent users
      const usersResponse = await APIService.get('/iam/users?limit=5');
      setUsers(usersResponse.data.users);
      
      // Load privileged accounts
      const accountsResponse = await APIService.get('/iam/pam/accounts?limit=5');
      setPrivilegedAccounts(accountsResponse.data.accounts);
      
      // Load pending access requests
      const accessResponse = await APIService.get('/iam/pam/access/pending?limit=5');
      setPendingAccess(accessResponse.data.access_requests);
      
    } catch (error) {
      console.error('Failed to load IAM data:', error);
      Alert.alert('Error', 'Failed to load IAM data');
    } finally {
      setLoading(false);
    }
  };

  const onRefresh = async () => {
    setRefreshing(true);
    await loadIAMData();
    setRefreshing(false);
  };

  const renderOverviewTab = () => (
    <ScrollView style={styles.tabContent}>
      {/* Stats Cards */}
      <View style={styles.statsGrid}>
        <Card style={styles.statCard}>
          <Card.Content>
            <View style={styles.statHeader}>
              <Icon name="account-group" size={24} color="#2196F3" />
              <Text style={styles.statValue}>{stats?.total_users || 0}</Text>
            </View>
            <Text style={styles.statLabel}>Total Users</Text>
          </Card.Content>
        </Card>

        <Card style={styles.statCard}>
          <Card.Content>
            <View style={styles.statHeader}>
              <Icon name="shield-account" size={24} color="#4CAF50" />
              <Text style={styles.statValue}>{stats?.active_users || 0}</Text>
            </View>
            <Text style={styles.statLabel}>Active Users</Text>
          </Card.Content>
        </Card>

        <Card style={styles.statCard}>
          <Card.Content>
            <View style={styles.statHeader}>
              <Icon name="key-variant" size={24} color="#FF9800" />
              <Text style={styles.statValue}>{stats?.privileged_accounts || 0}</Text>
            </View>
            <Text style={styles.statLabel}>Privileged Accounts</Text>
          </Card.Content>
        </Card>

        <Card style={styles.statCard}>
          <Card.Content>
            <View style={styles.statHeader}>
              <Icon name="clock-alert" size={24} color="#F44336" />
              <Text style={styles.statValue}>{stats?.pending_approvals || 0}</Text>
            </View>
            <Text style={styles.statLabel}>Pending Approvals</Text>
          </Card.Content>
        </Card>
      </View>

      {/* Security Metrics */}
      <Card style={styles.metricsCard}>
        <Card.Content>
          <Title>Security Metrics</Title>
          <View style={styles.metricsRow}>
            <View style={styles.metric}>
              <Icon name="two-factor-authentication" size={20} color="#4CAF50" />
              <Text style={styles.metricValue}>{stats?.mfa_enabled_users || 0}</Text>
              <Text style={styles.metricLabel}>MFA Enabled</Text>
            </View>
            <View style={styles.metric}>
              <Icon name="cloud" size={20} color="#2196F3" />
              <Text style={styles.metricValue}>{stats?.sso_enabled_users || 0}</Text>
              <Text style={styles.metricLabel}>SSO Users</Text>
            </View>
            <View style={styles.metric}>
              <Icon name="monitor-dashboard" size={20} color="#FF9800" />
              <Text style={styles.metricValue}>{stats?.active_sessions || 0}</Text>
              <Text style={styles.metricLabel}>Active Sessions</Text>
            </View>
          </View>
        </Card.Content>
      </Card>

      {/* Recent Activity Chart */}
      <Card style={styles.chartCard}>
        <Card.Content>
          <Title>Recent Activity</Title>
          <LineChart
            data={{
              labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
              datasets: [
                {
                  data: [20, 45, 28, 80, 99, 43, 50],
                  color: (opacity = 1) => `rgba(33, 150, 243, ${opacity})`,
                  strokeWidth: 2,
                },
              ],
            }}
            width={width - 60}
            height={220}
            chartConfig={{
              backgroundColor: '#ffffff',
              backgroundGradientFrom: '#ffffff',
              backgroundGradientTo: '#ffffff',
              decimalPlaces: 0,
              color: (opacity = 1) => `rgba(0, 0, 0, ${opacity})`,
              labelColor: (opacity = 1) => `rgba(0, 0, 0, ${opacity})`,
              style: {
                borderRadius: 16,
              },
            }}
            bezier
            style={styles.chart}
          />
        </Card.Content>
      </Card>
    </ScrollView>
  );

  const renderUsersTab = () => (
    <ScrollView style={styles.tabContent}>
      <View style={styles.sectionHeader}>
        <Title>User Management</Title>
        <Button
          mode="contained"
          onPress={() => navigation.navigate('UserManagement')}
          icon="account-group"
        >
          Manage Users
        </Button>
      </View>

      {users.map((user) => (
        <Card key={user.id} style={styles.userCard}>
          <Card.Content>
            <View style={styles.userHeader}>
              <Avatar.Text size={40} label={user.username.charAt(0).toUpperCase()} />
              <View style={styles.userInfo}>
                <Text style={styles.userName}>{user.full_name || user.username}</Text>
                <Text style={styles.userEmail}>{user.email}</Text>
                <View style={styles.userBadges}>
                  <Chip
                    mode="outlined"
                    compact
                    style={[styles.roleChip, { backgroundColor: getRoleColor(user.role) }]}
                  >
                    {user.role}
                  </Chip>
                  {user.mfa_enabled && (
                    <Chip mode="outlined" compact icon="two-factor-authentication">
                      MFA
                    </Chip>
                  )}
                  {user.is_active ? (
                    <Chip mode="outlined" compact icon="check-circle" style={{ borderColor: '#4CAF50' }}>
                      Active
                    </Chip>
                  ) : (
                    <Chip mode="outlined" compact icon="close-circle" style={{ borderColor: '#F44336' }}>
                      Inactive
                    </Chip>
                  )}
                </View>
              </View>
            </View>
            <Text style={styles.lastLogin}>
              Last login: {user.last_login ? new Date(user.last_login).toLocaleDateString() : 'Never'}
            </Text>
          </Card.Content>
          <Card.Actions>
            <Button onPress={() => navigation.navigate('EditUser', { userId: user.id })}>
              Edit
            </Button>
            <Button onPress={() => navigation.navigate('UserDetails', { userId: user.id })}>
              Details
            </Button>
          </Card.Actions>
        </Card>
      ))}

      <Button
        mode="outlined"
        onPress={() => navigation.navigate('UserList')}
        style={styles.viewAllButton}
      >
        View All Users
      </Button>
    </ScrollView>
  );

  const renderPrivilegedAccessTab = () => (
    <ScrollView style={styles.tabContent}>
      <View style={styles.sectionHeader}>
        <Title>Privileged Access Management</Title>
        <Button
          mode="contained"
          onPress={() => navigation.navigate('PrivilegedAccess')}
          icon="key-variant"
        >
          Manage Access
        </Button>
      </View>

      {/* Pending Approvals */}
      <Card style={styles.sectionCard}>
        <Card.Content>
          <Title>Pending Approvals ({pendingAccess.length})</Title>
          {pendingAccess.length === 0 ? (
            <Text style={styles.emptyText}>No pending approvals</Text>
          ) : (
            pendingAccess.map((access) => (
              <View key={access.id} style={styles.accessItem}>
                <View style={styles.accessHeader}>
                  <Text style={styles.accessTitle}>Access Request #{access.id}</Text>
                  <Chip mode="outlined" compact style={{ borderColor: '#FF9800' }}>
                    Pending
                  </Chip>
                </View>
                <Text style={styles.accessReason}>{access.reason}</Text>
                <Text style={styles.accessDate}>
                  Requested: {new Date(access.requested_at).toLocaleDateString()}
                </Text>
                <View style={styles.accessActions}>
                  <Button mode="outlined" compact onPress={() => handleApproveAccess(access.id)}>
                    Approve
                  </Button>
                  <Button mode="outlined" compact onPress={() => handleDenyAccess(access.id)}>
                    Deny
                  </Button>
                </View>
              </View>
            ))
          )}
        </Card.Content>
      </Card>

      {/* Privileged Accounts */}
      <Card style={styles.sectionCard}>
        <Card.Content>
          <Title>Privileged Accounts</Title>
          {privilegedAccounts.map((account) => (
            <View key={account.id} style={styles.accountItem}>
              <View style={styles.accountHeader}>
                <Icon name="server" size={20} color="#2196F3" />
                <Text style={styles.accountName}>{account.system_name}</Text>
                <Chip mode="outlined" compact>
                  {account.system_type}
                </Chip>
              </View>
              <Text style={styles.accountDetails}>
                Username: {account.username} | Type: {account.account_type}
              </Text>
              <Text style={styles.accountStatus}>
                Status: {account.is_active ? 'Active' : 'Inactive'} | 
                Last Rotation: {account.last_rotation ? new Date(account.last_rotation).toLocaleDateString() : 'Never'}
              </Text>
            </View>
          ))}
        </Card.Content>
      </Card>
    </ScrollView>
  );

  const renderAuditTab = () => (
    <ScrollView style={styles.tabContent}>
      <Card style={styles.sectionCard}>
        <Card.Content>
          <Title>Recent Audit Events</Title>
          <Text style={styles.auditCount}>
            {stats?.recent_audit_events || 0} events in the last 24 hours
          </Text>
          
          {/* Sample audit events */}
          <View style={styles.auditEvent}>
            <View style={styles.auditHeader}>
              <Icon name="login" size={16} color="#4CAF50" />
              <Text style={styles.auditAction}>User Login</Text>
              <Text style={styles.auditTime}>2 min ago</Text>
            </View>
            <Text style={styles.auditDetails}>admin@company.com logged in from 192.168.1.100</Text>
          </View>

          <View style={styles.auditEvent}>
            <View style={styles.auditHeader}>
              <Icon name="key-variant" size={16} color="#FF9800" />
              <Text style={styles.auditAction}>Privileged Access Request</Text>
              <Text style={styles.auditTime}>15 min ago</Text>
            </View>
            <Text style={styles.auditDetails}>john.doe requested access to production-server-01</Text>
          </View>

          <View style={styles.auditEvent}>
            <View style={styles.auditHeader}>
              <Icon name="alert" size={16} color="#F44336" />
              <Text style={styles.auditAction}>Failed Login Attempt</Text>
              <Text style={styles.auditTime}>1 hour ago</Text>
            </View>
            <Text style={styles.auditDetails}>Multiple failed login attempts from 203.0.113.45</Text>
          </View>
        </Card.Content>
      </Card>

      <Button
        mode="outlined"
        onPress={() => navigation.navigate('AuditLogs')}
        style={styles.viewAllButton}
      >
        View Full Audit Log
      </Button>
    </ScrollView>
  );

  const handleApproveAccess = async (accessId: number) => {
    try {
      await APIService.post(`/iam/pam/access/${accessId}/approve`);
      Alert.alert('Success', 'Access request approved');
      loadIAMData();
    } catch (error) {
      Alert.alert('Error', 'Failed to approve access request');
    }
  };

  const handleDenyAccess = async (accessId: number) => {
    try {
      await APIService.post(`/iam/pam/access/${accessId}/deny`);
      Alert.alert('Success', 'Access request denied');
      loadIAMData();
    } catch (error) {
      Alert.alert('Error', 'Failed to deny access request');
    }
  };

  const getRoleColor = (role: string) => {
    switch (role) {
      case 'admin': return '#F44336';
      case 'analyst': return '#FF9800';
      case 'user': return '#4CAF50';
      default: return '#9E9E9E';
    }
  };

  if (loading) {
    return (
      <View style={styles.loadingContainer}>
        <Text>Loading IAM Dashboard...</Text>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      {/* Header */}
      <LinearGradient colors={['#1e3c72', '#2a5298']} style={styles.header}>
        <View style={styles.headerContent}>
          <Icon name="shield-account" size={32} color="white" />
          <Text style={styles.headerTitle}>Identity & Access Management</Text>
        </View>
      </LinearGradient>

      {/* Tab Navigation */}
      <View style={styles.tabContainer}>
        <ScrollView horizontal showsHorizontalScrollIndicator={false}>
          <TouchableOpacity
            style={[styles.tab, activeTab === 'overview' && styles.activeTab]}
            onPress={() => setActiveTab('overview')}
          >
            <Icon name="view-dashboard" size={20} color={activeTab === 'overview' ? '#2196F3' : '#666'} />
            <Text style={[styles.tabText, activeTab === 'overview' && styles.activeTabText]}>
              Overview
            </Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={[styles.tab, activeTab === 'users' && styles.activeTab]}
            onPress={() => setActiveTab('users')}
          >
            <Icon name="account-group" size={20} color={activeTab === 'users' ? '#2196F3' : '#666'} />
            <Text style={[styles.tabText, activeTab === 'users' && styles.activeTabText]}>
              Users
            </Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={[styles.tab, activeTab === 'privileged' && styles.activeTab]}
            onPress={() => setActiveTab('privileged')}
          >
            <Icon name="key-variant" size={20} color={activeTab === 'privileged' ? '#2196F3' : '#666'} />
            <Text style={[styles.tabText, activeTab === 'privileged' && styles.activeTabText]}>
              Privileged Access
            </Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={[styles.tab, activeTab === 'audit' && styles.activeTab]}
            onPress={() => setActiveTab('audit')}
          >
            <Icon name="clipboard-list" size={20} color={activeTab === 'audit' ? '#2196F3' : '#666'} />
            <Text style={[styles.tabText, activeTab === 'audit' && styles.activeTabText]}>
              Audit
            </Text>
          </TouchableOpacity>
        </ScrollView>
      </View>

      {/* Tab Content */}
      <ScrollView
        style={styles.content}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} />}
      >
        {activeTab === 'overview' && renderOverviewTab()}
        {activeTab === 'users' && renderUsersTab()}
        {activeTab === 'privileged' && renderPrivilegedAccessTab()}
        {activeTab === 'audit' && renderAuditTab()}
      </ScrollView>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f5f5f5',
  },
  loadingContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
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
  tabContainer: {
    backgroundColor: 'white',
    borderBottomWidth: 1,
    borderBottomColor: '#e0e0e0',
  },
  tab: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: 20,
    paddingVertical: 15,
    borderBottomWidth: 2,
    borderBottomColor: 'transparent',
  },
  activeTab: {
    borderBottomColor: '#2196F3',
  },
  tabText: {
    marginLeft: 8,
    color: '#666',
    fontSize: 14,
  },
  activeTabText: {
    color: '#2196F3',
    fontWeight: 'bold',
  },
  content: {
    flex: 1,
  },
  tabContent: {
    padding: 15,
  },
  statsGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    justifyContent: 'space-between',
    marginBottom: 20,
  },
  statCard: {
    width: '48%',
    marginBottom: 10,
  },
  statHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: 5,
  },
  statValue: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#2196F3',
  },
  statLabel: {
    fontSize: 12,
    color: '#666',
  },
  metricsCard: {
    marginBottom: 20,
  },
  metricsRow: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    marginTop: 10,
  },
  metric: {
    alignItems: 'center',
  },
  metricValue: {
    fontSize: 18,
    fontWeight: 'bold',
    marginTop: 5,
  },
  metricLabel: {
    fontSize: 12,
    color: '#666',
    marginTop: 2,
  },
  chartCard: {
    marginBottom: 20,
  },
  chart: {
    marginVertical: 8,
    borderRadius: 16,
  },
  sectionHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 15,
  },
  userCard: {
    marginBottom: 10,
  },
  userHeader: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  userInfo: {
    marginLeft: 15,
    flex: 1,
  },
  userName: {
    fontSize: 16,
    fontWeight: 'bold',
  },
  userEmail: {
    fontSize: 14,
    color: '#666',
    marginTop: 2,
  },
  userBadges: {
    flexDirection: 'row',
    marginTop: 5,
  },
  roleChip: {
    marginRight: 5,
  },
  lastLogin: {
    fontSize: 12,
    color: '#666',
    marginTop: 10,
  },
  viewAllButton: {
    marginTop: 15,
  },
  sectionCard: {
    marginBottom: 15,
  },
  accessItem: {
    paddingVertical: 10,
    borderBottomWidth: 1,
    borderBottomColor: '#e0e0e0',
  },
  accessHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 5,
  },
  accessTitle: {
    fontSize: 14,
    fontWeight: 'bold',
  },
  accessReason: {
    fontSize: 14,
    color: '#666',
    marginBottom: 5,
  },
  accessDate: {
    fontSize: 12,
    color: '#999',
    marginBottom: 10,
  },
  accessActions: {
    flexDirection: 'row',
    gap: 10,
  },
  accountItem: {
    paddingVertical: 10,
    borderBottomWidth: 1,
    borderBottomColor: '#e0e0e0',
  },
  accountHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 5,
  },
  accountName: {
    fontSize: 14,
    fontWeight: 'bold',
    marginLeft: 8,
    flex: 1,
  },
  accountDetails: {
    fontSize: 12,
    color: '#666',
    marginBottom: 2,
  },
  accountStatus: {
    fontSize: 12,
    color: '#999',
  },
  emptyText: {
    textAlign: 'center',
    color: '#666',
    fontStyle: 'italic',
    marginVertical: 20,
  },
  auditCount: {
    fontSize: 14,
    color: '#666',
    marginBottom: 15,
  },
  auditEvent: {
    paddingVertical: 10,
    borderBottomWidth: 1,
    borderBottomColor: '#e0e0e0',
  },
  auditHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 5,
  },
  auditAction: {
    fontSize: 14,
    fontWeight: 'bold',
    marginLeft: 8,
    flex: 1,
  },
  auditTime: {
    fontSize: 12,
    color: '#999',
  },
  auditDetails: {
    fontSize: 12,
    color: '#666',
    marginLeft: 24,
  },
});

export default IAMScreen; 