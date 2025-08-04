import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  RefreshControl,
  Alert,
  Dimensions,
} from 'react-native';
import {
  Card,
  Title,
  Paragraph,
  Button,
  Chip,
  Avatar,
  Searchbar,
  FAB,
  Portal,
  Modal,
  TextInput,
  List,
  Divider,
  Menu,
  IconButton,
  ActivityIndicator,
  SegmentedButtons,
  DataTable,
} from 'react-native-paper';
import { LinearGradient } from 'react-native-linear-gradient';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';
import { APIService } from '../../services/APIService';

const { width } = Dimensions.get('window');

interface PrivilegedAccount {
  id: number;
  system_name: string;
  system_type: string;
  username: string;
  privilege_level: string;
  is_active: boolean;
  last_rotation: string;
  risk_score: number;
  owner_id: number;
}

interface PrivilegedAccess {
  id: number;
  user_id: number;
  account_id: number;
  access_type: string;
  status: string;
  reason: string;
  start_time: string;
  end_time: string;
  approval_user_id?: number;
  ip_address: string;
}

interface PrivilegedAccessScreenProps {
  navigation: any;
}

const PrivilegedAccessScreen: React.FC<PrivilegedAccessScreenProps> = ({ navigation }) => {
  const [accounts, setAccounts] = useState<PrivilegedAccount[]>([]);
  const [accessRequests, setAccessRequests] = useState<PrivilegedAccess[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSystemType, setSelectedSystemType] = useState<string>('');
  const [selectedStatus, setSelectedStatus] = useState<string>('');
  const [activeTab, setActiveTab] = useState('accounts');
  const [menuVisible, setMenuVisible] = useState<number | null>(null);
  const [requestModalVisible, setRequestModalVisible] = useState(false);
  const [selectedAccount, setSelectedAccount] = useState<PrivilegedAccount | null>(null);
  const [requestForm, setRequestForm] = useState({
    reason: '',
    duration_hours: '2',
    access_type: 'jit',
  });

  const systemTypes = ['server', 'database', 'network_device', 'application', 'cloud'];
  const accessTypes = ['jit', 'emergency', 'scheduled'];
  const statuses = ['pending', 'approved', 'denied', 'expired'];

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      
      // Load privileged accounts
      const accountsResponse = await APIService.get('/iam/pam/accounts');
      setAccounts(accountsResponse.data.accounts || []);
      
      // Load pending access requests
      const accessResponse = await APIService.get('/iam/pam/access/pending');
      setAccessRequests(accessResponse.data.access_requests || []);
      
    } catch (error) {
      console.error('Failed to load PAM data:', error);
      Alert.alert('Error', 'Failed to load privileged access data');
    } finally {
      setLoading(false);
    }
  };

  const onRefresh = async () => {
    setRefreshing(true);
    await loadData();
    setRefreshing(false);
  };

  const handleCreateAccount = () => {
    navigation.navigate('CreatePrivilegedAccount');
  };

  const handleRequestAccess = (account: PrivilegedAccount) => {
    setSelectedAccount(account);
    setRequestModalVisible(true);
  };

  const handleSubmitAccessRequest = async () => {
    if (!selectedAccount || !requestForm.reason.trim()) {
      Alert.alert('Error', 'Please provide a reason for access');
      return;
    }

    try {
      await APIService.post('/iam/pam/access/request', {
        account_id: selectedAccount.id,
        reason: requestForm.reason,
        duration_hours: parseInt(requestForm.duration_hours),
        access_type: requestForm.access_type,
      });

      Alert.alert('Success', 'Access request submitted successfully');
      setRequestModalVisible(false);
      setRequestForm({ reason: '', duration_hours: '2', access_type: 'jit' });
      loadData();
    } catch (error) {
      Alert.alert('Error', 'Failed to submit access request');
    }
  };

  const handleApproveRequest = async (requestId: number) => {
    try {
      await APIService.post(`/iam/pam/access/${requestId}/approve`);
      Alert.alert('Success', 'Access request approved');
      loadData();
    } catch (error) {
      Alert.alert('Error', 'Failed to approve request');
    }
  };

  const handleDenyRequest = async (requestId: number) => {
    try {
      await APIService.post(`/iam/pam/access/${requestId}/deny`);
      Alert.alert('Success', 'Access request denied');
      loadData();
    } catch (error) {
      Alert.alert('Error', 'Failed to deny request');
    }
  };

  const handleRotatePassword = async (accountId: number) => {
    try {
      await APIService.post(`/iam/pam/accounts/${accountId}/rotate-password`);
      Alert.alert('Success', 'Password rotated successfully');
      loadData();
    } catch (error) {
      Alert.alert('Error', 'Failed to rotate password');
    }
  };

  const getRiskColor = (riskScore: number) => {
    if (riskScore >= 80) return '#F44336';
    if (riskScore >= 60) return '#FF9800';
    if (riskScore >= 40) return '#FFC107';
    return '#4CAF50';
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'pending': return '#FF9800';
      case 'approved': return '#4CAF50';
      case 'denied': return '#F44336';
      case 'expired': return '#9E9E9E';
      default: return '#9E9E9E';
    }
  };

  const renderAccountsTab = () => (
    <ScrollView style={styles.tabContent}>
      <View style={styles.statsRow}>
        <Text style={styles.statsText}>
          {accounts.length} privileged accounts
        </Text>
      </View>

      {accounts.map((account) => (
        <Card key={account.id} style={styles.accountCard}>
          <Card.Content>
            <View style={styles.accountHeader}>
              <Avatar.Icon size={40} icon="server" />
              <View style={styles.accountInfo}>
                <Text style={styles.accountName}>{account.system_name}</Text>
                <Text style={styles.accountUsername}>{account.username}</Text>
                <View style={styles.accountBadges}>
                  <Chip mode="outlined" compact>
                    {account.system_type}
                  </Chip>
                  <Chip mode="outlined" compact>
                    {account.privilege_level}
                  </Chip>
                  <Chip
                    mode="outlined"
                    compact
                    style={{ borderColor: getRiskColor(account.risk_score) }}
                  >
                    Risk: {account.risk_score}
                  </Chip>
                </View>
              </View>
              <Menu
                visible={menuVisible === account.id}
                onDismiss={() => setMenuVisible(null)}
                anchor={
                  <IconButton
                    icon="dots-vertical"
                    onPress={() => setMenuVisible(account.id)}
                  />
                }
              >
                <Menu.Item
                  onPress={() => {
                    setMenuVisible(null);
                    handleRequestAccess(account);
                  }}
                  title="Request Access"
                  leadingIcon="key"
                />
                <Menu.Item
                  onPress={() => {
                    setMenuVisible(null);
                    handleRotatePassword(account.id);
                  }}
                  title="Rotate Password"
                  leadingIcon="refresh"
                />
                <Menu.Item
                  onPress={() => {
                    setMenuVisible(null);
                    navigation.navigate('EditPrivilegedAccount', { accountId: account.id });
                  }}
                  title="Edit Account"
                  leadingIcon="pencil"
                />
              </Menu>
            </View>

            <View style={styles.accountDetails}>
              <Text style={styles.accountStatus}>
                Status: {account.is_active ? 'Active' : 'Inactive'}
              </Text>
              <Text style={styles.accountRotation}>
                Last Rotation: {account.last_rotation ? new Date(account.last_rotation).toLocaleDateString() : 'Never'}
              </Text>
            </View>
          </Card.Content>
        </Card>
      ))}

      {accounts.length === 0 && (
        <Card style={styles.emptyCard}>
          <Card.Content>
            <Icon name="server-off" size={64} color="#ccc" style={styles.emptyIcon} />
            <Text style={styles.emptyText}>No privileged accounts found</Text>
            <Text style={styles.emptySubtext}>
              Add your first privileged account to get started
            </Text>
          </Card.Content>
        </Card>
      )}
    </ScrollView>
  );

  const renderRequestsTab = () => (
    <ScrollView style={styles.tabContent}>
      <View style={styles.statsRow}>
        <Text style={styles.statsText}>
          {accessRequests.length} pending requests
        </Text>
      </View>

      {accessRequests.map((request) => (
        <Card key={request.id} style={styles.requestCard}>
          <Card.Content>
            <View style={styles.requestHeader}>
              <Icon name="key-variant" size={24} color="#FF9800" />
              <View style={styles.requestInfo}>
                <Text style={styles.requestTitle}>Access Request #{request.id}</Text>
                <Text style={styles.requestAccount}>
                  Account: {accounts.find(a => a.id === request.account_id)?.system_name || 'Unknown'}
                </Text>
                <Text style={styles.requestReason}>{request.reason}</Text>
              </View>
              <Chip
                mode="outlined"
                compact
                style={{ borderColor: getStatusColor(request.status) }}
              >
                {request.status}
              </Chip>
            </View>

            <View style={styles.requestDetails}>
              <Text style={styles.requestTime}>
                Requested: {new Date(request.start_time).toLocaleString()}
              </Text>
              {request.end_time && (
                <Text style={styles.requestTime}>
                  Expires: {new Date(request.end_time).toLocaleString()}
                </Text>
              )}
              <Text style={styles.requestIP}>IP: {request.ip_address}</Text>
            </View>

            {request.status === 'pending' && (
              <View style={styles.requestActions}>
                <Button
                  mode="contained"
                  onPress={() => handleApproveRequest(request.id)}
                  style={[styles.actionButton, styles.approveButton]}
                >
                  Approve
                </Button>
                <Button
                  mode="outlined"
                  onPress={() => handleDenyRequest(request.id)}
                  style={[styles.actionButton, styles.denyButton]}
                >
                  Deny
                </Button>
              </View>
            )}
          </Card.Content>
        </Card>
      ))}

      {accessRequests.length === 0 && (
        <Card style={styles.emptyCard}>
          <Card.Content>
            <Icon name="check-circle" size={64} color="#4CAF50" style={styles.emptyIcon} />
            <Text style={styles.emptyText}>No pending requests</Text>
            <Text style={styles.emptySubtext}>
              All access requests have been processed
            </Text>
          </Card.Content>
        </Card>
      )}
    </ScrollView>
  );

  return (
    <View style={styles.container}>
      {/* Header */}
      <LinearGradient colors={['#1e3c72', '#2a5298']} style={styles.header}>
        <View style={styles.headerContent}>
          <Icon name="key-variant" size={32} color="white" />
          <Text style={styles.headerTitle}>Privileged Access Management</Text>
        </View>
      </LinearGradient>

      {/* Tab Navigation */}
      <View style={styles.tabContainer}>
        <SegmentedButtons
          value={activeTab}
          onValueChange={setActiveTab}
          buttons={[
            { value: 'accounts', label: 'Accounts', icon: 'server' },
            { value: 'requests', label: 'Requests', icon: 'key' },
          ]}
          style={styles.segmentedButtons}
        />
      </View>

      {/* Content */}
      <ScrollView
        style={styles.content}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} />}
      >
        {loading && !refreshing ? (
          <View style={styles.loadingContainer}>
            <ActivityIndicator size="large" color="#2196F3" />
            <Text style={styles.loadingText}>Loading...</Text>
          </View>
        ) : (
          <>
            {activeTab === 'accounts' && renderAccountsTab()}
            {activeTab === 'requests' && renderRequestsTab()}
          </>
        )}
      </ScrollView>

      {/* FAB */}
      <FAB
        style={styles.fab}
        icon="plus"
        onPress={handleCreateAccount}
        label="Add Account"
      />

      {/* Access Request Modal */}
      <Portal>
        <Modal
          visible={requestModalVisible}
          onDismiss={() => setRequestModalVisible(false)}
          contentContainerStyle={styles.modalContainer}
        >
          <Card>
            <Card.Content>
              <Title>Request Privileged Access</Title>
              <Text style={styles.modalSubtitle}>
                {selectedAccount?.system_name} ({selectedAccount?.username})
              </Text>

              <TextInput
                label="Reason for Access *"
                value={requestForm.reason}
                onChangeText={(text) => setRequestForm(prev => ({ ...prev, reason: text }))}
                multiline
                numberOfLines={3}
                style={styles.modalInput}
              />

              <TextInput
                label="Duration (hours)"
                value={requestForm.duration_hours}
                onChangeText={(text) => setRequestForm(prev => ({ ...prev, duration_hours: text }))}
                keyboardType="numeric"
                style={styles.modalInput}
              />

              <Text style={styles.modalLabel}>Access Type</Text>
              <SegmentedButtons
                value={requestForm.access_type}
                onValueChange={(value) => setRequestForm(prev => ({ ...prev, access_type: value }))}
                buttons={accessTypes.map(type => ({
                  value: type,
                  label: type.toUpperCase(),
                }))}
                style={styles.modalSegmentedButtons}
              />

              <View style={styles.modalActions}>
                <Button
                  mode="outlined"
                  onPress={() => setRequestModalVisible(false)}
                  style={styles.modalButton}
                >
                  Cancel
                </Button>
                <Button
                  mode="contained"
                  onPress={handleSubmitAccessRequest}
                  style={styles.modalButton}
                >
                  Submit Request
                </Button>
              </View>
            </Card.Content>
          </Card>
        </Modal>
      </Portal>
    </View>
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
  tabContainer: {
    padding: 15,
    backgroundColor: 'white',
  },
  segmentedButtons: {
    marginBottom: 0,
  },
  content: {
    flex: 1,
  },
  tabContent: {
    padding: 15,
  },
  statsRow: {
    marginBottom: 15,
  },
  statsText: {
    fontSize: 14,
    color: '#666',
  },
  loadingContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    paddingVertical: 50,
  },
  loadingText: {
    marginTop: 10,
    fontSize: 16,
    color: '#666',
  },
  accountCard: {
    marginBottom: 10,
  },
  accountHeader: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  accountInfo: {
    marginLeft: 15,
    flex: 1,
  },
  accountName: {
    fontSize: 16,
    fontWeight: 'bold',
  },
  accountUsername: {
    fontSize: 14,
    color: '#666',
    marginTop: 2,
  },
  accountBadges: {
    flexDirection: 'row',
    marginTop: 5,
    flexWrap: 'wrap',
  },
  accountDetails: {
    marginTop: 10,
  },
  accountStatus: {
    fontSize: 12,
    color: '#666',
  },
  accountRotation: {
    fontSize: 12,
    color: '#999',
    marginTop: 2,
  },
  requestCard: {
    marginBottom: 10,
  },
  requestHeader: {
    flexDirection: 'row',
    alignItems: 'flex-start',
  },
  requestInfo: {
    marginLeft: 15,
    flex: 1,
  },
  requestTitle: {
    fontSize: 16,
    fontWeight: 'bold',
  },
  requestAccount: {
    fontSize: 14,
    color: '#666',
    marginTop: 2,
  },
  requestReason: {
    fontSize: 14,
    color: '#666',
    marginTop: 5,
  },
  requestDetails: {
    marginTop: 10,
  },
  requestTime: {
    fontSize: 12,
    color: '#666',
  },
  requestIP: {
    fontSize: 12,
    color: '#999',
    marginTop: 2,
  },
  requestActions: {
    flexDirection: 'row',
    marginTop: 15,
    gap: 10,
  },
  actionButton: {
    flex: 1,
  },
  approveButton: {
    backgroundColor: '#4CAF50',
  },
  denyButton: {
    borderColor: '#F44336',
  },
  emptyCard: {
    marginTop: 20,
  },
  emptyIcon: {
    alignSelf: 'center',
    marginBottom: 10,
  },
  emptyText: {
    textAlign: 'center',
    fontSize: 18,
    fontWeight: 'bold',
    color: '#666',
  },
  emptySubtext: {
    textAlign: 'center',
    fontSize: 14,
    color: '#999',
    marginTop: 5,
  },
  fab: {
    position: 'absolute',
    margin: 16,
    right: 0,
    bottom: 0,
  },
  modalContainer: {
    backgroundColor: 'white',
    padding: 20,
    margin: 20,
    borderRadius: 8,
  },
  modalSubtitle: {
    fontSize: 14,
    color: '#666',
    marginBottom: 15,
  },
  modalInput: {
    marginBottom: 15,
  },
  modalLabel: {
    fontSize: 14,
    fontWeight: 'bold',
    marginBottom: 10,
    color: '#666',
  },
  modalSegmentedButtons: {
    marginBottom: 20,
  },
  modalActions: {
    flexDirection: 'row',
    justifyContent: 'space-between',
  },
  modalButton: {
    flex: 1,
    marginHorizontal: 5,
  },
});

export default PrivilegedAccessScreen; 