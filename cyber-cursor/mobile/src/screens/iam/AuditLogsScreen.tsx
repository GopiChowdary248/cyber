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
  Badge,
} from 'react-native-paper';
import { LinearGradient } from 'react-native-linear-gradient';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';
import { APIService } from '../../services/APIService';

const { width } = Dimensions.get('window');

interface AuditLog {
  id: number;
  user_id: number;
  session_id?: number;
  action: string;
  target_type: string;
  target_id: string;
  target_name: string;
  ip_address: string;
  user_agent: string;
  details: any;
  risk_level: string;
  timestamp: string;
  user?: {
    username: string;
    email: string;
    full_name: string;
  };
}

interface AuditLogsScreenProps {
  navigation: any;
}

const AuditLogsScreen: React.FC<AuditLogsScreenProps> = ({ navigation }) => {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [filteredLogs, setFilteredLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedAction, setSelectedAction] = useState<string>('');
  const [selectedRiskLevel, setSelectedRiskLevel] = useState<string>('');
  const [selectedTargetType, setSelectedTargetType] = useState<string>('');
  const [selectedLog, setSelectedLog] = useState<AuditLog | null>(null);
  const [logModalVisible, setLogModalVisible] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [hasMore, setHasMore] = useState(true);
  const [totalLogs, setTotalLogs] = useState(0);

  const actions = [
    'login', 'logout', 'password_change', 'mfa_enable', 'mfa_disable',
    'user_create', 'user_update', 'user_delete', 'role_change',
    'privileged_access_request', 'privileged_access_approve', 'privileged_access_deny',
    'account_lock', 'account_unlock', 'session_revoke'
  ];

  const riskLevels = ['low', 'medium', 'high', 'critical'];
  const targetTypes = ['user', 'account', 'session', 'system', 'privileged_account'];

  useEffect(() => {
    loadLogs();
  }, []);

  useEffect(() => {
    filterLogs();
  }, [logs, searchQuery, selectedAction, selectedRiskLevel, selectedTargetType]);

  useEffect(() => {
    loadLogs(1, false);
  }, [selectedAction, selectedRiskLevel, selectedTargetType]);

  const loadLogs = async (page = 1, append = false) => {
    try {
      setLoading(true);
      const skip = (page - 1) * 50;
      const response = await APIService.getAuditLogs({
        skip,
        limit: 50,
        action: selectedAction || undefined,
        risk_level: selectedRiskLevel || undefined,
        target_type: selectedTargetType || undefined,
      });
      
      if (append) {
        setLogs(prev => [...prev, ...response.logs]);
      } else {
        setLogs(response.logs);
      }
      
      setTotalLogs(response.total);
      setHasMore(response.logs.length === 50);
      setCurrentPage(page);
    } catch (error) {
      console.error('Failed to load audit logs:', error);
      Alert.alert('Error', 'Failed to load audit logs');
    } finally {
      setLoading(false);
    }
  };

  const onRefresh = async () => {
    setRefreshing(true);
    await loadLogs(1, false);
    setRefreshing(false);
  };

  const filterLogs = () => {
    let filtered = logs;

    if (searchQuery) {
      filtered = filtered.filter(log =>
        log.action.toLowerCase().includes(searchQuery.toLowerCase()) ||
        log.target_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        log.ip_address.includes(searchQuery) ||
        log.user?.username.toLowerCase().includes(searchQuery.toLowerCase()) ||
        log.user?.email.toLowerCase().includes(searchQuery.toLowerCase())
      );
    }

    if (selectedAction) {
      filtered = filtered.filter(log => log.action === selectedAction);
    }

    if (selectedRiskLevel) {
      filtered = filtered.filter(log => log.risk_level === selectedRiskLevel);
    }

    if (selectedTargetType) {
      filtered = filtered.filter(log => log.target_type === selectedTargetType);
    }

    setFilteredLogs(filtered);
  };

  const handleViewLogDetails = (log: AuditLog) => {
    setSelectedLog(log);
    setLogModalVisible(true);
  };

  const handleExportLogs = async () => {
    try {
      const response = await APIService.post('/iam/audit/reports/generate', {
        format: 'csv',
        filters: {
          action: selectedAction,
          risk_level: selectedRiskLevel,
          target_type: selectedTargetType,
          search: searchQuery,
        },
      });
      
      Alert.alert('Success', 'Audit report generated successfully');
    } catch (error) {
      Alert.alert('Error', 'Failed to generate audit report');
    }
  };

  const getActionIcon = (action: string) => {
    switch (action) {
      case 'login': return 'login';
      case 'logout': return 'logout';
      case 'password_change': return 'lock-reset';
      case 'mfa_enable': return 'two-factor-authentication';
      case 'mfa_disable': return 'two-factor-authentication';
      case 'user_create': return 'account-plus';
      case 'user_update': return 'account-edit';
      case 'user_delete': return 'account-remove';
      case 'role_change': return 'account-switch';
      case 'privileged_access_request': return 'key-plus';
      case 'privileged_access_approve': return 'check-circle';
      case 'privileged_access_deny': return 'close-circle';
      case 'account_lock': return 'lock';
      case 'account_unlock': return 'lock-open';
      case 'session_revoke': return 'logout-variant';
      default: return 'information';
    }
  };

  const getActionColor = (action: string) => {
    switch (action) {
      case 'login': return '#4CAF50';
      case 'logout': return '#9E9E9E';
      case 'password_change': return '#2196F3';
      case 'mfa_enable': return '#4CAF50';
      case 'mfa_disable': return '#FF9800';
      case 'user_create': return '#4CAF50';
      case 'user_update': return '#2196F3';
      case 'user_delete': return '#F44336';
      case 'role_change': return '#FF9800';
      case 'privileged_access_request': return '#FF9800';
      case 'privileged_access_approve': return '#4CAF50';
      case 'privileged_access_deny': return '#F44336';
      case 'account_lock': return '#F44336';
      case 'account_unlock': return '#4CAF50';
      case 'session_revoke': return '#F44336';
      default: return '#9E9E9E';
    }
  };

  const getRiskColor = (riskLevel: string) => {
    switch (riskLevel) {
      case 'critical': return '#F44336';
      case 'high': return '#FF5722';
      case 'medium': return '#FF9800';
      case 'low': return '#4CAF50';
      default: return '#9E9E9E';
    }
  };

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleString();
  };

  const renderLogCard = (log: AuditLog) => (
    <Card key={log.id} style={styles.logCard}>
      <Card.Content>
        <View style={styles.logHeader}>
          <View style={styles.logIcon}>
            <Icon 
              name={getActionIcon(log.action)} 
              size={24} 
              color={getActionColor(log.action)} 
            />
          </View>
          <View style={styles.logInfo}>
            <Text style={styles.logAction}>{log.action.replace(/_/g, ' ').toUpperCase()}</Text>
            <Text style={styles.logTarget}>
              {log.target_type}: {log.target_name}
            </Text>
            <Text style={styles.logUser}>
              User: {log.user?.username || log.user?.email || 'Unknown'}
            </Text>
          </View>
          <View style={styles.logBadges}>
            <Chip
              mode="outlined"
              compact
              style={{ borderColor: getRiskColor(log.risk_level) }}
            >
              {log.risk_level}
            </Chip>
            <IconButton
              icon="eye"
              size={20}
              onPress={() => handleViewLogDetails(log)}
            />
          </View>
        </View>

        <View style={styles.logDetails}>
          <Text style={styles.logTime}>{formatTimestamp(log.timestamp)}</Text>
          <Text style={styles.logIP}>IP: {log.ip_address}</Text>
        </View>
      </Card.Content>
    </Card>
  );

  const renderFilters = () => (
    <Card style={styles.filtersCard}>
      <Card.Content>
        <Title>Filters</Title>
        
        <View style={styles.filterRow}>
          <Text style={styles.filterLabel}>Action:</Text>
          <ScrollView horizontal showsHorizontalScrollIndicator={false}>
            <Chip
              mode={selectedAction === '' ? 'flat' : 'outlined'}
              onPress={() => setSelectedAction('')}
              style={styles.filterChip}
            >
              All
            </Chip>
            {actions.slice(0, 8).map(action => (
              <Chip
                key={action}
                mode={selectedAction === action ? 'flat' : 'outlined'}
                onPress={() => setSelectedAction(selectedAction === action ? '' : action)}
                style={styles.filterChip}
              >
                {action.replace(/_/g, ' ')}
              </Chip>
            ))}
          </ScrollView>
        </View>

        <View style={styles.filterRow}>
          <Text style={styles.filterLabel}>Risk Level:</Text>
          <ScrollView horizontal showsHorizontalScrollIndicator={false}>
            <Chip
              mode={selectedRiskLevel === '' ? 'flat' : 'outlined'}
              onPress={() => setSelectedRiskLevel('')}
              style={styles.filterChip}
            >
              All
            </Chip>
            {riskLevels.map(level => (
              <Chip
                key={level}
                mode={selectedRiskLevel === level ? 'flat' : 'outlined'}
                onPress={() => setSelectedRiskLevel(selectedRiskLevel === level ? '' : level)}
                style={[styles.filterChip, { borderColor: getRiskColor(level) }]}
              >
                {level}
              </Chip>
            ))}
          </ScrollView>
        </View>

        <View style={styles.filterRow}>
          <Text style={styles.filterLabel}>Target Type:</Text>
          <ScrollView horizontal showsHorizontalScrollIndicator={false}>
            <Chip
              mode={selectedTargetType === '' ? 'flat' : 'outlined'}
              onPress={() => setSelectedTargetType('')}
              style={styles.filterChip}
            >
              All
            </Chip>
            {targetTypes.map(type => (
              <Chip
                key={type}
                mode={selectedTargetType === type ? 'flat' : 'outlined'}
                onPress={() => setSelectedTargetType(selectedTargetType === type ? '' : type)}
                style={styles.filterChip}
              >
                {type}
              </Chip>
            ))}
          </ScrollView>
        </View>
      </Card.Content>
    </Card>
  );

  return (
    <View style={styles.container}>
      {/* Header */}
      <LinearGradient colors={['#1e3c72', '#2a5298']} style={styles.header}>
        <View style={styles.headerContent}>
          <Icon name="clipboard-list" size={32} color="white" />
          <Text style={styles.headerTitle}>Audit Logs</Text>
        </View>
      </LinearGradient>

      {/* Search Bar */}
      <View style={styles.searchContainer}>
        <Searchbar
          placeholder="Search logs..."
          onChangeText={setSearchQuery}
          value={searchQuery}
          style={styles.searchBar}
        />
      </View>

      {/* Filters */}
      {renderFilters()}

      {/* Log List */}
      <ScrollView
        style={styles.content}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} />}
      >
        <View style={styles.statsRow}>
          <Text style={styles.statsText}>
            Showing {filteredLogs.length} of {totalLogs} logs
          </Text>
          <Button
            mode="outlined"
            onPress={handleExportLogs}
            icon="download"
            compact
          >
            Export
          </Button>
        </View>

        {loading && !refreshing ? (
          <View style={styles.loadingContainer}>
            <ActivityIndicator size="large" color="#2196F3" />
            <Text style={styles.loadingText}>Loading audit logs...</Text>
          </View>
        ) : filteredLogs.length === 0 ? (
          <Card style={styles.emptyCard}>
            <Card.Content>
              <Icon name="clipboard-off" size={64} color="#ccc" style={styles.emptyIcon} />
              <Text style={styles.emptyText}>No audit logs found</Text>
              <Text style={styles.emptySubtext}>
                Try adjusting your search or filter criteria
              </Text>
            </Card.Content>
          </Card>
        ) : (
          filteredLogs.map(renderLogCard)
        )}

        {hasMore && !loading && (
          <Button
            mode="outlined"
            onPress={() => loadLogs(currentPage + 1, true)}
            style={styles.loadMoreButton}
          >
            Load More Logs
          </Button>
        )}
      </ScrollView>

      {/* Log Details Modal */}
      <Portal>
        <Modal
          visible={logModalVisible}
          onDismiss={() => setLogModalVisible(false)}
          contentContainerStyle={styles.modalContainer}
        >
          <Card>
            <Card.Content>
              <View style={styles.modalHeader}>
                <Title>Audit Log Details</Title>
                <IconButton
                  icon="close"
                  onPress={() => setLogModalVisible(false)}
                />
              </View>

              {selectedLog && (
                <View style={styles.logDetailsModal}>
                  <View style={styles.detailRow}>
                    <Text style={styles.detailLabel}>Action:</Text>
                    <Text style={styles.detailValue}>{selectedLog.action}</Text>
                  </View>

                  <View style={styles.detailRow}>
                    <Text style={styles.detailLabel}>Target:</Text>
                    <Text style={styles.detailValue}>
                      {selectedLog.target_type}: {selectedLog.target_name}
                    </Text>
                  </View>

                  <View style={styles.detailRow}>
                    <Text style={styles.detailLabel}>User:</Text>
                    <Text style={styles.detailValue}>
                      {selectedLog.user?.full_name || selectedLog.user?.username || 'Unknown'}
                    </Text>
                  </View>

                  <View style={styles.detailRow}>
                    <Text style={styles.detailLabel}>IP Address:</Text>
                    <Text style={styles.detailValue}>{selectedLog.ip_address}</Text>
                  </View>

                  <View style={styles.detailRow}>
                    <Text style={styles.detailLabel}>Risk Level:</Text>
                    <Chip
                      mode="outlined"
                      style={{ borderColor: getRiskColor(selectedLog.risk_level) }}
                    >
                      {selectedLog.risk_level}
                    </Chip>
                  </View>

                  <View style={styles.detailRow}>
                    <Text style={styles.detailLabel}>Timestamp:</Text>
                    <Text style={styles.detailValue}>{formatTimestamp(selectedLog.timestamp)}</Text>
                  </View>

                  {selectedLog.details && Object.keys(selectedLog.details).length > 0 && (
                    <View style={styles.detailRow}>
                      <Text style={styles.detailLabel}>Additional Details:</Text>
                      <Text style={styles.detailValue}>
                        {JSON.stringify(selectedLog.details, null, 2)}
                      </Text>
                    </View>
                  )}
                </View>
              )}
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
  searchContainer: {
    padding: 15,
    backgroundColor: 'white',
  },
  searchBar: {
    elevation: 2,
  },
  filtersCard: {
    marginHorizontal: 15,
    marginBottom: 15,
  },
  filterRow: {
    marginVertical: 10,
  },
  filterLabel: {
    fontSize: 14,
    fontWeight: 'bold',
    marginBottom: 8,
  },
  filterChip: {
    marginRight: 8,
  },
  content: {
    flex: 1,
  },
  statsRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: 15,
    paddingVertical: 10,
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
  emptyCard: {
    margin: 15,
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
  logCard: {
    marginHorizontal: 15,
    marginBottom: 10,
  },
  logHeader: {
    flexDirection: 'row',
    alignItems: 'flex-start',
  },
  logIcon: {
    marginRight: 15,
    marginTop: 2,
  },
  logInfo: {
    flex: 1,
  },
  logAction: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#333',
  },
  logTarget: {
    fontSize: 14,
    color: '#666',
    marginTop: 2,
  },
  logUser: {
    fontSize: 14,
    color: '#666',
    marginTop: 2,
  },
  logBadges: {
    alignItems: 'flex-end',
  },
  logDetails: {
    marginTop: 10,
    paddingTop: 10,
    borderTopWidth: 1,
    borderTopColor: '#e0e0e0',
  },
  logTime: {
    fontSize: 12,
    color: '#666',
  },
  logIP: {
    fontSize: 12,
    color: '#999',
    marginTop: 2,
  },
  loadMoreButton: {
    margin: 15,
  },
  modalContainer: {
    backgroundColor: 'white',
    padding: 20,
    margin: 20,
    borderRadius: 8,
    maxHeight: '80%',
  },
  modalHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 20,
  },
  logDetailsModal: {
    gap: 15,
  },
  detailRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  detailLabel: {
    fontSize: 14,
    fontWeight: 'bold',
    color: '#666',
    flex: 1,
  },
  detailValue: {
    fontSize: 14,
    color: '#333',
    flex: 2,
    textAlign: 'right',
  },
});

export default AuditLogsScreen; 