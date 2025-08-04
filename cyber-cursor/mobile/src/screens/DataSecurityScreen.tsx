import React, { useState, useEffect } from 'react';
import { View, Text, StyleSheet, ScrollView, TouchableOpacity, RefreshControl, Alert, Dimensions } from 'react-native';
import { Card, Title, Paragraph, Button, Chip, Avatar, List, Divider, ProgressBar } from 'react-native-paper';
import { LinearGradient } from 'react-native-linear-gradient';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';
import { LineChart, BarChart, PieChart } from 'react-native-chart-kit';
import { APIService } from '../services/APIService';

const { width } = Dimensions.get('window');

interface DataSecurityStats {
  total_encrypted_assets: number;
  active_dlp_incidents: number;
  monitored_databases: number;
  security_score: number;
  compliance_status: Record<string, string>;
  recent_vulnerabilities: number;
  pending_access_requests: number;
}

interface EncryptionStats {
  total_keys: number;
  active_keys: number;
  encrypted_files: number;
  encrypted_databases: number;
  key_rotation_due: number;
}

interface DLPStats {
  total_policies: number;
  active_policies: number;
  open_incidents: number;
  resolved_incidents: number;
  false_positives: number;
}

interface DatabaseSecurityStats {
  monitored_connections: number;
  total_audit_logs: number;
  anomalous_activities: number;
  open_vulnerabilities: number;
  pending_requests: number;
}

interface EncryptionKey {
  key_id: number;
  key_name: string;
  key_type: string;
  key_size: number;
  created_at: string;
  expires_at?: string;
  is_active: boolean;
}

interface DLPPolicy {
  policy_id: number;
  policy_name: string;
  policy_type: string;
  enforcement_level: string;
  is_active: boolean;
  created_at: string;
}

interface DLPIncident {
  incident_id: number;
  policy_id: number;
  violation_type: string;
  severity: string;
  status: string;
  created_at: string;
}

interface DatabaseConnection {
  connection_id: number;
  db_name: string;
  db_type: string;
  host: string;
  port?: number;
  is_monitored: boolean;
}

interface DatabaseAccessRequest {
  request_id: number;
  user_id: number;
  db_name: string;
  access_type: string;
  reason: string;
  status: string;
  created_at: string;
}

const DataSecurityScreen: React.FC = ({ navigation }: any) => {
  const [stats, setStats] = useState<DataSecurityStats | null>(null);
  const [encryptionStats, setEncryptionStats] = useState<EncryptionStats | null>(null);
  const [dlpStats, setDlpStats] = useState<DLPStats | null>(null);
  const [dbStats, setDbStats] = useState<DatabaseSecurityStats | null>(null);
  const [encryptionKeys, setEncryptionKeys] = useState<EncryptionKey[]>([]);
  const [dlpPolicies, setDlpPolicies] = useState<DLPPolicy[]>([]);
  const [dlpIncidents, setDlpIncidents] = useState<DLPIncident[]>([]);
  const [dbConnections, setDbConnections] = useState<DatabaseConnection[]>([]);
  const [accessRequests, setAccessRequests] = useState<DatabaseAccessRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    loadDataSecurityData();
  }, []);

  const loadDataSecurityData = async () => {
    try {
      setLoading(true);
      
      // Load dashboard stats
      const statsResponse = await APIService.getDataSecurityStats();
      setStats(statsResponse.data);
      
      // Load encryption stats
      const encryptionResponse = await APIService.getEncryptionStats();
      setEncryptionStats(encryptionResponse.data);
      
      // Load DLP stats
      const dlpResponse = await APIService.getDLPStats();
      setDlpStats(dlpResponse.data);
      
      // Load database security stats
      const dbResponse = await APIService.getDatabaseSecurityStats();
      setDbStats(dbResponse.data);
      
      // Load recent data
      const keysResponse = await APIService.getEncryptionKeys(5);
      setEncryptionKeys(keysResponse.data.keys);
      
      const policiesResponse = await APIService.getDLPPolicies(5);
      setDlpPolicies(policiesResponse.data.policies);
      
      const incidentsResponse = await APIService.getDLPIncidents(5);
      setDlpIncidents(incidentsResponse.data.incidents);
      
      const connectionsResponse = await APIService.getDatabaseConnections(5);
      setDbConnections(connectionsResponse.data.connections);
      
      const requestsResponse = await APIService.getDatabaseAccessRequests(5);
      setAccessRequests(requestsResponse.data.requests);
      
    } catch (error) {
      console.error('Error loading data security data:', error);
      Alert.alert('Error', 'Failed to load data security information');
    } finally {
      setLoading(false);
    }
  };

  const onRefresh = async () => {
    setRefreshing(true);
    await loadDataSecurityData();
    setRefreshing(false);
  };

  const getSecurityScoreColor = (score: number) => {
    if (score >= 80) return '#4CAF50';
    if (score >= 60) return '#FF9800';
    return '#F44336';
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return '#F44336';
      case 'high': return '#FF5722';
      case 'medium': return '#FF9800';
      case 'low': return '#4CAF50';
      default: return '#9E9E9E';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'open': return '#F44336';
      case 'investigating': return '#FF9800';
      case 'resolved': return '#4CAF50';
      case 'false_positive': return '#9E9E9E';
      default: return '#2196F3';
    }
  };

  const renderOverviewTab = () => (
    <ScrollView style={styles.tabContent}>
      {stats && (
        <>
          {/* Security Score Card */}
          <Card style={styles.card}>
            <LinearGradient
              colors={['#667eea', '#764ba2']}
              style={styles.gradientHeader}
            >
              <View style={styles.scoreContainer}>
                <Text style={styles.scoreTitle}>Security Score</Text>
                <Text style={[styles.scoreValue, { color: getSecurityScoreColor(stats.security_score) }]}>
                  {stats.security_score.toFixed(1)}
                </Text>
                <ProgressBar
                  progress={stats.security_score / 100}
                  color={getSecurityScoreColor(stats.security_score)}
                  style={styles.progressBar}
                />
              </View>
            </LinearGradient>
          </Card>

          {/* Key Metrics */}
          <View style={styles.metricsContainer}>
            <Card style={styles.metricCard}>
              <Card.Content>
                <View style={styles.metricRow}>
                  <Icon name="shield-check" size={24} color="#4CAF50" />
                  <View style={styles.metricText}>
                    <Text style={styles.metricValue}>{stats.total_encrypted_assets}</Text>
                    <Text style={styles.metricLabel}>Encrypted Assets</Text>
                  </View>
                </View>
              </Card.Content>
            </Card>

            <Card style={styles.metricCard}>
              <Card.Content>
                <View style={styles.metricRow}>
                  <Icon name="alert-circle" size={24} color="#FF9800" />
                  <View style={styles.metricText}>
                    <Text style={styles.metricValue}>{stats.active_dlp_incidents}</Text>
                    <Text style={styles.metricLabel}>DLP Incidents</Text>
                  </View>
                </View>
              </Card.Content>
            </Card>

            <Card style={styles.metricCard}>
              <Card.Content>
                <View style={styles.metricRow}>
                  <Icon name="database" size={24} color="#2196F3" />
                  <View style={styles.metricText}>
                    <Text style={styles.metricValue}>{stats.monitored_databases}</Text>
                    <Text style={styles.metricLabel}>Monitored DBs</Text>
                  </View>
                </View>
              </Card.Content>
            </Card>

            <Card style={styles.metricCard}>
              <Card.Content>
                <View style={styles.metricRow}>
                  <Icon name="clock-outline" size={24} color="#9C27B0" />
                  <View style={styles.metricText}>
                    <Text style={styles.metricValue}>{stats.pending_access_requests}</Text>
                    <Text style={styles.metricLabel}>Pending Requests</Text>
                  </View>
                </View>
              </Card.Content>
            </Card>
          </View>

          {/* Compliance Status */}
          <Card style={styles.card}>
            <Card.Content>
              <Title>Compliance Status</Title>
              <View style={styles.complianceContainer}>
                {Object.entries(stats.compliance_status).map(([framework, status]) => (
                  <Chip
                    key={framework}
                    mode="outlined"
                    style={[
                      styles.complianceChip,
                      { borderColor: status === 'compliant' ? '#4CAF50' : '#F44336' }
                    ]}
                  >
                    {framework.toUpperCase()}: {status}
                  </Chip>
                ))}
              </View>
            </Card.Content>
          </Card>
        </>
      )}
    </ScrollView>
  );

  const renderEncryptionTab = () => (
    <ScrollView style={styles.tabContent}>
      {encryptionStats && (
        <>
          {/* Encryption Overview */}
          <Card style={styles.card}>
            <Card.Content>
              <Title>Encryption Overview</Title>
              <View style={styles.statsGrid}>
                <View style={styles.statItem}>
                  <Text style={styles.statValue}>{encryptionStats.total_keys}</Text>
                  <Text style={styles.statLabel}>Total Keys</Text>
                </View>
                <View style={styles.statItem}>
                  <Text style={styles.statValue}>{encryptionStats.active_keys}</Text>
                  <Text style={styles.statLabel}>Active Keys</Text>
                </View>
                <View style={styles.statItem}>
                  <Text style={styles.statValue}>{encryptionStats.encrypted_files}</Text>
                  <Text style={styles.statLabel}>Encrypted Files</Text>
                </View>
                <View style={styles.statItem}>
                  <Text style={styles.statValue}>{encryptionStats.key_rotation_due}</Text>
                  <Text style={styles.statLabel}>Rotation Due</Text>
                </View>
              </View>
            </Card.Content>
          </Card>

          {/* Recent Encryption Keys */}
          <Card style={styles.card}>
            <Card.Content>
              <Title>Recent Encryption Keys</Title>
              {encryptionKeys.map((key) => (
                <List.Item
                  key={key.key_id}
                  title={key.key_name}
                  description={`${key.key_type} - ${key.key_size} bits`}
                  left={(props) => (
                    <List.Icon
                      {...props}
                      icon={key.is_active ? "key" : "key-off"}
                      color={key.is_active ? "#4CAF50" : "#9E9E9E"}
                    />
                  )}
                  right={() => (
                    <Chip
                      mode="outlined"
                      style={{ borderColor: key.is_active ? '#4CAF50' : '#9E9E9E' }}
                    >
                      {key.is_active ? 'Active' : 'Inactive'}
                    </Chip>
                  )}
                />
              ))}
            </Card.Content>
          </Card>
        </>
      )}
    </ScrollView>
  );

  const renderDLPTab = () => (
    <ScrollView style={styles.tabContent}>
      {dlpStats && (
        <>
          {/* DLP Overview */}
          <Card style={styles.card}>
            <Card.Content>
              <Title>DLP Overview</Title>
              <View style={styles.statsGrid}>
                <View style={styles.statItem}>
                  <Text style={styles.statValue}>{dlpStats.total_policies}</Text>
                  <Text style={styles.statLabel}>Total Policies</Text>
                </View>
                <View style={styles.statItem}>
                  <Text style={styles.statValue}>{dlpStats.active_policies}</Text>
                  <Text style={styles.statLabel}>Active Policies</Text>
                </View>
                <View style={styles.statItem}>
                  <Text style={styles.statValue}>{dlpStats.open_incidents}</Text>
                  <Text style={styles.statLabel}>Open Incidents</Text>
                </View>
                <View style={styles.statItem}>
                  <Text style={styles.statValue}>{dlpStats.resolved_incidents}</Text>
                  <Text style={styles.statLabel}>Resolved</Text>
                </View>
              </View>
            </Card.Content>
          </Card>

          {/* Recent DLP Incidents */}
          <Card style={styles.card}>
            <Card.Content>
              <Title>Recent DLP Incidents</Title>
              {dlpIncidents.map((incident) => (
                <List.Item
                  key={incident.incident_id}
                  title={incident.violation_type}
                  description={`Policy ID: ${incident.policy_id}`}
                  left={(props) => (
                    <List.Icon
                      {...props}
                      icon="alert-circle"
                      color={getSeverityColor(incident.severity)}
                    />
                  )}
                  right={() => (
                    <View style={styles.incidentStatus}>
                      <Chip
                        mode="outlined"
                        style={{ borderColor: getSeverityColor(incident.severity) }}
                      >
                        {incident.severity}
                      </Chip>
                      <Chip
                        mode="outlined"
                        style={{ borderColor: getStatusColor(incident.status) }}
                      >
                        {incident.status}
                      </Chip>
                    </View>
                  )}
                />
              ))}
            </Card.Content>
          </Card>
        </>
      )}
    </ScrollView>
  );

  const renderDatabaseSecurityTab = () => (
    <ScrollView style={styles.tabContent}>
      {dbStats && (
        <>
          {/* Database Security Overview */}
          <Card style={styles.card}>
            <Card.Content>
              <Title>Database Security Overview</Title>
              <View style={styles.statsGrid}>
                <View style={styles.statItem}>
                  <Text style={styles.statValue}>{dbStats.monitored_connections}</Text>
                  <Text style={styles.statLabel}>Monitored DBs</Text>
                </View>
                <View style={styles.statItem}>
                  <Text style={styles.statValue}>{dbStats.total_audit_logs}</Text>
                  <Text style={styles.statLabel}>Audit Logs</Text>
                </View>
                <View style={styles.statItem}>
                  <Text style={styles.statValue}>{dbStats.anomalous_activities}</Text>
                  <Text style={styles.statLabel}>Anomalies</Text>
                </View>
                <View style={styles.statItem}>
                  <Text style={styles.statValue}>{dbStats.pending_requests}</Text>
                  <Text style={styles.statLabel}>Pending Requests</Text>
                </View>
              </View>
            </Card.Content>
          </Card>

          {/* Database Connections */}
          <Card style={styles.card}>
            <Card.Content>
              <Title>Monitored Databases</Title>
              {dbConnections.map((connection) => (
                <List.Item
                  key={connection.connection_id}
                  title={connection.db_name}
                  description={`${connection.db_type} - ${connection.host}:${connection.port || 'default'}`}
                  left={(props) => (
                    <List.Icon
                      {...props}
                      icon="database"
                      color={connection.is_monitored ? "#4CAF50" : "#9E9E9E"}
                    />
                  )}
                  right={() => (
                    <Chip
                      mode="outlined"
                      style={{ borderColor: connection.is_monitored ? '#4CAF50' : '#9E9E9E' }}
                    >
                      {connection.is_monitored ? 'Monitored' : 'Not Monitored'}
                    </Chip>
                  )}
                />
              ))}
            </Card.Content>
          </Card>

          {/* Access Requests */}
          <Card style={styles.card}>
            <Card.Content>
              <Title>Pending Access Requests</Title>
              {accessRequests.map((request) => (
                <List.Item
                  key={request.request_id}
                  title={`${request.db_name} - ${request.access_type}`}
                  description={request.reason}
                  left={(props) => (
                    <List.Icon
                      {...props}
                      icon="account-key"
                      color={getStatusColor(request.status)}
                    />
                  )}
                  right={() => (
                    <Chip
                      mode="outlined"
                      style={{ borderColor: getStatusColor(request.status) }}
                    >
                      {request.status}
                    </Chip>
                  )}
                />
              ))}
            </Card.Content>
          </Card>
        </>
      )}
    </ScrollView>
  );

  const renderTabContent = () => {
    switch (activeTab) {
      case 'overview':
        return renderOverviewTab();
      case 'encryption':
        return renderEncryptionTab();
      case 'dlp':
        return renderDLPTab();
      case 'database':
        return renderDatabaseSecurityTab();
      default:
        return renderOverviewTab();
    }
  };

  if (loading) {
    return (
      <View style={styles.loadingContainer}>
        <Text>Loading Data Security Dashboard...</Text>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      {/* Header */}
      <LinearGradient
        colors={['#667eea', '#764ba2']}
        style={styles.header}
      >
        <View style={styles.headerContent}>
          <Icon name="shield-lock" size={32} color="white" />
          <Text style={styles.headerTitle}>Data Security</Text>
        </View>
      </LinearGradient>

      {/* Tab Navigation */}
      <View style={styles.tabContainer}>
        <ScrollView horizontal showsHorizontalScrollIndicator={false}>
          <TouchableOpacity
            style={[styles.tab, activeTab === 'overview' && styles.activeTab]}
            onPress={() => setActiveTab('overview')}
          >
            <Icon name="view-dashboard" size={20} color={activeTab === 'overview' ? '#667eea' : '#666'} />
            <Text style={[styles.tabText, activeTab === 'overview' && styles.activeTabText]}>
              Overview
            </Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={[styles.tab, activeTab === 'encryption' && styles.activeTab]}
            onPress={() => setActiveTab('encryption')}
          >
            <Icon name="key" size={20} color={activeTab === 'encryption' ? '#667eea' : '#666'} />
            <Text style={[styles.tabText, activeTab === 'encryption' && styles.activeTabText]}>
              Encryption
            </Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={[styles.tab, activeTab === 'dlp' && styles.activeTab]}
            onPress={() => setActiveTab('dlp')}
          >
            <Icon name="shield-alert" size={20} color={activeTab === 'dlp' ? '#667eea' : '#666'} />
            <Text style={[styles.tabText, activeTab === 'dlp' && styles.activeTabText]}>
              DLP
            </Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={[styles.tab, activeTab === 'database' && styles.activeTab]}
            onPress={() => setActiveTab('database')}
          >
            <Icon name="database" size={20} color={activeTab === 'database' ? '#667eea' : '#666'} />
            <Text style={[styles.tabText, activeTab === 'database' && styles.activeTabText]}>
              Database
            </Text>
          </TouchableOpacity>
        </ScrollView>
      </View>

      {/* Tab Content */}
      <ScrollView
        style={styles.content}
        refreshControl={
          <RefreshControl refreshing={refreshing} onRefresh={onRefresh} />
        }
      >
        {renderTabContent()}
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
    fontSize: 24,
    fontWeight: 'bold',
    color: 'white',
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
    borderBottomColor: '#667eea',
  },
  tabText: {
    marginLeft: 8,
    fontSize: 14,
    color: '#666',
  },
  activeTabText: {
    color: '#667eea',
    fontWeight: 'bold',
  },
  content: {
    flex: 1,
  },
  tabContent: {
    padding: 16,
  },
  card: {
    marginBottom: 16,
    elevation: 2,
  },
  gradientHeader: {
    padding: 20,
    borderTopLeftRadius: 8,
    borderTopRightRadius: 8,
  },
  scoreContainer: {
    alignItems: 'center',
  },
  scoreTitle: {
    fontSize: 16,
    color: 'white',
    marginBottom: 8,
  },
  scoreValue: {
    fontSize: 48,
    fontWeight: 'bold',
    marginBottom: 8,
  },
  progressBar: {
    width: '100%',
    height: 8,
    borderRadius: 4,
  },
  metricsContainer: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    justifyContent: 'space-between',
    marginBottom: 16,
  },
  metricCard: {
    width: '48%',
    marginBottom: 8,
  },
  metricRow: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  metricText: {
    marginLeft: 12,
  },
  metricValue: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#333',
  },
  metricLabel: {
    fontSize: 12,
    color: '#666',
  },
  complianceContainer: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 8,
  },
  complianceChip: {
    marginBottom: 8,
  },
  statsGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    justifyContent: 'space-between',
  },
  statItem: {
    width: '48%',
    alignItems: 'center',
    marginBottom: 16,
  },
  statValue: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#333',
  },
  statLabel: {
    fontSize: 12,
    color: '#666',
    textAlign: 'center',
  },
  incidentStatus: {
    alignItems: 'flex-end',
  },
});

export default DataSecurityScreen; 