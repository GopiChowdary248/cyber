import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  RefreshControl,
  Alert,
  Switch,
} from 'react-native';
import { LinearGradient } from 'react-native-linear-gradient';
import { Card, Title, Paragraph, Button, Chip, FAB, Portal, Dialog } from 'react-native-paper';
import { LineChart, PieChart } from 'react-native-chart-kit';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';
import { APIService, RASPApplication, RASPThreat } from '../services/APIService';
import { Dimensions } from 'react-native';

const { width } = Dimensions.get('window');

const RASPScreen: React.FC = ({ navigation }: any) => {
  const [applications, setApplications] = useState<RASPApplication[]>([]);
  const [selectedApp, setSelectedApp] = useState<RASPApplication | null>(null);
  const [threats, setThreats] = useState<RASPThreat[]>([]);
  const [metrics, setMetrics] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [threatDetailsModal, setThreatDetailsModal] = useState(false);
  const [selectedThreat, setSelectedThreat] = useState<RASPThreat | null>(null);

  const apiService = new APIService();

  const fetchApplications = async () => {
    try {
      setLoading(true);
      const [appsData, metricsData] = await Promise.all([
        apiService.getRASPApplications(),
        apiService.getRASPMetrics(),
      ]);
      setApplications(appsData);
      setMetrics(metricsData);
    } catch (error) {
      Alert.alert('Error', 'Failed to fetch RASP applications');
    } finally {
      setLoading(false);
    }
  };

  const fetchThreats = async (applicationId: string) => {
    try {
      const threatsData = await apiService.getRASPThreats(applicationId);
      setThreats(threatsData);
    } catch (error) {
      Alert.alert('Error', 'Failed to fetch threats');
    }
  };

  const toggleProtection = async (applicationId: string, enabled: boolean) => {
    try {
      await apiService.updateRASPProtection(applicationId, enabled);
      fetchApplications(); // Refresh the list
      Alert.alert('Success', `Protection ${enabled ? 'enabled' : 'disabled'} successfully`);
    } catch (error) {
      Alert.alert('Error', 'Failed to update protection status');
    }
  };

  useEffect(() => {
    fetchApplications();
  }, []);

  const onRefresh = async () => {
    setRefreshing(true);
    await fetchApplications();
    setRefreshing(false);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return '#4CAF50';
      case 'inactive': return '#9E9E9E';
      case 'error': return '#F44336';
      default: return '#9E9E9E';
    }
  };

  const getThreatTypeColor = (type: string) => {
    switch (type) {
      case 'sql_injection': return '#F44336';
      case 'xss': return '#FF5722';
      case 'rce': return '#E91E63';
      case 'path_traversal': return '#9C27B0';
      case 'authentication_bypass': return '#FF9800';
      default: return '#607D8B';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return '#F44336';
      case 'high': return '#FF5722';
      case 'medium': return '#FF9800';
      case 'low': return '#4CAF50';
      default: return '#9E9E9E';
    }
  };

  const chartConfig = {
    backgroundColor: '#1cc910',
    backgroundGradientFrom: '#1cc910',
    backgroundGradientTo: '#1cc910',
    decimalPlaces: 0,
    color: (opacity = 1) => `rgba(255, 255, 255, ${opacity})`,
    style: {
      borderRadius: 16,
    },
  };

  const renderApplicationCard = (app: RASPApplication) => (
    <Card key={app.id} style={styles.appCard} onPress={() => {
      setSelectedApp(app);
      fetchThreats(app.id);
    }}>
      <Card.Content>
        <View style={styles.appHeader}>
          <View style={styles.appInfo}>
            <Title style={styles.appTitle}>{app.name}</Title>
            <Paragraph style={styles.appType}>{app.application_type}</Paragraph>
          </View>
          <View style={styles.appStatus}>
            <Chip
              mode="outlined"
              textStyle={{ color: getStatusColor(app.status) }}
              style={[styles.statusChip, { borderColor: getStatusColor(app.status) }]}
            >
              {app.status}
            </Chip>
            <Switch
              value={app.protection_enabled}
              onValueChange={(value) => toggleProtection(app.id, value)}
              trackColor={{ false: '#767577', true: '#4CAF50' }}
              thumbColor={app.protection_enabled ? '#fff' : '#f4f3f4'}
            />
          </View>
        </View>
        
        <View style={styles.appMetrics}>
          <View style={styles.metric}>
            <Text style={styles.metricValue}>{app.threats_blocked}</Text>
            <Text style={styles.metricLabel}>Blocked</Text>
          </View>
          <View style={styles.metric}>
            <Text style={styles.metricValue}>{app.attacks_detected}</Text>
            <Text style={styles.metricLabel}>Detected</Text>
          </View>
          <View style={styles.metric}>
            <Text style={styles.metricValue}>{app.false_positives}</Text>
            <Text style={styles.metricLabel}>False Positives</Text>
          </View>
          <View style={styles.metric}>
            <Text style={styles.metricValue}>{app.agent_version}</Text>
            <Text style={styles.metricLabel}>Version</Text>
          </View>
        </View>
        
        <View style={styles.appFooter}>
          <Text style={styles.appDetail}>Environment: {app.environment}</Text>
          <Text style={styles.appDetail}>Last Activity: {new Date(app.last_activity).toLocaleDateString()}</Text>
        </View>
      </Card.Content>
    </Card>
  );

  const renderThreatCard = (threat: RASPThreat) => (
    <Card key={threat.id} style={styles.threatCard} onPress={() => {
      setSelectedThreat(threat);
      setThreatDetailsModal(true);
    }}>
      <Card.Content>
        <View style={styles.threatHeader}>
          <Title style={styles.threatTitle}>{threat.threat_type}</Title>
          <Chip
            mode="outlined"
            textStyle={{ color: getSeverityColor(threat.severity) }}
            style={[styles.severityChip, { borderColor: getSeverityColor(threat.severity) }]}
          >
            {threat.severity}
          </Chip>
        </View>
        
        <Paragraph style={styles.threatDescription}>{threat.description}</Paragraph>
        
        <View style={styles.threatDetails}>
          <Text style={styles.threatDetail}>Source IP: {threat.source_ip}</Text>
          <Text style={styles.threatDetail}>Action: {threat.action_taken}</Text>
          <Text style={styles.threatDetail}>Status: {threat.status}</Text>
          <Text style={styles.threatDetail}>Time: {new Date(threat.timestamp).toLocaleString()}</Text>
        </View>
      </Card.Content>
    </Card>
  );

  if (loading) {
    return (
      <View style={styles.loadingContainer}>
        <Text>Loading RASP applications...</Text>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <LinearGradient colors={['#2196F3', '#1976D2']} style={styles.header}>
        <Text style={styles.headerTitle}>RASP Protection</Text>
        <Text style={styles.headerSubtitle}>Runtime Application Self-Protection</Text>
      </LinearGradient>

      <ScrollView
        style={styles.content}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} />}
      >
        {/* Summary Metrics */}
        <View style={styles.summaryContainer}>
          <Text style={styles.sectionTitle}>Protection Overview</Text>
          <View style={styles.summaryGrid}>
            <View style={styles.summaryCard}>
              <Icon name="shield-alert" size={32} color="#2196F3" />
              <Text style={styles.summaryValue}>{applications.length}</Text>
              <Text style={styles.summaryLabel}>Applications</Text>
            </View>
            <View style={styles.summaryCard}>
              <Icon name="shield-check" size={32} color="#4CAF50" />
              <Text style={styles.summaryValue}>{metrics?.threats_blocked || 0}</Text>
              <Text style={styles.summaryLabel}>Threats Blocked</Text>
            </View>
            <View style={styles.summaryCard}>
              <Icon name="alert-circle" size={32} color="#FF5722" />
              <Text style={styles.summaryValue}>{metrics?.attacks_detected || 0}</Text>
              <Text style={styles.summaryLabel}>Attacks Detected</Text>
            </View>
            <View style={styles.summaryCard}>
              <Icon name="clock" size={32} color="#FF9800" />
              <Text style={styles.summaryValue}>{Math.round(metrics?.response_time_avg || 0)}ms</Text>
              <Text style={styles.summaryLabel}>Avg Response</Text>
            </View>
          </View>
        </View>

        {/* Performance Chart */}
        <View style={styles.chartContainer}>
          <Text style={styles.sectionTitle}>Performance Metrics</Text>
          <LineChart
            data={{
              labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
              datasets: [{
                data: [
                  metrics?.threats_blocked || 0,
                  metrics?.attacks_detected || 0,
                  metrics?.false_positives || 0,
                  metrics?.uptime_percentage || 0,
                  metrics?.response_time_avg || 0,
                  metrics?.threats_blocked || 0,
                  metrics?.attacks_detected || 0,
                ],
              }],
            }}
            width={width - 40}
            height={220}
            chartConfig={chartConfig}
            style={styles.chart}
          />
        </View>

        {/* Applications List */}
        <View style={styles.appsContainer}>
          <Text style={styles.sectionTitle}>Protected Applications</Text>
          {applications.length === 0 ? (
            <Card style={styles.emptyCard}>
              <Card.Content>
                <Text style={styles.emptyText}>No RASP applications found</Text>
                <Text style={styles.emptySubtext}>Deploy RASP agents to your applications to begin protection</Text>
              </Card.Content>
            </Card>
          ) : (
            applications.map(renderApplicationCard)
          )}
        </View>

        {/* Threats List for Selected App */}
        {selectedApp && threats.length > 0 && (
          <View style={styles.threatsContainer}>
            <Text style={styles.sectionTitle}>Recent Threats - {selectedApp.name}</Text>
            {threats.slice(0, 5).map(renderThreatCard)}
          </View>
        )}
      </ScrollView>

      {/* Threat Details Modal */}
      <Portal>
        <Dialog visible={threatDetailsModal} onDismiss={() => setThreatDetailsModal(false)}>
          <Dialog.Title>Threat Details</Dialog.Title>
          <Dialog.Content>
            {selectedThreat && (
              <View>
                <View style={styles.threatModalHeader}>
                  <Text style={styles.threatModalTitle}>{selectedThreat.threat_type}</Text>
                  <Chip
                    mode="outlined"
                    textStyle={{ color: getSeverityColor(selectedThreat.severity) }}
                    style={[styles.severityChip, { borderColor: getSeverityColor(selectedThreat.severity) }]}
                  >
                    {selectedThreat.severity}
                  </Chip>
                </View>
                
                <Text style={styles.threatModalDescription}>{selectedThreat.description}</Text>
                
                <View style={styles.threatModalDetails}>
                  <Text style={styles.threatModalDetail}>Source IP: {selectedThreat.source_ip}</Text>
                  <Text style={styles.threatModalDetail}>User Agent: {selectedThreat.user_agent}</Text>
                  <Text style={styles.threatModalDetail}>Action Taken: {selectedThreat.action_taken}</Text>
                  <Text style={styles.threatModalDetail}>Status: {selectedThreat.status}</Text>
                  <Text style={styles.threatModalDetail}>Timestamp: {new Date(selectedThreat.timestamp).toLocaleString()}</Text>
                </View>
                
                <View style={styles.payloadContainer}>
                  <Text style={styles.payloadTitle}>Payload:</Text>
                  <Text style={styles.payloadText}>{selectedThreat.payload}</Text>
                </View>
              </View>
            )}
          </Dialog.Content>
          <Dialog.Actions>
            <Button onPress={() => setThreatDetailsModal(false)}>Close</Button>
          </Dialog.Actions>
        </Dialog>
      </Portal>
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
    padding: 20,
    paddingTop: 60,
    paddingBottom: 30,
  },
  headerTitle: {
    fontSize: 28,
    fontWeight: 'bold',
    color: 'white',
    marginBottom: 5,
  },
  headerSubtitle: {
    fontSize: 16,
    color: 'rgba(255, 255, 255, 0.8)',
  },
  content: {
    flex: 1,
  },
  summaryContainer: {
    padding: 20,
  },
  sectionTitle: {
    fontSize: 20,
    fontWeight: 'bold',
    marginBottom: 15,
    color: '#333',
  },
  summaryGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    justifyContent: 'space-between',
  },
  summaryCard: {
    width: (width - 60) / 2,
    backgroundColor: 'white',
    padding: 20,
    borderRadius: 12,
    alignItems: 'center',
    marginBottom: 15,
    elevation: 2,
  },
  summaryValue: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#333',
    marginTop: 8,
  },
  summaryLabel: {
    fontSize: 12,
    color: '#666',
    marginTop: 4,
  },
  chartContainer: {
    padding: 20,
    backgroundColor: 'white',
    marginHorizontal: 20,
    borderRadius: 12,
    marginBottom: 20,
  },
  chart: {
    borderRadius: 12,
  },
  appsContainer: {
    padding: 20,
  },
  appCard: {
    marginBottom: 15,
    borderRadius: 12,
    elevation: 2,
  },
  appHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 15,
  },
  appInfo: {
    flex: 1,
  },
  appTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    marginBottom: 4,
  },
  appType: {
    fontSize: 14,
    color: '#666',
  },
  appStatus: {
    alignItems: 'flex-end',
  },
  statusChip: {
    marginBottom: 10,
  },
  appMetrics: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 15,
  },
  metric: {
    alignItems: 'center',
  },
  metricValue: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#333',
  },
  metricLabel: {
    fontSize: 10,
    color: '#666',
    marginTop: 2,
  },
  appFooter: {
    borderTopWidth: 1,
    borderTopColor: '#eee',
    paddingTop: 10,
  },
  appDetail: {
    fontSize: 12,
    color: '#666',
  },
  threatsContainer: {
    padding: 20,
  },
  threatCard: {
    marginBottom: 15,
    borderRadius: 8,
  },
  threatHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 10,
  },
  threatTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    flex: 1,
    marginRight: 10,
  },
  severityChip: {
    marginLeft: 10,
  },
  threatDescription: {
    fontSize: 14,
    color: '#666',
    marginBottom: 10,
  },
  threatDetails: {
    marginBottom: 10,
  },
  threatDetail: {
    fontSize: 12,
    color: '#666',
    marginBottom: 2,
  },
  emptyCard: {
    marginBottom: 15,
    borderRadius: 12,
  },
  emptyText: {
    fontSize: 16,
    textAlign: 'center',
    color: '#666',
  },
  emptySubtext: {
    fontSize: 14,
    textAlign: 'center',
    color: '#999',
    marginTop: 5,
  },
  threatModalHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 15,
  },
  threatModalTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    flex: 1,
    marginRight: 10,
  },
  threatModalDescription: {
    fontSize: 14,
    color: '#666',
    marginBottom: 15,
  },
  threatModalDetails: {
    marginBottom: 15,
  },
  threatModalDetail: {
    fontSize: 12,
    color: '#666',
    marginBottom: 5,
  },
  payloadContainer: {
    backgroundColor: '#f5f5f5',
    padding: 10,
    borderRadius: 5,
  },
  payloadTitle: {
    fontSize: 14,
    fontWeight: 'bold',
    color: '#333',
    marginBottom: 5,
  },
  payloadText: {
    fontSize: 12,
    color: '#666',
    fontFamily: 'monospace',
  },
});

export default RASPScreen; 