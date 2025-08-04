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
import { LineChart, BarChart } from 'react-native-chart-kit';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';
import { APIService, NetworkDevice, NetworkThreat } from '../services/APIService';
import { Dimensions } from 'react-native';

const { width } = Dimensions.get('window');

const NetworkSecurityScreen: React.FC = ({ navigation }: any) => {
  const [devices, setDevices] = useState<NetworkDevice[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<NetworkDevice | null>(null);
  const [threats, setThreats] = useState<NetworkThreat[]>([]);
  const [metrics, setMetrics] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [threatDetailsModal, setThreatDetailsModal] = useState(false);
  const [selectedThreat, setSelectedThreat] = useState<NetworkThreat | null>(null);
  const [selectedDeviceType, setSelectedDeviceType] = useState<string>('all');

  const apiService = new APIService();

  const fetchDevices = async () => {
    try {
      setLoading(true);
      const [devicesData, metricsData] = await Promise.all([
        apiService.getNetworkDevices(selectedDeviceType === 'all' ? undefined : selectedDeviceType),
        apiService.getNetworkMetrics(),
      ]);
      setDevices(devicesData);
      setMetrics(metricsData);
    } catch (error) {
      Alert.alert('Error', 'Failed to fetch network devices');
    } finally {
      setLoading(false);
    }
  };

  const fetchThreats = async (deviceId: string) => {
    try {
      const threatsData = await apiService.getNetworkThreats(deviceId);
      setThreats(threatsData);
    } catch (error) {
      Alert.alert('Error', 'Failed to fetch network threats');
    }
  };

  const updateDeviceStatus = async (deviceId: string, status: string) => {
    try {
      await apiService.updateDeviceStatus(deviceId, status);
      fetchDevices(); // Refresh the list
      Alert.alert('Success', 'Device status updated successfully');
    } catch (error) {
      Alert.alert('Error', 'Failed to update device status');
    }
  };

  useEffect(() => {
    fetchDevices();
  }, [selectedDeviceType]);

  const onRefresh = async () => {
    setRefreshing(true);
    await fetchDevices();
    setRefreshing(false);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online': return '#4CAF50';
      case 'offline': return '#9E9E9E';
      case 'warning': return '#FF9800';
      case 'error': return '#F44336';
      default: return '#9E9E9E';
    }
  };

  const getDeviceTypeColor = (type: string) => {
    switch (type) {
      case 'firewall': return '#F44336';
      case 'ids': return '#FF5722';
      case 'ips': return '#E91E63';
      case 'vpn': return '#9C27B0';
      case 'switch': return '#2196F3';
      case 'router': return '#4CAF50';
      default: return '#607D8B';
    }
  };

  const getThreatCategoryColor = (category: string) => {
    switch (category) {
      case 'malware': return '#F44336';
      case 'ddos': return '#FF5722';
      case 'intrusion': return '#E91E63';
      case 'phishing': return '#9C27B0';
      case 'data_exfiltration': return '#FF9800';
      default: return '#607D8B';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return '#F44336';
      case 'high': return '#FF5722';
      case 'medium': return '#FF9800';
      case 'low': return '#4CAF50';
      case 'info': return '#2196F3';
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

  const renderDeviceCard = (device: NetworkDevice) => (
    <Card key={device.id} style={styles.deviceCard} onPress={() => {
      setSelectedDevice(device);
      fetchThreats(device.id);
    }}>
      <Card.Content>
        <View style={styles.deviceHeader}>
          <View style={styles.deviceInfo}>
            <Title style={styles.deviceTitle}>{device.name}</Title>
            <Paragraph style={styles.deviceType}>{device.type.toUpperCase()}</Paragraph>
          </View>
          <View style={styles.deviceStatus}>
            <Chip
              mode="outlined"
              textStyle={{ color: getStatusColor(device.status) }}
              style={[styles.statusChip, { borderColor: getStatusColor(device.status) }]}
            >
              {device.status}
            </Chip>
            <Chip
              mode="outlined"
              textStyle={{ color: getDeviceTypeColor(device.type) }}
              style={[styles.typeChip, { borderColor: getDeviceTypeColor(device.type) }]}
            >
              {device.type}
            </Chip>
          </View>
        </View>
        
        <View style={styles.deviceMetrics}>
          <View style={styles.metric}>
            <Text style={styles.metricValue}>{device.threats_blocked}</Text>
            <Text style={styles.metricLabel}>Blocked</Text>
          </View>
          <View style={styles.metric}>
            <Text style={styles.metricValue}>{device.attacks_detected}</Text>
            <Text style={styles.metricLabel}>Detected</Text>
          </View>
          <View style={styles.metric}>
            <Text style={styles.metricValue}>{device.bandwidth_usage}%</Text>
            <Text style={styles.metricLabel}>Bandwidth</Text>
          </View>
          <View style={styles.metric}>
            <Text style={styles.metricValue}>{device.cpu_usage}%</Text>
            <Text style={styles.metricLabel}>CPU</Text>
          </View>
        </View>
        
        <View style={styles.deviceFooter}>
          <Text style={styles.deviceDetail}>IP: {device.ip_address}</Text>
          <Text style={styles.deviceDetail}>Vendor: {device.vendor}</Text>
          <Text style={styles.deviceDetail}>Model: {device.model}</Text>
          <Text style={styles.deviceDetail}>Last Seen: {new Date(device.last_seen).toLocaleDateString()}</Text>
        </View>
      </Card.Content>
    </Card>
  );

  const renderThreatCard = (threat: NetworkThreat) => (
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
          <Text style={styles.threatDetail}>Source: {threat.source_ip}</Text>
          <Text style={styles.threatDetail}>Destination: {threat.destination_ip}</Text>
          <Text style={styles.threatDetail}>Port: {threat.port}</Text>
          <Text style={styles.threatDetail}>Protocol: {threat.protocol}</Text>
          <Text style={styles.threatDetail}>Action: {threat.action_taken}</Text>
          <Text style={styles.threatDetail}>Time: {new Date(threat.timestamp).toLocaleString()}</Text>
        </View>
      </Card.Content>
    </Card>
  );

  if (loading) {
    return (
      <View style={styles.loadingContainer}>
        <Text>Loading network devices...</Text>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <LinearGradient colors={['#FF9800', '#F57C00']} style={styles.header}>
        <Text style={styles.headerTitle}>Network Security</Text>
        <Text style={styles.headerSubtitle}>Network Infrastructure Protection</Text>
      </LinearGradient>

      <ScrollView
        style={styles.content}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} />}
      >
        {/* Device Type Filter */}
        <View style={styles.filterContainer}>
          <Text style={styles.sectionTitle}>Device Type</Text>
          <View style={styles.filterButtons}>
            <Button
              mode={selectedDeviceType === 'all' ? 'contained' : 'outlined'}
              onPress={() => setSelectedDeviceType('all')}
              style={styles.filterButton}
            >
              All
            </Button>
            <Button
              mode={selectedDeviceType === 'firewall' ? 'contained' : 'outlined'}
              onPress={() => setSelectedDeviceType('firewall')}
              style={styles.filterButton}
            >
              Firewall
            </Button>
            <Button
              mode={selectedDeviceType === 'ids' ? 'contained' : 'outlined'}
              onPress={() => setSelectedDeviceType('ids')}
              style={styles.filterButton}
            >
              IDS
            </Button>
            <Button
              mode={selectedDeviceType === 'ips' ? 'contained' : 'outlined'}
              onPress={() => setSelectedDeviceType('ips')}
              style={styles.filterButton}
            >
              IPS
            </Button>
          </View>
        </View>

        {/* Summary Metrics */}
        <View style={styles.summaryContainer}>
          <Text style={styles.sectionTitle}>Network Overview</Text>
          <View style={styles.summaryGrid}>
            <View style={styles.summaryCard}>
              <Icon name="network" size={32} color="#FF9800" />
              <Text style={styles.summaryValue}>{metrics?.total_devices || 0}</Text>
              <Text style={styles.summaryLabel}>Devices</Text>
            </View>
            <View style={styles.summaryCard}>
              <Icon name="check-circle" size={32} color="#4CAF50" />
              <Text style={styles.summaryValue}>{metrics?.online_devices || 0}</Text>
              <Text style={styles.summaryLabel}>Online</Text>
            </View>
            <View style={styles.summaryCard}>
              <Icon name="shield-check" size={32} color="#2196F3" />
              <Text style={styles.summaryValue}>{metrics?.threats_blocked || 0}</Text>
              <Text style={styles.summaryLabel}>Blocked</Text>
            </View>
            <View style={styles.summaryCard}>
              <Icon name="alert-circle" size={32} color="#FF5722" />
              <Text style={styles.summaryValue}>{metrics?.attacks_detected || 0}</Text>
              <Text style={styles.summaryLabel}>Detected</Text>
            </View>
          </View>
        </View>

        {/* Network Performance Chart */}
        <View style={styles.chartContainer}>
          <Text style={styles.sectionTitle}>Network Performance</Text>
          <LineChart
            data={{
              labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
              datasets: [{
                data: [
                  metrics?.threats_blocked || 0,
                  metrics?.attacks_detected || 0,
                  metrics?.bandwidth_avg || 0,
                  metrics?.uptime_percentage || 0,
                  metrics?.security_score || 0,
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

        {/* Devices List */}
        <View style={styles.devicesContainer}>
          <Text style={styles.sectionTitle}>Network Devices</Text>
          {devices.length === 0 ? (
            <Card style={styles.emptyCard}>
              <Card.Content>
                <Text style={styles.emptyText}>No network devices found</Text>
                <Text style={styles.emptySubtext}>Add network devices to begin monitoring</Text>
              </Card.Content>
            </Card>
          ) : (
            devices.map(renderDeviceCard)
          )}
        </View>

        {/* Threats List for Selected Device */}
        {selectedDevice && threats.length > 0 && (
          <View style={styles.threatsContainer}>
            <Text style={styles.sectionTitle}>Recent Threats - {selectedDevice.name}</Text>
            {threats.slice(0, 5).map(renderThreatCard)}
          </View>
        )}
      </ScrollView>

      {/* Threat Details Modal */}
      <Portal>
        <Dialog visible={threatDetailsModal} onDismiss={() => setThreatDetailsModal(false)}>
          <Dialog.Title>Network Threat Details</Dialog.Title>
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
                  <Text style={styles.threatModalDetail}>Destination IP: {selectedThreat.destination_ip}</Text>
                  <Text style={styles.threatModalDetail}>Port: {selectedThreat.port}</Text>
                  <Text style={styles.threatModalDetail}>Protocol: {selectedThreat.protocol}</Text>
                  <Text style={styles.threatModalDetail}>Action Taken: {selectedThreat.action_taken}</Text>
                  <Text style={styles.threatModalDetail}>Status: {selectedThreat.status}</Text>
                  <Text style={styles.threatModalDetail}>Signature ID: {selectedThreat.signature_id}</Text>
                  <Text style={styles.threatModalDetail}>Category: {selectedThreat.category}</Text>
                  <Text style={styles.threatModalDetail}>Timestamp: {new Date(selectedThreat.timestamp).toLocaleString()}</Text>
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
  filterContainer: {
    padding: 20,
  },
  sectionTitle: {
    fontSize: 20,
    fontWeight: 'bold',
    marginBottom: 15,
    color: '#333',
  },
  filterButtons: {
    flexDirection: 'row',
    justifyContent: 'space-between',
  },
  filterButton: {
    flex: 1,
    marginHorizontal: 5,
  },
  summaryContainer: {
    padding: 20,
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
  devicesContainer: {
    padding: 20,
  },
  deviceCard: {
    marginBottom: 15,
    borderRadius: 12,
    elevation: 2,
  },
  deviceHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 15,
  },
  deviceInfo: {
    flex: 1,
  },
  deviceTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    marginBottom: 4,
  },
  deviceType: {
    fontSize: 14,
    color: '#666',
  },
  deviceStatus: {
    alignItems: 'flex-end',
  },
  statusChip: {
    marginBottom: 5,
  },
  typeChip: {
    marginLeft: 10,
  },
  deviceMetrics: {
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
  deviceFooter: {
    borderTopWidth: 1,
    borderTopColor: '#eee',
    paddingTop: 10,
  },
  deviceDetail: {
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
});

export default NetworkSecurityScreen; 