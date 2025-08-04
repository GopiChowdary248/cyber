import React, { useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  Alert,
  RefreshControl,
  ActivityIndicator,
} from 'react-native';
import { Card, Button, Chip, ProgressBar, Divider, Switch } from 'react-native-paper';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { COLORS, SIZES, FONTS } from '../../constants/theme';

interface NetworkDevice {
  id: string;
  name: string;
  type: 'firewall' | 'ids' | 'ips' | 'vpn' | 'switch' | 'router';
  ip_address: string;
  mac_address: string;
  status: 'online' | 'offline' | 'warning' | 'error';
  location: string;
  vendor: string;
  model: string;
  firmware_version: string;
  last_seen: string;
  threats_blocked: number;
  attacks_detected: number;
  bandwidth_usage: number;
  cpu_usage: number;
  memory_usage: number;
}

interface NetworkThreat {
  id: string;
  device_id: string;
  threat_type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  source_ip: string;
  destination_ip: string;
  port: number;
  protocol: string;
  description: string;
  timestamp: string;
  action_taken: 'blocked' | 'logged' | 'alerted' | 'quarantined';
  status: 'active' | 'resolved' | 'false_positive';
  signature_id: string;
  category: string;
}

interface NetworkMetrics {
  total_devices: number;
  online_devices: number;
  threats_blocked: number;
  attacks_detected: number;
  bandwidth_avg: number;
  uptime_percentage: number;
  security_score: number;
}

const NetworkSecurityScreen: React.FC = () => {
  const [selectedDevice, setSelectedDevice] = useState<NetworkDevice | null>(null);
  const [showThreats, setShowThreats] = useState(false);
  const [showMetrics, setShowMetrics] = useState(false);
  const [selectedDeviceType, setSelectedDeviceType] = useState<string>('all');
  const queryClient = useQueryClient();

  // Fetch network devices
  const { data: devices, isLoading: devicesLoading, refetch: refetchDevices } = useQuery({
    queryKey: ['network-devices', selectedDeviceType],
    queryFn: async () => {
      const url = selectedDeviceType === 'all' 
        ? 'http://localhost:8000/api/v1/network-security/devices'
        : `http://localhost:8000/api/v1/network-security/devices?type=${selectedDeviceType}`;
      const response = await fetch(url);
      if (!response.ok) throw new Error('Failed to fetch devices');
      return response.json();
    },
  });

  // Fetch threats for selected device
  const { data: threats, isLoading: threatsLoading } = useQuery({
    queryKey: ['network-threats', selectedDevice?.id],
    queryFn: async () => {
      if (!selectedDevice) return [];
      const response = await fetch(`http://localhost:8000/api/v1/network-security/devices/${selectedDevice.id}/threats`);
      if (!response.ok) throw new Error('Failed to fetch threats');
      return response.json();
    },
    enabled: !!selectedDevice,
  });

  // Fetch network security metrics
  const { data: metrics, isLoading: metricsLoading } = useQuery({
    queryKey: ['network-metrics'],
    queryFn: async () => {
      const response = await fetch('http://localhost:8000/api/v1/network-security/metrics');
      if (!response.ok) throw new Error('Failed to fetch metrics');
      return response.json();
    },
  });

  // Update device status mutation
  const updateDeviceStatusMutation = useMutation({
    mutationFn: async ({ deviceId, status }: { deviceId: string; status: string }) => {
      const response = await fetch(`http://localhost:8000/api/v1/network-security/devices/${deviceId}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status }),
      });
      if (!response.ok) throw new Error('Failed to update device status');
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['network-devices'] });
      Alert.alert('Success', 'Device status updated');
    },
    onError: (error) => {
      Alert.alert('Error', 'Failed to update device status');
    },
  });

  const handleUpdateDeviceStatus = (device: NetworkDevice, newStatus: string) => {
    updateDeviceStatusMutation.mutate({
      deviceId: device.id,
      status: newStatus,
    });
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return '#FF4444';
      case 'high': return '#FF8800';
      case 'medium': return '#FFCC00';
      case 'low': return '#00CC00';
      case 'info': return '#0088FF';
      default: return COLORS.gray;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online': return '#00CC00';
      case 'offline': return '#FF4444';
      case 'warning': return '#FFCC00';
      case 'error': return '#FF8800';
      default: return COLORS.gray;
    }
  };

  const getActionColor = (action: string) => {
    switch (action) {
      case 'blocked': return '#FF4444';
      case 'logged': return '#FFCC00';
      case 'alerted': return '#FF8800';
      case 'quarantined': return '#8800FF';
      default: return COLORS.gray;
    }
  };

  const getDeviceIcon = (type: string) => {
    switch (type) {
      case 'firewall': return 'shield-fire';
      case 'ids': return 'shield-alert';
      case 'ips': return 'shield-check';
      case 'vpn': return 'vpn';
      case 'switch': return 'ethernet';
      case 'router': return 'router-wireless';
      default: return 'network';
    }
  };

  const renderDeviceCard = (device: NetworkDevice) => (
    <Card key={device.id} style={styles.deviceCard}>
      <Card.Content>
        <View style={styles.deviceHeader}>
          <View style={styles.deviceInfo}>
            <View style={styles.deviceTitleRow}>
              <Icon name={getDeviceIcon(device.type)} size={20} color={COLORS.primary} />
              <Text style={styles.deviceName}>{device.name}</Text>
            </View>
            <View style={styles.deviceMeta}>
              <Text style={styles.deviceType}>{device.type.toUpperCase()}</Text>
              <Text style={styles.deviceIP}>{device.ip_address}</Text>
              <Text style={styles.deviceLocation}>{device.location}</Text>
            </View>
          </View>
          <Chip
            mode="outlined"
            textStyle={{ color: getStatusColor(device.status) }}
            style={{ borderColor: getStatusColor(device.status) }}
          >
            {device.status.toUpperCase()}
          </Chip>
        </View>
        
        <View style={styles.deviceStats}>
          <View style={styles.statItem}>
            <Text style={[styles.statNumber, { color: '#FF4444' }]}>
              {device.threats_blocked}
            </Text>
            <Text style={styles.statLabel}>Blocked</Text>
          </View>
          <View style={styles.statItem}>
            <Text style={[styles.statNumber, { color: '#FF8800' }]}>
              {device.attacks_detected}
            </Text>
            <Text style={styles.statLabel}>Detected</Text>
          </View>
          <View style={styles.statItem}>
            <Text style={styles.statNumber}>{device.bandwidth_usage}%</Text>
            <Text style={styles.statLabel}>Bandwidth</Text>
          </View>
          <View style={styles.statItem}>
            <Text style={styles.statNumber}>{device.cpu_usage}%</Text>
            <Text style={styles.statLabel}>CPU</Text>
          </View>
        </View>

        <View style={styles.deviceDetails}>
          <Text style={styles.deviceDetail}>
            <Icon name="server" size={16} color={COLORS.gray} />
            {device.vendor} {device.model}
          </Text>
          <Text style={styles.deviceDetail}>
            <Icon name="tag" size={16} color={COLORS.gray} />
            v{device.firmware_version}
          </Text>
          <Text style={styles.deviceDetail}>
            <Icon name="clock-outline" size={16} color={COLORS.gray} />
            Last seen: {new Date(device.last_seen).toLocaleString()}
          </Text>
        </View>
      </Card.Content>
      
      <Card.Actions>
        <Button
          mode="outlined"
          onPress={() => setSelectedDevice(device)}
          style={styles.actionButton}
        >
          View Details
        </Button>
        <Button
          mode="contained"
          onPress={() => setShowThreats(true)}
          style={styles.actionButton}
        >
          View Threats
        </Button>
      </Card.Actions>
    </Card>
  );

  const renderThreatCard = (threat: NetworkThreat) => (
    <Card key={threat.id} style={styles.threatCard}>
      <Card.Content>
        <View style={styles.threatHeader}>
          <Text style={styles.threatTitle}>{threat.threat_type}</Text>
          <View style={styles.threatBadges}>
            <Chip
              mode="outlined"
              textStyle={{ color: getSeverityColor(threat.severity) }}
              style={{ borderColor: getSeverityColor(threat.severity), marginRight: 8 }}
            >
              {threat.severity.toUpperCase()}
            </Chip>
            <Chip
              mode="outlined"
              textStyle={{ color: getActionColor(threat.action_taken) }}
              style={{ borderColor: getActionColor(threat.action_taken) }}
            >
              {threat.action_taken.toUpperCase()}
            </Chip>
          </View>
        </View>
        
        <Text style={styles.threatDescription}>{threat.description}</Text>
        
        <View style={styles.threatDetails}>
          <Text style={styles.threatDetail}>
            <Icon name="ip-network" size={16} color={COLORS.gray} />
            {threat.source_ip} → {threat.destination_ip}
          </Text>
          <Text style={styles.threatDetail}>
            <Icon name="connection" size={16} color={COLORS.gray} />
            {threat.protocol.toUpperCase()} Port {threat.port}
          </Text>
          <Text style={styles.threatDetail}>
            <Icon name="clock" size={16} color={COLORS.gray} />
            {new Date(threat.timestamp).toLocaleString()}
          </Text>
          <Text style={styles.threatDetail}>
            <Icon name="tag" size={16} color={COLORS.gray} />
            {threat.category}
          </Text>
        </View>
      </Card.Content>
    </Card>
  );

  const renderMetricsCard = () => (
    <Card style={styles.metricsCard}>
      <Card.Content>
        <Text style={styles.metricsTitle}>Network Security Overview</Text>
        
        <View style={styles.metricsGrid}>
          <View style={styles.metricItem}>
            <Text style={styles.metricValue}>{metrics?.total_devices || 0}</Text>
            <Text style={styles.metricLabel}>Total Devices</Text>
          </View>
          <View style={styles.metricItem}>
            <Text style={styles.metricValue}>{metrics?.online_devices || 0}</Text>
            <Text style={styles.metricLabel}>Online Devices</Text>
          </View>
          <View style={styles.metricItem}>
            <Text style={styles.metricValue}>{metrics?.threats_blocked || 0}</Text>
            <Text style={styles.metricLabel}>Threats Blocked</Text>
          </View>
          <View style={styles.metricItem}>
            <Text style={styles.metricValue}>{metrics?.attacks_detected || 0}</Text>
            <Text style={styles.metricLabel}>Attacks Detected</Text>
          </View>
          <View style={styles.metricItem}>
            <Text style={styles.metricValue}>{metrics?.security_score || 0}%</Text>
            <Text style={styles.metricLabel}>Security Score</Text>
          </View>
          <View style={styles.metricItem}>
            <Text style={styles.metricValue}>{metrics?.uptime_percentage || 0}%</Text>
            <Text style={styles.metricLabel}>Uptime</Text>
          </View>
        </View>
      </Card.Content>
    </Card>
  );

  const renderDeviceTypeFilter = () => (
    <View style={styles.filterContainer}>
      <Text style={styles.filterTitle}>Filter by Device Type:</Text>
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
        <Button
          mode={selectedDeviceType === 'vpn' ? 'contained' : 'outlined'}
          onPress={() => setSelectedDeviceType('vpn')}
          style={styles.filterButton}
        >
          VPN
        </Button>
      </View>
    </View>
  );

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.headerTitle}>Network Security</Text>
        <Button
          mode="contained"
          onPress={() => setShowMetrics(!showMetrics)}
          style={styles.metricsButton}
        >
          {showMetrics ? 'Hide Metrics' : 'Show Metrics'}
        </Button>
      </View>

      <ScrollView
        style={styles.content}
        refreshControl={
          <RefreshControl refreshing={devicesLoading} onRefresh={refetchDevices} />
        }
      >
        {renderDeviceTypeFilter()}

        {showMetrics && renderMetricsCard()}

        {devicesLoading ? (
          <View style={styles.loadingContainer}>
            <ActivityIndicator size="large" color={COLORS.primary} />
            <Text style={styles.loadingText}>Loading network devices...</Text>
          </View>
        ) : (
          <>
            <View style={styles.statsContainer}>
              <Card style={styles.statCard}>
                <Card.Content>
                  <Text style={styles.statTitle}>Total Devices</Text>
                  <Text style={styles.statValue}>{devices?.length || 0}</Text>
                </Card.Content>
              </Card>
              
              <Card style={styles.statCard}>
                <Card.Content>
                  <Text style={styles.statTitle}>Online Devices</Text>
                  <Text style={styles.statValue}>
                    {devices?.filter(d => d.status === 'online').length || 0}
                  </Text>
                </Card.Content>
              </Card>
              
              <Card style={styles.statCard}>
                <Card.Content>
                  <Text style={styles.statTitle}>Threats Blocked</Text>
                  <Text style={styles.statValue}>
                    {devices?.reduce((sum, device) => sum + device.threats_blocked, 0) || 0}
                  </Text>
                </Card.Content>
              </Card>
            </View>

            <Text style={styles.sectionTitle}>Network Devices</Text>
            
            {devices?.map(renderDeviceCard) || (
              <Card style={styles.emptyCard}>
                <Card.Content>
                  <Text style={styles.emptyText}>No network devices found</Text>
                  <Text style={styles.emptySubtext}>
                    Add network devices to start monitoring security
                  </Text>
                </Card.Content>
              </Card>
            )}

            {showThreats && selectedDevice && (
              <View style={styles.threatsSection}>
                <View style={styles.sectionHeader}>
                  <Text style={styles.sectionTitle}>
                    Threats - {selectedDevice.name}
                  </Text>
                  <TouchableOpacity
                    onPress={() => setShowThreats(false)}
                    style={styles.closeButton}
                  >
                    <Icon name="close" size={24} color={COLORS.white} />
                  </TouchableOpacity>
                </View>
                
                {threatsLoading ? (
                  <ActivityIndicator size="large" color={COLORS.primary} />
                ) : (
                  threats?.map(renderThreatCard) || (
                    <Text style={styles.emptyText}>No threats detected</Text>
                  )
                )}
              </View>
            )}
          </>
        )}
      </ScrollView>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: COLORS.dark,
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: 16,
    backgroundColor: COLORS.dark,
    borderBottomWidth: 1,
    borderBottomColor: COLORS.border,
  },
  headerTitle: {
    fontSize: 24,
    fontFamily: FONTS.bold,
    color: COLORS.white,
  },
  metricsButton: {
    backgroundColor: COLORS.primary,
  },
  content: {
    flex: 1,
    padding: 16,
  },
  filterContainer: {
    marginBottom: 16,
  },
  filterTitle: {
    fontSize: 16,
    fontFamily: FONTS.bold,
    color: COLORS.white,
    marginBottom: 8,
  },
  filterButtons: {
    flexDirection: 'row',
    flexWrap: 'wrap',
  },
  filterButton: {
    marginRight: 8,
    marginBottom: 8,
  },
  loadingContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  loadingText: {
    color: COLORS.white,
    fontSize: 16,
    marginTop: 16,
  },
  metricsCard: {
    marginBottom: 16,
    backgroundColor: COLORS.card,
  },
  metricsTitle: {
    fontSize: 18,
    fontFamily: FONTS.bold,
    color: COLORS.white,
    marginBottom: 16,
  },
  metricsGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    justifyContent: 'space-between',
  },
  metricItem: {
    width: '48%',
    alignItems: 'center',
    marginBottom: 16,
  },
  metricValue: {
    fontSize: 24,
    fontFamily: FONTS.bold,
    color: COLORS.white,
  },
  metricLabel: {
    fontSize: 12,
    color: COLORS.gray,
    fontFamily: FONTS.medium,
    textAlign: 'center',
    marginTop: 4,
  },
  statsContainer: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 24,
  },
  statCard: {
    flex: 1,
    marginHorizontal: 4,
    backgroundColor: COLORS.card,
  },
  statTitle: {
    fontSize: 12,
    color: COLORS.gray,
    fontFamily: FONTS.medium,
  },
  statValue: {
    fontSize: 24,
    color: COLORS.white,
    fontFamily: FONTS.bold,
    marginTop: 4,
  },
  sectionTitle: {
    fontSize: 20,
    fontFamily: FONTS.bold,
    color: COLORS.white,
    marginBottom: 16,
  },
  deviceCard: {
    marginBottom: 16,
    backgroundColor: COLORS.card,
  },
  deviceHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 12,
  },
  deviceInfo: {
    flex: 1,
  },
  deviceTitleRow: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 4,
  },
  deviceName: {
    fontSize: 18,
    fontFamily: FONTS.bold,
    color: COLORS.white,
    marginLeft: 8,
  },
  deviceMeta: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  deviceType: {
    fontSize: 12,
    color: COLORS.gray,
    fontFamily: FONTS.medium,
  },
  deviceIP: {
    fontSize: 12,
    color: COLORS.gray,
    fontFamily: FONTS.medium,
    marginLeft: 8,
  },
  deviceLocation: {
    fontSize: 12,
    color: COLORS.gray,
    fontFamily: FONTS.medium,
    marginLeft: 8,
  },
  deviceStats: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 12,
  },
  statItem: {
    alignItems: 'center',
  },
  statNumber: {
    fontSize: 20,
    fontFamily: FONTS.bold,
    color: COLORS.white,
  },
  statLabel: {
    fontSize: 12,
    color: COLORS.gray,
    fontFamily: FONTS.medium,
  },
  deviceDetails: {
    marginBottom: 12,
  },
  deviceDetail: {
    fontSize: 12,
    color: COLORS.gray,
    fontFamily: FONTS.medium,
    marginBottom: 4,
  },
  actionButton: {
    marginRight: 8,
  },
  emptyCard: {
    backgroundColor: COLORS.card,
    alignItems: 'center',
    padding: 32,
  },
  emptyText: {
    fontSize: 16,
    color: COLORS.white,
    fontFamily: FONTS.medium,
    textAlign: 'center',
  },
  emptySubtext: {
    fontSize: 14,
    color: COLORS.gray,
    fontFamily: FONTS.regular,
    textAlign: 'center',
    marginTop: 8,
  },
  threatsSection: {
    marginTop: 24,
  },
  sectionHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 16,
  },
  closeButton: {
    padding: 8,
  },
  threatCard: {
    marginBottom: 16,
    backgroundColor: COLORS.card,
  },
  threatHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 12,
  },
  threatTitle: {
    fontSize: 16,
    fontFamily: FONTS.bold,
    color: COLORS.white,
    flex: 1,
    marginRight: 12,
  },
  threatBadges: {
    flexDirection: 'row',
  },
  threatDescription: {
    fontSize: 14,
    color: COLORS.lightGray,
    fontFamily: FONTS.regular,
    marginBottom: 12,
  },
  threatDetails: {
    marginBottom: 12,
  },
  threatDetail: {
    fontSize: 12,
    color: COLORS.gray,
    fontFamily: FONTS.medium,
    marginBottom: 4,
  },
});

export default NetworkSecurityScreen; 