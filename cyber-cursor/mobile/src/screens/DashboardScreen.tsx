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
import { LinearGradient } from 'react-native-linear-gradient';
import { Card, Title, Paragraph, Button, IconButton } from 'react-native-paper';
import { LineChart, BarChart, PieChart } from 'react-native-chart-kit';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';
import { APIService } from '../services/APIService';

const { width } = Dimensions.get('window');

interface SecurityMetrics {
  sast: {
    total_scans: number;
    vulnerabilities_found: number;
    critical_count: number;
    high_count: number;
  };
  dast: {
    total_scans: number;
    vulnerabilities_found: number;
    critical_count: number;
    high_count: number;
  };
  rasp: {
    applications_monitored: number;
    threats_blocked: number;
    attacks_detected: number;
  };
  cloud: {
    total_resources: number;
    secure_resources: number;
    critical_findings: number;
    high_findings: number;
  };
  network: {
    total_devices: number;
    online_devices: number;
    threats_blocked: number;
    attacks_detected: number;
  };
}

const DashboardScreen: React.FC = ({ navigation }: any) => {
  const [metrics, setMetrics] = useState<SecurityMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const apiService = new APIService();

  const fetchMetrics = async () => {
    try {
      setLoading(true);
      // Fetch metrics from all security modules
      const [sastMetrics, dastMetrics, raspMetrics, cloudMetrics, networkMetrics] = await Promise.all([
        apiService.getSASTScans().then(scans => ({
          total_scans: scans.length,
          vulnerabilities_found: scans.reduce((sum, scan) => sum + scan.vulnerabilities_count, 0),
          critical_count: scans.reduce((sum, scan) => sum + scan.critical_count, 0),
          high_count: scans.reduce((sum, scan) => sum + scan.high_count, 0),
        })),
        apiService.getDASTScans().then(scans => ({
          total_scans: scans.length,
          vulnerabilities_found: scans.reduce((sum, scan) => sum + scan.vulnerabilities_count, 0),
          critical_count: scans.reduce((sum, scan) => sum + scan.critical_count, 0),
          high_count: scans.reduce((sum, scan) => sum + scan.high_count, 0),
        })),
        apiService.getRASPMetrics(),
        apiService.getCloudMetrics(),
        apiService.getNetworkMetrics(),
      ]);

      setMetrics({
        sast: sastMetrics,
        dast: dastMetrics,
        rasp: raspMetrics,
        cloud: cloudMetrics,
        network: networkMetrics,
      });
    } catch (error) {
      Alert.alert('Error', 'Failed to fetch security metrics');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMetrics();
  }, []);

  const onRefresh = async () => {
    setRefreshing(true);
    await fetchMetrics();
    setRefreshing(false);
  };

  const navigateToModule = (module: string) => {
    navigation.navigate(module);
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

  const vulnerabilityData = {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [
      {
        data: [
          (metrics?.sast.critical_count || 0) + (metrics?.dast.critical_count || 0),
          (metrics?.sast.high_count || 0) + (metrics?.dast.high_count || 0),
          0, // Medium count would be calculated
          0, // Low count would be calculated
        ],
      },
    ],
  };

  const renderMetricCard = (title: string, value: number, icon: string, color: string, onPress?: () => void) => (
    <TouchableOpacity onPress={onPress} style={styles.metricCard}>
      <LinearGradient colors={[color, color + '80']} style={styles.metricGradient}>
        <Icon name={icon} size={24} color="white" />
        <Text style={styles.metricValue}>{value}</Text>
        <Text style={styles.metricTitle}>{title}</Text>
      </LinearGradient>
    </TouchableOpacity>
  );

  const renderModuleCard = (title: string, description: string, icon: string, color: string, onPress: () => void) => (
    <Card style={styles.moduleCard} onPress={onPress}>
      <Card.Content style={styles.moduleCardContent}>
        <View style={styles.moduleIconContainer}>
          <Icon name={icon} size={32} color={color} />
        </View>
        <View style={styles.moduleTextContainer}>
          <Title style={styles.moduleTitle}>{title}</Title>
          <Paragraph style={styles.moduleDescription}>{description}</Paragraph>
        </View>
        <Icon name="chevron-right" size={24} color="#666" />
      </Card.Content>
    </Card>
  );

  if (loading) {
    return (
      <View style={styles.loadingContainer}>
        <Text>Loading security dashboard...</Text>
      </View>
    );
  }

  return (
    <ScrollView
      style={styles.container}
      refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} />}
    >
      <LinearGradient colors={['#1e3c72', '#2a5298']} style={styles.header}>
        <Text style={styles.headerTitle}>CyberShield Dashboard</Text>
        <Text style={styles.headerSubtitle}>Security Overview</Text>
      </LinearGradient>

      {/* Security Metrics */}
      <View style={styles.metricsContainer}>
        <Text style={styles.sectionTitle}>Security Metrics</Text>
        <View style={styles.metricsGrid}>
          {renderMetricCard(
            'Total Scans',
            (metrics?.sast.total_scans || 0) + (metrics?.dast.total_scans || 0),
            'shield-scan',
            '#4CAF50',
            () => navigateToModule('SAST')
          )}
          {renderMetricCard(
            'Vulnerabilities',
            (metrics?.sast.vulnerabilities_found || 0) + (metrics?.dast.vulnerabilities_found || 0),
            'bug',
            '#FF5722',
            () => navigateToModule('Vulnerabilities')
          )}
          {renderMetricCard(
            'Threats Blocked',
            metrics?.rasp.threats_blocked || 0,
            'shield-check',
            '#2196F3',
            () => navigateToModule('RASP')
          )}
          {renderMetricCard(
            'Cloud Resources',
            metrics?.cloud.total_resources || 0,
            'cloud',
            '#9C27B0',
            () => navigateToModule('CloudSecurity')
          )}
        </View>
      </View>

      {/* Vulnerability Chart */}
      <View style={styles.chartContainer}>
        <Text style={styles.sectionTitle}>Vulnerability Distribution</Text>
        <BarChart
          data={vulnerabilityData}
          width={width - 40}
          height={220}
          chartConfig={chartConfig}
          style={styles.chart}
        />
      </View>

      {/* Security Modules */}
      <View style={styles.modulesContainer}>
        <Text style={styles.sectionTitle}>Security Modules</Text>
        
        {renderModuleCard(
          'SAST Analysis',
          'Static Application Security Testing',
          'code-braces',
          '#4CAF50',
          () => navigateToModule('SAST')
        )}
        
        {renderModuleCard(
          'DAST Testing',
          'Dynamic Application Security Testing',
          'web',
          '#FF5722',
          () => navigateToModule('DAST')
        )}
        
        {renderModuleCard(
          'RASP Protection',
          'Runtime Application Self-Protection',
          'shield-alert',
          '#2196F3',
          () => navigateToModule('RASP')
        )}
        
        {renderModuleCard(
          'Cloud Security',
          'Cloud Infrastructure Security',
          'cloud-security',
          '#9C27B0',
          () => navigateToModule('CloudSecurity')
        )}
        
        {renderModuleCard(
          'Network Security',
          'Network Infrastructure Protection',
          'network',
          '#FF9800',
          () => navigateToModule('NetworkSecurity')
        )}
        
        {renderModuleCard(
          'Threat Intelligence',
          'Security Threat Analysis',
          'brain',
          '#E91E63',
          () => navigateToModule('ThreatIntelligence')
        )}
        
        {renderModuleCard(
          'Incident Response',
          'Security Incident Management',
          'alert-circle',
          '#F44336',
          () => navigateToModule('Incidents')
        )}
        
        {renderModuleCard(
          'Compliance',
          'Regulatory Compliance Management',
          'clipboard-check',
          '#607D8B',
          () => navigateToModule('Compliance')
        )}
      </View>
    </ScrollView>
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
  metricsContainer: {
    padding: 20,
  },
  sectionTitle: {
    fontSize: 20,
    fontWeight: 'bold',
    marginBottom: 15,
    color: '#333',
  },
  metricsGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    justifyContent: 'space-between',
  },
  metricCard: {
    width: (width - 60) / 2,
    marginBottom: 15,
    borderRadius: 12,
    overflow: 'hidden',
  },
  metricGradient: {
    padding: 20,
    alignItems: 'center',
    borderRadius: 12,
  },
  metricValue: {
    fontSize: 24,
    fontWeight: 'bold',
    color: 'white',
    marginTop: 8,
  },
  metricTitle: {
    fontSize: 12,
    color: 'white',
    marginTop: 4,
    textAlign: 'center',
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
  modulesContainer: {
    padding: 20,
  },
  moduleCard: {
    marginBottom: 15,
    borderRadius: 12,
    elevation: 2,
  },
  moduleCardContent: {
    flexDirection: 'row',
    alignItems: 'center',
    padding: 15,
  },
  moduleIconContainer: {
    width: 50,
    height: 50,
    borderRadius: 25,
    backgroundColor: '#f0f0f0',
    justifyContent: 'center',
    alignItems: 'center',
    marginRight: 15,
  },
  moduleTextContainer: {
    flex: 1,
  },
  moduleTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    marginBottom: 4,
  },
  moduleDescription: {
    fontSize: 12,
    color: '#666',
  },
});

export default DashboardScreen; 