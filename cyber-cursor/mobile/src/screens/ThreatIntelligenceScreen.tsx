import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  ScrollView,
  StyleSheet,
  RefreshControl,
  TouchableOpacity,
  Alert,
} from 'react-native';
import {
  Card,
  Title,
  Paragraph,
  Button,
  Chip,
  DataTable,
  ActivityIndicator,
  FAB,
  Portal,
  Modal,
  TextInput,
  List,
  Divider,
} from 'react-native-paper';
import LinearGradient from 'react-native-linear-gradient';
import { LineChart, BarChart, PieChart } from 'react-native-chart-kit';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';
import { Dimensions } from 'react-native';

import { APIService } from '../services/APIService';

const { width } = Dimensions.get('window');

interface ThreatIntelligenceStats {
  total_iocs: number;
  new_iocs_today: number;
  active_feeds: number;
  alerts_generated_today: number;
  threats_blocked_today: number;
  avg_confidence_score: number;
  threat_level_distribution: { [key: string]: number };
  top_ioc_types: Array<{ type: string; count: number }>;
  recent_alerts: Array<any>;
  feed_status_summary: { [key: string]: number };
}

interface ThreatFeed {
  id: number;
  name: string;
  feed_type: string;
  url: string;
  status: string;
  last_update: string;
  is_enabled: boolean;
  description?: string;
}

interface IoC {
  id: number;
  value: string;
  ioc_type: string;
  threat_level: string;
  confidence_score: number;
  first_seen: string;
  last_seen: string;
  tags: string[];
  is_active: boolean;
}

interface ThreatAlert {
  id: number;
  title: string;
  description?: string;
  threat_level: string;
  source: string;
  is_resolved: boolean;
  created_at: string;
}

const ThreatIntelligenceScreen: React.FC = () => {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState<ThreatIntelligenceStats | null>(null);
  const [feeds, setFeeds] = useState<ThreatFeed[]>([]);
  const [iocs, setIocs] = useState<IoC[]>([]);
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [showAddFeedModal, setShowAddFeedModal] = useState(false);
  const [showAddIoCModal, setShowAddIoCModal] = useState(false);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      await Promise.all([
        loadStats(),
        loadFeeds(),
        loadIOCs(),
        loadAlerts(),
      ]);
    } catch (error) {
      console.error('Error loading data:', error);
      Alert.alert('Error', 'Failed to load threat intelligence data');
    } finally {
      setLoading(false);
    }
  };

  const loadStats = async () => {
    try {
      const data = await APIService.getThreatIntelligenceStats();
      setStats(data);
    } catch (error) {
      console.error('Error loading stats:', error);
    }
  };

  const loadFeeds = async () => {
    try {
      const data = await APIService.getThreatFeeds();
      setFeeds(data.feeds || []);
    } catch (error) {
      console.error('Error loading feeds:', error);
    }
  };

  const loadIOCs = async () => {
    try {
      const data = await APIService.getIOCs();
      setIocs(data.iocs || []);
    } catch (error) {
      console.error('Error loading IoCs:', error);
    }
  };

  const loadAlerts = async () => {
    try {
      const data = await APIService.getThreatAlerts();
      setAlerts(data.alerts || []);
    } catch (error) {
      console.error('Error loading alerts:', error);
    }
  };

  const onRefresh = async () => {
    setRefreshing(true);
    await loadData();
    setRefreshing(false);
  };

  const getThreatLevelColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'critical':
        return '#d32f2f';
      case 'high':
        return '#f57c00';
      case 'medium':
        return '#fbc02d';
      case 'low':
        return '#388e3c';
      default:
        return '#757575';
    }
  };

  const getFeedStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'active':
        return '#388e3c';
      case 'inactive':
        return '#757575';
      case 'error':
        return '#d32f2f';
      case 'updating':
        return '#f57c00';
      default:
        return '#757575';
    }
  };

  const renderDashboard = () => {
    if (!stats) return null;

    const threatLevelData = Object.entries(stats.threat_level_distribution).map(([level, count]) => ({
      name: level.toUpperCase(),
      count,
      color: getThreatLevelColor(level),
    }));

    const iocTypeData = stats.top_ioc_types.slice(0, 5);

    return (
      <ScrollView style={styles.container}>
        {/* Overview Cards */}
        <View style={styles.statsGrid}>
          <Card style={styles.statCard}>
            <Card.Content>
              <Title style={styles.statTitle}>{stats.total_iocs.toLocaleString()}</Title>
              <Paragraph>Total IoCs</Paragraph>
            </Card.Content>
          </Card>

          <Card style={styles.statCard}>
            <Card.Content>
              <Title style={styles.statTitle}>{stats.new_iocs_today}</Title>
              <Paragraph>New Today</Paragraph>
            </Card.Content>
          </Card>

          <Card style={styles.statCard}>
            <Card.Content>
              <Title style={styles.statTitle}>{stats.active_feeds}</Title>
              <Paragraph>Active Feeds</Paragraph>
            </Card.Content>
          </Card>

          <Card style={styles.statCard}>
            <Card.Content>
              <Title style={styles.statTitle}>{stats.alerts_generated_today}</Title>
              <Paragraph>Alerts Today</Paragraph>
            </Card.Content>
          </Card>
        </View>

        {/* Threat Level Distribution */}
        <Card style={styles.chartCard}>
          <Card.Content>
            <Title>Threat Level Distribution</Title>
            <View style={styles.threatLevelList}>
              {threatLevelData.map((item, index) => (
                <View key={index} style={styles.threatLevelItem}>
                  <View style={[styles.threatLevelIndicator, { backgroundColor: item.color }]} />
                  <Text style={styles.threatLevelText}>{item.name}</Text>
                  <Text style={styles.threatLevelCount}>{item.count}</Text>
                </View>
              ))}
            </View>
          </Card.Content>
        </Card>

        {/* Top IoC Types */}
        <Card style={styles.chartCard}>
          <Card.Content>
            <Title>Top IoC Types</Title>
            <BarChart
              data={{
                labels: iocTypeData.map(item => item.type.substring(0, 8)),
                datasets: [{
                  data: iocTypeData.map(item => item.count)
                }]
              }}
              width={width - 60}
              height={220}
              chartConfig={{
                backgroundColor: '#ffffff',
                backgroundGradientFrom: '#ffffff',
                backgroundGradientTo: '#ffffff',
                decimalPlaces: 0,
                color: (opacity = 1) => `rgba(56, 142, 60, ${opacity})`,
                style: {
                  borderRadius: 16
                }
              }}
              style={styles.chart}
            />
          </Card.Content>
        </Card>

        {/* Recent Alerts */}
        <Card style={styles.chartCard}>
          <Card.Content>
            <Title>Recent Alerts</Title>
            {stats.recent_alerts.slice(0, 5).map((alert, index) => (
              <View key={index} style={styles.alertItem}>
                <View style={styles.alertHeader}>
                  <Text style={styles.alertTitle}>{alert.title}</Text>
                  <Chip
                    mode="outlined"
                    textStyle={{ color: getThreatLevelColor(alert.threat_level) }}
                    style={{ borderColor: getThreatLevelColor(alert.threat_level) }}
                  >
                    {alert.threat_level.toUpperCase()}
                  </Chip>
                </View>
                <Text style={styles.alertSource}>Source: {alert.source}</Text>
                <Text style={styles.alertTime}>
                  {new Date(alert.created_at).toLocaleDateString()}
                </Text>
              </View>
            ))}
          </Card.Content>
        </Card>
      </ScrollView>
    );
  };

  const renderFeeds = () => {
    return (
      <ScrollView style={styles.container}>
        <View style={styles.feedList}>
          {feeds.map((feed) => (
            <Card key={feed.id} style={styles.feedCard}>
              <Card.Content>
                <View style={styles.feedHeader}>
                  <Title>{feed.name}</Title>
                  <Chip
                    mode="outlined"
                    textStyle={{ color: getFeedStatusColor(feed.status) }}
                    style={{ borderColor: getFeedStatusColor(feed.status) }}
                  >
                    {feed.status.toUpperCase()}
                  </Chip>
                </View>
                <Paragraph style={styles.feedType}>Type: {feed.feed_type}</Paragraph>
                {feed.description && (
                  <Paragraph style={styles.feedDescription}>{feed.description}</Paragraph>
                )}
                <View style={styles.feedDetails}>
                  <Text style={styles.feedDetail}>
                    Last Update: {feed.last_update ? new Date(feed.last_update).toLocaleString() : 'Never'}
                  </Text>
                  <Text style={styles.feedDetail}>
                    Enabled: {feed.is_enabled ? 'Yes' : 'No'}
                  </Text>
                </View>
                <View style={styles.feedActions}>
                  <Button
                    mode="outlined"
                    onPress={() => updateFeed(feed.id)}
                    style={styles.feedButton}
                  >
                    Update
                  </Button>
                  <Button
                    mode="outlined"
                    onPress={() => toggleFeed(feed.id, !feed.is_enabled)}
                    style={styles.feedButton}
                  >
                    {feed.is_enabled ? 'Disable' : 'Enable'}
                  </Button>
                </View>
              </Card.Content>
            </Card>
          ))}
        </View>
      </ScrollView>
    );
  };

  const renderIOCs = () => {
    return (
      <ScrollView style={styles.container}>
        <DataTable>
          <DataTable.Header>
            <DataTable.Title>Value</DataTable.Title>
            <DataTable.Title>Type</DataTable.Title>
            <DataTable.Title>Level</DataTable.Title>
            <DataTable.Title numeric>Confidence</DataTable.Title>
          </DataTable.Header>

          {iocs.map((ioc) => (
            <DataTable.Row key={ioc.id}>
              <DataTable.Cell>
                <Text style={styles.iocValue} numberOfLines={1}>
                  {ioc.value}
                </Text>
              </DataTable.Cell>
              <DataTable.Cell>
                <Chip mode="outlined" compact>
                  {ioc.ioc_type}
                </Chip>
              </DataTable.Cell>
              <DataTable.Cell>
                <Chip
                  mode="outlined"
                  compact
                  textStyle={{ color: getThreatLevelColor(ioc.threat_level) }}
                  style={{ borderColor: getThreatLevelColor(ioc.threat_level) }}
                >
                  {ioc.threat_level}
                </Chip>
              </DataTable.Cell>
              <DataTable.Cell numeric>
                <Text>{(ioc.confidence_score * 100).toFixed(0)}%</Text>
              </DataTable.Cell>
            </DataTable.Row>
          ))}
        </DataTable>
      </ScrollView>
    );
  };

  const renderAlerts = () => {
    return (
      <ScrollView style={styles.container}>
        <View style={styles.alertList}>
          {alerts.map((alert) => (
            <Card key={alert.id} style={styles.alertCard}>
              <Card.Content>
                <View style={styles.alertHeader}>
                  <Title>{alert.title}</Title>
                  <Chip
                    mode="outlined"
                    textStyle={{ color: getThreatLevelColor(alert.threat_level) }}
                    style={{ borderColor: getThreatLevelColor(alert.threat_level) }}
                  >
                    {alert.threat_level.toUpperCase()}
                  </Chip>
                </View>
                {alert.description && (
                  <Paragraph style={styles.alertDescription}>{alert.description}</Paragraph>
                )}
                <View style={styles.alertDetails}>
                  <Text style={styles.alertSource}>Source: {alert.source}</Text>
                  <Text style={styles.alertTime}>
                    {new Date(alert.created_at).toLocaleString()}
                  </Text>
                  <Text style={styles.alertStatus}>
                    Status: {alert.is_resolved ? 'Resolved' : 'Active'}
                  </Text>
                </View>
                {!alert.is_resolved && (
                  <Button
                    mode="contained"
                    onPress={() => resolveAlert(alert.id)}
                    style={styles.resolveButton}
                  >
                    Mark as Resolved
                  </Button>
                )}
              </Card.Content>
            </Card>
          ))}
        </View>
      </ScrollView>
    );
  };

  const updateFeed = async (feedId: number) => {
    try {
      await APIService.updateThreatFeed(feedId);
      Alert.alert('Success', 'Feed update started');
      loadFeeds();
    } catch (error) {
      console.error('Error updating feed:', error);
      Alert.alert('Error', 'Failed to update feed');
    }
  };

  const toggleFeed = async (feedId: number, enabled: boolean) => {
    try {
      await APIService.updateThreatFeed(feedId, { is_enabled: enabled });
      Alert.alert('Success', `Feed ${enabled ? 'enabled' : 'disabled'}`);
      loadFeeds();
    } catch (error) {
      console.error('Error toggling feed:', error);
      Alert.alert('Error', 'Failed to update feed status');
    }
  };

  const resolveAlert = async (alertId: number) => {
    try {
      await APIService.updateThreatAlert(alertId, { is_resolved: true });
      Alert.alert('Success', 'Alert marked as resolved');
      loadAlerts();
    } catch (error) {
      console.error('Error resolving alert:', error);
      Alert.alert('Error', 'Failed to resolve alert');
    }
  };

  if (loading) {
    return (
      <View style={styles.loadingContainer}>
        <ActivityIndicator size="large" />
        <Text>Loading Threat Intelligence...</Text>
      </View>
    );
  }

  return (
    <View style={styles.mainContainer}>
      <LinearGradient
        colors={['#1e3c72', '#2a5298']}
        style={styles.header}
      >
        <Text style={styles.headerTitle}>Threat Intelligence</Text>
        <Text style={styles.headerSubtitle}>Monitor and manage threat feeds and IoCs</Text>
      </LinearGradient>

      {/* Tab Navigation */}
      <View style={styles.tabContainer}>
        <ScrollView horizontal showsHorizontalScrollIndicator={false}>
          <TouchableOpacity
            style={[styles.tab, activeTab === 'dashboard' && styles.activeTab]}
            onPress={() => setActiveTab('dashboard')}
          >
            <Icon name="view-dashboard" size={20} color={activeTab === 'dashboard' ? '#1e3c72' : '#666'} />
            <Text style={[styles.tabText, activeTab === 'dashboard' && styles.activeTabText]}>
              Dashboard
            </Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={[styles.tab, activeTab === 'feeds' && styles.activeTab]}
            onPress={() => setActiveTab('feeds')}
          >
            <Icon name="rss" size={20} color={activeTab === 'feeds' ? '#1e3c72' : '#666'} />
            <Text style={[styles.tabText, activeTab === 'feeds' && styles.activeTabText]}>
              Feeds
            </Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={[styles.tab, activeTab === 'iocs' && styles.activeTab]}
            onPress={() => setActiveTab('iocs')}
          >
            <Icon name="target" size={20} color={activeTab === 'iocs' ? '#1e3c72' : '#666'} />
            <Text style={[styles.tabText, activeTab === 'iocs' && styles.activeTabText]}>
              IoCs
            </Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={[styles.tab, activeTab === 'alerts' && styles.activeTab]}
            onPress={() => setActiveTab('alerts')}
          >
            <Icon name="alert" size={20} color={activeTab === 'alerts' ? '#1e3c72' : '#666'} />
            <Text style={[styles.tabText, activeTab === 'alerts' && styles.activeTabText]}>
              Alerts
            </Text>
          </TouchableOpacity>
        </ScrollView>
      </View>

      {/* Content */}
      <ScrollView
        style={styles.content}
        refreshControl={
          <RefreshControl refreshing={refreshing} onRefresh={onRefresh} />
        }
      >
        {activeTab === 'dashboard' && renderDashboard()}
        {activeTab === 'feeds' && renderFeeds()}
        {activeTab === 'iocs' && renderIOCs()}
        {activeTab === 'alerts' && renderAlerts()}
      </ScrollView>

      {/* FAB for adding new items */}
      <Portal>
        <FAB
          style={styles.fab}
          icon="plus"
          onPress={() => {
            if (activeTab === 'feeds') {
              setShowAddFeedModal(true);
            } else if (activeTab === 'iocs') {
              setShowAddIoCModal(true);
            }
          }}
        />
      </Portal>
    </View>
  );
};

const styles = StyleSheet.create({
  mainContainer: {
    flex: 1,
    backgroundColor: '#f5f5f5',
  },
  header: {
    padding: 20,
    paddingTop: 40,
  },
  headerTitle: {
    fontSize: 24,
    fontWeight: 'bold',
    color: 'white',
    marginBottom: 5,
  },
  headerSubtitle: {
    fontSize: 14,
    color: 'rgba(255, 255, 255, 0.8)',
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
    marginHorizontal: 5,
  },
  activeTab: {
    borderBottomWidth: 2,
    borderBottomColor: '#1e3c72',
  },
  tabText: {
    marginLeft: 8,
    fontSize: 14,
    color: '#666',
  },
  activeTabText: {
    color: '#1e3c72',
    fontWeight: 'bold',
  },
  content: {
    flex: 1,
  },
  container: {
    padding: 15,
  },
  loadingContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
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
  statTitle: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#1e3c72',
  },
  chartCard: {
    marginBottom: 20,
  },
  chart: {
    marginVertical: 8,
    borderRadius: 16,
  },
  threatLevelList: {
    marginTop: 10,
  },
  threatLevelItem: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: 8,
  },
  threatLevelIndicator: {
    width: 12,
    height: 12,
    borderRadius: 6,
    marginRight: 10,
  },
  threatLevelText: {
    flex: 1,
    fontSize: 14,
  },
  threatLevelCount: {
    fontSize: 14,
    fontWeight: 'bold',
  },
  alertItem: {
    paddingVertical: 10,
    borderBottomWidth: 1,
    borderBottomColor: '#e0e0e0',
  },
  alertHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 5,
  },
  alertTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    flex: 1,
  },
  alertSource: {
    fontSize: 12,
    color: '#666',
    marginBottom: 2,
  },
  alertTime: {
    fontSize: 12,
    color: '#999',
  },
  feedList: {
    padding: 15,
  },
  feedCard: {
    marginBottom: 15,
  },
  feedHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 10,
  },
  feedType: {
    fontSize: 14,
    color: '#666',
    marginBottom: 5,
  },
  feedDescription: {
    fontSize: 14,
    marginBottom: 10,
  },
  feedDetails: {
    marginBottom: 10,
  },
  feedDetail: {
    fontSize: 12,
    color: '#666',
    marginBottom: 2,
  },
  feedActions: {
    flexDirection: 'row',
    justifyContent: 'space-between',
  },
  feedButton: {
    flex: 1,
    marginHorizontal: 5,
  },
  alertList: {
    padding: 15,
  },
  alertCard: {
    marginBottom: 15,
  },
  alertDescription: {
    marginBottom: 10,
  },
  alertDetails: {
    marginBottom: 10,
  },
  alertStatus: {
    fontSize: 12,
    color: '#666',
  },
  resolveButton: {
    marginTop: 10,
  },
  iocValue: {
    fontSize: 12,
    maxWidth: 100,
  },
  fab: {
    position: 'absolute',
    margin: 16,
    right: 0,
    bottom: 0,
    backgroundColor: '#1e3c72',
  },
});

export default ThreatIntelligenceScreen; 