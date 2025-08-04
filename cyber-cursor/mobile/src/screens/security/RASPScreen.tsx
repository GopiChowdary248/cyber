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

interface RASPApplication {
  id: string;
  name: string;
  status: 'active' | 'inactive' | 'error';
  application_type: string;
  environment: string;
  created_at: string;
  last_activity: string;
  threats_blocked: number;
  attacks_detected: number;
  false_positives: number;
  protection_enabled: boolean;
  agent_version: string;
  server_url: string;
}

interface RASPThreat {
  id: string;
  application_id: string;
  threat_type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  timestamp: string;
  source_ip: string;
  user_agent: string;
  payload: string;
  action_taken: 'blocked' | 'logged' | 'alerted';
  status: 'active' | 'resolved' | 'false_positive';
}

interface RASPMetric {
  threats_blocked: number;
  attacks_detected: number;
  false_positives: number;
  response_time_avg: number;
  uptime_percentage: number;
}

const RASPScreen: React.FC = () => {
  const [selectedApp, setSelectedApp] = useState<RASPApplication | null>(null);
  const [showThreats, setShowThreats] = useState(false);
  const [showMetrics, setShowMetrics] = useState(false);
  const queryClient = useQueryClient();

  // Fetch RASP applications
  const { data: applications, isLoading: appsLoading, refetch: refetchApps } = useQuery({
    queryKey: ['rasp-applications'],
    queryFn: async () => {
      const response = await fetch('http://localhost:8000/api/v1/rasp/applications');
      if (!response.ok) throw new Error('Failed to fetch applications');
      return response.json();
    },
  });

  // Fetch threats for selected application
  const { data: threats, isLoading: threatsLoading } = useQuery({
    queryKey: ['rasp-threats', selectedApp?.id],
    queryFn: async () => {
      if (!selectedApp) return [];
      const response = await fetch(`http://localhost:8000/api/v1/rasp/applications/${selectedApp.id}/threats`);
      if (!response.ok) throw new Error('Failed to fetch threats');
      return response.json();
    },
    enabled: !!selectedApp,
  });

  // Fetch RASP metrics
  const { data: metrics, isLoading: metricsLoading } = useQuery({
    queryKey: ['rasp-metrics'],
    queryFn: async () => {
      const response = await fetch('http://localhost:8000/api/v1/rasp/metrics');
      if (!response.ok) throw new Error('Failed to fetch metrics');
      return response.json();
    },
  });

  // Toggle protection mutation
  const toggleProtectionMutation = useMutation({
    mutationFn: async ({ appId, enabled }: { appId: string; enabled: boolean }) => {
      const response = await fetch(`http://localhost:8000/api/v1/rasp/applications/${appId}/protection`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled }),
      });
      if (!response.ok) throw new Error('Failed to toggle protection');
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rasp-applications'] });
      Alert.alert('Success', 'Protection status updated');
    },
    onError: (error) => {
      Alert.alert('Error', 'Failed to update protection status');
    },
  });

  const handleToggleProtection = (app: RASPApplication) => {
    toggleProtectionMutation.mutate({
      appId: app.id,
      enabled: !app.protection_enabled,
    });
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return '#FF4444';
      case 'high': return '#FF8800';
      case 'medium': return '#FFCC00';
      case 'low': return '#00CC00';
      default: return COLORS.gray;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return '#00CC00';
      case 'inactive': return '#FF8800';
      case 'error': return '#FF4444';
      default: return COLORS.gray;
    }
  };

  const getActionColor = (action: string) => {
    switch (action) {
      case 'blocked': return '#FF4444';
      case 'logged': return '#FFCC00';
      case 'alerted': return '#FF8800';
      default: return COLORS.gray;
    }
  };

  const renderApplicationCard = (app: RASPApplication) => (
    <Card key={app.id} style={styles.appCard}>
      <Card.Content>
        <View style={styles.appHeader}>
          <View style={styles.appInfo}>
            <Text style={styles.appName}>{app.name}</Text>
            <Text style={styles.appType}>{app.application_type}</Text>
          </View>
          <View style={styles.appStatus}>
            <Chip
              mode="outlined"
              textStyle={{ color: getStatusColor(app.status) }}
              style={{ borderColor: getStatusColor(app.status) }}
            >
              {app.status.toUpperCase()}
            </Chip>
            <Switch
              value={app.protection_enabled}
              onValueChange={() => handleToggleProtection(app)}
              color={COLORS.primary}
              style={styles.protectionSwitch}
            />
          </View>
        </View>
        
        <View style={styles.threatStats}>
          <View style={styles.statItem}>
            <Text style={[styles.statNumber, { color: '#FF4444' }]}>
              {app.threats_blocked}
            </Text>
            <Text style={styles.statLabel}>Blocked</Text>
          </View>
          <View style={styles.statItem}>
            <Text style={[styles.statNumber, { color: '#FF8800' }]}>
              {app.attacks_detected}
            </Text>
            <Text style={styles.statLabel}>Detected</Text>
          </View>
          <View style={styles.statItem}>
            <Text style={[styles.statNumber, { color: '#FFCC00' }]}>
              {app.false_positives}
            </Text>
            <Text style={styles.statLabel}>False Positives</Text>
          </View>
        </View>

        <View style={styles.appDetails}>
          <Text style={styles.appDetail}>
            <Icon name="server" size={16} color={COLORS.gray} />
            {app.server_url}
          </Text>
          <Text style={styles.appDetail}>
            <Icon name="tag" size={16} color={COLORS.gray} />
            Agent v{app.agent_version}
          </Text>
          <Text style={styles.appDetail}>
            <Icon name="earth" size={16} color={COLORS.gray} />
            {app.environment}
          </Text>
          <Text style={styles.appDetail}>
            <Icon name="clock-outline" size={16} color={COLORS.gray} />
            Last activity: {new Date(app.last_activity).toLocaleString()}
          </Text>
        </View>
      </Card.Content>
      
      <Card.Actions>
        <Button
          mode="outlined"
          onPress={() => setSelectedApp(app)}
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

  const renderThreatCard = (threat: RASPThreat) => (
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
            <Icon name="clock" size={16} color={COLORS.gray} />
            {new Date(threat.timestamp).toLocaleString()}
          </Text>
          <Text style={styles.threatDetail}>
            <Icon name="ip-network" size={16} color={COLORS.gray} />
            {threat.source_ip}
          </Text>
          <Text style={styles.threatDetail}>
            <Icon name="web" size={16} color={COLORS.gray} />
            {threat.user_agent}
          </Text>
        </View>
        
        <Divider style={styles.divider} />
        
        <Text style={styles.payloadTitle}>Payload:</Text>
        <Text style={styles.payloadText}>{threat.payload}</Text>
      </Card.Content>
    </Card>
  );

  const renderMetricsCard = () => (
    <Card style={styles.metricsCard}>
      <Card.Content>
        <Text style={styles.metricsTitle}>RASP Performance Metrics</Text>
        
        <View style={styles.metricsGrid}>
          <View style={styles.metricItem}>
            <Text style={styles.metricValue}>{metrics?.threats_blocked || 0}</Text>
            <Text style={styles.metricLabel}>Threats Blocked</Text>
          </View>
          <View style={styles.metricItem}>
            <Text style={styles.metricValue}>{metrics?.attacks_detected || 0}</Text>
            <Text style={styles.metricLabel}>Attacks Detected</Text>
          </View>
          <View style={styles.metricItem}>
            <Text style={styles.metricValue}>{metrics?.false_positives || 0}</Text>
            <Text style={styles.metricLabel}>False Positives</Text>
          </View>
          <View style={styles.metricItem}>
            <Text style={styles.metricValue}>{metrics?.response_time_avg || 0}ms</Text>
            <Text style={styles.metricLabel}>Avg Response Time</Text>
          </View>
          <View style={styles.metricItem}>
            <Text style={styles.metricValue}>{metrics?.uptime_percentage || 0}%</Text>
            <Text style={styles.metricLabel}>Uptime</Text>
          </View>
        </View>
      </Card.Content>
    </Card>
  );

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.headerTitle}>RASP Protection</Text>
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
          <RefreshControl refreshing={appsLoading} onRefresh={refetchApps} />
        }
      >
        {showMetrics && renderMetricsCard()}

        {appsLoading ? (
          <View style={styles.loadingContainer}>
            <ActivityIndicator size="large" color={COLORS.primary} />
            <Text style={styles.loadingText}>Loading RASP applications...</Text>
          </View>
        ) : (
          <>
            <View style={styles.statsContainer}>
              <Card style={styles.statCard}>
                <Card.Content>
                  <Text style={styles.statTitle}>Protected Apps</Text>
                  <Text style={styles.statValue}>{applications?.length || 0}</Text>
                </Card.Content>
              </Card>
              
              <Card style={styles.statCard}>
                <Card.Content>
                  <Text style={styles.statTitle}>Active Protection</Text>
                  <Text style={styles.statValue}>
                    {applications?.filter(a => a.protection_enabled).length || 0}
                  </Text>
                </Card.Content>
              </Card>
              
              <Card style={styles.statCard}>
                <Card.Content>
                  <Text style={styles.statTitle}>Total Threats</Text>
                  <Text style={styles.statValue}>
                    {applications?.reduce((sum, app) => sum + app.threats_blocked, 0) || 0}
                  </Text>
                </Card.Content>
              </Card>
            </View>

            <Text style={styles.sectionTitle}>Protected Applications</Text>
            
            {applications?.map(renderApplicationCard) || (
              <Card style={styles.emptyCard}>
                <Card.Content>
                  <Text style={styles.emptyText}>No RASP applications found</Text>
                  <Text style={styles.emptySubtext}>
                    Configure RASP protection for your applications
                  </Text>
                </Card.Content>
              </Card>
            )}

            {showThreats && selectedApp && (
              <View style={styles.threatsSection}>
                <View style={styles.sectionHeader}>
                  <Text style={styles.sectionTitle}>
                    Threats - {selectedApp.name}
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
  appCard: {
    marginBottom: 16,
    backgroundColor: COLORS.card,
  },
  appHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 12,
  },
  appInfo: {
    flex: 1,
  },
  appName: {
    fontSize: 18,
    fontFamily: FONTS.bold,
    color: COLORS.white,
  },
  appType: {
    fontSize: 14,
    color: COLORS.gray,
    fontFamily: FONTS.medium,
  },
  appStatus: {
    alignItems: 'flex-end',
  },
  protectionSwitch: {
    marginTop: 8,
  },
  threatStats: {
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
  },
  statLabel: {
    fontSize: 12,
    color: COLORS.gray,
    fontFamily: FONTS.medium,
  },
  appDetails: {
    marginBottom: 12,
  },
  appDetail: {
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
  divider: {
    marginVertical: 12,
    backgroundColor: COLORS.border,
  },
  payloadTitle: {
    fontSize: 14,
    fontFamily: FONTS.bold,
    color: COLORS.white,
    marginBottom: 8,
  },
  payloadText: {
    fontSize: 12,
    color: COLORS.lightGray,
    fontFamily: FONTS.regular,
  },
});

export default RASPScreen; 