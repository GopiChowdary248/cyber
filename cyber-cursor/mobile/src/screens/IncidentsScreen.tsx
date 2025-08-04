import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  RefreshControl,
} from 'react-native';
import { LinearGradient } from 'react-native-linear-gradient';
import { Card, Title, Paragraph, Chip } from 'react-native-paper';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';

const IncidentsScreen: React.FC = ({ navigation }: any) => {
  const [refreshing, setRefreshing] = useState(false);

  const onRefresh = async () => {
    setRefreshing(true);
    setTimeout(() => {
      setRefreshing(false);
    }, 1000);
  };

  return (
    <View style={styles.container}>
      <LinearGradient colors={['#F44336', '#D32F2F']} style={styles.header}>
        <Text style={styles.headerTitle}>Incident Response</Text>
        <Text style={styles.headerSubtitle}>Security Incident Management</Text>
      </LinearGradient>

      <ScrollView
        style={styles.content}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} />}
      >
        <View style={styles.summaryContainer}>
          <Text style={styles.sectionTitle}>Incident Overview</Text>
          <View style={styles.summaryGrid}>
            <View style={styles.summaryCard}>
              <Icon name="alert-circle" size={32} color="#F44336" />
              <Text style={styles.summaryValue}>12</Text>
              <Text style={styles.summaryLabel}>Active Incidents</Text>
            </View>
            <View style={styles.summaryCard}>
              <Icon name="check-circle" size={32} color="#4CAF50" />
              <Text style={styles.summaryValue}>45</Text>
              <Text style={styles.summaryLabel}>Resolved</Text>
            </View>
            <View style={styles.summaryCard}>
              <Icon name="clock" size={32} color="#FF9800" />
              <Text style={styles.summaryValue}>2.3h</Text>
              <Text style={styles.summaryLabel}>Avg Response</Text>
            </View>
            <View style={styles.summaryCard}>
              <Icon name="shield-check" size={32} color="#2196F3" />
              <Text style={styles.summaryValue}>98%</Text>
              <Text style={styles.summaryLabel}>Success Rate</Text>
            </View>
          </View>
        </View>

        <View style={styles.incidentsContainer}>
          <Text style={styles.sectionTitle}>Recent Incidents</Text>
          
          <Card style={styles.incidentCard}>
            <Card.Content>
              <View style={styles.incidentHeader}>
                <Title style={styles.incidentTitle}>Data Breach Attempt</Title>
                <Chip mode="outlined" textStyle={{ color: '#F44336' }} style={[styles.severityChip, { borderColor: '#F44336' }]}>
                  Critical
                </Chip>
              </View>
              <Paragraph style={styles.incidentDescription}>
                Unauthorized access attempt detected on database server.
              </Paragraph>
              <View style={styles.incidentDetails}>
                <Text style={styles.incidentDetail}>Status: Under Investigation</Text>
                <Text style={styles.incidentDetail}>Assigned: Security Team</Text>
                <Text style={styles.incidentDetail}>Created: 2 hours ago</Text>
              </View>
            </Card.Content>
          </Card>

          <Card style={styles.incidentCard}>
            <Card.Content>
              <View style={styles.incidentHeader}>
                <Title style={styles.incidentTitle}>Malware Detection</Title>
                <Chip mode="outlined" textStyle={{ color: '#FF5722' }} style={[styles.severityChip, { borderColor: '#FF5722' }]}>
                  High
                </Chip>
              </View>
              <Paragraph style={styles.incidentDescription}>
                Ransomware detected on user workstation.
              </Paragraph>
              <View style={styles.incidentDetails}>
                <Text style={styles.incidentDetail}>Status: Resolved</Text>
                <Text style={styles.incidentDetail}>Assigned: IT Support</Text>
                <Text style={styles.incidentDetail}>Resolved: 1 hour ago</Text>
              </View>
            </Card.Content>
          </Card>
        </View>
      </ScrollView>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f5f5f5',
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
    width: '48%',
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
  incidentsContainer: {
    padding: 20,
  },
  incidentCard: {
    marginBottom: 15,
    borderRadius: 12,
    elevation: 2,
  },
  incidentHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 10,
  },
  incidentTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    flex: 1,
    marginRight: 10,
  },
  severityChip: {
    marginLeft: 10,
  },
  incidentDescription: {
    fontSize: 14,
    color: '#666',
    marginBottom: 10,
  },
  incidentDetails: {
    marginBottom: 10,
  },
  incidentDetail: {
    fontSize: 12,
    color: '#666',
    marginBottom: 2,
  },
});

export default IncidentsScreen; 