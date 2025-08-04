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

const ComplianceScreen: React.FC = ({ navigation }: any) => {
  const [refreshing, setRefreshing] = useState(false);

  const onRefresh = async () => {
    setRefreshing(true);
    setTimeout(() => {
      setRefreshing(false);
    }, 1000);
  };

  return (
    <View style={styles.container}>
      <LinearGradient colors={['#607D8B', '#455A64']} style={styles.header}>
        <Text style={styles.headerTitle}>Compliance</Text>
        <Text style={styles.headerSubtitle}>Regulatory Compliance Management</Text>
      </LinearGradient>

      <ScrollView
        style={styles.content}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} />}
      >
        <View style={styles.summaryContainer}>
          <Text style={styles.sectionTitle}>Compliance Overview</Text>
          <View style={styles.summaryGrid}>
            <View style={styles.summaryCard}>
              <Icon name="clipboard-check" size={32} color="#607D8B" />
              <Text style={styles.summaryValue}>95%</Text>
              <Text style={styles.summaryLabel}>Overall Compliance</Text>
            </View>
            <View style={styles.summaryCard}>
              <Icon name="check-circle" size={32} color="#4CAF50" />
              <Text style={styles.summaryValue}>12</Text>
              <Text style={styles.summaryLabel}>Frameworks</Text>
            </View>
            <View style={styles.summaryCard}>
              <Icon name="alert-circle" size={32} color="#FF9800" />
              <Text style={styles.summaryValue}>8</Text>
              <Text style={styles.summaryLabel}>Violations</Text>
            </View>
            <View style={styles.summaryCard}>
              <Icon name="calendar" size={32} color="#2196F3" />
              <Text style={styles.summaryValue}>30</Text>
              <Text style={styles.summaryLabel}>Days to Audit</Text>
            </View>
          </View>
        </View>

        <View style={styles.complianceContainer}>
          <Text style={styles.sectionTitle}>Compliance Frameworks</Text>
          
          <Card style={styles.complianceCard}>
            <Card.Content>
              <View style={styles.complianceHeader}>
                <Title style={styles.complianceTitle}>GDPR</Title>
                <Chip mode="outlined" textStyle={{ color: '#4CAF50' }} style={[styles.statusChip, { borderColor: '#4CAF50' }]}>
                  98%
                </Chip>
              </View>
              <Paragraph style={styles.complianceDescription}>
                General Data Protection Regulation compliance status.
              </Paragraph>
              <View style={styles.complianceDetails}>
                <Text style={styles.complianceDetail}>Status: Compliant</Text>
                <Text style={styles.complianceDetail}>Last Audit: 2 months ago</Text>
                <Text style={styles.complianceDetail}>Next Review: 1 month</Text>
              </View>
            </Card.Content>
          </Card>

          <Card style={styles.complianceCard}>
            <Card.Content>
              <View style={styles.complianceHeader}>
                <Title style={styles.complianceTitle}>SOC 2</Title>
                <Chip mode="outlined" textStyle={{ color: '#FF9800' }} style={[styles.statusChip, { borderColor: '#FF9800' }]}>
                  92%
                </Chip>
              </View>
              <Paragraph style={styles.complianceDescription}>
                Service Organization Control 2 Type II certification.
              </Paragraph>
              <View style={styles.complianceDetails}>
                <Text style={styles.complianceDetail}>Status: In Progress</Text>
                <Text style={styles.complianceDetail}>Last Audit: 6 months ago</Text>
                <Text style={styles.complianceDetail}>Next Review: 3 months</Text>
              </View>
            </Card.Content>
          </Card>

          <Card style={styles.complianceCard}>
            <Card.Content>
              <View style={styles.complianceHeader}>
                <Title style={styles.complianceTitle}>ISO 27001</Title>
                <Chip mode="outlined" textStyle={{ color: '#4CAF50' }} style={[styles.statusChip, { borderColor: '#4CAF50' }]}>
                  96%
                </Chip>
              </View>
              <Paragraph style={styles.complianceDescription}>
                Information Security Management System certification.
              </Paragraph>
              <View style={styles.complianceDetails}>
                <Text style={styles.complianceDetail}>Status: Certified</Text>
                <Text style={styles.complianceDetail}>Last Audit: 1 month ago</Text>
                <Text style={styles.complianceDetail}>Next Review: 11 months</Text>
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
  complianceContainer: {
    padding: 20,
  },
  complianceCard: {
    marginBottom: 15,
    borderRadius: 12,
    elevation: 2,
  },
  complianceHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 10,
  },
  complianceTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    flex: 1,
    marginRight: 10,
  },
  statusChip: {
    marginLeft: 10,
  },
  complianceDescription: {
    fontSize: 14,
    color: '#666',
    marginBottom: 10,
  },
  complianceDetails: {
    marginBottom: 10,
  },
  complianceDetail: {
    fontSize: 12,
    color: '#666',
    marginBottom: 2,
  },
});

export default ComplianceScreen; 