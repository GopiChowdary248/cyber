import React, { useState, useEffect } from 'react';
import EnhancedCard from '../../components/UI/EnhancedCard';
import EnhancedButton from '../../components/UI/EnhancedButton';
import EnhancedBadge from '../../components/UI/EnhancedBadge';
import EnhancedTabs from '../../components/UI/EnhancedTabs';
import { 
  Search, 
  Plus, 
  Play, 
  CheckCircle, 
  AlertTriangle, 
  Shield, 
  Target, 
  FileText,
  Activity,
  Database,
  TrendingUp,
  Users,
  Clock,
  Zap
} from 'lucide-react';

// Interfaces for TypeScript
interface ThreatIndicator {
  id: string;
  indicator_type: string;
  value: string;
  threat_type: string;
  severity: string;
  confidence: string;
  first_seen: string;
  last_seen: string;
  tags: string[];
  metadata: Record<string, any>;
  source: string;
  description: string;
}

interface ThreatCampaign {
  id: string;
  name: string;
  description: string;
  threat_type: string;
  severity: string;
  first_seen: string;
  last_seen: string;
  indicators: string[];
  targets: string[];
  tactics: string[];
  techniques: string[];
  attribution?: string;
  status: string;
}

interface ThreatReport {
  id: string;
  title: string;
  description: string;
  threat_type: string;
  severity: string;
  created_at: string;
  updated_at: string;
  author: string;
  content: string;
  indicators: string[];
  recommendations: string[];
  tags: string[];
  status: string;
}

interface ThreatHunt {
  id: string;
  name: string;
  description: string;
  hunt_type: string;
  status: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  analyst: string;
  hypothesis: string;
  scope: Record<string, any>;
  findings: Record<string, any>[];
  tools_used: string[];
  duration_minutes?: number;
}

interface HuntingQuery {
  id: string;
  name: string;
  description: string;
  query_type: string;
  query_string: string;
  created_at: string;
  created_by: string;
  tags: string[];
  success_rate: number;
  usage_count: number;
}

interface ThreatFeed {
  id: string;
  name: string;
  description: string;
  url: string;
  format: string;
  last_updated: string;
  update_frequency: string;
  enabled: boolean;
  indicators_count: number;
  last_sync?: string;
}

interface ThreatIntelligenceSummary {
  total_indicators: number;
  active_campaigns: number;
  recent_reports: number;
  ongoing_hunts: number;
  threat_feeds: number;
  high_severity_threats: number;
  new_indicators_24h: number;
  last_updated: string;
}

const ThreatIntelligence: React.FC = () => {
  const [summary, setSummary] = useState<ThreatIntelligenceSummary | null>(null);
  const [indicators, setIndicators] = useState<ThreatIndicator[]>([]);
  const [campaigns, setCampaigns] = useState<ThreatCampaign[]>([]);
  const [reports, setReports] = useState<ThreatReport[]>([]);
  const [hunts, setHunts] = useState<ThreatHunt[]>([]);
  const [queries, setQueries] = useState<HuntingQuery[]>([]);
  const [feeds, setFeeds] = useState<ThreatFeed[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');

  // Mock data for demonstration
  useEffect(() => {
    setSummary({
      total_indicators: 1247,
      active_campaigns: 8,
      recent_reports: 23,
      ongoing_hunts: 3,
      threat_feeds: 12,
      high_severity_threats: 5,
      new_indicators_24h: 45,
      last_updated: new Date().toISOString()
    });

    setIndicators([
      {
        id: '1',
        indicator_type: 'ip_address',
        value: '192.168.1.100',
        threat_type: 'malware',
        severity: 'high',
        confidence: 'high',
        first_seen: '2024-01-15T10:30:00Z',
        last_seen: '2024-01-15T10:30:00Z',
        tags: ['malware', 'c2'],
        metadata: {},
        source: 'ThreatFox',
        description: 'Malicious IP address'
      }
    ]);

    setCampaigns([
      {
        id: '1',
        name: 'APT29 Campaign',
        description: 'Advanced persistent threat campaign',
        threat_type: 'apt',
        severity: 'high',
        first_seen: '2024-01-10T00:00:00Z',
        last_seen: '2024-01-15T00:00:00Z',
        indicators: ['indicator1', 'indicator2'],
        targets: ['government', 'financial'],
        tactics: ['initial_access', 'persistence'],
        techniques: ['T1078', 'T1053'],
        status: 'active'
      }
    ]);

    setLoading(false);
  }, []);

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'danger';
      case 'high': return 'danger';
      case 'medium': return 'warning';
      case 'low': return 'success';
      default: return 'default';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'completed': return 'success';
      case 'in_progress': return 'primary';
      case 'planned': return 'warning';
      case 'suspended': return 'default';
      default: return 'default';
    }
  };

  const getConfidenceColor = (confidence: string) => {
    switch (confidence.toLowerCase()) {
      case 'very_high': return 'success';
      case 'high': return 'primary';
      case 'medium': return 'warning';
      case 'low': return 'danger';
      default: return 'default';
    }
  };

  // Define tabs for EnhancedTabs component
  const tabs = [
    {
      id: 'overview',
      label: 'Overview',
      content: (
        <div className="space-y-6">
          {summary && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <EnhancedCard>
                <div className="p-6">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-medium">Total Indicators</h3>
                    <Shield className="h-4 w-4 text-muted-foreground" />
                  </div>
                  <div className="text-2xl font-bold mt-2">{summary.total_indicators.toLocaleString()}</div>
                  <p className="text-xs text-muted-foreground mt-1">
                    +{summary.new_indicators_24h} in last 24h
                  </p>
                </div>
              </EnhancedCard>

              <EnhancedCard>
                <div className="p-6">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-medium">Active Campaigns</h3>
                    <Target className="h-4 w-4 text-muted-foreground" />
                  </div>
                  <div className="text-2xl font-bold mt-2">{summary.active_campaigns}</div>
                  <p className="text-xs text-muted-foreground mt-1">
                    {summary.high_severity_threats} high severity
                  </p>
                </div>
              </EnhancedCard>

              <EnhancedCard>
                <div className="p-6">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-medium">Ongoing Hunts</h3>
                    <Activity className="h-4 w-4 text-muted-foreground" />
                  </div>
                  <div className="text-2xl font-bold mt-2">{summary.ongoing_hunts}</div>
                  <p className="text-xs text-muted-foreground mt-1">
                    {summary.recent_reports} recent reports
                  </p>
                </div>
              </EnhancedCard>

              <EnhancedCard>
                <div className="p-6">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-medium">Threat Feeds</h3>
                    <Database className="h-4 w-4 text-muted-foreground" />
                  </div>
                  <div className="text-2xl font-bold mt-2">{summary.threat_feeds}</div>
                  <p className="text-xs text-muted-foreground mt-1">
                    Last updated: {new Date(summary.last_updated).toLocaleString()}
                  </p>
                </div>
              </EnhancedCard>
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <EnhancedCard>
              <div className="p-6">
                <h3 className="text-lg font-semibold mb-4">Recent Threat Indicators</h3>
                <div className="space-y-3">
                  {indicators.slice(0, 5).map((indicator) => (
                    <div key={indicator.id} className="flex items-center justify-between p-3 border rounded">
                      <div>
                        <div className="flex items-center gap-2">
                          <EnhancedBadge variant="default">{indicator.indicator_type}</EnhancedBadge>
                          <span className="font-mono text-sm">{indicator.value}</span>
                        </div>
                        <p className="text-sm text-muted-foreground mt-1">{indicator.source}</p>
                      </div>
                      <EnhancedBadge variant={getSeverityColor(indicator.severity)}>
                        {indicator.severity}
                      </EnhancedBadge>
                    </div>
                  ))}
                </div>
              </div>
            </EnhancedCard>

            <EnhancedCard>
              <div className="p-6">
                <h3 className="text-lg font-semibold mb-4">Active Threat Campaigns</h3>
                <div className="space-y-3">
                  {campaigns.slice(0, 5).map((campaign) => (
                    <div key={campaign.id} className="flex items-center justify-between p-3 border rounded">
                      <div>
                        <div className="font-medium">{campaign.name}</div>
                        <div className="flex items-center gap-2 mt-1">
                          <EnhancedBadge variant="default">{campaign.threat_type}</EnhancedBadge>
                          <EnhancedBadge variant={getStatusColor(campaign.status)}>
                            {campaign.status}
                          </EnhancedBadge>
                        </div>
                      </div>
                      <EnhancedBadge variant={getSeverityColor(campaign.severity)}>
                        {campaign.severity}
                      </EnhancedBadge>
                    </div>
                  ))}
                </div>
              </div>
            </EnhancedCard>
          </div>
        </div>
      )
    },
    {
      id: 'indicators',
      label: 'Indicators',
      content: (
        <EnhancedCard>
          <div className="p-6">
            <h3 className="text-lg font-semibold mb-4">Threat Indicators</h3>
            <div className="space-y-3">
              {indicators.map((indicator) => (
                <div key={indicator.id} className="p-4 border rounded">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <EnhancedBadge variant="default">{indicator.indicator_type}</EnhancedBadge>
                      <span className="font-mono text-sm">{indicator.value}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <EnhancedBadge variant={getSeverityColor(indicator.severity)}>
                        {indicator.severity}
                      </EnhancedBadge>
                      <EnhancedBadge variant={getConfidenceColor(indicator.confidence)}>
                        {indicator.confidence}
                      </EnhancedBadge>
                    </div>
                  </div>
                  <div className="text-sm text-muted-foreground">
                    <p><strong>Threat Type:</strong> {indicator.threat_type}</p>
                    <p><strong>Source:</strong> {indicator.source}</p>
                    <p><strong>First Seen:</strong> {new Date(indicator.first_seen).toLocaleDateString()}</p>
                    <p><strong>Description:</strong> {indicator.description}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </EnhancedCard>
      )
    },
    {
      id: 'campaigns',
      label: 'Campaigns',
      content: (
        <EnhancedCard>
          <div className="p-6">
            <h3 className="text-lg font-semibold mb-4">Threat Campaigns</h3>
            <div className="space-y-3">
              {campaigns.map((campaign) => (
                <div key={campaign.id} className="p-4 border rounded">
                  <div className="flex items-center justify-between mb-2">
                    <div className="font-medium">{campaign.name}</div>
                    <div className="flex items-center gap-2">
                      <EnhancedBadge variant="default">{campaign.threat_type}</EnhancedBadge>
                      <EnhancedBadge variant={getSeverityColor(campaign.severity)}>
                        {campaign.severity}
                      </EnhancedBadge>
                      <EnhancedBadge variant={getStatusColor(campaign.status)}>
                        {campaign.status}
                      </EnhancedBadge>
                    </div>
                  </div>
                  <div className="text-sm text-muted-foreground">
                    <p><strong>Description:</strong> {campaign.description}</p>
                    <p><strong>Targets:</strong> {campaign.targets.join(', ')}</p>
                    <p><strong>Tactics:</strong> {campaign.tactics.join(', ')}</p>
                    <p><strong>First Seen:</strong> {new Date(campaign.first_seen).toLocaleDateString()}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </EnhancedCard>
      )
    },
    {
      id: 'reports',
      label: 'Reports',
      content: (
        <EnhancedCard>
          <div className="p-6">
            <h3 className="text-lg font-semibold mb-4">Threat Reports</h3>
            <p className="text-muted-foreground">Reports functionality coming soon...</p>
          </div>
        </EnhancedCard>
      )
    },
    {
      id: 'hunting',
      label: 'Hunting',
      content: (
        <EnhancedCard>
          <div className="p-6">
            <h3 className="text-lg font-semibold mb-4">Threat Hunting</h3>
            <p className="text-muted-foreground">Hunting functionality coming soon...</p>
          </div>
        </EnhancedCard>
      )
    },
    {
      id: 'queries',
      label: 'Queries',
      content: (
        <EnhancedCard>
          <div className="p-6">
            <h3 className="text-lg font-semibold mb-4">Hunting Queries</h3>
            <p className="text-muted-foreground">Queries functionality coming soon...</p>
          </div>
        </EnhancedCard>
      )
    },
    {
      id: 'feeds',
      label: 'Feeds',
      content: (
        <EnhancedCard>
          <div className="p-6">
            <h3 className="text-lg font-semibold mb-4">Threat Intelligence Feeds</h3>
            <p className="text-muted-foreground">Feeds functionality coming soon...</p>
          </div>
        </EnhancedCard>
      )
    }
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-lg">Loading threat intelligence data...</div>
      </div>
    );
  }

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Threat Intelligence & Hunting</h1>
          <p className="text-muted-foreground">
            Proactive threat identification, analysis, and hunting capabilities
          </p>
        </div>
        <EnhancedButton onClick={() => window.location.reload()} variant="outline">
          <Zap className="w-4 h-4 mr-2" />
          Refresh
        </EnhancedButton>
      </div>

      <EnhancedTabs
        tabs={tabs}
        activeTab={activeTab}
        onTabChange={setActiveTab}
        variant="default"
        size="md"
      />
    </div>
  );
};

export default ThreatIntelligence; 