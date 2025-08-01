import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { Alert, AlertDescription } from '@/components/ui/alert';
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

  // Form states
  const [newIndicator, setNewIndicator] = useState({
    indicator_type: '',
    value: '',
    threat_type: '',
    severity: '',
    confidence: '',
    source: '',
    description: '',
    tags: ''
  });

  const [newHunt, setNewHunt] = useState({
    name: '',
    description: '',
    hunt_type: '',
    analyst: '',
    hypothesis: '',
    scope: ''
  });

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      setLoading(true);
      const [summaryRes, indicatorsRes, campaignsRes, reportsRes, huntsRes, queriesRes, feedsRes] = await Promise.all([
        fetch('/api/v1/threat-intelligence/summary'),
        fetch('/api/v1/threat-intelligence/indicators?limit=50'),
        fetch('/api/v1/threat-intelligence/campaigns?limit=20'),
        fetch('/api/v1/threat-intelligence/reports?limit=20'),
        fetch('/api/v1/threat-intelligence/hunts?limit=20'),
        fetch('/api/v1/threat-intelligence/queries?limit=20'),
        fetch('/api/v1/threat-intelligence/feeds')
      ]);

      const [summaryData, indicatorsData, campaignsData, reportsData, huntsData, queriesData, feedsData] = await Promise.all([
        summaryRes.json(),
        indicatorsRes.json(),
        campaignsRes.json(),
        reportsRes.json(),
        huntsRes.json(),
        queriesRes.json(),
        feedsRes.json()
      ]);

      setSummary(summaryData);
      setIndicators(indicatorsData);
      setCampaigns(campaignsData);
      setReports(reportsData);
      setHunts(huntsData);
      setQueries(queriesData);
      setFeeds(feedsData);
    } catch (error) {
      console.error('Error fetching threat intelligence data:', error);
    } finally {
      setLoading(false);
    }
  };

  const createIndicator = async () => {
    try {
      const response = await fetch('/api/v1/threat-intelligence/indicators', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...newIndicator,
          tags: newIndicator.tags.split(',').map(tag => tag.trim()).filter(tag => tag)
        })
      });
      
      if (response.ok) {
        setNewIndicator({
          indicator_type: '',
          value: '',
          threat_type: '',
          severity: '',
          confidence: '',
          source: '',
          description: '',
          tags: ''
        });
        fetchData();
      }
    } catch (error) {
      console.error('Error creating indicator:', error);
    }
  };

  const createHunt = async () => {
    try {
      const response = await fetch('/api/v1/threat-intelligence/hunts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...newHunt,
          scope: JSON.parse(newHunt.scope || '{}')
        })
      });
      
      if (response.ok) {
        setNewHunt({
          name: '',
          description: '',
          hunt_type: '',
          analyst: '',
          hypothesis: '',
          scope: ''
        });
        fetchData();
      }
    } catch (error) {
      console.error('Error creating hunt:', error);
    }
  };

  const startHunt = async (huntId: string) => {
    try {
      await fetch(`/api/v1/threat-intelligence/hunts/${huntId}/start`, { method: 'PUT' });
      fetchData();
    } catch (error) {
      console.error('Error starting hunt:', error);
    }
  };

  const syncFeed = async (feedId: string) => {
    try {
      await fetch(`/api/v1/threat-intelligence/feeds/${feedId}/sync`, { method: 'PUT' });
      fetchData();
    } catch (error) {
      console.error('Error syncing feed:', error);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'bg-red-500';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-yellow-500';
      case 'low': return 'bg-green-500';
      default: return 'bg-gray-500';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'completed': return 'bg-green-500';
      case 'in_progress': return 'bg-blue-500';
      case 'planned': return 'bg-yellow-500';
      case 'suspended': return 'bg-gray-500';
      default: return 'bg-gray-500';
    }
  };

  const getConfidenceColor = (confidence: string) => {
    switch (confidence.toLowerCase()) {
      case 'very_high': return 'bg-green-500';
      case 'high': return 'bg-blue-500';
      case 'medium': return 'bg-yellow-500';
      case 'low': return 'bg-red-500';
      default: return 'bg-gray-500';
    }
  };

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
        <Button onClick={fetchData} variant="outline">
          <Zap className="w-4 h-4 mr-2" />
          Refresh
        </Button>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid w-full grid-cols-7">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="indicators">Indicators</TabsTrigger>
          <TabsTrigger value="campaigns">Campaigns</TabsTrigger>
          <TabsTrigger value="reports">Reports</TabsTrigger>
          <TabsTrigger value="hunting">Hunting</TabsTrigger>
          <TabsTrigger value="queries">Queries</TabsTrigger>
          <TabsTrigger value="feeds">Feeds</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6">
          {summary && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Total Indicators</CardTitle>
                  <Shield className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{summary.total_indicators.toLocaleString()}</div>
                  <p className="text-xs text-muted-foreground">
                    +{summary.new_indicators_24h} in last 24h
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Active Campaigns</CardTitle>
                  <Target className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{summary.active_campaigns}</div>
                  <p className="text-xs text-muted-foreground">
                    {summary.high_severity_threats} high severity
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Ongoing Hunts</CardTitle>
                  <Activity className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{summary.ongoing_hunts}</div>
                  <p className="text-xs text-muted-foreground">
                    {summary.recent_reports} recent reports
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Threat Feeds</CardTitle>
                  <Database className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{summary.threat_feeds}</div>
                  <p className="text-xs text-muted-foreground">
                    Last updated: {new Date(summary.last_updated).toLocaleString()}
                  </p>
                </CardContent>
              </Card>
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>Recent Threat Indicators</CardTitle>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Type</TableHead>
                      <TableHead>Value</TableHead>
                      <TableHead>Severity</TableHead>
                      <TableHead>Source</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {indicators.slice(0, 5).map((indicator) => (
                      <TableRow key={indicator.id}>
                        <TableCell>
                          <Badge variant="outline">{indicator.indicator_type}</Badge>
                        </TableCell>
                        <TableCell className="font-mono text-sm">{indicator.value}</TableCell>
                        <TableCell>
                          <Badge className={getSeverityColor(indicator.severity)}>
                            {indicator.severity}
                          </Badge>
                        </TableCell>
                        <TableCell>{indicator.source}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Active Threat Campaigns</CardTitle>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Campaign</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Severity</TableHead>
                      <TableHead>Status</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {campaigns.slice(0, 5).map((campaign) => (
                      <TableRow key={campaign.id}>
                        <TableCell className="font-medium">{campaign.name}</TableCell>
                        <TableCell>
                          <Badge variant="outline">{campaign.threat_type}</Badge>
                        </TableCell>
                        <TableCell>
                          <Badge className={getSeverityColor(campaign.severity)}>
                            {campaign.severity}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge className={getStatusColor(campaign.status)}>
                            {campaign.status}
                          </Badge>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="indicators" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Add New Threat Indicator</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                <div>
                  <Label>Indicator Type</Label>
                  <Select value={newIndicator.indicator_type} onValueChange={(value) => setNewIndicator({...newIndicator, indicator_type: value})}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select type" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="ip_address">IP Address</SelectItem>
                      <SelectItem value="domain">Domain</SelectItem>
                      <SelectItem value="url">URL</SelectItem>
                      <SelectItem value="email">Email</SelectItem>
                      <SelectItem value="hash">Hash</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label>Value</Label>
                  <Input
                    value={newIndicator.value}
                    onChange={(e) => setNewIndicator({...newIndicator, value: e.target.value})}
                    placeholder="Enter indicator value"
                  />
                </div>
                <div>
                  <Label>Threat Type</Label>
                  <Select value={newIndicator.threat_type} onValueChange={(value) => setNewIndicator({...newIndicator, threat_type: value})}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select threat type" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="malware">Malware</SelectItem>
                      <SelectItem value="phishing">Phishing</SelectItem>
                      <SelectItem value="apt">APT</SelectItem>
                      <SelectItem value="ransomware">Ransomware</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label>Severity</Label>
                  <Select value={newIndicator.severity} onValueChange={(value) => setNewIndicator({...newIndicator, severity: value})}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select severity" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="low">Low</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="critical">Critical</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label>Confidence</Label>
                  <Select value={newIndicator.confidence} onValueChange={(value) => setNewIndicator({...newIndicator, confidence: value})}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select confidence" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="low">Low</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="very_high">Very High</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label>Source</Label>
                  <Input
                    value={newIndicator.source}
                    onChange={(e) => setNewIndicator({...newIndicator, source: e.target.value})}
                    placeholder="Enter source"
                  />
                </div>
              </div>
              <div className="mt-4">
                <Label>Description</Label>
                <Textarea
                  value={newIndicator.description}
                  onChange={(e) => setNewIndicator({...newIndicator, description: e.target.value})}
                  placeholder="Enter description"
                />
              </div>
              <div className="mt-4">
                <Label>Tags (comma-separated)</Label>
                <Input
                  value={newIndicator.tags}
                  onChange={(e) => setNewIndicator({...newIndicator, tags: e.target.value})}
                  placeholder="Enter tags"
                />
              </div>
              <Button onClick={createIndicator} className="mt-4">
                <Plus className="w-4 h-4 mr-2" />
                Add Indicator
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Threat Indicators</CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Type</TableHead>
                    <TableHead>Value</TableHead>
                    <TableHead>Threat Type</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Confidence</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead>First Seen</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {indicators.map((indicator) => (
                    <TableRow key={indicator.id}>
                      <TableCell>
                        <Badge variant="outline">{indicator.indicator_type}</Badge>
                      </TableCell>
                      <TableCell className="font-mono text-sm max-w-xs truncate">{indicator.value}</TableCell>
                      <TableCell>
                        <Badge variant="outline">{indicator.threat_type}</Badge>
                      </TableCell>
                      <TableCell>
                        <Badge className={getSeverityColor(indicator.severity)}>
                          {indicator.severity}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge className={getConfidenceColor(indicator.confidence)}>
                          {indicator.confidence}
                        </Badge>
                      </TableCell>
                      <TableCell>{indicator.source}</TableCell>
                      <TableCell>{new Date(indicator.first_seen).toLocaleDateString()}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="campaigns" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Threat Campaigns</CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Targets</TableHead>
                    <TableHead>Tactics</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>First Seen</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {campaigns.map((campaign) => (
                    <TableRow key={campaign.id}>
                      <TableCell className="font-medium">{campaign.name}</TableCell>
                      <TableCell>
                        <Badge variant="outline">{campaign.threat_type}</Badge>
                      </TableCell>
                      <TableCell>
                        <Badge className={getSeverityColor(campaign.severity)}>
                          {campaign.severity}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {campaign.targets.slice(0, 2).map((target, index) => (
                            <Badge key={index} variant="secondary" className="text-xs">
                              {target}
                            </Badge>
                          ))}
                          {campaign.targets.length > 2 && (
                            <Badge variant="secondary" className="text-xs">
                              +{campaign.targets.length - 2}
                            </Badge>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {campaign.tactics.slice(0, 2).map((tactic, index) => (
                            <Badge key={index} variant="outline" className="text-xs">
                              {tactic}
                            </Badge>
                          ))}
                          {campaign.tactics.length > 2 && (
                            <Badge variant="outline" className="text-xs">
                              +{campaign.tactics.length - 2}
                            </Badge>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge className={getStatusColor(campaign.status)}>
                          {campaign.status}
                        </Badge>
                      </TableCell>
                      <TableCell>{new Date(campaign.first_seen).toLocaleDateString()}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="reports" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Threat Reports</CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Title</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Author</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Created</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {reports.map((report) => (
                    <TableRow key={report.id}>
                      <TableCell className="font-medium">{report.title}</TableCell>
                      <TableCell>
                        <Badge variant="outline">{report.threat_type}</Badge>
                      </TableCell>
                      <TableCell>
                        <Badge className={getSeverityColor(report.severity)}>
                          {report.severity}
                        </Badge>
                      </TableCell>
                      <TableCell>{report.author}</TableCell>
                      <TableCell>
                        <Badge className={getStatusColor(report.status)}>
                          {report.status}
                        </Badge>
                      </TableCell>
                      <TableCell>{new Date(report.created_at).toLocaleDateString()}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="hunting" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Create New Threat Hunt</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <Label>Hunt Name</Label>
                  <Input
                    value={newHunt.name}
                    onChange={(e) => setNewHunt({...newHunt, name: e.target.value})}
                    placeholder="Enter hunt name"
                  />
                </div>
                <div>
                  <Label>Hunt Type</Label>
                  <Select value={newHunt.hunt_type} onValueChange={(value) => setNewHunt({...newHunt, hunt_type: value})}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select hunt type" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="behavioral">Behavioral</SelectItem>
                      <SelectItem value="network">Network</SelectItem>
                      <SelectItem value="endpoint">Endpoint</SelectItem>
                      <SelectItem value="memory">Memory</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label>Analyst</Label>
                  <Input
                    value={newHunt.analyst}
                    onChange={(e) => setNewHunt({...newHunt, analyst: e.target.value})}
                    placeholder="Enter analyst name"
                  />
                </div>
                <div>
                  <Label>Hypothesis</Label>
                  <Input
                    value={newHunt.hypothesis}
                    onChange={(e) => setNewHunt({...newHunt, hypothesis: e.target.value})}
                    placeholder="Enter hypothesis"
                  />
                </div>
              </div>
              <div className="mt-4">
                <Label>Description</Label>
                <Textarea
                  value={newHunt.description}
                  onChange={(e) => setNewHunt({...newHunt, description: e.target.value})}
                  placeholder="Enter hunt description"
                />
              </div>
              <div className="mt-4">
                <Label>Scope (JSON)</Label>
                <Textarea
                  value={newHunt.scope}
                  onChange={(e) => setNewHunt({...newHunt, scope: e.target.value})}
                  placeholder='{"networks": ["192.168.1.0/24"], "timeframe": "last_7_days"}'
                />
              </div>
              <Button onClick={createHunt} className="mt-4">
                <Plus className="w-4 h-4 mr-2" />
                Create Hunt
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Threat Hunts</CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Analyst</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Duration</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {hunts.map((hunt) => (
                    <TableRow key={hunt.id}>
                      <TableCell className="font-medium">{hunt.name}</TableCell>
                      <TableCell>
                        <Badge variant="outline">{hunt.hunt_type}</Badge>
                      </TableCell>
                      <TableCell>{hunt.analyst}</TableCell>
                      <TableCell>
                        <Badge className={getStatusColor(hunt.status)}>
                          {hunt.status}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {hunt.duration_minutes ? `${hunt.duration_minutes}m` : '-'}
                      </TableCell>
                      <TableCell>
                        {hunt.status === 'planned' && (
                          <Button
                            size="sm"
                            onClick={() => startHunt(hunt.id)}
                            variant="outline"
                          >
                            <Play className="w-4 h-4" />
                          </Button>
                        )}
                        {hunt.status === 'completed' && (
                          <CheckCircle className="w-4 h-4 text-green-500" />
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="queries" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Hunting Queries</CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Created By</TableHead>
                    <TableHead>Success Rate</TableHead>
                    <TableHead>Usage Count</TableHead>
                    <TableHead>Created</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {queries.map((query) => (
                    <TableRow key={query.id}>
                      <TableCell className="font-medium">{query.name}</TableCell>
                      <TableCell>
                        <Badge variant="outline">{query.query_type}</Badge>
                      </TableCell>
                      <TableCell>{query.created_by}</TableCell>
                      <TableCell>
                        <div className="flex items-center">
                          <div className="w-16 bg-gray-200 rounded-full h-2 mr-2">
                            <div
                              className="bg-blue-600 h-2 rounded-full"
                              style={{ width: `${query.success_rate * 100}%` }}
                            ></div>
                          </div>
                          <span className="text-sm">{(query.success_rate * 100).toFixed(0)}%</span>
                        </div>
                      </TableCell>
                      <TableCell>{query.usage_count}</TableCell>
                      <TableCell>{new Date(query.created_at).toLocaleDateString()}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="feeds" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Threat Intelligence Feeds</CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Format</TableHead>
                    <TableHead>Frequency</TableHead>
                    <TableHead>Indicators</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Last Sync</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {feeds.map((feed) => (
                    <TableRow key={feed.id}>
                      <TableCell className="font-medium">{feed.name}</TableCell>
                      <TableCell>
                        <Badge variant="outline">{feed.format}</Badge>
                      </TableCell>
                      <TableCell>{feed.update_frequency}</TableCell>
                      <TableCell>{feed.indicators_count.toLocaleString()}</TableCell>
                      <TableCell>
                        <Badge className={feed.enabled ? 'bg-green-500' : 'bg-gray-500'}>
                          {feed.enabled ? 'Enabled' : 'Disabled'}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {feed.last_sync ? new Date(feed.last_sync).toLocaleString() : 'Never'}
                      </TableCell>
                      <TableCell>
                        <Button
                          size="sm"
                          onClick={() => syncFeed(feed.id)}
                          variant="outline"
                        >
                          <Zap className="w-4 h-4" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default ThreatIntelligence; 