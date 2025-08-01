import React, { useState, useEffect } from 'react';
import EnhancedCard from '../../components/UI/EnhancedCard';
import EnhancedButton from '../../components/UI/EnhancedButton';
import EnhancedBadge from '../../components/UI/EnhancedBadge';
import EnhancedTabs from '../../components/UI/EnhancedTabs';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Shield, Lock, Database, AlertTriangle, CheckCircle, XCircle } from 'lucide-react';

interface EncryptionKey {
  id: string;
  name: string;
  algorithm: string;
  key_material: string;
  created_at: string;
  expires_at?: string;
  is_active: boolean;
  description: string;
}

interface EncryptedData {
  id: string;
  key_id: string;
  algorithm: string;
  encrypted_data: string;
  iv: string;
  created_at: string;
  metadata: Record<string, any>;
}

interface DLPPolicy {
  id: string;
  name: string;
  description: string;
  patterns: string[];
  violation_type: string;
  severity: string;
  actions: string[];
  is_active: boolean;
  created_at: string;
}

interface DLPViolation {
  id: string;
  policy_id: string;
  violation_type: string;
  severity: string;
  detected_data: string;
  source: string;
  timestamp: string;
  actions_taken: string[];
  status: string;
  resolved_at?: string;
}

interface DatabaseActivity {
  id: string;
  database_name: string;
  table_name: string;
  activity_type: string;
  user: string;
  ip_address: string;
  query: string;
  timestamp: string;
  risk_level: string;
  is_suspicious: boolean;
  metadata: Record<string, any>;
}

interface DataProtectionSummary {
  total_encrypted_files: number;
  active_encryption_keys: number;
  dlp_violations_today: number;
  dlp_violations_week: number;
  database_activities_today: number;
  suspicious_activities: number;
  encryption_health: string;
  dlp_health: string;
  database_monitoring_health: string;
}

const DataProtection: React.FC = () => {
  const [summary, setSummary] = useState<DataProtectionSummary | null>(null);
  const [encryptionKeys, setEncryptionKeys] = useState<EncryptionKey[]>([]);
  const [encryptedData, setEncryptedData] = useState<EncryptedData[]>([]);
  const [dlpPolicies, setDlpPolicies] = useState<DLPPolicy[]>([]);
  const [dlpViolations, setDlpViolations] = useState<DLPViolation[]>([]);
  const [databaseActivities, setDatabaseActivities] = useState<DatabaseActivity[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Form states
  const [newKeyName, setNewKeyName] = useState('');
  const [newKeyAlgorithm, setNewKeyAlgorithm] = useState('aes_256');
  const [newKeyDescription, setNewKeyDescription] = useState('');
  const [encryptData, setEncryptData] = useState('');
  const [encryptKeyId, setEncryptKeyId] = useState('');
  const [decryptId, setDecryptId] = useState('');
  const [decryptedData, setDecryptedData] = useState('');

  const [newPolicyName, setNewPolicyName] = useState('');
  const [newPolicyDescription, setNewPolicyDescription] = useState('');
  const [newPolicyPatterns, setNewPolicyPatterns] = useState('');
  const [newPolicyType, setNewPolicyType] = useState('credit_card');
  const [newPolicySeverity, setNewPolicySeverity] = useState('high');
  const [newPolicyActions, setNewPolicyActions] = useState<string[]>([]);
  const [scanContent, setScanContent] = useState('');
  const [scanSource, setScanSource] = useState('');

  const [dbName, setDbName] = useState('');
  const [tableName, setTableName] = useState('');
  const [dbActivityType, setDbActivityType] = useState('select');
  const [dbUser, setDbUser] = useState('');
  const [dbIpAddress, setDbIpAddress] = useState('');
  const [dbQuery, setDbQuery] = useState('');

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      setLoading(true);
      const [summaryRes, keysRes, dataRes, policiesRes, violationsRes, activitiesRes] = await Promise.all([
        fetch('/api/v1/data-protection/summary'),
        fetch('/api/v1/data-protection/encryption/keys'),
        fetch('/api/v1/data-protection/encryption/data'),
        fetch('/api/v1/data-protection/dlp/policies'),
        fetch('/api/v1/data-protection/dlp/violations'),
        fetch('/api/v1/data-protection/database/activities')
      ]);

      const [summaryData, keysData, dataData, policiesData, violationsData, activitiesData] = await Promise.all([
        summaryRes.json(),
        keysRes.json(),
        dataRes.json(),
        policiesRes.json(),
        violationsRes.json(),
        activitiesRes.json()
      ]);

      setSummary(summaryData);
      setEncryptionKeys(keysData);
      setEncryptedData(dataData);
      setDlpPolicies(policiesData);
      setDlpViolations(violationsData);
      setDatabaseActivities(activitiesData);
    } catch (err) {
      setError('Failed to fetch data protection information');
      console.error('Error fetching data:', err);
    } finally {
      setLoading(false);
    }
  };

  const createEncryptionKey = async () => {
    try {
      const response = await fetch('/api/v1/data-protection/encryption/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newKeyName,
          algorithm: newKeyAlgorithm,
          description: newKeyDescription
        })
      });

      if (response.ok) {
        setNewKeyName('');
        setNewKeyAlgorithm('aes_256');
        setNewKeyDescription('');
        fetchData();
      }
    } catch (err) {
      console.error('Error creating encryption key:', err);
    }
  };

  const encryptData = async () => {
    try {
      const response = await fetch('/api/v1/data-protection/encryption/encrypt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          data: encryptData,
          key_id: encryptKeyId
        })
      });

      if (response.ok) {
        setEncryptData('');
        setEncryptKeyId('');
        fetchData();
      }
    } catch (err) {
      console.error('Error encrypting data:', err);
    }
  };

  const decryptData = async () => {
    try {
      const response = await fetch('/api/v1/data-protection/encryption/decrypt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ encrypted_id: decryptId })
      });

      if (response.ok) {
        const result = await response.json();
        setDecryptedData(result.decrypted_data);
      }
    } catch (err) {
      console.error('Error decrypting data:', err);
    }
  };

  const createDLPPolicy = async () => {
    try {
      const response = await fetch('/api/v1/data-protection/dlp/policies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newPolicyName,
          description: newPolicyDescription,
          patterns: newPolicyPatterns.split('\n').filter(p => p.trim()),
          violation_type: newPolicyType,
          severity: newPolicySeverity,
          actions: newPolicyActions
        })
      });

      if (response.ok) {
        setNewPolicyName('');
        setNewPolicyDescription('');
        setNewPolicyPatterns('');
        setNewPolicyType('credit_card');
        setNewPolicySeverity('high');
        setNewPolicyActions([]);
        fetchData();
      }
    } catch (err) {
      console.error('Error creating DLP policy:', err);
    }
  };

  const scanContentForDLP = async () => {
    try {
      const response = await fetch('/api/v1/data-protection/dlp/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          content: scanContent,
          source: scanSource
        })
      });

      if (response.ok) {
        setScanContent('');
        setScanSource('');
        fetchData();
      }
    } catch (err) {
      console.error('Error scanning content:', err);
    }
  };

  const logDatabaseActivity = async () => {
    try {
      const response = await fetch('/api/v1/data-protection/database/activities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          database_name: dbName,
          table_name: tableName,
          activity_type: dbActivityType,
          user: dbUser,
          ip_address: dbIpAddress,
          query: dbQuery
        })
      });

      if (response.ok) {
        setDbName('');
        setTableName('');
        setDbActivityType('select');
        setDbUser('');
        setDbIpAddress('');
        setDbQuery('');
        fetchData();
      }
    } catch (err) {
      console.error('Error logging database activity:', err);
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

  const getHealthIcon = (health: string) => {
    switch (health) {
      case 'healthy': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'warning': return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      default: return <XCircle className="h-4 w-4 text-red-500" />;
    }
  };

  if (loading) {
    return <div className="flex items-center justify-center h-64">Loading...</div>;
  }

  if (error) {
    return <Alert><AlertDescription>{error}</AlertDescription></Alert>;
  }

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex items-center space-x-2">
        <Shield className="h-8 w-8 text-blue-600" />
        <h1 className="text-3xl font-bold">Data Protection</h1>
      </div>

      {/* Summary Cards */}
      {summary && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Encryption</CardTitle>
              {getHealthIcon(summary.encryption_health)}
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{summary.total_encrypted_files}</div>
              <p className="text-xs text-muted-foreground">
                {summary.active_encryption_keys} active keys
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">DLP Violations</CardTitle>
              {getHealthIcon(summary.dlp_health)}
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{summary.dlp_violations_today}</div>
              <p className="text-xs text-muted-foreground">
                {summary.dlp_violations_week} this week
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Database Activities</CardTitle>
              {getHealthIcon(summary.database_monitoring_health)}
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{summary.database_activities_today}</div>
              <p className="text-xs text-muted-foreground">
                {summary.suspicious_activities} suspicious
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Overall Health</CardTitle>
              <Shield className="h-4 w-4 text-blue-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-600">Protected</div>
              <p className="text-xs text-muted-foreground">
                All systems operational
              </p>
            </CardContent>
          </Card>
        </div>
      )}

      <Tabs defaultValue="encryption" className="space-y-4">
        <TabsList>
          <TabsTrigger value="encryption" className="flex items-center space-x-2">
            <Lock className="h-4 w-4" />
            <span>Encryption</span>
          </TabsTrigger>
          <TabsTrigger value="dlp" className="flex items-center space-x-2">
            <Shield className="h-4 w-4" />
            <span>Data Loss Prevention</span>
          </TabsTrigger>
          <TabsTrigger value="database" className="flex items-center space-x-2">
            <Database className="h-4 w-4" />
            <span>Database Monitoring</span>
          </TabsTrigger>
        </TabsList>

        {/* Encryption Tab */}
        <TabsContent value="encryption" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Create Encryption Key */}
            <Card>
              <CardHeader>
                <CardTitle>Create Encryption Key</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <Label htmlFor="keyName">Key Name</Label>
                  <Input
                    id="keyName"
                    value={newKeyName}
                    onChange={(e) => setNewKeyName(e.target.value)}
                    placeholder="Enter key name"
                  />
                </div>
                <div>
                  <Label htmlFor="keyAlgorithm">Algorithm</Label>
                  <Select value={newKeyAlgorithm} onValueChange={setNewKeyAlgorithm}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="aes_256">AES-256</SelectItem>
                      <SelectItem value="rsa_2048">RSA-2048</SelectItem>
                      <SelectItem value="chacha20">ChaCha20</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label htmlFor="keyDescription">Description</Label>
                  <Textarea
                    id="keyDescription"
                    value={newKeyDescription}
                    onChange={(e) => setNewKeyDescription(e.target.value)}
                    placeholder="Enter key description"
                  />
                </div>
                <Button onClick={createEncryptionKey}>Create Key</Button>
              </CardContent>
            </Card>

            {/* Encrypt Data */}
            <Card>
              <CardHeader>
                <CardTitle>Encrypt Data</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <Label htmlFor="encryptData">Data to Encrypt</Label>
                  <Textarea
                    id="encryptData"
                    value={encryptData}
                    onChange={(e) => setEncryptData(e.target.value)}
                    placeholder="Enter data to encrypt"
                  />
                </div>
                <div>
                  <Label htmlFor="encryptKey">Encryption Key</Label>
                  <Select value={encryptKeyId} onValueChange={setEncryptKeyId}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select encryption key" />
                    </SelectTrigger>
                    <SelectContent>
                      {encryptionKeys.map(key => (
                        <SelectItem key={key.id} value={key.id}>
                          {key.name} ({key.algorithm})
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <Button onClick={encryptData}>Encrypt Data</Button>
              </CardContent>
            </Card>
          </div>

          {/* Encryption Keys Table */}
          <Card>
            <CardHeader>
              <CardTitle>Encryption Keys</CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Algorithm</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead>Description</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {encryptionKeys.map(key => (
                    <TableRow key={key.id}>
                      <TableCell>{key.name}</TableCell>
                      <TableCell>{key.algorithm}</TableCell>
                      <TableCell>
                        <Badge variant={key.is_active ? "default" : "secondary"}>
                          {key.is_active ? "Active" : "Inactive"}
                        </Badge>
                      </TableCell>
                      <TableCell>{new Date(key.created_at).toLocaleDateString()}</TableCell>
                      <TableCell>{key.description}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          {/* Encrypted Data Table */}
          <Card>
            <CardHeader>
              <CardTitle>Encrypted Data</CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>ID</TableHead>
                    <TableHead>Key ID</TableHead>
                    <TableHead>Algorithm</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {encryptedData.map(data => (
                    <TableRow key={data.id}>
                      <TableCell>{data.id}</TableCell>
                      <TableCell>{data.key_id}</TableCell>
                      <TableCell>{data.algorithm}</TableCell>
                      <TableCell>{new Date(data.created_at).toLocaleDateString()}</TableCell>
                      <TableCell>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setDecryptId(data.id)}
                        >
                          Decrypt
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        {/* DLP Tab */}
        <TabsContent value="dlp" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Create DLP Policy */}
            <Card>
              <CardHeader>
                <CardTitle>Create DLP Policy</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <Label htmlFor="policyName">Policy Name</Label>
                  <Input
                    id="policyName"
                    value={newPolicyName}
                    onChange={(e) => setNewPolicyName(e.target.value)}
                    placeholder="Enter policy name"
                  />
                </div>
                <div>
                  <Label htmlFor="policyDescription">Description</Label>
                  <Textarea
                    id="policyDescription"
                    value={newPolicyDescription}
                    onChange={(e) => setNewPolicyDescription(e.target.value)}
                    placeholder="Enter policy description"
                  />
                </div>
                <div>
                  <Label htmlFor="policyPatterns">Patterns (one per line)</Label>
                  <Textarea
                    id="policyPatterns"
                    value={newPolicyPatterns}
                    onChange={(e) => setNewPolicyPatterns(e.target.value)}
                    placeholder="Enter regex patterns"
                  />
                </div>
                <div>
                  <Label htmlFor="policyType">Violation Type</Label>
                  <Select value={newPolicyType} onValueChange={setNewPolicyType}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="credit_card">Credit Card</SelectItem>
                      <SelectItem value="ssn">SSN</SelectItem>
                      <SelectItem value="email">Email</SelectItem>
                      <SelectItem value="phone">Phone</SelectItem>
                      <SelectItem value="api_key">API Key</SelectItem>
                      <SelectItem value="password">Password</SelectItem>
                      <SelectItem value="custom_pattern">Custom Pattern</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label htmlFor="policySeverity">Severity</Label>
                  <Select value={newPolicySeverity} onValueChange={setNewPolicySeverity}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="low">Low</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="critical">Critical</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <Button onClick={createDLPPolicy}>Create Policy</Button>
              </CardContent>
            </Card>

            {/* Scan Content */}
            <Card>
              <CardHeader>
                <CardTitle>Scan Content</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <Label htmlFor="scanContent">Content to Scan</Label>
                  <Textarea
                    id="scanContent"
                    value={scanContent}
                    onChange={(e) => setScanContent(e.target.value)}
                    placeholder="Enter content to scan for violations"
                  />
                </div>
                <div>
                  <Label htmlFor="scanSource">Source</Label>
                  <Input
                    id="scanSource"
                    value={scanSource}
                    onChange={(e) => setScanSource(e.target.value)}
                    placeholder="Enter source identifier"
                  />
                </div>
                <Button onClick={scanContentForDLP}>Scan Content</Button>
              </CardContent>
            </Card>
          </div>

          {/* DLP Policies Table */}
          <Card>
            <CardHeader>
              <CardTitle>DLP Policies</CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Patterns</TableHead>
                    <TableHead>Created</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {dlpPolicies.map(policy => (
                    <TableRow key={policy.id}>
                      <TableCell>{policy.name}</TableCell>
                      <TableCell>{policy.violation_type}</TableCell>
                      <TableCell>
                        <Badge className={getSeverityColor(policy.severity)}>
                          {policy.severity}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant={policy.is_active ? "default" : "secondary"}>
                          {policy.is_active ? "Active" : "Inactive"}
                        </Badge>
                      </TableCell>
                      <TableCell>{policy.patterns.length} patterns</TableCell>
                      <TableCell>{new Date(policy.created_at).toLocaleDateString()}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          {/* DLP Violations Table */}
          <Card>
            <CardHeader>
              <CardTitle>DLP Violations</CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Type</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Detected Data</TableHead>
                    <TableHead>Timestamp</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {dlpViolations.map(violation => (
                    <TableRow key={violation.id}>
                      <TableCell>{violation.violation_type}</TableCell>
                      <TableCell>
                        <Badge className={getSeverityColor(violation.severity)}>
                          {violation.severity}
                        </Badge>
                      </TableCell>
                      <TableCell>{violation.source}</TableCell>
                      <TableCell>
                        <Badge variant={violation.status === 'open' ? "destructive" : "default"}>
                          {violation.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="max-w-xs truncate">
                        {violation.detected_data}
                      </TableCell>
                      <TableCell>{new Date(violation.timestamp).toLocaleString()}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Database Monitoring Tab */}
        <TabsContent value="database" className="space-y-4">
          {/* Log Database Activity */}
          <Card>
            <CardHeader>
              <CardTitle>Log Database Activity</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                <div>
                  <Label htmlFor="dbName">Database Name</Label>
                  <Input
                    id="dbName"
                    value={dbName}
                    onChange={(e) => setDbName(e.target.value)}
                    placeholder="Enter database name"
                  />
                </div>
                <div>
                  <Label htmlFor="tableName">Table Name</Label>
                  <Input
                    id="tableName"
                    value={tableName}
                    onChange={(e) => setTableName(e.target.value)}
                    placeholder="Enter table name"
                  />
                </div>
                <div>
                  <Label htmlFor="dbActivityType">Activity Type</Label>
                  <Select value={dbActivityType} onValueChange={setDbActivityType}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="select">SELECT</SelectItem>
                      <SelectItem value="insert">INSERT</SelectItem>
                      <SelectItem value="update">UPDATE</SelectItem>
                      <SelectItem value="delete">DELETE</SelectItem>
                      <SelectItem value="create">CREATE</SelectItem>
                      <SelectItem value="drop">DROP</SelectItem>
                      <SelectItem value="alter">ALTER</SelectItem>
                      <SelectItem value="grant">GRANT</SelectItem>
                      <SelectItem value="revoke">REVOKE</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label htmlFor="dbUser">User</Label>
                  <Input
                    id="dbUser"
                    value={dbUser}
                    onChange={(e) => setDbUser(e.target.value)}
                    placeholder="Enter user"
                  />
                </div>
                <div>
                  <Label htmlFor="dbIpAddress">IP Address</Label>
                  <Input
                    id="dbIpAddress"
                    value={dbIpAddress}
                    onChange={(e) => setDbIpAddress(e.target.value)}
                    placeholder="Enter IP address"
                  />
                </div>
                <div className="md:col-span-2 lg:col-span-3">
                  <Label htmlFor="dbQuery">Query</Label>
                  <Textarea
                    id="dbQuery"
                    value={dbQuery}
                    onChange={(e) => setDbQuery(e.target.value)}
                    placeholder="Enter SQL query"
                  />
                </div>
              </div>
              <Button onClick={logDatabaseActivity} className="mt-4">
                Log Activity
              </Button>
            </CardContent>
          </Card>

          {/* Database Activities Table */}
          <Card>
            <CardHeader>
              <CardTitle>Database Activities</CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Database</TableHead>
                    <TableHead>Table</TableHead>
                    <TableHead>Activity</TableHead>
                    <TableHead>User</TableHead>
                    <TableHead>IP Address</TableHead>
                    <TableHead>Risk Level</TableHead>
                    <TableHead>Suspicious</TableHead>
                    <TableHead>Timestamp</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {databaseActivities.map(activity => (
                    <TableRow key={activity.id}>
                      <TableCell>{activity.database_name}</TableCell>
                      <TableCell>{activity.table_name}</TableCell>
                      <TableCell>
                        <Badge variant="outline">
                          {activity.activity_type.toUpperCase()}
                        </Badge>
                      </TableCell>
                      <TableCell>{activity.user}</TableCell>
                      <TableCell>{activity.ip_address}</TableCell>
                      <TableCell>
                        <Badge className={getSeverityColor(activity.risk_level)}>
                          {activity.risk_level}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {activity.is_suspicious ? (
                          <AlertTriangle className="h-4 w-4 text-red-500" />
                        ) : (
                          <CheckCircle className="h-4 w-4 text-green-500" />
                        )}
                      </TableCell>
                      <TableCell>{new Date(activity.timestamp).toLocaleString()}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Decrypt Modal */}
      {decryptId && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center">
          <Card className="w-96">
            <CardHeader>
              <CardTitle>Decrypt Data</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label>Encrypted Data ID</Label>
                <Input value={decryptId} disabled />
              </div>
              {decryptedData && (
                <div>
                  <Label>Decrypted Data</Label>
                  <Textarea value={decryptedData} readOnly />
                </div>
              )}
              <div className="flex space-x-2">
                <Button onClick={decryptData}>Decrypt</Button>
                <Button variant="outline" onClick={() => setDecryptId('')}>
                  Close
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
};

export default DataProtection; 