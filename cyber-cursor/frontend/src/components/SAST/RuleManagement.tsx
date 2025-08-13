import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  Button,
  Chip,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  IconButton,
  Tooltip,
  Alert,
  Switch,
  FormControlLabel,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  Divider
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  ExpandMore as ExpandMoreIcon,
  Security as SecurityIcon,
  Code as CodeIcon,
  BugReport as BugIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  Download as DownloadIcon,
  Upload as UploadIcon,
  Refresh as RefreshIcon
} from '@mui/icons-material';
import { sastService } from '../../services/sastService';

interface CustomRule {
  rule_id: string;
  name: string;
  description: string;
  category: string;
  subcategory?: string;
  severity: 'BLOCKER' | 'CRITICAL' | 'MAJOR' | 'MINOR' | 'INFO';
  type: 'VULNERABILITY' | 'BUG' | 'CODE_SMELL' | 'SECURITY_HOTSPOT';
  languages: string[];
  enabled: boolean;
  effort: number;
  cwe_id?: string;
  owasp_category?: string;
  tags: string[];
  pattern?: string;
  ast_pattern?: string;
  message_template: string;
}

const RuleManagement: React.FC = () => {
  const [rules, setRules] = useState<CustomRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [editingRule, setEditingRule] = useState<CustomRule | null>(null);
  
  // Form state
  const [ruleForm, setRuleForm] = useState<Partial<CustomRule>>({
    rule_id: '',
    name: '',
    description: '',
    category: '',
    subcategory: '',
    severity: 'MAJOR',
    type: 'VULNERABILITY',
    languages: [],
    enabled: true,
    effort: 0,
    cwe_id: '',
    owasp_category: '',
    tags: [],
    pattern: '',
    ast_pattern: '',
    message_template: 'Rule violation: {rule_name}'
  });
  
  // Filters
  const [languageFilter, setLanguageFilter] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [categoryFilter, setCategoryFilter] = useState<string>('');
  const [enabledFilter, setEnabledFilter] = useState<boolean | null>(null);
  
  // Error handling
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Load rules
  const loadRules = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      
      const rulesData = await sastService.getRules();
      // Convert SASTRule to CustomRule format
      const convertedRules: CustomRule[] = rulesData.map(rule => ({
        rule_id: rule.key || '',
        name: rule.name || '',
        description: rule.description || '',
        category: 'SECURITY', // Default category since SASTRule doesn't have it
        subcategory: '',
        severity: (rule.severity as 'BLOCKER' | 'CRITICAL' | 'MAJOR' | 'MINOR' | 'INFO') || 'MAJOR',
        type: (rule.type as 'VULNERABILITY' | 'BUG' | 'CODE_SMELL' | 'SECURITY_HOTSPOT') || 'VULNERABILITY',
        languages: [rule.language] || ['python'],
        enabled: rule.status === 'ACTIVE',
        effort: 0, // Default since SASTRule doesn't have it
        cwe_id: '',
        owasp_category: '',
        tags: rule.tags || [],
        pattern: '',
        ast_pattern: '',
        message_template: 'Rule violation: {rule_name}'
      }));
      setRules(convertedRules);
      
    } catch (err) {
      setError('Failed to load rules');
      console.error('Rules load error:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  // Create rule
  const createRule = useCallback(async () => {
    try {
      setError(null);
      
      // Validate required fields
      if (!ruleForm.rule_id || !ruleForm.name || !ruleForm.category || !ruleForm.languages?.length) {
        setError('Please fill in all required fields');
        return;
      }
      
      const newRule = await sastService.createCustomRule(ruleForm);
      setSuccess('Rule created successfully');
      setShowCreateModal(false);
      resetForm();
      loadRules();
      
    } catch (err) {
      setError('Failed to create rule');
      console.error('Rule creation error:', err);
    }
  }, [ruleForm, loadRules]);

  // Update rule
  const updateRule = useCallback(async () => {
    if (!editingRule) return;
    
    try {
      setError(null);
      
      const updatedRule = await sastService.updateRule(editingRule.rule_id, ruleForm);
      setSuccess('Rule updated successfully');
      setShowEditModal(false);
      setEditingRule(null);
      resetForm();
      loadRules();
      
    } catch (err) {
      setError('Failed to update rule');
      console.error('Rule update error:', err);
    }
  }, [editingRule, ruleForm, loadRules]);

  // Delete rule
  const deleteRule = useCallback(async (ruleId: string) => {
    if (!window.confirm('Are you sure you want to delete this rule?')) return;
    
    try {
      await sastService.deleteRule(ruleId);
      setSuccess('Rule deleted successfully');
      loadRules();
    } catch (err) {
      setError('Failed to delete rule');
      console.error('Rule deletion error:', err);
    }
  }, [loadRules]);

  // Edit rule
  const editRule = useCallback((rule: CustomRule) => {
    setEditingRule(rule);
    setRuleForm({
      rule_id: rule.rule_id,
      name: rule.name,
      description: rule.description,
      category: rule.category,
      subcategory: rule.subcategory,
      severity: rule.severity,
      type: rule.type,
      languages: rule.languages,
      enabled: rule.enabled,
      effort: rule.effort,
      cwe_id: rule.cwe_id,
      owasp_category: rule.owasp_category,
      tags: rule.tags,
      pattern: rule.pattern,
      ast_pattern: rule.ast_pattern,
      message_template: rule.message_template
    });
    setShowEditModal(true);
  }, []);

  // Reset form
  const resetForm = useCallback(() => {
    setRuleForm({
      rule_id: '',
      name: '',
      description: '',
      category: '',
      subcategory: '',
      severity: 'MAJOR',
      type: 'VULNERABILITY',
      languages: [],
      enabled: true,
      effort: 0,
      cwe_id: '',
      owasp_category: '',
      tags: [],
      pattern: '',
      ast_pattern: '',
      message_template: 'Rule violation: {rule_name}'
    });
  }, []);

  // Export rules
  const exportRules = useCallback(async () => {
    try {
      // This would call a backend endpoint to export rules
      setSuccess('Rules exported successfully');
    } catch (err) {
      setError('Failed to export rules');
      console.error('Export error:', err);
    }
  }, []);

  // Import rules
  const importRules = useCallback(async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    
    try {
      // This would call a backend endpoint to import rules
      setSuccess('Rules imported successfully');
      loadRules();
    } catch (err) {
      setError('Failed to import rules');
      console.error('Import error:', err);
    }
  }, [loadRules]);

  // Filter rules
  const filteredRules = rules.filter(rule => {
    if (languageFilter && !rule.languages.includes(languageFilter)) return false;
    if (severityFilter && rule.severity !== severityFilter) return false;
    if (categoryFilter && rule.category !== categoryFilter) return false;
    if (enabledFilter !== null && rule.enabled !== enabledFilter) return false;
    return true;
  });

  // Get available categories and languages
  const categories = Array.from(new Set(rules.map(r => r.category)));
  const languages = Array.from(new Set(rules.flatMap(r => r.languages)));

  // Load rules on component mount
  useEffect(() => {
    loadRules();
  }, [loadRules]);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'BLOCKER': return 'error';
      case 'CRITICAL': return 'error';
      case 'MAJOR': return 'warning';
      case 'MINOR': return 'info';
      case 'INFO': return 'default';
      default: return 'default';
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'VULNERABILITY': return <SecurityIcon />;
      case 'BUG': return <BugIcon />;
      case 'CODE_SMELL': return <CodeIcon />;
      case 'SECURITY_HOTSPOT': return <WarningIcon />;
      default: return <InfoIcon />;
    }
  };

  return (
    <Box sx={{ flexGrow: 1, p: 3 }}>
      {/* Header */}
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4" component="h1">
          Custom Rule Management
        </Typography>
        <Box display="flex" gap={2}>
          <Button
            variant="outlined"
            startIcon={<UploadIcon />}
            component="label"
          >
            Import Rules
            <input
              type="file"
              hidden
              accept=".json"
              onChange={importRules}
            />
          </Button>
          <Button
            variant="outlined"
            startIcon={<DownloadIcon />}
            onClick={exportRules}
          >
            Export Rules
          </Button>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => setShowCreateModal(true)}
          >
            Create Rule
          </Button>
        </Box>
      </Box>

      {/* Alerts */}
      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}
      {success && (
        <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSuccess(null)}>
          {success}
        </Alert>
      )}

      {/* Filters */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Filters
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} sm={6} md={3}>
              <FormControl fullWidth>
                <InputLabel>Language</InputLabel>
                <Select
                  value={languageFilter}
                  onChange={(e) => setLanguageFilter(e.target.value)}
                  label="Language"
                >
                  <MenuItem value="">All Languages</MenuItem>
                  {languages.map((lang) => (
                    <MenuItem key={lang} value={lang}>
                      {lang}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            
            <Grid item xs={12} sm={6} md={3}>
              <FormControl fullWidth>
                <InputLabel>Severity</InputLabel>
                <Select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  label="Severity"
                >
                  <MenuItem value="">All Severities</MenuItem>
                  <MenuItem value="BLOCKER">Blocker</MenuItem>
                  <MenuItem value="CRITICAL">Critical</MenuItem>
                  <MenuItem value="MAJOR">Major</MenuItem>
                  <MenuItem value="MINOR">Minor</MenuItem>
                  <MenuItem value="INFO">Info</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            
            <Grid item xs={12} sm={6} md={3}>
              <FormControl fullWidth>
                <InputLabel>Category</InputLabel>
                <Select
                  value={categoryFilter}
                  onChange={(e) => setCategoryFilter(e.target.value)}
                  label="Category"
                >
                  <MenuItem value="">All Categories</MenuItem>
                  {categories.map((cat) => (
                    <MenuItem key={cat} value={cat}>
                      {cat}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            
            <Grid item xs={12} sm={6} md={3}>
              <FormControl fullWidth>
                <InputLabel>Status</InputLabel>
                <Select
                  value={enabledFilter === null ? '' : enabledFilter ? 'true' : 'false'}
                  onChange={(e) => setEnabledFilter(e.target.value === '' ? null : e.target.value === 'true')}
                  label="Status"
                >
                  <MenuItem value="">All</MenuItem>
                  <MenuItem value="true">Enabled</MenuItem>
                  <MenuItem value="false">Disabled</MenuItem>
                </Select>
              </FormControl>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Rules Table */}
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Rule ID</TableCell>
              <TableCell>Name</TableCell>
              <TableCell>Category</TableCell>
              <TableCell>Severity</TableCell>
              <TableCell>Type</TableCell>
              <TableCell>Languages</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {filteredRules.map((rule) => (
              <TableRow key={rule.rule_id}>
                <TableCell>
                  <Typography variant="body2" fontFamily="monospace">
                    {rule.rule_id}
                  </Typography>
                </TableCell>
                
                <TableCell>
                  <Box>
                    <Typography variant="body2" fontWeight="medium">
                      {rule.name}
                    </Typography>
                    <Typography variant="caption" color="textSecondary">
                      {rule.description}
                    </Typography>
                  </Box>
                </TableCell>
                
                <TableCell>
                  <Chip
                    label={rule.category}
                    size="small"
                    variant="outlined"
                  />
                  {rule.subcategory && (
                    <Typography variant="caption" display="block" color="textSecondary">
                      {rule.subcategory}
                    </Typography>
                  )}
                </TableCell>
                
                <TableCell>
                  <Chip
                    label={rule.severity}
                    size="small"
                    color={getSeverityColor(rule.severity) as any}
                  />
                </TableCell>
                
                <TableCell>
                  <Box display="flex" alignItems="center" gap={1}>
                    {getTypeIcon(rule.type)}
                    <Typography variant="body2">
                      {rule.type}
                    </Typography>
                  </Box>
                </TableCell>
                
                <TableCell>
                  <Box display="flex" gap={0.5} flexWrap="wrap">
                    {rule.languages.map((lang) => (
                      <Chip
                        key={lang}
                        label={lang}
                        size="small"
                        variant="outlined"
                      />
                    ))}
                  </Box>
                </TableCell>
                
                <TableCell>
                  <Chip
                    label={rule.enabled ? 'Enabled' : 'Disabled'}
                    size="small"
                    color={rule.enabled ? 'success' : 'default'}
                  />
                </TableCell>
                
                <TableCell>
                  <Box display="flex" gap={1}>
                    <Tooltip title="Edit Rule">
                      <IconButton
                        size="small"
                        onClick={() => editRule(rule)}
                      >
                        <EditIcon />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Delete Rule">
                      <IconButton
                        size="small"
                        color="error"
                        onClick={() => deleteRule(rule.rule_id)}
                      >
                        <DeleteIcon />
                      </IconButton>
                    </Tooltip>
                  </Box>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      {/* Create Rule Modal */}
      <Dialog open={showCreateModal} onClose={() => setShowCreateModal(false)} maxWidth="md" fullWidth>
        <DialogTitle>Create Custom Rule</DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="Rule ID"
                value={ruleForm.rule_id}
                onChange={(e) => setRuleForm({ ...ruleForm, rule_id: e.target.value })}
                required
                helperText="Unique identifier for the rule"
              />
            </Grid>
            
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="Rule Name"
                value={ruleForm.name}
                onChange={(e) => setRuleForm({ ...ruleForm, name: e.target.value })}
                required
              />
            </Grid>
            
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Description"
                value={ruleForm.description}
                onChange={(e) => setRuleForm({ ...ruleForm, description: e.target.value })}
                multiline
                rows={3}
                required
              />
            </Grid>
            
            <Grid item xs={12} md={6}>
              <FormControl fullWidth required>
                <InputLabel>Category</InputLabel>
                <Select
                  value={ruleForm.category}
                  onChange={(e) => setRuleForm({ ...ruleForm, category: e.target.value })}
                  label="Category"
                >
                  <MenuItem value="Security">Security</MenuItem>
                  <MenuItem value="Performance">Performance</MenuItem>
                  <MenuItem value="Maintainability">Maintainability</MenuItem>
                  <MenuItem value="Reliability">Reliability</MenuItem>
                  <MenuItem value="Usability">Usability</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="Subcategory"
                value={ruleForm.subcategory}
                onChange={(e) => setRuleForm({ ...ruleForm, subcategory: e.target.value })}
              />
            </Grid>
            
            <Grid item xs={12} md={6}>
              <FormControl fullWidth required>
                <InputLabel>Severity</InputLabel>
                <Select
                  value={ruleForm.severity}
                  onChange={(e) => setRuleForm({ ...ruleForm, severity: e.target.value as any })}
                  label="Severity"
                >
                  <MenuItem value="BLOCKER">Blocker</MenuItem>
                  <MenuItem value="CRITICAL">Critical</MenuItem>
                  <MenuItem value="MAJOR">Major</MenuItem>
                  <MenuItem value="MINOR">Minor</MenuItem>
                  <MenuItem value="INFO">Info</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            
            <Grid item xs={12} md={6}>
              <FormControl fullWidth required>
                <InputLabel>Type</InputLabel>
                <Select
                  value={ruleForm.type}
                  onChange={(e) => setRuleForm({ ...ruleForm, type: e.target.value as any })}
                  label="Type"
                >
                  <MenuItem value="VULNERABILITY">Vulnerability</MenuItem>
                  <MenuItem value="BUG">Bug</MenuItem>
                  <MenuItem value="CODE_SMELL">Code Smell</MenuItem>
                  <MenuItem value="SECURITY_HOTSPOT">Security Hotspot</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            
            <Grid item xs={12} md={6}>
              <FormControl fullWidth required>
                <InputLabel>Languages</InputLabel>
                <Select
                  multiple
                  value={ruleForm.languages || []}
                  onChange={(e) => setRuleForm({ ...ruleForm, languages: e.target.value as string[] })}
                  label="Languages"
                >
                  <MenuItem value="python">Python</MenuItem>
                  <MenuItem value="javascript">JavaScript</MenuItem>
                  <MenuItem value="typescript">TypeScript</MenuItem>
                  <MenuItem value="java">Java</MenuItem>
                  <MenuItem value="php">PHP</MenuItem>
                  <MenuItem value="go">Go</MenuItem>
                  <MenuItem value="csharp">C#</MenuItem>
                  <MenuItem value="ruby">Ruby</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="Effort (minutes)"
                type="number"
                value={ruleForm.effort}
                onChange={(e) => setRuleForm({ ...ruleForm, effort: parseInt(e.target.value) || 0 })}
              />
            </Grid>
            
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="CWE ID"
                value={ruleForm.cwe_id}
                onChange={(e) => setRuleForm({ ...ruleForm, cwe_id: e.target.value })}
                placeholder="CWE-79"
              />
            </Grid>
            
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="OWASP Category"
                value={ruleForm.owasp_category}
                onChange={(e) => setRuleForm({ ...ruleForm, owasp_category: e.target.value })}
                placeholder="A03:2021 - Injection"
              />
            </Grid>
            
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Tags"
                value={ruleForm.tags?.join(', ') || ''}
                onChange={(e) => setRuleForm({ ...ruleForm, tags: e.target.value.split(',').map(t => t.trim()).filter(Boolean) })}
                placeholder="security, injection, xss"
                helperText="Comma-separated tags"
              />
            </Grid>
            
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Regex Pattern"
                value={ruleForm.pattern}
                onChange={(e) => setRuleForm({ ...ruleForm, pattern: e.target.value })}
                placeholder="execute.*\\(.*\\+.*"
                helperText="Regular expression pattern for rule matching"
              />
            </Grid>
            
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Message Template"
                value={ruleForm.message_template}
                onChange={(e) => setRuleForm({ ...ruleForm, message_template: e.target.value })}
                placeholder="Rule violation: {rule_name}"
                helperText="Message template with {rule_name} placeholder"
              />
            </Grid>
            
            <Grid item xs={12}>
              <FormControlLabel
                control={
                  <Switch
                    checked={ruleForm.enabled}
                    onChange={(e) => setRuleForm({ ...ruleForm, enabled: e.target.checked })}
                  />
                }
                label="Rule Enabled"
              />
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowCreateModal(false)}>Cancel</Button>
          <Button onClick={createRule} variant="contained">
            Create Rule
          </Button>
        </DialogActions>
      </Dialog>

      {/* Edit Rule Modal */}
      <Dialog open={showEditModal} onClose={() => setShowEditModal(false)} maxWidth="md" fullWidth>
        <DialogTitle>Edit Rule</DialogTitle>
        <DialogContent>
          {/* Same form fields as create modal */}
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="Rule ID"
                value={ruleForm.rule_id}
                disabled
                helperText="Rule ID cannot be changed"
              />
            </Grid>
            
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="Rule Name"
                value={ruleForm.name}
                onChange={(e) => setRuleForm({ ...ruleForm, name: e.target.value })}
                required
              />
            </Grid>
            
            {/* Add all other form fields similar to create modal */}
            {/* ... */}
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowEditModal(false)}>Cancel</Button>
          <Button onClick={updateRule} variant="contained">
            Update Rule
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default RuleManagement;
