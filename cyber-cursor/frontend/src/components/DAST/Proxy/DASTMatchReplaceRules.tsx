import React, { useState, useEffect, useCallback } from 'react';
import { 
  Box, 
  Button, 
  Card, 
  CardContent, 
  Typography, 
  TextField, 
  Chip, 
  List, 
  ListItem, 
  ListItemText, 
  ListItemIcon,
  ListItemSecondaryAction,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Grid,
  Alert,
  IconButton,
  Tooltip,
  Switch,
  Accordion,
  AccordionSummary,
  AccordionDetails
} from '@mui/material';
import { 
  Add, 
  Edit, 
  Delete, 
  ExpandMore, 
  ExpandLess,
  FilterList,
  Code,
  Http,
  Link,
  Description
} from '@mui/icons-material';
import { 
  createMatchReplaceRule, 
  listMatchReplaceRules, 
  updateMatchReplaceRule, 
  deleteMatchReplaceRule 
} from '../../../services/dastProjectToolsService';

interface MatchReplaceRule {
  id: string;
  name: string;
  description?: string;
  enabled: boolean;
  order_index: number;
  match_type: 'url' | 'header' | 'body' | 'response';
  match_pattern: string;
  match_case_sensitive: boolean;
  replace_type: 'url' | 'header' | 'body';
  replace_pattern: string;
  replace_value?: string;
  created_at: string;
  updated_at: string;
}

interface MatchReplaceRulesProps {
  projectId: string;
}

const DASTMatchReplaceRules: React.FC<MatchReplaceRulesProps> = ({ projectId }) => {
  const [rules, setRules] = useState<MatchReplaceRule[]>([]);
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [showEditDialog, setShowEditDialog] = useState(false);
  const [editingRule, setEditingRule] = useState<MatchReplaceRule | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [newRule, setNewRule] = useState({
    name: '',
    description: '',
    enabled: true,
    order_index: 0,
    match_type: 'url' as const,
    match_pattern: '',
    match_case_sensitive: false,
    replace_type: 'url' as const,
    replace_pattern: '',
    replace_value: ''
  });

  const matchTypes = [
    { value: 'url', label: 'URL', icon: <Link />, description: 'Match against request URL' },
    { value: 'header', label: 'Header', icon: <Http />, description: 'Match against request headers' },
    { value: 'body', label: 'Body', icon: <Description />, description: 'Match against request body' },
    { value: 'response', label: 'Response', icon: <Code />, description: 'Match against response body' }
  ];

  const replaceTypes = [
    { value: 'url', label: 'URL', icon: <Link />, description: 'Replace URL' },
    { value: 'header', label: 'Header', icon: <Http />, description: 'Replace header value' },
    { value: 'body', label: 'Body', icon: <Description />, description: 'Replace body content' }
  ];

  const loadRules = useCallback(async () => {
    try {
      const response = await listMatchReplaceRules(projectId);
      setRules(response || []);
    } catch (err: any) {
      setError(err.message || 'Failed to load rules');
    }
  }, [projectId]);

  useEffect(() => {
    loadRules();
  }, [loadRules]);

  const handleCreateRule = useCallback(async () => {
    if (!newRule.name.trim() || !newRule.match_pattern.trim()) {
      setError('Name and match pattern are required');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      await createMatchReplaceRule(projectId, newRule);
      setShowCreateDialog(false);
      setNewRule({
        name: '',
        description: '',
        enabled: true,
        order_index: 0,
        match_type: 'url',
        match_pattern: '',
        match_case_sensitive: false,
        replace_type: 'url',
        replace_pattern: '',
        replace_value: ''
      });
      await loadRules();
    } catch (err: any) {
      setError(err.message || 'Failed to create rule');
    } finally {
      setLoading(false);
    }
  }, [projectId, newRule, loadRules]);

  const handleUpdateRule = useCallback(async () => {
    if (!editingRule) return;

    setLoading(true);
    setError(null);

    try {
      await updateMatchReplaceRule(projectId, editingRule.id, editingRule);
      setShowEditDialog(false);
      setEditingRule(null);
      await loadRules();
    } catch (err: any) {
      setError(err.message || 'Failed to update rule');
    } finally {
      setLoading(false);
    }
  }, [projectId, editingRule, loadRules]);

  const handleDeleteRule = useCallback(async (ruleId: string) => {
    if (!window.confirm('Are you sure you want to delete this rule?')) return;

    try {
      await deleteMatchReplaceRule(projectId, ruleId);
      await loadRules();
    } catch (err: any) {
      setError(err.message || 'Failed to delete rule');
    }
  }, [projectId, loadRules]);

  const handleEditRule = useCallback((rule: MatchReplaceRule) => {
    setEditingRule(rule);
    setShowEditDialog(true);
  }, []);

  const getMatchTypeIcon = (type: string) => {
    return matchTypes.find(t => t.value === type)?.icon || <Code />;
  };

  const getReplaceTypeIcon = (type: string) => {
    return replaceTypes.find(t => t.value === type)?.icon || <Code />;
  };

  const getMatchTypeLabel = (type: string) => {
    return matchTypes.find(t => t.value === type)?.label || type;
  };

  const getReplaceTypeLabel = (type: string) => {
    return replaceTypes.find(t => t.value === type)?.label || type;
  };

  const renderRuleCard = (rule: MatchReplaceRule) => (
    <Card key={rule.id} sx={{ mb: 2 }}>
      <CardContent>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
          <Box>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              {rule.name}
              <Chip 
                label={rule.enabled ? 'Enabled' : 'Disabled'} 
                color={rule.enabled ? 'success' : 'default'}
                size="small"
              />
            </Typography>
            {rule.description && (
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                {rule.description}
              </Typography>
            )}
          </Box>
          <Box sx={{ display: 'flex', gap: 1 }}>
            <IconButton size="small" onClick={() => handleEditRule(rule)}>
              <Edit />
            </IconButton>
            <IconButton size="small" color="error" onClick={() => handleDeleteRule(rule.id)}>
              <Delete />
            </IconButton>
          </Box>
        </Box>

        <Grid container spacing={2}>
          <Grid item xs={12} md={6}>
            <Typography variant="subtitle2" gutterBottom>
              <FilterList sx={{ mr: 1, verticalAlign: 'middle' }} />
              Match Criteria
            </Typography>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
              {getMatchTypeIcon(rule.match_type)}
              <Chip label={getMatchTypeLabel(rule.match_type)} size="small" variant="outlined" />
              {rule.match_case_sensitive && (
                <Chip label="Case Sensitive" size="small" variant="outlined" />
              )}
            </Box>
            <Typography variant="body2" fontFamily="monospace" sx={{ bgcolor: 'grey.50', p: 1, borderRadius: 1 }}>
              {rule.match_pattern}
            </Typography>
          </Grid>

          <Grid item xs={12} md={6}>
            <Typography variant="subtitle2" gutterBottom>
              <Code sx={{ mr: 1, verticalAlign: 'middle' }} />
              Replace Action
            </Typography>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
              {getReplaceTypeIcon(rule.replace_type)}
              <Chip label={getReplaceTypeLabel(rule.replace_type)} size="small" variant="outlined" />
            </Box>
            {rule.replace_pattern ? (
              <Typography variant="body2" fontFamily="monospace" sx={{ bgcolor: 'grey.50', p: 1, borderRadius: 1 }}>
                Pattern: {rule.replace_pattern}
              </Typography>
            ) : (
              <Typography variant="body2" fontFamily="monospace" sx={{ bgcolor: 'grey.50', p: 1, borderRadius: 1 }}>
                Value: {rule.replace_value}
              </Typography>
            )}
          </Grid>
        </Grid>

        <Box sx={{ mt: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Typography variant="caption" color="text.secondary">
            Order: {rule.order_index} | Created: {new Date(rule.created_at).toLocaleDateString()}
          </Typography>
        </Box>
      </CardContent>
    </Card>
  );

  return (
    <Box sx={{ p: 2 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h5">
          <FilterList sx={{ mr: 1, verticalAlign: 'middle' }} />
          Match & Replace Rules
        </Typography>
        <Button
          variant="contained"
          color="primary"
          startIcon={<Add />}
          onClick={() => setShowCreateDialog(true)}
        >
          Add Rule
        </Button>
      </Box>

      {/* Rules List */}
      {rules.length > 0 ? (
        <Box>
          {rules
            .sort((a, b) => a.order_index - b.order_index)
            .map(renderRuleCard)
          }
        </Box>
      ) : (
        <Card>
          <CardContent>
            <Typography variant="body1" color="text.secondary" align="center">
              No match/replace rules configured yet.
            </Typography>
            <Typography variant="body2" color="text.secondary" align="center" sx={{ mt: 1 }}>
              Create rules to automatically modify requests and responses based on patterns.
            </Typography>
          </CardContent>
        </Card>
      )}

      {/* Error Display */}
      {error && (
        <Alert severity="error" sx={{ mt: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Create Rule Dialog */}
      <Dialog open={showCreateDialog} onClose={() => setShowCreateDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>Create Match/Replace Rule</DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Rule Name"
                value={newRule.name}
                onChange={(e) => setNewRule(prev => ({ ...prev, name: e.target.value }))}
                helperText="Give this rule a descriptive name"
              />
            </Grid>
            
            <Grid item xs={12}>
              <TextField
                fullWidth
                multiline
                rows={2}
                label="Description (Optional)"
                value={newRule.description}
                onChange={(e) => setNewRule(prev => ({ ...prev, description: e.target.value }))}
                helperText="Describe what this rule does"
              />
            </Grid>
            
            <Grid item xs={12} md={6}>
              <FormControl fullWidth>
                <InputLabel>Match Type</InputLabel>
                <Select
                  value={newRule.match_type}
                  onChange={(e) => setNewRule(prev => ({ ...prev, match_type: e.target.value as any }))}
                >
                  {matchTypes.map((type) => (
                    <MenuItem key={type.value} value={type.value}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        {type.icon}
                        <Box>
                          <Typography variant="body2">{type.label}</Typography>
                          <Typography variant="caption" color="text.secondary">
                            {type.description}
                          </Typography>
                        </Box>
                      </Box>
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            
            <Grid item xs={12} md={6}>
              <FormControl fullWidth>
                <InputLabel>Replace Type</InputLabel>
                <Select
                  value={newRule.replace_type}
                  onChange={(e) => setNewRule(prev => ({ ...prev, replace_type: e.target.value as any }))}
                >
                  {replaceTypes.map((type) => (
                    <MenuItem key={type.value} value={type.value}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        {type.icon}
                        <Box>
                          <Typography variant="body2">{type.label}</Typography>
                          <Typography variant="caption" color="text.secondary">
                            {type.description}
                          </Typography>
                        </Box>
                      </Box>
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Match Pattern (Regex)"
                value={newRule.match_pattern}
                onChange={(e) => setNewRule(prev => ({ ...prev, match_pattern: e.target.value }))}
                helperText="Regular expression pattern to match against"
                placeholder="example: .*admin.*"
              />
            </Grid>
            
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="Replace Pattern (Optional)"
                value={newRule.replace_pattern}
                onChange={(e) => setNewRule(prev => ({ ...prev, replace_pattern: e.target.value }))}
                helperText="Regex pattern to replace (leave empty for static value)"
                placeholder="example: admin"
              />
            </Grid>
            
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="Replace Value"
                value={newRule.replace_value}
                onChange={(e) => setNewRule(prev => ({ ...prev, replace_value: e.target.value }))}
                helperText="Value to replace with or static value if no pattern"
                placeholder="example: user"
              />
            </Grid>
            
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                type="number"
                label="Order Index"
                value={newRule.order_index}
                onChange={(e) => setNewRule(prev => ({ ...prev, order_index: parseInt(e.target.value) || 0 }))}
                helperText="Rules are processed in this order"
              />
            </Grid>
            
            <Grid item xs={12} md={6}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mt: 2 }}>
                <Typography variant="body2">Enabled</Typography>
                <Switch
                  checked={newRule.enabled}
                  onChange={(e) => setNewRule(prev => ({ ...prev, enabled: e.target.checked }))}
                />
                <Typography variant="body2">Case Sensitive</Typography>
                <Switch
                  checked={newRule.match_case_sensitive}
                  onChange={(e) => setNewRule(prev => ({ ...prev, match_case_sensitive: e.target.checked }))}
                />
              </Box>
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowCreateDialog(false)}>Cancel</Button>
          <Button 
            onClick={handleCreateRule} 
            variant="contained" 
            color="primary"
            disabled={loading || !newRule.name.trim() || !newRule.match_pattern.trim()}
          >
            {loading ? 'Creating...' : 'Create Rule'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Edit Rule Dialog */}
      <Dialog open={showEditDialog} onClose={() => setShowEditDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>Edit Match/Replace Rule</DialogTitle>
        <DialogContent>
          {editingRule && (
            <Grid container spacing={2} sx={{ mt: 1 }}>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Rule Name"
                  value={editingRule.name}
                  onChange={(e) => setEditingRule(prev => prev ? { ...prev, name: e.target.value } : null)}
                />
              </Grid>
              
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  multiline
                  rows={2}
                  label="Description"
                  value={editingRule.description || ''}
                  onChange={(e) => setEditingRule(prev => prev ? { ...prev, description: e.target.value } : null)}
                />
              </Grid>
              
              <Grid item xs={12} md={6}>
                <FormControl fullWidth>
                  <InputLabel>Match Type</InputLabel>
                  <Select
                    value={editingRule.match_type}
                    onChange={(e) => setEditingRule(prev => prev ? { ...prev, match_type: e.target.value as any } : null)}
                  >
                    {matchTypes.map((type) => (
                      <MenuItem key={type.value} value={type.value}>
                        {type.label}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
              
              <Grid item xs={12} md={6}>
                <FormControl fullWidth>
                  <InputLabel>Replace Type</InputLabel>
                  <Select
                    value={editingRule.replace_type}
                    onChange={(e) => setEditingRule(prev => prev ? { ...prev, replace_type: e.target.value as any } : null)}
                  >
                    {replaceTypes.map((type) => (
                      <MenuItem key={type.value} value={type.value}>
                        {type.label}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
              
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Match Pattern"
                  value={editingRule.match_pattern}
                  onChange={(e) => setEditingRule(prev => prev ? { ...prev, match_pattern: e.target.value } : null)}
                />
              </Grid>
              
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Replace Pattern"
                  value={editingRule.replace_pattern}
                  onChange={(e) => setEditingRule(prev => prev ? { ...prev, replace_pattern: e.target.value } : null)}
                />
              </Grid>
              
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Replace Value"
                  value={editingRule.replace_value || ''}
                  onChange={(e) => setEditingRule(prev => prev ? { ...prev, replace_value: e.target.value } : null)}
                />
              </Grid>
              
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  type="number"
                  label="Order Index"
                  value={editingRule.order_index}
                  onChange={(e) => setEditingRule(prev => prev ? { ...prev, order_index: parseInt(e.target.value) || 0 } : null)}
                />
              </Grid>
              
              <Grid item xs={12} md={6}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mt: 2 }}>
                  <Typography variant="body2">Enabled</Typography>
                  <Switch
                    checked={editingRule.enabled}
                    onChange={(e) => setEditingRule(prev => prev ? { ...prev, enabled: e.target.checked } : null)}
                  />
                  <Typography variant="body2">Case Sensitive</Typography>
                  <Switch
                    checked={editingRule.match_case_sensitive}
                    onChange={(e) => setEditingRule(prev => prev ? { ...prev, match_case_sensitive: e.target.checked } : null)}
                  />
                </Box>
              </Grid>
            </Grid>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowEditDialog(false)}>Cancel</Button>
          <Button 
            onClick={handleUpdateRule} 
            variant="contained" 
            color="primary"
            disabled={loading || !editingRule?.name.trim() || !editingRule?.match_pattern.trim()}
          >
            {loading ? 'Updating...' : 'Update Rule'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default DASTMatchReplaceRules;
