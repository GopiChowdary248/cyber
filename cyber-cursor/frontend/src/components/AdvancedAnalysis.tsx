import React, { useState, useEffect, useCallback } from 'react';
import {
  Box, Grid, Card, CardContent, Typography, Button, Chip, LinearProgress, Alert, IconButton, Tooltip,
  Dialog, DialogTitle, DialogContent, DialogActions, TextField, Select, MenuItem, FormControl, InputLabel,
  Tabs, Tab, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Paper, Badge, CircularProgress,
  Accordion, AccordionSummary, AccordionDetails, List, ListItem, ListItemText, ListItemIcon, Divider,
  FormControlLabel, Switch, Slider, Typography as MuiTypography
} from '@mui/material';
import {
  Refresh as RefreshIcon, PlayArrow as PlayIcon, Download as DownloadIcon,
  Security as SecurityIcon, Code as CodeIcon, BugReport as BugIcon, TrendingUp as TrendingIcon,
  Assessment as AssessmentIcon, DataUsage as DataUsageIcon, Warning as WarningIcon,
  CheckCircle as CheckCircleIcon, Error as ErrorIcon, Info as InfoIcon,
  ExpandMore as ExpandMoreIcon, Timeline as TimelineIcon, AccountTree as AccountTreeIcon,
  BugReport as BugReportIcon
} from '@mui/icons-material';
import { sastService } from '../services/sastService';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`advanced-analysis-tabpanel-${index}`}
      aria-labelledby={`advanced-analysis-tab-${index}`}
      {...other}
    >
      {value === index && (
        <Box sx={{ p: 3 }}>
          {children}
        </Box>
      )}
    </div>
  );
}

interface AdvancedAnalysisProps {
  projectId: string;
  projectName: string;
}

const AdvancedAnalysis: React.FC<AdvancedAnalysisProps> = ({ projectId, projectName }) => {
  const [tabValue, setTabValue] = useState(0);
  const [analysisRunning, setAnalysisRunning] = useState(false);
  const [analysisResults, setAnalysisResults] = useState<any>(null);
  const [dataFlowResults, setDataFlowResults] = useState<any>(null);
  const [taintResults, setTaintResults] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  // Analysis configuration
  const [analysisTypes, setAnalysisTypes] = useState<string[]>([
    'data_flow', 'taint_analysis', 'security_pattern'
  ]);
  const [languages, setLanguages] = useState<string[]>([
    'python', 'javascript', 'java'
  ]);
  
  // Modal states
  const [showAnalysisModal, setShowAnalysisModal] = useState(false);
  const [showDataFlowModal, setShowDataFlowModal] = useState(false);
  const [showTaintModal, setShowTaintModal] = useState(false);

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const startAdvancedAnalysis = async () => {
    try {
      setAnalysisRunning(true);
      setError(null);
      
      const result = await sastService.startAdvancedAnalysis(
        projectId,
        analysisTypes,
        languages
      );
      
      setAnalysisResults(result);
      setShowAnalysisModal(false);
      
      // Refresh data
      await loadDataFlowAnalysis();
      await loadTaintAnalysis();
      
    } catch (err: any) {
      setError(err.message || 'Failed to start advanced analysis');
    } finally {
      setAnalysisRunning(false);
    }
  };

  const loadDataFlowAnalysis = async () => {
    try {
      setLoading(true);
      const result = await sastService.getDataFlowAnalysis(projectId);
      setDataFlowResults(result);
    } catch (err: any) {
      console.error('Error loading data flow analysis:', err);
    } finally {
      setLoading(false);
    }
  };

  const loadTaintAnalysis = async () => {
    try {
      setLoading(true);
      const result = await sastService.getTaintAnalysis(projectId);
      setTaintResults(result);
    } catch (err: any) {
      console.error('Error loading taint analysis:', err);
    } finally {
      setLoading(false);
    }
  };

  const exportAnalysis = async (format: string) => {
    try {
      if (analysisResults?.analysis_id) {
        const result = await sastService.exportAdvancedAnalysis(
          analysisResults.analysis_id,
          format
        );
        
        if (format === 'csv') {
          // Handle CSV download
          const blob = new Blob([result], { type: 'text/csv' });
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `advanced_analysis_${analysisResults.analysis_id}.csv`;
          a.click();
          window.URL.revokeObjectURL(url);
        } else {
          // Handle JSON download
          const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `advanced_analysis_${analysisResults.analysis_id}.json`;
          a.click();
          window.URL.revokeObjectURL(url);
        }
      }
    } catch (err: any) {
      setError(err.message || 'Failed to export analysis');
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'error';
      case 'high': return 'warning';
      case 'medium': return 'info';
      case 'low': return 'success';
      default: return 'default';
    }
  };

  const getRiskLevelColor = (riskLevel: string) => {
    switch (riskLevel.toLowerCase()) {
      case 'high': return 'error';
      case 'medium': return 'warning';
      case 'low': return 'success';
      default: return 'default';
    }
  };

  useEffect(() => {
    if (projectId) {
      loadDataFlowAnalysis();
      loadTaintAnalysis();
    }
  }, [projectId]);

  return (
    <Box sx={{ width: '100%' }}>
      <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
        <Tabs value={tabValue} onChange={handleTabChange} aria-label="Advanced Analysis Tabs">
          <Tab label="Overview" icon={<AssessmentIcon />} iconPosition="start" />
          <Tab label="Data Flow Analysis" icon={<AccountTreeIcon />} iconPosition="start" />
          <Tab label="Taint Analysis" icon={<SecurityIcon />} iconPosition="start" />
          <Tab label="Security Patterns" icon={<BugReportIcon />} iconPosition="start" />
          <Tab label="Vulnerabilities" icon={<WarningIcon />} iconPosition="start" />
        </Tabs>
      </Box>

      {/* Overview Tab */}
      <TabPanel value={tabValue} index={0}>
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
                  <Typography variant="h6">Advanced Analysis Dashboard</Typography>
                  <Button
                    variant="contained"
                    startIcon={<PlayIcon />}
                    onClick={() => setShowAnalysisModal(true)}
                    disabled={analysisRunning}
                  >
                    {analysisRunning ? 'Running...' : 'Start Analysis'}
                  </Button>
                </Box>
                
                {analysisResults && (
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={3}>
                      <Card sx={{ bgcolor: 'primary.light', color: 'white' }}>
                        <CardContent>
                          <Typography variant="h4">{analysisResults.vulnerabilities_found}</Typography>
                          <Typography variant="body2">Vulnerabilities Found</Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                    <Grid item xs={12} md={3}>
                      <Card sx={{ bgcolor: 'secondary.light', color: 'white' }}>
                        <CardContent>
                          <Typography variant="h4">{analysisResults.data_flow_paths}</Typography>
                          <Typography variant="body2">Data Flow Paths</Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                    <Grid item xs={12} md={3}>
                      <Card sx={{ bgcolor: 'warning.light', color: 'white' }}>
                        <CardContent>
                          <Typography variant="h4">{analysisResults.taint_flows}</Typography>
                          <Typography variant="body2">Taint Flows</Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                    <Grid item xs={12} md={3}>
                      <Card sx={{ bgcolor: 'success.light', color: 'white' }}>
                        <CardContent>
                          <Typography variant="h4">{analysisResults.summary?.high_risk_paths || 0}</Typography>
                          <Typography variant="body2">High Risk Paths</Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                  </Grid>
                )}

                {!analysisResults && (
                  <Alert severity="info">
                    No advanced analysis has been run yet. Click "Start Analysis" to begin.
                  </Alert>
                )}
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Data Flow Analysis Tab */}
      <TabPanel value={tabValue} index={1}>
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
                  <Typography variant="h6">Data Flow Analysis</Typography>
                  <Button
                    variant="outlined"
                    startIcon={<RefreshIcon />}
                    onClick={loadDataFlowAnalysis}
                    disabled={loading}
                  >
                    Refresh
                  </Button>
                </Box>

                {loading ? (
                  <Box display="flex" justifyContent="center" p={3}>
                    <CircularProgress />
                  </Box>
                ) : dataFlowResults ? (
                  <Box>
                    <Grid container spacing={2} mb={3}>
                      <Grid item xs={12} md={3}>
                        <Card>
                          <CardContent>
                            <Typography variant="h6">{dataFlowResults.summary?.total_nodes || 0}</Typography>
                            <Typography variant="body2">Total Nodes</Typography>
                          </CardContent>
                        </Card>
                      </Grid>
                      <Grid item xs={12} md={3}>
                        <Card>
                          <CardContent>
                            <Typography variant="h6">{dataFlowResults.summary?.total_edges || 0}</Typography>
                            <Typography variant="body2">Total Edges</Typography>
                          </CardContent>
                        </Card>
                      </Grid>
                      <Grid item xs={12} md={3}>
                        <Card>
                          <CardContent>
                            <Typography variant="h6">{dataFlowResults.summary?.high_risk_paths || 0}</Typography>
                            <Typography variant="body2">High Risk Paths</Typography>
                          </CardContent>
                        </Card>
                      </Grid>
                      <Grid item xs={12} md={3}>
                        <Card>
                          <CardContent>
                            <Typography variant="h6">{dataFlowResults.summary?.total_paths || 0}</Typography>
                            <Typography variant="body2">Total Paths</Typography>
                          </CardContent>
                        </Card>
                      </Grid>
                    </Grid>

                    <Typography variant="h6" mb={2}>Data Flow Paths</Typography>
                    <TableContainer component={Paper}>
                      <Table>
                        <TableHead>
                          <TableRow>
                            <TableCell>Path ID</TableCell>
                            <TableCell>Source</TableCell>
                            <TableCell>Sink</TableCell>
                            <TableCell>Risk Level</TableCell>
                            <TableCell>Nodes</TableCell>
                            <TableCell>Actions</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {dataFlowResults.data_flow_paths?.map((path: any) => (
                            <TableRow key={path.path_id}>
                              <TableCell>{path.path_id}</TableCell>
                              <TableCell>
                                <Box>
                                  <Typography variant="body2">{path.source.name}</Typography>
                                  <Typography variant="caption" color="textSecondary">
                                    {path.source.file_path}:{path.source.line_number}
                                  </Typography>
                                </Box>
                              </TableCell>
                              <TableCell>
                                <Box>
                                  <Typography variant="body2">{path.sink.name}</Typography>
                                  <Typography variant="caption" color="textSecondary">
                                    {path.sink.file_path}:{path.sink.line_number}
                                  </Typography>
                                </Box>
                              </TableCell>
                              <TableCell>
                                <Chip
                                  label={path.risk_level}
                                  color={getRiskLevelColor(path.risk_level)}
                                  size="small"
                                />
                              </TableCell>
                              <TableCell>{path.node_count}</TableCell>
                              <TableCell>
                                <Button
                                  size="small"
                                  onClick={() => setShowDataFlowModal(true)}
                                >
                                  View Details
                                </Button>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  </Box>
                ) : (
                  <Alert severity="info">No data flow analysis results available.</Alert>
                )}
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Taint Analysis Tab */}
      <TabPanel value={tabValue} index={2}>
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
                  <Typography variant="h6">Taint Analysis</Typography>
                  <Button
                    variant="outlined"
                    startIcon={<RefreshIcon />}
                    onClick={loadTaintAnalysis}
                    disabled={loading}
                  >
                    Refresh
                  </Button>
                </Box>

                {loading ? (
                  <Box display="flex" justifyContent="center" p={3}>
                    <CircularProgress />
                  </Box>
                ) : taintResults ? (
                  <Box>
                    <Grid container spacing={2} mb={3}>
                      <Grid item xs={12} md={3}>
                        <Card>
                          <CardContent>
                            <Typography variant="h6">{taintResults.summary?.total_sources || 0}</Typography>
                            <Typography variant="body2">Taint Sources</Typography>
                          </CardContent>
                        </Card>
                      </Grid>
                      <Grid item xs={12} md={3}>
                        <Card>
                          <CardContent>
                            <Typography variant="h6">{taintResults.summary?.total_sinks || 0}</Typography>
                            <Typography variant="body2">Taint Sinks</Typography>
                          </CardContent>
                        </Card>
                      </Grid>
                      <Grid item xs={12} md={3}>
                        <Card>
                          <CardContent>
                            <Typography variant="h6">{taintResults.summary?.tainted_flows || 0}</Typography>
                            <Typography variant="body2">Tainted Flows</Typography>
                          </CardContent>
                        </Card>
                      </Grid>
                      <Grid item xs={12} md={3}>
                        <Card>
                          <CardContent>
                            <Typography variant="h6">{taintResults.summary?.sanitized_flows || 0}</Typography>
                            <Typography variant="body2">Sanitized Flows</Typography>
                          </CardContent>
                        </Card>
                      </Grid>
                    </Grid>

                    <Typography variant="h6" mb={2}>Taint Flows</Typography>
                    <TableContainer component={Paper}>
                      <Table>
                        <TableHead>
                          <TableRow>
                            <TableCell>Flow ID</TableCell>
                            <TableCell>Source</TableCell>
                            <TableCell>Sink</TableCell>
                            <TableCell>Status</TableCell>
                            <TableCell>Severity</TableCell>
                            <TableCell>Actions</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {taintResults.taint_flows?.map((flow: any) => (
                            <TableRow key={flow.id}>
                              <TableCell>{flow.id}</TableCell>
                              <TableCell>
                                <Box>
                                  <Typography variant="body2">{flow.source.name}</Typography>
                                  <Typography variant="caption" color="textSecondary">
                                    {flow.source.taint_type} - {flow.source.file_path}:{flow.source.line_number}
                                  </Typography>
                                </Box>
                              </TableCell>
                              <TableCell>
                                <Box>
                                  <Typography variant="body2">{flow.sink.name}</Typography>
                                  <Typography variant="caption" color="textSecondary">
                                    {flow.sink.sink_type} - {flow.sink.file_path}:{flow.sink.line_number}
                                  </Typography>
                                </Box>
                              </TableCell>
                              <TableCell>
                                <Chip
                                  label={flow.taint_status}
                                  color={
                                    flow.taint_status === 'sanitized' ? 'success' :
                                    flow.taint_status === 'tainted' ? 'error' : 'warning'
                                  }
                                  size="small"
                                />
                              </TableCell>
                              <TableCell>
                                <Chip
                                  label={flow.severity}
                                  color={getSeverityColor(flow.severity)}
                                  size="small"
                                />
                              </TableCell>
                              <TableCell>
                                <Button
                                  size="small"
                                  onClick={() => setShowTaintModal(true)}
                                >
                                  View Details
                                </Button>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  </Box>
                ) : (
                  <Alert severity="info">No taint analysis results available.</Alert>
                )}
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Security Patterns Tab */}
      <TabPanel value={tabValue} index={3}>
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" mb={2}>Security Pattern Detection</Typography>
                <Alert severity="info" sx={{ mb: 2 }}>
                  Security pattern analysis identifies common security anti-patterns and vulnerabilities in your code.
                </Alert>
                
                {analysisResults?.summary?.vulnerabilities_by_category && (
                  <Grid container spacing={2}>
                    {Object.entries(analysisResults.summary.vulnerabilities_by_category).map(([category, count]) => (
                      <Grid item xs={12} md={4} key={category}>
                        <Card>
                          <CardContent>
                            <Typography variant="h6">{count as number}</Typography>
                            <Typography variant="body2" color="textSecondary">
                              {category.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                            </Typography>
                          </CardContent>
                        </Card>
                      </Grid>
                    ))}
                  </Grid>
                )}
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Vulnerabilities Tab */}
      <TabPanel value={tabValue} index={4}>
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
                  <Typography variant="h6">Advanced Vulnerabilities</Typography>
                  {analysisResults && (
                    <Box>
                      <Button
                        variant="outlined"
                        startIcon={<DownloadIcon />}
                        onClick={() => exportAnalysis('json')}
                        sx={{ mr: 1 }}
                      >
                        Export JSON
                      </Button>
                      <Button
                        variant="outlined"
                        startIcon={<DownloadIcon />}
                        onClick={() => exportAnalysis('csv')}
                      >
                        Export CSV
                      </Button>
                    </Box>
                  )}
                </Box>

                {analysisResults?.vulnerabilities ? (
                  <TableContainer component={Paper}>
                    <Table>
                      <TableHead>
                        <TableRow>
                          <TableCell>Title</TableCell>
                          <TableCell>Category</TableCell>
                          <TableCell>Severity</TableCell>
                          <TableCell>File</TableCell>
                          <TableCell>Line</TableCell>
                          <TableCell>CWE ID</TableCell>
                          <TableCell>Actions</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {analysisResults.vulnerabilities.map((vuln: any) => (
                          <TableRow key={vuln.id}>
                            <TableCell>
                              <Typography variant="body2" fontWeight="medium">
                                {vuln.title}
                              </Typography>
                              <Typography variant="caption" color="textSecondary">
                                {vuln.description}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              <Chip label={vuln.category} size="small" />
                            </TableCell>
                            <TableCell>
                              <Chip
                                label={vuln.severity}
                                color={getSeverityColor(vuln.severity)}
                                size="small"
                              />
                            </TableCell>
                            <TableCell>
                              <Typography variant="body2">
                                {vuln.file_path.split('/').pop()}
                              </Typography>
                            </TableCell>
                            <TableCell>{vuln.line_number}</TableCell>
                            <TableCell>{vuln.cwe_id || '-'}</TableCell>
                            <TableCell>
                              <Button size="small">View Details</Button>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                ) : (
                  <Alert severity="info">No vulnerabilities found yet. Run an analysis to see results.</Alert>
                )}
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Analysis Configuration Modal */}
      <Dialog open={showAnalysisModal} onClose={() => setShowAnalysisModal(false)} maxWidth="md" fullWidth>
        <DialogTitle>Configure Advanced Analysis</DialogTitle>
        <DialogContent>
          <Grid container spacing={3} sx={{ mt: 1 }}>
            <Grid item xs={12}>
              <FormControl fullWidth>
                <InputLabel>Analysis Types</InputLabel>
                <Select
                  multiple
                  value={analysisTypes}
                  onChange={(e) => setAnalysisTypes(e.target.value as string[])}
                  renderValue={(selected) => (
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                      {selected.map((value) => (
                        <Chip key={value} label={value.replace(/_/g, ' ')} size="small" />
                      ))}
                    </Box>
                  )}
                >
                  <MenuItem value="data_flow">Data Flow Analysis</MenuItem>
                  <MenuItem value="taint_analysis">Taint Analysis</MenuItem>
                  <MenuItem value="security_pattern">Security Pattern Detection</MenuItem>
                  <MenuItem value="control_flow">Control Flow Analysis</MenuItem>
                  <MenuItem value="dependency_analysis">Dependency Analysis</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12}>
              <FormControl fullWidth>
                <InputLabel>Programming Languages</InputLabel>
                <Select
                  multiple
                  value={languages}
                  onChange={(e) => setLanguages(e.target.value as string[])}
                  renderValue={(selected) => (
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                      {selected.map((value) => (
                        <Chip key={value} label={value} size="small" />
                      ))}
                    </Box>
                  )}
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
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowAnalysisModal(false)}>Cancel</Button>
          <Button
            onClick={startAdvancedAnalysis}
            variant="contained"
            disabled={analysisRunning}
          >
            {analysisRunning ? 'Running...' : 'Start Analysis'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Error Display */}
      {error && (
        <Alert severity="error" sx={{ mt: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}
    </Box>
  );
};

export default AdvancedAnalysis;
