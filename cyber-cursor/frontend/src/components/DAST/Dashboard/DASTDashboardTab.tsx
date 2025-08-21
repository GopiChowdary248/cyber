import React, { useState, useEffect, useCallback } from 'react';
import { 
  Box, 
  Card, 
  CardContent, 
  Typography, 
  Grid, 
  Chip, 
  LinearProgress, 
  List, 
  ListItem, 
  ListItemText, 
  ListItemIcon,
  Button,
  Alert,
  CircularProgress,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper
} from '@mui/material';
import { 
  Dashboard, 
  Security, 
  BugReport, 
  Warning, 
  Info,
  Error,
  CheckCircle,
  ExpandMore,
  ExpandLess,
  Refresh,
  PlayArrow,
  Stop,
  Language,
  Http
} from '@mui/icons-material';
import { 
  dastProjectToolsService,
  getAllScannerIssues,
  getAllCrawlerResults
} from '../../../services/dastProjectToolsService';

interface DashboardActivity {
  type: string;
  title: string;
  description: string;
  timestamp: string;
  severity?: string;
  status?: string;
}

interface DashboardIssue {
  id: string;
  title: string;
  severity: string;
  confidence: string;
  url: string;
  method: string;
  created_at: string;
}

interface DashboardEvent {
  id: string;
  event_type: string;
  description: string;
  timestamp: string;
  metadata?: any;
}

interface DashboardProps {
  projectId: string;
}

const DASTDashboardTab: React.FC<DashboardProps> = ({ projectId }) => {
  const [activities, setActivities] = useState<DashboardActivity[]>([]);
  const [issues, setIssues] = useState<DashboardIssue[]>([]);
  const [events, setEvents] = useState<DashboardEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState({
    totalIssues: 0,
    criticalIssues: 0,
    highIssues: 0,
    mediumIssues: 0,
    lowIssues: 0,
    totalScans: 0,
    activeScans: 0,
    totalCrawls: 0,
    activeCrawls: 0
  });

  const loadDashboardData = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      // Load dashboard data from backend
      const [activityData, issuesData, eventsData] = await Promise.all([
        dastProjectToolsService.getDashboardActivity(projectId),
        dastProjectToolsService.getDashboardIssues(projectId),
        dastProjectToolsService.getDashboardEvents(projectId, { limit: 50 })
      ]);

      setActivities(activityData?.activities || []);
      setIssues(issuesData?.issues || []);
      setEvents(eventsData?.events || []);

      // Calculate statistics
      const totalIssues = issuesData?.issues?.length || 0;
      const criticalIssues = issuesData?.issues?.filter((i: any) => i.severity === 'critical').length || 0;
      const highIssues = issuesData?.issues?.filter((i: any) => i.severity === 'high').length || 0;
      const mediumIssues = issuesData?.issues?.filter((i: any) => i.severity === 'medium').length || 0;
      const lowIssues = issuesData?.issues?.filter((i: any) => i.severity === 'low').length || 0;

      setStats({
        totalIssues,
        criticalIssues,
        highIssues,
        mediumIssues,
        lowIssues,
        totalScans: 0, // Will be updated when scanner integration is complete
        activeScans: 0,
        totalCrawls: 0, // Will be updated when crawler integration is complete
        activeCrawls: 0
      });

    } catch (err: any) {
      setError(err.message || 'Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  }, [projectId]);

  useEffect(() => {
    loadDashboardData();
  }, [loadDashboardData]);

  const getSeverityIcon = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return <Error color="error" />;
      case 'high':
        return <Error color="error" />;
      case 'medium':
        return <Warning color="warning" />;
      case 'low':
        return <Info color="info" />;
      default:
        return <Info color="info" />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'error';
      case 'high':
        return 'error';
      case 'medium':
        return 'warning';
      case 'low':
        return 'info';
      default:
        return 'default';
    }
  };

  const getEventIcon = (eventType: string) => {
    switch (eventType.toLowerCase()) {
      case 'scan_started':
        return <PlayArrow color="primary" />;
      case 'scan_completed':
        return <CheckCircle color="success" />;
      case 'scan_failed':
        return <Error color="error" />;
      case 'crawl_started':
        return <Language color="primary" />;
      case 'crawl_completed':
        return <CheckCircle color="success" />;
      case 'vulnerability_found':
        return <BugReport color="error" />;
      default:
        return <Info color="info" />;
    }
  };

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = Math.floor((now.getTime() - date.getTime()) / 1000);
    
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return date.toLocaleDateString();
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: 400 }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ p: 2 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h5">
          <Dashboard sx={{ mr: 1, verticalAlign: 'middle' }} />
          Dashboard
        </Typography>
        <Button
          variant="outlined"
          startIcon={<Refresh />}
          onClick={loadDashboardData}
          size="small"
        >
          Refresh
        </Button>
      </Box>

      {/* Statistics Cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <BugReport color="error" />
                <Typography variant="h6" color="error">
                  {stats.criticalIssues}
                </Typography>
              </Box>
              <Typography variant="body2" color="text.secondary">
                Critical Issues
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <Warning color="warning" />
                <Typography variant="h6" color="warning.main">
                  {stats.highIssues}
                </Typography>
              </Box>
              <Typography variant="body2" color="text.secondary">
                High Issues
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <Security color="primary" />
                <Typography variant="h6" color="primary">
                  {stats.totalScans}
                </Typography>
              </Box>
              <Typography variant="body2" color="text.secondary">
                Total Scans
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <Language color="primary" />
                <Typography variant="h6" color="primary">
                  {stats.totalCrawls}
                </Typography>
              </Box>
              <Typography variant="body2" color="text.secondary">
                Total Crawls
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Recent Issues */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            <BugReport sx={{ mr: 1, verticalAlign: 'middle' }} />
            Recent Issues
          </Typography>
          
          {issues.length > 0 ? (
            <TableContainer component={Paper} variant="outlined">
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Severity</TableCell>
                    <TableCell>Title</TableCell>
                    <TableCell>URL</TableCell>
                    <TableCell>Method</TableCell>
                    <TableCell>Confidence</TableCell>
                    <TableCell>Found</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {issues.slice(0, 10).map((issue) => (
                    <TableRow key={issue.id}>
                      <TableCell>
                        <Chip
                          icon={getSeverityIcon(issue.severity)}
                          label={issue.severity.toUpperCase()}
                          color={getSeverityColor(issue.severity) as any}
                          size="small"
                        />
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" fontWeight="medium">
                          {issue.title}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" fontFamily="monospace" fontSize="small">
                          {issue.url.length > 50 ? `${issue.url.substring(0, 50)}...` : issue.url}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip label={issue.method} size="small" variant="outlined" />
                      </TableCell>
                      <TableCell>
                        <Chip 
                          label={issue.confidence.toUpperCase()} 
                          size="small" 
                          variant="outlined"
                          color={issue.confidence === 'high' ? 'error' : 'default'}
                        />
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" color="text.secondary">
                          {formatTimestamp(issue.created_at)}
                        </Typography>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          ) : (
            <Box sx={{ textAlign: 'center', py: 3 }}>
              <Typography variant="body1" color="text.secondary">
                No issues found yet.
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                Run a vulnerability scan to discover security issues.
              </Typography>
            </Box>
          )}
        </CardContent>
      </Card>

      {/* Recent Events */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            <Info sx={{ mr: 1, verticalAlign: 'middle' }} />
            Recent Events
          </Typography>
          
          {events.length > 0 ? (
            <List>
              {events.slice(0, 10).map((event) => (
                <ListItem key={event.id} divider>
                  <ListItemIcon>
                    {getEventIcon(event.event_type)}
                  </ListItemIcon>
                  <ListItemText
                    primary={event.description}
                    secondary={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 0.5 }}>
                        <Chip 
                          label={event.event_type.replace('_', ' ').toUpperCase()} 
                          size="small" 
                          variant="outlined"
                        />
                        <Typography variant="caption" color="text.secondary">
                          {formatTimestamp(event.timestamp)}
                        </Typography>
                      </Box>
                    }
                  />
                </ListItem>
              ))}
            </List>
          ) : (
            <Box sx={{ textAlign: 'center', py: 3 }}>
              <Typography variant="body1" color="text.secondary">
                No recent events.
              </Typography>
            </Box>
          )}
        </CardContent>
      </Card>

      {/* Recent Activities */}
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            <Http sx={{ mr: 1, verticalAlign: 'middle' }} />
            Recent Activities
          </Typography>
          
          {activities.length > 0 ? (
            <List>
              {activities.slice(0, 10).map((activity, index) => (
                <ListItem key={index} divider>
                  <ListItemIcon>
                    {getEventIcon(activity.type)}
                  </ListItemIcon>
                  <ListItemText
                    primary={activity.title}
                    secondary={
                      <Box sx={{ mt: 0.5 }}>
                        <Typography variant="body2" color="text.secondary">
                          {activity.description}
                        </Typography>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 0.5 }}>
                          {activity.severity && (
                            <Chip 
                              label={activity.severity.toUpperCase()} 
                              size="small" 
                              color={getSeverityColor(activity.severity) as any}
                            />
                          )}
                          {activity.status && (
                            <Chip 
                              label={activity.status.toUpperCase()} 
                              size="small" 
                              variant="outlined"
                            />
                          )}
                          <Typography variant="caption" color="text.secondary">
                            {formatTimestamp(activity.timestamp)}
                          </Typography>
                        </Box>
                      </Box>
                    }
                  />
                </ListItem>
              ))}
            </List>
          ) : (
            <Box sx={{ textAlign: 'center', py: 3 }}>
              <Typography variant="body1" color="text.secondary">
                No recent activities.
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                Start scanning or crawling to see activity here.
              </Typography>
            </Box>
          )}
        </CardContent>
      </Card>

      {/* Error Display */}
      {error && (
        <Alert severity="error" sx={{ mt: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}
    </Box>
  );
};

export default DASTDashboardTab;
