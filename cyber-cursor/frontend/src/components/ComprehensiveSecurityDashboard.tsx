import React, { useState, useEffect } from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  Button,
  Chip,
  LinearProgress,
  IconButton,
  Tooltip,
  Alert,
  CircularProgress,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemIcon
} from '@mui/material';
import {
  Security,
  BugReport,
  Code,
  Cloud,
  Computer,
  NetworkCheck,
  Person,
  Storage,
  Warning,
  TrendingUp,
  Assessment,
  Build,
  Psychology,
  AdminPanelSettings,
  People,
  History,
  BarChart,
  IntegrationInstructions,
  Refresh,
  PlayArrow,
  Stop,
  Settings,
  Visibility,
  Add
} from '@mui/icons-material';
import ComprehensiveSecurityService, {
  SecurityModule,
  DASTService,
  SASTService,
  RASPService,
  CloudSecurityService,
  EndpointSecurityService,
  NetworkSecurityService,
  IAMService,
  DataSecurityService,
  IncidentService,
  ThreatIntelligenceService,
  ComplianceService,
  DevSecOpsService,
  AIService,
  AdminService,
  UserManagementService,
  AuditService,
  ReportingService,
  IntegrationService
} from '../services/comprehensiveSecurityService';

interface DashboardStats {
  dast: { total_projects: number; active_scans: number };
  sast: { total_projects: number; vulnerabilities: number };
  incidents: { total: number; critical: number; open: number };
  threats: { total_indicators: number; high_risk: number };
  users: { total: number; active: number };
  compliance: { total_frameworks: number; compliant: number };
}

const ComprehensiveSecurityDashboard: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [modules, setModules] = useState<SecurityModule[]>([]);
  const [selectedModule, setSelectedModule] = useState<string | null>(null);

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      setError(null);

      const [statsData, platformOverview] = await Promise.all([
        ComprehensiveSecurityService.getDashboardStats(),
        ComprehensiveSecurityService.getPlatformOverview()
      ]);

      setStats(statsData);
      setModules(platformOverview.modules || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  };

  const handleModuleAction = async (module: string, action: string) => {
    try {
      switch (action) {
        case 'start':
          console.log(`Starting ${module} module`);
          break;
        case 'stop':
          console.log(`Stopping ${module} module`);
          break;
        case 'configure':
          console.log(`Configuring ${module} module`);
          break;
        default:
          console.log(`Action ${action} for ${module} module`);
      }
    } catch (err) {
      console.error(`Error performing action ${action} on ${module}:`, err);
    }
  };

  const getModuleIcon = (moduleName: string) => {
    const iconMap: { [key: string]: React.ReactElement } = {
      'DAST': <BugReport />,
      'SAST': <Code />,
      'RASP': <Security />,
      'Cloud Security': <Cloud />,
      'Endpoint Security': <Computer />,
      'Network Security': <NetworkCheck />,
      'IAM': <Person />,
      'Data Security': <Storage />,
      'Incident Management': <Warning />,
      'Threat Intelligence': <TrendingUp />,
      'Compliance': <Assessment />,
      'DevSecOps': <Build />,
      'AI/ML': <Psychology />,
      'Admin': <AdminPanelSettings />,
      'User Management': <People />,
      'Audit & Logging': <History />,
      'Reporting & Analytics': <BarChart />,
      'Integrations': <IntegrationInstructions />
    };
    return iconMap[moduleName] || <Security />;
  };

  const getModuleColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'active':
        return 'success';
      case 'warning':
        return 'warning';
      case 'error':
        return 'error';
      default:
        return 'default';
    }
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress size={60} />
      </Box>
    );
  }

  if (error) {
    return (
      <Alert severity="error" sx={{ mb: 2 }}>
        {error}
        <Button onClick={loadDashboardData} sx={{ ml: 2 }}>
          Retry
        </Button>
      </Alert>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h3" component="h1" gutterBottom>
          🛡️ Cyber Cursor Security Platform
        </Typography>
        <Typography variant="h6" color="text.secondary" gutterBottom>
          Comprehensive Security Management Dashboard
        </Typography>
        <Box sx={{ mt: 2 }}>
          <Button
            variant="contained"
            startIcon={<Refresh />}
            onClick={loadDashboardData}
            sx={{ mr: 2 }}
          >
            Refresh Dashboard
          </Button>
          <Button
            variant="outlined"
            startIcon={<Settings />}
            onClick={() => console.log('Open settings')}
          >
            Platform Settings
          </Button>
        </Box>
      </Box>

      {/* Statistics Overview */}
      {stats && (
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={2}>
            <Card>
              <CardContent>
                <Typography color="text.secondary" gutterBottom>
                  DAST Projects
                </Typography>
                <Typography variant="h4" component="div">
                  {stats.dast.total_projects}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {stats.dast.active_scans} active scans
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={2}>
            <Card>
              <CardContent>
                <Typography color="text.secondary" gutterBottom>
                  SAST Projects
                </Typography>
                <Typography variant="h4" component="div">
                  {stats.sast.total_projects}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {stats.sast.vulnerabilities} vulnerabilities
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={2}>
            <Card>
              <CardContent>
                <Typography color="text.secondary" gutterBottom>
                  Incidents
                </Typography>
                <Typography variant="h4" component="div">
                  {stats.incidents.total}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {stats.incidents.critical} critical
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={2}>
            <Card>
              <CardContent>
                <Typography color="text.secondary" gutterBottom>
                  Threat Indicators
                </Typography>
                <Typography variant="h4" component="div">
                  {stats.threats.total_indicators}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {stats.threats.high_risk} high risk
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={2}>
            <Card>
              <CardContent>
                <Typography color="text.secondary" gutterBottom>
                  Users
                </Typography>
                <Typography variant="h4" component="div">
                  {stats.users.total}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {stats.users.active} active
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={2}>
            <Card>
              <CardContent>
                <Typography color="text.secondary" gutterBottom>
                  Compliance
                </Typography>
                <Typography variant="h4" component="div">
                  {stats.compliance.total_frameworks}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {stats.compliance.compliant} compliant
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Security Modules Grid */}
      <Typography variant="h5" gutterBottom sx={{ mb: 3 }}>
        Security Modules ({modules.length})
      </Typography>
      
      <Grid container spacing={3}>
        {modules.map((module) => (
          <Grid item xs={12} sm={6} md={4} lg={3} key={module.module}>
            <Card 
              sx={{ 
                height: '100%',
                cursor: 'pointer',
                transition: 'all 0.3s ease',
                '&:hover': {
                  transform: 'translateY(-4px)',
                  boxShadow: 4
                }
              }}
              onClick={() => setSelectedModule(module.module)}
            >
              <CardContent>
                <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
                  <Box display="flex" alignItems="center">
                    {getModuleIcon(module.module)}
                    <Typography variant="h6" component="div" sx={{ ml: 1 }}>
                      {module.module}
                    </Typography>
                  </Box>
                  <Chip
                    label={module.status}
                    color={getModuleColor(module.status) as any}
                    size="small"
                  />
                </Box>
                
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  {module.description}
                </Typography>

                <Box sx={{ mb: 2 }}>
                  {module.features.slice(0, 3).map((feature, index) => (
                    <Chip
                      key={index}
                      label={feature}
                      size="small"
                      variant="outlined"
                      sx={{ mr: 0.5, mb: 0.5 }}
                    />
                  ))}
                  {module.features.length > 3 && (
                    <Chip
                      label={`+${module.features.length - 3} more`}
                      size="small"
                      variant="outlined"
                    />
                  )}
                </Box>

                <Box display="flex" justifyContent="space-between" alignItems="center">
                  <Button
                    size="small"
                    startIcon={<PlayArrow />}
                    onClick={(e) => {
                      e.stopPropagation();
                      handleModuleAction(module.module, 'start');
                    }}
                  >
                    Start
                  </Button>
                  <Button
                    size="small"
                    startIcon={<Visibility />}
                    onClick={(e) => {
                      e.stopPropagation();
                      handleModuleAction(module.module, 'view');
                    }}
                  >
                    View
                  </Button>
                  <IconButton
                    size="small"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleModuleAction(module.module, 'configure');
                    }}
                  >
                    <Settings />
                  </IconButton>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      {/* Module Details Panel */}
      {selectedModule && (
        <Box sx={{ mt: 4 }}>
          <Divider sx={{ my: 3 }} />
          <Typography variant="h6" gutterBottom>
            {selectedModule} Module Details
          </Typography>
          <Card>
            <CardContent>
              <Typography variant="body1" paragraph>
                Detailed information and controls for the {selectedModule} module will be displayed here.
              </Typography>
              <Button
                variant="outlined"
                onClick={() => setSelectedModule(null)}
              >
                Close Details
              </Button>
            </CardContent>
          </Card>
        </Box>
      )}

      {/* Quick Actions */}
      <Box sx={{ mt: 4 }}>
        <Typography variant="h6" gutterBottom>
          Quick Actions
        </Typography>
        <Grid container spacing={2}>
          <Grid item>
            <Button
              variant="contained"
              startIcon={<Add />}
              onClick={() => console.log('Create new project')}
            >
              New Project
            </Button>
          </Grid>
          <Grid item>
            <Button
              variant="outlined"
              startIcon={<Assessment />}
              onClick={() => console.log('Generate report')}
            >
              Generate Report
            </Button>
          </Grid>
          <Grid item>
            <Button
              variant="outlined"
              startIcon={<Warning />}
              onClick={() => console.log('Create incident')}
            >
              Create Incident
            </Button>
          </Grid>
          <Grid item>
            <Button
              variant="outlined"
              startIcon={<Security />}
              onClick={() => console.log('Run security scan')}
            >
              Security Scan
            </Button>
          </Grid>
        </Grid>
      </Box>
    </Box>
  );
};

export default ComprehensiveSecurityDashboard;
