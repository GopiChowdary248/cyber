import React, { useState, useEffect, useCallback } from 'react';
import { 
  Box, 
  Button, 
  Card, 
  CardContent, 
  Typography, 
  TextField, 
  Chip, 
  LinearProgress, 
  List, 
  ListItem, 
  ListItemText, 
  ListItemIcon,
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
  Accordion,
  AccordionSummary,
  AccordionDetails,
  TreeView,
  TreeItem
} from '@mui/material';
import { 
  PlayArrow, 
  Stop, 
  Refresh, 
  Language, 
  Link, 
  Code, 
  FormInput,
  ExpandMore,
  ExpandLess,
  Folder,
  InsertDriveFile,
  Web
} from '@mui/icons-material';
import { startCrawler, stopCrawler, getCrawlerStatus, getCrawlResults } from '../../../services/dastProjectToolsService';

interface CrawlResult {
  url: string;
  status_code: number;
  content_type: string;
  title: string;
  links: string[];
  forms: Array<{
    action: string;
    method: string;
    html: string;
  }>;
  javascript: string[];
  cookies: Record<string, string>;
  headers: Record<string, string>;
  body_length: number;
  crawl_time: string;
}

interface CrawlTarget {
  url: string;
  depth: number;
  parent_url?: string;
  discovered_at: string;
}

interface ScannerTabProps {
  projectId: string;
}

const DASTCrawlerTab: React.FC<ScannerTabProps> = ({ projectId }) => {
  const [crawlConfig, setCrawlConfig] = useState({
    startUrl: '',
    maxDepth: 3,
    delay: 1000,
    includePatterns: '',
    excludePatterns: '',
    allowedPorts: '80,443',
    allowedFiletypes: '.html,.php,.asp,.jsp,.js,.css'
  });
  
  const [activeCrawl, setActiveCrawl] = useState<{
    id: string;
    status: string;
    progress: number;
    started_at: string;
    total_discovered: number;
    start_url: string;
  } | null>(null);
  
  const [crawlResults, setCrawlResults] = useState<CrawlResult[]>([]);
  const [showStartDialog, setShowStartDialog] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedResult, setSelectedResult] = useState<CrawlResult | null>(null);

  const handleStartCrawl = useCallback(async () => {
    if (!crawlConfig.startUrl.trim()) {
      setError('Please enter a start URL');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const scopeConfig = {
        max_depth: crawlConfig.maxDepth,
        include_patterns: crawlConfig.includePatterns.split('\n').filter(p => p.trim()),
        exclude_patterns: crawlConfig.excludePatterns.split('\n').filter(p => p.trim()),
        allowed_ports: crawlConfig.allowedPorts.split(',').map(p => parseInt(p.trim())),
        allowed_filetypes: crawlConfig.allowedFiletypes.split(',').map(f => f.trim())
      };

      const response = await startCrawler(projectId, crawlConfig.startUrl, scopeConfig, {
        delay: crawlConfig.delay
      });

      setActiveCrawl({
        id: response.crawl_id,
        status: 'running',
        progress: 0,
        started_at: new Date().toISOString(),
        total_discovered: 0,
        start_url: crawlConfig.startUrl
      });

      setShowStartDialog(false);
      setCrawlResults([]);
      
      // Start polling for status
      pollCrawlStatus(response.crawl_id);
    } catch (err: any) {
      setError(err.message || 'Failed to start crawl');
    } finally {
      setLoading(false);
    }
  }, [projectId, crawlConfig]);

  const handleStopCrawl = useCallback(async () => {
    if (!activeCrawl) return;

    try {
      await stopCrawler(projectId, activeCrawl.id);
      setActiveCrawl(prev => prev ? { ...prev, status: 'stopped' } : null);
    } catch (err: any) {
      setError(err.message || 'Failed to stop crawl');
    }
  }, [projectId, activeCrawl]);

  const pollCrawlStatus = useCallback(async (crawlId: string) => {
    const interval = setInterval(async () => {
      try {
        const status = await getCrawlerStatus(projectId, crawlId);
        
        if (status.status === 'completed' || status.status === 'failed') {
          clearInterval(interval);
          setActiveCrawl(null);
          
          if (status.status === 'completed') {
            // Fetch crawl results
            const results = await getCrawlResults(projectId, crawlId);
            setCrawlResults(results.results || []);
          }
        } else {
          setActiveCrawl(prev => prev ? { ...prev, ...status } : null);
        }
      } catch (err) {
        console.error('Error polling crawl status:', err);
      }
    }, 3000);

    // Cleanup interval after 15 minutes
    setTimeout(() => clearInterval(interval), 900000);
  }, [projectId]);

  const formatCrawlDuration = (startedAt: string) => {
    const start = new Date(startedAt);
    const now = new Date();
    const diff = Math.floor((now.getTime() - start.getTime()) / 1000);
    
    if (diff < 60) return `${diff}s`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ${diff % 60}s`;
    return `${Math.floor(diff / 3600)}h ${Math.floor((diff % 3600) / 60)}m`;
  };

  const buildSiteMap = (results: CrawlResult[]) => {
    const urlMap = new Map<string, CrawlResult>();
    results.forEach(result => urlMap.set(result.url, result));
    
    // Group by domain
    const domains = new Map<string, CrawlResult[]>();
    results.forEach(result => {
      try {
        const domain = new URL(result.url).hostname;
        if (!domains.has(domain)) {
          domains.set(domain, []);
        }
        domains.get(domain)!.push(result);
      } catch (e) {
        // Invalid URL, skip
      }
    });

    return domains;
  };

  const renderSiteMap = (domains: Map<string, CrawlResult[]>) => {
    return Array.from(domains.entries()).map(([domain, results]) => (
      <Accordion key={domain} defaultExpanded>
        <AccordionSummary expandIcon={<ExpandMore />}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Language color="primary" />
            <Typography variant="subtitle1">{domain}</Typography>
            <Chip label={`${results.length} pages`} size="small" color="primary" variant="outlined" />
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <List dense>
            {results.map((result, index) => (
              <ListItem key={index} button onClick={() => setSelectedResult(result)}>
                <ListItemIcon>
                  <InsertDriveFile fontSize="small" />
                </ListItemIcon>
                <ListItemText
                  primary={result.title || result.url}
                  secondary={
                    <Box>
                      <Typography variant="caption" display="block">
                        {result.url}
                      </Typography>
                      <Box sx={{ display: 'flex', gap: 1, mt: 0.5 }}>
                        <Chip label={`${result.status_code}`} size="small" variant="outlined" />
                        <Chip label={`${result.links.length} links`} size="small" variant="outlined" />
                        <Chip label={`${result.forms.length} forms`} size="small" variant="outlined" />
                        <Chip label={`${result.javascript.length} JS`} size="small" variant="outlined" />
                      </Box>
                    </Box>
                  }
                />
              </ListItem>
            ))}
          </List>
        </AccordionDetails>
      </Accordion>
    ));
  };

  return (
    <Box sx={{ p: 2 }}>
      <Typography variant="h5" gutterBottom>
        <Language sx={{ mr: 1, verticalAlign: 'middle' }} />
        Web Crawler
      </Typography>

      {/* Crawl Configuration */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Crawl Configuration
          </Typography>
          
          <Grid container spacing={2}>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Start URL"
                placeholder="https://example.com"
                value={crawlConfig.startUrl}
                onChange={(e) => setCrawlConfig(prev => ({ ...prev, startUrl: e.target.value }))}
                helperText="Enter the starting URL for the crawl"
              />
            </Grid>
            
            <Grid item xs={12} md={4}>
              <TextField
                fullWidth
                type="number"
                label="Max Depth"
                value={crawlConfig.maxDepth}
                onChange={(e) => setCrawlConfig(prev => ({ ...prev, maxDepth: parseInt(e.target.value) || 3 }))}
                inputProps={{ min: 1, max: 10 }}
                helperText="Maximum crawl depth"
              />
            </Grid>
            
            <Grid item xs={12} md={4}>
              <TextField
                fullWidth
                type="number"
                label="Delay (ms)"
                value={crawlConfig.delay}
                onChange={(e) => setCrawlConfig(prev => ({ ...prev, delay: parseInt(e.target.value) || 1000 }))}
                inputProps={{ min: 100, max: 5000 }}
                helperText="Delay between requests"
              />
            </Grid>
            
            <Grid item xs={12} md={4}>
              <TextField
                fullWidth
                label="Allowed Ports"
                value={crawlConfig.allowedPorts}
                onChange={(e) => setCrawlConfig(prev => ({ ...prev, allowedPorts: e.target.value }))}
                helperText="Comma-separated port numbers"
              />
            </Grid>
            
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                multiline
                rows={2}
                label="Include Patterns (regex)"
                placeholder=".*admin.*
.*api.*"
                value={crawlConfig.includePatterns}
                onChange={(e) => setCrawlConfig(prev => ({ ...prev, includePatterns: e.target.value }))}
                helperText="URLs must match these patterns (one per line)"
              />
            </Grid>
            
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                multiline
                rows={2}
                label="Exclude Patterns (regex)"
                placeholder=".*logout.*
.*\.pdf$"
                value={crawlConfig.excludePatterns}
                onChange={(e) => setCrawlConfig(prev => ({ ...prev, excludePatterns: e.target.value }))}
                helperText="URLs matching these patterns will be skipped"
              />
            </Grid>
            
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Allowed File Types"
                value={crawlConfig.allowedFiletypes}
                onChange={(e) => setCrawlConfig(prev => ({ ...prev, allowedFiletypes: e.target.value }))}
                helperText="Comma-separated file extensions"
              />
            </Grid>
          </Grid>
          
          <Box sx={{ mt: 2 }}>
            <Button
              variant="contained"
              color="primary"
              startIcon={<PlayArrow />}
              onClick={() => setShowStartDialog(true)}
              disabled={loading || !crawlConfig.startUrl.trim()}
            >
              Start Crawl
            </Button>
          </Box>
        </CardContent>
      </Card>

      {/* Active Crawl Status */}
      {activeCrawl && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="h6">
                Active Crawl: {activeCrawl.id.slice(-8)}
              </Typography>
              <Box>
                <Chip 
                  label={activeCrawl.status.toUpperCase()} 
                  color={activeCrawl.status === 'running' ? 'success' : 'warning'}
                  sx={{ mr: 1 }}
                />
                <Button
                  variant="outlined"
                  color="error"
                  startIcon={<Stop />}
                  onClick={handleStopCrawl}
                  size="small"
                >
                  Stop
                </Button>
              </Box>
            </Box>
            
            <Box sx={{ mb: 2 }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                <Typography variant="body2">Progress</Typography>
                <Typography variant="body2">{activeCrawl.progress}%</Typography>
              </Box>
              <LinearProgress 
                variant="determinate" 
                value={activeCrawl.progress} 
                sx={{ height: 8, borderRadius: 4 }}
              />
            </Box>
            
            <Grid container spacing={2}>
              <Grid item xs={12} md={3}>
                <Typography variant="body2" color="text.secondary">
                  Started: {formatCrawlDuration(activeCrawl.started_at)}
                </Typography>
              </Grid>
              <Grid item xs={12} md={3}>
                <Typography variant="body2" color="text.secondary">
                  Start URL: {activeCrawl.start_url}
                </Typography>
              </Grid>
              <Grid item xs={12} md={3}>
                <Typography variant="body2" color="text.secondary">
                  Discovered: {activeCrawl.total_discovered}
                </Typography>
              </Grid>
              <Grid item xs={12} md={3}>
                <Typography variant="body2" color="text.secondary">
                  Status: {activeCrawl.status}
                </Typography>
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      )}

      {/* Crawl Results - Site Map */}
      {crawlResults.length > 0 && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Site Map ({crawlResults.length} pages discovered)
            </Typography>
            
            {renderSiteMap(buildSiteMap(crawlResults))}
          </CardContent>
        </Card>
      )}

      {/* Error Display */}
      {error && (
        <Alert severity="error" sx={{ mt: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Start Crawl Dialog */}
      <Dialog open={showStartDialog} onClose={() => setShowStartDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Start Web Crawl</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Are you sure you want to start crawling? This will discover and analyze web pages starting from the specified URL.
          </Typography>
          
          <Box sx={{ mb: 2 }}>
            <Typography variant="subtitle2" gutterBottom>Start URL:</Typography>
            <Typography variant="body2" fontFamily="monospace" sx={{ bgcolor: 'grey.50', p: 1, borderRadius: 1 }}>
              {crawlConfig.startUrl}
            </Typography>
          </Box>
          
          <Box sx={{ mb: 2 }}>
            <Typography variant="subtitle2" gutterBottom>Crawl Settings:</Typography>
            <Grid container spacing={1}>
              <Grid item xs={6}>
                <Typography variant="caption">Max Depth: {crawlConfig.maxDepth}</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="caption">Delay: {crawlConfig.delay}ms</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="caption">Ports: {crawlConfig.allowedPorts}</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="caption">File Types: {crawlConfig.allowedFiletypes}</Typography>
              </Grid>
            </Grid>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowStartDialog(false)}>Cancel</Button>
          <Button 
            onClick={handleStartCrawl} 
            variant="contained" 
            color="primary"
            disabled={loading}
          >
            {loading ? 'Starting...' : 'Start Crawl'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Crawl Result Detail Dialog */}
      <Dialog 
        open={!!selectedResult} 
        onClose={() => setSelectedResult(null)} 
        maxWidth="md" 
        fullWidth
      >
        {selectedResult && (
          <>
            <DialogTitle>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Web />
                {selectedResult.title || selectedResult.url}
              </Box>
            </DialogTitle>
            <DialogContent>
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom>URL:</Typography>
                  <Typography variant="body2" fontFamily="monospace" sx={{ bgcolor: 'grey.50', p: 1, borderRadius: 1 }}>
                    {selectedResult.url}
                  </Typography>
                </Grid>
                
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>Status:</Typography>
                  <Chip label={selectedResult.status_code} color="primary" variant="outlined" />
                </Grid>
                
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>Content Type:</Typography>
                  <Typography variant="body2">{selectedResult.content_type}</Typography>
                </Grid>
                
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>Body Length:</Typography>
                  <Typography variant="body2">{selectedResult.body_length} bytes</Typography>
                </Grid>
                
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>Crawl Time:</Typography>
                  <Typography variant="body2">
                    {new Date(selectedResult.crawl_time).toLocaleString()}
                  </Typography>
                </Grid>
                
                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom>Links ({selectedResult.links.length}):</Typography>
                  <Box sx={{ maxHeight: 100, overflow: 'auto', bgcolor: 'grey.50', p: 1, borderRadius: 1 }}>
                    {selectedResult.links.map((link, index) => (
                      <Typography key={index} variant="body2" fontFamily="monospace" fontSize="small">
                        {link}
                      </Typography>
                    ))}
                  </Box>
                </Grid>
                
                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom>Forms ({selectedResult.forms.length}):</Typography>
                  {selectedResult.forms.map((form, index) => (
                    <Box key={index} sx={{ mb: 1, p: 1, bgcolor: 'grey.50', borderRadius: 1 }}>
                      <Typography variant="caption" display="block">
                        <strong>Action:</strong> {form.action}
                      </Typography>
                      <Typography variant="caption" display="block">
                        <strong>Method:</strong> {form.method}
                      </Typography>
                    </Box>
                  ))}
                </Grid>
                
                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom>JavaScript ({selectedResult.javascript.length}):</Typography>
                  <Box sx={{ maxHeight: 100, overflow: 'auto', bgcolor: 'grey.50', p: 1, borderRadius: 1 }}>
                    {selectedResult.javascript.map((js, index) => (
                      <Typography key={index} variant="body2" fontFamily="monospace" fontSize="small">
                        {js}
                      </Typography>
                    ))}
                  </Box>
                </Grid>
              </Grid>
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setSelectedResult(null)}>Close</Button>
            </DialogActions>
          </>
        )}
      </Dialog>
    </Box>
  );
};

export default DASTCrawlerTab;
