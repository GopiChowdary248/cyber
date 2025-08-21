import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  PlusIcon,
  MagnifyingGlassIcon,
  EyeIcon,
  DocumentDuplicateIcon,
  TrashIcon,
  PlayIcon,
  ClockIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  ArrowPathIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  TargetIcon,
  ChartBarIcon,
  CogIcon
} from '@heroicons/react/24/outline';
import { useAuth } from '../../contexts/AuthContext';
import { useNavigate } from 'react-router-dom';
import QualityImprovementDashboard from '../../components/SAST/QualityImprovementDashboard';
import { useKeyboardShortcuts } from '../../hooks/useKeyboardShortcuts';
import EnhancedCodeBrowser from '../../components/SAST/EnhancedCodeBrowser';

interface SASTProject {
  id: number;
  name: string;
  key: string;
  language: string;
  repositoryUrl?: string;
  branch: string;
  linesOfCode?: number;
  lastScan?: {
    id: number;
    status: 'COMPLETED' | 'RUNNING' | 'FAILED' | 'PENDING';
    timestamp: string;
    duration?: string;
  };
  issues: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  // Additional Sonar-like counters
  bugCount: number;
  vulnerabilityCount: number;
  codeSmellCount: number;
  securityHotspotCount: number;
  coverage: number;
  duplicationPercent: number;
  // New Code metrics
  newCodeCoverage?: number;
  newBugs?: number;
  newVulnerabilities?: number;
  newCodeSmells?: number;
  newHotspots?: number;
  // Ratings
  maintainabilityRating?: 'A' | 'B' | 'C' | 'D' | 'E';
  securityRating?: 'A' | 'B' | 'C' | 'D' | 'E';
  reliabilityRating?: 'A' | 'B' | 'C' | 'D' | 'E';
  qualityGate: 'PASSED' | 'FAILED' | 'WARNING' | 'NONE';
  // Metadata (optional)
  favorite?: boolean;
  visibility?: 'public' | 'private';
  tags?: string[];
  createdBy: string;
  createdAt: string;
}

interface CreateProjectData {
  name: string;
  key: string;
  language: string;
  repository_url?: string;
  branch?: string;
}

interface DuplicateProjectData {
  name: string;
  key: string;
}

const SASTProjects: React.FC = () => {
  const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
  const navigate = useNavigate();
  const [projects, setProjects] = useState<SASTProject[]>([]);
  const [loading, setLoading] = useState(true);
  const [viewMode, setViewMode] = useState<'list' | 'cards'>('cards');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedLanguage, setSelectedLanguage] = useState<string>('all');
  const [selectedStatus, setSelectedStatus] = useState<string>('all');
  const [selectedQualityGate, setSelectedQualityGate] = useState<string>('all');
  const [selectedReliability, setSelectedReliability] = useState<string>('all');
  const [selectedSecurity, setSelectedSecurity] = useState<string>('all');
  const [selectedMaintainability, setSelectedMaintainability] = useState<string>('all');
  const [minCoverage, setMinCoverage] = useState<string>('');
  const [maxDuplication, setMaxDuplication] = useState<string>('');
  const [minHotspots, setMinHotspots] = useState<string>('');
  const [sortBy, setSortBy] = useState<string>('');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage, setItemsPerPage] = useState<number>(12);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showDuplicateModal, setShowDuplicateModal] = useState(false);
  const [selectedProject, setSelectedProject] = useState<SASTProject | null>(null);
  const [activeSubTab, setActiveSubTab] = useState<'projects' | 'quality' | 'coverage' | 'technical-debt'>('projects');
  const [createFormData, setCreateFormData] = useState<CreateProjectData>({
    name: '',
    key: '',
    language: '',
    repository_url: '',
    branch: 'main'
  });
  const [duplicateFormData, setDuplicateFormData] = useState<DuplicateProjectData>({
    name: '',
    key: ''
  });
  const [totalProjects, setTotalProjects] = useState(0);
  const [totalPages, setTotalPages] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [updatingProjectId, setUpdatingProjectId] = useState<number | null>(null);
  const [newTagByProject, setNewTagByProject] = useState<Record<number, string>>({});
  // New filters/scopes
  const [selectedVisibility, setSelectedVisibility] = useState<'all' | 'public' | 'private'>('all');
  const [favoriteOnly, setFavoriteOnly] = useState<boolean>(false);
  const [selectedTags, setSelectedTags] = useState<string>(''); // comma-separated
  const [selectedBranch, setSelectedBranch] = useState<string>('all');
  const [myProjectsOnly, setMyProjectsOnly] = useState<boolean>(false);
  const [dateFrom, setDateFrom] = useState<string>('');
  const [dateTo, setDateTo] = useState<string>('');
  // New Code (leak period)
  const [newCodeMode, setNewCodeMode] = useState<'none' | 'prev-version' | 'days' | 'since-date'>('none');
  const [newCodeDays, setNewCodeDays] = useState<number>(30);
  const [newCodeSince, setNewCodeSince] = useState<string>('');
  const [showNewCodeMetrics, setShowNewCodeMetrics] = useState<boolean>(false);
  // Filtering breadth
  const [selectedLanguages, setSelectedLanguages] = useState<string[]>([]);
  const [owner, setOwner] = useState<string>('');
  const [team, setTeam] = useState<string>('');
  const [permission, setPermission] = useState<'all' | 'admin' | 'browse' | 'execute'>('all');
  const [almProvider, setAlmProvider] = useState<'all' | 'github' | 'gitlab' | 'azure' | 'bitbucket' | 'bound' | 'unbound'>('all');
  const [minLoc, setMinLoc] = useState<string>('');
  const [maxLoc, setMaxLoc] = useState<string>('');
  const [tagsMode, setTagsMode] = useState<'any' | 'all'>('any');
  const [excludeTags, setExcludeTags] = useState<boolean>(false);
  // Bulk selection
  const [selectedProjectIds, setSelectedProjectIds] = useState<Set<number>>(new Set());
  // Saved views
  type SavedView = { name: string; state: any };
  const [savedViews, setSavedViews] = useState<SavedView[]>([]);
  const [selectedView, setSelectedView] = useState<string>('');

  // Keyboard shortcuts for projects page
  const shortcuts = useKeyboardShortcuts([
    {
      key: 'n',
      description: 'New Project',
      action: () => setShowCreateModal(true)
    },
    {
      key: 's',
      description: 'Search Projects',
      action: () => {
        const searchInput = document.getElementById('project-search-input');
        searchInput?.focus();
      }
    },
    {
      key: 'f',
      description: 'Toggle Favorites',
      action: () => setFavoriteOnly(!favoriteOnly)
    },
    {
      key: 'c',
      description: 'Cards View',
      action: () => setViewMode('cards')
    },
    {
      key: 'l',
      description: 'List View',
      action: () => setViewMode('list')
    },
    {
      key: 'Escape',
      description: 'Clear Search',
      action: () => setSearchTerm('')
    }
  ]);

  const fetchProjects = async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams({
        skip: ((currentPage - 1) * itemsPerPage).toString(),
        limit: itemsPerPage.toString()
      });

      if (searchTerm) params.append('search', searchTerm);
      if (selectedLanguage !== 'all') params.append('language', selectedLanguage);
      if (selectedLanguages.length && !selectedLanguages.includes('all')) params.append('languages', selectedLanguages.join(','));
      if (selectedStatus !== 'all') params.append('status_filter', selectedStatus);
      if (selectedQualityGate !== 'all') params.append('quality_gate', selectedQualityGate);
      if (selectedReliability !== 'all') params.append('reliability_rating', selectedReliability);
      if (selectedSecurity !== 'all') params.append('security_rating', selectedSecurity);
      if (selectedMaintainability !== 'all') params.append('maintainability_rating', selectedMaintainability);
      if (minCoverage) params.append('min_coverage', minCoverage);
      if (maxDuplication) params.append('max_duplication_percent', maxDuplication);
      if (minHotspots) params.append('min_hotspots', minHotspots);
      if (selectedVisibility !== 'all') params.append('visibility', selectedVisibility);
      if (favoriteOnly) params.append('favorite', 'true');
      if (selectedTags.trim()) params.append('tags', selectedTags.trim());
      if (tagsMode) params.append('tags_mode', tagsMode);
      if (excludeTags) params.append('exclude_tags', 'true');
      if (selectedBranch !== 'all') params.append('branch', selectedBranch);
      if (owner) params.append('owner', owner);
      if (team) params.append('team', team);
      if (permission !== 'all') params.append('permission', permission);
      if (almProvider !== 'all') params.append('alm_provider', almProvider);
      if (minLoc) params.append('min_loc', minLoc);
      if (maxLoc) params.append('max_loc', maxLoc);
      if (myProjectsOnly) params.append('owner_scope', 'me');
      if (newCodeMode !== 'none') {
        params.append('new_code_mode', newCodeMode);
        if (newCodeMode === 'days') params.append('new_code_days', String(newCodeDays));
        if (newCodeMode === 'since-date' && newCodeSince) params.append('new_code_since', newCodeSince);
        if (showNewCodeMetrics) params.append('include_new_code', 'true');
      }
      if (dateFrom) params.append('last_analyzed_from', dateFrom);
      if (dateTo) params.append('last_analyzed_to', dateTo);
      if (sortBy) {
        params.append('sort_by', sortBy);
        params.append('sort_order', sortOrder);
      }

      const response = await fetch(`${API_URL}/api/v1/sast/projects?${params}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      
      // Transform API response to match our interface
      const transformedProjects: SASTProject[] = data.projects.map((project: any) => ({
        id: project.id,
        name: project.name,
        key: project.key,
        language: project.language,
        repositoryUrl: project.repository_url,
        branch: project.branch,
        lastScan: project.last_scan ? {
          id: project.last_scan.id,
          status: project.last_scan.status,
          timestamp: project.last_scan.started_at,
          duration: project.last_scan.duration
        } : undefined,
        issues: project.issues || { critical: 0, high: 0, medium: 0, low: 0 },
        bugCount: project.bug_count || 0,
        vulnerabilityCount: project.vulnerability_count || 0,
        codeSmellCount: project.code_smell_count || 0,
        securityHotspotCount: project.security_hotspot_count || 0,
        coverage: project.coverage || 0,
        duplicationPercent: project.duplication_percent || 0,
        maintainabilityRating: project.maintainability_rating,
        securityRating: project.security_rating,
        reliabilityRating: project.reliability_rating,
        qualityGate: project.quality_gate || 'NONE',
        createdBy: project.created_by,
        createdAt: project.created_at
      }));

      setProjects(transformedProjects);
      setTotalProjects(data.total);
      setTotalPages(data.pages);
      setError(null);
      // Fetch metadata (favorite/visibility/tags) for visible projects in parallel
      try {
        const metaResponses = await Promise.all(
          transformedProjects.map(async (p) => {
            try {
              const r = await fetch(`${API_URL}/api/v1/sast/projects/${p.id}/metadata`, {
                headers: {
                  'Authorization': `Bearer ${localStorage.getItem('access_token')}`
                }
              });
              if (!r.ok) return null;
              const m = await r.json();
              return { id: p.id, meta: m } as { id: number; meta: any };
            } catch {
              return null;
            }
          })
        );
        const metaById: Record<number, any> = {};
        metaResponses.forEach((item) => {
          if (item && item.meta) metaById[item.id] = item.meta;
        });
        if (Object.keys(metaById).length) {
          setProjects((prev) => prev.map((p) => ({
            ...p,
            favorite: metaById[p.id]?.favorite ?? p.favorite,
            visibility: metaById[p.id]?.visibility ?? p.visibility,
            tags: metaById[p.id]?.tags ?? p.tags
          })));
        }
      } catch {
        // ignore metadata fetch errors
      }
    } catch (error) {
      console.error('Error fetching SAST projects:', error);
      setError('Failed to fetch projects');
      // Fallback to mock data for demo
      const mockProjects: SASTProject[] = [
        {
          id: 1,
          name: 'Web Application Security',
          key: 'web-app-sec',
          language: 'JavaScript',
          repositoryUrl: 'https://github.com/example/web-app',
          branch: 'main',
          lastScan: {
            id: 101,
            status: 'COMPLETED',
            timestamp: '2024-01-15T10:30:00Z',
            duration: '2m 34s'
          },
          issues: { critical: 2, high: 5, medium: 12, low: 8 },
          qualityGate: 'PASSED',
          createdBy: 'admin@example.com',
          createdAt: '2024-01-10T09:00:00Z'
        },
        {
          id: 2,
          name: 'API Security Testing',
          key: 'api-sec',
          language: 'Python',
          repositoryUrl: 'https://github.com/example/api',
          branch: 'develop',
          lastScan: {
            id: 102,
            status: 'COMPLETED',
            timestamp: '2024-01-14T15:45:00Z',
            duration: '1m 52s'
          },
          issues: { critical: 0, high: 3, medium: 7, low: 4 },
          qualityGate: 'PASSED',
          createdBy: 'admin@example.com',
          createdAt: '2024-01-08T14:30:00Z'
        },
        {
          id: 3,
          name: 'Mobile App Security',
          key: 'mobile-sec',
          language: 'React Native',
          repositoryUrl: 'https://github.com/example/mobile',
          branch: 'main',
          lastScan: {
            id: 103,
            status: 'RUNNING',
            timestamp: '2024-01-15T11:00:00Z'
          },
          issues: { critical: 1, high: 2, medium: 5, low: 3 },
          qualityGate: 'WARNING',
          createdBy: 'admin@example.com',
          createdAt: '2024-01-12T16:20:00Z'
        }
      ];
      setProjects(mockProjects);
      setTotalProjects(3);
      setTotalPages(1);
    } finally {
      setLoading(false);
    }
  };

  const applyDatePreset = (days: number) => {
    const to = new Date();
    const from = new Date();
    from.setDate(to.getDate() - days);
    setDateTo(to.toISOString().slice(0, 10));
    setDateFrom(from.toISOString().slice(0, 10));
  };

  const exportProjectsAsCSV = () => {
    const headers = [
      'id',
      'name',
      'key',
      'language',
      'branch',
      'qualityGate',
      'bugs',
      'vulnerabilities',
      'codeSmells',
      'hotspots',
      'coverage',
      'duplicationPercent',
      'visibility',
      'favorite',
      'tags',
      'lastScanStatus',
      'lastScanAt'
    ];
    const rows = projects.map((p) => [
      p.id,
      `"${(p.name || '').replace(/"/g, '""')}"`,
      p.key,
      p.language,
      p.branch,
      p.qualityGate,
      p.bugCount ?? '',
      p.vulnerabilityCount ?? '',
      p.codeSmellCount ?? '',
      p.securityHotspotCount ?? '',
      p.coverage ?? '',
      p.duplicationPercent ?? '',
      p.visibility ?? '',
      p.favorite ? 'true' : 'false',
      (p.tags || []).join('|'),
      p.lastScan?.status ?? '',
      p.lastScan?.timestamp ?? ''
    ]);
    const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', 'sast-projects.csv');
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const toggleFavorite = async (projectId: number, favorite: boolean) => {
    try {
      setUpdatingProjectId(projectId);
      const resp = await fetch(`${API_URL}/api/v1/sast/projects/${projectId}/favorite`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ favorite })
      });
      if (!resp.ok) throw new Error('Failed to update favorite');
      setProjects(prev => prev.map(p => p.id === projectId ? { ...p, favorite } : p));
    } catch (e) {
      console.error(e);
      setError('Failed to update favorite');
    } finally {
      setUpdatingProjectId(null);
    }
  };

  const updateVisibility = async (projectId: number, visibility: 'public' | 'private') => {
    try {
      setUpdatingProjectId(projectId);
      const resp = await fetch(`${API_URL}/api/v1/sast/projects/${projectId}/metadata`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ visibility })
      });
      if (!resp.ok) throw new Error('Failed to update visibility');
      setProjects(prev => prev.map(p => p.id === projectId ? { ...p, visibility } : p));
    } catch (e) {
      console.error(e);
      setError('Failed to update visibility');
    } finally {
      setUpdatingProjectId(null);
    }
  };

  const updateTags = async (projectId: number, tags: string[]) => {
    try {
      setUpdatingProjectId(projectId);
      const resp = await fetch(`${API_URL}/api/v1/sast/projects/${projectId}/metadata`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ tags })
      });
      if (!resp.ok) throw new Error('Failed to update tags');
      setProjects(prev => prev.map(p => p.id === projectId ? { ...p, tags } : p));
    } catch (e) {
      console.error(e);
      setError('Failed to update tags');
    } finally {
      setUpdatingProjectId(null);
    }
  };

  const addTag = (projectId: number) => {
    const value = (newTagByProject[projectId] || '').trim();
    if (!value) return;
    const current = projects.find(p => p.id === projectId)?.tags || [];
    if (current.includes(value)) return;
    updateTags(projectId, [...current, value]);
    setNewTagByProject(prev => ({ ...prev, [projectId]: '' }));
  };

  const removeTag = (projectId: number, tag: string) => {
    const current = projects.find(p => p.id === projectId)?.tags || [];
    updateTags(projectId, current.filter(t => t !== tag));
  };

  useEffect(() => {
    fetchProjects();
  }, [currentPage, searchTerm, selectedLanguage, selectedLanguages, selectedStatus, selectedQualityGate, selectedReliability, selectedSecurity, selectedMaintainability, minCoverage, maxDuplication, minHotspots, sortBy, sortOrder, selectedVisibility, favoriteOnly, selectedTags, tagsMode, excludeTags, selectedBranch, owner, team, permission, almProvider, minLoc, maxLoc, myProjectsOnly, newCodeMode, newCodeDays, newCodeSince, showNewCodeMetrics, dateFrom, dateTo, itemsPerPage]);

  const handleCreateProject = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const response = await fetch(`${API_URL}/api/v1/sast/projects`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(createFormData)
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to create project');
      }

      const newProject = await response.json();
      setProjects(prev => [newProject, ...prev]);
      setShowCreateModal(false);
      setCreateFormData({ name: '', key: '', language: '', repository_url: '', branch: 'main' });
      setError(null);
    } catch (error) {
      console.error('Error creating project:', error);
      setError(error instanceof Error ? error.message : 'Failed to create project');
    }
  };

  const handleDuplicateProject = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedProject) return;

    try {
      const response = await fetch(`${API_URL}/api/v1/sast/projects/${selectedProject.id}/duplicate`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(duplicateFormData)
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to duplicate project');
      }

      const duplicatedProject = await response.json();
      setProjects(prev => [duplicatedProject, ...prev]);
      setShowDuplicateModal(false);
      setSelectedProject(null);
      setDuplicateFormData({ name: '', key: '' });
      setError(null);
    } catch (error) {
      console.error('Error duplicating project:', error);
      setError(error instanceof Error ? error.message : 'Failed to duplicate project');
    }
  };

  const handleDeleteProject = async (projectId: number) => {
    if (!window.confirm('Are you sure you want to delete this project? This action cannot be undone.')) {
      return;
    }

    try {
      const response = await fetch(`${API_URL}/api/v1/sast/projects/${projectId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to delete project');
      }

      setProjects(prev => prev.filter(p => p.id !== projectId));
      setError(null);
    } catch (error) {
      console.error('Error deleting project:', error);
      setError(error instanceof Error ? error.message : 'Failed to delete project');
    }
  };

  const handleStartScan = async (projectId: number) => {
    try {
      const response = await fetch(`${API_URL}/api/v1/sast/scans`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          project_id: projectId,
          scan_type: 'full',
          branch: 'main'
        })
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to start scan');
      }

      // Refresh projects to show updated scan status
      fetchProjects();
      setError(null);
    } catch (error) {
      console.error('Error starting scan:', error);
      setError(error instanceof Error ? error.message : 'Failed to start scan');
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'COMPLETED':
        return 'text-green-600 bg-green-100';
      case 'RUNNING':
        return 'text-blue-600 bg-blue-100';
      case 'FAILED':
        return 'text-red-600 bg-red-100';
      case 'PENDING':
        return 'text-yellow-600 bg-yellow-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'COMPLETED':
        return <CheckCircleIcon className="w-4 h-4" />;
      case 'RUNNING':
        return <ArrowPathIcon className="w-4 h-4 animate-spin" />;
      case 'FAILED':
        return <XCircleIcon className="w-4 h-4" />;
      case 'PENDING':
        return <ClockIcon className="w-4 h-4" />;
      default:
        return <ClockIcon className="w-4 h-4" />;
    }
  };

  const getQualityGateColor = (status: string) => {
    switch (status) {
      case 'PASSED':
        return 'text-green-600 bg-green-100';
      case 'FAILED':
        return 'text-red-600 bg-red-100';
      case 'WARNING':
        return 'text-yellow-600 bg-yellow-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'text-red-600';
      case 'high':
        return 'text-orange-600';
      case 'medium':
        return 'text-yellow-600';
      case 'low':
        return 'text-blue-600';
      default:
        return 'text-gray-600';
    }
  };

  const languages = ['all', ...Array.from(new Set(projects.map(p => p.language)))];
  const branches = ['all', ...Array.from(new Set(projects.map(p => p.branch)))];

  // Bulk selection helpers
  const toggleSelectProject = (id: number) => {
    setSelectedProjectIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };
  const clearSelection = () => setSelectedProjectIds(new Set());
  const selectAllOnPage = () => setSelectedProjectIds(new Set(projects.map(p => p.id)));

  // Saved views helpers
  useEffect(() => {
    try {
      const raw = localStorage.getItem('sastProjectViews');
      if (raw) setSavedViews(JSON.parse(raw));
    } catch {}
  }, []);
  const persistSavedViews = (views: SavedView[]) => {
    try { localStorage.setItem('sastProjectViews', JSON.stringify(views)); } catch {}
  };
  const collectCurrentViewState = () => ({
    searchTerm, selectedLanguage, selectedLanguages, selectedStatus, selectedQualityGate,
    selectedReliability, selectedSecurity, selectedMaintainability, minCoverage, maxDuplication,
    minHotspots, sortBy, sortOrder, selectedVisibility, favoriteOnly, selectedTags, tagsMode,
    excludeTags, selectedBranch, owner, team, permission, almProvider, minLoc, maxLoc,
    myProjectsOnly, newCodeMode, newCodeDays, newCodeSince, showNewCodeMetrics, dateFrom, dateTo, itemsPerPage
  });
  const setStateFromView = (s: any) => {
    setSearchTerm(s.searchTerm ?? '');
    setSelectedLanguage(s.selectedLanguage ?? 'all');
    setSelectedLanguages(s.selectedLanguages ?? []);
    setSelectedStatus(s.selectedStatus ?? 'all');
    setSelectedQualityGate(s.selectedQualityGate ?? 'all');
    setSelectedReliability(s.selectedReliability ?? 'all');
    setSelectedSecurity(s.selectedSecurity ?? 'all');
    setSelectedMaintainability(s.selectedMaintainability ?? 'all');
    setMinCoverage(s.minCoverage ?? '');
    setMaxDuplication(s.maxDuplication ?? '');
    setMinHotspots(s.minHotspots ?? '');
    setSortBy(s.sortBy ?? '');
    setSortOrder(s.sortOrder ?? 'desc');
    setSelectedVisibility(s.selectedVisibility ?? 'all');
    setFavoriteOnly(!!s.favoriteOnly);
    setSelectedTags(s.selectedTags ?? '');
    setTagsMode(s.tagsMode ?? 'any');
    setExcludeTags(!!s.excludeTags);
    setSelectedBranch(s.selectedBranch ?? 'all');
    setOwner(s.owner ?? '');
    setTeam(s.team ?? '');
    setPermission(s.permission ?? 'all');
    setAlmProvider(s.almProvider ?? 'all');
    setMinLoc(s.minLoc ?? '');
    setMaxLoc(s.maxLoc ?? '');
    setMyProjectsOnly(!!s.myProjectsOnly);
    setNewCodeMode(s.newCodeMode ?? 'none');
    setNewCodeDays(s.newCodeDays ?? 30);
    setNewCodeSince(s.newCodeSince ?? '');
    setShowNewCodeMetrics(!!s.showNewCodeMetrics);
    setDateFrom(s.dateFrom ?? '');
    setDateTo(s.dateTo ?? '');
    setItemsPerPage(s.itemsPerPage ?? 12);
  };
  const saveCurrentView = () => {
    const name = window.prompt('Save view as:');
    if (!name) return;
    const next = [...savedViews.filter(v => v.name !== name), { name, state: collectCurrentViewState() }];
    setSavedViews(next); persistSavedViews(next); setSelectedView(name);
  };
  const applyViewByName = (name: string) => {
    setSelectedView(name);
    const v = savedViews.find(x => x.name === name);
    if (v) { setStateFromView(v.state); setCurrentPage(1); }
  };
  const deleteViewByName = (name: string) => {
    const next = savedViews.filter(v => v.name !== name);
    setSavedViews(next); persistSavedViews(next);
    if (selectedView === name) setSelectedView('');
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">SAST Projects</h1>
          <p className="text-gray-600">Manage and monitor your static application security testing projects</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-2">
            <select
              value={selectedView}
              onChange={(e) => applyViewByName(e.target.value)}
              className="px-3 py-2 border border-gray-300 text-sm rounded-md"
              title="Saved views"
            >
              <option value="">Views</option>
              {savedViews.map(v => (
                <option key={v.name} value={v.name}>{v.name}</option>
              ))}
            </select>
            <button onClick={saveCurrentView} className="px-3 py-2 border border-gray-300 text-sm rounded-md bg-white">Save View</button>
            {selectedView && (
              <button onClick={() => deleteViewByName(selectedView)} className="px-3 py-2 border border-gray-300 text-sm rounded-md bg-white">Delete View</button>
            )}
          </div>
          <button
            onClick={exportProjectsAsCSV}
            className="inline-flex items-center px-3 py-2 border border-gray-300 text-sm font-medium rounded-md shadow-sm text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
          >
            Export CSV
          </button>
          <button
            onClick={() => setShowCreateModal(true)}
            className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
          >
            <PlusIcon className="w-4 h-4 mr-2" />
            Create Project
          </button>
        </div>
      </div>

      {/* Keyboard Shortcuts Help */}
      <div className="bg-blue-50 border border-blue-200 rounded-md p-3">
        <div className="text-sm text-blue-800">
          <span className="font-medium">Keyboard Shortcuts:</span> 
          <span className="ml-2">N (new project), S (search), F (favorites), C (cards view), L (list view), Esc (clear search)</span>
        </div>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-md p-4">
          <div className="flex">
            <ExclamationTriangleIcon className="w-5 h-5 text-red-400" />
            <div className="ml-3">
              <h3 className="text-sm font-medium text-red-800">Error</h3>
              <p className="text-sm text-red-700 mt-1">{error}</p>
            </div>
          </div>
        </div>
      )}

      {/* Filters and Search */}
      <div className="bg-white p-4 rounded-lg shadow-sm border border-gray-200">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="flex-1">
            <div className="relative">
              <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                id="project-search-input"
                type="text"
                placeholder="Search projects..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
              />
            </div>
          </div>
          <div className="flex gap-2 flex-wrap">
            <select
              value={selectedLanguage}
              onChange={(e) => setSelectedLanguage(e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            >
              {languages.map(lang => (
                <option key={lang} value={lang}>
                  {lang === 'all' ? 'All Languages' : lang}
                </option>
              ))}
            </select>
            <select
              multiple
              value={selectedLanguages}
              onChange={(e) => setSelectedLanguages(Array.from(e.target.selectedOptions).map(o => o.value))}
              className="px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500 min-w-[10rem]"
              title="Languages (multi-select)"
            >
              {languages.map(lang => (
                <option key={`multi-${lang}`} value={lang}>{lang}</option>
              ))}
            </select>
            <select
              value={selectedBranch}
              onChange={(e) => setSelectedBranch(e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            >
              {branches.map(b => (
                <option key={b} value={b}>
                  {b === 'all' ? 'All Branches' : b}
                </option>
              ))}
            </select>
            <select
              value={selectedStatus}
              onChange={(e) => setSelectedStatus(e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="all">All Status</option>
              <option value="active">Active</option>
              <option value="completed">Completed</option>
              <option value="failed">Failed</option>
            </select>
            <select
              value={selectedQualityGate}
              onChange={(e) => setSelectedQualityGate(e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="all">All Gates</option>
              <option value="PASSED">Passed</option>
              <option value="FAILED">Failed</option>
              <option value="WARNING">Warning</option>
            </select>
            <select
              value={selectedVisibility}
              onChange={(e) => setSelectedVisibility(e.target.value as 'all'|'public'|'private')}
              className="px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="all">All Visibility</option>
              <option value="public">Public</option>
              <option value="private">Private</option>
            </select>
            <select
              value={permission}
              onChange={(e) => setPermission(e.target.value as any)}
              className="px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
              title="Permission"
            >
              <option value="all">Any Permission</option>
              <option value="admin">Admin</option>
              <option value="browse">Browse</option>
              <option value="execute">Execute Analysis</option>
            </select>
            <select
              value={almProvider}
              onChange={(e) => setAlmProvider(e.target.value as any)}
              className="px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
              title="ALM Provider"
            >
              <option value="all">All Providers</option>
              <option value="github">GitHub</option>
              <option value="gitlab">GitLab</option>
              <option value="azure">Azure DevOps</option>
              <option value="bitbucket">Bitbucket</option>
              <option value="bound">Bound</option>
              <option value="unbound">Unbound</option>
            </select>
            <select
              value={selectedReliability}
              onChange={(e) => setSelectedReliability(e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="all">Reliability A–E</option>
              {['A','B','C','D','E'].map(r => <option key={r} value={r}>{r}</option>)}
            </select>
            <select
              value={selectedSecurity}
              onChange={(e) => setSelectedSecurity(e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="all">Security A–E</option>
              {['A','B','C','D','E'].map(r => <option key={r} value={r}>{r}</option>)}
            </select>
            <select
              value={selectedMaintainability}
              onChange={(e) => setSelectedMaintainability(e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="all">Maintainability A–E</option>
              {['A','B','C','D','E'].map(r => <option key={r} value={r}>{r}</option>)}
            </select>
            <input
              type="text"
              placeholder="Tags (comma-separated)"
              value={selectedTags}
              onChange={(e) => setSelectedTags(e.target.value)}
              className="w-48 px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            />
            <select
              value={tagsMode}
              onChange={(e) => setTagsMode(e.target.value as any)}
              className="px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
              title="Tag match mode"
            >
              <option value="any">Tags match any</option>
              <option value="all">Tags match all</option>
            </select>
            <label className="inline-flex items-center gap-2 px-2 py-2 border border-gray-300 rounded-md">
              <input type="checkbox" checked={excludeTags} onChange={(e) => setExcludeTags(e.target.checked)} />
              <span className="text-sm text-gray-700">Exclude tags</span>
            </label>
            <input
              type="number"
              min={0}
              max={100}
              placeholder="Min Coverage %"
              value={minCoverage}
              onChange={(e) => setMinCoverage(e.target.value)}
              className="w-36 px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            />
            <input
              type="number"
              min={0}
              max={100}
              placeholder="Max Duplication %"
              value={maxDuplication}
              onChange={(e) => setMaxDuplication(e.target.value)}
              className="w-40 px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            />
            <input
              type="number"
              min={0}
              placeholder="Min Hotspots"
              value={minHotspots}
              onChange={(e) => setMinHotspots(e.target.value)}
              className="w-36 px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            />
            <input
              type="number"
              min={0}
              placeholder="Min LOC"
              value={minLoc}
              onChange={(e) => setMinLoc(e.target.value)}
              className="w-32 px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            />
            <input
              type="number"
              min={0}
              placeholder="Max LOC"
              value={maxLoc}
              onChange={(e) => setMaxLoc(e.target.value)}
              className="w-32 px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            />
            <input
              type="date"
              value={dateFrom}
              onChange={(e) => setDateFrom(e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
              title="Last analysis from"
            />
            <input
              type="date"
              value={dateTo}
              onChange={(e) => setDateTo(e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
              title="Last analysis to"
            />
            <div className="flex items-center gap-1">
              <button onClick={() => applyDatePreset(7)} className="px-2 py-1 text-xs border rounded">Last 7</button>
              <button onClick={() => applyDatePreset(30)} className="px-2 py-1 text-xs border rounded">30</button>
              <button onClick={() => applyDatePreset(90)} className="px-2 py-1 text-xs border rounded">90</button>
            </div>
            <select
              value={newCodeMode}
              onChange={(e) => setNewCodeMode(e.target.value as any)}
              className="px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
              title="New Code period"
            >
              <option value="none">No New Code period</option>
              <option value="prev-version">Previous Version</option>
              <option value="days">Last X days</option>
              <option value="since-date">Since date</option>
            </select>
            {newCodeMode === 'days' && (
              <input
                type="number"
                min={1}
                value={newCodeDays}
                onChange={(e) => setNewCodeDays(Number(e.target.value))}
                className="w-24 px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                placeholder="Days"
              />
            )}
            {newCodeMode === 'since-date' && (
              <input
                type="date"
                value={newCodeSince}
                onChange={(e) => setNewCodeSince(e.target.value)}
                className="px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
              />
            )}
            <label className="inline-flex items-center gap-2 px-2 py-2 border border-gray-300 rounded-md">
              <input
                type="checkbox"
                checked={showNewCodeMetrics}
                onChange={(e) => setShowNewCodeMetrics(e.target.checked)}
              />
              <span className="text-sm text-gray-700">Show New Code</span>
            </label>
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="">Sort By</option>
              <option value="name">Name</option>
              <option value="key">Key</option>
              <option value="last_analysis">Last Analysis</option>
              <option value="analysis_recency">Activity Trend</option>
              <option value="quality_gate">Quality Gate</option>
              <option value="coverage">Coverage</option>
              <option value="duplication_percent">Duplication %</option>
              <option value="lines_of_code">Lines of Code</option>
              <option value="bug_count">Bugs</option>
              <option value="vulnerability_count">Vulnerabilities</option>
              <option value="code_smell_count">Code Smells</option>
              <option value="security_hotspot_count">Security Hotspots</option>
              <option value="new_code_coverage">New Code Coverage</option>
              <option value="new_code_bugs">New Code Bugs</option>
              <option value="new_code_vulnerabilities">New Code Vulnerabilities</option>
              <option value="new_code_smells">New Code Smells</option>
              <option value="new_code_hotspots">New Code Hotspots</option>
              <option value="created_at">Created</option>
              <option value="updated_at">Updated</option>
            </select>
            <select
              value={sortOrder}
              onChange={(e) => setSortOrder(e.target.value as 'asc' | 'desc')}
              className="px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="desc">Desc</option>
              <option value="asc">Asc</option>
            </select>
            <label className="inline-flex items-center gap-2 px-2 py-2 border border-gray-300 rounded-md">
              <input
                type="checkbox"
                checked={favoriteOnly}
                onChange={(e) => setFavoriteOnly(e.target.checked)}
              />
              <span className="text-sm text-gray-700">Favorites</span>
            </label>
            <label className="inline-flex items-center gap-2 px-2 py-2 border border-gray-300 rounded-md">
              <input
                type="checkbox"
                checked={myProjectsOnly}
                onChange={(e) => setMyProjectsOnly(e.target.checked)}
              />
              <span className="text-sm text-gray-700">My projects</span>
            </label>
            <input
              type="text"
              placeholder="Owner (id/email)"
              value={owner}
              onChange={(e) => setOwner(e.target.value)}
              className="w-48 px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            />
            <input
              type="text"
              placeholder="Team"
              value={team}
              onChange={(e) => setTeam(e.target.value)}
              className="w-40 px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            />
            <div className="flex border border-gray-300 rounded-md">
              <button
                onClick={() => setViewMode('cards')}
                className={`px-3 py-2 text-sm font-medium ${
                  viewMode === 'cards' 
                    ? 'bg-blue-600 text-white' 
                    : 'bg-white text-gray-700 hover:bg-gray-50'
                }`}
              >
                Cards
              </button>
              <button
                onClick={() => setViewMode('list')}
                className={`px-3 py-2 text-sm font-medium ${
                  viewMode === 'list' 
                    ? 'bg-blue-600 text-white' 
                    : 'bg-white text-gray-700 hover:bg-gray-50'
                }`}
              >
                List
              </button>
            </div>
            <select
              value={itemsPerPage}
              onChange={(e) => setItemsPerPage(Number(e.target.value))}
              className="px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
              title="Items per page"
            >
              {[12, 24, 50, 100].map(n => (
                <option key={n} value={n}>{n} / page</option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Projects Display */}
      {viewMode === 'cards' ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {projects.map((project) => (
            <motion.div
              key={project.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="bg-white p-6 rounded-lg shadow-sm border border-gray-200 hover:shadow-md transition-shadow"
            >
              <div className="flex items-center justify-between mb-2">
                <label className="inline-flex items-center gap-2 text-sm text-gray-700">
                  <input type="checkbox" checked={selectedProjectIds.has(project.id)} onChange={() => toggleSelectProject(project.id)} />
                  Select
                </label>
                {typeof project.linesOfCode === 'number' && (
                  <span className="text-xs text-gray-500">LOC: {project.linesOfCode}</span>
                )}
              </div>
              <div className="flex items-start justify-between mb-4">
                <div className="flex-1">
                  <h3 className="text-lg font-semibold text-gray-900 mb-1">{project.name}</h3>
                  <p className="text-sm text-gray-600 mb-2">{project.key}</p>
                  <div className="flex items-center space-x-2">
                    <span className="text-xs bg-gray-100 text-gray-700 px-2 py-1 rounded">{project.language}</span>
                    <span className={`text-xs px-2 py-1 rounded ${getQualityGateColor(project.qualityGate)}`}>
                      {project.qualityGate}
                    </span>
                  </div>
                </div>
                <div className="ml-3 flex items-center gap-2">
                  <button
                    title={project.favorite ? 'Unstar' : 'Star'}
                    onClick={() => toggleFavorite(project.id, !project.favorite)}
                    className={`text-sm ${project.favorite ? 'text-yellow-500' : 'text-gray-400'} hover:text-yellow-500`}
                    disabled={updatingProjectId === project.id}
                  >
                    ★
                  </button>
                  <select
                    title="Visibility"
                    value={project.visibility || 'private'}
                    onChange={(e) => updateVisibility(project.id, e.target.value as 'public' | 'private')}
                    className="text-xs border border-gray-300 rounded px-1 py-0.5"
                    disabled={updatingProjectId === project.id}
                  >
                    <option value="public">public</option>
                    <option value="private">private</option>
                  </select>
                </div>
              </div>

              {/* Last Scan Info */}
              {project.lastScan && (
                <div className="mb-4 p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-gray-700">Last Scan</span>
                    <div className={`flex items-center space-x-1 px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(project.lastScan.status)}`}>
                      {getStatusIcon(project.lastScan.status)}
                      <span>{project.lastScan.status}</span>
                    </div>
                  </div>
                  <div className="text-xs text-gray-600">
                    {new Date(project.lastScan.timestamp).toLocaleDateString()}
                    {project.lastScan.duration && ` • ${project.lastScan.duration}`}
                  </div>
                </div>
              )}

              {/* Issues Summary */}
              <div className="mb-4">
                <h4 className="text-sm font-medium text-gray-700 mb-2">Issues</h4>
                <div className="grid grid-cols-4 gap-2 text-xs">
                  <div className="text-center">
                    <div className={`font-bold ${getSeverityColor('critical')}`}>{project.issues.critical}</div>
                    <div className="text-gray-500">Critical</div>
                  </div>
                  <div className="text-center">
                    <div className={`font-bold ${getSeverityColor('high')}`}>{project.issues.high}</div>
                    <div className="text-gray-500">High</div>
                  </div>
                  <div className="text-center">
                    <div className={`font-bold ${getSeverityColor('medium')}`}>{project.issues.medium}</div>
                    <div className="text-gray-500">Medium</div>
                  </div>
                  <div className="text-center">
                    <div className={`font-bold ${getSeverityColor('low')}`}>{project.issues.low}</div>
                    <div className="text-gray-500">Low</div>
                  </div>
                </div>
                <div className="grid grid-cols-3 gap-2 text-xs mt-3">
                  <div className="text-center">
                    <div className="font-bold text-gray-800">{project.bugCount}</div>
                    <div className="text-gray-500">Bugs</div>
                  </div>
                  <div className="text-center">
                    <div className="font-bold text-gray-800">{project.vulnerabilityCount}</div>
                    <div className="text-gray-500">Vulnerabilities</div>
                  </div>
                  <div className="text-center">
                    <div className="font-bold text-gray-800">{project.codeSmellCount}</div>
                    <div className="text-gray-500">Code Smells</div>
                  </div>
                </div>
                {showNewCodeMetrics && (
                  <div className="grid grid-cols-5 gap-2 text-[10px] mt-3">
                    <div className="text-center">
                      <div className="font-bold text-gray-800">{project.newBugs ?? '-'}</div>
                      <div className="text-gray-500">NC Bugs</div>
                    </div>
                    <div className="text-center">
                      <div className="font-bold text-gray-800">{project.newVulnerabilities ?? '-'}</div>
                      <div className="text-gray-500">NC Vulns</div>
                    </div>
                    <div className="text-center">
                      <div className="font-bold text-gray-800">{project.newCodeSmells ?? '-'}</div>
                      <div className="text-gray-500">NC Smells</div>
                    </div>
                    <div className="text-center">
                      <div className="font-bold text-gray-800">{project.newHotspots ?? '-'}</div>
                      <div className="text-gray-500">NC Hotspots</div>
                    </div>
                    <div className="text-center">
                      <div className="font-bold text-gray-800">{typeof project.newCodeCoverage === 'number' ? `${project.newCodeCoverage}%` : '-'}</div>
                      <div className="text-gray-500">NC Cov</div>
                    </div>
                  </div>
                )}
                <div className="grid grid-cols-3 gap-2 text-xs mt-3">
                  <div className="text-center">
                    <div className="font-bold text-gray-800">{project.securityHotspotCount}</div>
                    <div className="text-gray-500">Hotspots</div>
                  </div>
                  <div className="text-center">
                    <div className="font-bold text-gray-800">{project.coverage}%</div>
                    <div className="text-gray-500">Coverage</div>
                  </div>
                  <div className="text-center">
                    <div className="font-bold text-gray-800">{project.duplicationPercent}%</div>
                    <div className="text-gray-500">Duplication</div>
                  </div>
                </div>
                <div className="mt-3 flex flex-wrap gap-1 items-center">
                  {(project.tags || []).map((t, idx) => (
                    <span key={`${t}-${idx}`} className="text-[10px] px-2 py-0.5 bg-gray-100 text-gray-700 rounded inline-flex items-center gap-1">
                      #{t}
                      <button
                        className="text-gray-400 hover:text-red-500"
                        title="Remove tag"
                        onClick={() => removeTag(project.id, t)}
                        disabled={updatingProjectId === project.id}
                      >×</button>
                    </span>
                  ))}
                  <input
                    value={newTagByProject[project.id] || ''}
                    onChange={(e) => setNewTagByProject(prev => ({ ...prev, [project.id]: e.target.value }))}
                    onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addTag(project.id); } }}
                    placeholder="Add tag"
                    className="text-[10px] px-2 py-1 border border-gray-300 rounded"
                    disabled={updatingProjectId === project.id}
                    style={{ minWidth: '80px' }}
                  />
                  <button
                    className="text-[10px] px-2 py-1 bg-gray-800 text-white rounded"
                    onClick={() => addTag(project.id)}
                    disabled={updatingProjectId === project.id}
                  >Add</button>
                </div>
              </div>

              {/* Actions */}
              <div className="flex items-center justify-between pt-4 border-t border-gray-200">
                <div className="flex space-x-2">
                                     <button
                     onClick={() => navigate(`/sast/projects/${project.id}`)}
                     className="inline-flex items-center px-3 py-1.5 border border-gray-300 shadow-sm text-xs font-medium rounded text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                   >
                     <EyeIcon className="w-3 h-3 mr-1" />
                     View
                   </button>
                  <button
                    onClick={() => handleStartScan(project.id)}
                    className="inline-flex items-center px-3 py-1.5 border border-transparent text-xs font-medium rounded text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                  >
                    <PlayIcon className="w-3 h-3 mr-1" />
                    Scan
                  </button>
                </div>
                <div className="flex space-x-1">
                  <button
                    onClick={() => {
                      setSelectedProject(project);
                      setDuplicateFormData({
                        name: `${project.name} - Copy`,
                        key: `${project.key}-copy`
                      });
                      setShowDuplicateModal(true);
                    }}
                    className="p-1 text-gray-400 hover:text-gray-600"
                    title="Duplicate Project"
                  >
                    <DocumentDuplicateIcon className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => handleDeleteProject(project.id)}
                    className="p-1 text-gray-400 hover:text-red-600"
                    title="Delete Project"
                  >
                    <TrashIcon className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      ) : (
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3"></th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Project</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Language</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Last Scan</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Issues</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Metrics</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">New Code</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Quality Gate</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {projects.map((project) => (
                <tr key={project.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <input type="checkbox" checked={selectedProjectIds.has(project.id)} onChange={() => toggleSelectProject(project.id)} />
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div>
                      <div className="text-sm font-medium text-gray-900">{project.name}</div>
                      <div className="text-sm text-gray-500">{project.key}</div>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className="text-sm text-gray-900">{project.language}</span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    {project.lastScan ? (
                      <div>
                        <div className={`inline-flex items-center space-x-1 px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(project.lastScan.status)}`}>
                          {getStatusIcon(project.lastScan.status)}
                          <span>{project.lastScan.status}</span>
                        </div>
                        <div className="text-xs text-gray-500 mt-1">
                          {new Date(project.lastScan.timestamp).toLocaleDateString()}
                        </div>
                      </div>
                    ) : (
                      <span className="text-sm text-gray-500">No scans</span>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex space-x-2 text-xs">
                      <span className={`${getSeverityColor('critical')}`}>{project.issues.critical} Critical</span>
                      <span className={`${getSeverityColor('high')}`}>{project.issues.high} High</span>
                      <span className={`${getSeverityColor('medium')}`}>{project.issues.medium} Medium</span>
                      <span className={`${getSeverityColor('low')}`}>{project.issues.low} Low</span>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex flex-wrap gap-2 text-xs">
                      <span className="inline-flex items-center px-2 py-1 rounded bg-gray-100 text-gray-800">{project.bugCount} Bugs</span>
                      <span className="inline-flex items-center px-2 py-1 rounded bg-gray-100 text-gray-800">{project.vulnerabilityCount} Vulns</span>
                      <span className="inline-flex items-center px-2 py-1 rounded bg-gray-100 text-gray-800">{project.codeSmellCount} Smells</span>
                      <span className="inline-flex items-center px-2 py-1 rounded bg-gray-100 text-gray-800">{project.securityHotspotCount} Hotspots</span>
                      <span className="inline-flex items-center px-2 py-1 rounded bg-gray-100 text-gray-800">{project.coverage}% Cov</span>
                      <span className="inline-flex items-center px-2 py-1 rounded bg-gray-100 text-gray-800">{project.duplicationPercent}% Dup</span>
                      {typeof project.linesOfCode === 'number' && (
                        <span className="inline-flex items-center px-2 py-1 rounded bg-gray-100 text-gray-800">{project.linesOfCode} LOC</span>
                      )}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    {showNewCodeMetrics ? (
                      <div className="flex flex-wrap gap-2 text-xs">
                        <span className="inline-flex items-center px-2 py-1 rounded bg-gray-100 text-gray-800">{project.newBugs ?? '-'} NC Bugs</span>
                        <span className="inline-flex items-center px-2 py-1 rounded bg-gray-100 text-gray-800">{project.newVulnerabilities ?? '-'} NC Vulns</span>
                        <span className="inline-flex items-center px-2 py-1 rounded bg-gray-100 text-gray-800">{project.newCodeSmells ?? '-'} NC Smells</span>
                        <span className="inline-flex items-center px-2 py-1 rounded bg-gray-100 text-gray-800">{project.newHotspots ?? '-'} NC Hotspots</span>
                        <span className="inline-flex items-center px-2 py-1 rounded bg-gray-100 text-gray-800">{typeof project.newCodeCoverage === 'number' ? `${project.newCodeCoverage}%` : '-'} NC Cov</span>
                      </div>
                    ) : (
                      <span className="text-xs text-gray-400">—</span>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center gap-2">
                      <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full ${getQualityGateColor(project.qualityGate)}`}>
                        {project.qualityGate}
                      </span>
                      <button
                        title={project.favorite ? 'Unstar' : 'Star'}
                        onClick={() => toggleFavorite(project.id, !project.favorite)}
                        className={`text-sm ${project.favorite ? 'text-yellow-500' : 'text-gray-400'} hover:text-yellow-500`}
                        disabled={updatingProjectId === project.id}
                      >
                        ★
                      </button>
                      <select
                        title="Visibility"
                        value={project.visibility || 'private'}
                        onChange={(e) => updateVisibility(project.id, e.target.value as 'public' | 'private')}
                        className="text-xs border border-gray-300 rounded px-1 py-0.5"
                        disabled={updatingProjectId === project.id}
                      >
                        <option value="public">public</option>
                        <option value="private">private</option>
                      </select>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                                         <div className="flex space-x-2">
                       <button 
                         onClick={() => navigate(`/sast/projects/${project.id}`)}
                         className="text-blue-600 hover:text-blue-900"
                       >
                         View
                       </button>
                      <button 
                        onClick={() => handleStartScan(project.id)}
                        className="text-green-600 hover:text-green-900"
                      >
                        Scan
                      </button>
                      <button className="text-gray-600 hover:text-gray-900">Duplicate</button>
                      <button 
                        onClick={() => handleDeleteProject(project.id)}
                        className="text-red-600 hover:text-red-900"
                      >
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {selectedProjectIds.size > 0 && (
            <div className="p-3 border-t flex items-center justify-between bg-gray-50">
              <div className="text-sm text-gray-700">Selected: {selectedProjectIds.size}</div>
              <div className="flex items-center gap-2">
                <button onClick={selectAllOnPage} className="px-2 py-1 text-xs border rounded">Select all on page</button>
                <button onClick={clearSelection} className="px-2 py-1 text-xs border rounded">Clear</button>
                <button onClick={async () => { await Promise.all(Array.from(selectedProjectIds).map(id => toggleFavorite(id, true))); clearSelection(); fetchProjects(); }} className="px-2 py-1 text-xs border rounded">Star</button>
                <button onClick={async () => { await Promise.all(Array.from(selectedProjectIds).map(id => toggleFavorite(id, false))); clearSelection(); fetchProjects(); }} className="px-2 py-1 text-xs border rounded">Unstar</button>
                <button onClick={async () => { await Promise.all(Array.from(selectedProjectIds).map(id => updateVisibility(id, 'public'))); clearSelection(); fetchProjects(); }} className="px-2 py-1 text-xs border rounded">Set Public</button>
                <button onClick={async () => { await Promise.all(Array.from(selectedProjectIds).map(id => updateVisibility(id, 'private'))); clearSelection(); fetchProjects(); }} className="px-2 py-1 text-xs border rounded">Set Private</button>
                <button onClick={async () => {
                  const tag = window.prompt('Add tag to selected:');
                  if (!tag) return;
                  await Promise.all(Array.from(selectedProjectIds).map(async (id) => {
                    const current = projects.find(p => p.id === id)?.tags || [];
                    if (!current.includes(tag)) await updateTags(id, [...current, tag]);
                  }));
                  clearSelection(); fetchProjects();
                }} className="px-2 py-1 text-xs border rounded">Add Tag</button>
                <button onClick={async () => {
                  const tag = window.prompt('Remove tag from selected:');
                  if (!tag) return;
                  await Promise.all(Array.from(selectedProjectIds).map(async (id) => {
                    const current = projects.find(p => p.id === id)?.tags || [];
                    if (current.includes(tag)) await updateTags(id, current.filter(t => t !== tag));
                  }));
                  clearSelection(); fetchProjects();
                }} className="px-2 py-1 text-xs border rounded">Remove Tag</button>
                <button onClick={async () => {
                  if (!window.confirm('Delete selected projects?')) return;
                  await Promise.all(Array.from(selectedProjectIds).map(id => handleDeleteProject(id)));
                  clearSelection(); fetchProjects();
                }} className="px-2 py-1 text-xs border rounded text-red-600">Delete</button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <div className="text-sm text-gray-700">
            Showing {((currentPage - 1) * itemsPerPage) + 1} to {Math.min(currentPage * itemsPerPage, totalProjects)} of {totalProjects} projects
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
              disabled={currentPage === 1}
              className="inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm leading-4 font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <ChevronLeftIcon className="w-4 h-4" />
              Previous
            </button>
            <span className="text-sm text-gray-700">
              Page {currentPage} of {totalPages}
            </span>
            <button
              onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))}
              disabled={currentPage === totalPages}
              className="inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm leading-4 font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Next
              <ChevronRightIcon className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* Create Project Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Create New SAST Project</h3>
              <form onSubmit={handleCreateProject} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Project Name</label>
                  <input
                    type="text"
                    required
                    value={createFormData.name}
                    onChange={(e) => setCreateFormData({...createFormData, name: e.target.value})}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                    placeholder="Enter project name"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Project Key</label>
                  <input
                    type="text"
                    required
                    value={createFormData.key}
                    onChange={(e) => setCreateFormData({...createFormData, key: e.target.value})}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                    placeholder="project-key"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Repository URL</label>
                  <input
                    type="url"
                    value={createFormData.repository_url}
                    onChange={(e) => setCreateFormData({...createFormData, repository_url: e.target.value})}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                    placeholder="https://github.com/example/repo"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Programming Language</label>
                  <select 
                    required
                    value={createFormData.language}
                    onChange={(e) => setCreateFormData({...createFormData, language: e.target.value})}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  >
                    <option value="">Select language</option>
                    <option value="javascript">JavaScript</option>
                    <option value="python">Python</option>
                    <option value="java">Java</option>
                    <option value="csharp">C#</option>
                    <option value="php">PHP</option>
                    <option value="react-native">React Native</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Branch</label>
                  <input
                    type="text"
                    value={createFormData.branch}
                    onChange={(e) => setCreateFormData({...createFormData, branch: e.target.value})}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                    placeholder="main"
                  />
                </div>
                <div className="flex justify-end space-x-3 pt-4">
                  <button
                    type="button"
                    onClick={() => setShowCreateModal(false)}
                    className="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700"
                  >
                    Create Project
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* Duplicate Project Modal */}
      {showDuplicateModal && selectedProject && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Duplicate Project</h3>
              <p className="text-sm text-gray-600 mb-4">
                Create a copy of "{selectedProject.name}" with its settings and configuration.
              </p>
              <form onSubmit={handleDuplicateProject} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">New Project Name</label>
                  <input
                    type="text"
                    required
                    value={duplicateFormData.name}
                    onChange={(e) => setDuplicateFormData({...duplicateFormData, name: e.target.value})}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">New Project Key</label>
                  <input
                    type="text"
                    required
                    value={duplicateFormData.key}
                    onChange={(e) => setDuplicateFormData({...duplicateFormData, key: e.target.value})}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>
                <div className="flex justify-end space-x-3 pt-4">
                  <button
                    type="button"
                    onClick={() => setShowDuplicateModal(false)}
                    className="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700"
                  >
                    Duplicate Project
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SASTProjects; 