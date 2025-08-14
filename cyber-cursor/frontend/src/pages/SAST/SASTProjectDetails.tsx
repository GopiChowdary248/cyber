import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  ArrowLeftIcon,
  PlayIcon,
  ClockIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  ShieldExclamationIcon,
  ChartBarIcon,
  CogIcon,
  DocumentTextIcon,
  EyeIcon,
  MagnifyingGlassIcon,
  FunnelIcon,
  ChevronDownIcon,
  ChevronUpIcon,
  StarIcon,
  CodeBracketIcon,
  BeakerIcon,
  ArrowPathIcon,
  BugAntIcon,
  Cog6ToothIcon,
  ChevronLeftIcon,
  XMarkIcon,
  CheckIcon,
  ExclamationCircleIcon,
  InformationCircleIcon,
} from '@heroicons/react/24/outline';

interface ProjectDetails {
  id: number;
  name: string;
  key: string;
  language: string;
  repositoryUrl?: string;
  branch: string;
  qualityGate: 'PASSED' | 'FAILED' | 'WARNING' | 'NONE';
  maintainabilityRating: 'A' | 'B' | 'C' | 'D' | 'E';
  securityRating: 'A' | 'B' | 'C' | 'D' | 'E';
  reliabilityRating: 'A' | 'B' | 'C' | 'D' | 'E';
  vulnerabilityCount: number;
  bugCount: number;
  codeSmellCount: number;
  securityHotspotCount: number;
  linesOfCode: number;
  coverage: number;
  technicalDebt: number;
  lastAnalysis?: string;
  lastScan?: {
    id: number;
    status: 'COMPLETED' | 'RUNNING' | 'FAILED' | 'PENDING';
    timestamp: string;
    duration?: string;
  };
}

interface Issue {
  id: number;
  key: string;
  type: 'BUG' | 'VULNERABILITY' | 'CODE_SMELL';
  severity: 'BLOCKER' | 'CRITICAL' | 'MAJOR' | 'MINOR' | 'INFO';
  status: 'OPEN' | 'CONFIRMED' | 'RESOLVED' | 'CLOSED' | 'REOPENED';
  resolution?: 'FIXED' | 'FALSE_POSITIVE' | 'WONT_FIX' | 'REMOVED';
  component: string;
  line: number;
  message: string;
  effort: string;
  debt: string;
  author: string;
  creationDate: string;
  updateDate: string;
  tags: string[];
}

interface IssueFilter {
  type: string[];
  severity: string[];
  status: string[];
  resolution: string[];
  author: string;
  component: string;
}

interface IssueSort {
  field: keyof Issue;
  direction: 'asc' | 'desc';
}

interface SecurityHotspot {
  id: number;
  key: string;
  component: string;
  line: number;
  message: string;
  status: 'TO_REVIEW' | 'REVIEWED' | 'RESOLVED';
  resolution?: 'SAFE' | 'FIXED' | 'ACKNOWLEDGED' | 'FALSE_POSITIVE';
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  category: 'SQL_INJECTION' | 'XSS' | 'CSRF' | 'PATH_TRAVERSAL' | 'COMMAND_INJECTION' | 'LDAP_INJECTION' | 'OPEN_REDIRECT' | 'WEAK_CRYPTOGRAPHY' | 'INSECURE_DESERIALIZATION' | 'OTHER';
  vulnerabilityProbability: 'HIGH' | 'MEDIUM' | 'LOW';
  securityCategory: 'OWASP_TOP_10' | 'CWE' | 'SANS_TOP_25' | 'OTHER';
  author: string;
  creationDate: string;
  updateDate: string;
  reviewer?: string;
  reviewDate?: string;
  comment?: string;
}

interface HotspotFilter {
  status: string[];
  severity: string[];
  category: string[];
  securityCategory: string[];
  vulnerabilityProbability: string[];
  author: string;
  component: string;
}

interface HotspotSort {
  field: keyof SecurityHotspot;
  direction: 'asc' | 'desc';
}

interface QualityGate {
  id: number;
  name: string;
  status: 'PASSED' | 'FAILED' | 'WARNING' | 'NONE';
  conditions: QualityGateCondition[];
  lastEvaluation?: string;
  nextEvaluation?: string;
}

interface QualityGateCondition {
  id: number;
  metric: string;
  operator: 'GT' | 'LT' | 'EQ' | 'NE';
  threshold: number;
  actualValue: number;
  status: 'PASSED' | 'FAILED' | 'WARNING' | 'NONE';
  description: string;
  category: 'RELIABILITY' | 'SECURITY' | 'MAINTAINABILITY' | 'COVERAGE' | 'DUPLICATIONS' | 'SIZE';
}

interface QualityGateThreshold {
  metric: string;
  operator: 'GT' | 'LT' | 'EQ' | 'NE';
  threshold: number;
  description: string;
  category: 'RELIABILITY' | 'SECURITY' | 'MAINTAINABILITY' | 'COVERAGE' | 'DUPLICATIONS' | 'SIZE';
}

interface CoverageData {
  overall: number;
  lines: number;
  functions: number;
  branches: number;
  statements: number;
  uncoveredLines: number[];
  uncoveredFunctions: string[];
  uncoveredBranches: string[];
  fileCoverage: FileCoverage[];
  trendData: CoverageTrend[];
}

interface FileCoverage {
  file: string;
  lines: number;
  coveredLines: number;
  coverage: number;
  uncoveredLines: number[];
  complexity: number;
  lastModified: string;
}

interface CoverageTrend {
  date: string;
  overall: number;
  lines: number;
  functions: number;
  branches: number;
  statements: number;
}

interface TechnicalDebtData {
  totalDebt: number;
  debtRatio: number;
  debtBreakdown: DebtBreakdown[];
  effortEstimation: EffortEstimation;
  debtTrend: DebtTrend[];
  debtByCategory: DebtByCategory[];
  debtBySeverity: DebtBySeverity[];
}

interface DebtBreakdown {
  category: 'CODE_SMELL' | 'BUG' | 'VULNERABILITY' | 'SECURITY_HOTSPOT' | 'DUPLICATION' | 'MAINTAINABILITY';
  count: number;
  effort: number;
  percentage: number;
  description: string;
}

interface EffortEstimation {
  totalEffort: number;
  effortByCategory: {
    category: string;
    effort: number;
    count: number;
    averageEffort: number;
  }[];
  effortBySeverity: {
    severity: string;
    effort: number;
    count: number;
  }[];
}

interface DebtTrend {
  date: string;
  totalDebt: number;
  debtRatio: number;
  newDebt: number;
  resolvedDebt: number;
}

interface DebtByCategory {
  category: string;
  debt: number;
  count: number;
  percentage: number;
  color: string;
}

interface DebtBySeverity {
  severity: string;
  debt: number;
  count: number;
  percentage: number;
  color: string;
}

// Duplications interfaces
interface DuplicationData {
  duplicatedLines: number;
  duplicatedFiles: number;
  duplicatedBlocks: number;
  duplicationDensity: number;
  duplicationsByLanguage: DuplicationByLanguage[];
  duplicationsByFile: DuplicationByFile[];
  duplicationTrend: DuplicationTrend[];
}

interface DuplicationByLanguage {
  language: string;
  duplicatedLines: number;
  duplicatedFiles: number;
  duplicationDensity: number;
  color: string;
}

interface DuplicationByFile {
  file: string;
  duplicatedLines: number;
  duplicatedBlocks: number;
  duplicationDensity: number;
  lastModified: string;
}

interface DuplicationTrend {
  date: string;
  duplicatedLines: number;
  duplicatedFiles: number;
  duplicationDensity: number;
}

// Security Reports interfaces
interface SecurityReportData {
  overallSecurityRating: 'A' | 'B' | 'C' | 'D' | 'E';
  securityScore: number;
  vulnerabilitiesByCategory: VulnerabilityByCategory[];
  owaspTop10Mapping: OWASPMapping[];
  cweMapping: CWEMapping[];
  securityTrend: SecurityTrend[];
  securityHotspots: SecurityHotspotSummary[];
}

interface VulnerabilityByCategory {
  category: string;
  count: number;
  severity: string;
  percentage: number;
  color: string;
}

interface OWASPMapping {
  category: string;
  count: number;
  severity: string;
  description: string;
  color: string;
}

interface CWEMapping {
  cweId: string;
  name: string;
  count: number;
  severity: string;
  description: string;
}

interface SecurityTrend {
  date: string;
  vulnerabilities: number;
  securityScore: number;
  securityRating: 'A' | 'B' | 'C' | 'D' | 'E';
}

interface SecurityHotspotSummary {
  category: string;
  count: number;
  status: string;
  severity: string;
}

// Reliability interfaces
interface ReliabilityData {
  reliabilityRating: 'A' | 'B' | 'C' | 'D' | 'E';
  bugCount: number;
  bugDensity: number;
  bugsBySeverity: BugBySeverity[];
  bugsByCategory: BugByCategory[];
  reliabilityTrend: ReliabilityTrend[];
  newBugs: number;
  resolvedBugs: number;
}

interface BugBySeverity {
  severity: string;
  count: number;
  percentage: number;
  color: string;
}

interface BugByCategory {
  category: string;
  count: number;
  description: string;
  color: string;
}

interface ReliabilityTrend {
  date: string;
  bugCount: number;
  bugDensity: number;
  reliabilityRating: 'A' | 'B' | 'C' | 'D' | 'E';
}

// Maintainability interfaces
interface MaintainabilityData {
  maintainabilityRating: 'A' | 'B' | 'C' | 'D' | 'E';
  codeSmellCount: number;
  codeSmellDensity: number;
  complexity: number;
  codeSmellsByCategory: CodeSmellByCategory[];
  maintainabilityTrend: MaintainabilityTrend[];
  cognitiveComplexity: number;
}

interface CodeSmellByCategory {
  category: string;
  count: number;
  description: string;
  color: string;
}

interface MaintainabilityTrend {
  date: string;
  codeSmellCount: number;
  maintainabilityRating: 'A' | 'B' | 'C' | 'D' | 'E';
  complexity: number;
}

// Activity interfaces
interface ActivityData {
  recentCommits: Commit[];
  recentIssues: ActivityIssue[];
  recentHotspots: ActivityHotspot[];
  activityMetrics: ActivityMetrics;
  contributors: Contributor[];
  activityTrend: ActivityTrend[];
}

interface Commit {
  id: string;
  author: string;
  message: string;
  timestamp: string;
  filesChanged: number;
  linesAdded: number;
  linesRemoved: number;
}

interface ActivityIssue {
  id: number;
  type: string;
  severity: string;
  status: string;
  author: string;
  timestamp: string;
  message: string;
}

interface ActivityHotspot {
  id: number;
  category: string;
  severity: string;
  status: string;
  author: string;
  timestamp: string;
  message: string;
}

interface ActivityMetrics {
  totalCommits: number;
  totalIssues: number;
  totalHotspots: number;
  activeContributors: number;
  averageCommitFrequency: number;
}

interface Contributor {
  name: string;
  commits: number;
  issues: number;
  hotspots: number;
  lastActivity: string;
}

interface ActivityTrend {
  date: string;
  commits: number;
  issues: number;
  hotspots: number;
}

// Administration interfaces
interface ProjectConfiguration {
  id: number;
  name: string;
  key: string;
  description: string;
  language: string;
  repositoryUrl: string;
  branch: string;
  qualityProfile: string;
  qualityGate: string;
  exclusions: string[];
  settings: ProjectSettings;
  permissions: ProjectPermissions;
}

interface ProjectSettings {
  scanSchedule: string;
  autoScan: boolean;
  notifications: NotificationSettings;
  integrations: IntegrationSettings;
}

interface NotificationSettings {
  email: boolean;
  slack: boolean;
  webhook: string;
}

interface IntegrationSettings {
  gitHub: boolean;
  gitLab: boolean;
  bitbucket: boolean;
  jenkins: boolean;
}

interface ProjectPermissions {
  users: UserPermission[];
  groups: GroupPermission[];
}

interface UserPermission {
  username: string;
  role: string;
  permissions: string[];
}

interface GroupPermission {
  groupName: string;
  role: string;
  permissions: string[];
}

const SASTProjectDetails: React.FC = () => {
  const { projectId } = useParams<{ projectId: string }>();
  const navigate = useNavigate();
  const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
  
  const [project, setProject] = useState<ProjectDetails | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'overview' | 'issues' | 'hotspots' | 'quality-gates' | 'coverage' | 'debt' | 'duplications' | 'security-reports' | 'reliability' | 'maintainability' | 'activity' | 'administration'>('overview');
  const [scanning, setScanning] = useState(false);

  // Issues state
  const [issues, setIssues] = useState<Issue[]>([]);
  const [filteredIssues, setFilteredIssues] = useState<Issue[]>([]);
  const [selectedIssue, setSelectedIssue] = useState<Issue | null>(null);
  const [showIssueModal, setShowIssueModal] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [filters, setFilters] = useState<IssueFilter>({
    type: [],
    severity: [],
    status: [],
    resolution: [],
    author: '',
    component: '',
  });
  const [sort, setSort] = useState<IssueSort>({ field: 'severity', direction: 'desc' });
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage] = useState(20);

  // Security Hotspots state
  const [hotspots, setHotspots] = useState<SecurityHotspot[]>([]);
  const [filteredHotspots, setFilteredHotspots] = useState<SecurityHotspot[]>([]);
  const [selectedHotspot, setSelectedHotspot] = useState<SecurityHotspot | null>(null);
  const [showHotspotModal, setShowHotspotModal] = useState(false);
  const [hotspotSearchTerm, setHotspotSearchTerm] = useState('');
  const [hotspotFilters, setHotspotFilters] = useState<HotspotFilter>({
    status: [],
    severity: [],
    category: [],
    securityCategory: [],
    vulnerabilityProbability: [],
    author: '',
    component: '',
  });
  const [hotspotSort, setHotspotSort] = useState<HotspotSort>({ field: 'severity', direction: 'desc' });
  const [hotspotCurrentPage, setHotspotCurrentPage] = useState(1);
  const [hotspotItemsPerPage] = useState(20);

  // Quality Gates state
  const [qualityGate, setQualityGate] = useState<QualityGate | null>(null);
  const [thresholds, setThresholds] = useState<QualityGateThreshold[]>([]);
  const [showThresholdModal, setShowThresholdModal] = useState(false);
  const [editingThreshold, setEditingThreshold] = useState<QualityGateThreshold | null>(null);

  // Coverage state
  const [coverageData, setCoverageData] = useState<CoverageData | null>(null);
  const [selectedFile, setSelectedFile] = useState<string | null>(null);
  const [showFileDetails, setShowFileDetails] = useState(false);

  // Technical Debt state
  const [debtData, setDebtData] = useState<TechnicalDebtData | null>(null);

  // Duplications state
  const [duplicationData, setDuplicationData] = useState<DuplicationData | null>(null);

  // Security Reports state
  const [securityReportData, setSecurityReportData] = useState<SecurityReportData | null>(null);

  // Reliability state
  const [reliabilityData, setReliabilityData] = useState<ReliabilityData | null>(null);

  // Maintainability state
  const [maintainabilityData, setMaintainabilityData] = useState<MaintainabilityData | null>(null);

  // Activity state
  const [activityData, setActivityData] = useState<ActivityData | null>(null);

  // Administration state
  const [projectConfiguration, setProjectConfiguration] = useState<ProjectConfiguration | null>(null);
  const [showConfigurationModal, setShowConfigurationModal] = useState(false);

  useEffect(() => {
    if (projectId) {
      fetchProjectDetails();
    }
  }, [projectId]);

  useEffect(() => {
    if (activeTab === 'issues' && projectId) {
      fetchIssues();
    }
  }, [activeTab, projectId]);

  useEffect(() => {
    filterAndSortIssues();
  }, [issues, searchTerm, filters, sort]);

  useEffect(() => {
    if (activeTab === 'hotspots' && projectId) {
      fetchSecurityHotspots();
    }
  }, [activeTab, projectId]);

  useEffect(() => {
    if (activeTab === 'hotspots') {
      filterAndSortHotspots();
    }
  }, [hotspots, hotspotSearchTerm, hotspotFilters, hotspotSort]);

  useEffect(() => {
    if (activeTab === 'quality-gates' && projectId) {
      fetchQualityGate();
    }
  }, [activeTab, projectId]);

  useEffect(() => {
    if (activeTab === 'coverage' && projectId) {
      fetchCoverageData();
    }
  }, [activeTab, projectId]);

  useEffect(() => {
    if (activeTab === 'debt' && projectId) {
      fetchTechnicalDebtData();
    }
  }, [activeTab, projectId]);

  useEffect(() => {
    if (activeTab === 'duplications' && projectId) {
      fetchDuplicationData();
    }
  }, [activeTab, projectId]);

  useEffect(() => {
    if (activeTab === 'security-reports' && projectId) {
      fetchSecurityReportData();
    }
  }, [activeTab, projectId]);

  useEffect(() => {
    if (activeTab === 'reliability' && projectId) {
      fetchReliabilityData();
    }
  }, [activeTab, projectId]);

  useEffect(() => {
    if (activeTab === 'maintainability' && projectId) {
      fetchMaintainabilityData();
    }
  }, [activeTab, projectId]);

  useEffect(() => {
    if (activeTab === 'activity' && projectId) {
      fetchActivityData();
    }
  }, [activeTab, projectId]);

  useEffect(() => {
    if (activeTab === 'administration' && projectId) {
      fetchProjectConfiguration();
    }
  }, [activeTab, projectId]);

  const fetchProjectDetails = async () => {
    try {
      const response = await fetch(`${API_URL}/api/v1/sast/projects/${projectId}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        setProject(data);
      } else {
        // Fallback to mock data
        setProject({
          id: parseInt(projectId!),
          name: 'Web Application Security',
          key: 'web-app-sec',
          language: 'JavaScript',
          repositoryUrl: 'https://github.com/example/web-app',
          branch: 'main',
          qualityGate: 'PASSED',
          maintainabilityRating: 'A',
          securityRating: 'B',
          reliabilityRating: 'A',
          vulnerabilityCount: 2,
          bugCount: 5,
          codeSmellCount: 12,
          securityHotspotCount: 3,
          linesOfCode: 15420,
          coverage: 78.5,
          technicalDebt: 2.5,
          lastAnalysis: '2024-01-15T10:30:00Z',
          lastScan: {
            id: 101,
            status: 'COMPLETED',
            timestamp: '2024-01-15T10:30:00Z',
            duration: '2m 34s'
          }
        });
      }
    } catch (error) {
      console.error('Error fetching project details:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleStartScan = async () => {
    if (!project) return;
    
    setScanning(true);
    try {
      const response = await fetch(`${API_URL}/api/v1/sast/scans`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          project_id: project.id,
          scan_type: 'full',
          branch: project.branch
        })
      });

      if (response.ok) {
        setTimeout(() => {
          fetchProjectDetails();
          setScanning(false);
        }, 2000);
      }
    } catch (error) {
      console.error('Error starting scan:', error);
      setScanning(false);
    }
  };

  const fetchIssues = async () => {
    try {
      // Mock data for now - replace with actual API call
      const mockIssues: Issue[] = [
        {
          id: 1,
          key: 'AXe8b9cK',
          type: 'VULNERABILITY',
          severity: 'CRITICAL',
          status: 'OPEN',
          component: 'src/main/java/com/example/controller/UserController.java',
          line: 45,
          message: 'Make sure this SQL injection is safe here.',
          effort: '5min',
          debt: '5min',
          author: 'john.doe@example.com',
          creationDate: '2024-01-15T10:30:00Z',
          updateDate: '2024-01-15T10:30:00Z',
          tags: ['sql-injection', 'security'],
        },
        {
          id: 2,
          key: 'BXf9c0dL',
          type: 'BUG',
          severity: 'MAJOR',
          status: 'CONFIRMED',
          component: 'src/main/java/com/example/service/UserService.java',
          line: 123,
          message: 'Fix this "NullPointerException" error.',
          effort: '10min',
          debt: '10min',
          author: 'jane.smith@example.com',
          creationDate: '2024-01-14T14:20:00Z',
          updateDate: '2024-01-15T09:15:00Z',
          tags: ['null-pointer', 'bug'],
        },
        {
          id: 3,
          key: 'CXg0d1eM',
          type: 'CODE_SMELL',
          severity: 'MINOR',
          status: 'OPEN',
          component: 'src/main/java/com/example/util/DateUtils.java',
          line: 67,
          message: 'Remove this unused import "java.util.Date".',
          effort: '2min',
          debt: '2min',
          author: 'mike.wilson@example.com',
          creationDate: '2024-01-13T16:45:00Z',
          updateDate: '2024-01-13T16:45:00Z',
          tags: ['unused-import', 'clean-code'],
        },
      ];
      setIssues(mockIssues);
    } catch (error) {
      console.error('Error fetching issues:', error);
    }
  };

  const filterAndSortIssues = () => {
    let filtered = [...issues];

    // Search filter
    if (searchTerm) {
      filtered = filtered.filter(issue =>
        issue.message.toLowerCase().includes(searchTerm.toLowerCase()) ||
        issue.component.toLowerCase().includes(searchTerm.toLowerCase()) ||
        issue.key.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    // Type filter
    if (filters.type.length > 0) {
      filtered = filtered.filter(issue => filters.type.includes(issue.type));
    }

    // Severity filter
    if (filters.severity.length > 0) {
      filtered = filtered.filter(issue => filters.severity.includes(issue.severity));
    }

    // Status filter
    if (filters.status.length > 0) {
      filtered = filtered.filter(issue => filters.status.includes(issue.status));
    }

    // Resolution filter
    if (filters.resolution.length > 0) {
      filtered = filtered.filter(issue => 
        issue.resolution && filters.resolution.includes(issue.resolution)
      );
    }

    // Author filter
    if (filters.author) {
      filtered = filtered.filter(issue =>
        issue.author.toLowerCase().includes(filters.author.toLowerCase())
      );
    }

    // Component filter
    if (filters.component) {
      filtered = filtered.filter(issue =>
        issue.component.toLowerCase().includes(filters.component.toLowerCase())
      );
    }

    // Sorting
    filtered.sort((a, b) => {
      const aValue = a[sort.field];
      const bValue = b[sort.field];
      
      if (typeof aValue === 'string' && typeof bValue === 'string') {
        return sort.direction === 'asc' 
          ? aValue.localeCompare(bValue)
          : bValue.localeCompare(aValue);
      }
      
      if (typeof aValue === 'number' && typeof bValue === 'number') {
        return sort.direction === 'asc' ? aValue - bValue : bValue - aValue;
      }
      
      return 0;
    });

    setFilteredIssues(filtered);
    setCurrentPage(1);
  };

  const handleSort = (field: keyof Issue) => {
    setSort(prev => ({
      field,
      direction: prev.field === field && prev.direction === 'asc' ? 'desc' : 'asc'
    }));
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'BLOCKER': return 'bg-red-600';
      case 'CRITICAL': return 'bg-red-500';
      case 'MAJOR': return 'bg-orange-500';
      case 'MINOR': return 'bg-yellow-500';
      case 'INFO': return 'bg-blue-500';
      default: return 'bg-gray-500';
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'VULNERABILITY': return <ShieldExclamationIcon className="w-4 h-4" />;
      case 'BUG': return <BugAntIcon className="w-4 h-4" />;
      case 'CODE_SMELL': return <CodeBracketIcon className="w-4 h-4" />;
      default: return <InformationCircleIcon className="w-4 h-4" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'OPEN': return 'text-red-600 bg-red-50';
      case 'CONFIRMED': return 'text-orange-600 bg-orange-50';
      case 'RESOLVED': return 'text-green-600 bg-green-50';
      case 'CLOSED': return 'text-gray-600 bg-gray-50';
      case 'REOPENED': return 'text-red-600 bg-red-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  const paginatedIssues = filteredIssues.slice(
    (currentPage - 1) * itemsPerPage,
    currentPage * itemsPerPage
  );

  const totalPages = Math.ceil(filteredIssues.length / itemsPerPage);

  const fetchSecurityHotspots = async () => {
    try {
      // Mock data for now - replace with actual API call
      const mockHotspots: SecurityHotspot[] = [
        {
          id: 1,
          key: 'HS-001',
          component: 'src/main/java/com/example/controller/UserController.java',
          line: 45,
          message: 'Make sure this SQL injection is safe here.',
          status: 'TO_REVIEW',
          severity: 'HIGH',
          category: 'SQL_INJECTION',
          vulnerabilityProbability: 'HIGH',
          securityCategory: 'OWASP_TOP_10',
          author: 'john.doe@example.com',
          creationDate: '2024-01-15T10:30:00Z',
          updateDate: '2024-01-15T10:30:00Z',
        },
        {
          id: 2,
          key: 'HS-002',
          component: 'src/main/java/com/example/service/UserService.java',
          line: 123,
          message: 'Check if this input validation is sufficient to prevent XSS.',
          status: 'REVIEWED',
          resolution: 'SAFE',
          severity: 'MEDIUM',
          category: 'XSS',
          vulnerabilityProbability: 'MEDIUM',
          securityCategory: 'OWASP_TOP_10',
          author: 'jane.smith@example.com',
          creationDate: '2024-01-14T14:20:00Z',
          updateDate: '2024-01-15T09:15:00Z',
          reviewer: 'security.team@example.com',
          reviewDate: '2024-01-15T09:15:00Z',
          comment: 'Input is properly sanitized, no XSS risk.',
        },
        {
          id: 3,
          key: 'HS-003',
          component: 'src/main/java/com/example/util/FileUtils.java',
          line: 67,
          message: 'Verify this file path is safe from path traversal attacks.',
          status: 'RESOLVED',
          resolution: 'FIXED',
          severity: 'HIGH',
          category: 'PATH_TRAVERSAL',
          vulnerabilityProbability: 'HIGH',
          securityCategory: 'OWASP_TOP_10',
          author: 'mike.wilson@example.com',
          creationDate: '2024-01-13T16:45:00Z',
          updateDate: '2024-01-14T11:30:00Z',
          reviewer: 'security.team@example.com',
          reviewDate: '2024-01-14T11:30:00Z',
          comment: 'Path validation implemented to prevent traversal.',
        },
      ];
      setHotspots(mockHotspots);
    } catch (error) {
      console.error('Error fetching security hotspots:', error);
    }
  };

  const filterAndSortHotspots = () => {
    let filtered = [...hotspots];

    // Search filter
    if (hotspotSearchTerm) {
      filtered = filtered.filter(hotspot =>
        hotspot.message.toLowerCase().includes(hotspotSearchTerm.toLowerCase()) ||
        hotspot.component.toLowerCase().includes(hotspotSearchTerm.toLowerCase()) ||
        hotspot.key.toLowerCase().includes(hotspotSearchTerm.toLowerCase())
      );
    }

    // Status filter
    if (hotspotFilters.status.length > 0) {
      filtered = filtered.filter(hotspot => hotspotFilters.status.includes(hotspot.status));
    }

    // Severity filter
    if (hotspotFilters.severity.length > 0) {
      filtered = filtered.filter(hotspot => hotspotFilters.severity.includes(hotspot.severity));
    }

    // Category filter
    if (hotspotFilters.category.length > 0) {
      filtered = filtered.filter(hotspot => hotspotFilters.category.includes(hotspot.category));
    }

    // Security Category filter
    if (hotspotFilters.securityCategory.length > 0) {
      filtered = filtered.filter(hotspot => hotspotFilters.securityCategory.includes(hotspot.securityCategory));
    }

    // Vulnerability Probability filter
    if (hotspotFilters.vulnerabilityProbability.length > 0) {
      filtered = filtered.filter(hotspot => hotspotFilters.vulnerabilityProbability.includes(hotspot.vulnerabilityProbability));
    }

    // Author filter
    if (hotspotFilters.author) {
      filtered = filtered.filter(hotspot =>
        hotspot.author.toLowerCase().includes(hotspotFilters.author.toLowerCase())
      );
    }

    // Component filter
    if (hotspotFilters.component) {
      filtered = filtered.filter(hotspot =>
        hotspot.component.toLowerCase().includes(hotspotFilters.component.toLowerCase())
      );
    }

    // Sorting
    filtered.sort((a, b) => {
      const aValue = a[hotspotSort.field];
      const bValue = b[hotspotSort.field];
      
      if (typeof aValue === 'string' && typeof bValue === 'string') {
        return hotspotSort.direction === 'asc' 
          ? aValue.localeCompare(bValue)
          : bValue.localeCompare(aValue);
      }
      
      if (typeof aValue === 'number' && typeof bValue === 'number') {
        return hotspotSort.direction === 'asc' ? aValue - bValue : bValue - aValue;
      }
      
      return 0;
    });

    setFilteredHotspots(filtered);
    setHotspotCurrentPage(1);
  };

  const handleHotspotSort = (field: keyof SecurityHotspot) => {
    setHotspotSort(prev => ({
      field,
      direction: prev.field === field && prev.direction === 'asc' ? 'desc' : 'asc'
    }));
  };

  const getHotspotSeverityColor = (severity: string) => {
    switch (severity) {
      case 'HIGH': return 'bg-red-600';
      case 'MEDIUM': return 'bg-orange-500';
      case 'LOW': return 'bg-yellow-500';
      default: return 'bg-gray-500';
    }
  };

  const getHotspotStatusColor = (status: string) => {
    switch (status) {
      case 'TO_REVIEW': return 'text-red-600 bg-red-50';
      case 'REVIEWED': return 'text-blue-600 bg-blue-50';
      case 'RESOLVED': return 'text-green-600 bg-green-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  const getHotspotCategoryIcon = (category: string) => {
    switch (category) {
      case 'SQL_INJECTION': return <ShieldExclamationIcon className="w-4 h-4" />;
      case 'XSS': return <ExclamationTriangleIcon className="w-4 h-4" />;
      case 'CSRF': return <ExclamationCircleIcon className="w-4 h-4" />;
      case 'PATH_TRAVERSAL': return <CodeBracketIcon className="w-4 h-4" />;
      case 'COMMAND_INJECTION': return <BugAntIcon className="w-4 h-4" />;
      default: return <InformationCircleIcon className="w-4 h-4" />;
    }
  };

  const getResolutionColor = (resolution?: string) => {
    switch (resolution) {
      case 'SAFE': return 'text-green-600 bg-green-50';
      case 'FIXED': return 'text-blue-600 bg-blue-50';
      case 'ACKNOWLEDGED': return 'text-yellow-600 bg-yellow-50';
      case 'FALSE_POSITIVE': return 'text-gray-600 bg-gray-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  const hotspotPaginatedItems = filteredHotspots.slice(
    (hotspotCurrentPage - 1) * hotspotItemsPerPage,
    hotspotCurrentPage * hotspotItemsPerPage
  );

  const hotspotTotalPages = Math.ceil(filteredHotspots.length / hotspotItemsPerPage);

  const fetchQualityGate = async () => {
    try {
      // Mock data for now - replace with actual API call
      const mockQualityGate: QualityGate = {
        id: 1,
        name: 'Default Quality Gate',
        status: 'PASSED',
        lastEvaluation: '2024-01-15T10:30:00Z',
        nextEvaluation: '2024-01-16T10:30:00Z',
        conditions: [
          {
            id: 1,
            metric: 'Reliability Rating',
            operator: 'GT',
            threshold: 1,
            actualValue: 1,
            status: 'PASSED',
            description: 'Reliability rating must be better than A',
            category: 'RELIABILITY',
          },
          {
            id: 2,
            metric: 'Security Rating',
            operator: 'GT',
            threshold: 1,
            actualValue: 1,
            status: 'PASSED',
            description: 'Security rating must be better than A',
            category: 'SECURITY',
          },
          {
            id: 3,
            metric: 'Maintainability Rating',
            operator: 'GT',
            threshold: 1,
            actualValue: 1,
            status: 'PASSED',
            description: 'Maintainability rating must be better than A',
            category: 'MAINTAINABILITY',
          },
          {
            id: 4,
            metric: 'Coverage',
            operator: 'GT',
            threshold: 80,
            actualValue: 85,
            status: 'PASSED',
            description: 'Code coverage must be greater than 80%',
            category: 'COVERAGE',
          },
          {
            id: 5,
            metric: 'Duplicated Lines',
            operator: 'LT',
            threshold: 3,
            actualValue: 2,
            status: 'PASSED',
            description: 'Duplicated lines must be less than 3%',
            category: 'DUPLICATIONS',
          },
        ],
      };

      const mockThresholds: QualityGateThreshold[] = [
        {
          metric: 'Reliability Rating',
          operator: 'GT',
          threshold: 1,
          description: 'Reliability rating must be better than A',
          category: 'RELIABILITY',
        },
        {
          metric: 'Security Rating',
          operator: 'GT',
          threshold: 1,
          description: 'Security rating must be better than A',
          category: 'SECURITY',
        },
        {
          metric: 'Maintainability Rating',
          operator: 'GT',
          threshold: 1,
          description: 'Maintainability rating must be better than A',
          category: 'MAINTAINABILITY',
        },
        {
          metric: 'Coverage',
          operator: 'GT',
          threshold: 80,
          description: 'Code coverage must be greater than 80%',
          category: 'COVERAGE',
        },
        {
          metric: 'Duplicated Lines',
          operator: 'LT',
          threshold: 3,
          description: 'Duplicated lines must be less than 3%',
          category: 'DUPLICATIONS',
        },
        {
          metric: 'Lines of Code',
          operator: 'LT',
          threshold: 1000,
          description: 'Project must have less than 1000 lines of code',
          category: 'SIZE',
        },
      ];

      setQualityGate(mockQualityGate);
      setThresholds(mockThresholds);
    } catch (error) {
      console.error('Error fetching quality gate:', error);
    }
  };

  const getConditionStatusColor = (status: string) => {
    switch (status) {
      case 'PASSED': return 'text-green-600 bg-green-50';
      case 'FAILED': return 'text-red-600 bg-red-50';
      case 'WARNING': return 'text-yellow-600 bg-yellow-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  const getConditionStatusIcon = (status: string) => {
    switch (status) {
      case 'PASSED': return <CheckIcon className="w-4 h-4" />;
      case 'FAILED': return <XCircleIcon className="w-4 h-4" />;
      case 'WARNING': return <ExclamationTriangleIcon className="w-4 h-4" />;
      default: return <InformationCircleIcon className="w-4 h-4" />;
    }
  };

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'RELIABILITY': return <CheckCircleIcon className="w-4 h-4" />;
      case 'SECURITY': return <ShieldExclamationIcon className="w-4 h-4" />;
      case 'MAINTAINABILITY': return <CodeBracketIcon className="w-4 h-4" />;
      case 'COVERAGE': return <BeakerIcon className="w-4 h-4" />;
      case 'DUPLICATIONS': return <DocumentTextIcon className="w-4 h-4" />;
      case 'SIZE': return <ChartBarIcon className="w-4 h-4" />;
      default: return <InformationCircleIcon className="w-4 h-4" />;
    }
  };

  const handleEditThreshold = (threshold: QualityGateThreshold) => {
    setEditingThreshold(threshold);
    setShowThresholdModal(true);
  };

  const handleSaveThreshold = (updatedThreshold: QualityGateThreshold) => {
    setThresholds(prev => 
      prev.map(t => 
        t.metric === updatedThreshold.metric ? updatedThreshold : t
      )
    );
    setShowThresholdModal(false);
    setEditingThreshold(null);
  };

  const fetchCoverageData = async () => {
    try {
      // Mock data for now - replace with actual API call
      const mockCoverageData: CoverageData = {
        overall: 85,
        lines: 1200,
        functions: 150,
        branches: 300,
        statements: 800,
        uncoveredLines: [45, 67, 89, 123, 156],
        uncoveredFunctions: ['validateInput', 'processData', 'handleError'],
        uncoveredBranches: ['if (user.isAdmin)', 'switch (status)', 'try-catch block'],
        fileCoverage: [
          {
            file: 'src/main/java/com/example/controller/UserController.java',
            lines: 200,
            coveredLines: 180,
            coverage: 90,
            uncoveredLines: [45, 67, 89],
            complexity: 15,
            lastModified: '2024-01-15T10:30:00Z',
          },
          {
            file: 'src/main/java/com/example/service/UserService.java',
            lines: 150,
            coveredLines: 120,
            coverage: 80,
            uncoveredLines: [23, 45, 67],
            complexity: 12,
            lastModified: '2024-01-14T14:20:00Z',
          },
          {
            file: 'src/main/java/com/example/util/DateUtils.java',
            lines: 80,
            coveredLines: 75,
            coverage: 94,
            uncoveredLines: [12],
            complexity: 8,
            lastModified: '2024-01-13T16:45:00Z',
          },
          {
            file: 'src/main/java/com/example/model/User.java',
            lines: 50,
            coveredLines: 45,
            coverage: 90,
            uncoveredLines: [15, 23],
            complexity: 5,
            lastModified: '2024-01-12T09:15:00Z',
          },
        ],
        trendData: [
          { date: '2024-01-10', overall: 75, lines: 1000, functions: 120, branches: 250, statements: 600 },
          { date: '2024-01-11', overall: 78, lines: 1050, functions: 125, branches: 260, statements: 650 },
          { date: '2024-01-12', overall: 80, lines: 1100, functions: 130, branches: 270, statements: 700 },
          { date: '2024-01-13', overall: 82, lines: 1150, functions: 135, branches: 280, statements: 750 },
          { date: '2024-01-14', overall: 84, lines: 1180, functions: 140, branches: 290, statements: 780 },
          { date: '2024-01-15', overall: 85, lines: 1200, functions: 150, branches: 300, statements: 800 },
        ],
      };

      setCoverageData(mockCoverageData);
    } catch (error) {
      console.error('Error fetching coverage data:', error);
    }
  };

  const getCoverageColor = (coverage: number) => {
    if (coverage >= 90) return 'text-green-600 bg-green-100';
    if (coverage >= 80) return 'text-blue-600 bg-blue-100';
    if (coverage >= 70) return 'text-yellow-600 bg-yellow-100';
    return 'text-red-600 bg-red-100';
  };

  const getCoverageStatus = (coverage: number) => {
    if (coverage >= 90) return 'Excellent';
    if (coverage >= 80) return 'Good';
    if (coverage >= 70) return 'Fair';
    return 'Poor';
  };

  const fetchTechnicalDebtData = async () => {
    try {
      // Mock data for now - replace with actual API call
      const mockDebtData: TechnicalDebtData = {
        totalDebt: 120,
        debtRatio: 8.5,
        debtBreakdown: [
          {
            category: 'CODE_SMELL',
            count: 45,
            effort: 60,
            percentage: 50,
            description: 'Code quality issues that need refactoring',
          },
          {
            category: 'BUG',
            count: 20,
            effort: 30,
            percentage: 25,
            description: 'Bugs that need fixing',
          },
          {
            category: 'VULNERABILITY',
            count: 15,
            effort: 20,
            percentage: 17,
            description: 'Security vulnerabilities to address',
          },
          {
            category: 'SECURITY_HOTSPOT',
            count: 8,
            effort: 8,
            percentage: 7,
            description: 'Security hotspots requiring review',
          },
          {
            category: 'DUPLICATION',
            count: 2,
            effort: 2,
            percentage: 1,
            description: 'Code duplication to eliminate',
          },
        ],
        effortEstimation: {
          totalEffort: 120,
          effortByCategory: [
            { category: 'CODE_SMELL', effort: 60, count: 45, averageEffort: 1.33 },
            { category: 'BUG', effort: 30, count: 20, averageEffort: 1.5 },
            { category: 'VULNERABILITY', effort: 20, count: 15, averageEffort: 1.33 },
            { category: 'SECURITY_HOTSPOT', effort: 8, count: 8, averageEffort: 1.0 },
            { category: 'DUPLICATION', effort: 2, count: 2, averageEffort: 1.0 },
          ],
          effortBySeverity: [
            { severity: 'BLOCKER', effort: 15, count: 5 },
            { severity: 'CRITICAL', effort: 25, count: 10 },
            { severity: 'MAJOR', effort: 45, count: 30 },
            { severity: 'MINOR', effort: 30, count: 40 },
            { severity: 'INFO', effort: 5, count: 15 },
          ],
        },
        debtTrend: [
          { date: '2024-01-10', totalDebt: 150, debtRatio: 10.2, newDebt: 20, resolvedDebt: 5 },
          { date: '2024-01-11', totalDebt: 145, debtRatio: 9.8, newDebt: 15, resolvedDebt: 10 },
          { date: '2024-01-12', totalDebt: 140, debtRatio: 9.5, newDebt: 10, resolvedDebt: 15 },
          { date: '2024-01-13', totalDebt: 135, debtRatio: 9.1, newDebt: 8, resolvedDebt: 13 },
          { date: '2024-01-14', totalDebt: 130, debtRatio: 8.8, newDebt: 12, resolvedDebt: 17 },
          { date: '2024-01-15', totalDebt: 120, debtRatio: 8.5, newDebt: 5, resolvedDebt: 15 },
        ],
        debtByCategory: [
          { category: 'Code Smells', debt: 60, count: 45, percentage: 50, color: '#3b82f6' },
          { category: 'Bugs', debt: 30, count: 20, percentage: 25, color: '#ef4444' },
          { category: 'Vulnerabilities', debt: 20, count: 15, percentage: 17, color: '#f59e0b' },
          { category: 'Security Hotspots', debt: 8, count: 8, percentage: 7, color: '#8b5cf6' },
          { category: 'Duplications', debt: 2, count: 2, percentage: 1, color: '#10b981' },
        ],
        debtBySeverity: [
          { severity: 'Blocker', debt: 15, count: 5, percentage: 12.5, color: '#dc2626' },
          { severity: 'Critical', debt: 25, count: 10, percentage: 20.8, color: '#ea580c' },
          { severity: 'Major', debt: 45, count: 30, percentage: 37.5, color: '#d97706' },
          { severity: 'Minor', debt: 30, count: 40, percentage: 25, color: '#059669' },
          { severity: 'Info', debt: 5, count: 15, percentage: 4.2, color: '#6b7280' },
        ],
      };

      setDebtData(mockDebtData);
    } catch (error) {
      console.error('Error fetching technical debt data:', error);
    }
  };

  const formatDebtTime = (minutes: number) => {
    if (minutes < 60) return `${minutes}m`;
    const hours = Math.floor(minutes / 60);
    const remainingMinutes = minutes % 60;
    if (remainingMinutes === 0) return `${hours}h`;
    return `${hours}h ${remainingMinutes}m`;
  };

  const getDebtRatioColor = (ratio: number) => {
    if (ratio <= 5) return 'text-green-600 bg-green-100';
    if (ratio <= 10) return 'text-yellow-600 bg-yellow-100';
    if (ratio <= 20) return 'text-orange-600 bg-orange-100';
    return 'text-red-600 bg-red-100';
  };

  const getDebtRatioStatus = (ratio: number) => {
    if (ratio <= 5) return 'Excellent';
    if (ratio <= 10) return 'Good';
    if (ratio <= 20) return 'Fair';
    return 'Poor';
  };

  const fetchDuplicationData = async () => {
    try {
      // Mock data for now - replace with actual API call
      const mockDuplicationData: DuplicationData = {
        duplicatedLines: 450,
        duplicatedFiles: 12,
        duplicatedBlocks: 25,
        duplicationDensity: 3.2,
        duplicationsByLanguage: [
          { language: 'JavaScript', duplicatedLines: 200, duplicatedFiles: 5, duplicationDensity: 4.1, color: '#3b82f6' },
          { language: 'Java', duplicatedLines: 150, duplicatedFiles: 4, duplicationDensity: 2.8, color: '#ef4444' },
          { language: 'Python', duplicatedLines: 100, duplicatedFiles: 3, duplicationDensity: 1.9, color: '#10b981' },
        ],
        duplicationsByFile: [
          { file: 'src/main/java/com/example/controller/UserController.java', duplicatedLines: 45, duplicatedBlocks: 3, duplicationDensity: 5.2, lastModified: '2024-01-15T10:30:00Z' },
          { file: 'src/main/java/com/example/service/UserService.java', duplicatedLines: 38, duplicatedBlocks: 2, duplicationDensity: 4.1, lastModified: '2024-01-14T14:20:00Z' },
          { file: 'src/main/java/com/example/util/DateUtils.java', duplicatedLines: 25, duplicatedBlocks: 1, duplicationDensity: 3.8, lastModified: '2024-01-13T16:45:00Z' },
        ],
        duplicationTrend: [
          { date: '2024-01-10', duplicatedLines: 500, duplicatedFiles: 15, duplicationDensity: 3.8 },
          { date: '2024-01-11', duplicatedLines: 480, duplicatedFiles: 14, duplicationDensity: 3.6 },
          { date: '2024-01-12', duplicatedLines: 470, duplicatedFiles: 13, duplicationDensity: 3.4 },
          { date: '2024-01-13', duplicatedLines: 460, duplicatedFiles: 12, duplicationDensity: 3.3 },
          { date: '2024-01-14', duplicatedLines: 455, duplicatedFiles: 12, duplicationDensity: 3.2 },
          { date: '2024-01-15', duplicatedLines: 450, duplicatedFiles: 12, duplicationDensity: 3.2 },
        ],
      };
      setDuplicationData(mockDuplicationData);
    } catch (error) {
      console.error('Error fetching duplication data:', error);
    }
  };

  const fetchSecurityReportData = async () => {
    try {
      // Mock data for now - replace with actual API call
      const mockSecurityReportData: SecurityReportData = {
        overallSecurityRating: 'B',
        securityScore: 75,
        vulnerabilitiesByCategory: [
          { category: 'SQL Injection', count: 3, severity: 'CRITICAL', percentage: 25, color: '#ef4444' },
          { category: 'XSS', count: 2, severity: 'MAJOR', percentage: 17, color: '#f59e0b' },
          { category: 'CSRF', count: 1, severity: 'MAJOR', percentage: 8, color: '#f59e0b' },
          { category: 'Path Traversal', count: 2, severity: 'MINOR', percentage: 17, color: '#10b981' },
          { category: 'Weak Cryptography', count: 4, severity: 'MINOR', percentage: 33, color: '#10b981' },
        ],
        owaspTop10Mapping: [
          { category: 'A01:2021 - Broken Access Control', count: 2, severity: 'CRITICAL', description: 'Access control vulnerabilities', color: '#ef4444' },
          { category: 'A02:2021 - Cryptographic Failures', count: 4, severity: 'MAJOR', description: 'Weak cryptography implementation', color: '#f59e0b' },
          { category: 'A03:2021 - Injection', count: 5, severity: 'CRITICAL', description: 'SQL injection and XSS vulnerabilities', color: '#ef4444' },
          { category: 'A05:2021 - Security Misconfiguration', count: 1, severity: 'MINOR', description: 'Security configuration issues', color: '#10b981' },
        ],
        cweMapping: [
          { cweId: 'CWE-89', name: 'SQL Injection', count: 3, severity: 'CRITICAL', description: 'SQL injection vulnerabilities' },
          { cweId: 'CWE-79', name: 'Cross-site Scripting', count: 2, severity: 'MAJOR', description: 'XSS vulnerabilities' },
          { cweId: 'CWE-352', name: 'Cross-Site Request Forgery', count: 1, severity: 'MAJOR', description: 'CSRF vulnerabilities' },
          { cweId: 'CWE-22', name: 'Path Traversal', count: 2, severity: 'MINOR', description: 'Path traversal vulnerabilities' },
        ],
        securityTrend: [
          { date: '2024-01-10', vulnerabilities: 15, securityScore: 65, securityRating: 'C' },
          { date: '2024-01-11', vulnerabilities: 14, securityScore: 68, securityRating: 'C' },
          { date: '2024-01-12', vulnerabilities: 13, securityScore: 70, securityRating: 'B' },
          { date: '2024-01-13', vulnerabilities: 12, securityScore: 72, securityRating: 'B' },
          { date: '2024-01-14', vulnerabilities: 12, securityScore: 74, securityRating: 'B' },
          { date: '2024-01-15', vulnerabilities: 12, securityScore: 75, securityRating: 'B' },
        ],
        securityHotspots: [
          { category: 'SQL Injection', count: 3, status: 'TO_REVIEW', severity: 'HIGH' },
          { category: 'XSS', count: 2, status: 'REVIEWED', severity: 'MEDIUM' },
          { category: 'CSRF', count: 1, status: 'RESOLVED', severity: 'HIGH' },
        ],
      };
      setSecurityReportData(mockSecurityReportData);
    } catch (error) {
      console.error('Error fetching security report data:', error);
    }
  };

  const fetchReliabilityData = async () => {
    try {
      // Mock data for now - replace with actual API call
      const mockReliabilityData: ReliabilityData = {
        reliabilityRating: 'A',
        bugCount: 8,
        bugDensity: 0.5,
        bugsBySeverity: [
          { severity: 'BLOCKER', count: 1, percentage: 12.5, color: '#dc2626' },
          { severity: 'CRITICAL', count: 2, percentage: 25, color: '#ea580c' },
          { severity: 'MAJOR', count: 3, percentage: 37.5, color: '#d97706' },
          { severity: 'MINOR', count: 2, percentage: 25, color: '#059669' },
        ],
        bugsByCategory: [
          { category: 'Null Pointer Exception', count: 3, description: 'Null pointer dereference bugs', color: '#ef4444' },
          { category: 'Array Index Out of Bounds', count: 2, description: 'Array access violations', color: '#f59e0b' },
          { category: 'Resource Leak', count: 2, description: 'Resource management issues', color: '#10b981' },
          { category: 'Logic Error', count: 1, description: 'Logical programming errors', color: '#3b82f6' },
        ],
        reliabilityTrend: [
          { date: '2024-01-10', bugCount: 12, bugDensity: 0.8, reliabilityRating: 'B' },
          { date: '2024-01-11', bugCount: 11, bugDensity: 0.7, reliabilityRating: 'B' },
          { date: '2024-01-12', bugCount: 10, bugDensity: 0.6, reliabilityRating: 'A' },
          { date: '2024-01-13', bugCount: 9, bugDensity: 0.6, reliabilityRating: 'A' },
          { date: '2024-01-14', bugCount: 8, bugDensity: 0.5, reliabilityRating: 'A' },
          { date: '2024-01-15', bugCount: 8, bugDensity: 0.5, reliabilityRating: 'A' },
        ],
        newBugs: 2,
        resolvedBugs: 6,
      };
      setReliabilityData(mockReliabilityData);
    } catch (error) {
      console.error('Error fetching reliability data:', error);
    }
  };

  const fetchMaintainabilityData = async () => {
    try {
      // Mock data for now - replace with actual API call
      const mockMaintainabilityData: MaintainabilityData = {
        maintainabilityRating: 'A',
        codeSmellCount: 25,
        codeSmellDensity: 1.6,
        complexity: 15,
        cognitiveComplexity: 8,
        codeSmellsByCategory: [
          { category: 'Code Smells', count: 15, description: 'General code quality issues', color: '#3b82f6' },
          { category: 'Unused Code', count: 5, description: 'Dead code and unused variables', color: '#10b981' },
          { category: 'Complexity', count: 3, description: 'High complexity methods', color: '#f59e0b' },
          { category: 'Naming', count: 2, description: 'Poor naming conventions', color: '#8b5cf6' },
        ],
        maintainabilityTrend: [
          { date: '2024-01-10', codeSmellCount: 30, maintainabilityRating: 'B', complexity: 18 },
          { date: '2024-01-11', codeSmellCount: 28, maintainabilityRating: 'B', complexity: 17 },
          { date: '2024-01-12', codeSmellCount: 27, maintainabilityRating: 'A', complexity: 16 },
          { date: '2024-01-13', codeSmellCount: 26, maintainabilityRating: 'A', complexity: 16 },
          { date: '2024-01-14', codeSmellCount: 25, maintainabilityRating: 'A', complexity: 15 },
          { date: '2024-01-15', codeSmellCount: 25, maintainabilityRating: 'A', complexity: 15 },
        ],
      };
      setMaintainabilityData(mockMaintainabilityData);
    } catch (error) {
      console.error('Error fetching maintainability data:', error);
    }
  };

  const fetchActivityData = async () => {
    try {
      // Mock data for now - replace with actual API call
      const mockActivityData: ActivityData = {
        recentCommits: [
          { id: 'abc123', author: 'john.doe@example.com', message: 'Fix SQL injection vulnerability', timestamp: '2024-01-15T10:30:00Z', filesChanged: 3, linesAdded: 15, linesRemoved: 8 },
          { id: 'def456', author: 'jane.smith@example.com', message: 'Add input validation', timestamp: '2024-01-15T09:15:00Z', filesChanged: 2, linesAdded: 12, linesRemoved: 5 },
          { id: 'ghi789', author: 'mike.wilson@example.com', message: 'Refactor user service', timestamp: '2024-01-15T08:45:00Z', filesChanged: 5, linesAdded: 25, linesRemoved: 10 },
        ],
        recentIssues: [
          { id: 1, type: 'VULNERABILITY', severity: 'CRITICAL', status: 'RESOLVED', author: 'john.doe@example.com', timestamp: '2024-01-15T10:30:00Z', message: 'SQL injection fixed' },
          { id: 2, type: 'BUG', severity: 'MAJOR', status: 'OPEN', author: 'jane.smith@example.com', timestamp: '2024-01-15T09:15:00Z', message: 'Null pointer exception' },
          { id: 3, type: 'CODE_SMELL', severity: 'MINOR', status: 'OPEN', author: 'mike.wilson@example.com', timestamp: '2024-01-15T08:45:00Z', message: 'Unused import detected' },
        ],
        recentHotspots: [
          { id: 1, category: 'SQL_INJECTION', severity: 'HIGH', status: 'RESOLVED', author: 'john.doe@example.com', timestamp: '2024-01-15T10:30:00Z', message: 'SQL injection hotspot resolved' },
          { id: 2, category: 'XSS', severity: 'MEDIUM', status: 'REVIEWED', author: 'jane.smith@example.com', timestamp: '2024-01-15T09:15:00Z', message: 'XSS hotspot reviewed' },
        ],
        activityMetrics: {
          totalCommits: 45,
          totalIssues: 12,
          totalHotspots: 8,
          activeContributors: 5,
          averageCommitFrequency: 3.2,
        },
        contributors: [
          { name: 'john.doe@example.com', commits: 15, issues: 4, hotspots: 3, lastActivity: '2024-01-15T10:30:00Z' },
          { name: 'jane.smith@example.com', commits: 12, issues: 3, hotspots: 2, lastActivity: '2024-01-15T09:15:00Z' },
          { name: 'mike.wilson@example.com', commits: 10, issues: 2, hotspots: 1, lastActivity: '2024-01-15T08:45:00Z' },
          { name: 'sarah.jones@example.com', commits: 8, issues: 3, hotspots: 2, lastActivity: '2024-01-14T16:20:00Z' },
        ],
        activityTrend: [
          { date: '2024-01-10', commits: 5, issues: 2, hotspots: 1 },
          { date: '2024-01-11', commits: 4, issues: 1, hotspots: 0 },
          { date: '2024-01-12', commits: 6, issues: 3, hotspots: 2 },
          { date: '2024-01-13', commits: 3, issues: 2, hotspots: 1 },
          { date: '2024-01-14', commits: 4, issues: 1, hotspots: 0 },
          { date: '2024-01-15', commits: 3, issues: 2, hotspots: 2 },
        ],
      };
      setActivityData(mockActivityData);
    } catch (error) {
      console.error('Error fetching activity data:', error);
    }
  };

  const fetchProjectConfiguration = async () => {
    try {
      // Mock data for now - replace with actual API call
      const mockProjectConfiguration: ProjectConfiguration = {
        id: 1,
        name: 'Web Application Security',
        key: 'web-app-sec',
        description: 'Main web application security project',
        language: 'JavaScript',
        repositoryUrl: 'https://github.com/example/web-app',
        branch: 'main',
        qualityProfile: 'Sonar way',
        qualityGate: 'Default Quality Gate',
        exclusions: ['**/node_modules/**', '**/dist/**', '**/coverage/**'],
        settings: {
          scanSchedule: '0 2 * * *', // Daily at 2 AM
          autoScan: true,
          notifications: {
            email: true,
            slack: false,
            webhook: 'https://hooks.slack.com/services/xxx/yyy/zzz',
          },
          integrations: {
            gitHub: true,
            gitLab: false,
            bitbucket: false,
            jenkins: true,
          },
        },
        permissions: {
          users: [
            { username: 'john.doe@example.com', role: 'Admin', permissions: ['read', 'write', 'admin'] },
            { username: 'jane.smith@example.com', role: 'User', permissions: ['read', 'write'] },
            { username: 'mike.wilson@example.com', role: 'User', permissions: ['read'] },
          ],
          groups: [
            { groupName: 'developers', role: 'User', permissions: ['read', 'write'] },
            { groupName: 'security-team', role: 'Admin', permissions: ['read', 'write', 'admin'] },
          ],
        },
      };
      setProjectConfiguration(mockProjectConfiguration);
    } catch (error) {
      console.error('Error fetching project configuration:', error);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  if (!project) {
    return (
      <div className="p-6">
        <div className="text-center">
          <h2 className="text-xl font-semibold text-gray-900">Project not found</h2>
          <p className="text-gray-600 mt-2">The requested project could not be found.</p>
          <button
            onClick={() => navigate('/sast/projects')}
            className="mt-4 inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700"
          >
            <ArrowLeftIcon className="w-4 h-4 mr-2" />
            Back to Projects
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white shadow-sm border-b border-gray-200">
        <div className="px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <button
                onClick={() => navigate('/sast/projects')}
                className="inline-flex items-center p-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50"
              >
                <ArrowLeftIcon className="w-4 h-4" />
              </button>
              <div>
                <h1 className="text-2xl font-bold text-gray-900">{project.name}</h1>
                <p className="text-sm text-gray-600">{project.key} • {project.language}</p>
              </div>
            </div>
            <div className="flex items-center space-x-3">
              <button
                onClick={handleStartScan}
                disabled={scanning}
                className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50"
              >
                {scanning ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                    Scanning...
                  </>
                ) : (
                  <>
                    <PlayIcon className="w-4 h-4 mr-2" />
                    Start Scan
                  </>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="px-6">
          <nav className="flex space-x-8">
            {[
              { id: 'overview', name: 'Overview', icon: ChartBarIcon },
              { id: 'issues', name: 'Issues', icon: ExclamationTriangleIcon },
              { id: 'hotspots', name: 'Security Hotspots', icon: ShieldExclamationIcon },
              { id: 'quality-gates', name: 'Quality Gates', icon: CheckCircleIcon },
              { id: 'quality-management', name: 'Quality Management', icon: Cog6ToothIcon },
              { id: 'coverage', name: 'Coverage', icon: BeakerIcon },
              { id: 'debt', name: 'Technical Debt', icon: ClockIcon },
              { id: 'duplications', name: 'Duplications', icon: DocumentTextIcon },
              { id: 'security-reports', name: 'Security Reports', icon: ShieldExclamationIcon },
              { id: 'reliability', name: 'Reliability', icon: CheckCircleIcon },
              { id: 'maintainability', name: 'Maintainability', icon: CodeBracketIcon },
              { id: 'activity', name: 'Activity', icon: ArrowPathIcon },
              { id: 'administration', name: 'Administration', icon: Cog6ToothIcon }
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`flex items-center space-x-2 py-4 px-1 border-b-2 font-medium text-sm ${
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <tab.icon className="w-4 h-4" />
                <span>{tab.name}</span>
              </button>
            ))}
          </nav>
        </div>
      </div>

      {/* Content */}
      <div className="p-6">
        {activeTab === 'overview' && (
          <ProjectOverview project={project} />
        )}
        {activeTab === 'issues' && (
          <div className="space-y-6">
            {/* Issues Header */}
            <div className="flex justify-between items-center">
              <div>
                <h3 className="text-lg font-medium text-gray-900">Issues</h3>
                <p className="text-sm text-gray-600">
                  {filteredIssues.length} issues found
                </p>
              </div>
              <div className="flex space-x-2">
                <button className="inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50">
                  <FunnelIcon className="w-4 h-4 mr-2" />
                  Export
                </button>
              </div>
            </div>

            {/* Search and Filters */}
            <div className="bg-white border border-gray-200 rounded-lg p-4">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {/* Search */}
                <div className="lg:col-span-2">
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Search
                  </label>
                  <div className="relative">
                    <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                    <input
                      type="text"
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      placeholder="Search issues, components, or keys..."
                      className="pl-10 w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                </div>

                {/* Type Filter */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Type
                  </label>
                  <select
                    multiple
                    value={filters.type}
                    onChange={(e) => setFilters(prev => ({
                      ...prev,
                      type: Array.from(e.target.selectedOptions, option => option.value)
                    }))}
                    className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="VULNERABILITY">Vulnerability</option>
                    <option value="BUG">Bug</option>
                    <option value="CODE_SMELL">Code Smell</option>
                  </select>
                </div>

                {/* Severity Filter */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Severity
                  </label>
                  <select
                    multiple
                    value={filters.severity}
                    onChange={(e) => setFilters(prev => ({
                      ...prev,
                      severity: Array.from(e.target.selectedOptions, option => option.value)
                    }))}
                    className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="BLOCKER">Blocker</option>
                    <option value="CRITICAL">Critical</option>
                    <option value="MAJOR">Major</option>
                    <option value="MINOR">Minor</option>
                    <option value="INFO">Info</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
                {/* Status Filter */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Status
                  </label>
                  <select
                    multiple
                    value={filters.status}
                    onChange={(e) => setFilters(prev => ({
                      ...prev,
                      status: Array.from(e.target.selectedOptions, option => option.value)
                    }))}
                    className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="OPEN">Open</option>
                    <option value="CONFIRMED">Confirmed</option>
                    <option value="RESOLVED">Resolved</option>
                    <option value="CLOSED">Closed</option>
                    <option value="REOPENED">Reopened</option>
                  </select>
                </div>

                {/* Author Filter */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Author
                  </label>
                  <input
                    type="text"
                    value={filters.author}
                    onChange={(e) => setFilters(prev => ({ ...prev, author: e.target.value }))}
                    placeholder="Filter by author..."
                    className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>

                {/* Component Filter */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Component
                  </label>
                  <input
                    type="text"
                    value={filters.component}
                    onChange={(e) => setFilters(prev => ({ ...prev, component: e.target.value }))}
                    placeholder="Filter by component..."
                    className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
              </div>
            </div>

            {/* Issues Table */}
            <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100" onClick={() => handleSort('key')}>
                        <div className="flex items-center">
                          Key
                          {sort.field === 'key' && (
                            <ChevronUpIcon className={`w-4 h-4 ml-1 ${sort.direction === 'desc' ? 'rotate-180' : ''}`} />
                          )}
                        </div>
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100" onClick={() => handleSort('type')}>
                        <div className="flex items-center">
                          Type
                          {sort.field === 'type' && (
                            <ChevronUpIcon className={`w-4 h-4 ml-1 ${sort.direction === 'desc' ? 'rotate-180' : ''}`} />
                          )}
                        </div>
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100" onClick={() => handleSort('severity')}>
                        <div className="flex items-center">
                          Severity
                          {sort.field === 'severity' && (
                            <ChevronUpIcon className={`w-4 h-4 ml-1 ${sort.direction === 'desc' ? 'rotate-180' : ''}`} />
                          )}
                        </div>
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100" onClick={() => handleSort('status')}>
                        <div className="flex items-center">
                          Status
                          {sort.field === 'status' && (
                            <ChevronUpIcon className={`w-4 h-4 ml-1 ${sort.direction === 'desc' ? 'rotate-180' : ''}`} />
                          )}
                        </div>
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Component</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Message</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100" onClick={() => handleSort('creationDate')}>
                        <div className="flex items-center">
                          Created
                          {sort.field === 'creationDate' && (
                            <ChevronUpIcon className={`w-4 h-4 ml-1 ${sort.direction === 'desc' ? 'rotate-180' : ''}`} />
                          )}
                        </div>
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {paginatedIssues.map((issue) => (
                      <tr key={issue.id} className="hover:bg-gray-50">
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                          {issue.key}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center">
                            {getTypeIcon(issue.type)}
                            <span className="ml-2 text-sm text-gray-900">
                              {issue.type.replace('_', ' ')}
                            </span>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium text-white ${getSeverityColor(issue.severity)}`}>
                            {issue.severity}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(issue.status)}`}>
                            {issue.status}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          <div className="max-w-xs truncate" title={issue.component}>
                            {issue.component.split('/').pop()}
                          </div>
                          <div className="text-xs text-gray-500">Line {issue.line}</div>
                        </td>
                        <td className="px-6 py-4 text-sm text-gray-900">
                          <div className="max-w-md truncate" title={issue.message}>
                            {issue.message}
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {new Date(issue.creationDate).toLocaleDateString()}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                          <button
                            onClick={() => {
                              setSelectedIssue(issue);
                              setShowIssueModal(true);
                            }}
                            className="text-blue-600 hover:text-blue-900"
                          >
                            <EyeIcon className="w-4 h-4" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Pagination */}
              {totalPages > 1 && (
                <div className="bg-white px-4 py-3 flex items-center justify-between border-t border-gray-200 sm:px-6">
                  <div className="flex-1 flex justify-between sm:hidden">
                    <button
                      onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                      disabled={currentPage === 1}
                      className="relative inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50"
                    >
                      Previous
                    </button>
                    <button
                      onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
                      disabled={currentPage === totalPages}
                      className="ml-3 relative inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50"
                    >
                      Next
                    </button>
                  </div>
                  <div className="hidden sm:flex-1 sm:flex sm:items-center sm:justify-between">
                    <div>
                      <p className="text-sm text-gray-700">
                        Showing{' '}
                        <span className="font-medium">{(currentPage - 1) * itemsPerPage + 1}</span>
                        {' '}to{' '}
                        <span className="font-medium">
                          {Math.min(currentPage * itemsPerPage, filteredIssues.length)}
                        </span>
                        {' '}of{' '}
                        <span className="font-medium">{filteredIssues.length}</span>
                        {' '}results
                      </p>
                    </div>
                    <div>
                      <nav className="relative z-0 inline-flex rounded-md shadow-sm -space-x-px">
                        <button
                          onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                          disabled={currentPage === 1}
                          className="relative inline-flex items-center px-2 py-2 rounded-l-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 disabled:opacity-50"
                        >
                          Previous
                        </button>
                        {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                          const page = i + 1;
                          return (
                            <button
                              key={page}
                              onClick={() => setCurrentPage(page)}
                              className={`relative inline-flex items-center px-4 py-2 border text-sm font-medium ${
                                currentPage === page
                                  ? 'z-10 bg-blue-50 border-blue-500 text-blue-600'
                                  : 'bg-white border-gray-300 text-gray-500 hover:bg-gray-50'
                              }`}
                            >
                              {page}
                            </button>
                          );
                        })}
                        <button
                          onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
                          disabled={currentPage === totalPages}
                          className="relative inline-flex items-center px-2 py-2 rounded-r-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 disabled:opacity-50"
                        >
                          Next
                        </button>
                      </nav>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
        {activeTab === 'quality-management' && (
          <div className="space-y-6">
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Quality Management</h3>
              <p className="text-sm text-gray-600 mb-4">Open the full Quality Management view to manage Quality Profiles and Quality Rules.</p>
              <a
                href="/sast/quality-management"
                className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700"
              >
                Go to Quality Management
              </a>
            </div>
          </div>
        )}
        {activeTab === 'hotspots' && (
          <div className="space-y-6">
            {/* Security Hotspots Header */}
            <div className="flex justify-between items-center">
              <div>
                <h3 className="text-lg font-medium text-gray-900">Security Hotspots</h3>
                <p className="text-sm text-gray-600">
                  {filteredHotspots.length} hotspots found
                </p>
              </div>
              <div className="flex space-x-2">
                <button className="inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50">
                  <FunnelIcon className="w-4 h-4 mr-2" />
                  Export
                </button>
              </div>
            </div>

            {/* Search and Filters */}
            <div className="bg-white border border-gray-200 rounded-lg p-4">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {/* Search */}
                <div className="lg:col-span-2">
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Search
                  </label>
                  <div className="relative">
                    <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                    <input
                      type="text"
                      value={hotspotSearchTerm}
                      onChange={(e) => setHotspotSearchTerm(e.target.value)}
                      placeholder="Search hotspots, components, or keys..."
                      className="pl-10 w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                </div>

                {/* Status Filter */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Status
                  </label>
                  <select
                    multiple
                    value={hotspotFilters.status}
                    onChange={(e) => setHotspotFilters(prev => ({
                      ...prev,
                      status: Array.from(e.target.selectedOptions, option => option.value)
                    }))}
                    className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="TO_REVIEW">To Review</option>
                    <option value="REVIEWED">Reviewed</option>
                    <option value="RESOLVED">Resolved</option>
                  </select>
                </div>

                {/* Severity Filter */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Severity
                  </label>
                  <select
                    multiple
                    value={hotspotFilters.severity}
                    onChange={(e) => setHotspotFilters(prev => ({
                      ...prev,
                      severity: Array.from(e.target.selectedOptions, option => option.value)
                    }))}
                    className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mt-4">
                {/* Category Filter */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Category
                  </label>
                  <select
                    multiple
                    value={hotspotFilters.category}
                    onChange={(e) => setHotspotFilters(prev => ({
                      ...prev,
                      category: Array.from(e.target.selectedOptions, option => option.value)
                    }))}
                    className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="SQL_INJECTION">SQL Injection</option>
                    <option value="XSS">XSS</option>
                    <option value="CSRF">CSRF</option>
                    <option value="PATH_TRAVERSAL">Path Traversal</option>
                    <option value="COMMAND_INJECTION">Command Injection</option>
                    <option value="LDAP_INJECTION">LDAP Injection</option>
                    <option value="OPEN_REDIRECT">Open Redirect</option>
                    <option value="WEAK_CRYPTOGRAPHY">Weak Cryptography</option>
                    <option value="INSECURE_DESERIALIZATION">Insecure Deserialization</option>
                    <option value="OTHER">Other</option>
                  </select>
                </div>

                {/* Security Category Filter */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Security Category
                  </label>
                  <select
                    multiple
                    value={hotspotFilters.securityCategory}
                    onChange={(e) => setHotspotFilters(prev => ({
                      ...prev,
                      securityCategory: Array.from(e.target.selectedOptions, option => option.value)
                    }))}
                    className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="OWASP_TOP_10">OWASP Top 10</option>
                    <option value="CWE">CWE</option>
                    <option value="SANS_TOP_25">SANS Top 25</option>
                    <option value="OTHER">Other</option>
                  </select>
                </div>

                {/* Vulnerability Probability Filter */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Vulnerability Probability
                  </label>
                  <select
                    multiple
                    value={hotspotFilters.vulnerabilityProbability}
                    onChange={(e) => setHotspotFilters(prev => ({
                      ...prev,
                      vulnerabilityProbability: Array.from(e.target.selectedOptions, option => option.value)
                    }))}
                    className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>
                </div>

                {/* Author Filter */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Author
                  </label>
                  <input
                    type="text"
                    value={hotspotFilters.author}
                    onChange={(e) => setHotspotFilters(prev => ({ ...prev, author: e.target.value }))}
                    placeholder="Filter by author..."
                    className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
              </div>
            </div>

            {/* Security Hotspots Table */}
            <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100" onClick={() => handleHotspotSort('key')}>
                        <div className="flex items-center">
                          Key
                          {hotspotSort.field === 'key' && (
                            <ChevronUpIcon className={`w-4 h-4 ml-1 ${hotspotSort.direction === 'desc' ? 'rotate-180' : ''}`} />
                          )}
                        </div>
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100" onClick={() => handleHotspotSort('category')}>
                        <div className="flex items-center">
                          Category
                          {hotspotSort.field === 'category' && (
                            <ChevronUpIcon className={`w-4 h-4 ml-1 ${hotspotSort.direction === 'desc' ? 'rotate-180' : ''}`} />
                          )}
                        </div>
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100" onClick={() => handleHotspotSort('severity')}>
                        <div className="flex items-center">
                          Severity
                          {hotspotSort.field === 'severity' && (
                            <ChevronUpIcon className={`w-4 h-4 ml-1 ${hotspotSort.direction === 'desc' ? 'rotate-180' : ''}`} />
                          )}
                        </div>
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100" onClick={() => handleHotspotSort('status')}>
                        <div className="flex items-center">
                          Status
                          {hotspotSort.field === 'status' && (
                            <ChevronUpIcon className={`w-4 h-4 ml-1 ${hotspotSort.direction === 'desc' ? 'rotate-180' : ''}`} />
                          )}
                        </div>
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Component</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Message</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Resolution</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100" onClick={() => handleHotspotSort('creationDate')}>
                        <div className="flex items-center">
                          Created
                          {hotspotSort.field === 'creationDate' && (
                            <ChevronUpIcon className={`w-4 h-4 ml-1 ${hotspotSort.direction === 'desc' ? 'rotate-180' : ''}`} />
                          )}
                        </div>
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {hotspotPaginatedItems.map((hotspot) => (
                      <tr key={hotspot.id} className="hover:bg-gray-50">
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                          {hotspot.key}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center">
                            {getHotspotCategoryIcon(hotspot.category)}
                            <span className="ml-2 text-sm text-gray-900">
                              {hotspot.category.replace('_', ' ')}
                            </span>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium text-white ${getHotspotSeverityColor(hotspot.severity)}`}>
                            {hotspot.severity}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getHotspotStatusColor(hotspot.status)}`}>
                            {hotspot.status.replace('_', ' ')}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          <div className="max-w-xs truncate" title={hotspot.component}>
                            {hotspot.component.split('/').pop()}
                          </div>
                          <div className="text-xs text-gray-500">Line {hotspot.line}</div>
                        </td>
                        <td className="px-6 py-4 text-sm text-gray-900">
                          <div className="max-w-md truncate" title={hotspot.message}>
                            {hotspot.message}
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          {hotspot.resolution ? (
                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getResolutionColor(hotspot.resolution)}`}>
                              {hotspot.resolution.replace('_', ' ')}
                            </span>
                          ) : (
                            <span className="text-sm text-gray-500">-</span>
                          )}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {new Date(hotspot.creationDate).toLocaleDateString()}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                          <button
                            onClick={() => {
                              setSelectedHotspot(hotspot);
                              setShowHotspotModal(true);
                            }}
                            className="text-blue-600 hover:text-blue-900"
                          >
                            <EyeIcon className="w-4 h-4" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Pagination */}
              {hotspotTotalPages > 1 && (
                <div className="bg-white px-4 py-3 flex items-center justify-between border-t border-gray-200 sm:px-6">
                  <div className="flex-1 flex justify-between sm:hidden">
                    <button
                      onClick={() => setHotspotCurrentPage(prev => Math.max(1, prev - 1))}
                      disabled={hotspotCurrentPage === 1}
                      className="relative inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50"
                    >
                      Previous
                    </button>
                    <button
                      onClick={() => setHotspotCurrentPage(prev => Math.min(hotspotTotalPages, prev + 1))}
                      disabled={hotspotCurrentPage === hotspotTotalPages}
                      className="ml-3 relative inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50"
                    >
                      Next
                    </button>
                  </div>
                  <div className="hidden sm:flex-1 sm:flex sm:items-center sm:justify-between">
                    <div>
                      <p className="text-sm text-gray-700">
                        Showing{' '}
                        <span className="font-medium">{(hotspotCurrentPage - 1) * hotspotItemsPerPage + 1}</span>
                        {' '}to{' '}
                        <span className="font-medium">
                          {Math.min(hotspotCurrentPage * hotspotItemsPerPage, filteredHotspots.length)}
                        </span>
                        {' '}of{' '}
                        <span className="font-medium">{filteredHotspots.length}</span>
                        {' '}results
                      </p>
                    </div>
                    <div>
                      <nav className="relative z-0 inline-flex rounded-md shadow-sm -space-x-px">
                        <button
                          onClick={() => setHotspotCurrentPage(prev => Math.max(1, prev - 1))}
                          disabled={hotspotCurrentPage === 1}
                          className="relative inline-flex items-center px-2 py-2 rounded-l-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 disabled:opacity-50"
                        >
                          Previous
                        </button>
                        {Array.from({ length: Math.min(5, hotspotTotalPages) }, (_, i) => {
                          const page = i + 1;
                          return (
                            <button
                              key={page}
                              onClick={() => setHotspotCurrentPage(page)}
                              className={`relative inline-flex items-center px-4 py-2 border text-sm font-medium ${
                                hotspotCurrentPage === page
                                  ? 'z-10 bg-blue-50 border-blue-500 text-blue-600'
                                  : 'bg-white border-gray-300 text-gray-500 hover:bg-gray-50'
                              }`}
                            >
                              {page}
                            </button>
                          );
                        })}
                        <button
                          onClick={() => setHotspotCurrentPage(prev => Math.min(hotspotTotalPages, prev + 1))}
                          disabled={hotspotCurrentPage === hotspotTotalPages}
                          className="relative inline-flex items-center px-2 py-2 rounded-r-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 disabled:opacity-50"
                        >
                          Next
                        </button>
                      </nav>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
        {activeTab === 'quality-gates' && (
          <div className="space-y-6">
            {/* Quality Gate Header */}
            <div className="flex justify-between items-center">
              <div>
                <h3 className="text-lg font-medium text-gray-900">Quality Gate</h3>
                <p className="text-sm text-gray-600">
                  {qualityGate?.name || 'Default Quality Gate'}
                </p>
              </div>
              <div className="flex space-x-2">
                <button className="inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50">
                  <Cog6ToothIcon className="w-4 h-4 mr-2" />
                  Configure
                </button>
                <button className="inline-flex items-center px-3 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700">
                  <ArrowPathIcon className="w-4 h-4 mr-2" />
                  Evaluate Now
                </button>
              </div>
            </div>

            {/* Quality Gate Status */}
            {qualityGate && (
              <div className="bg-white border border-gray-200 rounded-lg p-6">
                <div className="flex items-center justify-between mb-4">
                  <h4 className="text-lg font-medium text-gray-900">Current Status</h4>
                  <div className="flex items-center space-x-4">
                    <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${
                      qualityGate.status === 'PASSED' ? 'text-green-600 bg-green-100' :
                      qualityGate.status === 'FAILED' ? 'text-red-600 bg-red-100' :
                      'text-yellow-600 bg-yellow-100'
                    }`}>
                      {qualityGate.status}
                    </span>
                    <span className="text-sm text-gray-600">
                      Last evaluated: {qualityGate.lastEvaluation ? new Date(qualityGate.lastEvaluation).toLocaleString() : 'Never'}
                    </span>
                  </div>
                </div>

                {/* Conditions Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {qualityGate.conditions.map((condition) => (
                    <div key={condition.id} className="border border-gray-200 rounded-lg p-4">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center">
                          {getCategoryIcon(condition.category)}
                          <span className="ml-2 text-sm font-medium text-gray-900">
                            {condition.metric}
                          </span>
                        </div>
                        <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getConditionStatusColor(condition.status)}`}>
                          {getConditionStatusIcon(condition.status)}
                          <span className="ml-1">{condition.status}</span>
                        </span>
                      </div>
                      <p className="text-xs text-gray-600 mb-2">{condition.description}</p>
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-gray-600">
                          {condition.operator === 'GT' ? '>' : 
                           condition.operator === 'LT' ? '<' : 
                           condition.operator === 'EQ' ? '=' : '≠'} {condition.threshold}
                        </span>
                        <span className="font-medium text-gray-900">
                          {condition.actualValue}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Thresholds Configuration */}
            <div className="bg-white border border-gray-200 rounded-lg p-6">
              <div className="flex items-center justify-between mb-4">
                <h4 className="text-lg font-medium text-gray-900">Thresholds Configuration</h4>
                <button
                  onClick={() => {
                    setEditingThreshold(null);
                    setShowThresholdModal(true);
                  }}
                  className="inline-flex items-center px-3 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700"
                >
                  Add Threshold
                </button>
              </div>

              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Category</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Metric</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Operator</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Threshold</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Description</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {thresholds.map((threshold, index) => (
                      <tr key={index} className="hover:bg-gray-50">
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center">
                            {getCategoryIcon(threshold.category)}
                            <span className="ml-2 text-sm text-gray-900">
                              {threshold.category}
                            </span>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          {threshold.metric}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          {threshold.operator === 'GT' ? 'Greater than' : 
                           threshold.operator === 'LT' ? 'Less than' : 
                           threshold.operator === 'EQ' ? 'Equal to' : 'Not equal to'}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          {threshold.threshold}
                        </td>
                        <td className="px-6 py-4 text-sm text-gray-900">
                          <div className="max-w-md truncate" title={threshold.description}>
                            {threshold.description}
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                          <button
                            onClick={() => handleEditThreshold(threshold)}
                            className="text-blue-600 hover:text-blue-900 mr-3"
                          >
                            Edit
                          </button>
                          <button className="text-red-600 hover:text-red-900">
                            Delete
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Quality Gate History */}
            <div className="bg-white border border-gray-200 rounded-lg p-6">
              <h4 className="text-lg font-medium text-gray-900 mb-4">Evaluation History</h4>
              <div className="space-y-3">
                <div className="flex items-center justify-between p-3 bg-green-50 border border-green-200 rounded-lg">
                  <div className="flex items-center">
                    <CheckIcon className="w-5 h-5 text-green-600 mr-3" />
                    <div>
                      <p className="text-sm font-medium text-green-900">Quality Gate Passed</p>
                      <p className="text-xs text-green-600">All conditions met</p>
                    </div>
                  </div>
                  <span className="text-sm text-green-600">
                    {qualityGate?.lastEvaluation ? new Date(qualityGate.lastEvaluation).toLocaleString() : 'Unknown'}
                  </span>
                </div>
                <div className="flex items-center justify-between p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
                  <div className="flex items-center">
                    <ExclamationTriangleIcon className="w-5 h-5 text-yellow-600 mr-3" />
                    <div>
                      <p className="text-sm font-medium text-yellow-900">Quality Gate Warning</p>
                      <p className="text-xs text-yellow-600">Some conditions need attention</p>
                    </div>
                  </div>
                  <span className="text-sm text-yellow-600">
                    2024-01-14 15:30:00
                  </span>
                </div>
                <div className="flex items-center justify-between p-3 bg-red-50 border border-red-200 rounded-lg">
                  <div className="flex items-center">
                    <XCircleIcon className="w-5 h-5 text-red-600 mr-3" />
                    <div>
                      <p className="text-sm font-medium text-red-900">Quality Gate Failed</p>
                      <p className="text-xs text-red-600">Critical conditions not met</p>
                    </div>
                  </div>
                  <span className="text-sm text-red-600">
                    2024-01-13 09:15:00
                  </span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Threshold Configuration Modal */}
        {showThresholdModal && (
          <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
            <div className="relative top-20 mx-auto p-5 border w-11/12 md:w-1/2 shadow-lg rounded-md bg-white">
              <div className="flex justify-between items-center mb-4">
                <h3 className="text-lg font-medium text-gray-900">
                  {editingThreshold ? 'Edit Threshold' : 'Add Threshold'}
                </h3>
                <button
                  onClick={() => setShowThresholdModal(false)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  <XMarkIcon className="w-6 h-6" />
                </button>
              </div>
              
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Category</label>
                  <select
                    defaultValue={editingThreshold?.category || 'RELIABILITY'}
                    className="mt-1 w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="RELIABILITY">Reliability</option>
                    <option value="SECURITY">Security</option>
                    <option value="MAINTAINABILITY">Maintainability</option>
                    <option value="COVERAGE">Coverage</option>
                    <option value="DUPLICATIONS">Duplications</option>
                    <option value="SIZE">Size</option>
                  </select>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700">Metric</label>
                  <input
                    type="text"
                    defaultValue={editingThreshold?.metric || ''}
                    placeholder="e.g., Coverage, Reliability Rating"
                    className="mt-1 w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700">Operator</label>
                  <select
                    defaultValue={editingThreshold?.operator || 'GT'}
                    className="mt-1 w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="GT">Greater than</option>
                    <option value="LT">Less than</option>
                    <option value="EQ">Equal to</option>
                    <option value="NE">Not equal to</option>
                  </select>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700">Threshold</label>
                  <input
                    type="number"
                    defaultValue={editingThreshold?.threshold || 0}
                    placeholder="Enter threshold value"
                    className="mt-1 w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700">Description</label>
                  <textarea
                    defaultValue={editingThreshold?.description || ''}
                    placeholder="Describe what this threshold measures"
                    rows={3}
                    className="mt-1 w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
              </div>
              
              <div className="flex justify-end space-x-3 mt-6">
                <button
                  onClick={() => setShowThresholdModal(false)}
                  className="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  onClick={() => {
                    // Handle save logic here
                    setShowThresholdModal(false);
                  }}
                  className="px-4 py-2 bg-blue-600 border border-transparent rounded-md text-sm font-medium text-white hover:bg-blue-700"
                >
                  {editingThreshold ? 'Update' : 'Add'} Threshold
                </button>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'coverage' && (
          <div className="space-y-6">
            {/* Coverage Header */}
            <div className="flex justify-between items-center">
              <div>
                <h3 className="text-lg font-medium text-gray-900">Code Coverage</h3>
                <p className="text-sm text-gray-600">
                  Overall coverage: {coverageData?.overall || 0}%
                </p>
              </div>
              <div className="flex space-x-2">
                <button className="inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50">
                  <FunnelIcon className="w-4 h-4 mr-2" />
                  Export Report
                </button>
                <button className="inline-flex items-center px-3 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700">
                  <ArrowPathIcon className="w-4 h-4 mr-2" />
                  Refresh Coverage
                </button>
              </div>
            </div>

            {/* Overall Coverage Summary */}
            {coverageData && (
              <div className="bg-white border border-gray-200 rounded-lg p-6">
                <h4 className="text-lg font-medium text-gray-900 mb-4">Overall Coverage</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6">
                  {/* Overall Coverage */}
                  <div className="text-center">
                    <div className="w-24 h-24 mx-auto relative">
                      <svg className="w-24 h-24 transform -rotate-90" viewBox="0 0 36 36">
                        <path
                          d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                          fill="none"
                          stroke="#e5e7eb"
                          strokeWidth="2"
                        />
                        <path
                          d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                          fill="none"
                          stroke="#3b82f6"
                          strokeWidth="2"
                          strokeDasharray={`${coverageData.overall}, 100`}
                        />
                      </svg>
                      <div className="absolute inset-0 flex items-center justify-center">
                        <span className="text-lg font-bold text-gray-900">{coverageData.overall}%</span>
                      </div>
                    </div>
                    <p className="text-sm font-medium text-gray-900 mt-2">Overall</p>
                    <p className="text-xs text-gray-600">{getCoverageStatus(coverageData.overall)}</p>
                  </div>

                  {/* Lines Coverage */}
                  <div className="text-center">
                    <div className="w-20 h-20 mx-auto relative">
                      <svg className="w-20 h-20 transform -rotate-90" viewBox="0 0 36 36">
                        <path
                          d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                          fill="none"
                          stroke="#e5e7eb"
                          strokeWidth="2"
                        />
                        <path
                          d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                          fill="none"
                          stroke="#10b981"
                          strokeWidth="2"
                          strokeDasharray={`${(coverageData.lines - coverageData.uncoveredLines.length) / coverageData.lines * 100}, 100`}
                        />
                      </svg>
                      <div className="absolute inset-0 flex items-center justify-center">
                        <span className="text-sm font-bold text-gray-900">
                          {Math.round((coverageData.lines - coverageData.uncoveredLines.length) / coverageData.lines * 100)}%
                        </span>
                      </div>
                    </div>
                    <p className="text-sm font-medium text-gray-900 mt-2">Lines</p>
                    <p className="text-xs text-gray-600">{coverageData.lines - coverageData.uncoveredLines.length}/{coverageData.lines}</p>
                  </div>

                  {/* Functions Coverage */}
                  <div className="text-center">
                    <div className="w-20 h-20 mx-auto relative">
                      <svg className="w-20 h-20 transform -rotate-90" viewBox="0 0 36 36">
                        <path
                          d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                          fill="none"
                          stroke="#e5e7eb"
                          strokeWidth="2"
                        />
                        <path
                          d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                          fill="none"
                          stroke="#f59e0b"
                          strokeWidth="2"
                          strokeDasharray={`${(coverageData.functions - coverageData.uncoveredFunctions.length) / coverageData.functions * 100}, 100`}
                        />
                      </svg>
                      <div className="absolute inset-0 flex items-center justify-center">
                        <span className="text-sm font-bold text-gray-900">
                          {Math.round((coverageData.functions - coverageData.uncoveredFunctions.length) / coverageData.functions * 100)}%
                        </span>
                      </div>
                    </div>
                    <p className="text-sm font-medium text-gray-900 mt-2">Functions</p>
                    <p className="text-xs text-gray-600">{coverageData.functions - coverageData.uncoveredFunctions.length}/{coverageData.functions}</p>
                  </div>

                  {/* Branches Coverage */}
                  <div className="text-center">
                    <div className="w-20 h-20 mx-auto relative">
                      <svg className="w-20 h-20 transform -rotate-90" viewBox="0 0 36 36">
                        <path
                          d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                          fill="none"
                          stroke="#e5e7eb"
                          strokeWidth="2"
                        />
                        <path
                          d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                          fill="none"
                          stroke="#ef4444"
                          strokeWidth="2"
                          strokeDasharray={`${(coverageData.branches - coverageData.uncoveredBranches.length) / coverageData.branches * 100}, 100`}
                        />
                      </svg>
                      <div className="absolute inset-0 flex items-center justify-center">
                        <span className="text-sm font-bold text-gray-900">
                          {Math.round((coverageData.branches - coverageData.uncoveredBranches.length) / coverageData.branches * 100)}%
                        </span>
                      </div>
                    </div>
                    <p className="text-sm font-medium text-gray-900 mt-2">Branches</p>
                    <p className="text-xs text-gray-600">{coverageData.branches - coverageData.uncoveredBranches.length}/{coverageData.branches}</p>
                  </div>

                  {/* Statements Coverage */}
                  <div className="text-center">
                    <div className="w-20 h-20 mx-auto relative">
                      <svg className="w-20 h-20 transform -rotate-90" viewBox="0 0 36 36">
                        <path
                          d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                          fill="none"
                          stroke="#e5e7eb"
                          strokeWidth="2"
                        />
                        <path
                          d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                          fill="none"
                          stroke="#8b5cf6"
                          strokeWidth="2"
                          strokeDasharray={`${(coverageData.statements / (coverageData.statements + 50)) * 100}, 100`}
                        />
                      </svg>
                      <div className="absolute inset-0 flex items-center justify-center">
                        <span className="text-sm font-bold text-gray-900">
                          {Math.round((coverageData.statements / (coverageData.statements + 50)) * 100)}%
                        </span>
                      </div>
                    </div>
                    <p className="text-sm font-medium text-gray-900 mt-2">Statements</p>
                    <p className="text-xs text-gray-600">{coverageData.statements}/{coverageData.statements + 50}</p>
                  </div>
                </div>
              </div>
            )}

            {/* Coverage Trends */}
            {coverageData && (
              <div className="bg-white border border-gray-200 rounded-lg p-6">
                <h4 className="text-lg font-medium text-gray-900 mb-4">Coverage Trends</h4>
                <div className="h-64 flex items-end space-x-2">
                  {coverageData.trendData.map((trend, index) => (
                    <div key={index} className="flex-1 flex flex-col items-center">
                      <div className="w-full bg-gray-200 rounded-t" style={{ height: `${trend.overall}%` }}>
                        <div className="bg-blue-500 rounded-t" style={{ height: '100%' }}></div>
                      </div>
                      <span className="text-xs text-gray-600 mt-1">{trend.overall}%</span>
                      <span className="text-xs text-gray-500">{new Date(trend.date).toLocaleDateString()}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* File-Level Coverage */}
            {coverageData && (
              <div className="bg-white border border-gray-200 rounded-lg p-6">
                <h4 className="text-lg font-medium text-gray-900 mb-4">File-Level Coverage</h4>
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">File</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Coverage</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Lines</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Uncovered</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Complexity</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Last Modified</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                      {coverageData.fileCoverage.map((file, index) => (
                        <tr key={index} className="hover:bg-gray-50">
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                            <div className="max-w-xs truncate" title={file.file}>
                              {file.file.split('/').pop()}
                            </div>
                            <div className="text-xs text-gray-500">{file.file}</div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="flex items-center">
                              <div className="w-16 bg-gray-200 rounded-full h-2 mr-2">
                                <div
                                  className="bg-blue-500 h-2 rounded-full"
                                  style={{ width: `${file.coverage}%` }}
                                ></div>
                              </div>
                              <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getCoverageColor(file.coverage)}`}>
                                {file.coverage}%
                              </span>
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                            {file.coveredLines}/{file.lines}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                            {file.uncoveredLines.length} lines
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                              file.complexity <= 5 ? 'text-green-600 bg-green-100' :
                              file.complexity <= 10 ? 'text-yellow-600 bg-yellow-100' :
                              'text-red-600 bg-red-100'
                            }`}>
                              {file.complexity}
                            </span>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                            {new Date(file.lastModified).toLocaleDateString()}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                            <button
                              onClick={() => {
                                setSelectedFile(file.file);
                                setShowFileDetails(true);
                              }}
                              className="text-blue-600 hover:text-blue-900"
                            >
                              <EyeIcon className="w-4 h-4" />
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Uncovered Items */}
            {coverageData && (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                {/* Uncovered Lines */}
                <div className="bg-white border border-gray-200 rounded-lg p-6">
                  <h4 className="text-lg font-medium text-gray-900 mb-4">Uncovered Lines</h4>
                  <div className="space-y-2">
                    {coverageData.uncoveredLines.map((line, index) => (
                      <div key={index} className="flex items-center justify-between p-2 bg-red-50 rounded">
                        <span className="text-sm text-red-700">Line {line}</span>
                        <span className="text-xs text-red-600">Not covered</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Uncovered Functions */}
                <div className="bg-white border border-gray-200 rounded-lg p-6">
                  <h4 className="text-lg font-medium text-gray-900 mb-4">Uncovered Functions</h4>
                  <div className="space-y-2">
                    {coverageData.uncoveredFunctions.map((func, index) => (
                      <div key={index} className="flex items-center justify-between p-2 bg-yellow-50 rounded">
                        <span className="text-sm text-yellow-700">{func}</span>
                        <span className="text-xs text-yellow-600">Not covered</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Uncovered Branches */}
                <div className="bg-white border border-gray-200 rounded-lg p-6">
                  <h4 className="text-lg font-medium text-gray-900 mb-4">Uncovered Branches</h4>
                  <div className="space-y-2">
                    {coverageData.uncoveredBranches.map((branch, index) => (
                      <div key={index} className="flex items-center justify-between p-2 bg-orange-50 rounded">
                        <span className="text-sm text-orange-700">{branch}</span>
                        <span className="text-xs text-orange-600">Not covered</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* File Coverage Details Modal */}
        {showFileDetails && selectedFile && coverageData && (
          <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
            <div className="relative top-20 mx-auto p-5 border w-11/12 md:w-3/4 lg:w-1/2 shadow-lg rounded-md bg-white">
              <div className="flex justify-between items-center mb-4">
                <h3 className="text-lg font-medium text-gray-900">
                  Coverage Details - {selectedFile.split('/').pop()}
                </h3>
                <button
                  onClick={() => setShowFileDetails(false)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  <XMarkIcon className="w-6 h-6" />
                </button>
              </div>
              
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">File Path</label>
                  <p className="text-sm text-gray-900 mt-1">{selectedFile}</p>
                </div>
                
                {coverageData.fileCoverage.find(f => f.file === selectedFile) && (
                  <>
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700">Coverage</label>
                        <p className="text-sm text-gray-900 mt-1">
                          {coverageData.fileCoverage.find(f => f.file === selectedFile)?.coverage}%
                        </p>
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700">Lines</label>
                        <p className="text-sm text-gray-900 mt-1">
                          {coverageData.fileCoverage.find(f => f.file === selectedFile)?.coveredLines}/
                          {coverageData.fileCoverage.find(f => f.file === selectedFile)?.lines}
                        </p>
                      </div>
                    </div>
                    
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Uncovered Lines</label>
                      <div className="mt-1 space-y-1">
                        {coverageData.fileCoverage.find(f => f.file === selectedFile)?.uncoveredLines.map((line, index) => (
                          <div key={index} className="inline-block bg-red-100 text-red-800 px-2 py-1 rounded text-sm mr-2 mb-2">
                            Line {line}
                          </div>
                        ))}
                      </div>
                    </div>
                    
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700">Complexity</label>
                        <p className="text-sm text-gray-900 mt-1">
                          {coverageData.fileCoverage.find(f => f.file === selectedFile)?.complexity}
                        </p>
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700">Last Modified</label>
                        <p className="text-sm text-gray-900 mt-1">
                          {coverageData.fileCoverage.find(f => f.file === selectedFile)?.lastModified ? 
                            new Date(coverageData.fileCoverage.find(f => f.file === selectedFile)!.lastModified).toLocaleString() : 
                            'Unknown'
                          }
                        </p>
                      </div>
                    </div>
                  </>
                )}
              </div>
              
              <div className="flex justify-end space-x-3 mt-6">
                <button
                  onClick={() => setShowFileDetails(false)}
                  className="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50"
                >
                  Close
                </button>
                <button className="px-4 py-2 bg-blue-600 border border-transparent rounded-md text-sm font-medium text-white hover:bg-blue-700">
                  View Source
                </button>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'debt' && (
          <div className="space-y-6">
            {/* Technical Debt Header */}
            <div className="flex justify-between items-center">
              <div>
                <h3 className="text-lg font-medium text-gray-900">Technical Debt</h3>
                <p className="text-sm text-gray-600">
                  Total debt: {debtData ? formatDebtTime(debtData.totalDebt) : '0m'}
                </p>
              </div>
              <div className="flex space-x-2">
                <button className="inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50">
                  <FunnelIcon className="w-4 h-4 mr-2" />
                  Export Report
                </button>
                <button className="inline-flex items-center px-3 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700">
                  <ArrowPathIcon className="w-4 h-4 mr-2" />
                  Analyze Debt
                </button>
              </div>
            </div>

            {/* Debt Overview */}
            {debtData && (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                {/* Total Debt */}
                <div className="bg-white border border-gray-200 rounded-lg p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-gray-600">Total Debt</p>
                      <p className="text-2xl font-bold text-gray-900">{formatDebtTime(debtData.totalDebt)}</p>
                    </div>
                    <div className="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center">
                      <ClockIcon className="w-6 h-6 text-blue-600" />
                    </div>
                  </div>
                </div>

                {/* Debt Ratio */}
                <div className="bg-white border border-gray-200 rounded-lg p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-gray-600">Debt Ratio</p>
                      <p className="text-2xl font-bold text-gray-900">{debtData.debtRatio}%</p>
                    </div>
                    <div className={`px-3 py-1 rounded-full text-sm font-medium ${getDebtRatioColor(debtData.debtRatio)}`}>
                      {getDebtRatioStatus(debtData.debtRatio)}
                    </div>
                  </div>
                </div>

                {/* Issues Count */}
                <div className="bg-white border border-gray-200 rounded-lg p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-gray-600">Total Issues</p>
                      <p className="text-2xl font-bold text-gray-900">
                        {debtData.debtBreakdown.reduce((sum, item) => sum + item.count, 0)}
                      </p>
                    </div>
                    <div className="w-12 h-12 bg-red-100 rounded-full flex items-center justify-center">
                      <ExclamationTriangleIcon className="w-6 h-6 text-red-600" />
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Debt Breakdown */}
            {debtData && (
              <div className="bg-white border border-gray-200 rounded-lg p-6">
                <h4 className="text-lg font-medium text-gray-900 mb-4">Debt Breakdown by Category</h4>
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {/* Chart */}
                  <div className="space-y-4">
                    {debtData.debtByCategory.map((category, index) => (
                      <div key={index} className="flex items-center space-x-4">
                        <div className="w-4 h-4 rounded" style={{ backgroundColor: category.color }}></div>
                        <div className="flex-1">
                          <div className="flex justify-between text-sm">
                            <span className="font-medium text-gray-900">{category.category}</span>
                            <span className="text-gray-600">{formatDebtTime(category.debt)}</span>
                          </div>
                          <div className="w-full bg-gray-200 rounded-full h-2 mt-1">
                            <div
                              className="h-2 rounded-full"
                              style={{ width: `${category.percentage}%`, backgroundColor: category.color }}
                            ></div>
                          </div>
                          <div className="flex justify-between text-xs text-gray-500 mt-1">
                            <span>{category.count} issues</span>
                            <span>{category.percentage}%</span>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Details */}
                  <div className="space-y-4">
                    {debtData.debtBreakdown.map((item, index) => (
                      <div key={index} className="border border-gray-200 rounded-lg p-4">
                        <div className="flex items-center justify-between mb-2">
                          <h5 className="text-sm font-medium text-gray-900">{item.category.replace('_', ' ')}</h5>
                          <span className="text-sm font-medium text-gray-600">{formatDebtTime(item.effort)}</span>
                        </div>
                        <p className="text-xs text-gray-600 mb-2">{item.description}</p>
                        <div className="flex justify-between text-xs text-gray-500">
                          <span>{item.count} issues</span>
                          <span>{item.percentage}% of total debt</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Effort Estimation */}
            {debtData && (
              <div className="bg-white border border-gray-200 rounded-lg p-6">
                <h4 className="text-lg font-medium text-gray-900 mb-4">Effort Estimation</h4>
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {/* By Category */}
                  <div>
                    <h5 className="text-sm font-medium text-gray-900 mb-3">Effort by Category</h5>
                    <div className="space-y-3">
                      {debtData.effortEstimation.effortByCategory.map((item, index) => (
                        <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                          <div>
                            <p className="text-sm font-medium text-gray-900">{item.category.replace('_', ' ')}</p>
                            <p className="text-xs text-gray-600">{item.count} issues</p>
                          </div>
                          <div className="text-right">
                            <p className="text-sm font-medium text-gray-900">{formatDebtTime(item.effort)}</p>
                            <p className="text-xs text-gray-600">~{item.averageEffort.toFixed(1)}h per issue</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* By Severity */}
                  <div>
                    <h5 className="text-sm font-medium text-gray-900 mb-3">Effort by Severity</h5>
                    <div className="space-y-3">
                      {debtData.effortEstimation.effortBySeverity.map((item, index) => (
                        <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                          <div className="flex items-center space-x-2">
                            <div className={`w-3 h-3 rounded-full ${
                              item.severity === 'BLOCKER' ? 'bg-red-500' :
                              item.severity === 'CRITICAL' ? 'bg-orange-500' :
                              item.severity === 'MAJOR' ? 'bg-yellow-500' :
                              item.severity === 'MINOR' ? 'bg-green-500' :
                              'bg-gray-500'
                            }`}></div>
                            <span className="text-sm font-medium text-gray-900">{item.severity}</span>
                          </div>
                          <div className="text-right">
                            <p className="text-sm font-medium text-gray-900">{formatDebtTime(item.effort)}</p>
                            <p className="text-xs text-gray-600">{item.count} issues</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Debt Trends */}
            {debtData && (
              <div className="bg-white border border-gray-200 rounded-lg p-6">
                <h4 className="text-lg font-medium text-gray-900 mb-4">Debt Trends</h4>
                <div className="h-64 flex items-end space-x-2">
                  {debtData.debtTrend.map((trend, index) => (
                    <div key={index} className="flex-1 flex flex-col items-center">
                      <div className="w-full bg-gray-200 rounded-t" style={{ height: `${(trend.totalDebt / 200) * 100}%` }}>
                        <div className="bg-blue-500 rounded-t" style={{ height: '100%' }}></div>
                      </div>
                      <span className="text-xs text-gray-600 mt-1">{formatDebtTime(trend.totalDebt)}</span>
                      <span className="text-xs text-gray-500">{new Date(trend.date).toLocaleDateString()}</span>
                    </div>
                  ))}
                </div>
                <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="text-center">
                    <p className="text-sm font-medium text-gray-900">New Debt</p>
                    <p className="text-lg font-bold text-red-600">
                      {debtData.debtTrend[debtData.debtTrend.length - 1]?.newDebt || 0} issues
                    </p>
                  </div>
                  <div className="text-center">
                    <p className="text-sm font-medium text-gray-900">Resolved Debt</p>
                    <p className="text-lg font-bold text-green-600">
                      {debtData.debtTrend[debtData.debtTrend.length - 1]?.resolvedDebt || 0} issues
                    </p>
                  </div>
                  <div className="text-center">
                    <p className="text-sm font-medium text-gray-900">Net Change</p>
                    <p className={`text-lg font-bold ${
                      (debtData.debtTrend[debtData.debtTrend.length - 1]?.resolvedDebt || 0) - 
                      (debtData.debtTrend[debtData.debtTrend.length - 1]?.newDebt || 0) > 0 
                        ? 'text-green-600' : 'text-red-600'
                    }`}>
                      {((debtData.debtTrend[debtData.debtTrend.length - 1]?.resolvedDebt || 0) - 
                        (debtData.debtTrend[debtData.debtTrend.length - 1]?.newDebt || 0)) > 0 ? '+' : ''}
                      {(debtData.debtTrend[debtData.debtTrend.length - 1]?.resolvedDebt || 0) - 
                       (debtData.debtTrend[debtData.debtTrend.length - 1]?.newDebt || 0)} issues
                    </p>
                  </div>
                </div>
              </div>
            )}

            {/* Debt by Severity */}
            {debtData && (
              <div className="bg-white border border-gray-200 rounded-lg p-6">
                <h4 className="text-lg font-medium text-gray-900 mb-4">Debt by Severity</h4>
                <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
                  {debtData.debtBySeverity.map((severity, index) => (
                    <div key={index} className="text-center">
                      <div className="w-16 h-16 mx-auto relative">
                        <svg className="w-16 h-16 transform -rotate-90" viewBox="0 0 36 36">
                          <path
                            d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                            fill="none"
                            stroke="#e5e7eb"
                            strokeWidth="2"
                          />
                          <path
                            d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                            fill="none"
                            stroke={severity.color}
                            strokeWidth="2"
                            strokeDasharray={`${severity.percentage}, 100`}
                          />
                        </svg>
                        <div className="absolute inset-0 flex items-center justify-center">
                          <span className="text-sm font-bold text-gray-900">{severity.count}</span>
                        </div>
                      </div>
                      <p className="text-sm font-medium text-gray-900 mt-2">{severity.severity}</p>
                      <p className="text-xs text-gray-600">{formatDebtTime(severity.debt)}</p>
                      <p className="text-xs text-gray-500">{severity.percentage}%</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Recommendations */}
            <div className="bg-white border border-gray-200 rounded-lg p-6">
              <h4 className="text-lg font-medium text-gray-900 mb-4">Recommendations</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-3">
                  <div className="flex items-start space-x-3 p-3 bg-blue-50 rounded-lg">
                    <div className="w-6 h-6 bg-blue-500 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5">
                      <span className="text-white text-xs font-bold">1</span>
                    </div>
                    <div>
                      <p className="text-sm font-medium text-blue-900">Address Critical Issues First</p>
                      <p className="text-xs text-blue-700 mt-1">Focus on blocker and critical severity issues to reduce high-impact debt quickly.</p>
                    </div>
                  </div>
                  <div className="flex items-start space-x-3 p-3 bg-green-50 rounded-lg">
                    <div className="w-6 h-6 bg-green-500 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5">
                      <span className="text-white text-xs font-bold">2</span>
                    </div>
                    <div>
                      <p className="text-sm font-medium text-green-900">Refactor Code Smells</p>
                      <p className="text-xs text-green-700 mt-1">Code smells represent 50% of technical debt. Prioritize refactoring efforts.</p>
                    </div>
                  </div>
                </div>
                <div className="space-y-3">
                  <div className="flex items-start space-x-3 p-3 bg-yellow-50 rounded-lg">
                    <div className="w-6 h-6 bg-yellow-500 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5">
                      <span className="text-white text-xs font-bold">3</span>
                    </div>
                    <div>
                      <p className="text-sm font-medium text-yellow-900">Security Vulnerabilities</p>
                      <p className="text-xs text-yellow-700 mt-1">Address security vulnerabilities promptly to maintain code security.</p>
                    </div>
                  </div>
                  <div className="flex items-start space-x-3 p-3 bg-purple-50 rounded-lg">
                    <div className="w-6 h-6 bg-purple-500 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5">
                      <span className="text-white text-xs font-bold">4</span>
                    </div>
                    <div>
                      <p className="text-sm font-medium text-purple-900">Regular Debt Reviews</p>
                      <p className="text-xs text-purple-700 mt-1">Schedule regular technical debt reviews to prevent accumulation.</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Issue Details Modal */}
      {showIssueModal && selectedIssue && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-11/12 md:w-3/4 lg:w-1/2 shadow-lg rounded-md bg-white">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-lg font-medium text-gray-900">
                Issue Details - {selectedIssue.key}
              </h3>
              <button
                onClick={() => setShowIssueModal(false)}
                className="text-gray-400 hover:text-gray-600"
              >
                <XMarkIcon className="w-6 h-6" />
              </button>
            </div>
            
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Type</label>
                  <div className="flex items-center mt-1">
                    {getTypeIcon(selectedIssue.type)}
                    <span className="ml-2 text-sm text-gray-900">
                      {selectedIssue.type.replace('_', ' ')}
                    </span>
                  </div>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Severity</label>
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium text-white mt-1 ${getSeverityColor(selectedIssue.severity)}`}>
                    {selectedIssue.severity}
                  </span>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Status</label>
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium mt-1 ${getStatusColor(selectedIssue.status)}`}>
                    {selectedIssue.status}
                  </span>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Resolution</label>
                  <span className="text-sm text-gray-900 mt-1">
                    {selectedIssue.resolution || 'Not resolved'}
                  </span>
                </div>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700">Component</label>
                <p className="text-sm text-gray-900 mt-1">{selectedIssue.component}</p>
                <p className="text-xs text-gray-500">Line {selectedIssue.line}</p>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700">Message</label>
                <p className="text-sm text-gray-900 mt-1">{selectedIssue.message}</p>
              </div>
              
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Effort</label>
                  <p className="text-sm text-gray-900 mt-1">{selectedIssue.effort}</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Technical Debt</label>
                  <p className="text-sm text-gray-900 mt-1">{selectedIssue.debt}</p>
                </div>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700">Tags</label>
                <div className="flex flex-wrap gap-1 mt-1">
                  {selectedIssue.tags.map((tag, index) => (
                    <span
                      key={index}
                      className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800"
                    >
                      {tag}
                    </span>
                  ))}
                </div>
              </div>
              
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Author</label>
                  <p className="text-sm text-gray-900 mt-1">{selectedIssue.author}</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Created</label>
                  <p className="text-sm text-gray-900 mt-1">
                    {new Date(selectedIssue.creationDate).toLocaleString()}
                  </p>
                </div>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700">Last Updated</label>
                <p className="text-sm text-gray-900 mt-1">
                  {new Date(selectedIssue.updateDate).toLocaleString()}
                </p>
              </div>
            </div>
            
            <div className="flex justify-end space-x-3 mt-6">
              <button
                onClick={() => setShowIssueModal(false)}
                className="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50"
              >
                Close
              </button>
              <button className="px-4 py-2 bg-blue-600 border border-transparent rounded-md text-sm font-medium text-white hover:bg-blue-700">
                Resolve Issue
              </button>
            </div>
          </div>
        </div>
      )}

        {/* Security Hotspot Details Modal */}
        {showHotspotModal && selectedHotspot && (
          <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
            <div className="relative top-20 mx-auto p-5 border w-11/12 md:w-3/4 lg:w-1/2 shadow-lg rounded-md bg-white">
              <div className="flex justify-between items-center mb-4">
                <h3 className="text-lg font-medium text-gray-900">
                  Security Hotspot Details - {selectedHotspot.key}
                </h3>
                <button
                  onClick={() => setShowHotspotModal(false)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  <XMarkIcon className="w-6 h-6" />
                </button>
              </div>
              
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700">Category</label>
                    <div className="flex items-center mt-1">
                      {getHotspotCategoryIcon(selectedHotspot.category)}
                      <span className="ml-2 text-sm text-gray-900">
                        {selectedHotspot.category.replace('_', ' ')}
                      </span>
                    </div>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700">Severity</label>
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium text-white mt-1 ${getHotspotSeverityColor(selectedHotspot.severity)}`}>
                      {selectedHotspot.severity}
                    </span>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700">Status</label>
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium mt-1 ${getHotspotStatusColor(selectedHotspot.status)}`}>
                      {selectedHotspot.status.replace('_', ' ')}
                    </span>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700">Resolution</label>
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium mt-1 ${getResolutionColor(selectedHotspot.resolution)}`}>
                      {selectedHotspot.resolution ? selectedHotspot.resolution.replace('_', ' ') : 'Not resolved'}
                    </span>
                  </div>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700">Component</label>
                  <p className="text-sm text-gray-900 mt-1">{selectedHotspot.component}</p>
                  <p className="text-xs text-gray-500">Line {selectedHotspot.line}</p>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700">Message</label>
                  <p className="text-sm text-gray-900 mt-1">{selectedHotspot.message}</p>
                </div>
                
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700">Security Category</label>
                    <p className="text-sm text-gray-900 mt-1">{selectedHotspot.securityCategory.replace('_', ' ')}</p>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700">Vulnerability Probability</label>
                    <p className="text-sm text-gray-900 mt-1">{selectedHotspot.vulnerabilityProbability}</p>
                  </div>
                </div>
                
                {selectedHotspot.reviewer && (
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Reviewer</label>
                      <p className="text-sm text-gray-900 mt-1">{selectedHotspot.reviewer}</p>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Review Date</label>
                      <p className="text-sm text-gray-900 mt-1">
                        {selectedHotspot.reviewDate ? new Date(selectedHotspot.reviewDate).toLocaleString() : '-'}
                      </p>
                    </div>
                  </div>
                )}
                
                {selectedHotspot.comment && (
                  <div>
                    <label className="block text-sm font-medium text-gray-700">Review Comment</label>
                    <p className="text-sm text-gray-900 mt-1">{selectedHotspot.comment}</p>
                  </div>
                )}
                
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700">Author</label>
                    <p className="text-sm text-gray-900 mt-1">{selectedHotspot.author}</p>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700">Created</label>
                    <p className="text-sm text-gray-900 mt-1">
                      {new Date(selectedHotspot.creationDate).toLocaleString()}
                    </p>
                  </div>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700">Last Updated</label>
                  <p className="text-sm text-gray-900 mt-1">
                    {new Date(selectedHotspot.updateDate).toLocaleString()}
                  </p>
                </div>
              </div>
              
              <div className="flex justify-end space-x-3 mt-6">
                <button
                  onClick={() => setShowHotspotModal(false)}
                  className="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50"
                >
                  Close
                </button>
                {selectedHotspot.status === 'TO_REVIEW' && (
                  <button className="px-4 py-2 bg-blue-600 border border-transparent rounded-md text-sm font-medium text-white hover:bg-blue-700">
                    Review Hotspot
                  </button>
                )}
              </div>
            </div>
          </div>
        )}
    </div>
  );
};

// Project Overview Component
const ProjectOverview: React.FC<{ project: ProjectDetails }> = ({ project }) => {
  const getRatingColor = (rating: string) => {
    switch (rating) {
      case 'A': return 'text-green-600 bg-green-100';
      case 'B': return 'text-blue-600 bg-blue-100';
      case 'C': return 'text-yellow-600 bg-yellow-100';
      case 'D': return 'text-orange-600 bg-orange-100';
      case 'E': return 'text-red-600 bg-red-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  return (
    <div className="space-y-6">
      {/* Quality Gate Status */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Quality Gate Status</h2>
        <div className="flex items-center space-x-4">
          <div className={`px-4 py-2 rounded-full text-sm font-medium ${
            project.qualityGate === 'PASSED' ? 'text-green-600 bg-green-100' :
            project.qualityGate === 'FAILED' ? 'text-red-600 bg-red-100' :
            'text-yellow-600 bg-yellow-100'
          }`}>
            {project.qualityGate}
          </div>
          <span className="text-sm text-gray-600">
            Last analysis: {project.lastAnalysis ? new Date(project.lastAnalysis).toLocaleDateString() : 'Never'}
          </span>
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* Maintainability */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Maintainability</p>
              <p className="text-2xl font-bold text-gray-900">{project.maintainabilityRating}</p>
            </div>
            <div className={`px-3 py-1 rounded-full text-sm font-medium ${getRatingColor(project.maintainabilityRating)}`}>
              {project.maintainabilityRating}
            </div>
          </div>
        </div>

        {/* Security */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Security</p>
              <p className="text-2xl font-bold text-gray-900">{project.securityRating}</p>
            </div>
            <div className={`px-3 py-1 rounded-full text-sm font-medium ${getRatingColor(project.securityRating)}`}>
              {project.securityRating}
            </div>
          </div>
        </div>

        {/* Reliability */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Reliability</p>
              <p className="text-2xl font-bold text-gray-900">{project.reliabilityRating}</p>
            </div>
            <div className={`px-3 py-1 rounded-full text-sm font-medium ${getRatingColor(project.reliabilityRating)}`}>
              {project.reliabilityRating}
            </div>
          </div>
        </div>

        {/* Coverage */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Coverage</p>
              <p className="text-2xl font-bold text-gray-900">{project.coverage}%</p>
            </div>
            <div className="w-12 h-12 relative">
              <svg className="w-12 h-12 transform -rotate-90" viewBox="0 0 36 36">
                <path
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                  fill="none"
                  stroke="#e5e7eb"
                  strokeWidth="2"
                />
                <path
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                  fill="none"
                  stroke="#3b82f6"
                  strokeWidth="2"
                  strokeDasharray={`${project.coverage}, 100`}
                />
              </svg>
            </div>
          </div>
        </div>
      </div>

      {/* Issues Summary */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Issues Summary</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="text-center">
            <div className="text-2xl font-bold text-red-600">{project.vulnerabilityCount}</div>
            <div className="text-sm text-gray-600">Vulnerabilities</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-orange-600">{project.bugCount}</div>
            <div className="text-sm text-gray-600">Bugs</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-yellow-600">{project.codeSmellCount}</div>
            <div className="text-sm text-gray-600">Code Smells</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-blue-600">{project.securityHotspotCount}</div>
            <div className="text-sm text-gray-600">Security Hotspots</div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SASTProjectDetails; 