import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  CloudIcon, 
  ShieldCheckIcon, 
  ChartBarIcon,
  CogIcon,
  BellIcon,
  UserCircleIcon,
  Bars3Icon,
  XMarkIcon,
  MagnifyingGlassIcon,
  SunIcon,
  MoonIcon,
  ComputerDesktopIcon,
  BugAntIcon,
  ArrowRightOnRectangleIcon,
  WifiIcon,
  DevicePhoneMobileIcon,
  KeyIcon,
  LockClosedIcon,
  DocumentTextIcon,
  ServerIcon,
  ShieldExclamationIcon,
  PlayIcon,
  BoltIcon,
  GlobeAltIcon,
  ExclamationTriangleIcon,
  CodeBracketIcon
} from '@heroicons/react/24/outline';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';

interface NavigationItem {
  id: string;
  label: string;
  icon: React.ReactNode;
  href: string;
  badge?: number;
  children?: NavigationItem[];
}

interface EnhancedNavigationProps {
  className?: string;
}

const navigationItems: NavigationItem[] = [
  {
    id: 'dashboard',
    label: 'Dashboard',
    icon: <ChartBarIcon className="w-5 h-5" />,
    href: '/dashboard'
  },
              {
              id: 'application-security',
              label: 'Application Security',
              icon: <BugAntIcon className="w-5 h-5" />,
              href: '/application-security',
              children: [
                { id: 'overview', label: 'Overview', icon: <ChartBarIcon className="w-4 h-4" />, href: '/application-security' },
                { id: 'sast', label: 'SAST', icon: <CodeBracketIcon className="w-4 h-4" />, href: '/sast' },
                { id: 'dast', label: 'DAST', icon: <ShieldExclamationIcon className="w-4 h-4" />, href: '/dast' },
                { id: 'rasp', label: 'RASP', icon: <ShieldCheckIcon className="w-4 h-4" />, href: '/application-security/rasp' },
                { id: 'monitoring', label: 'Monitoring', icon: <BellIcon className="w-4 h-4" />, href: '/application-security/monitoring' }
              ]
            },
  {
    id: 'cloud-security',
    label: 'Cloud Security',
    icon: <CloudIcon className="w-5 h-5" />,
    href: '/cloud-security',
    children: [
      { id: 'overview', label: 'Overview', icon: <ChartBarIcon className="w-4 h-4" />, href: '/cloud-security' },
      { id: 'cspm', label: 'CSPM', icon: <ShieldCheckIcon className="w-4 h-4" />, href: '/cloud-security/cspm' },
      { id: 'cwp', label: 'CWP', icon: <CloudIcon className="w-4 h-4" />, href: '/cloud-security/cwp' },
      { id: 'casb', label: 'CASB', icon: <ShieldCheckIcon className="w-4 h-4" />, href: '/cloud-security/casb' },
      { id: 'ciem', label: 'CIEM', icon: <UserCircleIcon className="w-4 h-4" />, href: '/cloud-security/ciem' },
      { id: 'monitoring', label: 'Monitoring', icon: <BellIcon className="w-4 h-4" />, href: '/cloud-security/monitoring' }
    ]
  },
  {
    id: 'network-security',
    label: 'Network Security',
    icon: <WifiIcon className="w-5 h-5" />,
    href: '/network-security',
    children: [
      { id: 'overview', label: 'Overview', icon: <ChartBarIcon className="w-4 h-4" />, href: '/network-security' },
      { id: 'firewall', label: 'Firewall', icon: <ShieldCheckIcon className="w-4 h-4" />, href: '/network-security/firewall' },
      { id: 'ids-ips', label: 'IDS/IPS', icon: <BellIcon className="w-4 h-4" />, href: '/network-security/ids-ips' },
      { id: 'vpn', label: 'VPN', icon: <WifiIcon className="w-4 h-4" />, href: '/network-security/vpn' },
      { id: 'nac', label: 'NAC', icon: <UserCircleIcon className="w-4 h-4" />, href: '/network-security/nac' },
      { id: 'monitoring', label: 'Monitoring', icon: <ComputerDesktopIcon className="w-4 h-4" />, href: '/network-security/monitoring' }
    ]
  },
  {
    id: 'endpoint-security',
    label: 'Endpoint Security',
    icon: <DevicePhoneMobileIcon className="w-5 h-5" />,
    href: '/endpoint-security',
    children: [
      { id: 'overview', label: 'Overview', icon: <ChartBarIcon className="w-4 h-4" />, href: '/endpoint-security' },
      { id: 'antivirus', label: 'Antivirus', icon: <ShieldCheckIcon className="w-4 h-4" />, href: '/endpoint-security/antivirus' },
      { id: 'edr', label: 'EDR', icon: <ComputerDesktopIcon className="w-4 h-4" />, href: '/endpoint-security/edr' },
      { id: 'dlp', label: 'DLP', icon: <ShieldCheckIcon className="w-4 h-4" />, href: '/endpoint-security/dlp' },
      { id: 'patching', label: 'Patching', icon: <CogIcon className="w-4 h-4" />, href: '/endpoint-security/patching' },
      { id: 'monitoring', label: 'Monitoring', icon: <BellIcon className="w-4 h-4" />, href: '/endpoint-security/monitoring' }
    ]
  },
  {
    id: 'iam-security',
    label: 'IAM Security',
    icon: <KeyIcon className="w-5 h-5" />,
    href: '/iam-security',
    children: [
      { id: 'overview', label: 'Overview', icon: <ChartBarIcon className="w-4 h-4" />, href: '/iam-security' },
      { id: 'identity-management', label: 'Identity Management', icon: <UserCircleIcon className="w-4 h-4" />, href: '/iam-security/identity-management' },
      { id: 'sso-mfa', label: 'SSO & MFA', icon: <LockClosedIcon className="w-4 h-4" />, href: '/iam-security/sso-mfa' },
      { id: 'pam', label: 'PAM', icon: <KeyIcon className="w-4 h-4" />, href: '/iam-security/pam' },
      { id: 'rbac', label: 'RBAC', icon: <ShieldCheckIcon className="w-4 h-4" />, href: '/iam-security/rbac' },
      { id: 'audit-compliance', label: 'Audit & Compliance', icon: <BellIcon className="w-4 h-4" />, href: '/iam-security/audit-compliance' }
    ]
  },
  {
    id: 'data-security',
    label: 'Data Security',
    icon: <DocumentTextIcon className="w-5 h-5" />,
    href: '/data-security',
    children: [
      { id: 'overview', label: 'Overview', icon: <ChartBarIcon className="w-4 h-4" />, href: '/data-security' },
      { id: 'encryption', label: 'Encryption', icon: <LockClosedIcon className="w-4 h-4" />, href: '/data-security/encryption' },
      { id: 'dlp', label: 'DLP', icon: <ShieldCheckIcon className="w-4 h-4" />, href: '/data-security/dlp' },
      { id: 'database-security', label: 'Database Security', icon: <ServerIcon className="w-4 h-4" />, href: '/data-security/database-security' },
      { id: 'compliance', label: 'Compliance', icon: <DocumentTextIcon className="w-4 h-4" />, href: '/data-security/compliance' },
      { id: 'monitoring', label: 'Monitoring', icon: <BellIcon className="w-4 h-4" />, href: '/data-security/monitoring' }
    ]
  },
  {
    id: 'siem-soar',
    label: 'SIEM & SOAR',
    icon: <ShieldExclamationIcon className="w-5 h-5" />,
    href: '/siem-soar',
    children: [
      { id: 'overview', label: 'Overview', icon: <ChartBarIcon className="w-4 h-4" />, href: '/siem-soar' },
      { id: 'log-collection', label: 'Log Collection', icon: <ServerIcon className="w-4 h-4" />, href: '/siem-soar/log-collection' },
      { id: 'event-correlation', label: 'Event Correlation', icon: <MagnifyingGlassIcon className="w-4 h-4" />, href: '/siem-soar/event-correlation' },
      { id: 'incident-management', label: 'Incident Management', icon: <ExclamationTriangleIcon className="w-4 h-4" />, href: '/siem-soar/incident-management' },
      { id: 'playbooks', label: 'Playbooks', icon: <PlayIcon className="w-4 h-4" />, href: '/siem-soar/playbooks' },
      { id: 'threat-intelligence', label: 'Threat Intelligence', icon: <GlobeAltIcon className="w-4 h-4" />, href: '/siem-soar/threat-intelligence' },
      { id: 'automation', label: 'Automation', icon: <BoltIcon className="w-4 h-4" />, href: '/siem-soar/automation' },
      { id: 'compliance', label: 'Compliance', icon: <ShieldCheckIcon className="w-4 h-4" />, href: '/siem-soar/compliance' }
    ]
  },

  {
    id: 'incidents',
    label: 'Incidents',
    icon: <BellIcon className="w-5 h-5" />,
    href: '/incidents',
    badge: 3
  },
  {
    id: 'settings',
    label: 'Settings',
    icon: <CogIcon className="w-5 h-5" />,
    href: '/settings'
  }
];

export const EnhancedNavigation: React.FC<EnhancedNavigationProps> = ({
  className = ''
}) => {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [expandedItems, setExpandedItems] = useState<string[]>([]);
  const [theme, setTheme] = useState<'light' | 'dark' | 'auto'>('dark');
  const [searchQuery, setSearchQuery] = useState('');
  const [showUserMenu, setShowUserMenu] = useState(false);
  const location = useLocation();
  const { user, logout } = useAuth();

  // Close mobile menu when route changes
  useEffect(() => {
    setIsMobileMenuOpen(false);
  }, [location.pathname]);

  const toggleExpanded = (itemId: string) => {
    setExpandedItems(prev => 
      prev.includes(itemId) 
        ? prev.filter(id => id !== itemId)
        : [...prev, itemId]
    );
  };

  const toggleTheme = () => {
    const themes: ('light' | 'dark' | 'auto')[] = ['light', 'dark', 'auto'];
    const currentIndex = themes.indexOf(theme);
    const nextIndex = (currentIndex + 1) % themes.length;
    setTheme(themes[nextIndex]);
  };

  const getThemeIcon = () => {
    switch (theme) {
      case 'light': return <SunIcon className="w-5 h-5" />;
      case 'dark': return <MoonIcon className="w-5 h-5" />;
      case 'auto': return <ComputerDesktopIcon className="w-5 h-5" />;
    }
  };

  const handleLogout = () => {
    setShowUserMenu(false);
    logout();
  };

  const renderNavigationItem = (item: NavigationItem, isChild = false) => {
    const isActive = location.pathname === item.href;
    const isExpanded = expandedItems.includes(item.id);
    const hasChildren = item.children && item.children.length > 0;

    return (
      <motion.div
        key={item.id}
        initial={{ opacity: 0, x: -20 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ duration: 0.2 }}
      >
        <Link
          to={item.href}
          className={`
            flex items-center justify-between px-4 py-3 rounded-lg transition-all duration-200 group
            ${isActive 
              ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20' 
              : 'text-gray-300 hover:bg-gray-800/50 hover:text-white'
            }
            ${isChild ? 'ml-4 text-sm' : ''}
          `}
          onClick={() => hasChildren && toggleExpanded(item.id)}
        >
          <div className="flex items-center gap-3">
            <div className={`
              ${isActive ? 'text-blue-400' : 'text-gray-400 group-hover:text-white'}
              transition-colors duration-200
            `}>
              {item.icon}
            </div>
            <span className="font-medium">{item.label}</span>
          </div>
          
          <div className="flex items-center gap-2">
            {item.badge && (
              <motion.span
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                className="px-2 py-1 text-xs font-medium bg-red-500 text-white rounded-full"
              >
                {item.badge}
              </motion.span>
            )}
            {hasChildren && (
              <motion.div
                animate={{ rotate: isExpanded ? 90 : 0 }}
                transition={{ duration: 0.2 }}
                className="text-gray-400"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                </svg>
              </motion.div>
            )}
          </div>
        </Link>

        {/* Children */}
        {hasChildren && (
          <AnimatePresence>
            {isExpanded && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                transition={{ duration: 0.3 }}
                className="overflow-hidden"
              >
                <div className="mt-2 space-y-1">
                  {item.children!.map(child => renderNavigationItem(child, true))}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        )}
      </motion.div>
    );
  };

  return (
    <>
      {/* Desktop Navigation */}
      <nav className={`hidden lg:flex flex-col w-64 bg-gray-900/50 backdrop-blur-xl border-r border-gray-800 h-screen ${className}`}>
        {/* Header */}
        <div className="p-6 border-b border-gray-800">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center">
              <ShieldCheckIcon className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">Cyber Cursor</h1>
              <p className="text-sm text-gray-400">Security Platform</p>
            </div>
          </div>
        </div>

        {/* Search */}
        <div className="p-4 border-b border-gray-800">
          <div className="relative">
            <input
              type="text"
              placeholder="Search..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full px-4 py-2 pl-10 bg-gray-800/50 border border-gray-700 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200"
            />
            <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
          </div>
        </div>

        {/* Navigation Items */}
        <div className="flex-1 p-4 space-y-2 overflow-y-auto">
          {navigationItems.map((item) => renderNavigationItem(item))}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-gray-800">
          <div className="flex items-center justify-between">
            <button
              onClick={toggleTheme}
              className="flex items-center gap-2 px-3 py-2 text-gray-400 hover:text-white hover:bg-gray-800/50 rounded-lg transition-all duration-200"
            >
              {getThemeIcon()}
              <span className="text-sm capitalize">{theme}</span>
            </button>
            
            <div className="flex items-center gap-2">
              <button className="p-2 text-gray-400 hover:text-white hover:bg-gray-800/50 rounded-lg transition-all duration-200">
                <BellIcon className="w-5 h-5" />
              </button>
              
              {/* User Menu */}
              <div className="relative">
                <button 
                  onClick={() => setShowUserMenu(!showUserMenu)}
                  className="p-2 text-gray-400 hover:text-white hover:bg-gray-800/50 rounded-lg transition-all duration-200"
                >
                  <UserCircleIcon className="w-5 h-5" />
                </button>
                
                {/* User Dropdown Menu */}
                <AnimatePresence>
                  {showUserMenu && (
                    <motion.div
                      initial={{ opacity: 0, y: -10, scale: 0.95 }}
                      animate={{ opacity: 1, y: 0, scale: 1 }}
                      exit={{ opacity: 0, y: -10, scale: 0.95 }}
                      transition={{ duration: 0.2 }}
                      className="absolute bottom-full right-0 mb-2 w-48 bg-gray-800 border border-gray-700 rounded-lg shadow-lg overflow-hidden z-50"
                    >
                      {/* User Info */}
                      <div className="px-4 py-3 border-b border-gray-700">
                        <p className="text-sm font-medium text-white">{user?.email}</p>
                        <p className="text-xs text-gray-400 capitalize">{user?.role}</p>
                      </div>
                      
                      {/* Menu Items */}
                      <div className="py-1">
                        <button
                          onClick={handleLogout}
                          className="w-full flex items-center gap-3 px-4 py-2 text-sm text-gray-300 hover:bg-gray-700 hover:text-white transition-colors duration-200"
                        >
                          <ArrowRightOnRectangleIcon className="w-4 h-4" />
                          <span>Sign Out</span>
                        </button>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </div>
          </div>
        </div>
      </nav>

      {/* Mobile Navigation */}
      <div className="lg:hidden">
        {/* Mobile Header */}
        <div className="flex items-center justify-between p-4 bg-gray-900/50 backdrop-blur-xl border-b border-gray-800">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center">
              <ShieldCheckIcon className="w-5 h-5 text-white" />
            </div>
            <h1 className="text-xl font-bold text-white">Cyber Cursor</h1>
          </div>
          
          <div className="flex items-center gap-2">
            <button
              onClick={toggleTheme}
              className="p-2 text-gray-400 hover:text-white hover:bg-gray-800/50 rounded-lg transition-all duration-200"
            >
              {getThemeIcon()}
            </button>
            
            <button
              onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
              className="p-2 text-gray-400 hover:text-white hover:bg-gray-800/50 rounded-lg transition-all duration-200"
            >
              {isMobileMenuOpen ? (
                <XMarkIcon className="w-6 h-6" />
              ) : (
                <Bars3Icon className="w-6 h-6" />
              )}
            </button>
          </div>
        </div>

        {/* Mobile Menu */}
        <AnimatePresence>
          {isMobileMenuOpen && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              transition={{ duration: 0.3 }}
              className="bg-gray-900/95 backdrop-blur-xl border-b border-gray-800 overflow-hidden"
            >
              {/* Search */}
              <div className="p-4 border-b border-gray-800">
                <div className="relative">
                  <input
                    type="text"
                    placeholder="Search..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full px-4 py-2 pl-10 bg-gray-800/50 border border-gray-700 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200"
                  />
                  <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                </div>
              </div>

              {/* Navigation Items */}
              <div className="p-4 space-y-2">
                {navigationItems.map((item) => renderNavigationItem(item))}
              </div>

              {/* User Actions */}
              <div className="p-4 border-t border-gray-800">
                <div className="flex items-center justify-between">
                  <button className="flex items-center gap-2 px-3 py-2 text-gray-400 hover:text-white hover:bg-gray-800/50 rounded-lg transition-all duration-200">
                    <BellIcon className="w-5 h-5" />
                    <span className="text-sm">Notifications</span>
                  </button>
                  
                  <button 
                    onClick={handleLogout}
                    className="flex items-center gap-2 px-3 py-2 text-gray-400 hover:text-white hover:bg-gray-800/50 rounded-lg transition-all duration-200"
                  >
                    <ArrowRightOnRectangleIcon className="w-5 h-5" />
                    <span className="text-sm">Sign Out</span>
                  </button>
                </div>
                
                {/* User Info */}
                <div className="mt-3 pt-3 border-t border-gray-700">
                  <p className="text-sm text-gray-300">{user?.email}</p>
                  <p className="text-xs text-gray-400 capitalize">{user?.role}</p>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </>
  );
};

export default EnhancedNavigation; 