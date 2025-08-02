import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import {
  HomeIcon,
  ShieldCheckIcon,
  CloudIcon,
  WifiIcon,
  CodeBracketIcon,
  UserGroupIcon,
  ChartBarIcon,
  CogIcon,
  DocumentTextIcon,
  BellIcon,
  ExclamationTriangleIcon,
  LockClosedIcon,
  ServerIcon,
  GlobeAltIcon,
  CpuChipIcon,
  ShieldExclamationIcon
} from '@heroicons/react/24/outline';

interface NavigationItem {
  name: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  roles: string[];
  description?: string;
}

const navigationItems: NavigationItem[] = [
  {
    name: 'Dashboard',
    href: '/dashboard',
    icon: HomeIcon,
    roles: ['admin', 'analyst', 'user'],
    description: 'Overview and metrics'
  },
  {
    name: 'Cloud Security',
    href: '/cloud-security',
    icon: CloudIcon,
    roles: ['admin', 'analyst', 'user'],
    description: 'CSPM, CASB, Cloud-native security'
  },
  {
    name: 'Network Security',
    href: '/network-security',
    icon: WifiIcon,
    roles: ['admin', 'analyst', 'user'],
    description: 'Firewalls, IDS/IPS, VPN, NAC'
  },
  {
    name: 'SAST Analysis',
    href: '/sast',
    icon: CodeBracketIcon,
    roles: ['admin', 'analyst'],
    description: 'Static application security testing'
  },
  {
    name: 'Incidents',
    href: '/incidents',
    icon: ExclamationTriangleIcon,
    roles: ['admin', 'analyst'],
    description: 'Security incident management'
  },
  {
    name: 'Threat Intelligence',
    href: '/threat-intelligence',
    icon: ShieldExclamationIcon,
    roles: ['admin', 'analyst'],
    description: 'Threat feeds and intelligence'
  },
  {
    name: 'Analytics',
    href: '/analytics',
    icon: ChartBarIcon,
    roles: ['admin', 'analyst'],
    description: 'Security analytics and reporting'
  },
  {
    name: 'User Management',
    href: '/admin/users',
    icon: UserGroupIcon,
    roles: ['admin'],
    description: 'Manage users and roles'
  },
  {
    name: 'System Settings',
    href: '/admin/settings',
    icon: CogIcon,
    roles: ['admin'],
    description: 'System configuration'
  },
  {
    name: 'Compliance',
    href: '/compliance',
    icon: DocumentTextIcon,
    roles: ['admin', 'analyst'],
    description: 'Compliance reporting'
  },
  {
    name: 'Integrations',
    href: '/integrations',
    icon: ServerIcon,
    roles: ['admin'],
    description: 'Third-party integrations'
  },
  {
    name: 'Data Protection',
    href: '/data-protection',
    icon: LockClosedIcon,
    roles: ['admin', 'analyst'],
    description: 'Data protection and privacy'
  },
  {
    name: 'Endpoint Security',
    href: '/endpoint-security',
    icon: CpuChipIcon,
    roles: ['admin', 'analyst'],
    description: 'Endpoint protection and monitoring'
  },
  {
    name: 'Application Security',
    href: '/application-security',
    icon: CodeBracketIcon,
    roles: ['admin', 'analyst'],
    description: 'Application security testing'
  },
  {
    name: 'Monitoring & SIEM',
    href: '/monitoring-siem-soar',
    icon: GlobeAltIcon,
    roles: ['admin', 'analyst'],
    description: 'Security monitoring and SIEM'
  }
];

const RoleBasedNavigation: React.FC = () => {
  const { user } = useAuth();
  const location = useLocation();

  if (!user) {
    return null;
  }

  // Filter navigation items based on user role
  const allowedItems = navigationItems.filter(item => 
    item.roles.includes(user.role)
  );

  return (
    <nav className="space-y-1">
      {allowedItems.map((item) => {
        const isActive = location.pathname === item.href;
        const Icon = item.icon;
        
        return (
          <Link
            key={item.name}
            to={item.href}
            className={`
              group flex items-center px-3 py-2 text-sm font-medium rounded-md transition-colors duration-200
              ${isActive
                ? 'bg-blue-600 text-white shadow-lg'
                : 'text-gray-300 hover:bg-gray-700 hover:text-white'
              }
            `}
            title={item.description}
          >
            <Icon
              className={`
                mr-3 flex-shrink-0 h-5 w-5 transition-colors duration-200
                ${isActive
                  ? 'text-white'
                  : 'text-gray-400 group-hover:text-white'
                }
              `}
              aria-hidden="true"
            />
            <span className="truncate">{item.name}</span>
            
            {/* Role indicator for admin-only items */}
            {item.roles.length === 1 && item.roles[0] === 'admin' && (
              <span className="ml-auto inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-800">
                Admin
              </span>
            )}
          </Link>
        );
      })}
    </nav>
  );
};

export default RoleBasedNavigation; 