import React from 'react';
import { ChevronRightIcon, HomeIcon } from '@heroicons/react/24/outline';
import { Link } from 'react-router-dom';

export interface BreadcrumbItem {
  label: string;
  path?: string;
  icon?: React.ComponentType<{ className?: string }>;
}

interface BreadcrumbNavigationProps {
  items: BreadcrumbItem[];
  className?: string;
}

const BreadcrumbNavigation: React.FC<BreadcrumbNavigationProps> = ({ 
  items, 
  className = '' 
}) => {
  return (
    <nav className={`flex items-center space-x-1 text-sm text-gray-600 ${className}`}>
      {/* Home */}
      <Link
        to="/sast"
        className="flex items-center space-x-1 hover:text-gray-900 transition-colors"
      >
        <HomeIcon className="w-4 h-4" />
        <span>SAST</span>
      </Link>

      {/* Separator */}
      <ChevronRightIcon className="w-4 h-4 text-gray-400" />

      {/* Breadcrumb items */}
      {items.map((item, index) => (
        <React.Fragment key={index}>
          {item.path ? (
            <Link
              to={item.path}
              className="flex items-center space-x-1 hover:text-gray-900 transition-colors"
            >
              {item.icon && <item.icon className="w-4 h-4" />}
              <span>{item.label}</span>
            </Link>
          ) : (
            <span className="flex items-center space-x-1 text-gray-900">
              {item.icon && <item.icon className="w-4 h-4" />}
              <span>{item.label}</span>
            </span>
          )}
          
          {/* Separator (except for last item) */}
          {index < items.length - 1 && (
            <ChevronRightIcon className="w-4 h-4 text-gray-400" />
          )}
        </React.Fragment>
      ))}
    </nav>
  );
};

export default BreadcrumbNavigation;
