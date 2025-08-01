import React, { ReactNode } from 'react';
import { motion } from 'framer-motion';

interface Tab {
  id: string;
  label: string;
  icon?: ReactNode;
  content: ReactNode;
  disabled?: boolean;
}

interface EnhancedTabsProps {
  tabs: Tab[];
  activeTab: string;
  onTabChange: (tabId: string) => void;
  variant?: 'default' | 'pills' | 'underline';
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

const EnhancedTabs: React.FC<EnhancedTabsProps> = ({
  tabs,
  activeTab,
  onTabChange,
  variant = 'default',
  size = 'md',
  className = ''
}) => {
  const baseClasses = 'flex space-x-1';
  
  const variantClasses = {
    default: 'bg-gray-800 p-1 rounded-lg',
    pills: 'bg-transparent space-x-2',
    underline: 'bg-transparent border-b border-gray-700'
  };

  const sizeClasses = {
    sm: 'text-sm',
    md: 'text-base',
    lg: 'text-lg'
  };

  const getTabClasses = (tab: Tab, isActive: boolean) => {
    const baseTabClasses = 'flex items-center px-4 py-2 rounded-md text-sm font-medium transition-all duration-200 cursor-pointer';
    
    if (tab.disabled) {
      return `${baseTabClasses} text-gray-500 cursor-not-allowed opacity-50`;
    }

    switch (variant) {
      case 'default':
        return `${baseTabClasses} ${
          isActive 
            ? 'bg-blue-600 text-white shadow-lg' 
            : 'text-gray-400 hover:text-white hover:bg-gray-700'
        }`;
      case 'pills':
        return `${baseTabClasses} ${
          isActive 
            ? 'bg-blue-600 text-white shadow-lg' 
            : 'text-gray-400 hover:text-white hover:bg-gray-700/50'
        }`;
      case 'underline':
        return `${baseTabClasses} ${
          isActive 
            ? 'text-blue-400 border-b-2 border-blue-400' 
            : 'text-gray-400 hover:text-white hover:border-b-2 hover:border-gray-500'
        }`;
      default:
        return baseTabClasses;
    }
  };

  const activeTabIndex = tabs.findIndex(tab => tab.id === activeTab);

  return (
    <div className={className}>
      {/* Tab Navigation */}
      <div className={`${baseClasses} ${variantClasses[variant]} ${sizeClasses[size]}`}>
        {tabs.map((tab, index) => (
          <motion.button
            key={tab.id}
            onClick={() => !tab.disabled && onTabChange(tab.id)}
            className={getTabClasses(tab, tab.id === activeTab)}
            disabled={tab.disabled}
            whileHover={!tab.disabled ? { scale: 1.05 } : {}}
            whileTap={!tab.disabled ? { scale: 0.95 } : {}}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.2, delay: index * 0.1 }}
          >
            {tab.icon && (
              <span className="mr-2">
                {tab.icon}
              </span>
            )}
            {tab.label}
          </motion.button>
        ))}
      </div>

      {/* Tab Content */}
      <motion.div
        key={activeTab}
        initial={{ opacity: 0, x: 20 }}
        animate={{ opacity: 1, x: 0 }}
        exit={{ opacity: 0, x: -20 }}
        transition={{ duration: 0.3 }}
        className="mt-6"
      >
        {tabs.find(tab => tab.id === activeTab)?.content}
      </motion.div>
    </div>
  );
};

export default EnhancedTabs; 