import React, { createContext, useContext, ReactNode } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

// Design System Context
interface DesignSystemContextType {
  theme: 'light' | 'dark' | 'auto';
  setTheme: (theme: 'light' | 'dark' | 'auto') => void;
  animations: {
    pageTransition: any;
    cardHover: any;
    buttonTap: any;
    modalBackdrop: any;
    listItem: any;
  };
  colors: {
    primary: string;
    secondary: string;
    success: string;
    warning: string;
    danger: string;
    info: string;
    background: string;
    surface: string;
    text: string;
    textSecondary: string;
    border: string;
  };
}

const DesignSystemContext = createContext<DesignSystemContextType | undefined>(undefined);

// Animation Presets
const animations = {
  pageTransition: {
    initial: { opacity: 0, y: 20 },
    animate: { opacity: 1, y: 0 },
    exit: { opacity: 0, y: -20 },
    transition: { duration: 0.3, ease: 'easeInOut' }
  },
  cardHover: {
    whileHover: { 
      scale: 1.02, 
      y: -2,
      transition: { duration: 0.2, ease: 'easeOut' }
    },
    whileTap: { 
      scale: 0.98,
      transition: { duration: 0.1 }
    }
  },
  buttonTap: {
    whileHover: { 
      scale: 1.05,
      transition: { duration: 0.2 }
    },
    whileTap: { 
      scale: 0.95,
      transition: { duration: 0.1 }
    }
  },
  modalBackdrop: {
    initial: { opacity: 0 },
    animate: { opacity: 1 },
    exit: { opacity: 0 },
    transition: { duration: 0.2 }
  },
  listItem: {
    initial: { opacity: 0, x: -20 },
    animate: { opacity: 1, x: 0 },
    exit: { opacity: 0, x: 20 },
    transition: { duration: 0.3 }
  }
};

// Color Schemes
const colorSchemes = {
  dark: {
    primary: '#3B82F6',
    secondary: '#6B7280',
    success: '#10B981',
    warning: '#F59E0B',
    danger: '#EF4444',
    info: '#06B6D4',
    background: '#0F172A',
    surface: '#1E293B',
    text: '#F8FAFC',
    textSecondary: '#94A3B8',
    border: '#334155'
  },
  light: {
    primary: '#2563EB',
    secondary: '#6B7280',
    success: '#059669',
    warning: '#D97706',
    danger: '#DC2626',
    info: '#0891B2',
    background: '#FFFFFF',
    surface: '#F8FAFC',
    text: '#1E293B',
    textSecondary: '#64748B',
    border: '#E2E8F0'
  },
  auto: {
    primary: '#3B82F6',
    secondary: '#6B7280',
    success: '#10B981',
    warning: '#F59E0B',
    danger: '#EF4444',
    info: '#06B6D4',
    background: '#0F172A',
    surface: '#1E293B',
    text: '#F8FAFC',
    textSecondary: '#94A3B8',
    border: '#334155'
  }
};

// Enhanced Page Container
interface PageContainerProps {
  children: ReactNode;
  className?: string;
  title?: string;
  subtitle?: string;
  actions?: ReactNode;
  loading?: boolean;
  error?: string;
}

export const PageContainer: React.FC<PageContainerProps> = ({
  children,
  className = '',
  title,
  subtitle,
  actions,
  loading = false,
  error
}) => {
  return (
    <motion.div
      {...animations.pageTransition}
      className={`min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 ${className}`}
    >
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        {(title || subtitle || actions) && (
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            className="mb-8"
          >
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
              <div>
                {title && (
                  <h1 className="text-3xl font-bold text-white mb-2">
                    {title}
                  </h1>
                )}
                {subtitle && (
                  <p className="text-gray-400 text-lg">
                    {subtitle}
                  </p>
                )}
              </div>
              {actions && (
                <div className="flex flex-wrap gap-3">
                  {actions}
                </div>
              )}
            </div>
          </motion.div>
        )}

        {/* Error State */}
        {error && (
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="mb-6 p-4 bg-red-500/10 border border-red-500/20 rounded-lg"
          >
            <div className="flex items-center gap-3">
              <div className="w-2 h-2 bg-red-500 rounded-full animate-pulse" />
              <p className="text-red-400 font-medium">{error}</p>
            </div>
          </motion.div>
        )}

        {/* Loading State */}
        {loading && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="flex items-center justify-center py-12"
          >
            <div className="flex items-center gap-3">
              <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
              <span className="text-gray-400">Loading...</span>
            </div>
          </motion.div>
        )}

        {/* Content */}
        <AnimatePresence mode="wait">
          {!loading && (
            <motion.div
              key="content"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.2 }}
            >
              {children}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  );
};

// Enhanced Grid Layout
interface GridLayoutProps {
  children: ReactNode;
  cols?: 1 | 2 | 3 | 4 | 6 | 12;
  gap?: 'sm' | 'md' | 'lg' | 'xl';
  className?: string;
}

export const GridLayout: React.FC<GridLayoutProps> = ({
  children,
  cols = 3,
  gap = 'lg',
  className = ''
}) => {
  const gridCols = {
    1: 'grid-cols-1',
    2: 'grid-cols-1 md:grid-cols-2',
    3: 'grid-cols-1 md:grid-cols-2 lg:grid-cols-3',
    4: 'grid-cols-1 md:grid-cols-2 lg:grid-cols-4',
    6: 'grid-cols-2 md:grid-cols-3 lg:grid-cols-6',
    12: 'grid-cols-2 md:grid-cols-4 lg:grid-cols-6 xl:grid-cols-12'
  };

  const gridGaps = {
    sm: 'gap-3',
    md: 'gap-4',
    lg: 'gap-6',
    xl: 'gap-8'
  };

  return (
    <div className={`grid ${gridCols[cols]} ${gridGaps[gap]} ${className}`}>
      {children}
    </div>
  );
};

// Enhanced Loading Spinner
interface LoadingSpinnerProps {
  size?: 'sm' | 'md' | 'lg' | 'xl';
  color?: 'primary' | 'white' | 'gray';
  text?: string;
  className?: string;
}

export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({
  size = 'md',
  color = 'primary',
  text,
  className = ''
}) => {
  const sizes = {
    sm: 'w-4 h-4',
    md: 'w-6 h-6',
    lg: 'w-8 h-8',
    xl: 'w-12 h-12'
  };

  const colors = {
    primary: 'border-blue-500 border-t-transparent',
    white: 'border-white border-t-transparent',
    gray: 'border-gray-400 border-t-transparent'
  };

  return (
    <div className={`flex items-center gap-3 ${className}`}>
      <div
        className={`${sizes[size]} border-2 ${colors[color]} rounded-full animate-spin`}
      />
      {text && <span className="text-gray-400">{text}</span>}
    </div>
  );
};

// Enhanced Empty State
interface EmptyStateProps {
  icon?: ReactNode;
  title: string;
  description?: string;
  action?: ReactNode;
  className?: string;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon,
  title,
  description,
  action,
  className = ''
}) => {
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      className={`flex flex-col items-center justify-center py-12 text-center ${className}`}
    >
      {icon && (
        <div className="w-16 h-16 text-gray-400 mb-4">
          {icon}
        </div>
      )}
      <h3 className="text-xl font-semibold text-white mb-2">
        {title}
      </h3>
      {description && (
        <p className="text-gray-400 mb-6 max-w-md">
          {description}
        </p>
      )}
      {action && action}
    </motion.div>
  );
};

// Enhanced Search Input
interface SearchInputProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  className?: string;
  onSearch?: () => void;
}

export const SearchInput: React.FC<SearchInputProps> = ({
  value,
  onChange,
  placeholder = 'Search...',
  className = '',
  onSearch
}) => {
  return (
    <div className={`relative ${className}`}>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full px-4 py-3 pl-12 bg-gray-800/50 border border-gray-700 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200"
        onKeyPress={(e) => e.key === 'Enter' && onSearch?.()}
      />
      <div className="absolute left-4 top-1/2 transform -translate-y-1/2 text-gray-400">
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
      </div>
    </div>
  );
};

// Enhanced Filter Bar
interface FilterBarProps {
  filters: Array<{
    key: string;
    label: string;
    options: Array<{ value: string; label: string }>;
    value: string;
    onChange: (value: string) => void;
  }>;
  className?: string;
}

export const FilterBar: React.FC<FilterBarProps> = ({
  filters,
  className = ''
}) => {
  return (
    <div className={`flex flex-wrap gap-4 ${className}`}>
      {filters.map((filter) => (
        <div key={filter.key} className="flex flex-col">
          <label className="text-sm font-medium text-gray-400 mb-1">
            {filter.label}
          </label>
          <select
            value={filter.value}
            onChange={(e) => filter.onChange(e.target.value)}
            className="px-3 py-2 bg-gray-800/50 border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200"
          >
            {filter.options.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </div>
      ))}
    </div>
  );
};

// Enhanced Breadcrumb
interface BreadcrumbItem {
  label: string;
  href?: string;
  onClick?: () => void;
}

interface BreadcrumbProps {
  items: BreadcrumbItem[];
  className?: string;
}

export const Breadcrumb: React.FC<BreadcrumbProps> = ({
  items,
  className = ''
}) => {
  return (
    <nav className={`flex items-center space-x-2 text-sm ${className}`}>
      {items.map((item, index) => (
        <React.Fragment key={index}>
          {index > 0 && (
            <svg className="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
            </svg>
          )}
          {item.href || item.onClick ? (
            <button
              onClick={item.onClick}
              className="text-gray-400 hover:text-white transition-colors duration-200"
            >
              {item.label}
            </button>
          ) : (
            <span className="text-white font-medium">{item.label}</span>
          )}
        </React.Fragment>
      ))}
    </nav>
  );
};

// Design System Provider
interface DesignSystemProviderProps {
  children: ReactNode;
  theme?: 'light' | 'dark' | 'auto';
}

export const DesignSystemProvider: React.FC<DesignSystemProviderProps> = ({
  children,
  theme = 'dark'
}) => {
  const [currentTheme, setCurrentTheme] = React.useState(theme);

  const value: DesignSystemContextType = {
    theme: currentTheme,
    setTheme: setCurrentTheme,
    animations,
    colors: colorSchemes[currentTheme]
  };

  return (
    <DesignSystemContext.Provider value={value}>
      {children}
    </DesignSystemContext.Provider>
  );
};

// Hook to use design system
export const useDesignSystem = () => {
  const context = useContext(DesignSystemContext);
  if (!context) {
    throw new Error('useDesignSystem must be used within a DesignSystemProvider');
  }
  return context;
};

export default DesignSystemProvider; 