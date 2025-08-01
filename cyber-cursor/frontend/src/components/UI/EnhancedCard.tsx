import React, { ReactNode } from 'react';
import { motion } from 'framer-motion';

interface EnhancedCardProps {
  children: ReactNode;
  className?: string;
  variant?: 'default' | 'elevated' | 'glass' | 'gradient';
  hover?: boolean;
  onClick?: () => void;
  loading?: boolean;
  icon?: ReactNode;
  title?: string;
  subtitle?: string;
  badge?: ReactNode;
  actions?: ReactNode;
}

const EnhancedCard: React.FC<EnhancedCardProps> = ({
  children,
  className = '',
  variant = 'default',
  hover = true,
  onClick,
  loading = false,
  icon,
  title,
  subtitle,
  badge,
  actions
}) => {
  const baseClasses = 'relative overflow-hidden rounded-xl border transition-all duration-300';
  
  const variantClasses = {
    default: 'bg-gray-800/50 border-gray-700/50 backdrop-blur-sm',
    elevated: 'bg-gray-800/80 border-gray-600/50 shadow-2xl shadow-black/20',
    glass: 'bg-white/5 border-white/10 backdrop-blur-md',
    gradient: 'bg-gradient-to-br from-blue-500/10 to-purple-500/10 border-blue-400/20'
  };

  const hoverClasses = hover ? 'hover:scale-[1.02] hover:shadow-xl hover:border-gray-500/50' : '';
  const clickableClasses = onClick ? 'cursor-pointer active:scale-[0.98]' : '';

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className={`${baseClasses} ${variantClasses[variant]} ${hoverClasses} ${clickableClasses} ${className}`}
      onClick={onClick}
      whileHover={hover ? { scale: 1.02 } : {}}
      whileTap={onClick ? { scale: 0.98 } : {}}
    >
      {/* Loading overlay */}
      {loading && (
        <div className="absolute inset-0 bg-gray-900/50 backdrop-blur-sm flex items-center justify-center z-10">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
        </div>
      )}

      {/* Header */}
      {(title || icon || badge || actions) && (
        <div className="flex items-center justify-between p-6 pb-4">
          <div className="flex items-center space-x-3">
            {icon && (
              <div className="flex-shrink-0">
                {icon}
              </div>
            )}
            <div className="flex-1 min-w-0">
              {title && (
                <h3 className="text-lg font-semibold text-white truncate">
                  {title}
                </h3>
              )}
              {subtitle && (
                <p className="text-sm text-gray-400 truncate">
                  {subtitle}
                </p>
              )}
            </div>
          </div>
          <div className="flex items-center space-x-2">
            {badge && badge}
            {actions && actions}
          </div>
        </div>
      )}

      {/* Content */}
      <div className="p-6 pt-0">
        {children}
      </div>

      {/* Gradient overlay for glass effect */}
      {variant === 'glass' && (
        <div className="absolute inset-0 bg-gradient-to-br from-white/5 to-transparent pointer-events-none" />
      )}
    </motion.div>
  );
};

export default EnhancedCard; 