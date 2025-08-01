import React from 'react';
import { motion } from 'framer-motion';

interface EnhancedBadgeProps {
  children: React.ReactNode;
  variant?: 'default' | 'success' | 'warning' | 'danger' | 'info' | 'primary';
  size?: 'sm' | 'md' | 'lg';
  rounded?: boolean;
  withDot?: boolean;
  className?: string;
}

const EnhancedBadge: React.FC<EnhancedBadgeProps> = ({
  children,
  variant = 'default',
  size = 'md',
  rounded = false,
  withDot = false,
  className = ''
}) => {
  const baseClasses = 'inline-flex items-center font-medium transition-all duration-200';
  
  const variantClasses = {
    default: 'bg-gray-700 text-gray-300 border border-gray-600',
    success: 'bg-green-500/20 text-green-400 border border-green-500/30',
    warning: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
    danger: 'bg-red-500/20 text-red-400 border border-red-500/30',
    info: 'bg-blue-500/20 text-blue-400 border border-blue-500/30',
    primary: 'bg-blue-600 text-white border border-blue-500'
  };

  const sizeClasses = {
    sm: 'px-2 py-0.5 text-xs',
    md: 'px-2.5 py-1 text-sm',
    lg: 'px-3 py-1.5 text-base'
  };

  const roundedClasses = rounded ? 'rounded-full' : 'rounded-md';

  const dotColors = {
    default: 'bg-gray-400',
    success: 'bg-green-400',
    warning: 'bg-yellow-400',
    danger: 'bg-red-400',
    info: 'bg-blue-400',
    primary: 'bg-white'
  };

  return (
    <motion.span
      className={`${baseClasses} ${variantClasses[variant]} ${sizeClasses[size]} ${roundedClasses} ${className}`}
      initial={{ opacity: 0, scale: 0.8 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.2 }}
      whileHover={{ scale: 1.05 }}
    >
      {withDot && (
        <motion.span
          className={`w-2 h-2 rounded-full mr-1.5 ${dotColors[variant]}`}
          initial={{ scale: 0 }}
          animate={{ scale: 1 }}
          transition={{ delay: 0.1, duration: 0.2 }}
        />
      )}
      {children}
    </motion.span>
  );
};

export default EnhancedBadge; 