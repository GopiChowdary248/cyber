import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Shield,
  Lock,
  Smartphone,
  Monitor,
  Laptop,
  Tablet,
  AlertTriangle,
  CheckCircle,
  Clock,
  TrendingUp,
  Plus,
  Search,
  Filter,
  Download,
  Upload,
  Eye,
  EyeOff,
  Users,
  Settings,
  Zap
} from 'lucide-react';
import DeviceControlDashboard from '../../components/DeviceControl/DeviceControlDashboard';

const DeviceControl: React.FC = () => {
  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900">Device Control & Management</h1>
          <p className="mt-2 text-gray-600">
            Monitor and control connected devices with comprehensive security policies and real-time monitoring.
          </p>
        </div>
        
        <DeviceControlDashboard />
      </div>
    </div>
  );
};

export default DeviceControl;
