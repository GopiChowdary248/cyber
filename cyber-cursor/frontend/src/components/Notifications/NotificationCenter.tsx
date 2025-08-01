import React, { useState, useEffect, useRef } from 'react';
import { BellIcon, XMarkIcon, CogIcon, CheckIcon } from '@heroicons/react/24/outline';
import { toast } from 'react-hot-toast';

interface Notification {
  id: string;
  type: string;
  message: string;
  timestamp: string;
  read: boolean;
  priority: 'low' | 'medium' | 'high' | 'critical';
  action_url?: string;
  metadata?: any;
}

interface NotificationPreferences {
  in_app_notifications: boolean;
  email_notifications: boolean;
  slack_notifications: boolean;
  sms_notifications: boolean;
  incident_enabled: boolean;
  security_alert_enabled: boolean;
  training_reminder_enabled: boolean;
  system_update_enabled: boolean;
  compliance_alert_enabled: boolean;
  phishing_alert_enabled: boolean;
  cloud_security_enabled: boolean;
  user_activity_enabled: boolean;
  quiet_hours_start: string;
  quiet_hours_end: string;
  timezone: string;
}

const NotificationCenter: React.FC = () => {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [isOpen, setIsOpen] = useState(false);
  const [isPreferencesOpen, setIsPreferencesOpen] = useState(false);
  const [unreadCount, setUnreadCount] = useState(0);
  const [isConnected, setIsConnected] = useState(false);
  const [preferences, setPreferences] = useState<NotificationPreferences>({
    in_app_notifications: true,
    email_notifications: true,
    slack_notifications: false,
    sms_notifications: false,
    incident_enabled: true,
    security_alert_enabled: true,
    training_reminder_enabled: true,
    system_update_enabled: false,
    compliance_alert_enabled: true,
    phishing_alert_enabled: true,
    cloud_security_enabled: true,
    user_activity_enabled: false,
    quiet_hours_start: "22:00",
    quiet_hours_end: "08:00",
    timezone: "UTC"
  });

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    initializeWebSocket();
    loadNotifications();
    loadPreferences();

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
    };
  }, []);

  const initializeWebSocket = () => {
    const token = localStorage.getItem('access_token');
    if (!token) return;

    const wsUrl = `${process.env.REACT_APP_API_URL?.replace('http', 'ws')}/api/v1/ws/${token}`;
    wsRef.current = new WebSocket(wsUrl);

    wsRef.current.onopen = () => {
      setIsConnected(true);
      console.log('WebSocket connected');
      
      // Send initial message to get notifications
      wsRef.current?.send(JSON.stringify({
        type: 'get_notifications'
      }));
    };

    wsRef.current.onmessage = (event) => {
      const data = JSON.parse(event.data);
      handleWebSocketMessage(data);
    };

    wsRef.current.onclose = () => {
      setIsConnected(false);
      console.log('WebSocket disconnected');
      
      // Attempt to reconnect after 5 seconds
      reconnectTimeoutRef.current = setTimeout(() => {
        initializeWebSocket();
      }, 5000);
    };

    wsRef.current.onerror = (error) => {
      console.error('WebSocket error:', error);
      setIsConnected(false);
    };
  };

  const handleWebSocketMessage = (data: any) => {
    switch (data.type) {
      case 'connection_established':
        console.log('WebSocket connection established');
        break;
      
      case 'notification':
        handleNewNotification(data);
        break;
      
      case 'notifications':
        setNotifications(data.notifications || []);
        updateUnreadCount(data.notifications || []);
        break;
      
      case 'subscriptions_updated':
        console.log('Notification subscriptions updated');
        break;
      
      case 'heartbeat':
        // Handle heartbeat - connection is alive
        break;
      
      default:
        console.log('Unknown WebSocket message type:', data.type);
    }
  };

  const handleNewNotification = (notification: Notification) => {
    setNotifications(prev => [notification, ...prev]);
    updateUnreadCount([notification, ...notifications]);
    
    // Show toast for high priority notifications
    if (notification.priority === 'critical' || notification.priority === 'high') {
      toast.custom((t) => (
        <div className={`${t.visible ? 'animate-enter' : 'animate-leave'} max-w-md w-full bg-white shadow-lg rounded-lg pointer-events-auto flex ring-1 ring-black ring-opacity-5`}>
          <div className="flex-1 w-0 p-4">
            <div className="flex items-start">
              <div className="flex-shrink-0">
                <div className={`w-8 h-8 rounded-full flex items-center justify-center ${
                  notification.priority === 'critical' ? 'bg-red-500' :
                  notification.priority === 'high' ? 'bg-orange-500' :
                  notification.priority === 'medium' ? 'bg-yellow-500' : 'bg-blue-500'
                }`}>
                  <BellIcon className="w-4 h-4 text-white" />
                </div>
              </div>
              <div className="ml-3 flex-1">
                <p className="text-sm font-medium text-gray-900">
                  {notification.type.replace('_', ' ').toUpperCase()}
                </p>
                <p className="mt-1 text-sm text-gray-500">
                  {notification.message}
                </p>
              </div>
            </div>
          </div>
          <div className="flex border-l border-gray-200">
            <button
              onClick={() => toast.dismiss(t.id)}
              className="w-full border border-transparent rounded-none rounded-r-lg p-4 flex items-center justify-center text-sm font-medium text-indigo-600 hover:text-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
            >
              Close
            </button>
          </div>
        </div>
      ), {
        duration: 6000,
      });
    }
  };

  const updateUnreadCount = (notifs: Notification[]) => {
    const unread = notifs.filter(n => !n.read).length;
    setUnreadCount(unread);
  };

  const loadNotifications = async () => {
    try {
      const token = localStorage.getItem('access_token');
      const response = await fetch(`${process.env.REACT_APP_API_URL}/api/v1/notifications`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      
      if (response.ok) {
        const data = await response.json();
        setNotifications(data.notifications || []);
        updateUnreadCount(data.notifications || []);
      }
    } catch (error) {
      console.error('Failed to load notifications:', error);
    }
  };

  const loadPreferences = async () => {
    try {
      const token = localStorage.getItem('access_token');
      const response = await fetch(`${process.env.REACT_APP_API_URL}/api/v1/notifications/settings`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      
      if (response.ok) {
        const data = await response.json();
        setPreferences(data);
      }
    } catch (error) {
      console.error('Failed to load notification preferences:', error);
    }
  };

  const markAsRead = async (notificationId: string) => {
    try {
      const token = localStorage.getItem('access_token');
      await fetch(`${process.env.REACT_APP_API_URL}/api/v1/notifications/${notificationId}/read`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      
      setNotifications(prev => 
        prev.map(n => n.id === notificationId ? { ...n, read: true } : n)
      );
      updateUnreadCount(notifications.map(n => n.id === notificationId ? { ...n, read: true } : n));
    } catch (error) {
      console.error('Failed to mark notification as read:', error);
    }
  };

  const updatePreferences = async (newPreferences: Partial<NotificationPreferences>) => {
    try {
      const token = localStorage.getItem('access_token');
      const response = await fetch(`${process.env.REACT_APP_API_URL}/api/v1/notifications/settings`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(newPreferences),
      });
      
      if (response.ok) {
        setPreferences(prev => ({ ...prev, ...newPreferences }));
        toast.success('Notification preferences updated');
      }
    } catch (error) {
      console.error('Failed to update notification preferences:', error);
      toast.error('Failed to update preferences');
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'critical': return 'bg-red-500 text-white';
      case 'high': return 'bg-orange-500 text-white';
      case 'medium': return 'bg-yellow-500 text-white';
      case 'low': return 'bg-blue-500 text-white';
      default: return 'bg-gray-500 text-white';
    }
  };

  const getPriorityIcon = (priority: string) => {
    switch (priority) {
      case 'critical': return '🚨';
      case 'high': return '⚠️';
      case 'medium': return 'ℹ️';
      case 'low': return '📝';
      default: return '📢';
    }
  };

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffInMinutes = Math.floor((now.getTime() - date.getTime()) / (1000 * 60));
    
    if (diffInMinutes < 1) return 'Just now';
    if (diffInMinutes < 60) return `${diffInMinutes}m ago`;
    if (diffInMinutes < 1440) return `${Math.floor(diffInMinutes / 60)}h ago`;
    return date.toLocaleDateString();
  };

  return (
    <div className="relative">
      {/* Notification Bell */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="relative p-2 text-gray-400 hover:text-gray-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
      >
        <BellIcon className="h-6 w-6" />
        {unreadCount > 0 && (
          <span className="absolute -top-1 -right-1 h-5 w-5 bg-red-500 text-white text-xs rounded-full flex items-center justify-center">
            {unreadCount > 99 ? '99+' : unreadCount}
          </span>
        )}
        {!isConnected && (
          <div className="absolute -bottom-1 -right-1 h-3 w-3 bg-gray-400 rounded-full"></div>
        )}
      </button>

      {/* Notification Panel */}
      {isOpen && (
        <div className="absolute right-0 mt-2 w-80 bg-white rounded-lg shadow-lg ring-1 ring-black ring-opacity-5 z-50">
          <div className="p-4 border-b border-gray-200">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-medium text-gray-900">Notifications</h3>
              <div className="flex items-center space-x-2">
                <button
                  onClick={() => setIsPreferencesOpen(true)}
                  className="p-1 text-gray-400 hover:text-gray-500"
                >
                  <CogIcon className="h-5 w-5" />
                </button>
                <button
                  onClick={() => setIsOpen(false)}
                  className="p-1 text-gray-400 hover:text-gray-500"
                >
                  <XMarkIcon className="h-5 w-5" />
                </button>
              </div>
            </div>
            <div className="flex items-center mt-2">
              <div className={`h-2 w-2 rounded-full ${isConnected ? 'bg-green-500' : 'bg-red-500'} mr-2`}></div>
              <span className="text-sm text-gray-500">
                {isConnected ? 'Connected' : 'Disconnected'}
              </span>
            </div>
          </div>

          <div className="max-h-96 overflow-y-auto">
            {notifications.length === 0 ? (
              <div className="p-4 text-center text-gray-500">
                <BellIcon className="h-12 w-12 mx-auto text-gray-300 mb-2" />
                <p>No notifications</p>
              </div>
            ) : (
              <div className="divide-y divide-gray-200">
                {notifications.map((notification) => (
                  <div
                    key={notification.id}
                    className={`p-4 hover:bg-gray-50 cursor-pointer ${
                      !notification.read ? 'bg-blue-50' : ''
                    }`}
                    onClick={() => {
                      if (!notification.read) {
                        markAsRead(notification.id);
                      }
                      if (notification.action_url) {
                        window.location.href = notification.action_url;
                      }
                    }}
                  >
                    <div className="flex items-start space-x-3">
                      <div className="flex-shrink-0">
                        <span className="text-lg">{getPriorityIcon(notification.priority)}</span>
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between">
                          <p className="text-sm font-medium text-gray-900">
                            {notification.type.replace('_', ' ').toUpperCase()}
                          </p>
                          <div className="flex items-center space-x-2">
                            <span className={`px-2 py-1 text-xs rounded-full ${getPriorityColor(notification.priority)}`}>
                              {notification.priority}
                            </span>
                            {notification.read && (
                              <CheckIcon className="h-4 w-4 text-green-500" />
                            )}
                          </div>
                        </div>
                        <p className="text-sm text-gray-600 mt-1">
                          {notification.message}
                        </p>
                        <p className="text-xs text-gray-400 mt-2">
                          {formatTimestamp(notification.timestamp)}
                        </p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Preferences Modal */}
      {isPreferencesOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4 max-h-[80vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-medium text-gray-900">Notification Preferences</h3>
              <button
                onClick={() => setIsPreferencesOpen(false)}
                className="text-gray-400 hover:text-gray-500"
              >
                <XMarkIcon className="h-5 w-5" />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <h4 className="text-sm font-medium text-gray-900 mb-2">Notification Channels</h4>
                <div className="space-y-2">
                  {[
                    { key: 'in_app_notifications', label: 'In-app notifications' },
                    { key: 'email_notifications', label: 'Email notifications' },
                    { key: 'slack_notifications', label: 'Slack notifications' },
                    { key: 'sms_notifications', label: 'SMS notifications' }
                  ].map(({ key, label }) => (
                    <label key={key} className="flex items-center">
                      <input
                        type="checkbox"
                        checked={preferences[key as keyof NotificationPreferences] as boolean}
                        onChange={(e) => updatePreferences({ [key]: e.target.checked })}
                        className="rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
                      />
                      <span className="ml-2 text-sm text-gray-700">{label}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div>
                <h4 className="text-sm font-medium text-gray-900 mb-2">Notification Types</h4>
                <div className="space-y-2">
                  {[
                    { key: 'incident_enabled', label: 'Incident alerts' },
                    { key: 'security_alert_enabled', label: 'Security alerts' },
                    { key: 'training_reminder_enabled', label: 'Training reminders' },
                    { key: 'system_update_enabled', label: 'System updates' },
                    { key: 'compliance_alert_enabled', label: 'Compliance alerts' },
                    { key: 'phishing_alert_enabled', label: 'Phishing alerts' },
                    { key: 'cloud_security_enabled', label: 'Cloud security alerts' },
                    { key: 'user_activity_enabled', label: 'User activity notifications' }
                  ].map(({ key, label }) => (
                    <label key={key} className="flex items-center">
                      <input
                        type="checkbox"
                        checked={preferences[key as keyof NotificationPreferences] as boolean}
                        onChange={(e) => updatePreferences({ [key]: e.target.checked })}
                        className="rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
                      />
                      <span className="ml-2 text-sm text-gray-700">{label}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div>
                <h4 className="text-sm font-medium text-gray-900 mb-2">Quiet Hours</h4>
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="block text-xs text-gray-500">Start Time</label>
                    <input
                      type="time"
                      value={preferences.quiet_hours_start}
                      onChange={(e) => updatePreferences({ quiet_hours_start: e.target.value })}
                      className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-gray-500">End Time</label>
                    <input
                      type="time"
                      value={preferences.quiet_hours_end}
                      onChange={(e) => updatePreferences({ quiet_hours_end: e.target.value })}
                      className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                    />
                  </div>
                </div>
              </div>
            </div>

            <div className="mt-6 flex justify-end">
              <button
                onClick={() => setIsPreferencesOpen(false)}
                className="bg-indigo-600 text-white px-4 py-2 rounded-md hover:bg-indigo-700"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default NotificationCenter; 