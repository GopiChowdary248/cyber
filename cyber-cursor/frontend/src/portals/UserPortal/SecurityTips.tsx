import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';

interface SecurityTip {
  id: number;
  title: string;
  content: string;
  category: string;
  priority: string;
  tags: string[];
  created_at: string;
  is_favorite: boolean;
  is_read: boolean;
}

interface TipCategory {
  name: string;
  icon: string;
  description: string;
  tip_count: number;
}

const SecurityTips: React.FC = () => {
  const { user } = useAuth();
  const [tips, setTips] = useState<SecurityTip[]>([]);
  const [categories, setCategories] = useState<TipCategory[]>([]);
  const [selectedCategory, setSelectedCategory] = useState('');
  const [selectedTip, setSelectedTip] = useState<SecurityTip | null>(null);
  const [showTipModal, setShowTipModal] = useState(false);
  const [loading, setLoading] = useState(true);
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid');
  const [searchTerm, setSearchTerm] = useState('');

  const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

  useEffect(() => {
    fetchSecurityTips();
  }, []);

  const fetchSecurityTips = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('access_token');
      
      const response = await fetch(`${API_URL}/api/v1/user/security-tips`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error('Failed to fetch security tips');
      }

      const data = await response.json();
      setTips(data || getMockTips());
      setCategories(getMockCategories());
    } catch (err) {
      console.error('Error fetching security tips:', err);
      setTips(getMockTips());
      setCategories(getMockCategories());
    } finally {
      setLoading(false);
    }
  };

  const getMockTips = (): SecurityTip[] => [
    {
      id: 1,
      title: "Strong Password Creation",
      content: "Create passwords that are at least 12 characters long and include a mix of uppercase letters, lowercase letters, numbers, and special characters. Avoid using personal information like birthdays or names. Consider using a passphrase instead of a single word.",
      category: "password_security",
      priority: "high",
      tags: ["passwords", "authentication", "security"],
      created_at: "2024-01-15T00:00:00Z",
      is_favorite: false,
      is_read: false
    },
    {
      id: 2,
      title: "Phishing Email Detection",
      content: "Be cautious of emails that create urgency, ask for personal information, or have suspicious links. Check the sender's email address carefully, look for spelling errors, and hover over links before clicking. When in doubt, contact the sender directly through official channels.",
      category: "email_security",
      priority: "high",
      tags: ["phishing", "email", "social_engineering"],
      created_at: "2024-01-14T00:00:00Z",
      is_favorite: true,
      is_read: true
    },
    {
      id: 3,
      title: "Two-Factor Authentication",
      content: "Enable 2FA on all your accounts, especially for banking, email, and social media. Use authenticator apps like Google Authenticator or Microsoft Authenticator instead of SMS when possible. Keep backup codes in a secure location.",
      category: "account_security",
      priority: "high",
      tags: ["2fa", "authentication", "security"],
      created_at: "2024-01-13T00:00:00Z",
      is_favorite: false,
      is_read: false
    },
    {
      id: 4,
      title: "Safe Browsing Habits",
      content: "Only visit trusted websites and avoid clicking on suspicious links. Keep your browser updated and use security extensions. Be cautious when downloading files and always scan them with antivirus software before opening.",
      category: "browsing_security",
      priority: "medium",
      tags: ["browsing", "web_security", "downloads"],
      created_at: "2024-01-12T00:00:00Z",
      is_favorite: false,
      is_read: false
    },
    {
      id: 5,
      title: "Social Media Privacy",
      content: "Review your privacy settings regularly and limit the information you share publicly. Be cautious about accepting friend requests from unknown people. Think twice before posting personal information or location data.",
      category: "social_media",
      priority: "medium",
      tags: ["social_media", "privacy", "personal_info"],
      created_at: "2024-01-11T00:00:00Z",
      is_favorite: false,
      is_read: false
    },
    {
      id: 6,
      title: "Public Wi-Fi Safety",
      content: "Avoid accessing sensitive information on public Wi-Fi networks. Use a VPN when connecting to public networks. Consider using your mobile hotspot instead of public Wi-Fi for important transactions.",
      category: "network_security",
      priority: "medium",
      tags: ["wifi", "vpn", "public_networks"],
      created_at: "2024-01-10T00:00:00Z",
      is_favorite: false,
      is_read: false
    }
  ];

  const getMockCategories = (): TipCategory[] => [
    {
      name: "password_security",
      icon: "🔐",
      description: "Password creation and management best practices",
      tip_count: 1
    },
    {
      name: "email_security",
      icon: "📧",
      description: "Email safety and phishing prevention",
      tip_count: 1
    },
    {
      name: "account_security",
      icon: "👤",
      description: "Account protection and authentication",
      tip_count: 1
    },
    {
      name: "browsing_security",
      icon: "🌐",
      description: "Safe web browsing practices",
      tip_count: 1
    },
    {
      name: "social_media",
      icon: "📱",
      description: "Social media privacy and security",
      tip_count: 1
    },
    {
      name: "network_security",
      icon: "📡",
      description: "Network and Wi-Fi security",
      tip_count: 1
    }
  ];

  const getPriorityColor = (priority: string) => {
    switch (priority.toLowerCase()) {
      case 'high': return 'text-red-400 bg-red-900/20';
      case 'medium': return 'text-yellow-400 bg-yellow-900/20';
      case 'low': return 'text-green-400 bg-green-900/20';
      default: return 'text-gray-400 bg-gray-900/20';
    }
  };

  const getCategoryIcon = (category: string) => {
    const cat = categories.find(c => c.name === category);
    return cat?.icon || '💡';
  };

  const handleToggleFavorite = async (tipId: number) => {
    try {
      const token = localStorage.getItem('access_token');
      await fetch(`${API_URL}/api/v1/user/security-tips/${tipId}/favorite`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });
      
      // Update local state
      setTips(tips.map(tip => 
        tip.id === tipId ? { ...tip, is_favorite: !tip.is_favorite } : tip
      ));
    } catch (error) {
      console.error('Error toggling favorite:', error);
    }
  };

  const handleMarkAsRead = async (tipId: number) => {
    try {
      const token = localStorage.getItem('access_token');
      await fetch(`${API_URL}/api/v1/user/security-tips/${tipId}/read`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });
      
      // Update local state
      setTips(tips.map(tip => 
        tip.id === tipId ? { ...tip, is_read: true } : tip
      ));
    } catch (error) {
      console.error('Error marking as read:', error);
    }
  };

  const filteredTips = tips.filter(tip => {
    if (selectedCategory && tip.category !== selectedCategory) return false;
    if (searchTerm && !tip.title.toLowerCase().includes(searchTerm.toLowerCase()) && 
        !tip.content.toLowerCase().includes(searchTerm.toLowerCase())) return false;
    return true;
  });

  const unreadCount = tips.filter(tip => !tip.is_read).length;
  const favoriteCount = tips.filter(tip => tip.is_favorite).length;

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyber-accent"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gradient-to-r from-green-900/20 to-blue-900/20 border border-cyber-accent/30 rounded-lg p-6">
        <h1 className="text-3xl font-bold text-white mb-2">💡 Security Tips</h1>
        <p className="text-gray-400">
          Daily security best practices to keep you safe online.
        </p>
      </div>

      {/* Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-4">
          <div className="text-2xl font-bold text-white">{tips.length}</div>
          <div className="text-gray-400">Total Tips</div>
        </div>
        <div className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-4">
          <div className="text-2xl font-bold text-orange-400">{unreadCount}</div>
          <div className="text-gray-400">Unread</div>
        </div>
        <div className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-4">
          <div className="text-2xl font-bold text-yellow-400">{favoriteCount}</div>
          <div className="text-gray-400">Favorites</div>
        </div>
        <div className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-4">
          <div className="text-2xl font-bold text-green-400">{categories.length}</div>
          <div className="text-gray-400">Categories</div>
        </div>
      </div>

      {/* Controls */}
      <div className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between space-y-4 md:space-y-0">
          <div className="flex items-center space-x-4">
            <input
              type="text"
              placeholder="Search tips..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-cyber-dark border border-cyber-accent/30 rounded-lg px-3 py-2 text-white w-64"
            />
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="bg-cyber-dark border border-cyber-accent/30 rounded-lg px-3 py-2 text-white"
            >
              <option value="">All Categories</option>
              {categories.map(category => (
                <option key={category.name} value={category.name}>
                  {category.icon} {category.name.replace('_', ' ').toUpperCase()}
                </option>
              ))}
            </select>
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setViewMode('grid')}
              className={`p-2 rounded-lg ${viewMode === 'grid' ? 'bg-cyber-accent text-white' : 'bg-cyber-dark text-gray-400'}`}
            >
              ⊞
            </button>
            <button
              onClick={() => setViewMode('list')}
              className={`p-2 rounded-lg ${viewMode === 'list' ? 'bg-cyber-accent text-white' : 'bg-cyber-dark text-gray-400'}`}
            >
              ☰
            </button>
          </div>
        </div>
      </div>

      {/* Categories */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {categories.map(category => (
          <button
            key={category.name}
            onClick={() => setSelectedCategory(selectedCategory === category.name ? '' : category.name)}
            className={`p-4 rounded-lg border transition-colors ${
              selectedCategory === category.name
                ? 'border-cyber-accent bg-cyber-accent/20'
                : 'border-cyber-accent/20 bg-cyber-darker hover:border-cyber-accent/50'
            }`}
          >
            <div className="text-2xl mb-2">{category.icon}</div>
            <div className="text-white font-medium text-sm mb-1">
              {category.name.replace('_', ' ').toUpperCase()}
            </div>
            <div className="text-gray-400 text-xs">{category.tip_count} tips</div>
          </button>
        ))}
      </div>

      {/* Tips Display */}
      {viewMode === 'grid' ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredTips.map((tip) => (
            <div key={tip.id} className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-6 hover:border-cyber-accent/50 transition-colors">
              <div className="flex items-start justify-between mb-4">
                <div className="text-2xl">{getCategoryIcon(tip.category)}</div>
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => handleToggleFavorite(tip.id)}
                    className={`text-lg ${tip.is_favorite ? 'text-yellow-400' : 'text-gray-400 hover:text-yellow-400'}`}
                  >
                    {tip.is_favorite ? '★' : '☆'}
                  </button>
                  {!tip.is_read && (
                    <div className="w-2 h-2 bg-blue-400 rounded-full"></div>
                  )}
                </div>
              </div>
              
              <h3 className="text-lg font-semibold text-white mb-2">{tip.title}</h3>
              <p className="text-gray-400 text-sm mb-4 line-clamp-3">
                {tip.content.substring(0, 120)}...
              </p>
              
              <div className="flex items-center justify-between mb-4">
                <span className={`px-2 py-1 rounded-full text-xs font-medium ${getPriorityColor(tip.priority)}`}>
                  {tip.priority}
                </span>
                <span className="text-gray-500 text-xs">
                  {new Date(tip.created_at).toLocaleDateString()}
                </span>
              </div>
              
              <div className="flex flex-wrap gap-1 mb-4">
                {tip.tags.slice(0, 2).map((tag, index) => (
                  <span key={index} className="px-2 py-1 bg-cyber-dark text-cyber-accent text-xs rounded">
                    #{tag}
                  </span>
                ))}
                {tip.tags.length > 2 && (
                  <span className="px-2 py-1 bg-cyber-dark text-gray-400 text-xs rounded">
                    +{tip.tags.length - 2}
                  </span>
                )}
              </div>
              
              <button
                onClick={() => { setSelectedTip(tip); setShowTipModal(true); handleMarkAsRead(tip.id); }}
                className="w-full bg-cyber-accent hover:bg-cyber-accent/80 text-white py-2 rounded-lg transition-colors"
              >
                Read More
              </button>
            </div>
          ))}
        </div>
      ) : (
        <div className="space-y-4">
          {filteredTips.map((tip) => (
            <div key={tip.id} className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-6 hover:border-cyber-accent/50 transition-colors">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3 mb-2">
                    <span className="text-2xl">{getCategoryIcon(tip.category)}</span>
                    <h3 className="text-lg font-semibold text-white">{tip.title}</h3>
                    <span className={`px-2 py-1 rounded-full text-xs font-medium ${getPriorityColor(tip.priority)}`}>
                      {tip.priority}
                    </span>
                    {!tip.is_read && (
                      <div className="w-2 h-2 bg-blue-400 rounded-full"></div>
                    )}
                  </div>
                  <p className="text-gray-400 mb-3">{tip.content}</p>
                  <div className="flex items-center space-x-4 text-sm text-gray-500">
                    <span>{new Date(tip.created_at).toLocaleDateString()}</span>
                    <div className="flex space-x-1">
                      {tip.tags.map((tag, index) => (
                        <span key={index} className="text-cyber-accent">#{tag}</span>
                      ))}
                    </div>
                  </div>
                </div>
                <div className="flex items-center space-x-2 ml-4">
                  <button
                    onClick={() => handleToggleFavorite(tip.id)}
                    className={`text-lg ${tip.is_favorite ? 'text-yellow-400' : 'text-gray-400 hover:text-yellow-400'}`}
                  >
                    {tip.is_favorite ? '★' : '☆'}
                  </button>
                  <button
                    onClick={() => { setSelectedTip(tip); setShowTipModal(true); handleMarkAsRead(tip.id); }}
                    className="bg-cyber-accent hover:bg-cyber-accent/80 text-white px-4 py-2 rounded-lg transition-colors"
                  >
                    View
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Tip Detail Modal */}
      {showTipModal && selectedTip && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-cyber-darker border border-cyber-accent/30 rounded-lg p-6 max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center space-x-3">
                <span className="text-3xl">{getCategoryIcon(selectedTip.category)}</span>
                <h2 className="text-2xl font-bold text-white">{selectedTip.title}</h2>
              </div>
              <button
                onClick={() => setShowTipModal(false)}
                className="text-gray-400 hover:text-white text-2xl"
              >
                ×
              </button>
            </div>
            
            <div className="space-y-4">
              <div className="flex items-center space-x-4">
                <span className={`px-3 py-1 rounded-full text-sm font-medium ${getPriorityColor(selectedTip.priority)}`}>
                  {selectedTip.priority} Priority
                </span>
                <span className="text-gray-400 text-sm">
                  {new Date(selectedTip.created_at).toLocaleDateString()}
                </span>
              </div>
              
              <div className="prose prose-invert max-w-none">
                <p className="text-gray-300 leading-relaxed">{selectedTip.content}</p>
              </div>
              
              <div className="flex flex-wrap gap-2">
                {selectedTip.tags.map((tag, index) => (
                  <span key={index} className="px-3 py-1 bg-cyber-dark text-cyber-accent text-sm rounded-full">
                    #{tag}
                  </span>
                ))}
              </div>
              
              <div className="flex justify-between items-center pt-4 border-t border-cyber-accent/20">
                <button
                  onClick={() => handleToggleFavorite(selectedTip.id)}
                  className={`flex items-center space-x-2 px-4 py-2 rounded-lg transition-colors ${
                    selectedTip.is_favorite 
                      ? 'bg-yellow-900/20 text-yellow-400' 
                      : 'bg-cyber-dark text-gray-400 hover:text-yellow-400'
                  }`}
                >
                  <span>{selectedTip.is_favorite ? '★' : '☆'}</span>
                  <span>{selectedTip.is_favorite ? 'Favorited' : 'Add to Favorites'}</span>
                </button>
                
                <button
                  onClick={() => setShowTipModal(false)}
                  className="bg-cyber-accent hover:bg-cyber-accent/80 text-white px-6 py-2 rounded-lg transition-colors"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SecurityTips; 