import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  XCircle,
  Plus,
  Eye,
  Download,
  RefreshCw,
  Activity
} from 'lucide-react';

interface RASPAgent {
  id: string;
  name: string;
  application: string;
  environment: string;
  status: string;
  last_heartbeat: string;
  version: string;
  rules_count: number;
  attacks_blocked: number;
  vulnerabilities_detected: number;
}

interface RASPAttack {
  id: string;
  agent_id: string;
  attack_type: string;
  severity: string;
  timestamp: string;
  status: string;
  details: string;
  blocked: boolean;
}

interface RASPSummary {
  total_agents: number;
  active_agents: number;
  total_attacks: number;
  blocked_attacks: number;
  vulnerabilities_detected: number;
  security_score: number;
}

const API_BASE_URL = '/api/rasp';

const RASPDashboard: React.FC = () => {
  const [summary, setSummary] = useState<RASPSummary | null>(null);
  const [agents, setAgents] = useState<RASPAgent[]>([]);
  const [attacks, setAttacks] = useState<RASPAttack[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchRASPData = async () => {
    try {
      const token = localStorage.getItem('token') || '';
      const headers = {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      };

      const [summaryRes, agentsRes, attacksRes] = await Promise.all([
        fetch(`${API_BASE_URL}/dashboard/overview`, { headers }),
        fetch(`${API_BASE_URL}/agents`, { headers }),
        fetch(`${API_BASE_URL}/attacks`, { headers }),
      ]);

      if (summaryRes.ok) {
        const summaryData = await summaryRes.json();
        setSummary(summaryData);
      }

      if (agentsRes.ok) {
        const agentsData = await agentsRes.json();
        setAgents(agentsData.agents || []);
      }

      if (attacksRes.ok) {
        const attacksData = await attacksRes.json();
        setAttacks(attacksData.attacks || []);
      }
    } catch (error) {
      console.error('Error fetching RASP data:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRASPData();
  }, []);

  const onRefresh = () => {
    setRefreshing(true);
    fetchRASPData().finally(() => setRefreshing(false));
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'text-green-600 bg-green-100';
      case 'inactive':
        return 'text-gray-600 bg-gray-100';
      case 'error':
        return 'text-red-600 bg-red-100';
      default:
        return 'text-yellow-600 bg-yellow-100';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active':
        return <CheckCircle className="w-4 h-4" />;
      case 'inactive':
        return <Clock className="w-4 h-4" />;
      case 'error':
        return <XCircle className="w-4 h-4" />;
      default:
        return <Clock className="w-4 h-4" />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'high':
        return 'text-red-600 bg-red-100';
      case 'medium':
        return 'text-yellow-600 bg-yellow-100';
      case 'low':
        return 'text-blue-600 bg-blue-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const getSecurityScoreColor = (score: number) => {
    if (score >= 80) return 'text-green-600';
    if (score >= 60) return 'text-yellow-600';
    return 'text-red-600';
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-gray-900 mb-2">
                RASP Dashboard
              </h1>
              <p className="text-gray-600">
                Runtime Application Self-Protection monitoring and management
              </p>
            </div>
            <div className="flex space-x-3">
              <button
                onClick={onRefresh}
                disabled={refreshing}
                className="inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
              >
                <RefreshCw className={`w-4 h-4 mr-2 ${refreshing ? 'animate-spin' : ''}`} />
                Refresh
              </button>
              <button
                onClick={() => window.location.href = '/rasp/agents/new'}
                className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                <Plus className="w-4 h-4 mr-2" />
                Add Agent
              </button>
            </div>
          </div>
        </div>

        {/* Summary Stats */}
        {summary && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <div className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center">
                <div className="p-2 bg-blue-100 rounded-lg">
                  <Shield className="w-6 h-6 text-blue-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Total Agents</p>
                  <p className="text-2xl font-semibold text-gray-900">{summary.total_agents}</p>
                </div>
              </div>
            </div>

            <div className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center">
                <div className="p-2 bg-green-100 rounded-lg">
                  <CheckCircle className="w-6 h-6 text-green-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Active Agents</p>
                  <p className="text-2xl font-semibold text-gray-900">{summary.active_agents}</p>
                </div>
              </div>
            </div>

            <div className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center">
                <div className="p-2 bg-red-100 rounded-lg">
                  <AlertTriangle className="w-6 h-6 text-red-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Total Attacks</p>
                  <p className="text-2xl font-semibold text-gray-900">{summary.total_attacks}</p>
                </div>
              </div>
            </div>

            <div className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center">
                <div className="p-2 bg-purple-100 rounded-lg">
                  <Activity className="w-6 h-6 text-purple-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Security Score</p>
                  <p className={`text-2xl font-semibold ${getSecurityScoreColor(summary.security_score)}`}>
                    {summary.security_score}%
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Attack Statistics */}
        {summary && (
          <div className="bg-white rounded-lg shadow p-6 mb-8">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">Attack Statistics</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="text-center">
                <div className="text-3xl font-bold text-green-600 mb-2">{summary.blocked_attacks}</div>
                <div className="text-sm text-gray-600">Attacks Blocked</div>
              </div>
              <div className="text-center">
                <div className="text-3xl font-bold text-red-600 mb-2">{summary.total_attacks - summary.blocked_attacks}</div>
                <div className="text-sm text-gray-600">Attacks Detected</div>
              </div>
              <div className="text-center">
                <div className="text-3xl font-bold text-blue-600 mb-2">{summary.vulnerabilities_detected}</div>
                <div className="text-sm text-gray-600">Vulnerabilities</div>
              </div>
            </div>
          </div>
        )}

        {/* RASP Agents */}
        <div className="bg-white rounded-lg shadow mb-8">
          <div className="px-6 py-4 border-b border-gray-200">
            <h2 className="text-lg font-semibold text-gray-900">RASP Agents</h2>
          </div>
          <div className="p-6">
            {agents.length === 0 ? (
              <div className="text-center py-8">
                <Shield className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                <p className="text-gray-500">No RASP agents found. Add your first agent to get started.</p>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {agents.map((agent) => (
                  <div key={agent.id} className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow">
                    <div className="flex items-center justify-between mb-3">
                      <h3 className="font-semibold text-gray-900 truncate">{agent.name}</h3>
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(agent.status)}`}>
                        {getStatusIcon(agent.status)}
                        <span className="ml-1 capitalize">{agent.status}</span>
                      </span>
                    </div>
                    <p className="text-sm text-gray-600 mb-3">{agent.application}</p>
                    <div className="text-xs text-gray-500 mb-3">{agent.environment}</div>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-gray-600">Version:</span>
                        <span className="font-medium">{agent.version}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-600">Rules:</span>
                        <span className="font-medium">{agent.rules_count}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-600">Attacks Blocked:</span>
                        <span className="font-medium text-green-600">{agent.attacks_blocked}</span>
                      </div>
                    </div>
                    <div className="flex space-x-2 mt-4">
                      <button
                        onClick={() => window.location.href = `/rasp/agents/${agent.id}`}
                        className="text-blue-600 hover:text-blue-900 text-sm"
                      >
                        View Details
                      </button>
                      <button
                        onClick={() => window.location.href = `/rasp/agents/${agent.id}/config`}
                        className="text-gray-600 hover:text-gray-900 text-sm"
                      >
                        Configure
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Recent Attacks */}
        <div className="bg-white rounded-lg shadow mb-8">
          <div className="px-6 py-4 border-b border-gray-200">
            <h2 className="text-lg font-semibold text-gray-900">Recent Attacks</h2>
          </div>
          <div className="p-6">
            {attacks.length === 0 ? (
              <div className="text-center py-8">
                <AlertTriangle className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                <p className="text-gray-500">No attacks detected. Your applications are secure!</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Time</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Agent</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Attack Type</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {attacks.slice(0, 10).map((attack) => (
                      <tr key={attack.id} className="hover:bg-gray-50">
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{attack.timestamp}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{attack.agent_id}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{attack.attack_type}</td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(attack.severity)}`}>
                            {attack.severity}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${attack.blocked ? 'text-green-600 bg-green-100' : 'text-red-600 bg-red-100'}`}>
                            {attack.blocked ? 'Blocked' : 'Detected'}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                          <button
                            onClick={() => window.location.href = `/rasp/attacks/${attack.id}`}
                            className="text-blue-600 hover:text-blue-900"
                          >
                            <Eye className="w-4 h-4" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default RASPDashboard; 