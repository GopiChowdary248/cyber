import React, { useEffect, useState } from 'react';

interface HotspotSummary {
  id: string | number;
  projectId: number;
  projectName: string;
  status: 'TO_REVIEW' | 'IN_REVIEW' | 'REVIEWED' | 'SAFE';
  severity: 'LOW' | 'MEDIUM' | 'HIGH';
  ruleKey?: string;
  component?: string;
  author?: string;
  createdAt?: string;
}

const SASTHotspots: React.FC = () => {
  const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [hotspots, setHotspots] = useState<HotspotSummary[]>([]);

  const [search, setSearch] = useState('');
  const [status, setStatus] = useState<'all' | 'TO_REVIEW' | 'IN_REVIEW' | 'REVIEWED' | 'SAFE'>('all');
  const [severity, setSeverity] = useState<'all' | 'LOW' | 'MEDIUM' | 'HIGH'>('all');
  const [project, setProject] = useState<string>('all');

  const fetchHotspots = async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams();
      if (search) params.append('search', search);
      if (status !== 'all') params.append('status', status);
      if (severity !== 'all') params.append('severity', severity);
      if (project !== 'all') params.append('project', project);
      const resp = await fetch(`${API_URL}/api/v1/sast/hotspots?${params.toString()}`, {
        headers: { 'Authorization': `Bearer ${localStorage.getItem('access_token') || ''}` }
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      setHotspots(data.hotspots || []);
      setError(null);
    } catch (e) {
      setError('Failed to fetch hotspots');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchHotspots(); }, [search, status, severity, project]);

  const projects = ['all', ...Array.from(new Set(hotspots.map(h => h.projectName)))];

  if (loading) {
    return <div className="flex items-center justify-center h-full"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>;
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-gray-900">Security Hotspots</h3>
      </div>
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-md p-3 text-sm text-red-700">{error}</div>
      )}
      <div className="bg-white p-4 rounded-lg border border-gray-200">
        <div className="flex gap-2 flex-wrap">
          <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search..." className="px-3 py-2 border rounded" />
          <select value={status} onChange={(e) => setStatus(e.target.value as any)} className="px-3 py-2 border rounded">
            <option value="all">All Status</option>
            <option value="TO_REVIEW">To Review</option>
            <option value="IN_REVIEW">In Review</option>
            <option value="REVIEWED">Reviewed</option>
            <option value="SAFE">Safe</option>
          </select>
          <select value={severity} onChange={(e) => setSeverity(e.target.value as any)} className="px-3 py-2 border rounded">
            <option value="all">All Severity</option>
            <option value="LOW">Low</option>
            <option value="MEDIUM">Medium</option>
            <option value="HIGH">High</option>
          </select>
          <select value={project} onChange={(e) => setProject(e.target.value)} className="px-3 py-2 border rounded">
            {projects.map(p => <option key={p} value={p}>{p === 'all' ? 'All Projects' : p}</option>)}
          </select>
        </div>
      </div>
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Project</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Rule</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Component</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Created</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {hotspots.map(h => (
              <tr key={h.id} className="hover:bg-gray-50">
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{h.projectName}</td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{h.severity}</td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{h.status}</td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{h.ruleKey || '-'}</td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{h.component || '-'}</td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{h.createdAt ? new Date(h.createdAt).toLocaleString() : '-'}</td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                  <div className="flex items-center gap-2">
                    <button
                      onClick={async () => {
                        try {
                          const resp = await fetch(`${API_URL}/api/v1/sast/hotspots/${h.id}/status`, {
                            method: 'POST',
                            headers: { 'Authorization': `Bearer ${localStorage.getItem('access_token') || ''}`, 'Content-Type': 'application/json' },
                            body: JSON.stringify({ status: 'TO_REVIEW' })
                          });
                          if (resp.ok) fetchHotspots();
                        } catch {}
                      }}
                      className="px-2 py-1 text-xs border rounded"
                    >To Review</button>
                    <button
                      onClick={async () => {
                        try {
                          const resp = await fetch(`${API_URL}/api/v1/sast/hotspots/${h.id}/status`, {
                            method: 'POST',
                            headers: { 'Authorization': `Bearer ${localStorage.getItem('access_token') || ''}`, 'Content-Type': 'application/json' },
                            body: JSON.stringify({ status: 'IN_REVIEW' })
                          });
                          if (resp.ok) fetchHotspots();
                        } catch {}
                      }}
                      className="px-2 py-1 text-xs border rounded"
                    >In Review</button>
                    <button
                      onClick={async () => {
                        try {
                          const resp = await fetch(`${API_URL}/api/v1/sast/hotspots/${h.id}/status`, {
                            method: 'POST',
                            headers: { 'Authorization': `Bearer ${localStorage.getItem('access_token') || ''}`, 'Content-Type': 'application/json' },
                            body: JSON.stringify({ status: 'REVIEWED' })
                          });
                          if (resp.ok) fetchHotspots();
                        } catch {}
                      }}
                      className="px-2 py-1 text-xs border rounded"
                    >Reviewed</button>
                    <button
                      onClick={async () => {
                        try {
                          const resp = await fetch(`${API_URL}/api/v1/sast/hotspots/${h.id}/status`, {
                            method: 'POST',
                            headers: { 'Authorization': `Bearer ${localStorage.getItem('access_token') || ''}`, 'Content-Type': 'application/json' },
                            body: JSON.stringify({ status: 'SAFE' })
                          });
                          if (resp.ok) fetchHotspots();
                        } catch {}
                      }}
                      className="px-2 py-1 text-xs border rounded"
                    >Mark Safe</button>
                  </div>
                </td>
              </tr>
            ))}
            {hotspots.length === 0 && (
              <tr><td className="px-6 py-6 text-sm text-gray-500" colSpan={6}>No hotspots found</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default SASTHotspots;


