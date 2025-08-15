import React, { useEffect, useState } from 'react';

interface QualityGateCondition {
  metric: string;
  operator: string;
  threshold: string;
}

interface QualityGate {
  id: number | string;
  name: string;
  isDefault?: boolean;
  conditions: QualityGateCondition[];
}

const SASTQualityGates: React.FC = () => {
  const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [gates, setGates] = useState<QualityGate[]>([]);
  const [creating, setCreating] = useState(false);
  const [newGateName, setNewGateName] = useState('');

  const fetchGates = async () => {
    try {
      setLoading(true);
      const resp = await fetch(`${API_URL}/api/v1/sast/quality-gates`, {
        headers: { 'Authorization': `Bearer ${localStorage.getItem('access_token') || ''}` }
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      setGates(data.gates || []);
      setError(null);
    } catch (e) {
      setError('Failed to fetch quality gates');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchGates(); }, []);

  const createGate = async () => {
    try {
      setCreating(true);
      const resp = await fetch(`${API_URL}/api/v1/sast/quality-gates`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${localStorage.getItem('access_token') || ''}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newGateName })
      });
      if (!resp.ok) throw new Error('Failed to create gate');
      setNewGateName('');
      await fetchGates();
    } catch (e) {
      setError('Failed to create quality gate');
    } finally {
      setCreating(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-gray-900">Quality Gates</h3>
        <div className="flex items-center gap-2">
          <input value={newGateName} onChange={(e) => setNewGateName(e.target.value)} placeholder="Gate name" className="px-3 py-2 border rounded" />
          <button disabled={creating || !newGateName.trim()} onClick={createGate} className="px-3 py-2 border rounded bg-blue-600 text-white disabled:opacity-50">Create</button>
        </div>
      </div>
      {error && <div className="bg-red-50 border border-red-200 rounded-md p-3 text-sm text-red-700">{error}</div>}
      {loading ? (
        <div className="flex items-center justify-center h-32"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {gates.map(g => (
            <div key={g.id} className="bg-white p-4 rounded-lg border border-gray-200">
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-gray-900 font-medium">{g.name}</div>
                  {g.isDefault && <div className="text-xs text-green-700 bg-green-100 inline-block px-2 py-0.5 rounded mt-1">Default</div>}
                </div>
                <button className="px-2 py-1 text-xs border rounded">Assign to Projects</button>
              </div>
              <div className="mt-3">
                <div className="text-xs text-gray-500">Conditions</div>
                <ul className="mt-1 space-y-1">
                  {g.conditions?.length ? g.conditions.map((c, idx) => (
                    <li key={idx} className="text-sm text-gray-800">
                      {c.metric} {c.operator} {c.threshold}
                    </li>
                  )) : <li className="text-sm text-gray-500">No conditions</li>}
                </ul>
              </div>
            </div>
          ))}
          {gates.length === 0 && (
            <div className="text-sm text-gray-500">No quality gates found</div>
          )}
        </div>
      )}
    </div>
  );
};

export default SASTQualityGates;


