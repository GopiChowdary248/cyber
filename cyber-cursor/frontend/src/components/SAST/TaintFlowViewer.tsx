import React, { useEffect, useMemo, useState } from 'react';

type TaintStep = { file_path: string; line_number: number; function_name?: string; code_snippet?: string; order_index: number };
type TaintFlow = { id: number; scan_id?: number; issue_id?: number; source?: string; sink?: string; steps: TaintStep[] };

interface Props { projectId: number | string; issueId?: number | string }

const API_URL = process.env.REACT_APP_API_URL || '';

const TaintFlowViewer: React.FC<Props> = ({ projectId, issueId }) => {
  const [flows, setFlows] = useState<TaintFlow[]>([]);
  const token = useMemo(() => localStorage.getItem('access_token') || '', []);

  useEffect(() => {
    const qs = new URLSearchParams();
    if (issueId) qs.set('issue_id', String(issueId));
    fetch(`${API_URL}/api/v1/sast/projects/${projectId}/taint-flows?${qs.toString()}`, {
      headers: { 'Authorization': `Bearer ${token}` }
    }).then(async r => {
      if (r.ok) {
        const data = await r.json();
        setFlows(data.flows || []);
      }
    });
  }, [projectId, issueId, token]);

  if (!flows.length) return null;

  return (
    <div className="mt-6">
      <h4 className="text-sm font-semibold mb-2">Taint Flows</h4>
      {flows.map((f) => (
        <div key={f.id} className="border rounded mb-3">
          <div className="px-3 py-2 bg-gray-50 text-xs text-gray-600">Source: {f.source || '-'} → Sink: {f.sink || '-'}</div>
          <ol className="p-3 space-y-2">
            {f.steps.map(s => (
              <li key={`${s.file_path}:${s.order_index}`} className="text-xs">
                <div className="font-mono text-gray-800">{s.file_path}:{s.line_number}{s.function_name ? ` (${s.function_name})` : ''}</div>
                {s.code_snippet ? (
                  <pre className="bg-gray-100 p-2 rounded text-[11px] whitespace-pre-wrap overflow-auto">{s.code_snippet}</pre>
                ) : null}
              </li>
            ))}
          </ol>
        </div>
      ))}
    </div>
  );
};

export default TaintFlowViewer;


