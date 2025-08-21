import React, { useEffect, useState } from 'react';
import { dastProjectToolsService } from '../../../services/dastProjectToolsService';
import { Play, X, RefreshCw } from 'lucide-react';

interface InterceptItem {
  id: string;
  request: any;
  status: string;
  created_at?: string;
}

interface DASTInterceptQueueProps {
  projectId: string;
}

const DASTInterceptQueue: React.FC<DASTInterceptQueueProps> = ({ projectId }) => {
  const [items, setItems] = useState<InterceptItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await dastProjectToolsService.listIntercepts(projectId);
      setItems(res?.intercepts || []);
    } catch (e: any) {
      setError(e?.message || 'Failed to load intercepts');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    const timer = setInterval(load, 4000);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId]);

  const forward = async (it: InterceptItem) => {
    await dastProjectToolsService.proxyForward(projectId, { interceptId: it.id, request: it.request });
    await load();
  };

  const drop = async (it: InterceptItem) => {
    await dastProjectToolsService.proxyDrop(projectId, { interceptId: it.id });
    await load();
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-sm font-medium">Intercept Queue</div>
        <button onClick={load} disabled={loading} className="inline-flex items-center px-2 py-1 text-xs border rounded disabled:opacity-50">
          <RefreshCw className={`w-3 h-3 mr-1 ${loading ? 'animate-spin' : ''}`} /> Refresh
        </button>
      </div>

      {error && <div className="text-red-600 text-sm">{error}</div>}

      <div className="divide-y border rounded">
        {items.map((it) => (
          <div key={it.id} className="p-3 text-xs flex items-start justify-between">
            <div className="space-y-1">
              <div className="font-mono">
                {(it.request?.method || 'GET')} {(it.request?.url || '')}
              </div>
              {it.request?.headers && (
                <pre className="bg-gray-50 p-2 rounded overflow-auto max-h-24">{JSON.stringify(it.request.headers, null, 2)}</pre>
              )}
              {typeof it.request?.body === 'string' && it.request.body.length > 0 && (
                <pre className="bg-gray-50 p-2 rounded overflow-auto max-h-24">{it.request.body}</pre>
              )}
            </div>
            <div className="flex items-center gap-2">
              <button onClick={() => forward(it)} className="inline-flex items-center px-2 py-1 bg-green-600 text-white rounded hover:bg-green-700">
                <Play className="w-3 h-3 mr-1" /> Forward
              </button>
              <button onClick={() => drop(it)} className="inline-flex items-center px-2 py-1 bg-red-600 text-white rounded hover:bg-red-700">
                <X className="w-3 h-3 mr-1" /> Drop
              </button>
            </div>
          </div>
        ))}
        {!loading && items.length === 0 && (
          <div className="p-4 text-xs text-gray-500">No pending intercepts</div>
        )}
        {loading && (
          <div className="p-4 text-xs text-gray-500">Loading…</div>
        )}
      </div>
    </div>
  );
};

export default DASTInterceptQueue;


