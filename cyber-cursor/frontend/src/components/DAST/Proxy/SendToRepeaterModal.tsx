import React, { useEffect, useState } from 'react';
import { dastProjectToolsService } from '../../../services/dastProjectToolsService';

interface SendToRepeaterModalProps {
  projectId: string;
  entryId?: string;
  open: boolean;
  onClose: () => void;
}

const SendToRepeaterModal: React.FC<SendToRepeaterModalProps> = ({ projectId, entryId, open, onClose }) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [request, setRequest] = useState<any>({ method: 'GET', url: '', headers: {}, body: '' });

  useEffect(() => {
    const load = async () => {
      if (!open || !entryId) return;
      try {
        setLoading(true);
        setError(null);
        const res = await dastProjectToolsService.getProxyEntry(projectId, entryId);
        const req = res?.request || {};
        setRequest({
          method: req.method || 'GET',
          url: req.url || '',
          headers: req.headers || {},
          body: typeof req.body === 'string' ? req.body : '',
        });
      } catch (e: any) {
        setError(e?.message || 'Failed to load request');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [projectId, entryId, open]);

  const send = async () => {
    try {
      setLoading(true);
      await dastProjectToolsService.repeaterSend(projectId, request);
      onClose();
    } catch (e: any) {
      setError(e?.message || 'Failed to send to repeater');
    } finally {
      setLoading(false);
    }
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="bg-white w-full max-w-3xl rounded shadow-lg p-4 space-y-3">
        <div className="flex items-center justify-between">
          <div className="font-semibold">Send to Repeater</div>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-700">✕</button>
        </div>
        {error && <div className="text-red-600 text-sm">{error}</div>}
        <div className="grid grid-cols-6 gap-2 items-center">
          <select className="border rounded px-2 py-1 col-span-1" value={request.method} onChange={e => setRequest((r: any) => ({ ...r, method: e.target.value }))}>
            {['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'].map(m => <option key={m} value={m}>{m}</option>)}
          </select>
          <input className="border rounded px-2 py-1 col-span-5" value={request.url} onChange={e => setRequest((r: any) => ({ ...r, url: e.target.value }))} placeholder="https://example.com/path" />
        </div>
        <div>
          <div className="text-xs text-gray-600 mb-1">Headers (JSON)</div>
          <textarea className="border rounded w-full px-2 py-1 font-mono text-xs h-24" value={JSON.stringify(request.headers, null, 2)} onChange={e => {
            try { setRequest((r: any) => ({ ...r, headers: JSON.parse(e.target.value || '{}') })); } catch {}
          }} />
        </div>
        <div>
          <div className="text-xs text-gray-600 mb-1">Body</div>
          <textarea className="border rounded w-full px-2 py-1 font-mono text-xs h-32" value={request.body} onChange={e => setRequest((r: any) => ({ ...r, body: e.target.value }))} />
        </div>
        <div className="flex items-center justify-end gap-2">
          <button onClick={onClose} className="px-3 py-1.5 border rounded">Cancel</button>
          <button onClick={send} disabled={loading} className="px-3 py-1.5 bg-blue-600 text-white rounded disabled:opacity-50">{loading ? 'Sending…' : 'Send'}</button>
        </div>
      </div>
    </div>
  );
};

export default SendToRepeaterModal;


