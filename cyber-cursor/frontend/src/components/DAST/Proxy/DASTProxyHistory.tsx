import React, { useEffect, useMemo, useState } from 'react';
import { dastProjectToolsService } from '../../../services/dastProjectToolsService';
import { RefreshCw, Filter, Search, Download, Send, ChevronLeft, ChevronRight } from 'lucide-react';

interface ProxyEntry {
  id: string;
  method: string;
  url: string;
  status?: number;
  size?: number;
  time?: string | null;
}

interface DASTProxyHistoryProps {
  projectId: string;
  onSendToRepeater?: (entry: ProxyEntry) => void;
}

const METHODS = ['ALL', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];

const DASTProxyHistory: React.FC<DASTProxyHistoryProps> = ({ projectId, onSendToRepeater }) => {
  const [loading, setLoading] = useState(false);
  const [entries, setEntries] = useState<ProxyEntry[]>([]);
  const [error, setError] = useState<string | null>(null);

  // Client-side filters (backend route currently returns last 200)
  const [method, setMethod] = useState<string>('ALL');
  const [status, setStatus] = useState<string>('');
  const [query, setQuery] = useState<string>('');

  // Simple pagination over the loaded 200 entries
  const [page, setPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(50);

  const fetchHistory = async () => {
    try {
      setLoading(true);
      setError(null);
      const params: any = { page, page_size: pageSize };
      if (method !== 'ALL') params.method = method;
      if (status.trim()) {
        const n = parseInt(status, 10);
        if (!Number.isNaN(n)) params.status = n;
      }
      if (query.trim()) params.host = query.trim();
      const res = await dastProjectToolsService.getHttpHistory(projectId, params);
      const list: ProxyEntry[] = (res?.entries || res?.items || []) as ProxyEntry[];
      setEntries(Array.isArray(list) ? list : []);
    } catch (e: any) {
      setError(e?.message || 'Failed to load proxy history');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId, page, pageSize, method, status, query]);

  const filtered = useMemo(() => {
    let out = entries;
    if (method !== 'ALL') {
      out = out.filter(e => e.method?.toUpperCase() === method);
    }
    if (status.trim()) {
      const num = parseInt(status, 10);
      if (!Number.isNaN(num)) out = out.filter(e => e.status === num);
    }
    if (query.trim()) {
      const q = query.toLowerCase();
      out = out.filter(e => e.url?.toLowerCase().includes(q));
    }
    return out;
  }, [entries, method, status, query]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const pageItems = filtered; // server-side paging already applied

  const handleExportHAR = () => {
    try {
      const har = {
        log: {
          version: '1.2',
          creator: { name: 'CyberShield', version: '1.0' },
          entries: entries.map((e) => ({
            startedDateTime: e.time || new Date().toISOString(),
            time: 0,
            request: { method: e.method, url: e.url, headers: [], cookies: [], queryString: [], httpVersion: 'HTTP/1.1', headersSize: -1, bodySize: e.size || 0 },
            response: { status: e.status || 0, statusText: '', httpVersion: 'HTTP/1.1', headers: [], cookies: [], content: { size: e.size || 0, mimeType: '' }, redirectURL: '', headersSize: -1, bodySize: e.size || 0 },
            cache: {},
            timings: { send: 0, wait: 0, receive: 0 },
          })),
        },
      };
      const blob = new Blob([JSON.stringify(har, null, 2)], { type: 'application/json' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `proxy-${projectId}.har`;
      a.click();
    } catch {
      // no-op
    }
  };

  const [modalOpen, setModalOpen] = useState(false);
  const [modalEntry, setModalEntry] = useState<ProxyEntry | null>(null);
  const [modalTab, setModalTab] = useState<'raw' | 'pretty' | 'hex'>('raw');
  const [modalPayload, setModalPayload] = useState<{ headers: any; body: string }>({ headers: {}, body: '' });
  const openModal = async (entry: ProxyEntry) => {
    try {
      const res = await dastProjectToolsService.getProxyEntryPayload(projectId, entry.id, 'response');
      const body = typeof res?.body === 'string' ? res.body : JSON.stringify(res?.body || {}, null, 2);
      setModalPayload({ headers: res?.headers || {}, body });
      setModalEntry(entry);
      setModalTab('raw');
      setModalOpen(true);
    } catch {
      setModalPayload({ headers: {}, body: '' });
      setModalEntry(entry);
      setModalOpen(true);
    }
  };

  const hexFromText = (text: string) => {
    try {
      const enc = new TextEncoder();
      const bytes = enc.encode(text || '');
      return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(' ');
    } catch { return ''; }
  };

  const prettyFromText = (text: string, headers: any) => {
    const isJson = /application\/(json|\+json)/i.test(JSON.stringify(headers || {}));
    if (isJson) {
      try { return JSON.stringify(JSON.parse(text || '{}'), null, 2); } catch { return text; }
    }
    return text;
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <button onClick={fetchHistory} disabled={loading} className="inline-flex items-center px-3 py-1.5 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50">
            <RefreshCw className={`w-4 h-4 mr-2 ${loading ? 'animate-spin' : ''}`} /> Refresh
          </button>
          <button onClick={handleExportHAR} className="inline-flex items-center px-3 py-1.5 bg-gray-100 text-gray-800 rounded hover:bg-gray-200">
            <Download className="w-4 h-4 mr-2" /> Export HAR
          </button>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center border rounded px-2">
            <Filter className="w-4 h-4 text-gray-500 mr-1" />
            <select value={method} onChange={(e) => setMethod(e.target.value)} className="py-1 bg-transparent outline-none">
              {METHODS.map(m => <option key={m} value={m}>{m}</option>)}
            </select>
          </div>
          <input value={status} onChange={(e) => setStatus(e.target.value)} placeholder="Status" className="border rounded px-2 py-1 w-24" />
          <div className="flex items-center border rounded px-2">
            <Search className="w-4 h-4 text-gray-500 mr-1" />
            <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search URL" className="py-1 bg-transparent outline-none" />
          </div>
          <select value={pageSize} onChange={(e) => setPageSize(parseInt(e.target.value, 10))} className="border rounded px-2 py-1">
            {[25, 50, 100, 200].map(ps => <option key={ps} value={ps}>{ps} / page</option>)}
          </select>
        </div>
      </div>

      {error && <div className="text-red-600 text-sm">{error}</div>}

      <div className="border rounded overflow-hidden">
        <div className="grid grid-cols-12 bg-gray-50 text-xs font-semibold text-gray-600 px-3 py-2">
          <div className="col-span-1">Method</div>
          <div className="col-span-1">Status</div>
          <div className="col-span-7">URL</div>
          <div className="col-span-1 text-right">Size</div>
          <div className="col-span-2">Time</div>
        </div>
        <div className="max-h-96 overflow-auto divide-y">
          {pageItems.map((e) => (
            <div key={e.id} className="grid grid-cols-12 items-center px-3 py-2 hover:bg-gray-50">
              <div className="col-span-1 text-xs font-mono">{e.method}</div>
              <div className="col-span-1 text-xs">{e.status ?? ''}</div>
              <div className="col-span-7 text-xs truncate" title={e.url}>{e.url}</div>
              <div className="col-span-1 text-xs text-right">{e.size ?? ''}</div>
              <div className="col-span-2 flex items-center justify-between text-xs">
                <span>{e.time ? new Date(e.time).toLocaleTimeString() : ''}</span>
                <div className="flex items-center gap-2">
                  <button onClick={() => openModal(e)} className="inline-flex items-center px-2 py-0.5 text-xs border rounded">View</button>
                  {!!onSendToRepeater && (
                    <button onClick={() => onSendToRepeater(e)} className="inline-flex items-center px-2 py-0.5 text-blue-600 hover:bg-blue-50 rounded">
                      <Send className="w-3 h-3 mr-1" /> Repeater
                    </button>
                  )}
                </div>
              </div>
            </div>
          ))}
          {!loading && pageItems.length === 0 && (
            <div className="px-3 py-6 text-sm text-gray-500">No entries</div>
          )}
          {loading && (
            <div className="px-3 py-6 text-sm text-gray-500">Loading…</div>
          )}
        </div>
      </div>

      {modalOpen && modalEntry && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
          <div className="bg-white rounded-md shadow-xl w-[90vw] max-w-5xl max-h-[85vh] flex flex-col">
            <div className="flex items-center justify-between px-4 py-2 border-b">
              <div className="text-sm font-medium truncate">{modalEntry.method} {modalEntry.url}</div>
              <button className="text-sm px-2 py-1 border rounded" onClick={() => setModalOpen(false)}>Close</button>
            </div>
            <div className="px-4 py-2 border-b">
              <div className="inline-flex items-center gap-2 text-xs">
                <button className={`px-2 py-1 rounded ${modalTab==='raw'?'bg-blue-600 text-white':'bg-gray-100'}`} onClick={() => setModalTab('raw')}>Raw</button>
                <button className={`px-2 py-1 rounded ${modalTab==='pretty'?'bg-blue-600 text-white':'bg-gray-100'}`} onClick={() => setModalTab('pretty')}>Pretty</button>
                <button className={`px-2 py-1 rounded ${modalTab==='hex'?'bg-blue-600 text-white':'bg-gray-100'}`} onClick={() => setModalTab('hex')}>Hex</button>
              </div>
            </div>
            <div className="p-4 overflow-auto text-xs" style={{ maxHeight: '65vh' }}>
              {modalTab === 'raw' && (
                <pre className="whitespace-pre-wrap break-words">{modalPayload.body}</pre>
              )}
              {modalTab === 'pretty' && (
                <pre className="whitespace-pre-wrap break-words">{prettyFromText(modalPayload.body, modalPayload.headers)}</pre>
              )}
              {modalTab === 'hex' && (
                <pre className="whitespace-pre-wrap break-words">{hexFromText(modalPayload.body)}</pre>
              )}
            </div>
          </div>
        </div>
      )}

      <div className="flex items-center justify-end gap-2">
        <button disabled={page <= 1} onClick={() => setPage(p => Math.max(1, p - 1))} className="inline-flex items-center px-2 py-1 border rounded disabled:opacity-50">
          <ChevronLeft className="w-4 h-4" />
        </button>
        <div className="text-sm">Page {page} / {totalPages}</div>
        <button disabled={page >= totalPages} onClick={() => setPage(p => Math.min(totalPages, p + 1))} className="inline-flex items-center px-2 py-1 border rounded disabled:opacity-50">
          <ChevronRight className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
};

export default DASTProxyHistory;


