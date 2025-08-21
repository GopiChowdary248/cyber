import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useParams } from 'react-router-dom';
import { dastProjectToolsService } from '../../services/dastProjectToolsService';
import DASTProxyHistory from '../../components/DAST/Proxy/DASTProxyHistory';
import DASTInterceptQueue from '../../components/DAST/Proxy/DASTInterceptQueue';

// Removed duplicate older ProxyEntryDetail version

function buildTargetTree(nodes: any[]): any[] {
  const idTo: Record<string, any> = {};
  const roots: any[] = [];
  nodes.forEach(n => { idTo[n.id] = { ...n, children: [] }; });
  nodes.forEach(n => {
    const item = idTo[n.id];
    if (n.parent_id && idTo[n.parent_id]) {
      idTo[n.parent_id].children.push(item);
    } else {
      roots.push(item);
    }
  });
  return roots;
}

function filterTree(tree: any[], term: string): any[] {
  if (!term) return tree;
  const q = term.toLowerCase();
  const dfs = (node: any): any | null => {
    const selfMatch = (node.label || '').toLowerCase().includes(q) || (node.type || '').toLowerCase().includes(q);
    const children = (node.children || []).map((c: any) => dfs(c)).filter(Boolean) as any[];
    if (selfMatch || children.length) {
      return { ...node, children };
    }
    return null;
  };
  return tree.map(n => dfs(n)).filter(Boolean) as any[];
}

function renderHighlighted(text: string, term: string): JSX.Element {
  if (!term) return <>{text}</>;
  const q = term.toLowerCase();
  const parts = text.split(new RegExp(`(${term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'ig'));
  return (
    <>
      {parts.map((part, i) => (
        part.toLowerCase() === q ? <mark key={i} className="bg-yellow-200 text-gray-900">{part}</mark> : <span key={i}>{part}</span>
      ))}
    </>
  );
}

function base64ToHexDump(b64: string): string {
  try {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    let out = '';
    for (let i = 0; i < bytes.length; i += 16) {
      const chunk = bytes.slice(i, i + 16);
      const hex = Array.from(chunk).map(b => b.toString(16).padStart(2, '0')).join(' ');
      const ascii = Array.from(chunk).map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.')).join('');
      out += `${i.toString(16).padStart(8, '0')}  ${hex.padEnd(16 * 3 - 1, ' ')}  |${ascii}|\n`;
    }
    return out || '(empty)';
  } catch {
    return '(invalid base64)';
  }
}

function stringToHexDump(text: string): string {
  try {
    const bytes = new TextEncoder().encode(text);
    let out = '';
    for (let i = 0; i < bytes.length; i += 16) {
      const chunk = bytes.slice(i, i + 16);
      const hex = Array.from(chunk).map(b => b.toString(16).padStart(2, '0')).join(' ');
      const ascii = Array.from(chunk).map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.')).join('');
      out += `${i.toString(16).padStart(8, '0')}  ${hex.padEnd(16 * 3 - 1, ' ')}  |${ascii}|\n`;
    }
    return out || '(empty)';
  } catch {
    return '(invalid string)';
  }
}


function ProxyEntryDetail({ projectId, entry, onClose, onAfterAction }: { projectId: string; entry: any; onClose: () => void; onAfterAction?: () => void }) {
  const [detail, setDetail] = useState<any>(null);
  const [method, setMethod] = useState<string>('GET');
  const [url, setUrl] = useState<string>('');
  const [headersText, setHeadersText] = useState<string>('{}');
  const [bodyText, setBodyText] = useState<string>('');
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const d = await dastProjectToolsService.getProxyEntry(projectId, entry.id);
        if (!cancelled) setDetail(d);
      } catch {
        if (!cancelled) setDetail(entry);
      }
    })();
    return () => { cancelled = true; };
  }, [projectId, entry]);
  useEffect(() => {
    const req = (detail as any)?.request || entry?.request || {};
    setMethod(req.method || entry.method || 'GET');
    setUrl(req.url || entry.url || '');
    setHeadersText(JSON.stringify(req.headers || {}, null, 2));
    setBodyText(req.body || '');
  }, [detail, entry]);
  return (
    <div className="bg-white rounded-md border p-4">
      <div className="flex items-center justify-between">
        <div className="font-semibold mb-2">Entry Detail</div>
        <button className="text-sm text-gray-600 hover:text-gray-900" onClick={onClose}>Close</button>
      </div>
      <div className="text-xs text-gray-500 mb-2">{entry.method} {entry.url}</div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="space-y-2">
          <div className="font-semibold text-sm mb-1">Request (editable)</div>
          <div className="flex gap-2">
            <select className="border rounded px-2 py-1" value={method} onChange={(e) => setMethod(e.target.value)}>
              {['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'].map(m => <option key={m} value={m}>{m}</option>)}
            </select>
            <input className="border rounded px-2 py-1 flex-1" value={url} onChange={(e) => setUrl(e.target.value)} />
          </div>
          <div>
            <div className="text-xs text-gray-600 mb-1">Headers (JSON)</div>
            <textarea className="w-full border rounded p-2 text-xs" rows={6} value={headersText} onChange={(e) => setHeadersText(e.target.value)} />
          </div>
          <div>
            <div className="text-xs text-gray-600 mb-1">Body</div>
            <textarea className="w-full border rounded p-2 text-xs" rows={8} value={bodyText} onChange={(e) => setBodyText(e.target.value)} />
          </div>
          <div className="flex gap-2">
            <button className="px-3 py-1.5 bg-blue-600 text-white rounded" onClick={async () => {
              try {
                let headers = {} as any;
                try { headers = JSON.parse(headersText || '{}'); } catch {}
                const payload: any = { request: { method, url, headers, body: bodyText } };
                if (entry.source === 'intercept' || entry.interceptId) payload.interceptId = entry.interceptId || entry.id;
                else payload.entryId = entry.id;
                await dastProjectToolsService.proxyForward(projectId, payload);
                onAfterAction && onAfterAction();
                onClose();
              } catch {}
            }}>Forward</button>
            <button className="px-3 py-1.5 bg-red-600 text-white rounded" onClick={async () => {
              try {
                const payload: any = {};
                if (entry.source === 'intercept' || entry.interceptId) payload.interceptId = entry.interceptId || entry.id; else payload.entryId = entry.id;
                await dastProjectToolsService.proxyDrop(projectId, payload);
                onAfterAction && onAfterAction();
                onClose();
              } catch {}
            }}>Drop</button>
          </div>
        </div>
        <div>
          <div className="font-semibold text-sm mb-1">Response</div>
          <pre className="text-xs overflow-auto">{JSON.stringify(detail?.response || {}, null, 2)}</pre>
        </div>
      </div>
    </div>
  );
}

function CAConfigForm({ projectId }: { projectId: string }) {
  const [enabled, setEnabled] = useState<boolean>(false);
  const [hasCert, setHasCert] = useState<boolean>(false);
  const [hasKey, setHasKey] = useState<boolean>(false);
  const [certText, setCertText] = useState<string>('');
  const [keyText, setKeyText] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const base = (process.env.REACT_APP_API_URL || '').replace(/\/$/, '');
      const token = localStorage.getItem('access_token');
      const res = await fetch(`${base}/api/v1/dast/projects/${projectId}/proxy/ca`, { headers: { Authorization: `Bearer ${token}` } });
      const data = await res.json();
      setEnabled(Boolean(data?.enabled));
      setHasCert(Boolean(data?.has_cert));
      setHasKey(Boolean(data?.has_key));
    } catch (e: any) { setError(e?.message || 'Failed to load CA status'); } finally { setLoading(false); }
  }, [projectId]);

  useEffect(() => { load(); }, [load]);

  const handleSave = async () => {
    try {
      setLoading(true);
      setError(null);
      const base = (process.env.REACT_APP_API_URL || '').replace(/\/$/, '');
      const token = localStorage.getItem('access_token');
      await fetch(`${base}/api/v1/dast/projects/${projectId}/proxy/ca`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ ca_cert_pem: certText || undefined, ca_key_pem: keyText || undefined, enabled }),
      });
      await load();
      setCertText('');
      setKeyText('');
    } catch (e: any) { setError(e?.message || 'Failed to save CA'); } finally { setLoading(false); }
  };

  return (
    <div className="space-y-2">
      <div className="font-medium text-sm mb-1">HTTPS Interception (Project CA)</div>
      {error && <div className="text-red-600 text-xs">{error}</div>}
      <div className="flex items-center gap-3">
        <label className="text-xs text-gray-700 inline-flex items-center gap-1"><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enabled</label>
        <div className="text-xs text-gray-600">Status: {hasCert ? 'Cert' : 'No Cert'} • {hasKey ? 'Key' : 'No Key'}</div>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
        <div>
          <div className="text-xs text-gray-600 mb-1">CA Certificate (PEM)</div>
          <textarea className="w-full border rounded p-2 text-xs h-32" placeholder="-----BEGIN CERTIFICATE-----\n..." value={certText} onChange={(e) => setCertText(e.target.value)} />
        </div>
        <div>
          <div className="text-xs text-gray-600 mb-1">CA Private Key (PEM)</div>
          <textarea className="w-full border rounded p-2 text-xs h-32" placeholder="-----BEGIN PRIVATE KEY-----\n..." value={keyText} onChange={(e) => setKeyText(e.target.value)} />
        </div>
      </div>
      <div className="flex items-center justify-between">
        <a className="text-xs text-blue-600 hover:underline" href={`${(process.env.REACT_APP_API_URL || '').replace(/\/$/, '')}/api/v1/dast/projects/${projectId}/proxy/ca/cert`} target="_blank" rel="noreferrer">Download CA Certificate</a>
        <div>
          <button className="px-3 py-1.5 bg-gray-200 rounded mr-2" disabled={loading} onClick={load}>Reload</button>
          <button className="px-3 py-1.5 bg-blue-600 text-white rounded" disabled={loading} onClick={handleSave}>{loading ? 'Saving…' : 'Save'}</button>
        </div>
      </div>
    </div>
  );
}

type TabId = 'dashboard' | 'target' | 'proxy' | 'intruder' | 'repeater' | 'sequencer' | 'decoder' | 'comparer' | 'extender' | 'scanner' | 'logger' | 'settings';
type TabAll = TabId | 'members';

const tabs: { id: TabAll; label: string }[] = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'target', label: 'Target' },
  { id: 'proxy', label: 'Proxy' },
  { id: 'intruder', label: 'Intruder' },
  { id: 'repeater', label: 'Repeater' },
  { id: 'sequencer', label: 'Sequencer' },
  { id: 'decoder', label: 'Decoder' },
  { id: 'comparer', label: 'Comparer' },
  { id: 'extender', label: 'Extender' },
  { id: 'scanner', label: 'Scanner' },
  { id: 'logger', label: 'Logger' },
  { id: 'settings', label: 'Settings' },
  { id: 'members', label: 'Members' },
];

const wsUrl = (path: string) => (process.env.REACT_APP_API_URL || '').replace('http', 'ws') + path;

const DASTProjectTools: React.FC = () => {
  const { projectId = '' } = useParams<{ projectId: string }>();
  const [active, setActive] = useState<TabAll>('dashboard');

  // Dashboard
  const [activity, setActivity] = useState<any>(null);
  const [issues, setIssues] = useState<any>(null);
  const [events, setEvents] = useState<any[]>([]);

  // Target
  const [siteMap, setSiteMap] = useState<any[]>([]);
  const [siteExpanded, setSiteExpanded] = useState<Record<string, boolean>>({});
  const [siteFilter, setSiteFilter] = useState<string>('');
  const [siteSelected, setSiteSelected] = useState<Record<string, boolean>>({});
  const [scopeRules, setScopeRules] = useState<any>({ include: ['example.com'], exclude: ['/admin'] });
  const [newTarget, setNewTarget] = useState<string>('');

  // Proxy
  const [interceptEnabled, setInterceptEnabled] = useState<boolean>(false);
  const [httpHistory, setHttpHistory] = useState<any[]>([]);
  const [selectedProxyEntry, setSelectedProxyEntry] = useState<any | null>(null);
  const [proxySettings, setProxySettings] = useState<any>({ listeners: [], matchReplace: [] });
  const [intercepts, setIntercepts] = useState<any[]>([]);
  const [interceptQueue, setInterceptQueue] = useState<any[]>([]);
  const [interceptIndex, setInterceptIndex] = useState<number>(0);
  const [wsFrames, setWsFrames] = useState<any[]>([]);
  const [wsFramesLimit, setWsFramesLimit] = useState<number>(200);
  const [wsFramesOpcode, setWsFramesOpcode] = useState<string>('all');
  const [wsFramesSearch, setWsFramesSearch] = useState<string>('');
  const [wsFrameModal, setWsFrameModal] = useState<{ open: boolean; frame: any | null; view: 'raw' | 'hex'; meta?: any }>(() => ({ open: false, frame: null, view: 'raw' }));
  // keyboard shortcuts for intercepts
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (active !== 'proxy') return;
      if (!interceptQueue.length) return;
      if (e.key.toLowerCase() === 'j') {
        setInterceptIndex((i) => Math.min(interceptQueue.length - 1, i + 1));
      } else if (e.key.toLowerCase() === 'k') {
        setInterceptIndex((i) => Math.max(0, i - 1));
      } else if (e.key.toLowerCase() === 'o') {
        const it: any = interceptQueue[interceptIndex];
        if (!it) return;
        const req = it.request || {};
        setSelectedProxyEntry({ id: it.id, method: req.method || 'GET', url: req.url || '', request: req });
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [active, interceptQueue, interceptIndex]);

  // Intruder
  const [attackConfig, setAttackConfig] = useState<any>({ host: '', port: 443, request: '', payloads: [] });
  const [attackId, setAttackId] = useState<string>('');
  const [attackStatus, setAttackStatus] = useState<any>(null);
  const [attackResults, setAttackResults] = useState<any[]>([]);
  const attackRequestRef = useRef<HTMLTextAreaElement | null>(null);
  const [payloadsText, setPayloadsText] = useState<string>('');

  // Repeater
  const [repMethod, setRepMethod] = useState<string>('GET');
  const [repUrl, setRepUrl] = useState<string>('');
  const [repHeaders, setRepHeaders] = useState<string>('{}');
  const [repBody, setRepBody] = useState<string>('');
  const [repResponse, setRepResponse] = useState<any>(null);
  const [repHistory, setRepHistory] = useState<any[]>([]);
  const [repSelected, setRepSelected] = useState<any | null>(null);
  const [repViewMode, setRepViewMode] = useState<'raw' | 'pretty' | 'hex'>('raw');

  function normalizeHeaderValue(headers: any, name: string): string | undefined {
    try {
      if (!headers) return undefined;
      if (Array.isArray(headers)) {
        for (const h of headers) {
          if (Array.isArray(h) && h.length >= 2 && String(h[0]).toLowerCase() === name.toLowerCase()) return String(h[1]);
          if (h && typeof h === 'object') {
            const k = Object.keys(h).find(k => k.toLowerCase() === name.toLowerCase());
            if (k) return String(h[k]);
          }
        }
        return undefined;
      }
      if (typeof headers === 'object') {
        const k = Object.keys(headers).find(k => k.toLowerCase() === name.toLowerCase());
        return k ? String(headers[k]) : undefined;
      }
      return undefined;
    } catch { return undefined; }
  }

  function getRepResponseText(): { text: string; contentType: string } {
    const headers = (repResponse && (repResponse.headers || repResponse.response_headers)) || {};
    const contentType = (normalizeHeaderValue(headers, 'content-type') || '').toLowerCase();
    let text = '';
    if (repResponse && typeof repResponse.body === 'string') text = repResponse.body;
    else if (repResponse && typeof repResponse.text === 'string') text = repResponse.text;
    else if (repResponse && typeof repResponse.response === 'string') text = repResponse.response;
    else if (repResponse && typeof repResponse.response?.body === 'string') text = repResponse.response.body;
    else if (repResponse) text = JSON.stringify(repResponse, null, 2);
    return { text, contentType };
  }

  function prettyXml(input: string): string {
    try {
      const reg = /(>)(<)(\/*)/g;
      let xml = input.replace(reg, '$1\n$2$3');
      let pad = 0;
      return xml.split(/\r?\n/).map((line) => {
        let indent = 0;
        if (line.match(/^\s*<\//)) pad = Math.max(pad - 1, 0);
        if (line.match(/^\s*<[^!?]/) && !line.endsWith('/>') && !line.match(/^\s*<.*><\/.*>\s*$/)) indent = 1;
        const out = `${'  '.repeat(pad)}${line.trim()}`;
        pad += indent;
        return out;
      }).join('\n');
    } catch {
      return input;
    }
  }

  function renderRepResponse(): string {
    const { text, contentType } = getRepResponseText();
    if (repViewMode === 'hex') return stringToHexDump(text || '');
    if (repViewMode === 'pretty') {
      // JSON
      if (contentType.includes('application/json') || contentType.includes('text/json')) {
        try { return JSON.stringify(JSON.parse(text), null, 2); } catch { /* fallthrough */ }
      }
      // XML/HTML
      if (contentType.includes('xml') || contentType.includes('html')) {
        return prettyXml(text);
      }
      // Heuristic JSON if no header
      try { return JSON.stringify(JSON.parse(text), null, 2); } catch {}
      return text;
    }
    // raw
    return text;
  }

  // Sequencer
  const [sequenceId, setSequenceId] = useState<string>('');
  const [sequenceResults, setSequenceResults] = useState<any>(null);

  // Decoder
  const [decInput, setDecInput] = useState<string>('');
  const [decMode, setDecMode] = useState<'encode' | 'decode' | 'hash'>('encode');
  const [decOutput, setDecOutput] = useState<string>('');

  // Comparer
  const [cmpLeft, setCmpLeft] = useState<string>('');
  const [cmpRight, setCmpRight] = useState<string>('');
  const [cmpMode, setCmpMode] = useState<'words' | 'bytes'>('words');
  const [cmpResult, setCmpResult] = useState<any>(null);

  // Extender
  const [extensions, setExtensions] = useState<any[]>([]);
  const [installName, setInstallName] = useState<string>('');

  // Scanner
  const [scanConfig, setScanConfig] = useState<any>({ scope: 'in-scope', speed: 'normal', modules: ['common'] });
  const [scanId, setScanId] = useState<string>('');
  const [scanStatus, setScanStatus] = useState<any>(null);
  const [scanIssues, setScanIssues] = useState<any[]>([]);
  const [scannerLogs, setScannerLogs] = useState<any[]>([]);
  const [scannerPaused, setScannerPaused] = useState<boolean>(false);
  const [scannerFilter, setScannerFilter] = useState<{ info: boolean; warn: boolean; error: boolean }>({ info: true, warn: true, error: true });
  const scannerPausedRef = useRef<boolean>(false);
  const scannerFilterRef = useRef<{ info: boolean; warn: boolean; error: boolean }>({ info: true, warn: true, error: true });
  useEffect(() => { scannerPausedRef.current = scannerPaused; }, [scannerPaused]);
  useEffect(() => { scannerFilterRef.current = scannerFilter; }, [scannerFilter]);

  // Logger
  const [logEntries, setLogEntries] = useState<any[]>([]);
  const [logQuery, setLogQuery] = useState<string>('');
  const [logMethod, setLogMethod] = useState<string>('');
  const [logStatus, setLogStatus] = useState<string>('');
  const [logHost, setLogHost] = useState<string>('');
  const [logMime, setLogMime] = useState<string>('');
  const [logPage, setLogPage] = useState<number>(1);
  const [logPageSize, setLogPageSize] = useState<number>(100);
  const [logTotal, setLogTotal] = useState<number>(0);
  const [logOnlyBookmarked, setLogOnlyBookmarked] = useState<boolean>(false);
  const [logSelected, setLogSelected] = useState<any | null>(null);
  const [logDetail, setLogDetail] = useState<any | null>(null);
  const loadLogDetail = useCallback(async (entryId: string) => {
    try {
      const d = await dastProjectToolsService.getLoggerEntryDetail(projectId, entryId);
      setLogDetail(d);
    } catch {}
  }, [projectId]);
  const toCurl = (detail: any): string => {
    if (!detail) return '';
    const method = detail.method || 'GET';
    const url = detail.url || '';
    const parts: string[] = ["curl", "-i", "-X", method, JSON.stringify(url)];
    const headers = (((detail.details || {}).request || {}).headers) || {};
    Object.keys(headers).forEach(k => {
      const v = headers[k];
      parts.push("-H", JSON.stringify(`${k}: ${v}`));
    });
    const body = (((detail.details || {}).request || {}).body);
    if (body) parts.push("--data", JSON.stringify(typeof body === 'string' ? body : JSON.stringify(body)));
    return parts.join(' ');
  };
  const handleLoggerExport = () => {
    const base = (process.env.REACT_APP_API_URL || '') + `/api/v1/dast/projects/${projectId}/logger/export?format=har`;
    window.open(base, '_blank');
  };

  // Settings
  const [settings, setSettings] = useState<any>(null);
  const [settingsDraft, setSettingsDraft] = useState<string>('');

  // Members
  const [members, setMembers] = useState<any[]>([]);
  const [newMemberUserId, setNewMemberUserId] = useState<string>('');
  const [newMemberRole, setNewMemberRole] = useState<string>('member');

  // WebSockets
  const dashboardWs = useRef<WebSocket | null>(null);
  const proxyWs = useRef<WebSocket | null>(null);
  const loggerWs = useRef<WebSocket | null>(null);
  const scannerWs = useRef<WebSocket | null>(null);

  // Initial load
  useEffect(() => {
    const load = async () => {
      if (!projectId) return;
      const [a, i, e, map, hist, ext, logs, psettings, frames] = await Promise.all([
        dastProjectToolsService.getDashboardActivity(projectId),
        dastProjectToolsService.getDashboardIssues(projectId),
        dastProjectToolsService.getDashboardEvents(projectId, { limit: 50 }),
        dastProjectToolsService.getSiteMap(projectId),
        dastProjectToolsService.getHttpHistory(projectId),
        dastProjectToolsService.extenderList(projectId),
        dastProjectToolsService.loggerEntries(projectId),
        dastProjectToolsService.getProxySettings(projectId),
        dastProjectToolsService.getWSFrames(projectId, { limit: 200 }),
      ]);
      setActivity(a as any);
      setIssues(i as any);
      setEvents((e as any)?.events || []);
      setSiteMap((map as any)?.nodes || []);
      setHttpHistory((hist as any)?.entries || []);
      setExtensions((ext as any)?.installed || []);
      setLogEntries((logs as any)?.entries || []);
      setProxySettings(((psettings as any)?.settings) || { listeners: [], matchReplace: [] });
      setWsFrames(((frames as any)?.frames) || []);
      // initial intercept queue load
      try {
        const q = await dastProjectToolsService.listIntercepts(projectId);
        setInterceptQueue(((q as any)?.intercepts) || []);
        setInterceptIndex(0);
      } catch {}
    };
    load();
  }, [projectId]);

  const refreshWsFrames = useCallback(async () => {
    if (!projectId) return;
    try {
      const frames = await dastProjectToolsService.getWSFrames(projectId, { limit: wsFramesLimit });
      setWsFrames(((frames as any)?.frames) || []);
    } catch {}
  }, [projectId, wsFramesLimit]);

  // Scanner WS only when tab active
  useEffect(() => {
    if (!projectId) return;
    // Close any prior
    if (active !== 'scanner') {
      scannerWs.current?.close();
      scannerWs.current = null;
      return;
    }
    try {
      const token = localStorage.getItem('access_token');
      scannerWs.current = new WebSocket(wsUrl(`/api/v1/dast/projects/ws/${projectId}/scanner?token=${token || ''}`));
      scannerWs.current.onmessage = (evt) => {
        try {
          const data = JSON.parse(evt.data);
          if (data.type === 'log') {
            const lvl = (data.level || 'info').toLowerCase();
            if (scannerPausedRef.current) return;
            if (!scannerFilterRef.current[(lvl as 'info' | 'warn' | 'error')]) return;
            setScannerLogs((prev) => [{ id: Date.now().toString(), level: lvl, message: data.message, timestamp: data.timestamp }, ...prev].slice(0, 500));
          }
        } catch {}
      };
    } catch {}
    return () => {
      scannerWs.current?.close();
      scannerWs.current = null;
    };
  }, [active, projectId]);

  // Settings lazy load when tab opens
  useEffect(() => {
    const loadSettings = async () => {
      if (active !== 'settings' || !projectId) return;
      const s = await dastProjectToolsService.getSettings(projectId);
      setSettings(s);
      setSettingsDraft(JSON.stringify(s, null, 2));
    };
    loadSettings();
  }, [active, projectId]);

  // Members load when tab opens
  useEffect(() => {
    const loadMembers = async () => {
      if (active !== 'members' || !projectId) return;
      const res = await dastProjectToolsService.listMembers(projectId);
      setMembers((res as any)?.members || []);
    };
    loadMembers();
  }, [active, projectId]);

  // WebSockets
  useEffect(() => {
    if (!projectId) return;

    // Dashboard WS
    {
      const token = localStorage.getItem('access_token');
      dashboardWs.current = new WebSocket(wsUrl(`/api/v1/dast/projects/ws/${projectId}/dashboard?token=${token || ''}`));
    }
    dashboardWs.current.onmessage = (evt) => {
      try {
        const data = JSON.parse(evt.data);
        if (data.type === 'heartbeat') return;
        setEvents((prev) => [{ id: Date.now().toString(), type: 'ws', message: JSON.stringify(data), timestamp: new Date().toISOString() }, ...prev].slice(0, 200));
      } catch {}
    };

    // Proxy WS
    {
      const token = localStorage.getItem('access_token');
      proxyWs.current = new WebSocket(wsUrl(`/api/v1/dast/projects/ws/${projectId}/proxy?token=${token || ''}`));
    }
    proxyWs.current.onmessage = (evt) => {
      try {
        const data = JSON.parse(evt.data);
        if (data.type === 'intercepted' && data.request) {
          setIntercepts((prev) => [{ ...data.request, ts: new Date().toISOString() }, ...prev].slice(0, 200));
        } else if (data.type === 'ws_message' && data.message) {
          setWsFrames((prev) => [{ ...data.message, ts: data.timestamp }, ...prev].slice(0, 200));
        }
      } catch {}
    };

    // Logger WS
    {
      const token = localStorage.getItem('access_token');
      loggerWs.current = new WebSocket(wsUrl(`/api/v1/dast/projects/ws/${projectId}/logger?token=${token || ''}`));
    }
    loggerWs.current.onmessage = (evt) => {
      try {
        const data = JSON.parse(evt.data);
        if (data.type === 'log' && data.entry) {
          setLogEntries((prev) => [data.entry, ...prev].slice(0, 500));
        }
      } catch {}
    };

    return () => {
      dashboardWs.current?.close();
      proxyWs.current?.close();
      loggerWs.current?.close();
    };
  }, [projectId]);

  // Actions
  const handleAddTarget = async () => {
    if (!newTarget) return;
    await dastProjectToolsService.addTarget(projectId, { url: newTarget } as any);
    setNewTarget('');
    const map = await dastProjectToolsService.getSiteMap(projectId);
    setSiteMap((map as any)?.nodes || []);
  };

  const handleUpdateScope = async () => {
    await dastProjectToolsService.updateScope(projectId, scopeRules);
  };

  const handleToggleIntercept = async () => {
    const res = await dastProjectToolsService.toggleIntercept(projectId, !interceptEnabled);
    setInterceptEnabled(Boolean((res as any)?.intercept_enabled));
  };

  const handleSaveProxySettings = async () => {
    await dastProjectToolsService.updateProxySettings(projectId, proxySettings);
  };

  const handleIntruderStart = async () => {
    const parsedPayloads = (payloadsText || '')
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    const res = await dastProjectToolsService.intruderStart(projectId, { ...attackConfig, payloads: parsedPayloads });
    setAttackId((res as any)?.attack_id || '');
    setAttackStatus({ status: 'started' });
  };

  const handleIntruderPoll = async () => {
    if (!attackId) return;
    const res = await dastProjectToolsService.intruderStatus(projectId, attackId);
    setAttackStatus(res as any);
    if ((res as any)?.status === 'running') return;
    const out = await dastProjectToolsService.intruderResults(projectId, attackId);
    setAttackResults((out as any)?.results || []);
  };

  const handleIntruderStop = async () => {
    if (!attackId) return;
    await dastProjectToolsService.intruderStop(projectId, attackId);
    setAttackStatus({ status: 'stopped' });
  };

  const handleRepeaterSend = async () => {
    try {
      const headers = repHeaders ? JSON.parse(repHeaders) : {};
      const res = await dastProjectToolsService.repeaterSend(projectId, {
        method: repMethod,
        url: repUrl,
        headers,
        body: repBody,
      } as any);
      setRepResponse((res as any)?.response || res);
      const hist = await dastProjectToolsService.repeaterHistory(projectId);
      setRepHistory((hist as any)?.sessions || []);
    } catch (e) {
      setRepResponse({ error: 'Invalid headers JSON or request failed' });
    }
  };

  const handleSequencerStart = async () => {
    const res = await dastProjectToolsService.sequencerStart(projectId, { token_source: 'header:Authorization' } as any);
    setSequenceId((res as any)?.sequence_id || '');
  };

  const handleSequencerResults = async () => {
    if (!sequenceId) return;
    const res = await dastProjectToolsService.sequencerResults(projectId, sequenceId);
    setSequenceResults(res);
  };

  const handleDecoderRun = async () => {
    const res = await dastProjectToolsService.decoderTransform(projectId, { mode: decMode, text: decInput } as any);
    setDecOutput((res as any)?.output || '');
  };

  const handleComparerRun = async () => {
    const res = await dastProjectToolsService.comparerCompare(projectId, { left: cmpLeft, right: cmpRight, mode: cmpMode });
    setCmpResult(res);
  };

  const handleExtenderInstall = async () => {
    if (!installName) return;
    await dastProjectToolsService.extenderInstall(projectId, { name: installName } as any);
    const ext = await dastProjectToolsService.extenderList(projectId);
    setExtensions((ext as any)?.installed || []);
    setInstallName('');
  };

  const handleExtenderRemove = async (nameOrId: string) => {
    await dastProjectToolsService.extenderRemove(projectId, nameOrId);
    const ext = await dastProjectToolsService.extenderList(projectId);
    setExtensions((ext as any)?.installed || []);
  };

  const handleScannerStart = async () => {
    const res = await dastProjectToolsService.scannerStart(projectId, scanConfig);
    setScanId((res as any)?.scan_id || '');
  };

  const handleScannerPoll = async () => {
    if (!scanId) return;
    const st = await dastProjectToolsService.scannerStatus(projectId, scanId);
    setScanStatus(st as any);
    const issues = await dastProjectToolsService.scannerIssues(projectId);
    setScanIssues((issues as any)?.issues || []);
  };

  const handleScannerStop = async () => {
    if (!scanId) return;
    await dastProjectToolsService.scannerStop(projectId, scanId);
    setScanStatus({ status: 'stopped' });
  };

  const handleLoggerSearch = async () => {
    const params: any = { q: logQuery, page: logPage, page_size: logPageSize };
    if (logOnlyBookmarked) params.q = `${params.q || ''} is:bookmarked`.trim();
    if (logMethod) params.method = logMethod;
    if (logStatus && !isNaN(parseInt(logStatus))) params.status = parseInt(logStatus, 10);
    if (logHost) params.host = logHost;
    if (logMime) params.mime = logMime;
    const res = await dastProjectToolsService.loggerEntries(projectId, params);
    setLogEntries((res as any)?.entries || []);
    setLogTotal((res as any)?.total || 0);
  };

  const handleSettingsSave = async () => {
    try {
      const parsed = JSON.parse(settingsDraft || '{}');
      await dastProjectToolsService.updateSettings(projectId, parsed);
      setSettings(parsed);
    } catch {
      // ignore parsing error
    }
  };

  const content = useMemo(() => {
    switch (active) {
      case 'dashboard':
        return (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="lg:col-span-2 space-y-4">
              <div className="bg-white rounded-md border p-4">
                <div className="font-semibold mb-2">Active Tasks</div>
                <pre className="text-sm overflow-auto">{JSON.stringify(activity?.active_tasks || [], null, 2)}</pre>
              </div>
              <div className="bg-white rounded-md border p-4">
                <div className="font-semibold mb-2">Completed Tasks</div>
                <pre className="text-sm overflow-auto">{JSON.stringify(activity?.completed_tasks || [], null, 2)}</pre>
              </div>
            </div>
            <div className="space-y-4">
              <div className="bg-white rounded-md border p-4">
                <div className="font-semibold mb-2">Vulnerabilities</div>
                <pre className="text-sm">{JSON.stringify(issues || {}, null, 2)}</pre>
              </div>
              <div className="bg-white rounded-md border p-4 max-h-72 overflow-auto">
                <div className="font-semibold mb-2">Event Log</div>
                <ul className="text-sm space-y-2">
                  {events.map((ev) => (
                    <li key={ev.id || ev.timestamp} className="text-gray-700">
                      <span className="text-gray-500 mr-2">{ev.timestamp}</span>
                      {ev.message}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        );
      case 'target':
        return (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="bg-white rounded-md border p-4 lg:col-span-2">
              <div className="font-semibold mb-2">Site Map</div>
              <div className="text-xs text-gray-500 mb-2">Click a row to toggle expand. Use the switch to set in-scope.</div>
              <div className="flex items-center gap-2 mb-3">
                <input className="border rounded px-2 py-1 flex-1" placeholder="Filter by label..." value={siteFilter} onChange={(e) => setSiteFilter(e.target.value)} />
                <button className="px-3 py-1.5 bg-green-600 text-white rounded" onClick={async () => {
                  const ids = Object.keys(siteSelected).filter(id => siteSelected[id]);
                  if (ids.length === 0) return;
                  await dastProjectToolsService.bulkUpdateNodeScope(projectId, ids, true);
                  const map = await dastProjectToolsService.getSiteMap(projectId);
                  setSiteMap((map as any)?.nodes || []);
                  setSiteSelected({});
                }}>Set In-Scope</button>
                <button className="px-3 py-1.5 bg-gray-700 text-white rounded" onClick={async () => {
                  const ids = Object.keys(siteSelected).filter(id => siteSelected[id]);
                  if (ids.length === 0) return;
                  await dastProjectToolsService.bulkUpdateNodeScope(projectId, ids, false);
                  const map = await dastProjectToolsService.getSiteMap(projectId);
                  setSiteMap((map as any)?.nodes || []);
                  setSiteSelected({});
                }}>Set Out-of-Scope</button>
              </div>
              <div className="overflow-x-auto">
                <table className="min-w-full text-sm">
                  <thead>
                    <tr className="text-left text-gray-500">
                      <th className="py-2 pr-4"><input type="checkbox" onChange={(e) => {
                        const checked = e.target.checked; const all: Record<string, boolean> = {};
                        filterTree(buildTargetTree(siteMap), siteFilter).forEach((n: any) => all[n.id] = checked);
                        setSiteSelected(all);
                      }} /></th>
                      <th className="py-2 pr-4">Scope</th>
                      <th className="py-2 pr-4">Node</th>
                      <th className="py-2 pr-4">Type</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filterTree(buildTargetTree(siteMap), siteFilter).map((node: any) => renderTargetRow(node, 0))}
                  </tbody>
                </table>
              </div>
            </div>
            <div className="space-y-4">
              <div className="bg-white rounded-md border p-4">
                <div className="font-semibold mb-2">Add Target</div>
                <div className="flex gap-2">
                  <input className="border rounded px-2 py-1 flex-1" placeholder="https://target.example.com" value={newTarget} onChange={(e) => setNewTarget(e.target.value)} />
                  <button className="px-3 py-1.5 bg-blue-600 text-white rounded" onClick={handleAddTarget}>Add</button>
                </div>
              </div>
              <div className="bg-white rounded-md border p-4">
                <div className="font-semibold mb-2">Scope Settings</div>
                <textarea className="w-full border rounded p-2 text-sm" rows={8} value={JSON.stringify(scopeRules, null, 2)} onChange={(e) => {
                  try { setScopeRules(JSON.parse(e.target.value)); } catch { /* ignore */ }
                }} />
                <div className="mt-2 text-right">
                  <button className="px-3 py-1.5 bg-green-600 text-white rounded" onClick={handleUpdateScope}>Save</button>
                </div>
              </div>
            </div>
          </div>
        );
      case 'members':
        return (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="bg-white rounded-md border p-4 lg:col-span-2">
              <div className="font-semibold mb-2">Project Members</div>
              <div className="overflow-x-auto">
                <table className="min-w-full text-sm">
                  <thead>
                    <tr className="text-left text-gray-500">
                      <th className="py-2 pr-4">User ID</th>
                      <th className="py-2 pr-4">Role</th>
                      <th className="py-2 pr-4">Added</th>
                      <th className="py-2 pr-4"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {(members || []).map((m: any, idx: number) => (
                      <tr key={`${m.user_id}-${idx}`} className="border-t">
                        <td className="py-2 pr-4">{m.user_id}</td>
                        <td className="py-2 pr-4">
                          <div className="flex items-center gap-2">
                            <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${m.role === 'owner' ? 'bg-purple-100 text-purple-800' : m.role === 'analyst' ? 'bg-blue-100 text-blue-800' : 'bg-gray-100 text-gray-800'}`}>{m.role}</span>
                            <select className="border rounded px-1 py-0.5 text-xs" value={m.role}
                              onChange={async (e) => {
                                const newRole = e.target.value;
                                try {
                                  await dastProjectToolsService.updateMemberRole(projectId, Number(m.user_id), newRole);
                                  const res = await dastProjectToolsService.listMembers(projectId);
                                  setMembers((res as any)?.members || []);
                                } catch {}
                              }}>
                              <option value="member">member</option>
                              <option value="analyst">analyst</option>
                              <option value="owner">owner</option>
                            </select>
                          </div>
                        </td>
                        <td className="py-2 pr-4">{m.created_at || '-'}</td>
                        <td className="py-2 pr-4 text-right">
                          <button className="px-2 py-1 text-xs bg-red-600 text-white rounded" onClick={async () => {
                            const ok = window.confirm('Remove this member?');
                            if (!ok) return;
                            await dastProjectToolsService.removeMember(projectId, Number(m.user_id));
                            const res = await dastProjectToolsService.listMembers(projectId);
                            setMembers((res as any)?.members || []);
                          }}>Remove</button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
            <div className="bg-white rounded-md border p-4">
              <div className="font-semibold mb-2">Add Member</div>
              <div className="space-y-2">
                <input className="border rounded px-2 py-1 w-full" placeholder="User ID" value={newMemberUserId} onChange={(e) => setNewMemberUserId(e.target.value)} />
                <select className="border rounded px-2 py-1 w-full" value={newMemberRole} onChange={(e) => setNewMemberRole(e.target.value)}>
                  <option value="member">member</option>
                  <option value="analyst">analyst</option>
                  <option value="owner">owner</option>
                </select>
                <button className="px-3 py-1.5 bg-blue-600 text-white rounded" onClick={async () => {
                  if (!newMemberUserId) return;
                  await dastProjectToolsService.addMember(projectId, { user_id: Number(newMemberUserId), role: newMemberRole });
                  const res = await dastProjectToolsService.listMembers(projectId);
                  setMembers((res as any)?.members || []);
                  setNewMemberUserId('');
                  setNewMemberRole('member');
                }}>Add</button>
              </div>
            </div>
          </div>
        );
      case 'proxy':
        return (
          <div className="space-y-4">
            <div className="bg-white rounded-md border p-4 flex items-center gap-3">
              <button className={`px-3 py-1.5 rounded text-white ${interceptEnabled ? 'bg-red-600' : 'bg-blue-600'}`} onClick={handleToggleIntercept}>
                {interceptEnabled ? 'Disable Intercept' : 'Enable Intercept'}
              </button>
              <div className="text-sm text-gray-600">Live Intercepts: {intercepts.length}</div>
            </div>
            <div className="bg-white rounded-md border p-4">
              <div className="font-semibold mb-3">HTTP History</div>
              <DASTProxyHistory
                projectId={projectId}
                onSendToRepeater={(e) => setSelectedProxyEntry(e)}
              />
            </div>
            <div className="bg-white rounded-md border p-4">
              <div className="font-semibold mb-2">WebSocket Messages</div>
              <div className="grid grid-cols-1 md:grid-cols-4 gap-2 mb-2 text-sm">
                <div className="flex items-center gap-2">
                  <span>Limit</span>
                  <select className="border rounded px-2 py-1" value={wsFramesLimit} onChange={(e) => setWsFramesLimit(parseInt(e.target.value, 10))}>
                    {[50, 100, 200, 500].map(n => <option key={n} value={n}>{n}</option>)}
                  </select>
                </div>
                <div className="flex items-center gap-2">
                  <span>Opcode</span>
                  <select className="border rounded px-2 py-1" value={wsFramesOpcode} onChange={(e) => setWsFramesOpcode(e.target.value)}>
                    <option value="all">All</option>
                    <option value="text">Text</option>
                    <option value="binary">Binary</option>
                  </select>
                </div>
                <input className="border rounded px-2 py-1 w-full" placeholder="Search text" value={wsFramesSearch} onChange={(e) => setWsFramesSearch(e.target.value)} />
                <div className="flex items-center gap-2">
                  <button className="px-2 py-1 border rounded" onClick={refreshWsFrames}>Refresh</button>
                </div>
              </div>
              <div className="overflow-x-auto">
                <table className="min-w-full text-sm">
                  <thead>
                    <tr className="text-left text-gray-500">
                      <th className="py-2 pr-4">Dir</th>
                      <th className="py-2 pr-4">Opcode</th>
                      <th className="py-2 pr-4">Preview</th>
                      <th className="py-2 pr-4">Time</th>
                      <th className="py-2 pr-4"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {wsFrames.filter((f) => {
                      if (wsFramesOpcode !== 'all') {
                        const isText = !!f.text && !f.payload_base64;
                        const isBin = !!f.payload_base64 && !f.text;
                        if (wsFramesOpcode === 'text' && !isText) return false;
                        if (wsFramesOpcode === 'binary' && !isBin) return false;
                      }
                      if (wsFramesSearch) {
                        const t = (f.text || '').toLowerCase();
                        if (!t.includes(wsFramesSearch.toLowerCase())) return false;
                      }
                      return true;
                    }).map((f, idx) => (
                      <tr key={f.id || idx} className={`border-t align-top ${f.pinned ? 'bg-yellow-50' : ''}`}>
                        <td className="py-2 pr-4">{f.direction}</td>
                        <td className="py-2 pr-4">{f.opcode}</td>
                        <td className="py-2 pr-4">
                          {typeof f.text === 'string' ? (
                            <pre className="max-w-xl truncate" title={f.text}>{f.text}</pre>
                          ) : f.payload_base64 ? (
                            <pre className="max-w-xl overflow-auto" title="binary">
                              {base64ToHexDump(f.payload_base64)}
                            </pre>
                          ) : null}
                          {f.note && <div className="text-xs text-gray-600 mt-1">Note: {f.note}</div>}
                        </td>
                        <td className="py-2 pr-4">{f.created_at || f.ts}</td>
                        <td className="py-2 pr-4 text-right">
                          <div className="flex items-center gap-2">
                            <button className="px-2 py-1 text-xs border rounded" onClick={async () => {
                              try {
                                const nextPinned = !f.pinned;
                                await dastProjectToolsService.pinWSFrame(projectId, f.id, nextPinned);
                                setWsFrames(prev => prev.map(x => x.id === f.id ? { ...x, pinned: nextPinned } : x));
                              } catch {}
                            }}>{f.pinned ? 'Unpin' : 'Pin'}</button>
                            <button className="px-2 py-1 text-xs border rounded" onClick={async () => {
                              const note = window.prompt('Add note for this frame', f.note || '') || '';
                              try {
                                await dastProjectToolsService.noteWSFrame(projectId, f.id, note);
                                setWsFrames(prev => prev.map(x => x.id === f.id ? { ...x, note } : x));
                              } catch {}
                            }}>Note</button>
                            <button className="px-2 py-1 text-xs border rounded" onClick={async () => {
                              let meta: any = null;
                              if (f.entry_id) {
                                try {
                                  meta = await dastProjectToolsService.getHttpHistoryEntry(projectId, f.entry_id);
                                } catch {}
                              }
                              setWsFrameModal({ open: true, frame: f, view: 'raw', meta });
                            }}>Expand</button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
            {wsFrameModal.open && wsFrameModal.frame && (
              <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
                <div className="bg-white rounded-md border w-[90vw] max-w-4xl max-h-[85vh] overflow-hidden flex flex-col">
                  <div className="p-3 border-b flex items-center justify-between">
                    <div className="font-semibold">WebSocket Frame</div>
                    <button className="text-sm" onClick={() => setWsFrameModal({ open: false, frame: null, view: 'raw' })}>Close</button>
                  </div>
                  <div className="p-3 grid grid-cols-1 md:grid-cols-3 gap-3 text-sm">
                    <div>
                      <div className="text-gray-600">Direction</div>
                      <div className="font-mono">{wsFrameModal.frame.direction}</div>
                    </div>
                    <div>
                      <div className="text-gray-600">Opcode</div>
                      <div className="font-mono">{wsFrameModal.frame.opcode}</div>
                    </div>
                    <div>
                      <div className="text-gray-600">Time</div>
                      <div className="font-mono">{wsFrameModal.frame.created_at || wsFrameModal.frame.ts}</div>
                    </div>
                    <div className="md:col-span-3">
                      <div className="text-gray-600">Linked HTTP Entry</div>
                      {wsFrameModal.frame.entry_id ? (
                        <div className="flex items-center gap-2">
                          <code className="px-2 py-0.5 bg-gray-100 rounded text-xs">{wsFrameModal.frame.entry_id}</code>
                          <button className="px-2 py-1 text-xs border rounded" onClick={() => {
                            // open Proxy tab and select this entry in history UI if possible
                            setActive('proxy');
                            setSelectedProxyEntry({ id: wsFrameModal.frame.entry_id });
                          }}>Open in HTTP History</button>
                        </div>
                      ) : (
                        <div className="text-gray-500">None</div>
                      )}
                    </div>
                    {wsFrameModal.frame.note && (
                      <div className="md:col-span-3">
                        <div className="text-gray-600">Note</div>
                        <div className="text-sm">{wsFrameModal.frame.note}</div>
                      </div>
                    )}
                  </div>
                  <div className="px-3 pb-3">
                    <div className="flex items-center gap-2 mb-2">
                      <button className={`px-2 py-1 text-xs border rounded ${wsFrameModal.view === 'raw' ? 'bg-gray-200' : ''}`} onClick={() => setWsFrameModal(m => ({ ...m, view: 'raw' }))}>Raw</button>
                      <button className={`px-2 py-1 text-xs border rounded ${wsFrameModal.view === 'hex' ? 'bg-gray-200' : ''}`} onClick={() => setWsFrameModal(m => ({ ...m, view: 'hex' }))}>Hex</button>
                    </div>
                    <div className="border rounded p-2 max-h-[45vh] overflow-auto text-xs">
                      {wsFrameModal.view === 'raw' ? (
                        wsFrameModal.frame.text ? (
                          <pre className="whitespace-pre-wrap">{wsFrameModal.frame.text}</pre>
                        ) : wsFrameModal.frame.payload_base64 ? (
                          <pre className="whitespace-pre-wrap">(binary)</pre>
                        ) : null
                      ) : (
                        <pre className="whitespace-pre">{wsFrameModal.frame.payload_base64 ? base64ToHexDump(wsFrameModal.frame.payload_base64) : stringToHexDump(wsFrameModal.frame.text || '')}</pre>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )}
            {selectedProxyEntry && (
              <ProxyEntryDetail
                projectId={projectId}
                entry={selectedProxyEntry}
                onClose={() => setSelectedProxyEntry(null)}
                onAfterAction={async () => {
                  try {
                    const q = await dastProjectToolsService.listIntercepts(projectId);
                    setInterceptQueue(((q as any)?.intercepts) || []);
                    setInterceptIndex((idx) => Math.min(idx, Math.max(0, (((q as any)?.intercepts) || []).length - 1)));
                  } catch {}
                }}
              />
            )}
            <div className="bg-white rounded-md border p-4">
              <div className="font-semibold mb-2">Proxy Options</div>
              <div className="space-y-3">
                <div>
                  <div className="font-medium text-sm mb-1">Listeners</div>
                  <div className="space-y-2">
                    {(proxySettings.listeners || []).map((l: any, idx: number) => (
                      <div key={idx} className="flex items-center gap-2">
                        <input className="border rounded px-2 py-1 w-28" placeholder="Host" value={l.host || ''} onChange={(e) => {
                          const next = { ...proxySettings }; next.listeners = [...(next.listeners || [])]; next.listeners[idx] = { ...next.listeners[idx], host: e.target.value }; setProxySettings(next);
                        }} />
                        <input className="border rounded px-2 py-1 w-24" placeholder="Port" type="number" value={l.port || ''} onChange={(e) => {
                          const next = { ...proxySettings }; next.listeners = [...(next.listeners || [])]; next.listeners[idx] = { ...next.listeners[idx], port: Number(e.target.value) }; setProxySettings(next);
                        }} />
                        <label className="text-xs text-gray-700 inline-flex items-center gap-1">
                          <input type="checkbox" checked={!!l.https} onChange={(e) => { const next = { ...proxySettings }; next.listeners = [...(next.listeners || [])]; next.listeners[idx] = { ...next.listeners[idx], https: e.target.checked }; setProxySettings(next); }} /> HTTPS
                        </label>
                        <button className="px-2 py-1 text-xs bg-red-600 text-white rounded ml-auto" onClick={() => {
                          const next = { ...proxySettings }; next.listeners = (next.listeners || []).filter((_: any, i: number) => i !== idx); setProxySettings(next);
                        }}>Remove</button>
                      </div>
                    ))}
                    <button className="px-2 py-1 text-xs bg-gray-200 rounded" onClick={() => setProxySettings((prev: any) => ({ ...prev, listeners: [...(prev.listeners || []), { host: '127.0.0.1', port: 8080, https: false }] }))}>Add Listener</button>
                  </div>
                </div>
                <div>
                  <div className="font-medium text-sm mb-1">Match & Replace</div>
                  <div className="space-y-2">
                    {(proxySettings.matchReplace || []).map((r: any, idx: number) => (
                      <div key={idx} className="grid grid-cols-1 md:grid-cols-4 gap-2 items-center">
                        <select className="border rounded px-2 py-1" value={r.scope || 'request-url'} onChange={(e) => {
                          const next = { ...proxySettings }; next.matchReplace = [...(next.matchReplace || [])]; next.matchReplace[idx] = { ...next.matchReplace[idx], scope: e.target.value }; setProxySettings(next);
                        }}>
                          <option value="request-url">Request URL</option>
                          <option value="request-header">Request Header</option>
                          <option value="request-body">Request Body</option>
                          <option value="response-header">Response Header</option>
                          <option value="response-body">Response Body</option>
                        </select>
                        <input className="border rounded px-2 py-1" placeholder="Match (regex)" value={r.match || ''} onChange={(e) => {
                          const next = { ...proxySettings }; next.matchReplace = [...(next.matchReplace || [])]; next.matchReplace[idx] = { ...next.matchReplace[idx], match: e.target.value }; setProxySettings(next);
                        }} />
                        <input className="border rounded px-2 py-1" placeholder="Replace" value={r.replace || ''} onChange={(e) => {
                          const next = { ...proxySettings }; next.matchReplace = [...(next.matchReplace || [])]; next.matchReplace[idx] = { ...next.matchReplace[idx], replace: e.target.value }; setProxySettings(next);
                        }} />
                        <div className="flex items-center gap-2">
                          <label className="text-xs text-gray-700 inline-flex items-center gap-1">
                            <input type="checkbox" checked={!!r.enabled} onChange={(e) => { const next = { ...proxySettings }; next.matchReplace = [...(next.matchReplace || [])]; next.matchReplace[idx] = { ...next.matchReplace[idx], enabled: e.target.checked }; setProxySettings(next); }} /> Enabled
                          </label>
                          <button className="px-2 py-1 text-xs bg-red-600 text-white rounded ml-auto" onClick={() => {
                            const next = { ...proxySettings }; next.matchReplace = (next.matchReplace || []).filter((_: any, i: number) => i !== idx); setProxySettings(next);
                          }}>Remove</button>
                        </div>
                      </div>
                    ))}
                    <button className="px-2 py-1 text-xs bg-gray-200 rounded" onClick={() => setProxySettings((prev: any) => ({ ...prev, matchReplace: [...(prev.matchReplace || []), { scope: 'request-url', match: '', replace: '', enabled: true }] }))}>Add Rule</button>
                  </div>
                </div>
              </div>
              <div className="mt-3 text-right">
                <button className="px-3 py-1.5 bg-green-600 text-white rounded" onClick={handleSaveProxySettings}>Save</button>
              </div>
            </div>
            <div className="bg-white rounded-md border p-4">
              <CAConfigForm projectId={projectId} />
            </div>
            <div className="bg-white rounded-md border p-4">
              <DASTInterceptQueue projectId={projectId} />
            </div>
          </div>
        );
      case 'intruder':
        return (
          <div className="space-y-4">
            <div className="bg-white rounded-md border p-4">
              <div className="font-semibold mb-2">Target & Positions</div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <input className="border rounded px-2 py-1" placeholder="Host" value={attackConfig.host} onChange={(e) => setAttackConfig({ ...attackConfig, host: e.target.value })} />
                <input className="border rounded px-2 py-1" placeholder="Port" type="number" value={attackConfig.port} onChange={(e) => setAttackConfig({ ...attackConfig, port: Number(e.target.value) })} />
              </div>
              <div className="flex items-center gap-2 mt-2">
                <button className="px-2 py-1 text-xs bg-gray-200 rounded" onClick={() => {
                  if (!attackRequestRef.current) return;
                  const el = attackRequestRef.current;
                  const start = el.selectionStart || 0; const end = el.selectionEnd || 0;
                  const v = attackConfig.request || '';
                  const next = v.slice(0, start) + '§' + v.slice(start, end) + '§' + v.slice(end);
                  setAttackConfig({ ...attackConfig, request: next });
                  setTimeout(() => { try { el.focus(); el.selectionStart = start + 1; el.selectionEnd = end + 1; } catch {} }, 0);
                }}>Wrap selection with §</button>
                <div className="text-xs text-gray-600">Use § to mark positions</div>
              </div>
              <textarea ref={attackRequestRef} className="w-full border rounded p-2 text-sm mt-2" rows={8} placeholder={'Raw HTTP request with § markers'} value={attackConfig.request} onChange={(e) => setAttackConfig({ ...attackConfig, request: e.target.value })} />
              <div className="mt-2 flex gap-2">
                <button className="px-3 py-1.5 bg-blue-600 text-white rounded" onClick={handleIntruderStart}>Start Attack</button>
                <button className="px-3 py-1.5 bg-gray-600 text-white rounded" onClick={handleIntruderPoll}>Poll Status</button>
                <button className="px-3 py-1.5 bg-red-600 text-white rounded" onClick={handleIntruderStop}>Stop</button>
              </div>
              <div className="mt-3 text-sm text-gray-700">Attack ID: {attackId || '-'}</div>
              <pre className="text-sm mt-2">{JSON.stringify(attackStatus || {}, null, 2)}</pre>
            </div>
            <div className="bg-white rounded-md border p-4">
              <div className="font-semibold mb-2">Payloads</div>
              <div className="text-xs text-gray-600 mb-2">One payload per line</div>
              <textarea className="w-full border rounded p-2 text-sm" rows={8} placeholder={'admin\npassword\n…'} value={payloadsText} onChange={(e) => setPayloadsText(e.target.value)} />
            </div>
            <div className="bg-white rounded-md border p-4">
              <div className="font-semibold mb-2">Results</div>
              <pre className="text-sm overflow-auto">{JSON.stringify(attackResults || [], null, 2)}</pre>
            </div>
          </div>
        );
      case 'repeater':
        return (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="space-y-3 bg-white rounded-md border p-4">
              <div className="font-semibold mb-2">Request</div>
              <div className="flex gap-2">
                <select className="border rounded px-2 py-1" value={repMethod} onChange={(e) => setRepMethod(e.target.value)}>
                  {['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'].map(m => <option key={m} value={m}>{m}</option>)}
                </select>
                <input className="border rounded px-2 py-1 flex-1" placeholder="https://example.com/path" value={repUrl} onChange={(e) => setRepUrl(e.target.value)} />
                <button className="px-3 py-1.5 bg-blue-600 text-white rounded" onClick={handleRepeaterSend}>Send</button>
              </div>
              <div>
                <div className="text-sm text-gray-600 mb-1">Headers (JSON)</div>
                <textarea className="w-full border rounded p-2 text-sm" rows={5} value={repHeaders} onChange={(e) => setRepHeaders(e.target.value)} />
              </div>
              <div>
                <div className="text-sm text-gray-600 mb-1">Body</div>
                <textarea className="w-full border rounded p-2 text-sm" rows={8} value={repBody} onChange={(e) => setRepBody(e.target.value)} />
              </div>
              <div className="text-xs text-gray-600">Response view: Raw | Pretty | Hex</div>
            </div>
            <div className="space-y-3">
              <div className="bg-white rounded-md border p-4">
                <div className="font-semibold mb-2">Response</div>
                <div className="flex items-center gap-2 mb-2 text-sm">
                  <button className={`px-2 py-1 border rounded ${repViewMode === 'raw' ? 'bg-gray-200' : ''}`} onClick={() => setRepViewMode('raw')}>Raw</button>
                  <button className={`px-2 py-1 border rounded ${repViewMode === 'pretty' ? 'bg-gray-200' : ''}`} onClick={() => setRepViewMode('pretty')}>Pretty</button>
                  <button className={`px-2 py-1 border rounded ${repViewMode === 'hex' ? 'bg-gray-200' : ''}`} onClick={() => setRepViewMode('hex')}>Hex</button>
                </div>
                <pre className="text-sm overflow-auto whitespace-pre-wrap">{renderRepResponse()}</pre>
              </div>
              <div className="bg-white rounded-md border p-4">
                <div className="font-semibold mb-2">History</div>
                <div className="overflow-x-auto">
                  <table className="min-w-full text-sm">
                    <thead>
                      <tr className="text-left text-gray-500">
                        <th className="py-2 pr-4">Method</th>
                        <th className="py-2 pr-4">URL</th>
                        <th className="py-2 pr-4">Status</th>
                        <th className="py-2 pr-4">Created</th>
                      </tr>
                    </thead>
                    <tbody>
                      {repHistory.map((r: any) => (
                        <tr key={r.id} className="border-t cursor-pointer hover:bg-gray-50" onClick={() => setRepSelected(r)}>
                          <td className="py-2 pr-4">{r.method}</td>
                          <td className="py-2 pr-4 max-w-xl truncate">{r.url}</td>
                          <td className="py-2 pr-4">{r.status}</td>
                          <td className="py-2 pr-4">{r.created_at}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
              {repSelected && (
                <div className="bg-white rounded-md border p-4">
                  <div className="flex items-center justify-between">
                    <div className="font-semibold mb-2">History Detail</div>
                    <button className="text-sm text-gray-600 hover:text-gray-900" onClick={() => setRepSelected(null)}>Close</button>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <div>
                      <div className="text-sm text-gray-600 mb-1">Selected</div>
                      <pre className="text-sm overflow-auto">{JSON.stringify(repSelected, null, 2)}</pre>
                    </div>
                    <div>
                      <div className="text-sm text-gray-600 mb-1">Baseline</div>
                      <pre className="text-sm overflow-auto">{JSON.stringify(repResponse || {}, null, 2)}</pre>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        );
      case 'sequencer':
        return (
          <div className="space-y-4">
            <div className="bg-white rounded-md border p-4">
              <div className="flex items-center gap-2">
                <button className="px-3 py-1.5 bg-blue-600 text-white rounded" onClick={handleSequencerStart}>Capture Token</button>
                <button className="px-3 py-1.5 bg-gray-600 text-white rounded" onClick={handleSequencerResults} disabled={!sequenceId}>Get Results</button>
                <div className="text-sm text-gray-600">Sequence ID: {sequenceId || '-'}</div>
              </div>
            </div>
            <div className="bg-white rounded-md border p-4">
              <div className="font-semibold mb-2">Analysis</div>
              <pre className="text-sm overflow-auto">{JSON.stringify(sequenceResults || {}, null, 2)}</pre>
            </div>
          </div>
        );
      case 'decoder':
        return (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="bg-white rounded-md border p-4 space-y-3">
              <div className="font-semibold mb-2">Input</div>
              <textarea className="w-full border rounded p-2 text-sm" rows={10} value={decInput} onChange={(e) => setDecInput(e.target.value)} />
              <div className="flex items-center gap-2">
                <select className="border rounded px-2 py-1" value={decMode} onChange={(e) => setDecMode(e.target.value as any)}>
                  <option value="encode">Encode (hex)</option>
                  <option value="decode">Decode (hex)</option>
                  <option value="hash">Hash (passthrough)</option>
                </select>
                <button className="px-3 py-1.5 bg-blue-600 text-white rounded" onClick={handleDecoderRun}>Run</button>
              </div>
            </div>
            <div className="bg-white rounded-md border p-4">
              <div className="font-semibold mb-2">Output</div>
              <pre className="text-sm overflow-auto">{decOutput}</pre>
            </div>
          </div>
        );
      case 'comparer':
        return (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="bg-white rounded-md border p-4">
              <div className="font-semibold mb-2">Left</div>
              <textarea className="w-full border rounded p-2 text-sm" rows={12} value={cmpLeft} onChange={(e) => setCmpLeft(e.target.value)} />
            </div>
            <div className="bg-white rounded-md border p-4">
              <div className="font-semibold mb-2">Right</div>
              <textarea className="w-full border rounded p-2 text-sm" rows={12} value={cmpRight} onChange={(e) => setCmpRight(e.target.value)} />
            </div>
            <div className="bg-white rounded-md border p-4 space-y-3">
              <div className="font-semibold mb-2">Options</div>
              <select className="border rounded px-2 py-1" value={cmpMode} onChange={(e) => setCmpMode(e.target.value as any)}>
                <option value="words">Words</option>
                <option value="bytes">Bytes</option>
              </select>
              <button className="px-3 py-1.5 bg-blue-600 text-white rounded" onClick={handleComparerRun}>Compare</button>
              <div>
                <div className="font-semibold mb-2">Differences</div>
                <pre className="text-sm overflow-auto">{JSON.stringify(cmpResult || {}, null, 2)}</pre>
              </div>
            </div>
          </div>
        );
      case 'extender':
        return (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="bg-white rounded-md border p-4 lg:col-span-2">
              <div className="font-semibold mb-2">Installed</div>
              <ul className="text-sm space-y-2">
                {extensions.map((ext) => (
                  <li key={ext.name} className="flex items-center justify-between border-b py-2">
                    <div>
                      <div className="font-medium">{ext.name}</div>
                      <div className="text-gray-500">{ext.author} • {ext.status}</div>
                    </div>
                    <button className="px-3 py-1.5 bg-red-600 text-white rounded" onClick={() => handleExtenderRemove(ext.name)}>Remove</button>
                  </li>
                ))}
              </ul>
            </div>
            <div className="bg-white rounded-md border p-4">
              <div className="font-semibold mb-2">Install from Store</div>
              <div className="flex gap-2">
                <input className="border rounded px-2 py-1 flex-1" placeholder="Extension name" value={installName} onChange={(e) => setInstallName(e.target.value)} />
                <button className="px-3 py-1.5 bg-blue-600 text-white rounded" onClick={handleExtenderInstall}>Install</button>
              </div>
            </div>
          </div>
        );
      case 'scanner':
        return (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="bg-white rounded-md border p-4">
              <div className="font-semibold mb-2">Configuration</div>
              <textarea className="w-full border rounded p-2 text-sm" rows={10} value={JSON.stringify(scanConfig, null, 2)} onChange={(e) => { try { setScanConfig(JSON.parse(e.target.value)); } catch {} }} />
              <div className="mt-2 flex gap-2">
                <button className="px-3 py-1.5 bg-blue-600 text-white rounded" onClick={handleScannerStart}>Start</button>
                <button className="px-3 py-1.5 bg-gray-600 text-white rounded" onClick={handleScannerPoll} disabled={!scanId}>Refresh</button>
                <button className="px-3 py-1.5 bg-red-600 text-white rounded" onClick={handleScannerStop} disabled={!scanId}>Stop</button>
              </div>
              <div className="mt-2 text-sm text-gray-700">Scan ID: {scanId || '-'}</div>
              <pre className="text-sm mt-2">{JSON.stringify(scanStatus || {}, null, 2)}</pre>
            </div>
            <div className="lg:col-span-2 space-y-4">
              <div className="bg-white rounded-md border p-4">
                <div className="flex items-center justify-between">
                  <div className="font-semibold mb-2">Live Log</div>
                  <div className="flex items-center gap-2">
                    <label className="text-xs text-gray-700 inline-flex items-center gap-1">
                      <input type="checkbox" checked={scannerFilter.info} onChange={(e) => setScannerFilter((f) => ({ ...f, info: e.target.checked }))} /> Info
                    </label>
                    <label className="text-xs text-gray-700 inline-flex items-center gap-1">
                      <input type="checkbox" checked={scannerFilter.warn} onChange={(e) => setScannerFilter((f) => ({ ...f, warn: e.target.checked }))} /> Warn
                    </label>
                    <label className="text-xs text-gray-700 inline-flex items-center gap-1">
                      <input type="checkbox" checked={scannerFilter.error} onChange={(e) => setScannerFilter((f) => ({ ...f, error: e.target.checked }))} /> Error
                    </label>
                    <button className={`px-2 py-1 text-xs rounded ${scannerPaused ? 'bg-blue-600 text-white' : 'bg-gray-200'}`} onClick={() => setScannerPaused((p) => !p)}>
                      {scannerPaused ? 'Resume' : 'Pause'}
                    </button>
                    <button className="px-2 py-1 text-xs bg-gray-200 rounded" onClick={() => setScannerLogs([])}>Clear</button>
                  </div>
                </div>
                <div className="max-h-64 overflow-auto text-sm">
                  <ul className="space-y-1">
                    {scannerLogs.map((l) => (
                      <li key={l.id} className="text-gray-800">
                        <span className="text-gray-500 mr-2">{l.timestamp}</span>
                        <span className={`mr-2 uppercase ${l.level === 'error' ? 'text-red-600' : l.level === 'warn' ? 'text-yellow-600' : 'text-green-700'}`}>{l.level || 'info'}</span>
                        {l.message}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
              <div className="bg-white rounded-md border p-4">
                <div className="font-semibold mb-2">Issues</div>
                <div className="overflow-x-auto">
                  <table className="min-w-full text-sm">
                    <thead>
                      <tr className="text-left text-gray-500">
                        <th className="py-2 pr-4">Severity</th>
                        <th className="py-2 pr-4">Description</th>
                        <th className="py-2 pr-4">Confidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scanIssues.map((i, idx) => (
                        <tr key={idx} className="border-t">
                          <td className="py-2 pr-4">{i.severity}</td>
                          <td className="py-2 pr-4">{i.description}</td>
                          <td className="py-2 pr-4">{i.confidence}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        );
      case 'logger':
        return (
          <div className="space-y-4">
            <div className="bg-white rounded-md border p-4 grid grid-cols-1 md:grid-cols-7 gap-2 items-center">
              <input className="border rounded px-2 py-1 w-full" placeholder="Search URL" value={logQuery} onChange={(e) => setLogQuery(e.target.value)} />
              <input className="border rounded px-2 py-1 w-full" placeholder="Method (e.g., GET)" value={logMethod} onChange={(e) => setLogMethod(e.target.value)} />
              <input className="border rounded px-2 py-1 w-full" placeholder="Status (e.g., 200)" value={logStatus} onChange={(e) => setLogStatus(e.target.value)} />
              <input className="border rounded px-2 py-1 w-full" placeholder="Host contains" value={logHost} onChange={(e) => setLogHost(e.target.value)} />
              <input className="border rounded px-2 py-1 w-full" placeholder="MIME contains" value={logMime} onChange={(e) => setLogMime(e.target.value)} />
              <label className="text-xs text-gray-700 inline-flex items-center gap-1"><input type="checkbox" checked={logOnlyBookmarked} onChange={(e) => setLogOnlyBookmarked(e.target.checked)} /> Bookmarked</label>
              <div className="flex items-center gap-2">
                <button className="px-3 py-1.5 bg-blue-600 text-white rounded" onClick={handleLoggerSearch}>Search</button>
                <button className="px-3 py-1.5 bg-gray-700 text-white rounded" onClick={handleLoggerExport}>Export HAR</button>
              </div>
              <div className="md:col-span-7 flex items-center gap-2 text-sm">
                <span>Page</span>
                <input type="number" className="border rounded px-2 py-1 w-20" value={logPage} onChange={(e) => setLogPage(Math.max(1, parseInt(e.target.value || '1', 10)))} />
                <span>Size</span>
                <select className="border rounded px-2 py-1" value={logPageSize} onChange={(e) => setLogPageSize(parseInt(e.target.value, 10))}>
                  {[50, 100, 200, 500].map(s => <option key={s} value={s}>{s}</option>)}
                </select>
                <span className="ml-auto text-gray-600">Total: {logTotal}</span>
              </div>
            </div>
            <div className="bg-white rounded-md border p-4">
              <div className="font-semibold mb-2">Logs</div>
              <div className="overflow-x-auto">
                <table className="min-w-full text-sm">
                  <thead>
                    <tr className="text-left text-gray-500">
                      <th className="py-2 pr-4">Method</th>
                      <th className="py-2 pr-4">URL</th>
                      <th className="py-2 pr-4">Status</th>
                      <th className="py-2 pr-4"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {logEntries.map((l: any, idx: number) => (
                      <tr key={idx} className={`border-t ${l.bookmarked ? 'bg-yellow-50' : ''} ${logSelected?.id === l.id ? 'bg-blue-50' : ''}`}
                          onClick={() => { setLogSelected(l); setLogDetail(null); loadLogDetail(l.id); }}>
                        <td className="py-2 pr-4">{l.method}</td>
                        <td className="py-2 pr-4 max-w-xl truncate" title={l.url}>{l.url}</td>
                        <td className="py-2 pr-4">{l.status}</td>
                        <td className="py-2 pr-4 text-right">
                          <div className="flex items-center gap-2">
                            <button className="px-2 py-1 text-xs border rounded" onClick={async () => {
                              try {
                                await dastProjectToolsService.loggerBookmark(projectId, l.id, !l.bookmarked);
                                setLogEntries(prev => prev.map((x: any, i: number) => i === idx ? { ...x, bookmarked: !l.bookmarked } : x));
                              } catch {}
                            }}>{l.bookmarked ? 'Unbookmark' : 'Bookmark'}</button>
                            <button className="px-2 py-1 text-xs border rounded" onClick={async () => {
                              const note = window.prompt('Add note for this entry', (l as any).note || '') || '';
                              try {
                                await dastProjectToolsService.loggerNote(projectId, l.id, note);
                              } catch {}
                            }}>Note</button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {logSelected && (
                <div className="mt-3 border-t pt-3">
                  <div className="flex items-center justify-between">
                    <div className="font-semibold">Entry Detail</div>
                    <div className="flex items-center gap-2">
                      <button className="px-2 py-1 text-xs border rounded" onClick={() => { const txt = toCurl(logDetail || logSelected); navigator.clipboard.writeText(txt); }}>Copy as cURL</button>
                      <button className="px-2 py-1 text-xs border rounded" onClick={() => {
                        const d = logDetail || logSelected || {};
                        const req = ((d.details || {}).request) || {};
                        setRepMethod(d.method || req.method || 'GET');
                        setRepUrl(d.url || req.url || '');
                        try { setRepHeaders(JSON.stringify(req.headers || {}, null, 2)); } catch { setRepHeaders('{}'); }
                        setRepBody(typeof req.body === 'string' ? req.body : (req.body ? JSON.stringify(req.body, null, 2) : ''));
                        setActive('repeater');
                      }}>Send to Repeater</button>
                      <button className="px-2 py-1 text-xs border rounded" onClick={async () => {
                        try {
                          const d = logDetail || logSelected || {};
                          const req = ((d.details || {}).request) || {};
                          const method = d.method || req.method || 'GET';
                          const url = d.url || req.url || '';
                          const headers = req.headers || {};
                          const body = typeof req.body === 'string' ? req.body : (req.body ? JSON.stringify(req.body) : undefined);
                          const res = await dastProjectToolsService.repeaterSend(projectId, { method, url, headers, body } as any);
                          setRepMethod(method);
                          setRepUrl(url);
                          try { setRepHeaders(JSON.stringify(headers || {}, null, 2)); } catch { setRepHeaders('{}'); }
                          setRepBody(body || '');
                          setRepResponse((res as any)?.response || res);
                          const hist = await dastProjectToolsService.repeaterHistory(projectId);
                          setRepHistory((hist as any)?.sessions || []);
                          setActive('repeater');
                        } catch {}
                      }}>Replay Now</button>
                      <button className="text-xs" onClick={() => { setLogSelected(null); setLogDetail(null); }}>Close</button>
                    </div>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-2 text-xs">
                    <div>
                      <div className="text-gray-600 mb-1">Summary</div>
                      <pre className="whitespace-pre-wrap">{JSON.stringify(logDetail ? { method: logDetail.method, url: logDetail.url, status: logDetail.status } : logSelected, null, 2)}</pre>
                    </div>
                    <div>
                      <div className="text-gray-600 mb-1">Details</div>
                      <pre className="whitespace-pre-wrap overflow-auto max-h-64">{JSON.stringify((logDetail || {}).details || {}, null, 2)}</pre>
                    </div>
                  </div>
                </div>
              )}
              <div className="mt-2 flex items-center justify-between text-sm">
                <div>Showing {logEntries.length} of {logTotal}</div>
                <div className="flex items-center gap-2">
                  <button className="px-2 py-1 border rounded" disabled={logPage <= 1} onClick={() => { setLogPage(p => Math.max(1, p - 1)); setTimeout(handleLoggerSearch, 0); }}>Prev</button>
                  <button className="px-2 py-1 border rounded" disabled={(logPage * logPageSize) >= logTotal} onClick={() => { setLogPage(p => p + 1); setTimeout(handleLoggerSearch, 0); }}>Next</button>
                </div>
              </div>
            </div>
          </div>
        );
      case 'settings':
        return (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="bg-white rounded-md border p-4">
              <div className="font-semibold mb-2">Current Settings</div>
              <pre className="text-sm overflow-auto">{JSON.stringify(settings || {}, null, 2)}</pre>
            </div>
            <div className="bg-white rounded-md border p-4">
              <div className="font-semibold mb-2">Edit</div>
              <div className="space-y-2">
                <div className="text-xs text-gray-600">Scope (regex supported). Example: include: ["^https?://example\\.com"], exclude: ["/admin"], ports: [80,443], filetypes: [".js",".css"]</div>
                <textarea className="w-full border rounded p-2 text-sm" rows={12} value={settingsDraft} onChange={(e) => setSettingsDraft(e.target.value)} />
                <div className="grid grid-cols-1 md:grid-cols-4 gap-2 text-sm">
                  <div>
                    <div className="font-medium mb-1">Include</div>
                    <textarea className="w-full border rounded p-2 text-xs h-24" placeholder="one regex per line" onChange={(e) => {
                      try {
                        const s = JSON.parse(settingsDraft || '{}');
                        s.project = s.project || {}; s.project.scope = s.project.scope || {};
                        s.project.scope.include = (e.target.value || '').split(/\r?\n/).filter(Boolean);
                        setSettingsDraft(JSON.stringify(s, null, 2));
                      } catch {}
                    }} />
                  </div>
                  <div>
                    <div className="font-medium mb-1">Exclude</div>
                    <textarea className="w-full border rounded p-2 text-xs h-24" placeholder="one regex per line" onChange={(e) => {
                      try {
                        const s = JSON.parse(settingsDraft || '{}');
                        s.project = s.project || {}; s.project.scope = s.project.scope || {};
                        s.project.scope.exclude = (e.target.value || '').split(/\r?\n/).filter(Boolean);
                        setSettingsDraft(JSON.stringify(s, null, 2));
                      } catch {}
                    }} />
                  </div>
                  <div>
                    <div className="font-medium mb-1">Ports</div>
                    <input className="w-full border rounded px-2 py-1 text-xs" placeholder="80,443" onChange={(e) => {
                      try {
                        const nums = (e.target.value || '').split(',').map(v => parseInt(v.trim(), 10)).filter(v => !isNaN(v));
                        const s = JSON.parse(settingsDraft || '{}');
                        s.project = s.project || {}; s.project.scope = s.project.scope || {};
                        s.project.scope.ports = nums;
                        setSettingsDraft(JSON.stringify(s, null, 2));
                      } catch {}
                    }} />
                  </div>
                  <div>
                    <div className="font-medium mb-1">Filetypes</div>
                    <input className="w-full border rounded px-2 py-1 text-xs" placeholder=".js,.css" onChange={(e) => {
                      try {
                        const list = (e.target.value || '').split(',').map(v => v.trim()).filter(Boolean);
                        const s = JSON.parse(settingsDraft || '{}');
                        s.project = s.project || {}; s.project.scope = s.project.scope || {};
                        s.project.scope.filetypes = list;
                        setSettingsDraft(JSON.stringify(s, null, 2));
                      } catch {}
                    }} />
                  </div>
                </div>
              </div>
              <div className="mt-2 text-right">
                <button className="px-3 py-1.5 bg-green-600 text-white rounded" onClick={handleSettingsSave}>Save</button>
              </div>
            </div>
          </div>
        );
      default:
        return null;
    }
  }, [active, activity, issues, events, siteMap, scopeRules, newTarget, interceptEnabled, httpHistory, proxySettings, intercepts, attackConfig, attackId, attackStatus, attackResults, repMethod, repUrl, repHeaders, repBody, repResponse, repHistory, sequenceId, sequenceResults, decInput, decMode, decOutput, cmpLeft, cmpRight, cmpMode, cmpResult, extensions, installName, scanConfig, scanId, scanStatus, scanIssues, logEntries, logQuery, settings, settingsDraft]);

  function renderTargetRow(node: any, depth: number): JSX.Element {
    const pad = { paddingLeft: `${depth * 16}px` } as React.CSSProperties;
    return (
      <React.Fragment key={node.id}>
        <tr className="border-t">
          <td className="py-2 pr-4"><input type="checkbox" checked={!!siteSelected[node.id]} onChange={(e) => setSiteSelected(prev => ({ ...prev, [node.id]: e.target.checked }))} /></td>
          <td className="py-2 pr-4">
            <label className="inline-flex items-center cursor-pointer">
              <input type="checkbox" className="sr-only peer" checked={!!node.in_scope} onChange={async (e) => {
                try {
                  await dastProjectToolsService.updateTargetNodeScope(projectId, node.id, e.target.checked);
                  const map = await dastProjectToolsService.getSiteMap(projectId);
                  setSiteMap((map as any)?.nodes || []);
                } catch {}
              }} />
              <span className="ml-2 text-gray-700">{node.in_scope ? 'In' : 'Out'}</span>
            </label>
          </td>
          <td className="py-2 pr-4" style={pad}>
            <button className="text-left w-full" onClick={() => setSiteExpanded(prev => ({ ...prev, [node.id]: !prev[node.id] }))}>
              <span className="text-gray-800">{renderHighlighted(node.label || '', siteFilter)}</span>
            </button>
            {siteExpanded[node.id] && node.metadata && (
              <div className="mt-2 text-xs text-gray-500">
                <pre>{JSON.stringify(node.metadata || {}, null, 2)}</pre>
              </div>
            )}
          </td>
          <td className="py-2 pr-4">{node.type}</td>
        </tr>
        {siteExpanded[node.id] && (node.children || []).map((child: any) => renderTargetRow(child, depth + 1))}
      </React.Fragment>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">DAST Project Tools</h1>
        <div className="text-sm text-gray-500">Project: {projectId}</div>
      </div>
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex flex-wrap gap-4">
          {tabs.map((t) => (
            <button
              key={t.id}
              onClick={() => setActive(t.id)}
              className={`py-2 px-1 border-b-2 text-sm ${active === t.id ? 'border-blue-500 text-blue-600' : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'}`}
            >
              {t.label}
            </button>
          ))}
        </nav>
      </div>
      {content}
    </div>
  );
};

export default DASTProjectTools;


