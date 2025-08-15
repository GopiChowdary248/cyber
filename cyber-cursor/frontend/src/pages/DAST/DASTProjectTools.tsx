import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useParams } from 'react-router-dom';
import { dastProjectToolsService } from '../../services/dastProjectToolsService';

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


function ProxyEntryDetail({ projectId, entry, onClose }: { projectId: string; entry: any; onClose: () => void }) {
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
                await fetch(`${process.env.REACT_APP_API_URL}/api/v1/dast/projects/${projectId}/proxy/intercept/forward`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${localStorage.getItem('access_token') || ''}` },
                  body: JSON.stringify({ entry_id: entry.id, request: { method, url, headers, body: bodyText } })
                });
                onClose();
              } catch {}
            }}>Forward</button>
            <button className="px-3 py-1.5 bg-red-600 text-white rounded" onClick={async () => { try { await dastProjectToolsService.proxyDrop(projectId, entry.id); onClose(); } catch {} }}>Drop</button>
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

  // Intruder
  const [attackConfig, setAttackConfig] = useState<any>({ host: '', port: 443, request: '', payloads: [] });
  const [attackId, setAttackId] = useState<string>('');
  const [attackStatus, setAttackStatus] = useState<any>(null);
  const [attackResults, setAttackResults] = useState<any[]>([]);

  // Repeater
  const [repMethod, setRepMethod] = useState<string>('GET');
  const [repUrl, setRepUrl] = useState<string>('');
  const [repHeaders, setRepHeaders] = useState<string>('{}');
  const [repBody, setRepBody] = useState<string>('');
  const [repResponse, setRepResponse] = useState<any>(null);
  const [repHistory, setRepHistory] = useState<any[]>([]);
  const [repSelected, setRepSelected] = useState<any | null>(null);

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

  // Logger
  const [logEntries, setLogEntries] = useState<any[]>([]);
  const [logQuery, setLogQuery] = useState<string>('');
  const handleLoggerExport = () => {
    const base = (process.env.REACT_APP_API_URL || '') + `/api/v1/dast/projects/${projectId}/logger/export?format=csv`;
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

  // Initial load
  useEffect(() => {
    const load = async () => {
      if (!projectId) return;
      const [a, i, e, map, hist, ext, logs] = await Promise.all([
        dastProjectToolsService.getDashboardActivity(projectId),
        dastProjectToolsService.getDashboardIssues(projectId),
        dastProjectToolsService.getDashboardEvents(projectId, { limit: 50 }),
        dastProjectToolsService.getSiteMap(projectId),
        dastProjectToolsService.getHttpHistory(projectId),
        dastProjectToolsService.extenderList(projectId),
        dastProjectToolsService.loggerEntries(projectId),
      ]);
      setActivity(a as any);
      setIssues(i as any);
      setEvents((e as any)?.events || []);
      setSiteMap((map as any)?.nodes || []);
      setHttpHistory((hist as any)?.entries || []);
      setExtensions((ext as any)?.installed || []);
      setLogEntries((logs as any)?.entries || []);
    };
    load();
  }, [projectId]);

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
    const res = await dastProjectToolsService.intruderStart(projectId, attackConfig);
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
    const res = await dastProjectToolsService.loggerEntries(projectId, { q: logQuery });
    setLogEntries((res as any)?.entries || []);
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
                          <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${m.role === 'owner' ? 'bg-purple-100 text-purple-800' : m.role === 'analyst' ? 'bg-blue-100 text-blue-800' : 'bg-gray-100 text-gray-800'}`}>{m.role}</span>
                        </td>
                        <td className="py-2 pr-4">{m.created_at || '-'}</td>
                        <td className="py-2 pr-4 text-right">
                          <button className="px-2 py-1 text-xs bg-red-600 text-white rounded" onClick={async () => {
                            if (!confirm('Remove this member?')) return;
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
              <div className="font-semibold mb-2">HTTP History</div>
              <div className="overflow-x-auto">
                <table className="min-w-full text-sm">
                  <thead>
                    <tr className="text-left text-gray-500">
                      <th className="py-2 pr-4">Method</th>
                      <th className="py-2 pr-4">URL</th>
                      <th className="py-2 pr-4">Status</th>
                      <th className="py-2 pr-4">Size</th>
                      <th className="py-2 pr-4">Time</th>
                    </tr>
                  </thead>
                  <tbody>
                    {httpHistory.map((h) => (
                      <tr key={h.id} className="border-t cursor-pointer hover:bg-gray-50" onClick={() => setSelectedProxyEntry(h)}>
                        <td className="py-2 pr-4">{h.method}</td>
                        <td className="py-2 pr-4 max-w-xl truncate">{h.url}</td>
                        <td className="py-2 pr-4">{h.status}</td>
                        <td className="py-2 pr-4">{h.size}</td>
                        <td className="py-2 pr-4">{h.time}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
            {selectedProxyEntry && (
              <ProxyEntryDetail projectId={projectId} entry={selectedProxyEntry} onClose={() => setSelectedProxyEntry(null)} />
            )}
            <div className="bg-white rounded-md border p-4">
              <div className="font-semibold mb-2">Proxy Options</div>
              <textarea className="w-full border rounded p-2 text-sm" rows={8} value={JSON.stringify(proxySettings, null, 2)} onChange={(e) => {
                try { setProxySettings(JSON.parse(e.target.value)); } catch {}
              }} />
              <div className="mt-2 text-right">
                <button className="px-3 py-1.5 bg-green-600 text-white rounded" onClick={handleSaveProxySettings}>Save</button>
              </div>
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
              <textarea className="w-full border rounded p-2 text-sm mt-2" rows={8} placeholder={'Raw HTTP request with § markers'} value={attackConfig.request} onChange={(e) => setAttackConfig({ ...attackConfig, request: e.target.value })} />
              <div className="mt-2 flex gap-2">
                <button className="px-3 py-1.5 bg-blue-600 text-white rounded" onClick={handleIntruderStart}>Start Attack</button>
                <button className="px-3 py-1.5 bg-gray-600 text-white rounded" onClick={handleIntruderPoll}>Poll Status</button>
                <button className="px-3 py-1.5 bg-red-600 text-white rounded" onClick={handleIntruderStop}>Stop</button>
              </div>
              <div className="mt-3 text-sm text-gray-700">Attack ID: {attackId || '-'}</div>
              <pre className="text-sm mt-2">{JSON.stringify(attackStatus || {}, null, 2)}</pre>
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
            </div>
            <div className="space-y-3">
              <div className="bg-white rounded-md border p-4">
                <div className="font-semibold mb-2">Response</div>
                <pre className="text-sm overflow-auto">{JSON.stringify(repResponse || {}, null, 2)}</pre>
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
                  <pre className="text-sm overflow-auto">{JSON.stringify(repSelected, null, 2)}</pre>
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
            <div className="bg-white rounded-md border p-4 lg:col-span-2">
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
        );
      case 'logger':
        return (
          <div className="space-y-4">
            <div className="bg-white rounded-md border p-4 flex items-center gap-2">
              <input className="border rounded px-2 py-1 flex-1" placeholder="Search URL, method, status" value={logQuery} onChange={(e) => setLogQuery(e.target.value)} />
              <button className="px-3 py-1.5 bg-blue-600 text-white rounded" onClick={handleLoggerSearch}>Search</button>
              <button className="px-3 py-1.5 bg-gray-700 text-white rounded" onClick={handleLoggerExport}>Export CSV</button>
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
                    </tr>
                  </thead>
                  <tbody>
                    {logEntries.map((l, idx) => (
                      <tr key={idx} className="border-t">
                        <td className="py-2 pr-4">{l.method}</td>
                        <td className="py-2 pr-4 max-w-xl truncate">{l.url}</td>
                        <td className="py-2 pr-4">{l.status}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
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
              <textarea className="w-full border rounded p-2 text-sm" rows={18} value={settingsDraft} onChange={(e) => setSettingsDraft(e.target.value)} />
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
              <span className="text-gray-800">{node.label}</span>
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


