import os
import sys
import tempfile
import subprocess
import textwrap
from typing import Dict, Optional, List
from datetime import datetime, timedelta
import json
import re


class ProxyEngineManager:
    """Manages mitmproxy subprocesses per project.

    This is a simple in-process manager. In production, prefer a supervisor or
    a persistent worker to avoid orphaned processes on app reload.
    """

    def __init__(self) -> None:
        self._proc_by_project: Dict[str, subprocess.Popen] = {}
        self._tokens_by_project: Dict[str, str] = {}

    def is_running(self, project_id: str) -> bool:
        proc = self._proc_by_project.get(project_id)
        return bool(proc and proc.poll() is None)

    def get_ingest_token(self, project_id: str) -> Optional[str]:
        return self._tokens_by_project.get(project_id)

    def start(self, *, project_id: str, api_base: str, ingest_token: str, listen_host: str = "127.0.0.1", listen_port: int = 8080, https: bool = False) -> None:
        if self.is_running(project_id):
            return
        
        self._tokens_by_project[project_id] = ingest_token
        
        mitm = os.environ.get("MITMPROXY_BIN", "mitmdump")
        addon_code = self._build_addon_code(api_base=api_base, ingest_token=ingest_token, project_id=project_id)
        addon_path = self._write_addon(addon_code)

        args = [mitm, "-s", addon_path, "--listen-host", listen_host, "--listen-port", str(listen_port)]
        # TLS interception is handled by mitmproxy's internal CA; wiring to project CA can be added here
        # If upstream proxy/DNS overrides are needed, append args accordingly
        env = os.environ.copy()
        # Reduce noise; ensure UTF-8
        env["PYTHONIOENCODING"] = "utf-8"
        
        # Hide console window on Windows
        if os.name == 'nt':
            proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
        
        self._proc_by_project[project_id] = proc

    def stop(self, *, project_id: str) -> None:
        proc = self._proc_by_project.get(project_id)
        if not proc:
            return
        try:
            proc.terminate()
        except Exception:
            pass
        self._proc_by_project.pop(project_id, None)
        self._tokens_by_project.pop(project_id, None)

    def _write_addon(self, code: str) -> str:
        fd, path = tempfile.mkstemp(prefix="cs_mitm_addon_", suffix=".py")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(code)
        return path

    def _build_addon_code(self, *, api_base: str, ingest_token: str, project_id: str) -> str:
        # Enhanced mitmproxy addon that posts flows and WS events back to API with match/replace support
        addon_code = f"""
            import json
            import threading
            import re
            from mitmproxy import http, websocket
            try:
                import requests
            except Exception:
                requests = None

            API_BASE = {json.dumps(api_base)}
            INGEST_TOKEN = {json.dumps(ingest_token)}
            PROJECT_ID = {json.dumps(project_id)}

            def _post(path: str, payload: dict):
                if not requests:
                    return
                try:
                    headers = {{'Content-Type': 'application/json', 'X-Ingest-Token': INGEST_TOKEN}}
                    requests.post(f"{{API_BASE}}{{path}}", headers=headers, data=json.dumps(payload), timeout=3)
                except Exception:
                    pass

            def _apply_match_replace_rules(data: dict, rules: list) -> dict:
                if not rules:
                    return data
                
                modified = data.copy()
                for rule in rules:
                    if not rule.get('enabled', True):
                        continue
                    
                    match_type = rule.get('match_type', '')
                    match_pattern = rule.get('match_pattern', '')
                    match_case_sensitive = rule.get('match_case_sensitive', False)
                    replace_type = rule.get('replace_type', '')
                    replace_pattern = rule.get('replace_pattern', '')
                    replace_value = rule.get('replace_value', '')
                    
                    if not match_pattern or not replace_type:
                        continue
                    
                    flags = 0 if match_case_sensitive else re.IGNORECASE
                    
                    if match_type == 'url' and 'url' in modified:
                        if re.search(match_pattern, modified['url'], flags=flags):
                            if replace_pattern:
                                modified['url'] = re.sub(replace_pattern, replace_value or '', modified['url'])
                            else:
                                modified['url'] = replace_value
                    
                    elif match_type == 'header' and 'headers' in modified:
                        headers = dict(modified['headers'])
                        for header_name, header_value in headers.items():
                            if re.search(match_pattern, f"{{header_name}}: {{header_value}}", flags=flags):
                                if replace_type == 'header':
                                    if replace_pattern:
                                        new_value = re.sub(replace_pattern, replace_value or '', header_value)
                                    else:
                                        new_value = replace_value
                                    if new_value is not None:
                                        headers[header_name] = new_value
                        modified['headers'] = headers
                    
                    elif match_type == 'body' and 'body' in modified:
                        body = modified['body']
                        if re.search(match_pattern, body, flags=flags):
                            if replace_pattern:
                                modified['body'] = re.sub(replace_pattern, replace_value or '', body)
                            else:
                                modified['body'] = replace_value
                
                return modified

            def request(flow: http.HTTPFlow):
                try:
                    req_data = {{
                        'method': flow.request.method,
                        'url': flow.request.pretty_url,
                        'headers': dict(flow.request.headers),
                        'body': flow.request.get_text() if flow.request.content else ''
                    }}
                    
                    basic_rules = [
                        {{'enabled': True, 'match_type': 'header', 'match_pattern': 'User-Agent', 'replace_type': 'header', 'replace_pattern': '', 'replace_value': 'CyberShield/1.0'}},
                        {{'enabled': True, 'match_type': 'url', 'match_pattern': r'\\b(admin|login|auth)\\b', 'replace_type': 'url', 'replace_pattern': '', 'replace_value': '{{flow.request.pretty_url}}'}}
                    ]
                    
                    modified_req = _apply_match_replace_rules(req_data, basic_rules)
                    
                    if modified_req['url'] != req_data['url']:
                        flow.request.url = modified_req['url']
                    if modified_req['headers'] != req_data['headers']:
                        flow.request.headers.clear()
                        for k, v in modified_req['headers'].items():
                            flow.request.headers[k] = v
                    if modified_req['body'] != req_data['body']:
                        flow.request.content = modified_req['body'].encode('utf-8')
                    
                except Exception:
                    pass

            def response(flow: http.HTTPFlow):
                try:
                    req = {{
                        'method': flow.request.method,
                        'url': flow.request.pretty_url,
                        'headers': dict(flow.request.headers),
                        'body': flow.request.get_text() if flow.request.content else ''
                    }}
                    resp = {{
                        'status': flow.response.status_code,
                        'headers': dict(flow.response.headers),
                        'body': flow.response.get_text() if flow.response.content else ''
                    }}
                    
                    response_rules = [
                        {{'enabled': True, 'match_type': 'response', 'match_pattern': r'<script[^>]*src=[^>]*>', 'replace_type': 'body', 'replace_pattern': '', 'replace_value': '<!-- Script blocked by CyberShield -->'}}
                    ]
                    
                    modified_resp = _apply_match_replace_rules(resp, response_rules)
                    
                    if modified_resp['body'] != resp['body']:
                        flow.response.content = modified_resp['body'].encode('utf-8')
                    
                    payload = {{'request': req, 'response': modified_resp, 'correlation_id': flow.id}}
                    threading.Thread(target=_post, args=(f"/api/v1/dast/projects/{{PROJECT_ID}}/proxy/ingest/flow", payload), daemon=True).start()
                    
                except Exception:
                    pass

            def websocket_message(flow: http.HTTPFlow):
                try:
                    if not flow.websocket.messages:
                        return
                    msg = flow.websocket.messages[-1]
                    direction = 'in' if msg.from_client is False else 'out'
                    item = {{'direction': direction, 'opcode': 1 if msg.is_text else 2}}
                    if msg.is_text:
                        item['text'] = msg.content if isinstance(msg.content, str) else msg.content.decode('utf-8', 'replace')
                    else:
                        import base64
                        raw = msg.content if isinstance(msg.content, (bytes, bytearray)) else bytes(msg.content)
                        item['payload_base64'] = base64.b64encode(raw).decode('ascii')
                    payload = {{'entry_correlation_id': flow.id, 'frame': item}}
                    threading.Thread(target=_post, args=(f"/api/v1/dast/projects/{{PROJECT_ID}}/proxy/ingest/ws", payload), daemon=True).start()
                except Exception:
                    pass


            """
        
        return textwrap.dedent(addon_code)


# Singleton manager
proxy_engine_manager = ProxyEngineManager()


