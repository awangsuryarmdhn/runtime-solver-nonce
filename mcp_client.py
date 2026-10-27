"""Minimal Streamable HTTP MCP client for the NONCE MCP endpoint.

- JSON-RPC over POST with Accept: application/json, text/event-stream.
- Captures and re-sends the Mcp-Session-Id header.
- Reads responses in streaming mode and returns after the first complete
  JSON-RPC object, so a server-held SSE stream cannot hang the call.
- Parses both plain-JSON and SSE (data:) responses.
- tools/call results are unwrapped from content[].text (JSON) and
  isError=True raises ToolError.
- 429 responses raise RateLimited (with retry_after when the server sends
  one). A 429 means the request was rejected before processing, so a
  later retry of the same call cannot duplicate an effect.
- No credentials are ever printed by this module. Callers must never log
  tokens, capabilities, or signatures.
"""
import json
import random
import time
import uuid

import requests


class MCPError(Exception):
    pass


class RateLimited(MCPError):
    def __init__(self, retry_after=None, body=""):
        super().__init__(f"HTTP 429: {body[:200]}")
        self.retry_after = retry_after
        self.body = body


class ToolError(MCPError):
    def __init__(self, message, raw=None):
        super().__init__(message)
        self.raw = raw


def _parse_rpc_payload(body_bytes):
    """Parse a Streamable HTTP response body into a JSON-RPC object."""
    text = body_bytes.decode("utf-8", errors="replace").strip()
    if not text:
        return None
    if "data:" in text:
        datas = []
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                datas.append(line[len("data:"):].strip())
        if datas:
            for raw in reversed(datas):
                try:
                    obj = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, dict) and ("result" in obj or "error" in obj):
                    return obj
            return json.loads(datas[-1])
    return json.loads(text)


class MCPClient:
    def __init__(self, endpoint, token=None, timeout=60):
        self.endpoint = endpoint
        self.token = token
        self.timeout = timeout
        self.session = requests.Session()
        self.session_id = None
        self._next_id = 1
        self._initialized = False

    def _headers(self):
        h = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.token:
            h["Authorization"] = "Bearer " + self.token
        if self.session_id:
            h["Mcp-Session-Id"] = self.session_id
        return h

    def _post(self, payload, timeout=None):
        """POST and return the first complete JSON-RPC object (or None)."""
        deadline = time.time() + (timeout or self.timeout)
        with self.session.post(
            self.endpoint,
            headers=self._headers(),
            data=json.dumps(payload),
            timeout=(timeout or self.timeout),
            stream=True,
        ) as resp:
            sid = resp.headers.get("Mcp-Session-Id") or resp.headers.get("mcp-session-id")
            if sid:
                self.session_id = sid
            if resp.status_code == 429:
                ra = resp.headers.get("Retry-After") or resp.headers.get("retry-after")
                try:
                    ra = float(ra) if ra is not None else None
                except ValueError:
                    ra = None
                body = resp.text[:300] if resp.content else ""
                raise RateLimited(retry_after=ra, body=body)
            if resp.status_code == 202 or resp.status_code == 204:
                return None
            if resp.status_code >= 400:
                raise MCPError(f"HTTP {resp.status_code}: {resp.text[:500]}")
            # Stream lines until one complete JSON-RPC object arrives.
            buf = []
            try:
                for raw_line in resp.iter_lines(decode_unicode=True):
                    if time.time() > deadline:
                        raise requests.exceptions.ReadTimeout(
                            "deadline waiting for JSON-RPC response"
                        )
                    if raw_line is None:
                        continue
                    line = raw_line.strip()
                    if not line:
                        continue
                    if line.startswith("data:"):
                        buf.append(line[len("data:"):].strip())
                        candidate = "\n".join(buf)
                        try:
                            obj = json.loads(candidate)
                        except json.JSONDecodeError:
                            continue
                        if isinstance(obj, dict) and ("result" in obj or "error" in obj):
                            return obj
                    elif line.startswith("{"):
                        # Plain JSON (possibly pretty-printed across lines).
                        buf.append(line)
                        candidate = "\n".join(buf)
                        try:
                            obj = json.loads(candidate)
                        except json.JSONDecodeError:
                            continue
                        if isinstance(obj, dict) and ("result" in obj or "error" in obj):
                            return obj
            except requests.exceptions.ReadTimeout:
                raise
            if buf:
                return _parse_rpc_payload("\n".join(buf).encode("utf-8"))
            return None

    def _request(self, method, params=None, timeout=None):
        rid = self._next_id
        self._next_id += 1
        payload = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            payload["params"] = params
        obj = self._post(payload, timeout=timeout)
        if obj is None:
            return None
        if "error" in obj:
            raise MCPError(f"JSON-RPC error for {method}: {json.dumps(obj['error'])[:500]}")
        return obj.get("result")

    def _notify(self, method, params=None):
        payload = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        try:
            self._post(payload, timeout=10)
        except Exception:
            pass

    def initialize(self):
        if self._initialized:
            return
        result = self._request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "nonce-mint-driver", "version": "1.0"},
            },
            timeout=60,
        )
        self._initialized = True
        self._notify("notifications/initialized")
        return result

    def list_tools(self):
        self.initialize()
        result = self._request("tools/list", {}, timeout=60)
        return result.get("tools", []) if isinstance(result, dict) else []

    def call_tool(self, name, arguments, timeout=None):
        """Call a tool; returns parsed JSON from content[].text.

        Raises ToolError on isError or on an unparseable result.
        """
        self.initialize()
        result = self._request(
            "tools/call",
            {"name": name, "arguments": arguments},
            timeout=timeout or self.timeout,
        )
        if not isinstance(result, dict):
            raise ToolError(f"tool {name} returned non-object result: {result!r:.200}")
        if result.get("isError"):
            texts = []
            for c in result.get("content", []):
                if isinstance(c, dict) and "text" in c:
                    texts.append(c["text"])
            raise ToolError(
                f"tool {name} isError: " + " | ".join(texts)[:1000],
                raw=result,
            )
        texts = []
        for c in result.get("content", []):
            if isinstance(c, dict) and c.get("type") == "text" and "text" in c:
                texts.append(c["text"])
        if not texts:
            raise ToolError(f"tool {name} returned no text content: {json.dumps(result)[:500]}")
        raw = texts[0]
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"_raw_text": raw}


def retry_with_backoff(fn, attempts=8, base=5.0, max_wait=60.0, server_response_only=False):
    """Retry on RateLimited (honoring Retry-After + jitter) and on
    transient network/5xx errors. A 429 means the call was not executed,
    so retrying the same call cannot duplicate an effect. Returns the
    function result or raises the last error after the budget is spent.
    With server_response_only=True, only retries when the server actually
    responded with a rejection (RateLimited or an MCPError whose message
    starts with "HTTP "); a timeout/connection error (uncertain execution)
    raises immediately instead of risking a duplicate effect."""
    last = None
    wait = base
    for i in range(attempts):
        try:
            return fn()
        except RateLimited as e:
            last = e
            w = e.retry_after if e.retry_after is not None else wait
            w = min(max(w, 1.0), max_wait) + random.uniform(0, 3.0)
            print(f"[retry] 429 busy, attempt {i+1}/{attempts}, waiting {w:.0f}s", flush=True)
            time.sleep(w)
            wait = min(wait * 2, max_wait)
        except (requests.RequestException, MCPError) as e:
            if server_response_only and not (
                isinstance(e, MCPError) and str(e).startswith("HTTP ")
            ):
                raise
            last = e
            if i + 1 < attempts:
                w = min(wait, max_wait) + random.uniform(0, 2.0)
                print(f"[retry] {type(e).__name__}, attempt {i+1}/{attempts}, waiting {w:.0f}s", flush=True)
                time.sleep(w)
                wait = min(wait * 2, max_wait)
    raise last


def new_uuid():
    return str(uuid.uuid4())
