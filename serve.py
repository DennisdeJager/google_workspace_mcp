#!/usr/bin/env python3
"""
serve.py — Google Workspace MCP + OAuth bridge for ChatGPT Connector Platform

What's in here:
- OAuth 2.0 AS facade for ChatGPT (discovery, dynamic client registration, authorize, token)
- Google OAuth consent & token exchange
- Protected resource root ("/") that ALSO speaks **MCP JSON-RPC** so ChatGPT can discover & call tools
- Deep, masked DEBUG logging throughout

Notes:
- Demo stores are in-memory
- Never log full secrets in production
"""

from __future__ import annotations

import base64
import os
import time
import json
import secrets
import logging
import hashlib
from typing import Dict, Any, Optional, Tuple

import requests
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware

# =========================
# Logging configuration
# =========================
LOG_LEVEL = os.getenv("LOG_LEVEL", "DEBUG").upper()
logging.basicConfig(level=LOG_LEVEL, format="[%(levelname)s] %(message)s")
log = logging.getLogger("mcp-google-oauth")

# Masking helpers
MASK_FIELDS = {
    "client_secret", "authorization", "access_token", "refresh_token",
    "id_token", "code", "code_verifier", "code_challenge"
}

def _mask_val(v: Optional[str], keep: int = 4) -> Optional[str]:
    if not isinstance(v, str):
        return v
    if len(v) <= keep * 2:
        return v[:keep] + "…" if v else v
    return f"{v[:keep]}…{v[-keep:]}"

def _mask_dict(d: Dict[str, Any], extra_sensitive: Optional[set[str]] = None) -> Dict[str, Any]:
    sens = set(MASK_FIELDS)
    if extra_sensitive:
        sens |= set(extra_sensitive)
    out: Dict[str, Any] = {}
    for k, v in (d or {}).items():
        if k.lower() in sens:
            out[k] = _mask_val(str(v))
        else:
            out[k] = v
    return out

# =========================
# FastAPI app
# =========================
app = FastAPI(title="Google Workspace MCP Connector", version="0.4.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================
# Request/Response logging middleware
# =========================
@app.middleware("http")
async def log_requests(request: Request, call_next):
    rid = request.headers.get("x-request-id") or secrets.token_hex(8)
    request.state.request_id = rid
    client_ip = request.client.host if request.client else "-"
    start = time.time()

    try:
        log.debug(f"[{rid}] >>> {request.method} {request.url} from {client_ip}")
        auth_hdr = request.headers.get("authorization")
        if auth_hdr:
            log.debug(f"[{rid}]     Authorization: {_mask_val(auth_hdr)}")
        ct = request.headers.get("content-type")
        if ct:
            log.debug(f"[{rid}]     Content-Type: {ct}")
    except Exception:
        pass

    try:
        response = await call_next(request)
    except Exception:
        log.exception(f"[{rid}] !!! Unhandled exception while handling {request.method} {request.url.path}")
        raise

    dur_ms = (time.time() - start) * 1000
    log.debug(f"[{rid}] <<< {response.status_code} {request.method} {request.url.path} ({dur_ms:.1f} ms)")
    return response

# =========================
# Configuration helpers
# =========================

def get_base_url() -> str:
    base = os.getenv("SERVER_EXTERNAL_BASE_URL", "").strip().rstrip("/")
    if not base:
        port = os.getenv("PORT", "8000")
        base = f"http://127.0.0.1:{port}"
    return base

def get_google_oauth_config() -> Dict[str, Any]:
    return {
        "client_id": os.getenv("GOOGLE_OAUTH_CLIENT_ID", "").strip(),
        "client_secret": os.getenv("GOOGLE_OAUTH_CLIENT_SECRET", "").strip(),
        "redirect_uri": os.getenv("GOOGLE_OAUTH_REDIRECT_URI", "").strip(),
        "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "scopes": [
            "openid", "email", "profile",
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/drive",
            "https://www.googleapis.com/auth/calendar",
        ],
    }

def require_google_config() -> Dict[str, Any]:
    cfg = get_google_oauth_config()
    if not cfg["client_id"] or not cfg["client_secret"] or not cfg["redirect_uri"]:
        log.error("Google OAuth env not fully configured: %s", _mask_dict(cfg, {"client_id", "client_secret"}))
        raise HTTPException(status_code=500, detail="Google OAuth env not fully configured")
    return cfg

# =========================
# In-memory stores
# =========================
CLIENTS: Dict[str, Dict[str, Any]] = {}
AUTH_CODES: Dict[str, Dict[str, Any]] = {}
TOKENS: Dict[str, Dict[str, Any]] = {}
REFRESH_TOKENS: Dict[str, Dict[str, Any]] = {}
PENDING: Dict[str, Dict[str, Any]] = {}

AUTH_CODE_TTL_SECONDS = 120
ACCESS_TOKEN_TTL_SECONDS = 3600

# =========================
# Utility helpers
# =========================

def _now() -> float:
    return time.time()

def _b64_basic_from_header(auth_header: str) -> Optional[tuple[str, str]]:
    try:
        if not auth_header.lower().startswith("basic "):
            return None
        b64 = auth_header.split(" ", 1)[1].strip()
        raw = base64.b64decode(b64).decode("utf-8")
        if ":" not in raw:
            return None
        cid, csec = raw.split(":", 1)
        return cid, csec
    except Exception:
        return None

def _validate_registered_client(client_id: str, client_secret: Optional[str] = None) -> Dict[str, Any]:
    rec = CLIENTS.get(client_id)
    if not rec:
        log.warning("invalid_client: unknown client_id=%s", _mask_val(client_id))
        raise HTTPException(status_code=401, detail="invalid_client")
    if client_secret is not None and rec.get("client_secret") != client_secret:
        log.warning("invalid_client: bad secret for client_id=%s", _mask_val(client_id))
        raise HTTPException(status_code=401, detail="invalid_client")
    return rec

def _issue_auth_code(client_id: str, redirect_uri: str, scope: str, sub: str = "user:google") -> str:
    code = secrets.token_urlsafe(32)
    AUTH_CODES[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "sub": sub,
        "issued_at": _now(),
        "used": False,
    }
    log.debug("Issued auth_code=%s for client_id=%s scope=%s", _mask_val(code), _mask_val(client_id), scope)
    return code

def _redeem_auth_code(code: str, client_id: str, redirect_uri: str, code_verifier: Optional[str] = None) -> Dict[str, Any]:
    rec = AUTH_CODES.get(code)
    if not rec:
        log.warning("invalid_grant: unknown code=%s", _mask_val(code))
        raise HTTPException(status_code=400, detail="invalid_grant")
    if rec["used"]:
        log.warning("invalid_grant: reused code=%s", _mask_val(code))
        raise HTTPException(status_code=400, detail="invalid_grant")
    if rec["client_id"] != client_id:
        log.warning("invalid_grant: client mismatch code=%s", _mask_val(code))
        raise HTTPException(status_code=400, detail="invalid_grant")
    if rec["redirect_uri"] != redirect_uri:
        log.warning("invalid_grant: redirect_uri mismatch code=%s", _mask_val(code))
        raise HTTPException(status_code=400, detail="invalid_grant")
    if _now() - rec["issued_at"] > AUTH_CODE_TTL_SECONDS:
        log.warning("invalid_grant: code expired code=%s", _mask_val(code))
        raise HTTPException(status_code=400, detail="invalid_grant")

    pkce = rec.get("pkce")
    if pkce and pkce.get("code_challenge"):
        if not code_verifier:
            log.warning("invalid_grant: missing code_verifier for PKCE")
            raise HTTPException(status_code=400, detail="invalid_grant: missing code_verifier")
        method = (pkce.get("code_challenge_method") or "plain").lower()
        ch = pkce["code_challenge"]
        if method == "plain":
            valid = code_verifier == ch
        elif method == "s256":
            digest = hashlib.sha256(code_verifier.encode()).digest()
            computed = base64.urlsafe_b64encode(digest).decode().rstrip("=")
            valid = computed == ch
        else:
            log.warning("invalid_grant: unsupported code_challenge_method=%s", method)
            raise HTTPException(status_code=400, detail="invalid_grant: unsupported code_challenge_method")
        if not valid:
            log.warning("invalid_grant: code_verifier mismatch (method=%s)", method)
            raise HTTPException(status_code=400, detail="invalid_grant: code_verifier mismatch")
        log.debug("PKCE verified (method=%s)", method)

    rec["used"] = True
    log.debug("Redeemed auth_code=%s", _mask_val(code))
    return rec

def _issue_access_token(client_id: str, scope: str, sub: str = "user:google") -> Dict[str, Any]:
    access_token = "at_" + secrets.token_urlsafe(48)
    refresh_token = "rt_" + secrets.token_urlsafe(48)
    expires_at = _now() + ACCESS_TOKEN_TTL_SECONDS
    TOKENS[access_token] = {
        "client_id": client_id,
        "scope": scope,
        "sub": sub,
        "issued_at": _now(),
        "expires_at": expires_at,
        "refresh_token": refresh_token,
        # will fill TOKENS[access_token]["google"] later in /token with Google creds
    }
    REFRESH_TOKENS[refresh_token] = {"client_id": client_id, "scope": scope, "sub": sub}
    log.debug("Issued access_token=%s refresh_token=%s sub=%s scope=%s", _mask_val(access_token), _mask_val(refresh_token), sub, scope)
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_TTL_SECONDS,
        "refresh_token": refresh_token,
        "scope": scope,
    }

# =========================
# Basic endpoints
# =========================
@app.get("/health", summary="Health")
def health():
    return {"status": "ok"}

# ---- Protected resource root + MCP JSON-RPC ----

def _extract_bearer(auth_header: Optional[str]) -> Optional[str]:
    if not auth_header:
        return None
    parts = auth_header.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None

def _introspect_token(token: str) -> Optional[Dict[str, Any]]:
    rec = TOKENS.get(token)
    if not rec:
        return None
    if _now() >= rec.get("expires_at", 0):
        return None
    return rec

# --- Google helpers ---

def _google_get(google_access_token: str, url: str, params: Optional[Dict[str, Any]] = None) -> Tuple[int, Any]:
    headers = {"Authorization": f"Bearer {google_access_token}"}
    r = requests.get(url, headers=headers, params=params or {}, timeout=20)
    try:
        data = r.json()
    except Exception:
        data = r.text
    return r.status_code, data

# MCP tool definitions (minimal schema)
TOOLS_DEF = [
    {
        "name": "whoami",
        "description": "Show the connected Google subject and granted scopes.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "calendar.list_events",
        "description": "List upcoming events from the user's primary Google Calendar.",
        "input_schema": {
            "type": "object",
            "properties": {
                "max_results": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10},
            },
        },
    },
    {
        "name": "gmail.search",
        "description": "Search messages in Gmail using a Gmail search query.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Gmail search query (e.g., 'from:me OR is:starred')"},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10},
            },
            "required": ["query"],
        },
    },
]

# JSON-RPC helpers

def _jsonrpc_result(jid: Any, result: Any) -> JSONResponse:
    return JSONResponse({"jsonrpc": "2.0", "id": jid, "result": result})

def _jsonrpc_error(jid: Any, code: int, message: str, data: Any = None) -> JSONResponse:
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return JSONResponse({"jsonrpc": "2.0", "id": jid, "error": err}, status_code=400)

async def _handle_mcp_jsonrpc(request: Request, rec: Dict[str, Any]) -> JSONResponse:
    rid = getattr(request.state, "request_id", "-")
    try:
        payload = await request.json()
    except Exception:
        return _jsonrpc_error(None, -32700, "Parse error")

    # ---- Support JSON-RPC batch ----
    if isinstance(payload, list):
        results = []
        for item in payload:
            if not isinstance(item, dict) or item.get("jsonrpc") != "2.0":
                results.append({"jsonrpc": "2.0", "id": item.get("id") if isinstance(item, dict) else None, "error": {"code": -32600, "message": "Invalid Request"}})
                continue
            jid = item.get("id")
            method = item.get("method")
            params = item.get("params") or {}
            log.debug(f"[{rid}] MCP JSON-RPC(batch) method={method} params={json.dumps(_mask_dict(params), ensure_ascii=False)}")
            if method == "initialize":
                results.append({"jsonrpc": "2.0", "id": jid, "result": {
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "google-workspace-mcp", "version": getattr(app, 'version', '0.4.0')},
                    "protocolVersion": params.get("protocolVersion") or "2025-03-26",
                }})
                continue
            if method == "tools/list":
                results.append({"jsonrpc": "2.0", "id": jid, "result": {"tools": TOOLS_DEF}})
                continue
            if method == "tools/call":
                name = params.get("name") or params.get("tool_name")
                arguments = params.get("arguments") or params.get("args") or {}
                if not name:
                    results.append({"jsonrpc": "2.0", "id": jid, "error": {"code": -32602, "message": "Missing tool name"}})
                    continue
                resp = await _tools_call_impl(jid, name, arguments, rec)
                results.append(resp.body if isinstance(resp, JSONResponse) else resp)
                continue
            results.append({"jsonrpc": "2.0", "id": jid, "error": {"code": -32601, "message": "Method not found"}})
        return JSONResponse(results)

    if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0":
        return _jsonrpc_error(payload.get("id") if isinstance(payload, dict) else None, -32600, "Invalid Request")

    jid = payload.get("id")
    method = payload.get("method")
    params = payload.get("params") or {}

    log.debug(f"[{rid}] MCP JSON-RPC method={method} params={json.dumps(_mask_dict(params), ensure_ascii=False)}")

    if method == "initialize":
        return _jsonrpc_result(jid, {
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "google-workspace-mcp", "version": getattr(app, 'version', '0.4.0')},
            "protocolVersion": params.get("protocolVersion") or "2025-03-26",
        })

    if method == "tools/list":
        return _jsonrpc_result(jid, {"tools": TOOLS_DEF})

    if method == "tools/call":
        name = params.get("name") or params.get("tool_name")
        arguments = params.get("arguments") or params.get("args") or {}
        if not name:
            return _jsonrpc_error(jid, -32602, "Missing tool name")
        return await _tools_call_impl(jid, name, arguments, rec)

    return _jsonrpc_error(jid, -32601, "Method not found")

@app.api_route("/", methods=["GET", "POST"], summary="Root / Protected Resource + MCP JSON-RPC")
async def root(request: Request):
    rid = getattr(request.state, "request_id", "-")
    auth_header = request.headers.get("authorization")
    bearer = _extract_bearer(auth_header)

    if request.method == "POST":
        # If JSON-RPC and token present, serve MCP
        if bearer:
            rec = _introspect_token(bearer)
            if not rec:
                return JSONResponse({"error": "invalid_token"}, status_code=401, headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""})
            if (request.headers.get("content-type") or "").lower().startswith("application/json"):
                return await _handle_mcp_jsonrpc(request, rec)
            # Non-JSON body -> simple probe success
            return JSONResponse({
                "ok": True,
                "resource": get_base_url(),
                "sub": rec["sub"],
                "scope": rec["scope"],
                "expires_at": rec["expires_at"],
            })
        # No token on POST
        log.debug(f"[{rid}] / POST without bearer -> 401")
        return JSONResponse({"error": "unauthorized", "message": "Bearer token required"}, status_code=401, headers={"WWW-Authenticate": "Bearer"})

    # GET
    if bearer:
        rec = _introspect_token(bearer)
        if rec:
            return JSONResponse({
                "ok": True,
                "resource": get_base_url(),
                "sub": rec["sub"],
                "scope": rec["scope"],
                "expires_at": rec["expires_at"],
            })
    # GET without token: informational payload
    info = {
        "ok": False,
        "message": "Protected resource root. Provide Bearer token via Authorization header.",
        "resource": get_base_url(),
        "docs": f"{get_base_url()}/manifest",
    }
    log.debug(f"[{rid}] / GET without bearer -> 200 info payload")
    return JSONResponse(info, status_code=200)

# =========================
# MCP Manifest
# =========================
@app.get("/manifest", summary="Manifest")
def manifest():
    base = get_base_url()
    return {
        "name": "Google Workspace MCP",
        "version": "0.4.0",
        "description": "MCP connector for Google Workspace (Gmail/Drive/Calendar).",
        "oauth": {
            "issuer": base,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "registration_endpoint": f"{base}/register",
        },
        "endpoints": {
            "health": f"{base}/health",
            "start": f"{base}/start",
            "oauth2callback": f"{base}/oauth2callback",
        },
    }

# =========================
# OpenID / OAuth Discovery
# =========================
@app.get("/.well-known/openid-configuration", summary="OpenID Discovery")
@app.get("/openid-configuration", summary="OpenID Discovery")
@app.get("/oauth-authorization-server", summary="OpenID Discovery")
def openid_configuration():
    base = get_base_url()
    log.info("🔐 OAuth Authorization Server metadata requested")
    return {
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
        "registration_endpoint": f"{base}/register",
        "jwks_uri": f"{base}/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "scopes_supported": [
            "openid", "email", "profile",
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/drive",
            "https://www.googleapis.com/auth/calendar",
        ],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "userinfo_endpoint": f"{base}/userinfo",
        "introspection_endpoint": f"{base}/introspect",
        "revocation_endpoint": f"{base}/revoke",
    }

@app.get("/.well-known/oauth-authorization-server", summary="OAuth AS Discovery (alias)")
def oauth_as_alias():
    return openid_configuration()

@app.get("/.well-known/oauth-protected-resource", summary="Protected Resource metadata")
def oauth_pr_metadata():
    base = get_base_url()
    log.info("🛡️ OAuth Protected Resource metadata requested")
    return {
        "resource": base,
        "authorization_servers": [base],
        "scopes_supported": [
            "openid", "email", "profile",
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/drive",
            "https://www.googleapis.com/auth/calendar",
        ]
    }

# =========================
# RFC 7591 Dynamic Client Registration
# =========================
@app.post("/register", summary="Dynamic Client Registration")
async def register(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    log.info("📨 RFC7591 registration received: %s", json.dumps(_mask_dict(body), indent=2))

    client_name = str(body.get("client_name", "client")).strip()
    redirect_uris = body.get("redirect_uris") or []
    if not redirect_uris or not isinstance(redirect_uris, list):
        log.warning("invalid_client_metadata: redirect_uris missing or invalid")
        raise HTTPException(status_code=400, detail="invalid_client_metadata")

    client_id = secrets.token_urlsafe(16)
    client_secret = secrets.token_urlsafe(32)

    CLIENTS[client_id] = {
        "client_id": client_id,
        "client_secret": client_secret,
        "client_name": client_name,
        "redirect_uris": redirect_uris,
        "grant_types": body.get("grant_types") or ["authorization_code", "refresh_token"],
        "response_types": body.get("response_types") or ["code"],
        "token_endpoint_auth_method": body.get("token_endpoint_auth_method") or "client_secret_basic",
        "created_at": _now(),
    }

    log.info("✅ Registered client id=%s name=%s redirects=%s", _mask_val(client_id), client_name, redirect_uris)

    return JSONResponse(status_code=200, content={
        "client_id": client_id,
        "client_secret": client_secret,
        "client_name": client_name,
        "redirect_uris": redirect_uris,
        "token_endpoint_auth_method": CLIENTS[client_id]["token_endpoint_auth_method"],
    })

# =========================
# Authorization endpoint (/authorize)
# =========================
@app.get("/authorize", summary="Authorization Endpoint")
def authorize(request: Request):
    rid = getattr(request.state, "request_id", "-")
    params = dict(request.query_params)

    response_type = params.get("response_type", "")
    client_id = params.get("client_id", "")
    client_state = params.get("state", "")
    redirect_uri = params.get("redirect_uri", "")
    scope = params.get("scope", "")
    resource = params.get("resource", "")
    code_challenge = params.get("code_challenge")
    code_challenge_method = params.get("code_challenge_method", "plain")

    log.debug(f"[{rid}] /authorize params: {json.dumps(_mask_dict(params), ensure_ascii=False)}")

    if response_type != "code":
        raise HTTPException(status_code=400, detail="unsupported_response_type")

    rec = _validate_registered_client(client_id)
    if redirect_uri not in rec.get("redirect_uris", []):
        raise HTTPException(status_code=400, detail="invalid_request: redirect_uri mismatch")

    if not client_state:
        raise HTTPException(status_code=400, detail="invalid_request: missing state")

    PENDING[client_state] = {
        "client_id": client_id,
        "client_redirect_uri": redirect_uri,
        "requested_scope": scope,
        "resource": resource,
        "created_at": _now(),
        "pkce": {"code_challenge": code_challenge, "code_challenge_method": code_challenge_method},
    }
    log.debug(f"[{rid}] Stored PENDING for state={client_state}: {json.dumps(_mask_dict(PENDING[client_state]), ensure_ascii=False)}")

    g = require_google_config()
    google_url = (
        f"{g['authorization_url']}?"
        f"client_id={requests.utils.quote(g['client_id'])}"
        f"&redirect_uri={requests.utils.quote(g['redirect_uri'])}"
        f"&response_type=code"
        f"&scope={requests.utils.quote(' '.join(g['scopes']))}"
        f"&access_type=offline&prompt=consent"
        f"&state={requests.utils.quote(client_state)}"
    )

    log.info("➡️ Redirecting user to Google for login/consent (state=%s)", client_state)
    return RedirectResponse(url=google_url, status_code=307)

@app.get("/start", summary="Start Google OAuth (helper)")
def oauth_start(request: Request):
    return authorize(request)

# =========================
# Google OAuth callback
# =========================
@app.get("/oauth2callback", summary="OAuth2 Callback from Google")
def oauth2_callback(request: Request):
    rid = getattr(request.state, "request_id", "-")
    google_code = request.query_params.get("code")
    client_state = request.query_params.get("state")

    if not google_code or not client_state:
        log.warning(f"[{rid}] oauth2callback missing code/state")
        return JSONResponse({"error": "invalid_request", "detail": "missing code or state"}, status_code=400)

    g = require_google_config()
    payload = {
        "code": google_code,
        "client_id": g["client_id"],
        "client_secret": g["client_secret"],
        "redirect_uri": g["redirect_uri"],
        "grant_type": "authorization_code",
    }
    log.info("🔄 Exchanging Google code for tokens… state=%s", client_state)
    r = requests.post(g["token_url"], data=payload, timeout=20)
    if r.status_code != 200:
        log.error(f"[{rid}] Google token exchange failed: status=%s body=%s", r.status_code, _mask_val(r.text))
        return JSONResponse({"error": "google_exchange_failed", "detail": "token exchange failed"}, status_code=400)
    google_tokens = r.json()
    log.info("✅ Received Google tokens (id_token=%s, access_token=%s, refresh_token=%s)",
             _mask_val(google_tokens.get("id_token")), _mask_val(google_tokens.get("access_token")), _mask_val(google_tokens.get("refresh_token")))

    # Subject from id_token if present
    sub = "user:google"
    try:
        id_token = google_tokens.get("id_token")
        if id_token:
            parts = id_token.split(".")
            if len(parts) == 3:
                def b64url_decode(s: str) -> bytes:
                    s += "=" * ((4 - len(s) % 4) % 4)
                    return base64.urlsafe_b64decode(s.encode())
                payload_json = b64url_decode(parts[1]).decode()
                claims = json.loads(payload_json)
                if isinstance(claims, dict) and claims.get("sub"):
                    sub = f"google:{claims['sub']}"
    except Exception:
        log.debug(f"[{rid}] Failed to parse id_token payload (non-fatal)")

    tx = PENDING.get(client_state)
    if not tx:
        log.warning(f"[{rid}] invalid_state: no pending transaction for state=%s", client_state)
        return JSONResponse({"error": "invalid_state", "detail": "no pending transaction for this state"}, status_code=400)

    pkce = None
    try:
        tx_pkce = (tx.get("pkce") or {})
        if tx_pkce.get("code_challenge"):
            pkce = {"code_challenge": tx_pkce.get("code_challenge"), "code_challenge_method": tx_pkce.get("code_challenge_method", "plain")}
    except Exception:
        pkce = None

    our_code = _issue_auth_code(client_id=tx["client_id"], redirect_uri=tx["client_redirect_uri"], scope=tx["requested_scope"] or "openid email profile", sub=sub)
    if pkce:
        AUTH_CODES[our_code]["pkce"] = pkce
    AUTH_CODES[our_code]["google_id_token"] = google_tokens.get("id_token")
    AUTH_CODES[our_code]["google_access_token"] = google_tokens.get("access_token")
    AUTH_CODES[our_code]["google_refresh_token"] = google_tokens.get("refresh_token")

    redirect_back = f"{tx['client_redirect_uri']}?state={requests.utils.quote(client_state)}&code={requests.utils.quote(our_code)}"
    log.info("🔁 Redirecting back to ChatGPT with our authorization code (state=%s, code=%s)", client_state, _mask_val(our_code))
    return RedirectResponse(url=redirect_back, status_code=302)

# =========================
# Token endpoint
# =========================
@app.post("/token", summary="Token Endpoint")
async def token(request: Request):
    rid = getattr(request.state, "request_id", "-")
    try:
        body = await request.body()
        form = dict([kv.split("=", 1) if "=" in kv else (kv, "") for kv in body.decode().split("&") if kv])
        form = {k: requests.utils.unquote(v) for k, v in form.items()}
    except Exception:
        form = {}

    log.debug(f"[{rid}] /token form: {json.dumps(_mask_dict(form), ensure_ascii=False)}")

    grant_type = form.get("grant_type", "")
    client_id = None
    client_secret = None

    auth_header = request.headers.get("authorization")
    cred = _b64_basic_from_header(auth_header) if auth_header else None
    if cred:
        client_id, client_secret = cred
    else:
        client_id = form.get("client_id")
        client_secret = form.get("client_secret")

    if not client_id or not client_secret:
        log.warning(f"[{rid}] invalid_client: missing credentials")
        raise HTTPException(status_code=401, detail="invalid_client")

    _validate_registered_client(client_id, client_secret)

    if grant_type == "authorization_code":
        code = form.get("code", "")
        redirect_uri = form.get("redirect_uri", "")
        code_verifier = form.get("code_verifier")
        if not code or not redirect_uri:
            raise HTTPException(status_code=400, detail="invalid_request")
        rec = _redeem_auth_code(code, client_id=client_id, redirect_uri=redirect_uri, code_verifier=code_verifier)
        token_payload = _issue_access_token(client_id=client_id, scope=rec["scope"], sub=rec["sub"])
        # Attach Google tokens to *our* access token so MCP tools can call Google APIs
        at = token_payload["access_token"]
        TOKENS[at]["google"] = {
            "access_token": AUTH_CODES[code].get("google_access_token"),
            "refresh_token": AUTH_CODES[code].get("google_refresh_token"),
            "id_token": AUTH_CODES[code].get("google_id_token"),
        }
        response_body = {
            "access_token": token_payload["access_token"],
            "token_type": "Bearer",
            "expires_in": token_payload["expires_in"],
            "refresh_token": token_payload["refresh_token"],
            "scope": token_payload["scope"],
        }
        log.debug(f"[{rid}] /token -> 200 body: {json.dumps(_mask_dict(response_body), ensure_ascii=False)}")
        return JSONResponse(response_body, status_code=200)

    elif grant_type == "refresh_token":
        refresh_token = form.get("refresh_token")
        if not refresh_token:
            raise HTTPException(status_code=400, detail="invalid_request")
        rec = REFRESH_TOKENS.get(refresh_token)
        if not rec or rec.get("client_id") != client_id:
            log.warning(f"[{rid}] invalid_grant: unknown/foreign refresh_token")
            raise HTTPException(status_code=400, detail="invalid_grant")
        token_payload = _issue_access_token(client_id=client_id, scope=rec["scope"], sub=rec["sub"])
        token_payload["refresh_token"] = refresh_token
        return JSONResponse({
            "access_token": token_payload["access_token"],
            "token_type": "Bearer",
            "expires_in": token_payload["expires_in"],
            "refresh_token": token_payload["refresh_token"],
            "scope": token_payload["scope"],
        }, status_code=200)

    else:
        log.warning(f"[{rid}] unsupported_grant_type: {grant_type}")
        raise HTTPException(status_code=400, detail="unsupported_grant_type")

# =========================
# JWKS placeholder (not used in this demo)
# =========================
@app.get("/jwks.json", summary="JWKS (unused)")
def jwks():
    return {"keys": []}

# =========================
# OpenID Connect UserInfo (minimal)
# =========================
@app.get("/userinfo", summary="OIDC UserInfo")
async def userinfo(request: Request):
    auth_header = request.headers.get("authorization")
    bearer = _extract_bearer(auth_header)
    if not bearer:
        return JSONResponse({"error": "invalid_token"}, status_code=401, headers={"WWW-Authenticate": "Bearer"})
    rec = _introspect_token(bearer)
    if not rec:
        return JSONResponse({"error": "invalid_token"}, status_code=401, headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""})
    return JSONResponse({"sub": rec["sub"], "email": None, "email_verified": None, "name": None, "preferred_username": None})

# =========================
# RFC 7662 Token Introspection & RFC 7009 Revocation
# =========================
@app.post("/introspect", summary="OAuth2 Token Introspection")
async def introspect(request: Request):
    try:
        body = await request.body()
        form = dict([kv.split("=", 1) if "=" in kv else (kv, "") for kv in body.decode().split("&") if kv])
        form = {k: requests.utils.unquote(v) for k, v in form.items()}
    except Exception:
        form = {}
    token = form.get("token")
    rec = TOKENS.get(token) if token else None
    active = bool(rec and _now() < rec.get("expires_at", 0))
    return JSONResponse({
        "active": active,
        **({
            "client_id": rec["client_id"],
            "scope": rec["scope"],
            "sub": rec["sub"],
            "exp": int(rec["expires_at"]),
            "token_type": "access_token",
        } if active else {})
    })

@app.post("/revoke", summary="OAuth2 Token Revocation")
async def revoke(request: Request):
    try:
        body = await request.body()
        form = dict([kv.split("=", 1) if "=" in kv else (kv, "") for kv in body.decode().split("&") if kv])
        form = {k: requests.utils.unquote(v) for k, v in form.items()}
    except Exception:
        form = {}
    token = form.get("token")
    if token in TOKENS:
        TOKENS.pop(token, None)
    elif token in REFRESH_TOKENS:
        REFRESH_TOKENS.pop(token, None)
    return PlainTextResponse("OK")

# =========================
# Startup log
# =========================
@app.on_event("startup")
def on_startup():
    base = get_base_url()
    g = get_google_oauth_config()
    log.info("🚀 Server started (log level=%s)", LOG_LEVEL)
    log.info("Base URL: %s", base)
    log.info("Google redirect URI: %s", g.get("redirect_uri") or "<unset>")
    log.info("Available routes:")
    for r in app.router.routes:
        path = getattr(r, "path", None) or getattr(r, "path_format", None) or str(r)
        methods = getattr(r, "methods", None)
        if methods:
            log.info("  %s  %s", ",".join(sorted(methods)), path)
        else:
            log.info("  %s", path)
