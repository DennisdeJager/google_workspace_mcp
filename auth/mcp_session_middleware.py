"""
MCP Session Middleware

This middleware intercepts MCP requests and sets the session context
for use by tool functions.
"""

import logging
from typing import Callable, Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from auth.session_context import (
    SessionContext,
    SessionContextManager,
    extract_session_from_headers,
)
# OAuth 2.1 is now handled by FastMCP auth

logger = logging.getLogger(__name__)


class MCPSessionMiddleware(BaseHTTPMiddleware):
    """
    Middleware that extracts session information from requests and makes it
    available to MCP tool functions via context variables.
    """
    
    async def dispatch(self, request: Request, call_next: Callable) -> Any:
        """Process request and set session context."""
        
        logger.debug(f"MCPSessionMiddleware processing request: {request.method} {request.url.path}")
        
        # Skip non-MCP paths
        if not request.url.path.startswith("/mcp"):
            logger.debug(f"Skipping non-MCP path: {request.url.path}")
            return await call_next(request)
        
        session_context = None
        
        try:
            # Extract session information
            headers = dict(request.headers)
            session_id = extract_session_from_headers(headers)
            
            # Try to get OAuth 2.1 auth context
            auth_context = None
            if hasattr(request.state, "auth"):
                auth_context = request.state.auth
            
            # Build session context
            if session_id or auth_context:
                session_context = SessionContext(
                    session_id=session_id or (auth_context.session_id if auth_context else None),
                    user_id=auth_context.user_id if auth_context else None,
                    auth_context=auth_context,
                    request=request,
                    metadata={
                        "path": request.url.path,
                        "method": request.method,
                    }
                )
                
                logger.debug(
                    f"MCP request with session: session_id={session_context.session_id}, "
                    f"user_id={session_context.user_id}, path={request.url.path}"
                )
            
            # Process request with session context
            with SessionContextManager(session_context):
                response = await call_next(request)
                return response
                
        except Exception as e:
            logger.error(f"Error in MCP session middleware: {e}")
            # Continue without session context
            return await call_next(request)