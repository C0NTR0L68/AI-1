"""Strict local HTTP-origin boundary; this is not user authentication.

AI-1 uses http://127.0.0.1:8000. Browser writes need that exact Origin.
Native PowerShell writes may send the same Origin, or X-AI1-Client: local-cli
without any Sec-Fetch-* headers. The marker is public and is not a credential.
No hostname aliases, proxy trust, storage, settings reads or network discovery.
"""
from dataclasses import dataclass
import re

from starlette.responses import JSONResponse

_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_JSON = re.compile(r'application/json(?:\s*;\s*charset=(?:utf-8|"utf-8"))?\Z', re.I)
_SINGLE = {'host', 'origin', 'authorization', 'content-type', 'content-length',
           'transfer-encoding', 'x-ai1-client'}


@dataclass(frozen=True)
class LocalRequestPolicy:
    port: int
    native_writes: str

    def __post_init__(self):
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError('Explicit valid listener port required')
        if self.native_writes not in ('deny', 'marker'):
            raise ValueError('Explicit native-write policy required')

    @property
    def authority(self):
        return '127.0.0.1' if self.port == 80 else f'127.0.0.1:{self.port}'

    @property
    def origin(self):
        return 'http://' + self.authority

    def check(self, scope):
        if scope.get('scheme') != 'http':
            return 403
        raw = scope.get('headers')
        if not isinstance(raw, (list, tuple)) or len(raw) > 64:
            return 400
        values = {}
        for pair in raw:
            if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                return 400
            key, value = pair
            if type(key) is not bytes or type(value) is not bytes:
                return 400
            try:
                name, text = key.decode('ascii').lower(), value.decode('ascii')
            except UnicodeDecodeError:
                return 400
            if (not _TOKEN.fullmatch(name) or len(text) > 8192
                    or any(ord(c) < 32 or ord(c) == 127 for c in text)):
                return 400
            singleton = name in _SINGLE or name.startswith('sec-fetch-') or name == 'forwarded' or name.startswith('x-forwarded-')
            if singleton and name in values:
                return 400
            # Unrelated legal repeated headers are preserved on the forwarded
            # scope, not treated as identity and not collapsed for downstream.
            values[name] = text
        hosts = {self.authority}
        if self.port == 80:
            hosts.add('127.0.0.1:80')
        if values.get('host') not in hosts:
            return 400
        if any(name == 'forwarded' or name.startswith('x-forwarded-') or name in (
                'x-http-method-override', 'x-method-override') for name in values):
            return 403
        if 'content-length' in values:
            length = values['content-length']
            if not length or not length.isdecimal() or len(length) > 20 or 'transfer-encoding' in values:
                return 400
        if 'transfer-encoding' in values and values['transfer-encoding'].lower() != 'chunked':
            return 400
        method = scope.get('method')
        if type(method) is not str or method not in ('GET', 'HEAD', 'POST', 'DELETE'):
            return 405
        site = values.get('sec-fetch-site')
        if site not in (None, 'same-origin', 'none'):
            return 403
        origin = values.get('origin')
        if origin is not None and origin != self.origin:
            return 403
        if 'x-ai1-client' in values and values['x-ai1-client'] != 'local-cli':
            return 403
        if method in ('POST', 'DELETE'):
            if origin is None:
                if (self.native_writes != 'marker' or values.get('x-ai1-client') != 'local-cli'
                        or any(name.startswith('sec-fetch-') for name in values)):
                    return 403
            elif values.get('sec-fetch-mode') not in (None, 'cors', 'same-origin'):
                return 403
            content_type = values.get('content-type')
            if (method == 'POST' or content_type is not None) and not _JSON.fullmatch(content_type or ''):
                return 415
        return None


class LocalRequestBoundary:
    """Apply globally before RuntimeGuard/router/body/store, not to a path prefix.

    Host/Origin policy is not user identity; native software and same-origin XSS
    can forge these headers. Proxy deployments and WebSockets are unsupported.
    """
    def __init__(self, app, *, policy):
        if type(policy) is not LocalRequestPolicy:
            raise ValueError('Explicit reviewed policy required')
        self.app, self.policy = app, policy

    async def __call__(self, scope, receive, send):
        if scope['type'] == 'websocket':
            await send({'type': 'websocket.close', 'code': 1008})
            return
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        status = self.policy.check(scope)
        if status is not None:
            response = JSONResponse({'error': 'local_request_denied'}, status_code=status,
                                    headers={'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'})
            return await response(scope, receive, send)

        async def safe_send(event):
            if event['type'] == 'http.response.start':
                event = dict(event)
                event['headers'] = [(k, v) for k, v in event.get('headers', [])
                                    if not k.lower().startswith(b'access-control-allow-')]
            await send(event)
        # Preserve path/root/raw headers/state: no identity inferred from URLs,
        # Referer, User-Agent, cookies, scope.server or Forwarded values.
        await self.app(scope, receive, safe_send)
