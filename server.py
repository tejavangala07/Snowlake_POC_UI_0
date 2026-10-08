"""Local presentation demo. Python 3.9+ standard library only. Run: python server.py"""
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from http.cookies import SimpleCookie
import hashlib
import hmac
import json
import secrets
import time
import threading
import webbrowser

ROOT = Path(__file__).resolve().parent
SALT = secrets.token_bytes(16)
PASSWORD_HASH = hashlib.pbkdf2_hmac('sha256', b'Demo@123', SALT, 200_000)
USERS = {'teja@demo.com': {'name': 'Teja', 'email': 'teja@demo.com', 'role': 'DEVELOPER'},
         'user@demo.com': {'name': 'Alex', 'email': 'user@demo.com', 'role': 'USER'}}
SESSIONS = {}
LOCK = threading.Lock()

class Handler(BaseHTTPRequestHandler):
    def respond(self, status, data, cookie=None, html=False):
        body = data if html else json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8' if html else 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        if cookie: self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(body)

    def token(self):
        try:
            cookie = SimpleCookie(self.headers.get('Cookie', ''))
            return cookie['demo_session'].value if 'demo_session' in cookie else ''
        except Exception: return ''

    def user(self):
        with LOCK:
            session = SESSIONS.get(self.token())
        return session['user'] if session and session['expires'] > time.time() else None

    def do_GET(self):
        if self.path in ('/', '/index.html'):
            return self.respond(200, (ROOT / 'index.html').read_bytes(), html=True)
        if self.path == '/api/me':
            user = self.user()
            return self.respond(200 if user else 401, user or {'error': 'Please sign in'})
        if self.path == '/api/developer':
            user = self.user()
            if not user: return self.respond(401, {'error': 'Please sign in'})
            if user['role'] != 'DEVELOPER': return self.respond(403, {'error': 'Developer access required'})
            return self.respond(200, {'mode': 'Demo', 'query': 'SELECT region, SUM(revenue) AS revenue FROM sales GROUP BY region;', 'duration_ms': 128, 'rows': 4})
        return self.respond(404, {'error': 'Not found'})

    def do_POST(self):
        # A required custom header blocks cross-origin form submissions; no CORS enabled.
        if self.headers.get('X-Demo-Request') != '1':
            return self.respond(403, {'error': 'Invalid request'})
        origin = self.headers.get('Origin')
        if origin and origin not in ('http://127.0.0.1:8000', 'http://localhost:8000'):
            return self.respond(403, {'error': 'Invalid origin'})
        if self.path == '/api/logout':
            with LOCK: SESSIONS.pop(self.token(), None)
            return self.respond(200, {'ok': True}, 'demo_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0')
        if self.path != '/api/login': return self.respond(404, {'error': 'Not found'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 4096: raise ValueError()
            data = json.loads(self.rfile.read(length))
            email, password = data.get('email', ''), data.get('password', '')
            if not isinstance(email, str) or not isinstance(password, str): raise ValueError()
        except (ValueError, AttributeError): return self.respond(400, {'error': 'Invalid login request'})
        hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 200_000)
        if not hmac.compare_digest(hashed, PASSWORD_HASH) or email.lower() not in USERS:
            return self.respond(401, {'error': 'Email or password is incorrect'})
        token = secrets.token_urlsafe(32)
        with LOCK:
            for key in list(SESSIONS):
                if SESSIONS[key]['expires'] < time.time(): SESSIONS.pop(key, None)
            SESSIONS.pop(self.token(), None)
            SESSIONS[token] = {'user': USERS[email.lower()], 'expires': time.time() + 28800}
        return self.respond(200, USERS[email.lower()], f'demo_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800')

if __name__ == '__main__':
    try: server = ThreadingHTTPServer(('127.0.0.1', 8000), Handler)
    except OSError:
        raise SystemExit('Port 8000 is busy. Stop the other server and run this file again.')
    print('Demo: http://127.0.0.1:8000\nDeveloper: teja@demo.com | Demo@123\nUser: user@demo.com | Demo@123\nCtrl+C to stop. Local demonstration only.')
    threading.Timer(0.7, lambda: webbrowser.open('http://127.0.0.1:8000')).start()
    try: server.serve_forever()
    except KeyboardInterrupt: server.server_close()
