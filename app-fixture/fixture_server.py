#!/usr/bin/env python3
"""Owned QA response surfaces only. TLS on fixed Unix sockets; no IP networking inside container."""
import argparse, hashlib, html, http.client, http.server, json, os, socketserver, ssl, threading
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
import public_clients

http.client._MAXLINE = 8192
http.client._MAXHEADERS = 32
MAX_REQUESTS = 50000
STATE = None
COUNTERS = {"requests": 0, "rejected": 0}
LOCK = threading.Lock()
MODES = {
    "affected": {"apache": "2.4.60", "tomcat": "9.0.85", "certificate": "cn-only"},
    "compliant": {"apache": "2.4.62", "tomcat": "9.0.86", "certificate": "dns-san"},
}
ROOT = '''<!doctype html><html><head><title>Vornin owned scanner QA fixture</title>
<meta name="generator" content="WordPress 6.8"><script src="/assets/frameworks.js"></script></head>
<body><h1>Owned scanner QA fixture</h1><p>Apache Tomcat/{tomcat}</p>
<a href="/reflect?name=hello">GET reflection control</a>
<form action="/reflect" method="get"><label>Name<input name="name" value="hello"></label><button>Show</button></form>
<p>First-party synthetic signatures, no real Apache, Tomcat, WordPress or framework deployment.</p></body></html>'''
FRAMEWORKS = '/* react/19.2.4 vue/3.5.30 */\nconst qaNext={"version":"16.2.0","name":"next"};\n'


def mode(listener):
    value = json.loads((STATE / "config.json").read_text())[listener]
    if value not in MODES:
        raise ValueError("Unknown local fixture mode")
    return value


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    block_on_close = True
    slots = threading.BoundedSemaphore(16)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(15)
        selected = mode(self.listener)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        cert = MODES[selected]["certificate"]
        context.load_cert_chain(STATE / "keys" / (cert + ".crt"), STATE / "keys" / (cert + ".key"))
        try:
            return context.wrap_socket(connection, server_side=True), address
        except Exception:
            connection.close()
            raise

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        super().process_request(request, address)

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = ""
    sys_version = ""

    def log_message(self, *args):
        pass  # No remote IP, query payload, identity or body logs.

    def send(self, status, body, kind="text/html; charset=utf-8", banner=None):
        selected = mode(self.server.listener)
        self.send_response_only(status)
        self.send_header("Server", banner or "Apache/" + MODES[selected]["apache"])
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.send_header("X-Vornin-QA-Fixture", "immediate-2026-10-24")
        self.send_header("X-Fixture-Mode", selected)
        if selected == "compliant":
            self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self.close_connection = True

    def bounded(self):
        with LOCK:
            COUNTERS["requests"] += 1
            count = COUNTERS["requests"]
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 4097
        if count > MAX_REQUESTS or len(self.path) > 4096 or length < 0 or length > 4096 or sum(len(k) + len(v) for k, v in self.headers.items()) > 8192 or "Transfer-Encoding" in self.headers:
            with LOCK:
                COUNTERS["rejected"] += 1
            self.send(413, b"Bounded owned QA fixture request refused")
            return False
        if self.path.startswith(("http://", "https://", "//")):
            self.send(400, b"Absolute/proxy requests refused")
            return False
        return True

    def do_GET(self):
        if not self.bounded():
            return
        selected = mode(self.server.listener)
        parsed = urlsplit(self.path)
        path = parsed.path
        if path == "/":
            return self.send(200, ROOT.format(tomcat=MODES[selected]["tomcat"]).replace("</head>", '<script src="/assets/supabase-pairing.js"></script></head>' if (STATE / "runtime" / "public-clients.json").exists() else "</head>").encode())
        if path == "/assets/supabase-pairing.js":
            try:
                config = public_clients.load(STATE / "runtime" / "public-clients.json")
                if config is None:
                    return self.send(404, b"Optional public client fixture is disabled", "text/plain")
                return self.send(200, public_clients.render(config), "application/javascript")
            except (ValueError, OSError, TypeError):
                return self.send(503, b"Invalid runtime public client configuration", "text/plain")
        if path == "/assets/frameworks.js":
            return self.send(200, FRAMEWORKS.encode(), "application/javascript")
        if path == "/reflect":
            try:
                value = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=16).get("name", ["hello"])[0][:2048]
            except ValueError:
                return self.send(400, b"Too many query fields")
            shown = value if selected == "affected" else html.escape(value, quote=True)
            return self.send(200, ("<!doctype html><html><body><div id=echo>" + shown + "</div></body></html>").encode())
        if path == "/wp-content/plugins/404-to-301/readme.txt":
            return self.send(200, b"=== Synthetic catalogue delivery QA ===\nStable tag: 1.0.0\n", "text/plain; charset=utf-8")
        if path == "/wp-content/themes/twentytwentyfive/style.css":
            return self.send(200, b"/*\nTheme Name: Twenty Twenty-Five\nVersion: 1.3\n*/\n", "text/css")
        if path == "/robots.txt":
            return self.send(200, b"User-agent: *\nAllow: /\n", "text/plain")
        if path == "/_truth":
            with LOCK:
                counts = dict(COUNTERS)
            truth = {"fixture": "immediate-2026-10-24", "listener": self.server.listener, "mode": selected,
                     "signatures": MODES[selected], "counters": counts,
                     "sourceSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                     "data": "synthetic signatures only; not installed engine identity"}
            return self.send(200, json.dumps(truth, sort_keys=True).encode(), "application/json")
        controls = {"/banners/apache/2.4.59": "Apache/2.4.59", "/banners/apache/2.4.60": "Apache/2.4.60", "/banners/apache/2.4.62": "Apache/2.4.62",
                    "/banners/tomcat/9.0.85": "Apache Tomcat/9.0.85", "/banners/tomcat/9.0.86": "Apache Tomcat/9.0.86"}
        if path in controls:
            return self.send(200, ("<html><body>" + controls[path] + "</body></html>").encode(), banner=controls[path])
        self.send(404, b"<html><body>Owned QA fixture: unknown route</body></html>")

    do_HEAD = do_GET

    def do_OPTIONS(self):
        self.send(204, b"")

    def refuse(self):
        self.send(405, b"Owned fixture supports GET/HEAD only; no mutations")

    do_POST = do_PUT = do_DELETE = do_PATCH = do_TRACE = do_CONNECT = refuse


def main():
    global STATE
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path, default=Path("/state"))
    parser.add_argument("--socket-dir", type=Path, default=Path("/sockets"))
    args = parser.parse_args()
    STATE = args.state.resolve()
    args.socket_dir.mkdir(parents=True, exist_ok=True)
    servers = []
    for listener in ("affected", "compliant"):
        endpoint = args.socket_dir / (listener + ".sock")
        endpoint.unlink(missing_ok=True)
        server = Server(str(endpoint), Handler)
        server.listener = listener
        os.chmod(endpoint, 0o600)
        servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    threading.Event().wait()


if __name__ == "__main__":
    main()
