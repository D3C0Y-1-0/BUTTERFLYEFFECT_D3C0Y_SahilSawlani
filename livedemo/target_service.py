"""The small web service on the protected laptop (port 8080): what the HTTP burst hits. It asks the shared rate limiter before answering; a limited client is closed without a reply."""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGE = b"<html><body><h2>Demo service</h2><p>This page is protected by ATHENA.</p></body></html>"


def make(limiter, port=8080):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def do_GET(self):
            if not limiter.allow(self.client_address[0]):
                self.close_connection = True
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(PAGE)))
            self.end_headers()
            self.wfile.write(PAGE)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("0.0.0.0", port), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv
