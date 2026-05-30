#!/usr/bin/env python3
"""Minimal HTTP server that captures POST bodies to /webhooks/hook_N.json."""
import http.server
import os

os.makedirs("/webhooks", exist_ok=True)

class Handler(http.server.BaseHTTPRequestHandler):
    counter = 0

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        Handler.counter += 1
        path = f"/webhooks/hook_{Handler.counter}.json"
        with open(path, "wb") as f:
            f.write(body)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")
        print(f"[webhook] Received POST #{Handler.counter} ({length}B)", flush=True)

    def log_message(self, *a):
        pass

if __name__ == "__main__":
    http.server.HTTPServer(("0.0.0.0", 9999), Handler).serve_forever()
