#!/usr/bin/env python3
"""Tiny demo server for testing TruePunch tunnels."""

from http.server import HTTPServer, BaseHTTPRequestHandler
import random

PHRASES = [
    "you just punched through my NAT. respect.",
    "surprise! this is coming from behind a firewall.",
    "NAT said no. we said yes.",
    "your packets took the scenic route.",
    "hole punched. vibe checked.",
    "TCP SYN walked into a NAT and came out the other side.",
]

HTML = """<!DOCTYPE html>
<html>
<head><title>TruePunch</title></head>
<body style="font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#111;color:#0f0">
<div style="text-align:center">
<h1>&#128302; TruePunch</h1>
<p style="font-size:1.5em">{phrase}</p>
<pre style="color:#555;margin-top:2em">p2p connection &#x2022; zero relay traffic</pre>
</div>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(HTML.format(phrase=random.choice(PHRASES)).encode())

    def log_message(self, fmt, *args):
        print(f"[demo] {args[0]}")


if __name__ == "__main__":
    port = 3000
    print(f"demo server running on http://localhost:{port}")
    HTTPServer(("", port), Handler).serve_forever()
