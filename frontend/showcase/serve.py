#!/usr/bin/env python3
"""
AI-NIDS Showcase HTTP Server
Serves the multi-page engineering specification on http://localhost:3001
Supports clean URLs (/how-it-works, /results, /technology, /about)
"""

import http.server
import socketserver
import os
import sys

PORT = 3001
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

ROUTE_MAP = {
    "/": "index.html",
    "/index": "index.html",
    "/index.html": "index.html",
    "/how-it-works": "how-it-works.html",
    "/how-it-works/": "how-it-works.html",
    "/architecture": "how-it-works.html",
    "/architecture.html": "how-it-works.html",
    "/results": "results.html",
    "/results/": "results.html",
    "/technology": "technology.html",
    "/technology/": "technology.html",
    "/tech-stack": "technology.html",
    "/tech-stack.html": "technology.html",
    "/about": "about.html",
    "/about/": "about.html",
}

class ShowcaseHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def translate_path(self, path):
        clean_path = path.split("?")[0]
        if clean_path in ROUTE_MAP:
            return os.path.join(DIRECTORY, ROUTE_MAP[clean_path])
        return super().translate_path(path)

    def log_message(self, format, *args):
        sys.stderr.write(f"[AI-NIDS SHOWCASE] {self.address_string()} - {format % args}\n")

if __name__ == "__main__":
    os.chdir(DIRECTORY)
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), ShowcaseHandler) as httpd:
        print("=" * 72)
        print("  AI-NIDS // EDITORIAL CYBERSECURITY SPECIFICATION")
        print(f"  Live Server: http://localhost:{PORT}")
        print("  Routes:")
        print(f"    - Home:             http://localhost:{PORT}/")
        print(f"    - How It Works:     http://localhost:{PORT}/how-it-works")
        print(f"    - Results:          http://localhost:{PORT}/results")
        print(f"    - Technology Stack: http://localhost:{PORT}/technology")
        print(f"    - About / Notes:    http://localhost:{PORT}/about")
        print("=" * 72)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down showcase server gracefully...")
            sys.exit(0)
