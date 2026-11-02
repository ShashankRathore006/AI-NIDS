#!/usr/bin/env python3
"""
AI-NIDS Frontend HTTP Server
Zero-dependency static server to host the unified AI-NIDS web application on http://localhost:3000
Supports SPA routing for:
  - /overview
  - /soc
  - /traffic
  - /threats
  - /alerts
  - /analytics
"""

import http.server
import socketserver
import os
import sys

PORT = 3000
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

APP_ROUTES = {
    "/": "index.html",
    "/overview": "index.html",
    "/overview/": "index.html",
    "/soc": "index.html",
    "/soc/": "index.html",
    "/dashboard": "index.html",
    "/dashboard/": "index.html",
    "/traffic": "index.html",
    "/traffic/": "index.html",
    "/threats": "index.html",
    "/threats/": "index.html",
    "/alerts": "index.html",
    "/alerts/": "index.html",
    "/analytics": "index.html",
    "/analytics/": "index.html",

    # Showcase backward-compatibility mappings
    "/showcase": "showcase/index.html",
    "/showcase/": "showcase/index.html",
    "/showcase/how-it-works": "showcase/how-it-works.html",
    "/showcase/results": "showcase/results.html",
    "/showcase/technology": "showcase/technology.html",
    "/showcase/about": "showcase/about.html",
}

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def translate_path(self, path):
        clean_path = path.split("?")[0]
        if clean_path in APP_ROUTES:
            return os.path.join(DIRECTORY, APP_ROUTES[clean_path])
        return super().translate_path(path)

    def log_message(self, format, *args):
        # Clean terminal output for SOC console feel
        sys.stderr.write(f"[AI-NIDS APP] {self.address_string()} - {format % args}\n")

if __name__ == "__main__":
    os.chdir(DIRECTORY)
    # Allow port reuse immediately upon restart
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print("=" * 68)
        print(f"  AI-NIDS // UNIFIED NETWORK INTRUSION DETECTION SYSTEM")
        print(f"  Application URL: http://localhost:{PORT}")
        print(f"  Pages:")
        print(f"    - Overview:         http://localhost:{PORT}/#/overview")
        print(f"    - Live SOC:         http://localhost:{PORT}/#/soc")
        print(f"    - Network Traffic:  http://localhost:{PORT}/#/traffic")
        print(f"    - Threat Detection: http://localhost:{PORT}/#/threats")
        print(f"    - Alerts:           http://localhost:{PORT}/#/alerts")
        print(f"    - Analytics:        http://localhost:{PORT}/#/analytics")
        print(f"  Target Backend API:   http://localhost:8000")
        print("=" * 68)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server gracefully...")
            sys.exit(0)
