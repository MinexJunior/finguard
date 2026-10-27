import os
import json
import urllib.parse
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from ui.backend.core_bridge import FinGuardBridge
from ui.backend.gatekeeper import PreFlightGatekeeper

class FinGuardHTTPRequestHandler(SimpleHTTPRequestHandler):
    bridge = FinGuardBridge()
    gatekeeper = PreFlightGatekeeper(bridge)
    static_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=self.static_dir, **kwargs)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        real_procfs = query.get("real_procfs", ["false"])[0].lower() == "true"

        if path == "/api/scan":
            self.send_json(self.bridge.scan_system(real_procfs=real_procfs))
        elif path == "/api/targets":
            self.send_json(self.gatekeeper.get_targets())
        elif path == "/api/status":
            decision = self.bridge.get_preflight_decision(real_procfs)
            score = self.bridge.get_risk_score(real_procfs)
            self.send_json({
                "decision_code": decision,
                "risk_score": score,
                "library_loaded": self.bridge.lib is not None
            })
        else:
            # Serve static files (HTML, CSS, JS)
            super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b"{}"

        try:
            body = json.loads(post_data.decode("utf-8")) if post_data else {}
        except Exception:
            body = {}

        if path == "/api/preflight":
            target_id = body.get("target_id", "cbe_bank")
            real_procfs = body.get("real_procfs", False)
            result = self.gatekeeper.check_preflight_for_target(target_id, real_procfs=real_procfs)
            self.send_json(result)

        elif path == "/api/terminate":
            pid = body.get("pid")
            if pid:
                self.gatekeeper.simulate_terminate_threat(int(pid))
                self.send_json({"success": True, "terminated_pid": pid})
            else:
                self.send_json({"error": "Missing pid parameter"}, status=400)

        elif path == "/api/reset":
            self.gatekeeper.reset_remediation()
            self.send_json({"success": True, "message": "Remediation state reset"})

        elif path == "/api/analyze-pe":
            filepath = body.get("filepath", "samples/suspicious_dropper.exe")
            # If relative path, resolve relative to root
            if not os.path.isabs(filepath):
                base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                filepath = os.path.join(base_dir, filepath)
            result = self.bridge.analyze_pe(filepath)
            self.send_json(result)

        else:
            self.send_json({"error": "Endpoint not found"}, status=404)

    def send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(body)

def run_server(port: int = 8443):
    server_address = ("127.0.0.1", port)
    httpd = ThreadingHTTPServer(server_address, FinGuardHTTPRequestHandler)
    print(f"\n\033[1;36m[+] FinGuard Security Dashboard running on: http://127.0.0.1:{port}\033[0m")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down FinGuard Server...")
        httpd.server_close()

if __name__ == "__main__":
    run_server()
