#!/usr/bin/env python3
import sys
import os
import argparse
import webbrowser

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui.backend.server import run_server

def main():
    parser = argparse.ArgumentParser(description="FinGuard Financial Endpoint Security Shield UI")
    parser.add_argument("--port", type=int, default=8443, help="Port to bind FinGuard UI server (default: 8443)")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically launch web browser")
    args = parser.parse_args()

    url = f"http://127.0.0.1:{args.port}"
    print("\033[1;36m")
    print("========================================================")
    print("   FinGuard: Financial Application Security Shield      ")
    print("   Pre-Flight Endpoint Integrity & Malware Interceptor  ")
    print("========================================================")
    print(f"[*] Starting Security UI at: {url}\033[0m")

    if not args.no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    run_server(port=args.port)

if __name__ == "__main__":
    main()
