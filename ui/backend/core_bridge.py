import os
import json
import ctypes
from typing import Dict, Any, Optional

class FinGuardBridge:
    """
    High-speed Python bridge interfacing with the native C++20 libfinguard library
    via C-ABI (ctypes), with automatic fallback to standalone CLI subprocess.
    """
    def __init__(self, lib_path: Optional[str] = None):
        self.lib = None
        self._init_library(lib_path)

    def _init_library(self, custom_path: Optional[str]):
        search_paths = []
        if custom_path:
            search_paths.append(custom_path)

        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        search_paths.extend([
            os.path.join(base_dir, "build", "core", "libfinguard.so"),
            os.path.join(base_dir, "build", "core", "finguard.dll"),
            os.path.join(base_dir, "libfinguard.so"),
            "libfinguard.so"
        ])

        for path in search_paths:
            if os.path.exists(path):
                try:
                    self.lib = ctypes.CDLL(path)
                    self._setup_bindings()
                    self.lib_path = path
                    return
                except Exception as e:
                    print(f"[FinGuardBridge] Warning: failed to load {path}: {e}")

        self.lib = None
        self.binary_path = os.path.join(base_dir, "build", "core", "finguard-core")

    def _setup_bindings(self):
        # char* finguard_scan_system_json(bool real_procfs)
        self.lib.finguard_scan_system_json.argtypes = [ctypes.c_bool]
        self.lib.finguard_scan_system_json.restype = ctypes.c_void_p

        # char* finguard_analyze_pe_json(const char* filepath)
        self.lib.finguard_analyze_pe_json.argtypes = [ctypes.c_char_p]
        self.lib.finguard_analyze_pe_json.restype = ctypes.c_void_p

        # int finguard_get_preflight_decision(bool real_procfs)
        self.lib.finguard_get_preflight_decision.argtypes = [ctypes.c_bool]
        self.lib.finguard_get_preflight_decision.restype = ctypes.c_int

        # uint32_t finguard_get_system_risk_score(bool real_procfs)
        self.lib.finguard_get_system_risk_score.argtypes = [ctypes.c_bool]
        self.lib.finguard_get_system_risk_score.restype = ctypes.c_uint32

        # void finguard_free_string(char* ptr)
        self.lib.finguard_free_string.argtypes = [ctypes.c_void_p]
        self.lib.finguard_free_string.restype = None

    def scan_system(self, real_procfs: bool = False) -> Dict[str, Any]:
        """Runs the native C++ pre-flight scan and returns structured JSON dictionary."""
        if self.lib:
            ptr = self.lib.finguard_scan_system_json(real_procfs)
            if not ptr:
                return {"error": "Native engine returned null pointer"}
            try:
                raw_str = ctypes.cast(ptr, ctypes.c_char_p).value.decode('utf-8')
                return json.loads(raw_str)
            finally:
                self.lib.finguard_free_string(ptr)
        else:
            # Fallback to binary execution
            import subprocess
            cmd = [self.binary_path, "--json"]
            if real_procfs:
                cmd.append("--real-procfs")
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return json.loads(res.stdout)

    def analyze_pe(self, filepath: str) -> Dict[str, Any]:
        """Runs native C++ PE file inspection on a given .exe or .dll."""
        if not os.path.exists(filepath):
            return {"error": f"File not found: {filepath}", "valid_pe": False}

        if self.lib:
            c_path = filepath.encode('utf-8')
            ptr = self.lib.finguard_analyze_pe_json(c_path)
            if not ptr:
                return {"error": "Native PE analyzer returned null pointer"}
            try:
                raw_str = ctypes.cast(ptr, ctypes.c_char_p).value.decode('utf-8')
                return json.loads(raw_str)
            finally:
                self.lib.finguard_free_string(ptr)
        else:
            import subprocess
            cmd = [self.binary_path, "--analyze-pe", filepath, "--json"]
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return json.loads(res.stdout)

    def get_preflight_decision(self, real_procfs: bool = False) -> int:
        """Returns 0=Allow, 1=Warn, 2=Review, 3=Block."""
        if self.lib:
            return self.lib.finguard_get_preflight_decision(real_procfs)
        data = self.scan_system(real_procfs)
        decision = data.get("preflight_decision", "BLOCK_LAUNCH")
        mapping = {
            "ALLOW_LAUNCH": 0,
            "WARN_USER": 1,
            "REQUIRE_USER_REVIEW": 2,
            "BLOCK_LAUNCH": 3
        }
        return mapping.get(decision, 3)

    def get_risk_score(self, real_procfs: bool = False) -> int:
        if self.lib:
            return self.lib.finguard_get_system_risk_score(real_procfs)
        data = self.scan_system(real_procfs)
        return data.get("overall_risk_score", 100)
