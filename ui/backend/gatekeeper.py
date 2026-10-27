import time
from typing import Dict, List, Any, Optional
from ui.backend.core_bridge import FinGuardBridge

DEFAULT_PROTECTED_TARGETS = [
    {
        "id": "cbe_bank",
        "name": "Commercial Bank of Ethiopia (CBE)",
        "category": "Mobile & Web Banking",
        "target_type": "web",
        "url": "https://www.cbe.com.et",
        "icon": "bank",
        "enforce_strict": True,
        "description": "Primary Ethiopian state-owned commercial bank portal."
    },
    {
        "id": "telebirr",
        "name": "Telebirr Digital Wallet",
        "category": "Digital Wallet",
        "target_type": "app_or_web",
        "url": "https://telebirr.et",
        "process_name": "telebirr.exe",
        "icon": "wallet",
        "enforce_strict": True,
        "description": "Ethio Telecom mobile money and digital wallet gateway."
    },
    {
        "id": "boa_bank",
        "name": "Bank of Abyssinia (BOA)",
        "category": "Commercial Bank",
        "target_type": "web",
        "url": "https://www.bankofabyssinia.com",
        "icon": "credit-card",
        "enforce_strict": True,
        "description": "Digital banking & internet banking portal."
    },
    {
        "id": "dashen_amole",
        "name": "Dashen Bank (Amole)",
        "category": "Commercial Bank",
        "target_type": "web",
        "url": "https://dashenbanksc.com",
        "icon": "shield",
        "enforce_strict": True,
        "description": "Amole digital payment platform and banking."
    },
    {
        "id": "awash_bank",
        "name": "Awash Bank Online",
        "category": "Commercial Bank",
        "target_type": "web",
        "url": "https://www.awashbank.com",
        "icon": "landmark",
        "enforce_strict": True,
        "description": "Internet banking portal for Awash International Bank."
    }
]

class PreFlightGatekeeper:
    def __init__(self, bridge: Optional[FinGuardBridge] = None):
        self.bridge = bridge or FinGuardBridge()
        self.targets = {t["id"]: t for t in DEFAULT_PROTECTED_TARGETS}
        self.remediated_pids = set()

    def get_targets(self) -> List[Dict[str, Any]]:
        return list(self.targets.values())

    def add_custom_target(self, target: Dict[str, Any]):
        self.targets[target["id"]] = target

    def simulate_terminate_threat(self, pid: int) -> bool:
        """Simulates terminating an offending process during pre-flight remediation."""
        self.remediated_pids.add(pid)
        return True

    def reset_remediation(self):
        self.remediated_pids.clear()

    def check_preflight_for_target(self, target_id: str, real_procfs: bool = False) -> Dict[str, Any]:
        target = self.targets.get(target_id)
        if not target:
            return {"error": f"Target {target_id} not found in registry", "allowed": False}

        scan_result = self.bridge.scan_system(real_procfs)

        # Filter out any threats that the user terminated in this session
        filtered_threats = []
        for t in scan_result.get("top_threats", []):
            if t["pid"] not in self.remediated_pids:
                filtered_threats.append(t)

        recalculated_score = 0
        if filtered_threats:
            recalculated_score = max(t["final_score"] for t in filtered_threats)

        allowed = (recalculated_score < 60) if target.get("enforce_strict") else (recalculated_score < 100)
        decision = "ALLOW_LAUNCH" if recalculated_score < 30 else (
            "WARN_USER" if recalculated_score < 60 else (
                "REQUIRE_USER_REVIEW" if recalculated_score < 100 else "BLOCK_LAUNCH"
            )
        )

        tier = "CLEAN" if recalculated_score < 30 else (
            "GUARDED" if recalculated_score < 60 else (
                "ELEVATED" if recalculated_score < 100 else "CRITICAL"
            )
        )

        return {
            "target": target,
            "timestamp": time.time(),
            "allowed": allowed,
            "decision": decision,
            "risk_score": recalculated_score,
            "tier": tier,
            "threat_count": len(filtered_threats),
            "threats": filtered_threats,
            "critical_blockers": scan_result.get("critical_blockers", []) if not allowed else [],
            "remediation_steps": [
                s for s in scan_result.get("remediation_steps", [])
                if not any(f"PID {p}" in s for p in self.remediated_pids)
            ],
            "total_processes": scan_result.get("total_processes", 0)
        }
