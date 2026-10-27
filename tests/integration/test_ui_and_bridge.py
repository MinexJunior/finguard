import sys
import os

# Add root directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from ui.backend.core_bridge import FinGuardBridge
from ui.backend.gatekeeper import PreFlightGatekeeper

def test_bridge_initialization():
    bridge = FinGuardBridge()
    assert bridge.lib is not None, "FinGuardBridge must load native libfinguard.so"
    print("[PASSED] test_bridge_initialization (libfinguard.so loaded)")

def test_system_scan_via_c_abi():
    bridge = FinGuardBridge()
    scan = bridge.scan_system(real_procfs=False)
    assert scan["overall_risk_score"] == 100, f"Expected 100 in threat scenario, got {scan['overall_risk_score']}"
    assert scan["risk_tier"] == "CRITICAL"
    assert scan["preflight_decision"] == "BLOCK_LAUNCH"
    assert len(scan["top_threats"]) >= 3
    print(f"[PASSED] test_system_scan_via_c_abi (score: {scan['overall_risk_score']}/100 [{scan['risk_tier']}])")

def test_pe_analysis_via_c_abi():
    bridge = FinGuardBridge()
    pe = bridge.analyze_pe("samples/suspicious_dropper.exe")
    assert pe["valid_pe"] is True
    assert pe["architecture"] == "x64"
    assert len(pe["sections"]) == 2
    # Verify section 2 (.rwx) is detected with packed entropy and RWX flag
    rwx_sec = pe["sections"][1]
    assert rwx_sec["name"] == ".rwx"
    assert rwx_sec["is_rwx"] is True
    assert rwx_sec["is_packed"] is True
    print(f"[PASSED] test_pe_analysis_via_c_abi (section .rwx entropy: {rwx_sec['entropy']:.2f}, RWX: {rwx_sec['is_rwx']})")

def test_preflight_gatekeeper_workflow():
    bridge = FinGuardBridge()
    gatekeeper = PreFlightGatekeeper(bridge)

    # 1. Check initial blocked state
    res1 = gatekeeper.check_preflight_for_target("cbe_bank")
    assert res1["allowed"] is False
    assert res1["decision"] == "BLOCK_LAUNCH"
    assert res1["risk_score"] == 100

    # 2. Remediate critical threats (matching Scenario E: Re-scan after removal)
    gatekeeper.simulate_terminate_threat(4894) # powershell reverse shell
    gatekeeper.simulate_terminate_threat(4112) # svchost impostor
    gatekeeper.simulate_terminate_threat(6200) # untrusted injector
    gatekeeper.simulate_terminate_threat(5500) # UnknownApp.exe (Scenario B threat removed)

    # 3. Check allowed state (Scenario E: Risk returns to low/safe; user continues)
    res2 = gatekeeper.check_preflight_for_target("cbe_bank")
    assert res2["allowed"] is True
    assert res2["risk_score"] < 60
    print(f"[PASSED] test_preflight_gatekeeper_workflow (remediated risk score: {res2['risk_score']}/100, allowed: {res2['allowed']})")

def main():
    print("\n=== Running FinGuard Phase 5 C-ABI Bridge & Gatekeeper Tests ===")
    test_bridge_initialization()
    test_system_scan_via_c_abi()
    test_pe_analysis_via_c_abi()
    test_preflight_gatekeeper_workflow()
    print("=== ALL PHASE 5 INTEGRATION TESTS PASSED SUCCESSFULLY! ===\n")

if __name__ == "__main__":
    main()
