import sys
import os

# Add agent directory to path
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_AGENT_DIR = os.path.join(_THIS_DIR, "..", "agent")
sys.path.insert(0, _AGENT_DIR)
sys.path.insert(0, os.path.join(_THIS_DIR, ".."))

from router import route, RouteCategory
from safety_guards import validate_delete_route, validate_set_interface_status
from unittest.mock import patch
from dataclasses import dataclass

ROUTER_CASES = [
    # 1. Ambiguous Knowledge vs Live Read
    ("What does policy 4 do?", RouteCategory.LIVE_READ),
    ("How do I configure a policy?", RouteCategory.KNOWLEDGE),
    ("Is NAT enabled on policy BlockSSH?", RouteCategory.LIVE_READ),
    ("What is NAT?", RouteCategory.KNOWLEDGE),
    
    # 2. Security Analysis
    ("Check my firewall for vulnerabilities", RouteCategory.SECURITY_ANALYSIS),
    ("Are there any insecure policies?", RouteCategory.SECURITY_ANALYSIS),
    
    # 3. Write Actions
    ("Delete policy 5", RouteCategory.WRITE_ACTION),
    ("Enable NAT in policy 10", RouteCategory.WRITE_ACTION),
    ("Block IP 1.2.3.4", RouteCategory.WRITE_ACTION),
    ("Reboot the firewall", RouteCategory.WRITE_ACTION),
    
    # 4. French Bilingual Edge Cases
    ("Qu'est-ce que fait la politique 4 ?", RouteCategory.LIVE_READ),
    ("Supprimer la politique 5", RouteCategory.WRITE_ACTION),
    ("Analyse la sécurité de mon pare-feu", RouteCategory.SECURITY_ANALYSIS),
]

def run_router_tests():
    print("=" * 60)
    print("ROUTER DETERMINISTIC TESTS")
    print("=" * 60)
    passed = 0
    for text, expected in ROUTER_CASES:
        # We test the deterministic stage 1 (passing None for LLM)
        # If it returns UNKNOWN, it implies it needs Stage 2 (LLM)
        res = route(text, None) 
        if res.category == expected:
            print(f"[PASS] {text[:40]:<40} -> {expected.name}")
            passed += 1
        elif res.category == RouteCategory.UNKNOWN:
            print(f"[LLM ] {text[:40]:<40} -> (Proceeds to Stage 2)")
        else:
            print(f"[FAIL] {text[:40]:<40} -> Expected {expected.name}, Got {res.category.name}")
    print(f"\nRouter Tests: {passed}/{len(ROUTER_CASES)} passed at Stage 1.")


@patch('safety_guards._get_routes')
def run_safety_guard_tests(mock_routes):
    print("\n" + "=" * 60)
    print("SAFETY GUARD ADVERSARIAL TESTS")
    print("=" * 60)
    
    # Mocking the FortiGate routing table
    mock_routes.return_value = [
        {"seq-num": 1, "dst": "0.0.0.0 0.0.0.0", "gateway": "192.168.1.1", "device": "port1"},
        {"seq-num": 2, "dst": "10.0.0.0 255.0.0.0", "gateway": "10.0.0.1", "device": "port2"}
    ]
    
    # Test 1: Deleting the default route (MUST BE BLOCKED)
    res = validate_delete_route({"route_id": "1"})
    if not res.valid and "BLOCKED" in res.errors[0]:
        print(f"[PASS] Default route deletion blocked successfully: {res.errors[0]}")
    else:
        print(f"[FAIL] Default route deletion was NOT blocked!")
        
    # Test 2: Deleting a normal route (SHOULD WARN, NOT BLOCK)
    res2 = validate_delete_route({"route_id": "2"})
    if res2.valid and len(res2.warnings) > 0:
        print(f"[PASS] Normal route deletion allowed with warning: {res2.warnings[0]}")
    else:
        print(f"[FAIL] Normal route deletion failed validation: {res2.errors}")
        
    # Test 3: Deleting nonexistent route
    res3 = validate_delete_route({"route_id": "99"})
    if not res3.valid and "does not exist" in res3.errors[0]:
        print(f"[PASS] Nonexistent route deletion rejected.")
    else:
        print(f"[FAIL] Nonexistent route deletion handled incorrectly.")

if __name__ == "__main__":
    run_router_tests()
    run_safety_guard_tests()
