import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from modules.system import get_system_status
from modules.monitor import get_cpu_usage, get_memory_usage, get_active_sessions
from modules.policies import list_policies, create_policy
from modules.addresses import list_addresses, create_address, delete_address
from modules.interfaces import list_interfaces
from modules.routing import list_routes
from modules.users import list_users
from modules.vpn import get_vpn_status
from modules.backup import backup_config

def test_separator(title):
    print(f"\n{'='*40}")
    print(f"  {title}")
    print(f"{'='*40}")

# ── 1. System ──────────────────────────────
test_separator("SYSTEM STATUS")
status = get_system_status()
print(f"Hostname : {status['results'].get('hostname')}")
print(f"Model    : {status['results'].get('model_name')}")
print(f"Version  : {status.get('version')}")

# ── 2. Monitor ─────────────────────────────
test_separator("MONITOR")
cpu = get_cpu_usage()
mem = get_memory_usage()
print(f"CPU    : {cpu['results']['cpu'][0]['current']}%")
print(f"Memory : {mem['results']['mem'][0]['current']}%")

# ── 3. Policies ────────────────────────────
test_separator("FIREWALL POLICIES")
policies = list_policies()
results = policies if isinstance(policies, list) else policies.get("results", [])
for p in results:
    print(f"  [{p.get('policyid')}] {p.get('name')} — action: {p.get('action')}")

# ── 4. Addresses ───────────────────────────
test_separator("ADDRESS OBJECTS")
addresses = list_addresses()
for a in addresses.get("results", [])[:5]:  # show first 5 only
    print(f"  {a.get('name')} — {a.get('subnet')}")

# ── 5. Test create + delete address ────────
test_separator("CREATE & DELETE ADDRESS TEST")
print("Creating TestServer...")
r = create_address("TestServer", "10.10.10.10/32")
print("Result:", r.get("status"))
print("Deleting TestServer...")
r = delete_address("TestServer")
print("Result:", r.get("status"))

# ── 6. Interfaces ──────────────────────────
test_separator("INTERFACES")
ifaces = list_interfaces()
for i in ifaces.get("results", [])[:5]:
    print(f"  {i.get('name')} — {i.get('ip')} — status: {i.get('status')}")

# ── 7. Routes ──────────────────────────────
test_separator("STATIC ROUTES")
routes = list_routes()
for r in routes.get("results", []):
    print(f"  dst: {r.get('dst')} via {r.get('gateway')} on {r.get('device')}")

# ── 8. Users ───────────────────────────────
test_separator("LOCAL USERS")
users = list_users()
for u in users.get("results", []):
    print(f"  {u.get('name')} — status: {u.get('status')}")

# ── 9. VPN ─────────────────────────────────
test_separator("VPN STATUS")
print(get_vpn_status())

# ── 10. Backup ─────────────────────────────
test_separator("BACKUP CONFIG")
result = backup_config()
print(result)