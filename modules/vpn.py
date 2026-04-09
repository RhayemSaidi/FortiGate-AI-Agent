from api.client import get, post, delete

def list_ipsec_tunnels():
    """List all IPsec VPN phase1 tunnels"""
    return get("/cmdb/vpn.ipsec/phase1-interface")

def get_vpn_status():
    """Get live VPN tunnel status"""
    return get("/monitor/vpn/ipsec")

def list_ssl_vpn_users():
    """List active SSL VPN sessions"""
    return get("/monitor/vpn/ssl")

def delete_ipsec_tunnel(name):
    """Delete an IPsec tunnel by name"""
    return delete(f"/cmdb/vpn.ipsec/phase1-interface/{name}")