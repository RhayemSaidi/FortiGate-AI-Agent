from api.client import get

def get_traffic_logs():
    """Get recent traffic logs"""
    return get("/monitor/log/traffic?logtype=traffic&rows=50")

def get_threat_logs():
    """Get recent threat/attack logs"""
    return get("/monitor/log/threat?rows=50")

def get_event_logs():
    """Get recent system event logs"""
    return get("/monitor/log/event?rows=50")