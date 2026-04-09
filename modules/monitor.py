from api.client import get

def get_cpu_usage():
    """Get current CPU usage"""
    return get("/monitor/system/resource/usage?resource=cpu")

def get_memory_usage():
    """Get current memory usage"""
    return get("/monitor/system/resource/usage?resource=mem")

def get_active_sessions():
    """Get number of active firewall sessions"""
    return get("/monitor/system/session/select")

def get_bandwidth():
    """Get current bandwidth usage per interface"""
    return get("/monitor/system/interface/bandwidth")

def get_fortigate_status():
    """Get full system status summary"""
    return get("/monitor/system/status")