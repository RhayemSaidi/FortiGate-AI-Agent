from api.client import get


def get_cpu_usage():
    """Get CPU usage statistics."""
    return get("/monitor/system/resource/usage?resource=cpu")


def get_memory_usage():
    """Get memory usage statistics."""
    return get("/monitor/system/resource/usage?resource=mem")


def get_active_sessions():
    """
    Get active session count.
    Tries multiple endpoints for compatibility across FortiOS versions.
    FIX: previous single endpoint returned 404 on FortiOS 7.6.
    """
    # Try endpoints in order — return first successful response
    endpoints = [
        "/monitor/system/session/select",
        "/monitor/system/resource/usage?resource=session",
        "/monitor/system/session/full-stat",
    ]
    last_error = None
    for endpoint in endpoints:
        try:
            r = get(endpoint)
            if r.get("status") == "success":
                return r
            if r.get("http_status") != 404:
                return r
            last_error = r
        except Exception as exc:
            last_error = {"status": "error", "message": str(exc)}
    return last_error or {"status": "error",
                          "message": "No session endpoint available"}


def get_bandwidth():
    """Get bandwidth usage per interface."""
    return get("/monitor/system/interface/bandwidth")


def get_fortigate_status():
    """Get full system status summary."""
    return get("/monitor/system/status")