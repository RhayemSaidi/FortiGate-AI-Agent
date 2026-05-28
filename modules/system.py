from api.client import get, post


def get_system_status():
    return get("/monitor/system/status")


def get_system_performance():
    """Returns CPU and memory usage. Endpoint: /monitor/system/performance/status"""
    return get("/monitor/system/performance/status")


def reboot_system():
    return post("/monitor/system/os/reboot", {})