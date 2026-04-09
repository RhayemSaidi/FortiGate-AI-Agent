from api.client import get

def get_system_status():
    return get("/monitor/system/status")