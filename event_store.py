from collections import deque
from datetime import datetime

# Holds latest 200 events
event_log = deque(maxlen=200)

def add_event(event_type, file_path, hashes=None, vt_result=None):
    event = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "type": event_type,
        "file_path": file_path,
        "hashes": hashes,
        "vt_result": vt_result,
    }
    event_log.append(event)

def get_events():
    return list(event_log)