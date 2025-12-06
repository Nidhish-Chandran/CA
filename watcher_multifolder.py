# watcher_multifolder.py

import time
import threading
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from hashing import compute_hashes
from vt import check_filehash_virustotal
from event_store import add_event
from logger import log_event
from notifier import notify
from watcher_config import WATCH_FOLDERS


# Ensure folders exist
for folder in WATCH_FOLDERS:
    os.makedirs(folder, exist_ok=True)


def wait_until_file_is_ready(path):
    """Wait until the file is fully written and unlocked."""
    last_size = -1

    while True:
        try:
            current_size = os.path.getsize(path)

            # If size stable → file is ready
            if current_size == last_size and current_size > 0:
                with open(path, "rb"):
                    return True

            last_size = current_size
            time.sleep(0.5)

        except (PermissionError, FileNotFoundError):
            time.sleep(0.3)


class ThreatWatchHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return

        file_path = event.src_path
        print(f"[Watchdog] New file detected: {file_path}")

        # FULLY SAFE WAIT
        wait_until_file_is_ready(file_path)

        # Compute hashes
        hashes = compute_hashes(file_path)

        # VT Check
        vt_result = check_filehash_virustotal(hashes["sha256"])

        # Store in event_store
        add_event(
            event_type="file_created",
            file_path=file_path,
            hashes=hashes,
            vt_result=vt_result
        )

        # Log
        log_event(
            event_type="watchdog_file_created",
            file_path=file_path,
            hashes=hashes,
            vt_result=vt_result
        )

        # Notify
        notify(
            event_type="watchdog_file_created",
            file_path=file_path,
            hashes=hashes,
            vt_result=vt_result
        )


def start_watcher(folder):
    observer = Observer()
    handler = ThreatWatchHandler()
    observer.schedule(handler, folder, recursive=False)
    observer.start()
    print(f"[Watchdog] Monitoring: {folder}")
    observer.join()


threads = []
for folder in WATCH_FOLDERS:
    t = threading.Thread(target=start_watcher, args=(folder,), daemon=True)
    t.start()
    threads.append(t)

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("[Watchdog] Stopping all observers...")
