import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from hashing import compute_hashes
from vt import check_filehash_virustotal
from event_store import add_event
from logger import log_event
from notifier import notify


WATCH_FOLDER = "watch_folder"
os.makedirs(WATCH_FOLDER, exist_ok=True)


class ThreatWatchHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return

        file_path = event.src_path
        print(f"[Watchdog] New file: {file_path}")

        hashes = compute_hashes(file_path)
        vt_result = check_filehash_virustotal(hashes["sha256"])

        add_event(
            event_type="file_created",
            file_path=file_path,
            hashes=hashes,
            vt_result=vt_result,
        )

        log_event(
            event_type="watchdog_file_created",
            file_path=file_path,
            hashes=hashes,
            vt_result=vt_result
        )
        notify(
            event_type="watchdog_file_created",
            file_path=file_path,
            hashes=hashes,
            vt_result=vt_result
        )


def start_watcher():
    observer = Observer()
    handler = ThreatWatchHandler()
    observer.schedule(handler, WATCH_FOLDER, recursive=False)

    observer.start()
    print(f"[Watchdog] Monitoring: {WATCH_FOLDER}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()


if __name__ == "__main__":
    start_watcher()
