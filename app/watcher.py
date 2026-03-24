"""
watcher.py — Fixed Real-time log file watcher
=============================================
Key fix: stores the event loop reference at start() time (after FastAPI
startup), so the thread->asyncio bridge always has the correct loop.
"""

import asyncio
import os
import threading
from pathlib import Path
from typing import Callable

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


class LogWatcher:
    def __init__(self, watch_path: str, on_new_line: Callable[[str, str], None]):
        self.watch_path      = os.path.abspath(watch_path)
        self.on_new_line     = on_new_line
        self._file_positions: dict[str, int] = {}
        self._lock           = threading.Lock()
        self._observer       = Observer()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._handler        = _LogFileHandler(self._on_file_event)

    def start(self, loop: asyncio.AbstractEventLoop):
        """
        Call AFTER the asyncio event loop is running.
        Pass the running loop explicitly so the thread bridge works.
        """
        self._loop = loop

        watch_dir = str(Path(self.watch_path).parent) if os.path.isfile(self.watch_path) \
                    else self.watch_path
        os.makedirs(watch_dir, exist_ok=True)

        self._observer.schedule(self._handler, watch_dir, recursive=False)
        self._observer.daemon = True
        self._observer.start()
        print(f"[LogWatcher] Watching: {watch_dir}")

    def stop(self):
        self._observer.stop()
        self._observer.join()

    def update_loop(self, loop: asyncio.AbstractEventLoop):
        """Call if the loop reference needs to be refreshed."""
        self._loop = loop

    def _on_file_event(self, filepath: str):
        ext = Path(filepath).suffix.lower()
        if ext not in {".log", ".txt", ".out"}:
            return
        if os.path.isfile(self.watch_path):
            if os.path.abspath(filepath) != self.watch_path:
                return
        self._tail_new_lines(filepath)

    def _tail_new_lines(self, filepath: str):
        with self._lock:
            try:
                current_size = os.path.getsize(filepath)
                last_pos     = self._file_positions.get(filepath, 0)
                if current_size < last_pos:
                    last_pos = 0
                if current_size == last_pos:
                    return
                with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(last_pos)
                    new_content = f.read()
                    self._file_positions[filepath] = f.tell()
                for line in new_content.splitlines():
                    line = line.strip()
                    if line:
                        self._schedule(filepath, line)
            except (OSError, IOError) as e:
                print(f"[LogWatcher] Read error: {e}")

    def _schedule(self, filepath: str, line: str):
        """Safely schedule on_new_line onto the asyncio event loop from any thread."""
        if self._loop is None or not self._loop.is_running():
            return
        asyncio.run_coroutine_threadsafe(
            self._async_emit(filepath, line),
            self._loop
        )

    async def _async_emit(self, filepath: str, line: str):
        self.on_new_line(filepath, line)


class _LogFileHandler(FileSystemEventHandler):
    def __init__(self, callback):
        self._cb = callback

    def on_modified(self, event):
        if not event.is_directory:
            self._cb(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self._cb(event.src_path)