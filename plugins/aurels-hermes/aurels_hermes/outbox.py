"""Bounded disk-backed retry queue for already-redacted telemetry events."""

import hashlib
import json
import os
import errno
from pathlib import Path
import tempfile
import threading
import logging
import time
from contextlib import contextmanager

MAX_EVENTS = 1000
MAX_BYTES = 8 * 1024 * 1024
MAX_EVENT_BYTES = 64_000
MAX_EVENT_AGE_SECONDS = 7 * 24 * 60 * 60
MAX_STAGING_AGE_SECONDS = 24 * 60 * 60
FLUSH_BATCH_SIZE = 20
INITIAL_RETRY_DELAY_SECONDS = 1.0
MAX_RETRY_DELAY_SECONDS = 60.0
_LOGGER = logging.getLogger("aurels_hermes.outbox")


def _probe_process(pid):
    """Raise ProcessLookupError only for a demonstrably exited owner."""
    if os.name != "nt":
        os.kill(pid, 0)
        return
    # os.kill(pid, 0) calls TerminateProcess on Windows. A zero-time wait
    # observes process state without delivering a signal or terminating it.
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
    if not handle:
        error = ctypes.get_last_error()
        if error == 87:  # ERROR_INVALID_PARAMETER: no such PID
            raise ProcessLookupError(pid)
        if error == 5:  # ERROR_ACCESS_DENIED: leave this owner's lock intact
            raise PermissionError(pid)
        raise ctypes.WinError(error)
    try:
        state = kernel.WaitForSingleObject(handle, 0)
        if state == 0:  # WAIT_OBJECT_0: terminated
            raise ProcessLookupError(pid)
        if state != 258:  # WAIT_TIMEOUT: still running
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.CloseHandle(handle)


def default_spool_dir():
    override = os.getenv("AURELS_TELEMETRY_SPOOL_DIR")
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        root = Path(os.getenv("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        return root / "Aurels" / "plugins" / "hermes" / "telemetry"
    if os.uname().sysname == "Darwin":
        return Path.home() / "Library" / "Application Support" / "Aurels" / "plugins" / "hermes" / "telemetry"
    root = Path(os.getenv("XDG_STATE_HOME") or Path.home() / ".local" / "state")
    return root / "aurels" / "plugins" / "hermes" / "telemetry"


class TelemetryOutbox:
    def __init__(self, directory):
        self.directory = Path(directory).expanduser().absolute()
        self._lock = threading.Lock()
        self._flush_lock = threading.Lock()
        self._retry_guard = threading.Lock()
        self._retry_timer = None
        self._retry_delay = INITIAL_RETRY_DELAY_SECONDS
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.directory.is_symlink() or not self.directory.is_dir():
            raise ValueError("Telemetry spool path must be a real directory")
        try:
            self.directory.chmod(0o700)
        except OSError:
            # Windows ACLs are inherited from LOCALAPPDATA; chmod is best effort there.
            if os.name != "nt":
                raise

    def enqueue(self, event):
        serialized = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(serialized) > MAX_EVENT_BYTES:
            raise ValueError("Telemetry event exceeds the local spool limit")
        digest = hashlib.sha256(serialized).hexdigest()
        destination = self.directory / f"{digest}.json"
        with self._lock, self._queue_lock():
            self._purge_expired()
            if destination.exists():
                return destination
            queued = self._queued_files()
            queued_bytes = sum(path.stat().st_size for path in queued)
            if len(queued) >= MAX_EVENTS or queued_bytes + len(serialized) > MAX_BYTES:
                raise OSError("Telemetry spool is full; event was not persisted")
            descriptor, temporary_name = tempfile.mkstemp(prefix=".pending-", suffix=".tmp", dir=self.directory)
            temporary = Path(temporary_name)
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    os.chmod(temporary, 0o600)
                    stream.write(serialized)
                    stream.flush()
                    os.fsync(stream.fileno())
                try:
                    os.link(temporary, destination)
                except FileExistsError:
                    pass
                except OSError as error:
                    if error.errno not in {errno.EPERM, errno.ENOTSUP, getattr(errno, "EOPNOTSUPP", errno.ENOTSUP)}:
                        raise
                    if not destination.exists():
                        os.replace(temporary, destination)
            finally:
                temporary.unlink(missing_ok=True)
        return destination

    @contextmanager
    def _queue_lock(self):
        lock_path = self.directory / ".enqueue.lock"
        deadline = time.monotonic() + 0.5
        descriptor = None
        while descriptor is None:
            try:
                descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.write(descriptor, str(os.getpid()).encode("ascii"))
                os.fsync(descriptor)
            except FileExistsError:
                if self._stale_queue_lock(lock_path):
                    self._unlink_queue_lock(lock_path)
                elif time.monotonic() >= deadline:
                    raise OSError("Telemetry queue is busy; event was not persisted")
                else:
                    time.sleep(0.01 + (os.getpid() % 7) / 1000)
            except Exception:
                if descriptor is not None:
                    os.close(descriptor)
                    descriptor = None
                    self._unlink_queue_lock(lock_path)
                raise
        try:
            yield
        finally:
            os.close(descriptor)
            self._unlink_queue_lock(lock_path)

    @staticmethod
    def _unlink_queue_lock(lock_path):
        deadline = time.monotonic() + 0.5
        while True:
            try:
                lock_path.unlink(missing_ok=True)
                return
            except PermissionError as error:
                # Windows can briefly deny unlink while a competing stale-lock
                # check has the lock file open. Retry only that sharing error.
                if os.name != "nt" or getattr(error, "winerror", None) != 32 or time.monotonic() >= deadline:
                    raise
                time.sleep(0.005)

    @staticmethod
    def _stale_queue_lock(lock_path):
        try:
            info = lock_path.lstat()
            if lock_path.is_symlink() or not lock_path.is_file():
                return False
            try:
                pid = int(lock_path.read_text(encoding="ascii"))
            except (OSError, ValueError):
                return time.time() - info.st_mtime > 30
            if pid <= 0:
                return time.time() - info.st_mtime > 30
            try:
                _probe_process(pid)
                return False
            except ProcessLookupError:
                # A competing writer may replace the path while the PID probe
                # runs. Only classify the lock as stale if it is still the
                # same file instance and still contains the inspected PID.
                try:
                    current = lock_path.lstat()
                    if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
                        return False
                    return lock_path.read_text(encoding="ascii") == str(pid)
                except OSError:
                    return False
            except PermissionError:
                return False
            except OSError:
                # Unknown process state is not evidence that a lock is stale.
                return False
        except FileNotFoundError:
            # The owner may have released the lock between the caller's
            # FileExistsError and this inspection. Never unlink a path we
            # did not observe; a new writer may already have recreated it.
            return False

    def flush(self, sender):
        with self._flush_lock:
            return self._flush_queued(sender)

    def flush_async(self, sender):
        if not self._flush_lock.acquire(blocking=False):
            return False
        with self._retry_guard:
            if self._retry_timer is not None:
                self._retry_timer.cancel()
                self._retry_timer = None

        def run():
            delivered = 0
            try:
                delivered = self._flush_queued(sender)
            except FileNotFoundError:
                # The user or test owner may remove the spool while a retry is pending.
                pass
            except Exception as error:
                _LOGGER.warning("Aurels telemetry outbox flush failed (%s)", type(error).__name__)
            finally:
                self._flush_lock.release()
            if self._queued_files():
                if delivered >= FLUSH_BATCH_SIZE:
                    self.flush_async(sender)
                else:
                    self._schedule_retry(sender)
            else:
                with self._retry_guard:
                    self._retry_delay = INITIAL_RETRY_DELAY_SECONDS

        thread = threading.Thread(target=run, name="aurels-telemetry-flush", daemon=True)
        try:
            thread.start()
        except Exception:
            self._flush_lock.release()
            raise
        return True

    def _schedule_retry(self, sender):
        with self._retry_guard:
            if self._retry_timer is not None:
                return
            delay = self._retry_delay
            self._retry_delay = min(self._retry_delay * 2, MAX_RETRY_DELAY_SECONDS)

            def retry():
                with self._retry_guard:
                    self._retry_timer = None
                self.flush_async(sender)

            timer = threading.Timer(delay, retry)
            timer.daemon = True
            self._retry_timer = timer
            timer.start()

    def _flush_queued(self, sender):
        delivered = 0
        with self._lock:
            self._purge_expired()
        for path in self._queued_files():
            if delivered >= FLUSH_BATCH_SIZE:
                break
            try:
                if path.is_symlink() or path.stat().st_size > MAX_EVENT_BYTES:
                    continue
                event = json.loads(path.read_text(encoding="utf-8"))
                sender(event)
            except Exception:
                # Keep the event for a later retry; stop to avoid hot-looping a failing endpoint.
                break
            with self._lock:
                path.unlink(missing_ok=True)
            delivered += 1
        return delivered

    def _queued_files(self):
        return sorted(path for path in self.directory.glob("*.json") if path.is_file() and not path.is_symlink())

    def _purge_expired(self):
        now = time.time()
        for path in self.directory.iterdir():
            try:
                if path.name.startswith(".pending-") and path.name.endswith(".tmp"):
                    if path.is_file() and not path.is_symlink() and now - path.stat().st_mtime > MAX_STAGING_AGE_SECONDS:
                        path.unlink(missing_ok=True)
                    continue
                if path.suffix == ".json" and path.is_file() and not path.is_symlink() and now - path.stat().st_mtime > MAX_EVENT_AGE_SECONDS:
                    path.unlink(missing_ok=True)
                    _LOGGER.warning("Aurels telemetry event expired from the local outbox")
            except OSError:
                continue
