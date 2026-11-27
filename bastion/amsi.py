"""Asks the installed antivirus (through Windows' Antimalware Scan Interface) about content Bastion holds in memory.

This lets Microsoft Defender, or whichever antivirus is installed, judge scripts and web pages - including the hidden layers Bastion
has decoded, which a normal file scan never sees. Nothing is written to disk and nothing leaves the PC because of it; a detection is
also recorded by the antivirus itself."""
import ctypes
import threading

DETECTED = 32768        # AMSI_RESULT_DETECTED and above


class Amsi:
    def __init__(self, app="Bastion"):
        self.app, self._ctx, self._dll, self._lock, self.error = app, None, None, threading.Lock(), ""

    def _ready(self):
        if self._ctx is not None:
            return True
        if self.error:
            return False
        try:
            dll = ctypes.WinDLL("amsi")
            ctx = ctypes.c_void_p()
            if dll.AmsiInitialize(ctypes.c_wchar_p(self.app), ctypes.byref(ctx)) != 0 or not ctx.value:
                raise OSError("AMSI did not start")
            dll.AmsiScanString.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
            dll.AmsiScanBuffer.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_wchar_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
            self._dll, self._ctx = dll, ctx
            return True
        except (OSError, AttributeError) as e:
            self.error = str(e)[:120] or "AMSI is not available"
            return False

    def text(self, content, name):
        """True if the antivirus says this text is malware, False if not, None if it can't be asked."""
        if not content or not self._ready():
            return None
        res = ctypes.c_int()
        with self._lock:
            hr = self._dll.AmsiScanString(self._ctx, content[:2_000_000], name, None, ctypes.byref(res))
        return None if hr != 0 else res.value >= DETECTED

    def data(self, content, name):
        if not content or not self._ready():
            return None
        buf = ctypes.create_string_buffer(bytes(content[:8_000_000]), min(len(content), 8_000_000))
        res = ctypes.c_int()
        with self._lock:
            hr = self._dll.AmsiScanBuffer(self._ctx, buf, len(buf), name, None, ctypes.byref(res))
        return None if hr != 0 else res.value >= DETECTED
