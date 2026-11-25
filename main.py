"""Bastion: 24/7 guard that works alongside your antivirus.   main.py [--tray] [--keepalive] [--stop] [--uninstall]"""
import ctypes
import multiprocessing
import os
import sys
import threading
import zlib

from bastion import core

# Named per sign-in session, so two people signed in to one PC each get their own guard.
TAG = format(zlib.crc32(os.environ["BASTION_DATA"].encode()), "x") if "BASTION_DATA" in os.environ else ""      # a copy with its own data folder is its own guard
MUTEX, SHOW, STOP = (f"Local{chr(92)}Bastion{n}{TAG}" for n in ("Guard", "Show", "Stop"))
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.CreateMutexW.restype = k32.CreateEventW.restype = ctypes.c_void_p
for fn in (k32.SetEvent, k32.CloseHandle):
    fn.argtypes = [ctypes.c_void_p]
k32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]


def main():
    k32.SetDllDirectoryW("")        # never load a library from whatever folder this was started in
    os.chdir(core.SYSTEM32)
    show, stop = k32.CreateEventW(None, False, False, SHOW), k32.CreateEventW(None, False, False, STOP)
    if "--stop" in sys.argv or "--uninstall" in sys.argv:
        k32.SetEvent(stop)
        if "--uninstall" in sys.argv:
            core.remove_traces()
        return 0
    settings = core.Settings()
    keepalive = "--keepalive" in sys.argv
    if keepalive and settings["stopped_by_user"]:
        return 0
    lock = k32.CreateMutexW(None, False, MUTEX)
    if not lock or ctypes.get_last_error() == 183:
        if not keepalive:           # already running: ask it to show its window
            k32.SetEvent(show)
        return 0
    k32.WaitForSingleObject(stop, 0)    # an old request is not for this run

    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication
    from bastion.engine import Intel, Quarantine
    from bastion.guards import Context
    from bastion.gui import Window

    if settings["stopped_by_user"]:
        settings["stopped_by_user"] = False
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    ctx = Context(settings, core.EventLog(), Intel(), Quarantine())
    win = Window(ctx)
    asked, ending = threading.Event(), threading.Event()

    def listen(handle, flag):
        while k32.WaitForSingleObject(handle, 0xFFFFFFFF) == 0:
            flag.set()
    for handle, flag in ((show, asked), (stop, ending)):
        threading.Thread(target=listen, args=(handle, flag), daemon=True).start()

    def poll():
        if ending.is_set():
            app.quit()
        elif asked.is_set():
            asked.clear()
            win.bring_up()
    timer = QTimer()
    timer.timeout.connect(poll)
    timer.start(400)
    if "--tray" not in sys.argv:
        win.show()
        win.welcome()
    ctx.start()
    code = app.exec()
    for pid in list(ctx.held):
        ctx.release(pid)
    ctx.shutdown()
    return code


if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(main())
