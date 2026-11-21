# ARISE — Windows Keylogger

Authorized-security-testing tool for Windows. Pure Python + ctypes, **zero
dependencies** — uses the low-level keyboard hook (`WH_KEYBOARD_LL`).

## Quick start

| File | What it does |
|------|--------------|
| `arise_start.bat` | Run **visible** (console mirror + log file). Best for testing. |
| `arise_hidden.bat` | Run **hidden** via `pythonw.exe` — no window. |
| `arise_stop.bat` | Create the stop flag → running instance exits cleanly. |
| `arise_persist.bat` | **Optional**: add HKCU Run-key autostart at login. |
| `arise_unpersist.bat` | Remove the autostart entry. |

Logs are written to `logs\arise_YYYY-MM-DD.log` (daily rotation).

## Manual control

```bat
python arise.py                    :: run, logs only
python arise.py --stdout           :: run, mirror keys to console too
python arise.py --log-dir C:\logs  :: custom log directory
python arise.py --stop-file C:\go  :: custom stop-flag path
python arise.py --ignore-injected  :: skip synthetic (SendInput) events
python arise.py --no-window-titles :: disable window-title tracking
```

**Stop:** run `arise_stop.bat`, create `arise.stop` yourself, or press
Ctrl+C in a visible console.

## Log format

```
=== ARISE session start 2026-11-21 14:32:10 | user=X host=Y pid=1234 ===

[14:32:15 | Untitled - Notepad | Notepad.exe] Hello world[ENTER]
[14:32:22 | Search - Google Chrome | chrome.exe] [CTRL+l]https://example.org[ENTER]
```

- `[HH:MM:SS | window title | process.exe]` appears whenever the active
  window changes, then keystrokes follow inline.
- Shift/CapsLock/AltGr are resolved into the actual typed characters.
- Modifiers, arrows, F-keys etc. appear as tokens: `[SHIFT]`, `[LEFT]`,
  `[F5]`, `[CTRL+c]`, `[WIN]`, ...

## Notes

- Single-instance lock: a second copy refuses to start (use `--force` to
  override a stale lock).
- Elevated (admin) windows can't be opened for process-name lookup from a
  non-admin process — the process name shows `(unknown)` there; keystrokes
  are still captured.
- `pythonw.exe` must be on PATH for the hidden launcher (it ships with the
  Microsoft Store Python install).
- Dead keys / IME edge cases may log slightly imperfectly; this is a
  known artifact of `ToUnicode` translation.

Use only on systems you are authorized to assess.
