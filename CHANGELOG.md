# Changelog

## 1.2.0 - 2026-11-16
- **Deep scan**: opens every file on every drive and detects programs disguised as other file types.
- **Coverage report**: every scan logs files opened, programs checked, and folders/files it could not read.
- **Quarantine & restore** (command line and dashboard), with an admin prompt only when Windows requires it.
- **Auto-quarantine** of files containing the exact virus code (on by default, switchable).
- Dashboard redesign (Apple HIG-inspired): status hero, cards, one primary action with secondary scan buttons,
  and a threat history with live status (Still on your PC / Quarantined / Deleted / Removed / Replaced (clean)).
- Custom logo, used for the window, taskbar, tray icon and shortcuts.
- Automated test suite with harmless samples (22 tests).
- `SIMPLEAV_HOME` override; one-click `Install.cmd` / `Uninstall.cmd`.
- README states the scope clearly: the signature matches one specific virus family.

## 1.1.0
- First dashboard window: status, scan buttons with live progress, findings list.
- Installs outside AppData so scheduled tasks always find it.

## 1.0.0
- Scanner: exact-signature + structural detection of the file infector, system signature checks,
  DLL-hijack detection, startup/persistence checks.
- Real-time watcher with notifications; daily scheduled scan; self-integrity check.
