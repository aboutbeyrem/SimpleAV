# Changelog

Versions 1.0 to 1.2 were built and used locally on the infected PC; this repository starts at 1.2.0, published
on 2026-11-17.

## 1.3.0 - 2026-11-17
Hardening after a code review, and after the infection came back on the PC this tool was built for.
- **Shared detection core** (`src/SimpleAV.Detection.ps1`): the scanner and the dashboard now use one PE parser
  instead of two copies that had drifted apart. Headers longer than 4 KB are re-read (up to 64 KB) instead of being
  treated as clean, and files that can't be read show as "Check details" instead of a false red alert.
- **Safer restore:** refuses to overwrite an existing file (exit 4), refuses when the file's SHA-256 doesn't match its
  quarantine record or the record's path is tampered (exit 3), and only asks for admin rights when Windows really
  denies access (exit 5). A locked file now reports "in use" (exit 6) instead of triggering a useless admin prompt.
- **Quarantine** accepts single files only; a folder path is never moved wholesale.
- **Watcher:** drains event bursts without starving the process and startup checks, logs FileSystemWatcher
  overflows, tracks processes by ID + start time, and uses a per-data-folder lock instead of command-line matching.
- **Self-whitelisting fixed:** processes and startup entries were skipped if their command line merely *contained*
  `SimpleAV.ps1`; now only SimpleAV's own scripts, matched by full path, are skipped. The self-exclusion folder check
  no longer matches neighbours like `SimpleAVUpdate\`.
- **Faster scans:** Authenticode results are cached by path + size + last-write time (Quick scan: 169 s → 41 s on
  the second run); the MSBuild-copy check runs
  during the main walk instead of a second recursive pass over the user profile.
- **Self-integrity** now covers all three scripts; reinstalling stops the old watcher so the new version takes over.
- **Dashboard:** no more stacked "Scan finished" dialogs; correct status for HKLM Winlogon entries, scheduled tasks in
  sub-folders and reused process IDs; scan numbers parse correctly from French-language Windows logs; test samples
  no longer inflate the quarantine count; specific error messages for each restore/quarantine failure.
- **Tests:** 22 → 47. Samples moved out of the watched folders so an installed watcher can't grab them mid-test.
- README rewritten: architecture, the reinfection story, and what to do when SimpleAV finds something.

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
