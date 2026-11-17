# How it works - the infection SimpleAV was built for

This document describes the real infection that SimpleAV was written to detect, how it was
analysed, and how each detection in SimpleAV maps to a technique the malware used.

> All findings below come from my own PC (Windows 10, infected in June 2026, analysed in November 2026): Malwarebytes scan
> results, the registry, scheduled tasks, the Windows Installer database, and byte-level
> inspection of infected program files.

---

## 1. Symptoms

- Malwarebytes repeatedly found and "successfully" removed the same threats
  (`Spyware.DarkSide`, `Trojan.Crypt`, `RiskWare.MSBuild.Abused`), but they **came back after every reboot**.
- New suspicious `.tmp` files kept appearing in `%TEMP%`, and a crypto-miner hidden as `.jpeg` files was found.
- Program files of normal apps (Discord, VS Code, OneDrive, Steam, npm tools...) were flagged as trojans.

## 2. What was actually going on

The infection had several cooperating parts.

### 2.1 A loader installed as fake drivers (PavinLoader)

Two Windows Installer packages were installed from `%TEMP%` in July 2026, pretending to be hardware software:

| Display name | Claimed publisher |
|---|---|
| Wireless Utility | Broadcom Inc. |
| Unifying Agent | Logitech Inc. |

They dropped folders in `%LOCALAPPDATA%\Broadcom\...` and `%LOCALAPPDATA%\Logitech\...` containing a **copy of
`MSBuild.exe`**, a `.csproj` project, a `build.cmd` and a shortcut. MSBuild is a legitimate Microsoft build tool
that can compile and run C# code embedded in a project file. Malware uses it to run code through a trusted,
signed program ("living off the land").

### 2.2 A payload hidden in the registry (fileless persistence)

- The payload was stored **Base64-encoded in a registry value**: `HKCU\Environment\UserCache`,
  with a backup copy under a fake-looking CLSID: `HKCU\Software\Classes\CLSID\{A1B2C3D4-E5F6-7890-1234-567890ABCDEF}`.
- Two **launchers** ran it at every logon:
  - `HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell` =
    `explorer.exe,conhost.exe --headless powershell.exe -w hidden -nop -ep bypass -c "...FromBase64String((Get-ItemProperty 'HKCU:\Environment').UserCache)..."`
  - `HKCU\Environment\UserInitMprLogonScript` = the same command.

**This is why the infection kept coming back.** The antivirus deleted the payload, but not the two launchers,
and the payload was rebuilt at the next logon.

### 2.3 Defender blocked

An *Image File Execution Options* "debugger" was set for `MpCmdRun.exe` (Windows Defender's command-line
scanner), which stops it from running.

### 2.4 A file infector (865 programs patched)

865 program files across many apps had been modified. Comparing infected and clean files showed the pattern:

| | Clean program | Infected program |
|---|---|---|
| Section where execution starts | `.text` (code) | the **last** section, e.g. `.reloc` (normally data) |
| Permissions of that section | read-only data (`0x42000040`) | **read + write + execute** (`0xE0000040`) |
| Digital signature | valid | **gone** (the infector strips it) |
| First bytes executed | normal code | `E8 D9 00 00 00 48 8D 58 FB 51 52 41` in **every** infected file |

So every time one of those programs started, the virus code ran first and then handed control back to the
real program, which is how it kept spreading to other programs.

### 2.5 A DLL hijack in Explorer

An **unsigned 56 KB `omadmapi.dll`** was placed directly in `C:\Windows`, next to `explorer.exe`. The real file
lives in `System32` (225 KB, signed by Microsoft). Windows loads a DLL from the program's own folder first, so
**Explorer loaded the fake one at every start**. Its timestamp had been faked to 2021, and its content changed
between two observations about 20 minutes apart while it was loaded.

### 2.6 Payloads

A crypto miner disguised as `.jpeg` files in `%APPDATA%\Microsoft`, and encrypted payload drops
(`Trojan.Crypt`) in `%TEMP%`. The origin was most likely an untrusted download.

## 3. Techniques (MITRE ATT&CK) and how SimpleAV detects them

| Technique | ATT&CK | Seen as | SimpleAV detection |
|---|---|---|---|
| Winlogon Shell persistence | T1547.004 | HKCU `Winlogon\Shell` launcher | `STARTUP/PERSISTENCE` (per-user Shell set) |
| Logon script | T1037.001 | `UserInitMprLogonScript` | `STARTUP/PERSISTENCE` (`ENV` hook) |
| Payload in registry / obfuscation | T1112, T1027 | Base64 in `UserCache`, fake CLSID | `ENV` + `CLSID` checks; process command-line check for `FromBase64String` |
| MSBuild proxy execution | T1127.001 | copied `MSBuild.exe` + `.csproj` | `MSBUILD COPY` (files) and `SUSPICIOUS MSBUILD` (processes) |
| Msiexec install of loader | T1218.007 | fake Broadcom/Logitech MSIs | (indirect) dropped MSBuild copies + persistence |
| IFEO injection / impair defenses | T1546.012, T1562.001 | debugger on `MpCmdRun.exe` | `IFEO` check on security tools |
| DLL search-order hijacking | T1574.001 | fake `C:\Windows\omadmapi.dll` | `DLL HIJACK`: unsigned DLL in `C:\Windows` with a System32 name |
| File infection | - | 865 patched programs | `INFECTED FILE`: exact 12-byte marker **or** entry point in a writable+executable last data section |
| Timestomp | T1070.006 | DLL dated 2021 | (not relied on - detection uses content and signatures, not dates) |
| Masquerading file type | T1036.008 | miner saved as `.jpeg` | `DISGUISED PROGRAM` (Deep scan reads every file's real header) |
| Resource hijacking | T1496 | crypto miner | via `DISGUISED PROGRAM` / infected-file detections |

Real-time, the watcher re-checks new and changed program files within seconds, inspects new processes every
15 seconds, and diffs all startup locations every 60 seconds.

## 4. Remediation that was performed

1. Removed the two logon launchers (Winlogon `Shell`, `UserInitMprLogonScript`), the registry payload and the fake CLSID.
2. Removed the empty fake Broadcom/Logitech folders. The cached MSI packages had already been quarantined by Malwarebytes.
3. Deleted the program folders containing the 865 infected files (apps reinstalled later from official sources).
4. SimpleAV's first full scan then found **2 more infected files** the first pass had missed (in Docker Desktop and OpenCode),
   because their entry-point sections had unusual names (`.symtab`, `.bun`). The exact byte-marker check caught them. Both were deleted.
5. SimpleAV also flagged the fake `omadmapi.dll`. It was quarantined with administrator rights, Explorer was restarted
   (afterwards no process had it loaded), and it did not come back.
6. After a reboot: no launchers, no payload, no fake DLL, no hidden PowerShell running, and quick/full re-scans were clean.
   Reinstalled apps (e.g. Discord) were verified as clean: valid signatures and no virus code.

### Reinfection (16-17 November 2026)

7. The infection came back. SimpleAV auto-quarantined **18 newly infected programs** by their exact 12-byte marker:
   Discord, Claude Code, an installer in `Downloads`, two `%TEMP%\tx_*.exe` drops, and programs under an old Windows
   profile on a second drive (`J:\Users\...`).
8. The dashboard showed all four registry hooks (`UserCache`, `UserInitMprLogonScript`, HKCU Winlogon `Shell`, the
   fake CLSID, whose registry export alone was ~278 KB) and the unsigned 56 KB `C:\Windows\omadmapi.dll` back in place.
9. The hooks were exported to quarantine (renamed so they can't be re-imported by double-click), then removed:
   **launchers first, payload second**, so nothing could rebuild it in between. They stayed gone on re-check, and no
   payload process was running. The DLL was quarantined through SimpleAV with one admin prompt (SHA-256
   `D2797D9AAB9ED671B07CC4BDA0CCF3D5837AECE3BCD38B2BE42D6B84607041A1`).
10. **Open question:** what re-installs it. The infected programs on the old profile on the second drive are the main
    suspect. Two returns after cleanup means the dependable fix is a clean Windows reinstall, copying back documents
    only (never programs or installers).

## 5. Design decisions

- **Detect by content, not by name or date.** The malware faked dates and file types, so SimpleAV reads file headers,
  entry points and signatures.
- **Only automate what is certain.** Files with the exact virus marker are quarantined automatically; anything heuristic is
  only reported, so a false alarm can never break a legitimate program.
- **Quarantine, don't delete.** Files are moved and renamed (`*.quarantined`) with a record of the original path and SHA-256,
  so they can be restored.
- **Be honest about coverage.** Every scan logs how many folders and files it could not read.
- **No dependencies.** Plain Windows PowerShell 5.1 and .NET, both signed by Microsoft and present on every Windows 10/11 PC,
  so the tool doesn't depend on any program the infection could have modified.
