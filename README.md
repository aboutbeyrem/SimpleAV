<p align="center"><img src="docs/logo.png" width="96" alt="SimpleAV logo"></p>

<h1 align="center">SimpleAV</h1>

<p align="center"><b>A targeted malware scanner and real-time watcher for Windows,<br>built to find and contain the specific virus family that infected my own PC.</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/Windows-10%20%7C%2011-0078D6" alt="Windows 10/11">
  <img src="https://img.shields.io/badge/PowerShell-5.1-5391FE" alt="PowerShell 5.1">
  <img src="https://img.shields.io/badge/tests-22%20passing-34C759" alt="22 tests passing">
  <img src="https://img.shields.io/badge/license-MIT-lightgrey" alt="MIT license">
</p>

![SimpleAV dashboard](docs/screenshot.png)

<p align="center"><i>Made by Beyrem</i></p>

> [!IMPORTANT]
> **SimpleAV is not a general-purpose antivirus.** Its virus-signature detection matches **one specific
> file-infector family**: the one that infected my PC, identified by an exact 12-byte code sequence
> (`E8 D9 00 00 00 48 8D 58 FB 51 52 41`) at the start of every infected program. A structural check may also
> catch close variants of that family. Its other checks (hidden startup entries, DLL hijacks, disguised programs,
> tampered signatures) are generic rules based on the techniques this malware used, **not** signatures for other viruses.
> It will **not** recognize unrelated malware families. **Keep Windows Defender or another real antivirus turned on.**

---

## Why I built this

In November 2026 my PC got infected, and the infection **kept coming back** no matter how many times my
antivirus "removed" it. I investigated it myself and found several parts working together:

- a **file-infecting virus** that had patched **865 programs** (Discord, VS Code, Steam, npm tools...) so that
  its code ran every time I opened one of them
- a **loader** (PavinLoader) disguised as Broadcom and Logitech driver software, running hidden code through
  Microsoft's own `MSBuild.exe`
- a payload **hidden inside the registry**, restarted at every login by two hidden startup hooks. My
  antivirus kept deleting the payload but never the hooks, which is why it always came back
- a **fake system DLL** placed next to `explorer.exe`, so Windows Explorer loaded the virus every time it started

I built SimpleAV to find and contain exactly these tricks, and to keep watching so it couldn't happen again.

### Did it work? Yes.

- After the first manual cleanup, SimpleAV's first full scan found **2 more infected programs** that the
  cleanup had missed (in Docker Desktop and OpenCode). Its exact-signature check caught them even though
  the virus had hidden its code in unusual places.
- It **independently detected the fake Explorer DLL**, which was then quarantined.
- After removal and a reboot, re-scans came back **clean**, the hidden startup hooks never returned, and
  reinstalled apps were verified as clean (valid signatures, no virus code).

The full technical write-up, including how each piece of the malware maps to MITRE ATT&CK techniques, is in
**[docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md)**.

---

## Features

| | |
|---|---|
| **Infected-program detection** | Finds programs infected by **this specific virus family**, by its exact 12-byte signature **and** by its structural fingerprint (execution redirected into a writable + executable data section), which can also catch close variants of the same family. |
| **Deep scan** | Opens **every file on every drive**, not only programs, and checks what it really is. Catches programs disguised as photos or documents (the miner here was saved as `.jpeg`). |
| **System integrity** | Verifies the digital signatures of Windows system files and installed apps, and detects DLL hijacks next to `explorer.exe`. |
| **Startup / persistence check** | Run keys, Winlogon, logon scripts, scheduled tasks, IFEO "debugger" hijacks, WMI consumers, AppInit DLLs, startup folders, and the registry locations this malware used. |
| **Real-time watcher** | Checks new or changed program files within seconds, new processes every 15 s (hidden encoded PowerShell, MSBuild abuse, infected programs), and startup changes every 60 s. Alerts through Windows notifications. |
| **Quarantine and restore** | Files with the **exact** virus code are quarantined automatically (can be switched off). Everything else is only reported, and you decide with one click. Quarantined files are renamed so they can't run, and a record of the original path and SHA-256 is kept so they can be restored. |
| **Honest coverage report** | Every scan reports how many files it opened and **how many folders Windows wouldn't let it read**, so nothing is skipped silently. |
| **Clear dashboard** | Shows the status of every threat in plain words: *Still on your PC / Quarantined / Deleted / Removed / Replaced (clean)*, re-checked live against your disk. |
| **Tamper check** | SimpleAV verifies its own file hash and warns if something modified it. |
| **No dependencies** | Plain Windows PowerShell 5.1 + .NET, both already on every Windows 10/11 PC and signed by Microsoft. |

## Install

1. Download this repository (**Code → Download ZIP**, then extract it), or clone it:
   ```
   git clone https://github.com/aboutbeyrem/SimpleAV.git
   ```
2. Double-click **`Install.cmd`**.

That's it. SimpleAV copies itself to `%USERPROFILE%\SimpleAV`, starts the real-time watcher (it then starts
automatically at every login), schedules a daily scan of all drives at 13:00, and adds a **SimpleAV** shortcut
to your desktop and Start menu.

To remove it, double-click **`Uninstall.cmd`**. Your logs and quarantine are kept.

> No administrator rights are needed. Windows will only ask for them if you quarantine a file inside a protected
> system folder.

## Use

Open **SimpleAV** from the desktop or Start menu:

- **Scan now** checks every program on `C:` plus system signatures and startup entries (about 7 minutes)
- **Quick scan** checks your user folder only
- **All drives** checks every program on every drive
- **Deep scan** opens every file on every drive (slowest, most thorough)
- Click any row in **Threat history** to see what it is, and to quarantine or restore it

Command line (from the `src` folder):

```powershell
powershell -ExecutionPolicy Bypass -File SimpleAV.ps1 -Scan            # full scan of C:
powershell -ExecutionPolicy Bypass -File SimpleAV.ps1 -Deep            # every file, every drive
powershell -ExecutionPolicy Bypass -File SimpleAV.ps1 -Paths D:\Games  # one folder
powershell -ExecutionPolicy Bypass -File SimpleAV.ps1 -Quarantine "C:\path\file.exe"
powershell -ExecutionPolicy Bypass -File SimpleAV.ps1 -Restore    "%USERPROFILE%\SimpleAV\quarantine\file.exe_....quarantined"
Get-Help .\SimpleAV.ps1 -Detailed
```

Logs (one `.log` + `.csv` per scan) are saved in `%USERPROFILE%\SimpleAV\logs`.

## Tests

```powershell
powershell -ExecutionPolicy Bypass -File tests\Run-Tests.ps1
```

The test suite builds **harmless** sample files: tiny fake program headers that contain the virus's marker
bytes but no runnable code, plus a renamed copy of Notepad. It then checks every detection, auto-quarantine
(on and off), manual quarantine and restore, and the dashboard. It uses a temporary folder and never touches
your real data. **22/22 tests pass.**

## Limitations

SimpleAV is a focused tool, not a replacement for a full antivirus. **Keep Windows Defender (or another antivirus) on.**

- **The exact-byte signature only identifies one virus family**: the file infector described in
  [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md). Files infected by any other virus will not match it.
- The structural check (entry point moved into a writable + executable data section) is tuned to how *this*
  family patches programs. It may catch close variants, but it is not a general infection detector.
- The startup, DLL-hijack, disguised-program and signature checks are generic rules. They can flag
  suspicious things from other malware, but they are not a substitute for a signature database covering thousands
  of families, like Windows Defender or Malwarebytes.
- Without administrator rights it cannot read some protected Windows folders (the number is shown after every scan).
- It does not look inside `.zip` / `.rar` archives or installers.
- Files that are only suspicious (not an exact match) are reported, never removed automatically.

## Project structure

```
Install.cmd / Uninstall.cmd   one-click install / removal
src/SimpleAV.ps1              engine: scanner, real-time watcher, quarantine, installer
src/SimpleAV-App.ps1          dashboard window
src/SimpleAV.ico              app icon (generated by tools/Build-Icon.ps1)
tests/Run-Tests.ps1           automated tests
tests/New-TestSamples.ps1     harmless test-sample generator
tools/Build-Icon.ps1          draws the logo and builds the .ico (16-256 px)
docs/HOW-IT-WORKS.md          analysis of the infection and the detection logic
```

## Acknowledgements

Built with AI pair-programming assistance (Claude by Anthropic), which helped with the malware analysis,
code and testing. The dashboard design follows Apple's Human Interface Guidelines principles: one primary action,
clear status, plain language.

## License

[MIT](LICENSE) © 2026 Beyrem
