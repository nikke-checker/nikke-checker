# NIKKE PC Launcher Infection Checker

[한국어](README.md)

Download `NikkeChecker_EN.exe` from [Releases](https://github.com/nikke-checker/nikke-checker/releases/latest) and run it.
No install is needed (it uses .NET Framework 4.8, built into Windows 10/11).
`NikkeChecker.exe` is the same program; it opens in Korean on Korean Windows. You can switch the language at the top right.

> **Windows Defender false positive (v1.5.0)**
> Microsoft Defender may flag v1.5.0 as `Trojan:Win32/Wacatac.B!ml`. This is a machine-learning verdict on a new unsigned exe, and it is being reported to Microsoft as a false positive.
> We do not recommend turning Defender off or adding an exclusion while it is pending. You can check that your download is genuine:
> - SHA-256: `c5a2c5816e23c80f1bbb9e9c0f3c6ac58039dbdebd9bd3d6920d1eac25c75c61` (`NikkeChecker.exe` and `NikkeChecker_EN.exe` are the same file)
> - Build provenance: `gh attestation verify NikkeChecker_EN.exe --repo nikke-checker/nikke-checker` ([Verify the download](#verify-the-download))
>
> If it is still flagged after Microsoft updates the verdict, run `"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -SignatureUpdate` from an administrator Command Prompt.

On September 27, 2026, four scripts on Level Infinite's CDN were modified, and the NIKKE PC launcher loaded `insightjs.com/l.js`.
From October 23, some launches also downloaded and ran a remote-access agent (`insight.bundle`).
Level Infinite announced a fix on November 4, but how the attacker got into the CDN is still unknown.
Delete the launcher cache (`tbs_cache`) before opening the launcher again, and keep the blocks in place.

## Checks (only the ticked ones run)

| # | Check | Infected (●) | Exposed (▲) |
|---|---|---|---|
| 1 | Browser persistence DLL | In 14 Chromium browsers (Chrome, Edge, Brave, Vivaldi, Opera, Opera GX, Chromium, Naver Whale, Arc, Yandex, Cốc Cốc, Comodo Dragon, Thorium, Epic): a 64-hex folder under `User Data\PlatformExperienceHelper` (even without the DLL) or `platform_experience_helper.dll`; the older `platform_experience_helper.dll(.old)` and `old-clsid.txt` in `Chrome\Application\PlatformExperienceHelper` | |
| 2 | Registry CLSID | `HKCU\Software\Classes\(WOW6432Node\)CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}` (DLL path or empty leftover) and the DLL file it names. A CLSID under another name counts too when its `InprocServer32` points into `PlatformExperienceHelper` or a browser `User Data` folder | |
| 3 | Running processes | Processes with a `platform_experience_helper*` module loaded. A running launcher (`nikke_launcher*`) is critical only when the same scan found another sign of the agent; otherwise it is shown for reference | |
| 4 | Launcher data `%APPDATA%\nikke_launcher(_hmt, _google)` and the launcher's login browser profile `%LOCALAPPDATA%\CEF\User Data` | `k2f.agent` / `k2f_chan` (also inside decompressed LevelDB `.ldb` tables); analytics.insightjs.com in HSTS (`TransportSecurity`) or `Network Persistent State` | insightjs in `Cache`/`Code Cache`; insightjs.com/org in HSTS; `Reporting and NEL` |
| 5 | Temp folder | `k2f-bcreds-*` (stolen credentials), `k2f-keyscan-*` (collected keys), `k2f_screen_*` (screenshots) - only names starting with `k2f-`, `k2f_`, `k2f.` | |
| 6 | File names on all drives | `platform_experience_helper.dll*` outside known places; `insight.bundle`, `k2f.lua`, `tinyget*` that start with LuaJIT bytecode; `k2f-bcreds*`, `k2f-keyscan*`, `k2f_screen*`, `k2f.agent*` (cloud drives, `\Windows` and junctions skipped). `k2f-*` files outside the temp folder and DLLs outside your profile are reported but not deleted automatically | |
| 7 | NIKKE install folder | `k2f_chan`, `agent started as`, `lua downloaded to`, `adopted/resuming <uuid>`, analytics.insightjs.com or insight.bundle in `debug.log`; **finished** insight.bundle downloads in `Launcher\log`; agent files (LuaJIT bytecode `1B 4C 4A` or `k2f*`) | logs that name only insightjs; insight.bundle requests that never arrived (server did not answer) |
| 8 | Autostart programs (to check) | Autostart targets that are new since Sep 27 and have no publisher signature (file or catalog): Run/RunOnce (HKCU, HKLM), Startup folders, Task Scheduler, services (ServiceDll for svchost), WMI event consumers. Hidden PowerShell/mshta commands are marked high risk. Each file is scanned with Windows Defender. **No effect on the verdict** | |
| 9 | Extra checks | **Programs connected to the hacker servers (89.127.233.127, 89.126.250.172) right now** | **DNS cache records of hacker addresses** |
|   | (to check, no effect on the verdict) | Browsers running in remote-control mode (`--remote-debugging-*`, `--load-extension`) and such shortcuts, extensions force-installed by policy, risky Windows Defender exclusions (whole drives, AppData, Temp, executable extensions, ...), remote-access apps installed since Sep 27 or running (AnyDesk, TeamViewer, ...), proxy / auto-config (PAC), changed Winlogon Shell/Userinit, IFEO debuggers, AppInit_DLLs | |
| 10 | Block status (reference) | The 7 domains in hosts (insightjs.com, www, analytics, portal, docs; insightjs.org, analytics), firewall rule contents (enabled, outbound, block, both IPs) | |

The agent build (upload time, size) is decoded from the ETag in `tinyget.mem.log` (7 known builds).
Reading PC-wide entries (HKLM, Task Scheduler, services, WMI, Defender settings) needs administrator rights, so checks 8 and 9 ask for UAC once (read-only).

**Verdicts**
- *INFECTED*: infection traces are present now (files, registry, connections, ...)
- *PAST INFECTION (records only)*: traces only in the launcher logs (`debug.log`, download records). Logs keep showing up on every run, but this does not mean hacking files are still on the PC. Change your passwords
- *EXPOSED*: only exposed traces
- *No known traces* / *NIKKE not found*

## Screens

Four steps: start, checking, result, done. On the start screen you only press [Start check]; choosing checks and setting the install path are under Advanced.
The result screen shows a verdict banner and one card per kind of finding; the done screen shows what to do next (passwords etc.) as a checklist.
The log is under Show details, and the report saves that log as is.

## Clean-up ([Clean up]: confirm, save the report to the Desktop, then run. Nothing is deleted if the report cannot be saved)

1. Close the launcher
2. Delete the HKCU CLSID key (first, so browsers stop loading the DLL)
3. End processes that loaded the DLL or are connected to the hacker servers (not Windows programs), and close the affected browser (not explorer.exe)
4. Delete the 64-hex folder / DLL - if it is locked, you are told to **restart Windows and run again**
5. Delete the launcher cache `tbs_cache` (recommended option even with no traces), the launcher login browser profile (CEF) when it had traces (you only sign in to the launcher again), and flush the DNS cache
6. Delete temp `k2f*` files, saved agent files and files found by the drive scan (logs are kept as evidence)
7. Items to check: only the ones **you tick** in the list are fixed. Items Defender confirmed as malware are ticked already
   - Autostarts: unregistered and their files deleted. **Files inside Windows or Program Files are only unregistered**
   - Browsers are only closed, shortcuts lose only the remote-control options, settings are turned off or restored to the Windows default, Defender exclusions are only removed from the list
   - Remote-access apps: closed; for PC-wide installs only the official uninstaller is opened (uninstall commands registered in the user area may have been changed, so they are not run)
8. (Admin, UAC) Older persistence files in Program Files and PC-wide items; block the 7 domains in hosts; block `89.127.233.127` and `89.126.250.172` outbound in the firewall (the rule is recreated if its contents differ)
9. (Optional) Windows Defender offline scan: asks again before the restart. On PCs where Defender is not the active antivirus, BitLocker is on, or the Windows Recovery Environment is off, it explains how to run a Full scan instead. Skipped if done in the last 24 hours

**Remove NIKKE completely (optional, "Remove NIKKE…" on the result and done screens)** - not for people who keep playing. After two confirmations it deletes the install folder (game + launcher), launcher data, game data (`AppData\LocalLow`, about 5 GB), downloaded installers (`nikkeminiloader*.exe`), the Installed apps entry, `nikkelauncher://` and game settings, and shortcuts. Your account and progress stay on the servers.
- Launcher folders are removed only if they contain `nikke_launcher.exe` and are named `Launcher` or contain `nikke` (the parent when it is named `NIKKE`)
- Folders directly under your profile (Desktop, Documents, Downloads, ...), whole drives, and Windows / Program Files / profile folders themselves are excluded
- Other games of the same publisher (`com.proximabeta`) are left alone; only subfolders and keys with `nikke` in the name
- Executables the launcher installed (uninstallers etc.) are never run

**Safety**
- The program runs with normal rights and hands only admin tasks to an elevated copy of itself (UAC), so it checks the real user's HKCU/AppData even when the admin account is different.
- The elevated copy re-checks every requested path or item with the same rules and acts only on what passes (older persistence files, items it finds again itself, folders that pass the NIKKE folder rules, ...).
- Program Files, Windows and system tool paths come from Windows APIs, not environment variables, and `sc.exe`, `ipconfig.exe`, `netstat.exe`, `msiexec.exe` run by their full System32 path.
- Paths with a junction or symbolic link in a parent folder are not deleted; you are asked to check them yourself.

If the verdict was INFECTED, from a clean device change your passwords, sign out of all devices, clear browser cookies, reissue tokens/SSH keys/cloud CLI credentials, and move crypto to a new wallet.
If other Windows accounts use the PC, sign in to each and run the tool again (HKCU and AppData are per account).
Finding nothing does not prove the PC is clean.

## Verify the download
Release exe files carry a build provenance attestation. Check with the [GitHub CLI](https://cli.github.com/):
```
gh attestation verify NikkeChecker_EN.exe --repo nikke-checker/nikke-checker
```

## References
The code in this repository was written from scratch; no code was taken from other tools. The detection rules draw on these public sources:
- [MotherSphere/NIKKE-Launcher-Check](https://github.com/MotherSphere/NIKKE-Launcher-Check) (up to 0.5.1) and its [write-up](https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5) - the first analysis of this incident: IoCs, HSTS keys, agent build ETags, the finished-download rule, compressed LevelDB tables, the launcher login browser profile
- [hamzzi](https://x.com/choi_hamzzi)'s NIKKE_k2f_cleaner (v3.1-v4.5) - used as a reference for check ideas: drive-wide name scan, autostart and extra security checks, Defender per-file and offline scans, the past-record verdict, NIKKE removal and its safeguards
