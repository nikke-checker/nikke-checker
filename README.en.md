# NIKKE PC Launcher Infection Checker

[한국어](README.md)

Download `NikkeChecker_EN.exe` from [Releases](https://github.com/nikke-checker/nikke-checker/releases/latest) and run it.
No install is needed (it uses .NET Framework 4.8, built into Windows 10/11).
`NikkeChecker.exe` is the same program; it opens in Korean on Korean Windows. You can switch the language at the top right.

On September 27, 2026, four scripts on Level Infinite's CDN were modified, and the NIKKE PC launcher loaded `insightjs.com/l.js`.
From October 23, some launches also downloaded and ran a remote-access agent (`insight.bundle`).

## Checks (only the ticked ones run)

| # | Check | Infected (●) | Exposed (▲) |
|---|---|---|---|
| 1 | Browser persistence DLL | In 14 Chromium browsers (Chrome, Edge, Brave, Vivaldi, Opera, Opera GX, Chromium, Naver Whale, Arc, Yandex, Cốc Cốc, Comodo Dragon, Thorium, Epic): a 64-hex folder under `User Data\PlatformExperienceHelper` (even without the DLL) or `platform_experience_helper.dll`; the older `platform_experience_helper.dll(.old)` and `old-clsid.txt` in `Chrome\Application\PlatformExperienceHelper` | |
| 2 | Registry CLSID | `HKCU\Software\Classes\(WOW6432Node\)CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}` (DLL path or empty leftover) and the DLL file it names; variant CLSIDs that point to a DLL in a 64-hex folder | |
| 3 | Running processes | `nikke_launcher*` running; processes with a `platform_experience_helper*` module loaded | |
| 4 | Launcher data `%APPDATA%\nikke_launcher(_hmt)` | `k2f.agent` / `k2f_chan`; analytics.insightjs.com in HSTS (`TransportSecurity`) or `Network Persistent State` | insightjs in `Cache`/`Code Cache`; insightjs.com/org in HSTS; `Reporting and NEL` |
| 5 | Temp folder | `k2f-bcreds-*` (stolen credentials), `k2f_screen_*.jpg` (screenshots) - only names starting with `k2f-`, `k2f_`, `k2f.` | |
| 6 | File names on all drives | `platform_experience_helper.dll*` outside known places; `insight.bundle`, `k2f.lua`, `tinyget*` that start with LuaJIT bytecode; `k2f-bcreds*`, `k2f_screen*`, `k2f.agent*` (cloud drives, `\Windows` and junctions skipped). Files outside the temp folder and DLLs outside your profile are reported but not deleted automatically | |
| 7 | NIKKE install folder | `k2f_chan`, `agent started as`, `lua downloaded to`, `adopted/resuming <uuid>`, analytics.insightjs.com or insight.bundle in `debug.log`; insight.bundle download records in `Launcher\log`; agent files (LuaJIT bytecode `1B 4C 4A` or `k2f*`) | logs that name only insightjs |
| 8 | Autostart programs (to check) | Autostart targets that are new since Sep 27 and have no publisher signature (file or catalog): Run/RunOnce (HKCU, HKLM), Startup folders, Task Scheduler, services (ServiceDll for svchost), WMI event consumers. Hidden PowerShell/mshta commands are marked high risk. Each file is scanned with Windows Defender. **No effect on the verdict** | |
| 9 | Block status (reference) | The three domains in hosts; firewall rule contents (enabled, outbound, block, both IPs) | |

**Verdict**: any infected trace gives *INFECTED*, only exposed traces give *EXPOSED*, otherwise *no known traces*, or *NIKKE not found*.

Reading PC-wide autostarts needs administrator rights, so check 8 asks for UAC once (read-only).

## Clean-up ([Clean up]: confirm, save the report to the Desktop, then run. Nothing is deleted if the report cannot be saved)

1. Close the launcher
2. Delete the HKCU CLSID key (first, so browsers stop loading the DLL)
3. End processes that loaded the DLL and close the affected browser (not explorer.exe)
4. Delete the 64-hex folder / DLL - if it is locked, you are told to **restart Windows and run again**
5. Delete the launcher cache `tbs_cache` (recommended option even with no traces)
6. Delete temp `k2f*` files, saved agent files and files found by the drive scan (logs are kept as evidence)
7. Autostart programs to check: only the ones **you tick** in the list are unregistered and their files deleted (files inside the Windows folder are only unregistered). Items Defender confirmed as malware are ticked already
8. (Admin, UAC) Delete older persistence files in Program Files and PC-wide autostart items; block the three domains in hosts; block `89.127.233.127` and `89.126.250.172` outbound in the firewall (the rule is recreated if its contents differ)
9. (Optional) Windows Defender offline scan: asks again before the restart. On PCs where Defender is not the active antivirus, BitLocker is on, or the Windows Recovery Environment is off, it explains how to run a Full scan instead. Skipped if done in the last 24 hours

The program runs with normal rights and hands only admin tasks to an elevated copy of itself (UAC), so it checks the real user's HKCU/AppData even when the admin account is different.
The elevated copy deletes no paths other than the known older persistence files, and for autostart items it checks again itself and removes only the items whose Id was requested.

If the verdict was INFECTED, from a clean device change your passwords, sign out of all devices, clear browser cookies, reissue tokens/SSH keys/cloud CLI credentials, and move crypto to a new wallet.
If other Windows accounts use the PC, sign in to each and run the tool again (HKCU and AppData are per account).
Finding nothing does not prove the PC is clean.

## Verify the download
Release exe files carry a build provenance attestation. Check with the [GitHub CLI](https://cli.github.com/):
```
gh attestation verify NikkeChecker_EN.exe --repo nikke-checker/nikke-checker
```

## Credits
The detection rules (IoCs, HSTS keys, agent build ETags) are based on
[MotherSphere/NIKKE-Launcher-Check](https://github.com/MotherSphere/NIKKE-Launcher-Check) and its
[write-up](https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5).
Rules from [hamzzi's NIKKE_k2f_cleaner](https://x.com/choi_hamzzi) v3.1-v4 are included too (drive-wide name scan, agent registration lines in debug.log, firewall rule check, deletion safeguards, autostart check, Defender per-file and offline scans, English UI).
The code in this repository was written from scratch.
