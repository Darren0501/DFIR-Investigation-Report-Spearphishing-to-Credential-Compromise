# Figure Manifest

Save each screenshot you pasted into the chat at the **exact filename** below (PNG), then commit.
Once committed, GitHub renders them inline in the main `README.md`.

| Save as (filename) | Screenshot to use |
|---|---|
| `fig01-sysmon-timeline.png` | The **wide Sysmon/EvtxECmd timeline** (columns: Time Created, Event Id, Level, Channel, Provider, Map Description, Executable Info) — rows from 15:43:43 to 15:47:56. |
| `fig02-userassist.png` | **UserAssist** table (Program Name / Run Counter / Focus / Last Executed) showing `CompanyA_Invoice.pdf.lnk`. |
| `fig03-prefetch-executables.png` | **Prefetch** list of executables run from `\VOLUME{01dd29e558b7786de61a}\...` (POWERSHELL, WHOAMI, SCHTASKS, RUNDLL32, WEVTUTIL...). |
| `fig04-prefetch-lastrun.png` | **Prefetch** small table: Program + Execution Time (conhost, cmd, powershell 15:47:37, Notepad 15:46:24). |
| `fig05-taskscheduler-tree.png` | **Task Scheduler tree** with `T1053_005_OnLogon` / `T1053_005_OnStartup` highlighted. |
| `fig06-task-onlogon.png` | Scheduled task **OnLogon** detail row (GUID `{9AFA980B-...}`, `cmd.exe /c calc.exe`). |
| `fig07-task-onstartup.png` | Scheduled task **OnStartup** detail (Version/Key Name/Path/Command/Arguments/Author; key `{CE7575DC-...}`). |
| `fig08-lecmd-lnk.png` | **LECmd output** of `CompanyA_Invoice.pdf.lnk` (run `LECmd.exe -f "...lnk" --csv .`). Add after you run it. |

> Tip: filenames are case-sensitive on GitHub. Keep them lowercase exactly as above.
