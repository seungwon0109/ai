# CAPE + Sysmon Windows guest preparation

This folder is for the disposable Windows analysis VM only. Do not run the
installer on the Windows host or on a personal VM.

The sysmon-config.xml policy collects process, injection, network, persistence
and file-write telemetry. CAPE's current Windows evtx auxiliary already exports
the Microsoft-Windows-Sysmon/Operational channel as evtx.zip at the end of each
analysis; no separate CAPE plug-in is required.

After the CAPE Linux controller and isolated Windows VM network exist, copy
this directory into the VM and run, from an elevated PowerShell inside the VM:

    Set-ExecutionPolicy Bypass -Scope Process -Force
    .\Install-CapeGuest.ps1

The script downloads Sysmon from Microsoft, verifies its Authenticode
signature, installs the XML policy, then downloads CAPE Agent 0.22 from the
same pinned CAPE revision as the controller and verifies its SHA-256. It starts
the agent in the logged-in analysis user session with an AtLogOn task. CAPE
requires an interactive session to launch and monitor samples correctly. The
script intentionally does not execute any sample.

Before taking the Ready snapshot, verify:

    Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" |
      Select-Object LogName, IsEnabled, RecordCount
    Get-ScheduledTask -TaskName "CAPE Agent"

The controller address and analysis-only guest IP must be set after the
Hyper-V isolated switch is created. Keep the guest disconnected from personal
and production networks.
