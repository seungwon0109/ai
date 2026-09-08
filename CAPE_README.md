# CAPE integration

`CAPE_DEMO.py` adds CAPE v2 dynamic evidence before the existing three local-AI
reviews. The original CAPE JSON is stored as `*.cape.json`; only a bounded
summary is included in local/cloud AI prompts.

```powershell
$env:CAPE_API_URL = "http://cape-host:8000/apiv2"
$env:CAPE_API_TOKEN = "TOKEN"
.\run_cape_demo.ps1 .\samples\ransom_sample\ransom.exe
```

The token can instead be supplied with `-CapeToken`. Optional parameters include
`-CapePackage`, `-CapeMachine`, `-CapeTags`, `-CapeAnalysisTimeout`, and
`-CapeWaitTimeout`.

## Safety requirements

- CAPE must run on a dedicated Linux host with disposable Windows analysis VMs.
- Restore the guest VM snapshot after every task.
- Do not allow the guest to reach personal or production networks.
- Enable CAPE token authentication and do not store tokens in source files.
- A CAPE timeout or error is recorded as `dynamic_analysis.status=unavailable`;
  it is never interpreted as clean behavior.
