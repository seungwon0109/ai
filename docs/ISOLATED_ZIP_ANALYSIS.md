# Isolated password-protected ZIP analysis

Password-protected malware archives are never decrypted on the Windows host.

## Flow

1. Windows hashes the encrypted ZIP.
2. The encrypted ZIP is streamed over standard input into `Ubuntu-24.04` WSL.
3. The selected member is decrypted only inside WSL ext4 temporary storage.
4. PE metadata, strings, imports, CAPE's capa rules, and Ghidra Headless decompilation are collected.
5. Temporary plaintext and encrypted staging files are deleted.
6. Structured JSON only is returned to Windows and passed to `malware-qwen:9b`.
7. For dynamic analysis, the original encrypted ZIP is submitted to CAPE.

The WSL worker fails closed. It does not fall back to Windows decryption if WSL
analysis fails.

## Commands

```powershell
# Does not execute the sample
python main.py ".\malware-vault\sample.zip" `
  --archive-password infected `
  --static-only

# Static plus CAPE dynamic analysis; VS Code must be running as Administrator
python main.py ".\malware-vault\sample.zip" `
  --archive-password infected
```

Before dynamic submission, `main.py` requires the Hyper-V audit to verify:

- VM `CAPE-Win11` is attached to the `CAPE-Lab` switch.
- `CAPE-Lab` is an Internal switch.
- no NAT exposes `192.168.56.0/24`.
- IPv4 forwarding is disabled.
- checkpoint `Ready` exists.

If the audit cannot run or any condition fails, no CAPE task is submitted.

## Ghidra and hash correlation

OpenJDK 21 is installed in the CAPE WSL environment. The existing Ghidra 12.1.2
distribution is used through its Linux `analyzeHeadless` launcher. Its project,
decrypted sample, and decompiler output files are created only in WSL temporary
storage and deleted after structured JSON is collected.

The encrypted outer ZIP and decrypted inner executable intentionally have
different SHA-256 values. Both are retained as separate entities linked by a
`CONTAINS` relation. CAPE then verifies the outer upload hash and separately
correlates the inner hash with report objects and observed process names.
