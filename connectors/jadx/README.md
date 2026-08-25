# MATKAP JADX Connector

This package is ready to install. End users do not compile it and do not need
Maven, Python, or a separate MCP bridge.

## Install on Windows

1. Download and extract the MATKAP JADX connector ZIP.
2. Close JADX if it is open.
3. Open PowerShell in the extracted folder.
4. Run:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

5. Open JADX and load the APK.
6. In MATKAP, open **MCP Lab**, click **Connect JADX**, then click
   **Scan open JADX project**.

The connector listens only on `http://127.0.0.1:8650`. Ghidra and Binary Ninja
connectors are planned but are not included in this release.
